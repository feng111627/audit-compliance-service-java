# 审计合规服务（audit-compliance-service-java）

本地可运行的审计事件接收、合规判定与可验证留存服务。全部依赖为内存或本地文件，
不依赖外部服务、真实凭据或联网付费资源。

## 快速开始

```bash
# 跑全部测试（日志会打印每个业务覆盖的用例与结果）
mvn test

# 本地启动（默认随机端口，可用 --server.port=8080 固定）
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080
```

## 合规规则模型

规则完全由 JSON 配置（默认 `classpath:rules.json`，可用 `--audit.rules.path=file:/path/rules.json`
指向外部文件），**改规则不用改代码**，`POST /api/rules/reload` 热加载。

```json
{
  "version": "v1",
  "rules": [
    { "id": "R2", "type": "REQUIRED",       "field": "actor",  "message": "操作者 actor 缺失" },
    { "id": "R6", "type": "FORMAT",         "field": "eventId", "pattern": "^[A-Za-z0-9_-]{4,64}$", "message": "..." },
    { "id": "R7", "type": "ALLOWED_VALUES", "field": "result", "values": ["SUCCESS","FAILURE","DENIED"], "message": "..." },
    { "id": "R9", "type": "ALERT_WHEN",     "field": "result", "values": ["FAILURE","DENIED"], "message": "..." }
  ]
}
```

- 四种规则类型：`REQUIRED`（必填）、`FORMAT`（正则）、`ALLOWED_VALUES`（枚举）、
  `ALERT_WHEN`（不违规，只把结论提升为 `ALERT` 触发异步告警转发）。
- `field` 支持 `eventId/actor/action/resource/result/timestamp` 及 `attributes.<key>`。
- 判定结论三态：`ACCEPTED` / `ALERT` / `REJECTED`。`REJECTED` 携带每条违规的
  字段、规则 ID 与原因（含实际值），逐条返回，**畸形事件不静默放行，也不拖垮整批**。
- 每条结论记录判定时的 `ruleVersion`；规则集按版本留存，历史记录可通过
  `GET /api/audit/records/{seq}/reproduce` 按**当时的规则**复现当时的结论，规则升级不影响复现。

## 留存与完整性校验

- **写入顺序**：`AuditLedger.append` 在公平锁内分配序号并链接哈希，并发写入下
  序号唯一、连续、无断档；`readAll` 按提交顺序返回。被拒收的事件不落账，因此不占序号。
- **哈希链**：每条记录 `hash = SHA-256(确定性序列化(序号+事件+结论) + prevHash)`，
  首条 `prevHash = "GENESIS"`。序列化字段顺序固定、`attributes` 按键排序，保证可独立重算。
- **独立校验**：`LedgerVerifier.verify(records)` 不依赖账本内部状态，可对任意一份
  记录列表（如导出的 JSONL 文件）校验：
  - 序号断档/乱序 → 删除或调换；
  - 记录哈希与内容重算不符 → 篡改；
  - `prevHash` 与前条不符 → 链断裂（删除/插入/调换）。
  每类异常都指出具体 `seq` 与 `eventId`。接口：`GET /api/audit/verify`。
- **持久化**：默认纯内存；配置 `--audit.ledger.path=./data/ledger.jsonl` 后按行追加落盘，
  重启自动恢复并先做一次完整性校验。

## 存证摘要（可保存、可对外发布）

- **摘要语义**：`GET /api/audit/digest` 返回 `{recordCount, tailHash, generatedAt, peaks}`，
  含义是“截止到这一刻，账本共 `recordCount` 条，链尾指纹为 `tailHash`，位置指纹为 `peaks`”。
  `tailHash` 是第 `recordCount` 条记录的链尾哈希，承诺链式衔接；`peaks` 是 MMR
  （Merkle Mountain Range）山尖集（高度从高到低排列，形状只由 `recordCount` 决定），
  逐位置承诺每个山尖覆盖段内的记录——任何一段里某条记录被改（哪怕把自身校验码也改对）、
  两条记录位置被互换，对应山尖都会变。
- **不停写、自洽位置**：摘要生成只在公平锁内读取序号、链尾与山尖（O(log n) 个山尖快照），
  不等待进行中的写入；与追加共用同一把锁，因此并发追加下每份摘要都对应一个确定、自洽的
  留存位置——记录、链尾、山尖是同一个提交点，事后拿账本前缀核对必然对得上（有并发测试佐证）。
- **核对副本**：任何人拿着摘要和一份记录副本，用 `DigestVerifier.check(digest, copy)`
  （或 `POST /api/audit/verify/copy`）即可独立核对：
  - 副本前 `recordCount` 条的链尾哈希 == 摘要指纹 → 两边是同一份内容；
  - 副本末尾被整段删掉若干条（自身看着连贯、单看副本链校验能通过）→ 报
    “末尾整段缺失”，说清缺少的 seq 范围与条数，**不能当成完好**；
  - 内容被改（含把整条链重算伪装自洽）→ 指纹不符或副本自身链异常，均被指出。

## 增量核验

- **用法**：保存上一回已确认可信的摘要，之后
  `POST /api/audit/verify/incremental`（或 `AuditLedger.verifyIncremental`）
  以它为锚点核验当前账本。服务端在**同一把公平锁内**同时取“当前 MMR 山尖 + 记录快照”，
  二者必然对应同一个留存位置，并发追加不会让结论横跨半个状态。
- **能发现哪些更早的改动（修复后）**：从可信旧山尖出发，只对新增的 m 条做 MMR 追加
  （每条 1 次叶子哈希、生命周期内至多 1 次父节点合并，总哈希数为 **2m+O(log k)**，
  不随历史总长 k 线性重算），再逐山尖与当前山尖比对：
  - 摘要覆盖范围内**中间某条记录内容被改，即使把该条自身携带的校验码也重算成能对上**
    （但没重算其后的链）→ 该条所在山尖失配，定位到具体 seq，并指出其后一条 prevHash 断链；
  - 覆盖范围内**两条记录整体互换位置**（自带的 seq/hash 原样跟着走）→ 山尖位置承诺识破，
    指出涉及的两个位置、乱序与断链明细；
  - 改动后把整条哈希链重算成自洽伪装（整体核验单看看不出来）→ 山尖/链尾锚点仍然不符。
  一句话：**整体核验能发现的，增量核验都能发现；同一批记录两者结论一致。**
- **定位信息**：山尖先粗定位到覆盖段（哪一段、落在历史内/跨锚点/新增段、多少条），
  再只对失配段与新增段的并集重放与整体核验同口径的三项检查（序号、内容重算哈希、
  prevHash），收窄到精确的 seq 区间与逐条明细；异常定位的额外重算只在发现问题时付出。
- **适用范围与前提**：
  - 所用摘要必须**来源可信**（上一回生成时已确认前缀完好，且摘要本身未被调包）；
    增量核验把“前 k 条的记录自带哈希未变”作为山尖承诺。快速路径要求**当前山尖由账本
    锁内提供**（服务端接口即如此），不能取自不受信的被核副本本身。
  - “只改内容、不换记录自带校验码”这种形态在活账本内存里不可能发生（记录由锁内追加、
    追加后不可变）；它只可能出现在**持久化文件离线期间被改**的场景。配置
    `audit.ledger.path` 时，账本启动会做一次全量核验，发现的异常会并入之后的增量核验
    结论，因此文件被改后增量核验仍与整体核验一致（有重启场景测试佐证）。
  - 拿着摘要核对手上的**不受信记录副本**时（`IncrementalVerifier.verifySince(digest,
    records)` 两参入口、或 `POST /api/audit/verify/copy`），因为副本可能“只改内容不换
    校验码”，必须对副本整体重算一次（O(副本总长)），这是信息论决定的，不属于线上
    周期增量核验路径；线上请走账本锁内快速路径。
  - 无 MMR 山尖的旧格式摘要（`peaks` 为空）会回退为一次整体核验（结论不漏报），
    重新生成并保存带山尖的新摘要后即恢复只随新增计费；锚点为 `count=0` 时增量核验
    等价于整体核验。
  - 末尾缺失只能发现“少于摘要覆盖范围”的部分；摘要之后新增又被整段删掉的，
    需用更新后的摘要才能约束——所以应在每个核验周期结束时重新生成并妥善保存摘要。

### 本地怎么复现这次修复的漏报、怎么验证

```bash
# 跑全部测试，日志按 [业务覆盖]/[用例]/[结果] 打印
mvn test

# 只看本次漏报相关场景（覆盖：中间记录被改含校验码一并改对、两条互换、
# 增量与整体结论一致、不误伤诚实账本、开销只随新增增长、并发确定性、文件重启兜底）
mvn -Dtest=IncrementalTamperCoverageTest,IncrementalVerificationTest test
```

关键测试在 `IncrementalTamperCoverageTest`：
`middleRecordContentChangedWithOwnHashRecomputedIsDetected`（中间记录被改+自身校验码
改对）、`twoRecordsSwappedInsideCoveredHistoryIsDetected`（覆盖范围内两条互换）、
`incrementalAndFullAgreeAcrossAllMutationScenarios`（7 种篡改下增量与整体结论一致）、
`honestLedgerStaysIntact`（诚实账本不误伤）、`hashWorkGrowsOnlyWithNewRecords`
（1000 与 99900 条历史下同样新增 100 条，追加哈希数相同）、
`concurrentAppendsAndVerificationsAlwaysLandOnSelfConsistentPosition`（并发确定性）、
`middleRecordContentChangedKeepingHashIsDetected`（文件被改+重启兜底）。

手工端到端复现：

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8080 --audit.ledger.path=./data/ledger.jsonl"

# 1. 写入若干条并保存可信摘要（此时 peaks 与 tailHash 都在摘要里）
for i in 1 2 3 4 5; do
  curl -s -X POST localhost:8080/api/audit/events -H 'Content-Type: application/json' \
    -d "[{\"eventId\":\"evt-000$i\",\"actor\":\"alice\",\"action\":\"READ\",\"resource\":\"doc-$i\",\"result\":\"SUCCESS\",\"timestamp\":\"2026-10-02T00:00:0$iZ\"}]" >/dev/null
done
curl -s localhost:8080/api/audit/digest | tee digest.json

# 2. 再追加几条新增
for i in 6 7 8; do
  curl -s -X POST localhost:8080/api/audit/events -H 'Content-Type: application/json' \
    -d "[{\"eventId\":\"evt-000$i\",\"actor\":\"alice\",\"action\":\"READ\",\"resource\":\"doc-$i\",\"result\":\"SUCCESS\",\"timestamp\":\"2026-10-02T00:00:1$iZ\"}]" >/dev/null
done
# 3. 停服，直接改 data/ledger.jsonl 里某一条的内容（模拟离线篡改），再启动，增量核验必报异常并定位
curl -s -X POST localhost:8080/api/audit/verify/incremental \
  -H 'Content-Type: application/json' -d @digest.json
```

## 证据包（可移植、可离线核验、可导回续写）

- **表述**：`GET /api/audit/evidence` 导出 JSON 证据包
  `{format:"audit-evidence", formatVersion:1, exportedAt, digest, records, ruleSets}`——
  一段留存记录 + 对应存证摘要 + 判定时所用的全部规则集版本。
- **离线核验**：`EvidenceVerifier.verify(pkg)` 是纯静态方法，不依赖 Spring 容器、
  账本实例或任何外部服务，未部署本服务、甚至离线的环境也能独立核验：
  1) 记录哈希链完整性；2) 内嵌摘要与记录是否一致（条数+指纹）；
  3) 用内嵌规则集逐条复现判定结论并与记录中保存的结论比对。
- **导回续写**：`POST /api/audit/evidence/import` 先完整离线核验，通过才落入
  **空账本**（非空账本拒绝导入，防止覆盖历史），并把内嵌规则集登记进规则提供者
  （同版本内容必须一致，否则拒绝）。导入后接着原有编号继续追加，不重号、不断档，
  历史记录仍可按当时规则版本复现结论。
- **兼容范围**：`formatVersion` 当前为 1，核验器拒绝未知格式/版本并明确报错；
  同版本服务间导出的证据包可互相导入；离线核验只依赖 JDK 与本仓库的模型/规则类，
  不需要联网或外部服务。

## 转发与失败处理语义

- **异步不拖慢接收**：`ALERT` 事件落账后仅入队即返回，单消费者线程在后台投递
  （`AlertForwarder`），下游故障期间接收路径不受影响（有测试佐证）。
- **重试**：失败按固定间隔重试，次数与间隔可配
  （`--audit.forward.max-attempts=3 --audit.forward.retry-backoff-ms=200`）。
- **不丢不重**：
  - 重试耗尽进入失败队列（`DeadLetter` 含记录、尝试次数、最后错误、时间），
    `GET /api/forward/dead-letters` 可查，事件不丢；
  - 按 `eventId` 去重：重复提交、重复回执、超时后重试都不会让同一条成功事件
    被重复投递；模拟下游本身也按 `eventId` 幂等，重复投递返回相同回执。
- **本地模拟下游**：`SimulatedDownstreamClient` 实现 `DownstreamClient` 接口，
  可编程注入故障（`failNextTimes(n)`）模拟连接失败/超时，无需任何外部服务。

## REST 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/audit/events` | 批量接收事件，逐条返回结论（含拒收原因） |
| GET  | `/api/audit/records` | 按写入顺序查询全部留存记录 |
| GET  | `/api/audit/verify` | 完整性校验，异常指出具体记录 |
| GET  | `/api/audit/digest` | 生成当前留存位置的存证摘要（不阻塞并发写入） |
| POST | `/api/audit/verify/incremental` | 以上一回可信摘要为锚点做增量核验 |
| POST | `/api/audit/verify/copy` | 用摘要核对一份记录副本（识别末尾删减/内容改动） |
| GET  | `/api/audit/evidence` | 导出可移植证据包（记录+摘要+全部规则集版本） |
| POST | `/api/audit/evidence/import` | 离线核验通过后导入空账本并登记历史规则集 |
| GET  | `/api/audit/records/{seq}/reproduce` | 按当时规则版本复现结论并比对 |
| GET  | `/api/forward/dead-letters` | 查询转发失败队列 |
| POST | `/api/rules/reload` | 热加载规则文件 |

示例：

```bash
curl -X POST localhost:8080/api/audit/events -H 'Content-Type: application/json' -d '[
  {"eventId":"evt-0001","actor":"alice","action":"READ","resource":"doc-1","result":"SUCCESS","timestamp":"2026-10-02T01:00:00Z"},
  {"eventId":"evt-0002","actor":"bob","action":"DELETE","resource":"doc-2","result":"FAILURE","timestamp":"2026-10-02T01:00:01Z"},
  {"actor":"carol","action":"READ","resource":"doc-3","result":"SUCCESS"}
]'
# 第 1 条 ACCEPTED 落账；第 2 条 ALERT 落账并异步转发；第 3 条 REJECTED 并说明 eventId 缺失
```

存证与证据包的本地验证示例：

```bash
# 1. 生成并保存当前存证摘要
curl -s localhost:8080/api/audit/digest | tee digest.json

# 2. 之后任何时候做增量核验（锁内快速路径：只对新增部分做 MMR 追加，不重算历史）
curl -s -X POST localhost:8080/api/audit/verify/incremental \
  -H 'Content-Type: application/json' -d @digest.json

# 3. 导出证据包并离线核验（核验器不依赖运行的服务）
curl -s localhost:8080/api/audit/evidence > evidence.json

# 4. 拿摘要核对手上的记录副本（这里用证据包里的记录演示）
jq '{digest: .digest, records: .records}' evidence.json | \
  curl -s -X POST localhost:8080/api/audit/verify/copy -H 'Content-Type: application/json' -d @-

# 5. 把证据包导回另一个全新实例（账本为空时才接受），接着原编号续写
curl -s -X POST localhost:8081/api/audit/evidence/import \
  -H 'Content-Type: application/json' -d @evidence.json
```

## 本地验证（测试覆盖）

`mvn test` 的日志按 `[业务覆盖] / [用例] / [结果]` 打印，覆盖：

| 测试类 | 业务场景 |
|---|---|
| `LedgerConcurrencyTest` | 8 线程并发写 800 条：序号唯一连续、读序=提交序、链校验通过 |
| `LedgerIntegrityTest` | 篡改/删除/调换历史记录均被检出并定位到具体 seq |
| `AlertForwarderTest` | 瞬时故障重试成功且只投递一次；持续故障进失败队列；重复提交+重复回执不重复投递；下游故障时接收不被拖慢 |
| `MalformedEventTest` | 缺字段/格式错/取值越界逐条拒收并说明原因；混合批量中坏的不影响好的、序号不断档 |
| `RuleReproductionTest` | 规则 v1→v2 升级后，历史记录仍按 v1 复现出当时结论 |
| `DigestConsistencyTest` | 摘要与账本一致；8 线程并发追加 800 条时连续生成 200 份摘要，每份都对应最终账本的真实前缀位置且增量核验完好 |
| `DigestCopyCheckTest` | 完整副本核对一致；末尾整段删减被发现并说清缺失 seq 范围；内容篡改、重算链伪装均被指纹比对识破 |
| `IncrementalVerificationTest` | 增量核验只算新增部分且结论与整体核验一致；历史被重算伪装时凭可信锚点发现；覆盖范围内中间记录被改（含自身校验码改对）/两条互换均不漏报并定位；末尾缺失被定位；count=0 锚点等价整体核验 |
| `IncrementalTamperCoverageTest` | 漏报复盘：覆盖范围内篡改（自身校验码改对/不改）、两条互换、跨界互换、新增段篡改、整链重算伪装共 7 种场景与整体核验结论一致；诚实账本不误伤；哈希开销 2m+O(log k) 不随历史增长；并发追加+持续核验结论对应确定位置；文件被改后重启由启动全量核验兜底 |
| `IncrementalDifferentialRandomTest` | 30 个随机账本 × 随机锚点/篡改位置/形态共 50 个用例，快速路径与整体核验结论始终一致、无漏报 |
| `EvidencePackageTest` | 证据包导出后离线核验通过；篡改结论被检出；导回新实例接着 seq 续写不重号不断档、结论按当时规则复现一致；篡改包/非空账本拒绝导入 |
| `EvidenceApiTest` | REST 全链路：空实例导入外部证据包→续写→摘要→增量核验→副本核对→导出→重复导入被拒 |
| `ApiIntegrationTest` | 本地起服务全链路：批量接收→留存→校验→异步转发→复现 |
