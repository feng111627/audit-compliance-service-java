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

`GET /api/audit/digest` 在任意时刻生成一份存证摘要：

```json
{ "recordCount": 105, "tailHash": "e28a4b…f19f", "generatedAt": "2026-10-03T04:26:28Z" }
```

- **语义**：`recordCount` 是截止生成时刻的记录总数；`tailHash` 是该位置的哈希链链尖，
  在密码学意义上提交了此前全部记录内容——这就是"整体指纹"。
- **并发安全**：链尖快照（条数+指纹）只在写锁内成对更新，生成摘要只读快照、
  **不停顿、不等待写入**；并发追加再密集，每份摘要也钉在一个确定、自洽的留存位置上，
  事后用该位置之前的记录副本核对必然对得上（有并发测试佐证）。
- **副本核对**：别人拿着摘要核对自己手上的记录副本，用
  `POST /api/audit/digest/check`（body：`{"digest": …, "records": […]}`）或离线调用
  `DigestVerifier.check(digest, copy)`：
  - 内容被改动、中间被删除/调换 → 哈希链校验异常，定位到具体 `seq`；
  - **末尾被整段删掉** → `matches=false`，并明确给出 `missingFromSeq` 与
    `missingCount`（少了哪些、少了多少），不能当成完好；
  - 副本比摘要位置**更新**（更长）不影响核对：摘要钉住的是位置，之后的新增不算冲突。

## 增量核验

`POST /api/audit/verify/incremental`（body：`{"trusted": <摘要>, "records": […]}`），
或离线调用 `LedgerVerifier.verifyIncremental(trusted, records)`。

- **适用范围与前提**：手头有一份**之前已确认可信**的摘要（上一轮回整体核验或增量核验
  通过后得到的），现在要核验它之后新增的部分。第一回核验没有可信摘要时，用整体核验
  （`GET /api/audit/verify`）建立第一份可信摘要。
- **代价只随新增部分增长**：哈希重算次数 = 新增条数（报告里的 `recomputedHashes`），
  与历史总长无关——历史 100 条与 1000 条，同样新增 3 条都只重算 3 次（有测试佐证）。
- **更早部分不漏检**：可信摘要的 `tailHash` 锚定了整个前缀。增量核验对前缀做结构校验
  （序号连续 + 链式衔接 + 锚点一致），对前缀的任何改动——删除、调换、改内容、甚至把
  整条链重算伪装连贯——要么破坏链式衔接、要么使锚点对不上，都会被发现；
  前缀的内容级校验在生成该摘要时已完成并由锚点固化。同一批异常场景下，
  增量核验与整体核验结论一致（有对照测试）。
- **可接力**：核验通过后 `report.toDigest()` 生成新的可信摘要，作为下一轮的锚点，
  一轮一轮往后滚，无需任何一次重算全量。

## 证据包（可移植、可离线核验）

`GET /api/audit/evidence/export` 把当前全部留存导出成一份证据包（单个 JSON）：

```json
{
  "formatVersion": "evidence-pack/v1",
  "exportedAt": "…", "recordCount": 5, "tailHash": "…",
  "records": [ …全部审计记录… ],
  "ruleSets": [ …判定当时所用的每个规则集版本… ]
}
```

- **表述**：记录 + 条数/整体指纹 + **判定当时所用的规则集**一起打包。规则随包走，
  核验时不依赖本服务当前加载什么规则。
- **独立核验（离线、无需部署本服务）**：`EvidencePackVerifier.verify(pack)` 是纯 Java、
  无 Spring 依赖；命令行工具 `EvidencePackCli` 直接核验包文件，核验三件事：
  哈希链完整性、条数与整体指纹一致、每条结论按包内当时规则复现与保存的结论一致。
- **兼容范围**：`formatVersion` 相同的包可互相导入/核验；格式升级会引入新版本号，
  不同版本号的包会被明确拒绝而不是误读。
- **导入续写**：`POST /api/audit/evidence/import` 把包导入**全新实例**（空账本）：
  先完整核验（不通过拒绝导入），通过后规则集登记进历史、记录落账，链尖恢复到包内位置；
  之后追加**接着原编号继续、不重号也不断档**，历史结论仍可按当时规则复现。
  非空账本拒绝导入，防止两段历史混接。

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
| GET  | `/api/audit/digest` | 生成当前留存位置的存证摘要（无锁快照） |
| POST | `/api/audit/digest/check` | 用摘要核对记录副本（识别改动与末尾整段删减） |
| POST | `/api/audit/verify/incremental` | 从可信摘要往后做增量核验 |
| GET  | `/api/audit/evidence/export` | 导出可移植证据包（含当时规则集） |
| POST | `/api/audit/evidence/import` | 核验并导入证据包（仅空账本），之后接着原编号续写 |
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

## 本地验证（测试覆盖）

`mvn test` 的日志按 `[业务覆盖] / [用例] / [结果]` 打印，覆盖：

| 测试类 | 业务场景 |
|---|---|
| `LedgerConcurrencyTest` | 8 线程并发写 800 条：序号唯一连续、读序=提交序、链校验通过 |
| `LedgerIntegrityTest` | 篡改/删除/调换历史记录均被检出并定位到具体 seq |
| `LedgerDigestTest` | 摘要与同内容副本一致；600 条并发追加期间生成 200 份摘要均钉在真实前缀上；末尾整段删减指出缺少的序号区间与条数；内容改动被检出；更长的副本不影响旧摘要核对 |
| `IncrementalVerificationTest` | 增量与整体核验结论一致；重算次数只随新增部分（100 与 1000 条历史下新增 3 条都只重算 3 次）；新增篡改、前缀改动、整链重算伪装、副本短于锚点均被检出；摘要逐轮接力 |
| `EvidencePackTest` | 导出后离线独立核验通过；JSON 文件往返可移植；篡改包被检出；重算整条链伪造结论被规则复现识破；导入全新实例后续写编号连续、链完整、结论可按当时规则复现；篡改包/非空账本拒绝导入 |
| `AlertForwarderTest` | 瞬时故障重试成功且只投递一次；持续故障进失败队列；重复提交+重复回执不重复投递；下游故障时接收不被拖慢 |
| `MalformedEventTest` | 缺字段/格式错/取值越界逐条拒收并说明原因；混合批量中坏的不影响好的、序号不断档 |
| `RuleReproductionTest` | 规则 v1→v2 升级后，历史记录仍按 v1 复现出当时结论 |
| `ApiIntegrationTest` | 本地起服务全链路：批量接收→留存→校验→异步转发→复现 |

## 本地把新能力跑一遍

全部在本机完成，不依赖外部服务或联网资源：

```bash
# 1. 启动服务
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080

# 2. 灌入若干事件
curl -X POST localhost:8080/api/audit/events -H 'Content-Type: application/json' -d '[
  {"eventId":"evt-1001","actor":"alice","action":"READ","resource":"doc-1","result":"SUCCESS","timestamp":"2026-10-02T01:00:00Z"},
  {"eventId":"evt-1002","actor":"bob","action":"DELETE","resource":"doc-2","result":"FAILURE","timestamp":"2026-10-02T01:00:01Z"}
]'

# 3. 生成存证摘要（可保存、可发布）
curl -s localhost:8080/api/audit/digest

# 4. 用摘要核对副本：把 records 原样送回应 matches=true；
#    删掉末尾几条再送回，会指出 missingFromSeq 与 missingCount
curl -s localhost:8080/api/audit/records > /tmp/copy.json
# （把 copy.json 与第 3 步的摘要拼成 {"digest":…,"records":…} POST 到 /api/audit/digest/check）

# 5. 再追加几条后做增量核验：trusted 用第 3 步的摘要，
#    records 用最新全量，recomputedHashes 只等于新增条数
curl -s -X POST localhost:8080/api/audit/verify/incremental \
  -H 'Content-Type: application/json' -d '{"trusted":<第3步摘要>,"records":<最新records>}'

# 6. 导出证据包并离线核验（不依赖运行中的服务）
curl -s localhost:8080/api/audit/evidence/export > pack.json
mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp "target/classes:$(cat target/cp.txt)" \
  com.github.feng111627.auditcomplianceservicejava.evidence.EvidencePackCli verify pack.json
# 退出码 0 = 核验通过；改动 pack.json 里任意字段再跑，应核验失败且退出码非 0

# 7. 导入续写：用全新实例（空账本）启动后
curl -X POST localhost:8080/api/audit/evidence/import \
  -H 'Content-Type: application/json' -d @pack.json
# 之后 POST 新事件，序号从包内最后一条继续，GET /api/audit/verify 仍 intact
```
