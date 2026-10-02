# 审计合规服务（本地可运行版）

接收审计事件 → 给出合规结论 → 顺序留存在可独立校验的账本上 → 把不合规事件异步转发给本地模拟下游。
**不依赖任何外部服务、真实凭据或联网资源**：存储用本地 JSONL 文件，下游用内存模拟器。

## 1. 构建与运行

要求 JDK 21+、Maven 3.6+（本机实测 JDK 25 也可）。

```bash
mvn spring-boot:run                 # 默认端口 8080（被占用时：-Dspring-boot.run.jvmArguments='-DSERVER_PORT=8099'）
mvn test                            # 运行全部 28 个单测，日志逐条打印业务模块/用例/结果
```

运行期数据默认写到工程根目录 `./audit-data/`（已在 `.gitignore` 忽略），可用配置覆盖：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `audit.data-dir` | `audit-data` | 账本、发件箱、规则快照目录 |
| `audit.rules-location` | `classpath:rules/default-rules.json` | 规则文件，支持 `file:` 外部路径 |
| `audit.forward-interval-millis` | `200` | 转发器轮询间隔 |
| `audit.backoff-base-millis` | `100` | 重试退避基数（指数退避 base·2^(n-1)） |
| `audit.max-attempts` | `5` | 最大尝试次数，达到后转死信 |

## 2. 合规规则模型（改规则不用改代码）

规则文件是普通 JSON，结构为 `RuleSet{version, eventSchemaVersion, rules[]}`：

```json
{
  "version": "v1",
  "eventSchemaVersion": "event-1.0",
  "rules": [
    {
      "id": "R-DENY-PROD-DELETE",
      "description": "任何操作者删除生产资源(prod- 前缀)均判为不合规",
      "decision": "DENY",
      "conditions": [
        { "field": "action",   "op": "eq",         "value": "DELETE" },
        { "field": "resource", "op": "startsWith", "value": "prod-" }
      ]
    }
  ]
}
```

- **一条规则内 conditions 是 AND**，全部命中才算该规则命中；规则按文件顺序求值，命中的规则全部列出。
- `decision`：`DENY`（命中 → 不合规）/ `ALLOW`；**没有命中任何规则时默认 COMPLIANT**。
- `field`：顶层 `actor / action / resource / result / eventId / timestamp`，或 `attributes.<任意自定义字段>`。
- `op`：`eq`、`neq`、`in`（逗号分隔白名单）、`startsWith`、`endsWith`、`contains`、`regex`。
- 结论里带 `matchedRuleIds` 与中文 `reasons`，**每条判定可解释**。
- 热刷新：`POST /api/admin/rules/reload` 重新读文件。
- **版本不可变保护**：每个版本在 `audit-data/rule-snapshots/<version>.json` 留存快照；
  用相同版本号提交不同内容会被拒绝（返回 400），改规则必须升版本号，防止历史结论被悄悄改变。

### 事件校验（畸形事件不静默、不连坐）

必填且非空白：`actor / action / resource / result`；`result ∈ {SUCCESS, FAILURE}`；
`action` 需为大写字母数字下划线短横线；`timestamp` 选填，但给出时必须是 ISO-8601。
批量接口对**逐条**返回 `accepted/rejected` 与各自拒因，一条非法不影响同批其它条目；
整个请求体不是合法 JSON 时返回 400 并说明解析错误。

## 3. 顺序留存与完整性校验

文件布局：

```
audit-data/
├── audit-ledger.jsonl     # 账本，每行一条 AuditRecord，只追加
├── audit-head.txt         # 独立头指针："<末条seq>:<末条entryHash>"
├── rule-snapshots/        # 各版本规则不可变快照
└── alerts/outbox.jsonl    # 告警发件箱
```

- **编号**：`seq` 从 1 开始。`append` 在单把锁内完成“分配编号 → 计算哈希 → 追加落盘 → 更新头指针”，
  并发写入编号不重复、不断档；读出顺序等于加锁提交顺序（乱序的 `timestamp` 仅作为数据，不影响留存顺序）。
  重启后按账本实际最大条数继续编号。
- **哈希链**（SHA-256，Hex）：
  - `contentHash = SHA256(规范化JSON(除两个哈希字段外的全部字段))`，规范化 JSON 字段顺序固定；
  - `entryHash   = SHA256(prevEntryHash + "|" + contentHash)`；
  - 首条 `prevEntryHash = 000…000`（64 个 0）。
- **独立校验** `GET /api/integrity`：只依据文件内容与头指针重新计算，不依赖内存状态，
  返回 `valid / recordCount / headHash / issues[]`，每个 issue 带类型、位置（seq）与说明：

| 问题类型 | 能发现的篡改 |
| --- | --- |
| `CONTENT_TAMPERED` | 记录任何字段被改动（或 entryHash 被伪造） |
| `CHAIN_BROKEN` | 相邻记录绑定被破坏——**调换两条**记录会在这里暴露 |
| `GAP` | **删除中间记录**造成编号断档（附带 seq 位置） |
| `TAIL_MISSING` / `HEAD_MISMATCH` | 光看账本本身发现不了的**删尾部**：独立头指针记录末条 seq+hash，对不上即报 |

### 历史结论按当时规则复现

每条记录都留存了 `decision.ruleVersion` 与 `eventSchemaVersion`。
`GET /api/replay` 用该版本的不可变快照重新判定并逐条比对状态与命中规则集合；
规则/事件结构升级后，只要老快照还在，老记录就复现出与当时一致的结论；
快照缺失或结论漂移会在 `mismatches[]` 中按 seq 列出。

## 4. 告警转发与失败处理语义

```
接收线程：校验 → 判定 → append 账本 → 若 NON_COMPLIANT 则 outbox.enqueue（仅本地落盘）后立即返回
后台线程：单线程定时扫描 PENDING → 调模拟下游 → 标 DELIVERED / 退避重试 / 转 DEAD
```

- **不拖慢接收**：接收路径不做任何“网络”调用，只做一次本地文件追加。
- **不丢**：PENDING 先持久化再投递；连不上/超时只增加 attempts 并按指数退避重试；
  进程重启后从 `outbox.jsonl` 恢复，未完成的继续投递。
- **不重**：成功（含下游返回的重复成功回执）立即标记 `DELIVERED`，后续轮询不再发送；
  下游自身也以 `seq` 为幂等键去重，双重保证同一条成功事件只投递一次。
- **可查询失败队列**：尝试次数达到 `audit.max-attempts` 转 `DEAD`，
  `GET /api/alerts/dead-letters` 可查（含 seq、attempts、lastError）；
  下游恢复后 `POST /api/alerts/dead-letters/{seq}/retry` 重新入队并立即尝试。
- 模拟下游（内存、不联网）支持四种模式，便于复现各类故障：
  `OK / UNREACHABLE / TIMEOUT / DUPLICATE_ACK`，还可注入“接下来失败 N 次”。

## 5. HTTP 接口一览

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/events` | 接收事件，体为 `{"events":[...]}` 或数组；逐条返回结论/拒因 |
| `GET  /api/records`、`GET /api/records/{seq}` | 按顺序读账本 / 读单条 |
| `GET  /api/integrity` | 独立完整性校验（问题定位到 seq） |
| `GET  /api/replay` | 按当时规则版本复现全部历史结论 |
| `GET  /api/alerts/pending`、`GET /api/alerts/dead-letters` | 待投递 / 死信告警 |
| `POST /api/alerts/dead-letters/{seq}/retry` | 死信重放 |
| `GET  /api/rules`、`POST /api/admin/rules/reload` | 查看当前规则与版本 / 热刷新 |
| `POST /api/test/downstream/mode`、`GET /api/test/downstream` | 测试用：故障注入与投递观测 |

### 30 秒手工验证示例

```bash
# 1) 混合批次：1 缺字段、1 合规、1 不合规（删除生产资源）
curl -s -X POST localhost:8080/api/events -H 'Content-Type: application/json' -d '{
  "events": [
    {"action":"READ","resource":"doc-1","result":"SUCCESS"},
    {"actor":"bob","action":"READ","resource":"doc-1","result":"SUCCESS"},
    {"actor":"eve","action":"DELETE","resource":"prod-db-1","result":"SUCCESS"}
  ]}'
# 2) 完整性与复现
curl -s localhost:8080/api/integrity
curl -s localhost:8080/api/replay
# 3) 下游故障 -> 死信 -> 恢复重放
curl -s -X POST localhost:8080/api/test/downstream/mode -H 'Content-Type: application/json' -d '{"mode":"UNREACHABLE"}'
curl -s -X POST localhost:8080/api/events -H 'Content-Type: application/json' -d '{"events":[{"actor":"x","action":"DELETE","resource":"prod-x","result":"SUCCESS"}]}'
sleep 6
curl -s localhost:8080/api/alerts/dead-letters
curl -s -X POST localhost:8080/api/test/downstream/mode -H 'Content-Type: application/json' -d '{"mode":"OK"}'
curl -s -X POST localhost:8080/api/alerts/dead-letters/1/retry
# 4) 篡改检测（直接改文件）
sed -i '2s/"actor":"[^"]*"/"actor":"HACKER"/' audit-data/audit-ledger.jsonl
curl -s localhost:8080/api/integrity   # valid=false 且指出 seq=2 CONTENT_TAMPERED
```

## 6. 测试覆盖与日志

`mvn test` 共 28 个用例（控制台逐条打印 `[业务测试] >>/<< 模块=… 用例=… 结果=…`）：

| 测试类 | 覆盖业务 |
| --- | --- |
| `MalformedEventValidationTest` | 缺字段/非法 result、action、timestamp/null 事件逐条拒收；非法事件不连坐；可配置规则的可解释结论 |
| `ConcurrentWriteTest` | 8 线程×125 并发：编号 1..1000 唯一不断档、读序=提交序；乱序时间戳；重启后续号 |
| `IntegrityVerificationTest` | 干净账本；内容篡改定位 seq；删中间 GAP；调换 CHAIN_BROKEN；删尾部 TAIL_MISSING/HEAD_MISMATCH；头指针被改 |
| `AlertForwardingTest` | 成功仅投一次；先失败后成功重试；持续故障进死信；死信重放；重复回执不重投；重启恢复 PENDING |
| `RuleUpgradeReplayTest` | 规则升版后新老事件各按各版本判定/复现；快照跨重启；同版本不同内容被拒 |
| `WebApiTest` | 畸形 JSON 返回 400；混合批次；完整性/单条查询；死信 API 全生命周期 |

## 7. 本地模拟的边界（设计取舍）

- 存储为本地文件（JSONL + 原子 tmp 重写），单机足够表达“顺序、可校验、可恢复”语义；
  换生产存储时只需替换 `AuditStore` / `AlertOutbox` 两个接口。
- 哈希链防的是**非授权篡改/删除/调换**并定位问题；它不是加密时间戳服务，
  头指针与账本在同一台机器上——需要更强防抵赖时可把 `headHash` 对外发布（或对接只追加外部设施）。
