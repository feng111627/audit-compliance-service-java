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
| `AlertForwarderTest` | 瞬时故障重试成功且只投递一次；持续故障进失败队列；重复提交+重复回执不重复投递；下游故障时接收不被拖慢 |
| `MalformedEventTest` | 缺字段/格式错/取值越界逐条拒收并说明原因；混合批量中坏的不影响好的、序号不断档 |
| `RuleReproductionTest` | 规则 v1→v2 升级后，历史记录仍按 v1 复现出当时结论 |
| `ApiIntegrationTest` | 本地起服务全链路：批量接收→留存→校验→异步转发→复现 |
