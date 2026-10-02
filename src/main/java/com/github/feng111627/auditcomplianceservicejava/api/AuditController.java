package com.github.feng111627.auditcomplianceservicejava.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.feng111627.auditcomplianceservicejava.forward.AlertForwarder;
import com.github.feng111627.auditcomplianceservicejava.forward.DeadLetter;
import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.FieldViolation;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleProvider;
import com.github.feng111627.auditcomplianceservicejava.service.AuditService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REST 入口：批量接收事件、查询留存、完整性校验、结论复现、失败队列。
 * 批量接收时逐条解析与判定：单条畸形只影响该条，原因逐条返回。
 */
@RestController
@RequestMapping("/api")
public class AuditController {

    private final AuditService auditService;
    private final AuditLedger ledger;
    private final AlertForwarder forwarder;
    private final RuleProvider ruleProvider;

    public AuditController(AuditService auditService, AuditLedger ledger,
                           AlertForwarder forwarder, RuleProvider ruleProvider) {
        this.auditService = auditService;
        this.ledger = ledger;
        this.forwarder = forwarder;
        this.ruleProvider = ruleProvider;
    }

    /** 批量接收审计事件，逐条返回结论。 */
    @PostMapping("/audit/events")
    public BatchResponse ingest(@RequestBody List<JsonNode> batch) {
        List<AuditService.IngestResult> results = new ArrayList<>(batch.size());
        for (int i = 0; i < batch.size(); i++) {
            results.add(ingestOne(i, batch.get(i)));
        }
        long accepted = results.stream().filter(r -> r.verdict().status() != ComplianceStatus.REJECTED).count();
        return new BatchResponse(results.size(), accepted, results.size() - accepted, results);
    }

    /** 按写入顺序查询全部留存记录。 */
    @GetMapping("/audit/records")
    public List<AuditRecord> records() {
        return ledger.readAll();
    }

    /** 独立校验历史记录完整性。 */
    @GetMapping("/audit/verify")
    public VerificationReport verify() {
        return ledger.verify();
    }

    /** 按记录当时的规则版本复现结论并比对。 */
    @GetMapping("/audit/records/{seq}/reproduce")
    public ReproduceResponse reproduce(@PathVariable long seq) {
        AuditRecord record = ledger.readAll().stream()
                .filter(r -> r.seq() == seq).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("不存在 seq=" + seq + " 的记录"));
        ComplianceVerdict replayed = auditService.reproduce(record);
        return new ReproduceResponse(record.verdict(), replayed, auditService.reproduceMatches(record));
    }

    /** 查询转发失败队列。 */
    @GetMapping("/forward/dead-letters")
    public List<DeadLetter> deadLetters() {
        return forwarder.deadLetters();
    }

    /** 热加载规则文件（改规则不用改代码）。 */
    @PostMapping("/rules/reload")
    public Map<String, String> reloadRules() {
        ruleProvider.reload();
        return Map.of("currentVersion", ruleProvider.current().version());
    }

    private AuditService.IngestResult ingestOne(int index, JsonNode node) {
        AuditEvent event;
        String timestampError = null;
        try {
            if (node == null || !node.isObject()) {
                return rejected(index, null, "事件体为空或不是 JSON 对象");
            }
            Instant timestamp = null;
            JsonNode tsNode = node.get("timestamp");
            if (tsNode != null && tsNode.isTextual() && !tsNode.asText().isBlank()) {
                try {
                    timestamp = Instant.parse(tsNode.asText());
                } catch (DateTimeParseException e) {
                    timestampError = "timestamp 格式非法（应为 ISO-8601），实际值: " + tsNode.asText();
                }
            }
            Map<String, String> attributes = new LinkedHashMap<>();
            JsonNode attrs = node.get("attributes");
            if (attrs != null && attrs.isObject()) {
                attrs.fields().forEachRemaining(e -> attributes.put(e.getKey(), e.getValue().asText()));
            }
            event = new AuditEvent(
                    textOrNull(node, "eventId"), textOrNull(node, "actor"),
                    textOrNull(node, "action"), textOrNull(node, "resource"),
                    textOrNull(node, "result"), timestamp, attributes);
        } catch (Exception e) {
            return rejected(index, null, "事件解析失败: " + e.getMessage());
        }
        if (timestampError != null) {
            // 时间戳非法：只判定不落账，合并其他违规原因后拒收
            ComplianceVerdict dryRun = auditService.evaluateOnly(event);
            List<FieldViolation> violations = new ArrayList<>(dryRun.violations());
            violations.add(new FieldViolation("timestamp", "R0", timestampError));
            return new AuditService.IngestResult(index,
                    ComplianceVerdict.rejected(violations, dryRun.ruleVersion()), null);
        }
        return auditService.ingest(index, event);
    }

    private AuditService.IngestResult rejected(int index, String eventId, String reason) {
        return new AuditService.IngestResult(index,
                ComplianceVerdict.rejected(List.of(new FieldViolation("(event)", "R0", reason)),
                        ruleProvider.current().version()), null);
    }

    private String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }

    public record BatchResponse(int total, long accepted, long rejected,
                                List<AuditService.IngestResult> results) {
    }

    public record ReproduceResponse(ComplianceVerdict original, ComplianceVerdict replayed,
                                    boolean matches) {
    }
}
