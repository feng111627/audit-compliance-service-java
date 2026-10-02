package com.github.feng111627.auditcomplianceservicejava.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.auditcomplianceservicejava.alert.AlertForwarder;
import com.github.feng111627.auditcomplianceservicejava.alert.AlertOutbox;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.domain.IngestResponse;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleRepository;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleSet;
import com.github.feng111627.auditcomplianceservicejava.service.AuditIngestService;
import com.github.feng111627.auditcomplianceservicejava.service.ReplayReport;
import com.github.feng111627.auditcomplianceservicejava.service.ReplayService;
import com.github.feng111627.auditcomplianceservicejava.store.AuditStore;
import com.github.feng111627.auditcomplianceservicejava.store.IntegrityReport;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** REST 接口。 */
@RestController
@RequestMapping("/api")
public class AuditController {

    private final AuditIngestService ingestService;
    private final AuditStore store;
    private final RuleRepository ruleRepository;
    private final ReplayService replayService;
    private final AlertOutbox outbox;
    private final AlertForwarder forwarder;
    private final ObjectMapper objectMapper;

    public AuditController(AuditIngestService ingestService, AuditStore store,
                           RuleRepository ruleRepository, ReplayService replayService,
                           AlertOutbox outbox, AlertForwarder forwarder, ObjectMapper objectMapper) {
        this.ingestService = ingestService;
        this.store = store;
        this.ruleRepository = ruleRepository;
        this.replayService = replayService;
        this.outbox = outbox;
        this.forwarder = forwarder;
        this.objectMapper = objectMapper;
    }

    /**
     * 接收事件（单条 {"events":[...]} 或直接传数组）。
     * 手工解析 JSON：整体 JSON 非法时明确返回 400 与原因，而不是静默处理。
     */
    @PostMapping("/events")
    public ResponseEntity<?> ingest(@RequestBody String rawBody) {
        JsonNode root;
        try {
            root = objectMapper.readTree(rawBody);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "请求体不是合法 JSON",
                    "detail", e.getMessage() == null ? e.toString() : e.getMessage()));
        }
        JsonNode array = root.isArray() ? root : root.get("events");
        if (array == null || !array.isArray()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "缺少 events 数组",
                    "detail", "请求体应为 {\"events\":[...]} 或事件数组"));
        }

        List<AuditEvent> events = new ArrayList<>();
        for (JsonNode node : array) {
            if (node == null || node.isNull()) {
                events.add(null);
            } else if (node.isObject()) {
                events.add(objectMapper.convertValue(node, AuditEvent.class));
            } else {
                // 数组元素不是对象：放一个标记，由逐条校验给出拒因而不影响其它条目
                events.add(null);
            }
        }
        IngestResponse response = ingestService.ingest(events);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/records")
    public List<?> records() {
        return store.readAll();
    }

    @GetMapping("/records/{seq}")
    public ResponseEntity<?> record(@PathVariable long seq) {
        return store.findBySeq(seq)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(Map.of("error", "记录不存在", "seq", seq)));
    }

    @GetMapping("/integrity")
    public IntegrityReport integrity() {
        return store.verifyIntegrity();
    }

    @GetMapping("/replay")
    public ReplayReport replay() {
        return replayService.replayAll();
    }

    @GetMapping("/alerts/pending")
    public Object pending() {
        return outbox.pending();
    }

    @GetMapping("/alerts/dead-letters")
    public Object deadLetters() {
        return outbox.deadLetters();
    }

    @PostMapping("/alerts/dead-letters/{seq}/retry")
    public ResponseEntity<?> retryDeadLetter(@PathVariable long seq) {
        int updated = outbox.retryDeadLetter(seq);
        if (updated == 0) {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "未找到 seq=" + seq + " 的死信告警"));
        }
        // 重新入队后立即驱动一次，便于本地马上看到效果
        forwarder.drain();
        return ResponseEntity.ok(Map.of("seq", seq, "status", "重新入队 PENDING"));
    }

    @GetMapping("/rules")
    public Map<String, Object> rules() {
        RuleSet current = ruleRepository.current();
        return Map.of("currentVersion", current.version(),
                "eventSchemaVersion", current.eventSchemaVersion(),
                "versions", ruleRepository.versions(),
                "rules", current.rules());
    }

    @PostMapping("/admin/rules/reload")
    public ResponseEntity<?> reloadRules() {
        try {
            RuleSet ruleSet = ruleRepository.reload();
            return ResponseEntity.ok(Map.of(
                    "currentVersion", ruleSet.version(),
                    "eventSchemaVersion", ruleSet.eventSchemaVersion(),
                    "versions", ruleRepository.versions()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "规则刷新被拒绝", "detail", String.valueOf(e.getMessage())));
        }
    }
}
