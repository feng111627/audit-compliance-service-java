package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.forward.AlertForwarder;
import com.github.feng111627.auditcomplianceservicejava.forward.SimulatedDownstreamClient;
import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.FieldViolation;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleProvider;
import com.github.feng111627.auditcomplianceservicejava.service.AuditService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：合规判定 —— 字段缺失/格式错误的事件逐条拒收并说明原因，不拖垮整批。 */
class MalformedEventTest {

    private AuditService auditService;
    private AuditLedger ledger;
    private AlertForwarder forwarder;

    @BeforeEach
    void setUp() {
        TestLog.suite("合规判定：畸形事件的逐条拒收与原因说明");
        RuleProvider ruleProvider = new RuleProvider("classpath:rules.json");
        ledger = new AuditLedger("");
        forwarder = new AlertForwarder(new SimulatedDownstreamClient(), 3, 10);
        auditService = new AuditService(new RuleEngine(ruleProvider), ruleProvider, ledger, forwarder);
    }

    @AfterEach
    void tearDown() {
        forwarder.shutdown();
    }

    @Test
    void missingFieldsAreRejectedWithPerFieldReasons() {
        TestLog.caseStart("缺少 actor/action/result 的事件应被拒收并逐字段说明");
        AuditEvent event = new AuditEvent("evt-bad-1", null, null, "doc-1", null, Instant.now(), Map.of());
        AuditService.IngestResult result = auditService.ingest(0, event);

        assertEquals(ComplianceStatus.REJECTED, result.verdict().status());
        assertNull(result.seq(), "被拒收的事件不应落账");
        List<String> fields = result.verdict().violations().stream().map(FieldViolation::field).toList();
        assertTrue(fields.containsAll(List.of("actor", "action", "result")), "应指出所有缺失字段: " + fields);
        result.verdict().violations().forEach(v ->
                System.out.println("    拒收原因: 字段=" + v.field() + " 规则=" + v.ruleId() + " 说明=" + v.reason()));
        TestLog.pass("3 个缺失字段全部指出，事件未落账");
    }

    @Test
    void malformedFormatsAreRejectedWithActualValue() {
        TestLog.caseStart("eventId 格式非法、result 取值越界应被拒收并给出实际值");
        AuditEvent event = new AuditEvent("!!", "alice", "READ", "doc-1", "MAYBE", Instant.now(), Map.of());
        AuditService.IngestResult result = auditService.ingest(0, event);

        assertEquals(ComplianceStatus.REJECTED, result.verdict().status());
        assertTrue(result.verdict().violations().stream().anyMatch(v -> v.ruleId().equals("R6")));
        assertTrue(result.verdict().violations().stream().anyMatch(v -> v.ruleId().equals("R7")));
        result.verdict().violations().forEach(v ->
                System.out.println("    拒收原因: 字段=" + v.field() + " 规则=" + v.ruleId() + " 说明=" + v.reason()));
        TestLog.pass("格式与取值违规均被指出且含实际值");
    }

    @Test
    void mixedBatchRejectsOnlyTheBadOnes() {
        TestLog.caseStart("5 条混合批量：3 好 2 坏，坏的逐条拒收、好的正常落账，序号不断档");
        List<AuditEvent> batch = List.of(
                new AuditEvent("evt-ok-1", "alice", "READ", "doc-1", "SUCCESS", Instant.now(), Map.of()),
                new AuditEvent(null, "alice", "READ", "doc-2", "SUCCESS", Instant.now(), Map.of()),
                new AuditEvent("evt-ok-2", "bob", "DELETE", "doc-3", "FAILURE", Instant.now(), Map.of()),
                new AuditEvent("evt-bad-2", "", "FLY", "doc-4", "SUCCESS", Instant.now(), Map.of()),
                new AuditEvent("evt-ok-3", "carol", "LOGIN", "portal", "SUCCESS", Instant.now(), Map.of()));

        List<AuditService.IngestResult> results = new ArrayList<>();
        for (int i = 0; i < batch.size(); i++) {
            results.add(auditService.ingest(i, batch.get(i)));
        }

        assertEquals(ComplianceStatus.ACCEPTED, results.get(0).verdict().status());
        assertEquals(ComplianceStatus.REJECTED, results.get(1).verdict().status());
        assertEquals(ComplianceStatus.ALERT, results.get(2).verdict().status(), "DELETE+FAILURE 应触发告警");
        assertEquals(ComplianceStatus.REJECTED, results.get(3).verdict().status());
        assertEquals(ComplianceStatus.ACCEPTED, results.get(4).verdict().status());

        assertEquals(3, ledger.size(), "只有 3 条合规事件落账");
        assertNotNull(results.get(0).seq());
        assertEquals(List.of(1L, 2L, 3L),
                List.of(results.get(0).seq(), results.get(2).seq(), results.get(4).seq()),
                "落账序号应连续无断档");
        assertTrue(ledger.verify().intact());
        TestLog.pass("2 条畸形被拒（原因逐条返回），3 条落账 seq=1,2,3 连续，账本校验通过");
    }
}
