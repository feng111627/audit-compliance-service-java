package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.forward.AlertForwarder;
import com.github.feng111627.auditcomplianceservicejava.forward.SimulatedDownstreamClient;
import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleProvider;
import com.github.feng111627.auditcomplianceservicejava.service.AuditService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：合规判定 —— 规则升级后，历史记录仍按当时版本复现当时的结论。 */
class RuleReproductionTest {

    private static final String RULES_V1 = """
            { "version": "v1", "rules": [
              { "id": "R1", "type": "REQUIRED", "field": "actor", "message": "actor 缺失" },
              { "id": "R2", "type": "ALLOWED_VALUES", "field": "action",
                "values": ["READ", "WRITE"], "message": "action 不允许" }
            ] }""";

    /** v2 把 WRITE 从允许集合中移除：同样的事件在新规则下会被拒。 */
    private static final String RULES_V2 = """
            { "version": "v2", "rules": [
              { "id": "R1", "type": "REQUIRED", "field": "actor", "message": "actor 缺失" },
              { "id": "R2", "type": "ALLOWED_VALUES", "field": "action",
                "values": ["READ"], "message": "action 不允许" }
            ] }""";

    private AlertForwarder forwarder;

    @TempDir
    Path tempDir;

    @AfterEach
    void tearDown() {
        if (forwarder != null) {
            forwarder.shutdown();
        }
    }

    @Test
    void historicalRecordReproducesVerdictWithRulesAtThatTime() throws Exception {
        TestLog.suite("合规判定：规则升级后的历史结论复现");
        TestLog.caseStart("v1 规则下落账的事件，规则升级到 v2 后仍按 v1 复现出相同结论");

        Path rulesFile = tempDir.resolve("rules.json");
        Files.writeString(rulesFile, RULES_V1);
        RuleProvider ruleProvider = new RuleProvider(rulesFile.toUri().toString());
        AuditLedger ledger = new AuditLedger("");
        forwarder = new AlertForwarder(new SimulatedDownstreamClient(), 3, 10);
        AuditService auditService = new AuditService(new RuleEngine(ruleProvider), ruleProvider, ledger, forwarder);

        AuditEvent event = new AuditEvent("evt-hist-1", "alice", "WRITE", "doc-1",
                "SUCCESS", Instant.now(), Map.of());
        AuditService.IngestResult atIngest = auditService.ingest(0, event);
        assertEquals(ComplianceStatus.ACCEPTED, atIngest.verdict().status(), "v1 下 WRITE 应被接受");
        assertEquals("v1", atIngest.verdict().ruleVersion());
        System.out.println("    落账时结论: status=" + atIngest.verdict().status()
                + " ruleVersion=" + atIngest.verdict().ruleVersion());

        // 规则升级：改文件 + 热加载，不改代码
        Files.writeString(rulesFile, RULES_V2);
        ruleProvider.reload();
        assertEquals("v2", ruleProvider.current().version());
        assertEquals(ComplianceStatus.REJECTED,
                new RuleEngine(ruleProvider).evaluate(event).status(),
                "同一事件在 v2 下应被拒（WRITE 不再允许）");
        System.out.println("    规则升级后当前结论: status=REJECTED ruleVersion=v2（符合预期，新规则更严）");

        AuditRecord record = ledger.readAll().get(0);
        assertTrue(auditService.reproduceMatches(record), "历史记录应能按 v1 复现出当时结论");
        assertEquals(ComplianceStatus.ACCEPTED, auditService.reproduce(record).status());
        assertEquals("v1", auditService.reproduce(record).ruleVersion());
        TestLog.pass("历史记录 seq=1 按 v1 复现结论 ACCEPTED，与落账时一致；当前规则 v2 判定为 REJECTED，互不影响");
    }
}
