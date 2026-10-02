package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.alert.AlertOutbox;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.domain.IngestResponse;
import com.github.feng111627.auditcomplianceservicejava.service.AuditIngestService;
import com.github.feng111627.auditcomplianceservicejava.tests.support.BusinessTestLogging;
import com.github.feng111627.auditcomplianceservicejava.tests.support.TestContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * 业务：审计事件接收与合规判定 —— 畸形事件处理。
 */
@ExtendWith(BusinessTestLogging.class)
class MalformedEventValidationTest {

    private AuditIngestService newService(TestContext ctx) {
        return new AuditIngestService(ctx.store, ctx.ruleRepository, ctx.ruleEngine, mock(AlertOutbox.class));
    }

    private AuditEvent event(String actor, String action, String resource, String result, String ts) {
        AuditEvent e = new AuditEvent();
        e.setActor(actor);
        e.setAction(action);
        e.setResource(resource);
        e.setResult(result);
        e.setTimestamp(ts);
        return e;
    }

    @Test
    @DisplayName("接收合规判定: 缺失必填字段的事件被逐条拒收并说明全部缺失字段，不静默放行")
    void missingFieldsRejectedWithReasons(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        var svc = newService(ctx);

        AuditEvent noActor = event(null, "READ", "doc-1", "SUCCESS", null);
        AuditEvent emptyAction = event("alice", "  ", "doc-1", "SUCCESS", null);
        IngestResponse resp = svc.ingest(List.of(noActor, emptyAction));

        assertEquals(0, resp.getAcceptedCount());
        assertEquals(2, resp.getRejectedCount());
        assertTrue(resp.getResults().get(0).getRejectionReasons().stream()
                .anyMatch(r -> r.contains("actor")));
        assertTrue(resp.getResults().get(1).getRejectionReasons().stream()
                .anyMatch(r -> r.contains("action")));
        assertEquals(0, ctx.store.readAll().size(), "被拒事件不得写入账本");
        System.out.println("拒因示例: " + resp.getResults().get(0).getRejectionReasons());
    }

    @Test
    @DisplayName("接收合规判定: result/action/timestamp 格式非法分别给出明确拒因")
    void badFormatFieldsRejected(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        var svc = newService(ctx);

        List<String> allReasons = new ArrayList<>();
        allReasons.addAll(svc.ingest(List.of(event("a", "READ", "r", "MAYBE", null)))
                .getResults().get(0).getRejectionReasons());
        allReasons.addAll(svc.ingest(List.of(event("a", "lowercase", "r", "SUCCESS", null)))
                .getResults().get(0).getRejectionReasons());
        allReasons.addAll(svc.ingest(List.of(event("a", "READ", "r", "SUCCESS", "2026/10/02 10:00")))
                .getResults().get(0).getRejectionReasons());

        assertTrue(allReasons.stream().anyMatch(r -> r.contains("result")));
        assertTrue(allReasons.stream().anyMatch(r -> r.contains("action")));
        assertTrue(allReasons.stream().anyMatch(r -> r.contains("timestamp")));
        System.out.println("格式类拒因: " + allReasons);
    }

    @Test
    @DisplayName("接收合规判定: 同批中畸形事件不连坐，合法事件仍接收留存并给出结论")
    void malformedEventDoesNotFailBatch(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        var svc = newService(ctx);

        AuditEvent bad = event(null, "READ", "r", "SUCCESS", null);
        AuditEvent good = event("bob", "READ", "doc-2", "SUCCESS", null);
        IngestResponse resp = svc.ingest(List.of(bad, good));

        assertEquals(1, resp.getAcceptedCount());
        assertEquals(1, resp.getRejectedCount());
        assertFalse(resp.getResults().get(0).isAccepted());
        assertTrue(resp.getResults().get(1).isAccepted());
        assertEquals(1L, resp.getResults().get(1).getSeq());
        assertEquals(ComplianceStatus.COMPLIANT, resp.getResults().get(1).getComplianceStatus());
        assertEquals("v1", resp.getResults().get(1).getRuleVersion());
        assertEquals(1, ctx.store.readAll().size());
    }

    @Test
    @DisplayName("接收合规判定: null 事件被拒收且不影响后续条目")
    void nullEventRejected(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        var svc = newService(ctx);

        IngestResponse resp = svc.ingest(java.util.Arrays.asList(null, event("bob", "READ", "r", "SUCCESS", null)));
        assertEquals(1, resp.getAcceptedCount());
        assertEquals(1, resp.getRejectedCount());
        assertTrue(resp.getResults().get(0).getRejectionReasons().get(0).contains("null"));
    }

    @Test
    @DisplayName("接收合规判定: 命中可配置拒绝规则判不合规，未命中默认合规（结论可解释）")
    void configurableRulesProduceExplainableDecisions(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        var svc = newService(ctx);

        AuditEvent prodDelete = event("alice", "DELETE", "prod-db-1", "SUCCESS", null);
        AuditEvent testDelete = event("alice", "DELETE", "test-db-1", "SUCCESS", null);
        AuditEvent rootFail = event("root", "LOGIN", "console", "FAILURE", null);

        IngestResponse resp = svc.ingest(List.of(prodDelete, testDelete, rootFail));
        assertEquals(ComplianceStatus.NON_COMPLIANT, resp.getResults().get(0).getComplianceStatus());
        assertTrue(resp.getResults().get(0).getReasons().get(0).contains("R-DENY-PROD-DELETE"));
        assertEquals(ComplianceStatus.COMPLIANT, resp.getResults().get(1).getComplianceStatus());
        assertEquals(ComplianceStatus.NON_COMPLIANT, resp.getResults().get(2).getComplianceStatus());
        System.out.println("不合规解释: " + resp.getResults().get(0).getReasons());
    }
}
