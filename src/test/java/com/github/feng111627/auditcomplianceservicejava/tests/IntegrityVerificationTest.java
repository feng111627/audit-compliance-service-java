package com.github.feng111627.auditcomplianceservicejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.feng111627.auditcomplianceservicejava.alert.FileAlertOutbox;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.service.AuditIngestService;
import com.github.feng111627.auditcomplianceservicejava.store.FileAuditStore;
import com.github.feng111627.auditcomplianceservicejava.store.IntegrityReport;
import com.github.feng111627.auditcomplianceservicejava.tests.support.BusinessTestLogging;
import com.github.feng111627.auditcomplianceservicejava.tests.support.TestContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 业务：历史记录独立完整性校验 —— 篡改 / 删除 / 调换检测。
 */
@ExtendWith(BusinessTestLogging.class)
class IntegrityVerificationTest {

    private AuditEvent event(String actor, String action, String resource) {
        AuditEvent e = new AuditEvent();
        e.setActor(actor);
        e.setAction(action);
        e.setResource(resource);
        e.setResult("SUCCESS");
        return e;
    }

    private void seed(TestContext ctx, int count) {
        var outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var svc = new AuditIngestService(ctx.store, ctx.ruleRepository, ctx.ruleEngine, outbox);
        for (int i = 1; i <= count; i++) {
            svc.ingest(List.of(event("actor" + i, "READ", "res-" + i)));
        }
    }

    private Path ledger(Path dir) {
        return dir.resolve("audit-ledger.jsonl");
    }

    private List<String> lines(Path dir) throws Exception {
        return Files.readAllLines(ledger(dir));
    }

    private void writeLines(Path dir, List<String> lines) throws Exception {
        Files.writeString(ledger(dir), String.join(System.lineSeparator(), lines) + System.lineSeparator());
    }

    @Test
    @DisplayName("完整性校验: 未被改动的账本校验通过")
    void cleanLedgerIsValid(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        seed(ctx, 5);
        IntegrityReport report = ctx.store.verifyIntegrity();
        assertTrue(report.isValid(), () -> "干净账本不应有问题: " + report.getIssues());
        assertEquals(5, report.getRecordCount());
        System.out.println("干净账本校验通过，记录数=" + report.getRecordCount());
    }

    @Test
    @DisplayName("完整性校验: 改动第3条记录的操作者，报告 seq=3 处 CONTENT_TAMPERED")
    void contentTamperDetectedAndLocated(@TempDir Path dir) throws Exception {
        var ctx = TestContext.create(dir);
        seed(ctx, 5);

        List<String> lines = lines(dir);
        JsonNode node = ctx.objectMapper.readTree(lines.get(2));
        ((com.fasterxml.jackson.databind.node.ObjectNode) node.path("event")).put("actor", "attacker");
        lines.set(2, ctx.objectMapper.writeValueAsString(node));
        writeLines(dir, lines);

        IntegrityReport report = ctx.store.verifyIntegrity();
        assertFalse(report.isValid());
        assertTrue(report.getIssues().stream().anyMatch(i ->
                "CONTENT_TAMPERED".equals(i.type()) && i.seq() == 3L),
                "必须指出 seq=3 内容被篡改，实际: " + report.getIssues());
        System.out.println("篡改检测问题: " + report.getIssues());
    }

    @Test
    @DisplayName("完整性校验: 删除中间第2条记录，发现 GAP 断档并指向缺失位置")
    void middleDeletionDetected(@TempDir Path dir) throws Exception {
        var ctx = TestContext.create(dir);
        seed(ctx, 5);

        List<String> lines = lines(dir);
        lines.remove(1);
        writeLines(dir, lines);

        IntegrityReport report = ctx.store.verifyIntegrity();
        assertFalse(report.isValid());
        assertTrue(report.getIssues().stream().anyMatch(i ->
                        "GAP".equals(i.type()) && i.seq() == 2L),
                "必须发现 seq=2 断档，实际: " + report.getIssues());
        assertTrue(report.getIssues().stream().anyMatch(i -> "CHAIN_BROKEN".equals(i.type())));
        System.out.println("删中间记录检测问题: " + report.getIssues());
    }

    @Test
    @DisplayName("完整性校验: 调换第2/3条记录，哈希链断裂被发现")
    void swapDetected(@TempDir Path dir) throws Exception {
        var ctx = TestContext.create(dir);
        seed(ctx, 5);

        List<String> lines = lines(dir);
        String second = lines.get(1);
        lines.set(1, lines.get(2));
        lines.set(2, second);
        writeLines(dir, lines);

        IntegrityReport report = ctx.store.verifyIntegrity();
        assertFalse(report.isValid());
        assertTrue(report.getIssues().stream().anyMatch(i -> "CHAIN_BROKEN".equals(i.type())),
                "调换记录必须被哈希链发现，实际: " + report.getIssues());
        System.out.println("调换检测问题: " + report.getIssues());
    }

    @Test
    @DisplayName("完整性校验: 删除尾部2条记录，头指针暴露 TAIL_MISSING 与 HEAD_MISMATCH")
    void tailDeletionDetectedByHeadPointer(@TempDir Path dir) throws Exception {
        var ctx = TestContext.create(dir);
        seed(ctx, 5);

        List<String> lines = lines(dir);
        writeLines(dir, lines.subList(0, 3));

        IntegrityReport report = ctx.store.verifyIntegrity();
        assertFalse(report.isValid());
        assertTrue(report.getIssues().stream().anyMatch(i -> "TAIL_MISSING".equals(i.type())),
                "删尾部必须由头指针发现，实际: " + report.getIssues());
        assertTrue(report.getIssues().stream().anyMatch(i -> "HEAD_MISMATCH".equals(i.type())));
        System.out.println("删尾部检测问题: " + report.getIssues());
    }

    @Test
    @DisplayName("完整性校验: 头指针文件本身被改，发现 HEAD_MISMATCH")
    void headTamperingDetected(@TempDir Path dir) throws Exception {
        var ctx = TestContext.create(dir);
        seed(ctx, 3);

        Path head = dir.resolve("audit-head.txt");
        Files.writeString(head, "3:" + FileAuditStore.GENESIS_HASH);

        IntegrityReport report = ctx.store.verifyIntegrity();
        assertFalse(report.isValid());
        assertTrue(report.getIssues().stream().anyMatch(i -> "HEAD_MISMATCH".equals(i.type())),
                "头指针被改必须发现，实际: " + report.getIssues());
        System.out.println("头指针篡改检测问题: " + report.getIssues());
    }
}
