package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.alert.FileAlertOutbox;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.domain.IngestResponse;
import com.github.feng111627.auditcomplianceservicejava.rule.FileRuleRepository;
import com.github.feng111627.auditcomplianceservicejava.service.AuditIngestService;
import com.github.feng111627.auditcomplianceservicejava.service.ReplayReport;
import com.github.feng111627.auditcomplianceservicejava.service.ReplayService;
import com.github.feng111627.auditcomplianceservicejava.tests.support.BusinessTestLogging;
import com.github.feng111627.auditcomplianceservicejava.tests.support.TestContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.DefaultResourceLoader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 业务：规则升级与历史结论复现。
 */
@ExtendWith(BusinessTestLogging.class)
class RuleUpgradeReplayTest {

    private AuditEvent readProdEvent() {
        AuditEvent e = new AuditEvent();
        e.setActor("alice");
        e.setAction("READ");
        e.setResource("prod-secret");
        e.setResult("SUCCESS");
        return e;
    }

    @Test
    @DisplayName("规则升级: v2新增规则后新事件按v2判定，v1时期的历史记录仍按v1复现出原结论")
    void historyReplaysWithRuleVersionInEffectAtThatTime(@TempDir Path dir) throws Exception {
        var ctx = TestContext.create(dir);
        var outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var svc = new AuditIngestService(ctx.store, ctx.ruleRepository, ctx.ruleEngine, outbox);

        // 1) v1 时期：READ prod-secret 没有规则命中，判合规
        IngestResponse r1 = svc.ingest(List.of(readProdEvent()));
        assertEquals(ComplianceStatus.COMPLIANT, r1.getResults().get(0).getComplianceStatus());
        assertEquals("v1", r1.getResults().get(0).getRuleVersion());

        // 2) 规则升级到 v2：任何对 prod- 资源的访问都拒绝
        Path v2 = dir.resolve("v2-rules.json");
        Files.writeString(v2, """
                {
                  "version": "v2",
                  "eventSchemaVersion": "event-1.0",
                  "rules": [
                    {
                      "id": "R-DENY-PROD-ACCESS",
                      "description": "v2: 访问任何生产资源都拒绝",
                      "decision": "DENY",
                      "conditions": [
                        { "field": "resource", "op": "startsWith", "value": "prod-" }
                      ]
                    }
                  ]
                }
                """);
        ctx.properties.setRulesLocation(v2.toUri().toString());
        ((FileRuleRepository) ctx.ruleRepository).reload();
        assertEquals("v2", ctx.ruleRepository.current().version());

        // 3) v2 时期同样事件判不合规
        IngestResponse r2 = svc.ingest(List.of(readProdEvent()));
        assertEquals(ComplianceStatus.NON_COMPLIANT, r2.getResults().get(0).getComplianceStatus());
        assertEquals("v2", r2.getResults().get(0).getRuleVersion());

        // 4) 复现全部历史：seq=1 用 v1 快照仍得合规，seq=2 用 v2 得不合规
        var replayService = new ReplayService(ctx.store, ctx.ruleRepository, ctx.ruleEngine);
        ReplayReport report = replayService.replayAll();
        assertTrue(report.isConsistent(), () -> "历史结论必须可复现: " + report.getMismatches());
        assertEquals(2, report.getChecked());
        assertEquals("v1", ctx.store.findBySeq(1).orElseThrow().getDecision().ruleVersion());
        assertEquals("v2", ctx.store.findBySeq(2).orElseThrow().getDecision().ruleVersion());
        System.out.println("复现结果: seq1(v1)=" + ctx.store.findBySeq(1).orElseThrow().getDecision().status()
                + ", seq2(v2)=" + ctx.store.findBySeq(2).orElseThrow().getDecision().status());
    }

    @Test
    @DisplayName("规则升级: 重启后从快照恢复历史版本，老记录依然可按老版本复现")
    void snapshotsPersistAcrossRestart(@TempDir Path dir) throws Exception {
        var ctx1 = TestContext.create(dir);
        var outbox1 = new FileAlertOutbox(ctx1.properties, ctx1.objectMapper);
        new AuditIngestService(ctx1.store, ctx1.ruleRepository, ctx1.ruleEngine, outbox1)
                .ingest(List.of(readProdEvent()));

        Path v2 = dir.resolve("v2-rules.json");
        Files.writeString(v2, """
                { "version": "v2", "eventSchemaVersion": "event-1.0", "rules": [] }
                """);
        ctx1.properties.setRulesLocation(v2.toUri().toString());
        ((FileRuleRepository) ctx1.ruleRepository).reload();

        // 重启：新仓库先加载快照目录，再加载当前 v2 文件
        var ctx2 = TestContext.create(dir);
        ctx2.properties.setRulesLocation(v2.toUri().toString());
        var repo2 = new FileRuleRepository(ctx2.properties, ctx2.objectMapper, new DefaultResourceLoader());

        assertEquals("v2", repo2.current().version());
        assertTrue(repo2.versions().containsAll(List.of("v1", "v2")));
        assertNotNull(repo2.getVersion("v1"), "v1 快照必须可恢复");
        var replay = new ReplayService(ctx2.store, repo2, ctx2.ruleEngine).replayAll();
        assertTrue(replay.isConsistent(), () -> "重启后历史仍可复现: " + replay.getMismatches());
        System.out.println("重启后可用规则版本: " + repo2.versions());
    }

    @Test
    @DisplayName("规则升级: 用相同版本号v1提交不同内容必须被拒绝，防止历史结论被悄悄改变")
    void sameVersionDifferentContentIsRejected(@TempDir Path dir) throws Exception {
        var ctx = TestContext.create(dir);

        Path evil = dir.resolve("evil-rules.json");
        Files.writeString(evil, """
                {
                  "version": "v1",
                  "eventSchemaVersion": "event-1.0",
                  "rules": [
                    { "id": "R-EVIL", "decision": "DENY",
                      "conditions": [ { "field": "action", "op": "eq", "value": "READ" } ] }
                  ]
                }
                """);
        ctx.properties.setRulesLocation(evil.toUri().toString());

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> ((FileRuleRepository) ctx.ruleRepository).reload());
        assertTrue(ex.getMessage().contains("v1"));
        System.out.println("同版本覆盖被拒绝: " + ex.getMessage());
    }
}
