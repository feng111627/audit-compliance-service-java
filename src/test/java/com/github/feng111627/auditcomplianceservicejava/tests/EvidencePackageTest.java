package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.evidence.EvidencePackage;
import com.github.feng111627.auditcomplianceservicejava.evidence.EvidenceService;
import com.github.feng111627.auditcomplianceservicejava.evidence.EvidenceVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：证据包 —— 导出后离线独立核验；导回新实例接着原编号续写；结论与当时规则都能对得上。 */
class EvidencePackageTest {

    private AuditLedger ledgerA;
    private RuleProvider ruleProviderA;
    private EvidenceService evidenceA;

    private static AuditEvent event(int i, String result) {
        return new AuditEvent("evt-e-" + i, "alice", "READ", "doc-" + i,
                result, Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
    }

    @BeforeEach
    void setUp() {
        // 实例 A：不启动 Spring，纯手工组装，模拟一套正在运行的服务
        ledgerA = new AuditLedger("");
        ruleProviderA = new RuleProvider("classpath:rules.json");
        evidenceA = new EvidenceService(ledgerA, ruleProviderA);
        RuleEngine engine = new RuleEngine(ruleProviderA);
        for (int i = 1; i <= 5; i++) {
            AuditEvent event = event(i, i == 3 ? "FAILURE" : "SUCCESS");
            ledgerA.append(event, engine.evaluate(event));
        }
    }

    @Test
    void exportedPackagePassesOfflineVerification() {
        TestLog.suite("证据包：导出离线核验、导入续写、结论与规则对得上");
        TestLog.caseStart("导出证据包，离线核验应通过（链+摘要+结论复现）");
        EvidencePackage pkg = evidenceA.export();
        assertEquals(5, pkg.digest().recordCount());
        assertEquals(ledgerA.readAll().get(4).hash(), pkg.digest().tailHash());
        assertFalse(pkg.ruleSets().isEmpty(), "证据包必须内嵌判定所用规则集");

        VerificationReport report = EvidenceVerifier.verify(pkg);
        assertTrue(report.intact(), "离线核验应通过: " + report.anomalies());
        assertEquals(5, report.checkedCount());
        TestLog.pass("离线核验通过：5 条记录链完整、摘要一致、结论按内嵌规则 v1 复现一致");
    }

    @Test
    void tamperedPackageFailsOfflineVerification() {
        TestLog.caseStart("篡改证据包中第 3 条的结论（ACCEPTED 伪装 ALERT 记录），离线核验应发现");
        EvidencePackage pkg = evidenceA.export();
        List<AuditRecord> forged = new ArrayList<>(pkg.records());
        AuditRecord r3 = forged.get(2);
        forged.set(2, new AuditRecord(r3.seq(), r3.storedAt(), r3.event(),
                ComplianceVerdict.of(ComplianceStatus.ACCEPTED, r3.verdict().ruleVersion()),
                r3.prevHash(), r3.hash()));
        EvidencePackage tampered = new EvidencePackage(pkg.format(), pkg.formatVersion(),
                pkg.exportedAt(), pkg.digest(), forged, pkg.ruleSets());

        VerificationReport report = EvidenceVerifier.verify(tampered);
        assertFalse(report.intact());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("seq=3")),
                "应定位到 seq=3: " + report.anomalies());
        TestLog.pass("离线核验检出被改动的结论并定位 seq=3: " + report.anomalies());
    }

    @Test
    void importedInstanceContinuesNumberingAndReproducesVerdicts() {
        TestLog.caseStart("证据包导回全新实例：接着 seq=6 续写不重号不断档，结论按当时规则复现一致");
        EvidencePackage pkg = evidenceA.export();

        // 实例 B：全新账本 + 全新规则提供者（模拟另一套刚部署的服务）
        AuditLedger ledgerB = new AuditLedger("");
        RuleProvider ruleProviderB = new RuleProvider("classpath:rules.json");
        EvidenceService evidenceB = new EvidenceService(ledgerB, ruleProviderB);
        VerificationReport importReport = evidenceB.importPackage(pkg);
        assertTrue(importReport.intact());
        assertEquals(5, ledgerB.size());
        assertTrue(ledgerB.verify().intact(), "导入后账本自身完整性校验应通过");

        RuleEngine engineB = new RuleEngine(ruleProviderB);
        for (int i = 6; i <= 8; i++) {
            AuditEvent event = event(i, "SUCCESS");
            ledgerB.append(event, engineB.evaluate(event));
        }
        List<AuditRecord> all = ledgerB.readAll();
        assertEquals(8, all.size());
        for (int i = 0; i < 8; i++) {
            assertEquals(i + 1, all.get(i).seq(), "续写必须接着原编号、不重号不断档");
        }
        assertEquals(all.get(4).hash(), all.get(5).prevHash(),
                "续写第 6 条必须链接到导入链尾");
        assertTrue(ledgerB.verify().intact(), "续写后整本账完整性校验应通过");
        assertEquals(ledgerB.digest().tailHash(), all.get(7).hash());

        // 结论与当时规则对得上：导入的历史记录仍按 v1 复现出原结论
        for (AuditRecord record : all) {
            String version = record.verdict().ruleVersion();
            ComplianceVerdict replayed = RuleEngine.evaluate(record.event(),
                    ruleProviderB.byVersion(version).orElseThrow());
            assertEquals(record.verdict().status(), replayed.status(),
                    "seq=" + record.seq() + " 的结论应能按当时规则版本 " + version + " 复现");
            assertEquals(record.verdict().violations(), replayed.violations());
        }
        TestLog.pass("导入 5 条后续写 3 条：seq=1..8 连续、链校验通过、8 条结论均按当时规则复现一致");
    }

    @Test
    void tamperedOrNonEmptyImportIsRejected() {
        TestLog.caseStart("被篡改的证据包拒绝导入；非空账本拒绝导入");
        EvidencePackage pkg = evidenceA.export();
        List<AuditRecord> forged = ChainTools.forgeAndRecompute(pkg.records(), 0,
                new AuditEvent("evt-e-1", "mallory", "READ", "doc-1",
                        "SUCCESS", Instant.parse("2026-10-01T00:00:01Z"), Map.of()));
        EvidencePackage tampered = new EvidencePackage(pkg.format(), pkg.formatVersion(),
                pkg.exportedAt(), pkg.digest(), forged, pkg.ruleSets());

        AuditLedger ledgerB = new AuditLedger("");
        EvidenceService evidenceB = new EvidenceService(ledgerB, new RuleProvider("classpath:rules.json"));
        assertThrows(IllegalArgumentException.class, () -> evidenceB.importPackage(tampered),
                "篡改过的证据包必须被拒绝");
        assertEquals(0, ledgerB.size(), "拒绝导入后账本必须保持为空");

        evidenceB.importPackage(pkg);
        assertThrows(IllegalStateException.class, () -> evidenceB.importPackage(pkg),
                "非空账本必须拒绝再次导入，防止覆盖已有历史");
        assertEquals(5, ledgerB.size());
        TestLog.pass("篡改包被拒且账本保持为空；重复导入非空账本被拒，已有 5 条不受影响");
    }
}
