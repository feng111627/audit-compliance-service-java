package com.github.feng111627.auditcomplianceservicejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.feng111627.auditcomplianceservicejava.evidence.EvidencePackVerifier;
import com.github.feng111627.auditcomplianceservicejava.evidence.EvidenceService;
import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.EvidencePack;
import com.github.feng111627.auditcomplianceservicejava.model.EvidencePackReport;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleProvider;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：证据包 —— 可移植导出、离线独立核验、导入后接着原编号继续追加。 */
class EvidencePackTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    /** 用真实规则引擎造 6 条记录（含 ACCEPTED 与 ALERT 两种结论）。 */
    private static AuditLedger ledgerWithRealVerdicts(RuleEngine engine) {
        AuditLedger ledger = new AuditLedger("");
        String[] results = {"SUCCESS", "FAILURE", "SUCCESS", "DENIED", "SUCCESS", "SUCCESS"};
        String[] actions = {"READ", "READ", "DELETE", "LOGIN", "EXPORT", "READ"};
        for (int i = 1; i <= 6; i++) {
            AuditEvent event = new AuditEvent("evt-e-" + i, "alice", actions[i - 1], "doc-" + i,
                    results[i - 1], Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
            ComplianceVerdict verdict = engine.evaluate(event);
            assertTrue(verdict.status() != ComplianceStatus.REJECTED, "造数事件不应被拒收");
            ledger.append(event, verdict);
        }
        return ledger;
    }

    @Test
    void exportedPackVerifiesOffline() {
        TestLog.suite("证据包：导出、离线独立核验、篡改识别、导入续写");
        TestLog.caseStart("导出证据包后不依赖服务独立核验，应通过且逐条结论复现一致");
        RuleProvider ruleProvider = new RuleProvider("classpath:rules.json");
        EvidenceService service = new EvidenceService(
                ledgerWithRealVerdicts(new RuleEngine(ruleProvider)), ruleProvider);

        EvidencePack pack = service.exportPack();
        assertEquals(EvidencePack.FORMAT_VERSION, pack.formatVersion());
        assertEquals(6, pack.recordCount());
        assertEquals(1, pack.ruleSets().size(), "判定用过的规则集版本应随包携带");
        assertEquals("v1", pack.ruleSets().get(0).version());

        // 独立核验：只用 EvidencePackVerifier，不碰任何 Spring 组件
        EvidencePackReport report = EvidencePackVerifier.verify(pack);
        assertTrue(report.intact(), "离线核验应通过: " + report.anomalies());
        assertEquals(6, report.verdictsReproduced());
        TestLog.pass("证据包 6 条记录离线核验通过，6 条结论按包内 v1 规则复现全部一致");
    }

    @Test
    void packSurvivesJsonFileRoundTrip() throws Exception {
        TestLog.caseStart("证据包序列化成 JSON 文件再读回，核验仍应通过（可移植性）");
        RuleProvider ruleProvider = new RuleProvider("classpath:rules.json");
        EvidenceService service = new EvidenceService(
                ledgerWithRealVerdicts(new RuleEngine(ruleProvider)), ruleProvider);
        EvidencePack pack = service.exportPack();

        String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(pack);
        EvidencePack readBack = MAPPER.readValue(json, EvidencePack.class);
        EvidencePackReport report = EvidencePackVerifier.verify(readBack);
        assertTrue(report.intact(), "JSON 往返后核验应通过: " + report.anomalies());
        assertEquals(pack.tailHash(), readBack.tailHash());
        TestLog.pass("证据包 JSON 序列化/反序列化往返后核验通过，可作为文件带走");
    }

    @Test
    void tamperedPackIsDetectedOffline() {
        TestLog.caseStart("包内第 2 条记录被改动，离线核验应发现");
        RuleProvider ruleProvider = new RuleProvider("classpath:rules.json");
        EvidenceService service = new EvidenceService(
                ledgerWithRealVerdicts(new RuleEngine(ruleProvider)), ruleProvider);
        EvidencePack pack = service.exportPack();

        List<AuditRecord> records = new ArrayList<>(pack.records());
        AuditRecord original = records.get(1);
        AuditEvent forged = new AuditEvent(original.event().eventId(), "mallory",
                original.event().action(), original.event().resource(), original.event().result(),
                original.event().timestamp(), original.event().attributes());
        records.set(1, new AuditRecord(original.seq(), original.storedAt(), forged,
                original.verdict(), original.prevHash(), original.hash()));
        EvidencePack tampered = new EvidencePack(pack.formatVersion(), pack.exportedAt(),
                pack.recordCount(), pack.tailHash(), records, pack.ruleSets());

        EvidencePackReport report = EvidencePackVerifier.verify(tampered);
        assertFalse(report.intact());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("篡改")),
                "应发现记录被改动: " + report.anomalies());
        TestLog.pass("篡改的证据包被离线核验检出: " + report.anomalies());
    }

    @Test
    void forgedVerdictIsCaughtByRuleReproduction() {
        TestLog.caseStart("改动者把事件 actor 清空并重算整条链伪装完好，结论复现应识破");
        RuleProvider ruleProvider = new RuleProvider("classpath:rules.json");
        EvidenceService service = new EvidenceService(
                ledgerWithRealVerdicts(new RuleEngine(ruleProvider)), ruleProvider);
        EvidencePack pack = service.exportPack();

        // 把第 3 条 actor 清空，并从该条起重算整条哈希链：链本身自洽，
        // 但保存的结论(ACCEPTED/ALERT)与按当时规则复现的结论(REJECTED)必然不一致
        List<AuditRecord> records = new ArrayList<>(pack.records());
        String prev = records.get(1).hash();
        for (int i = 2; i < records.size(); i++) {
            AuditRecord r = records.get(i);
            AuditEvent ev = i == 2
                    ? new AuditEvent(r.event().eventId(), "", r.event().action(),
                            r.event().resource(), r.event().result(), r.event().timestamp(),
                            r.event().attributes())
                    : r.event();
            String hash = RecordHasher.hash(r.seq(), ev, r.verdict(), prev);
            records.set(i, new AuditRecord(r.seq(), r.storedAt(), ev, r.verdict(), prev, hash));
            prev = hash;
        }
        EvidencePack forged = new EvidencePack(pack.formatVersion(), pack.exportedAt(),
                pack.recordCount(), prev, records, pack.ruleSets());

        EvidencePackReport report = EvidencePackVerifier.verify(forged);
        assertFalse(report.intact());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("复现不一致")),
                "应按当时规则复现识破伪造结论: " + report.anomalies());
        TestLog.pass("规则随包带走，伪造的结论被复现比对识破: " + report.anomalies());
    }

    @Test
    void importedInstanceContinuesSequenceWithoutGaps() {
        TestLog.caseStart("证据包导入全新实例后接着追加，编号连续、链完整、结论可复现");
        RuleProvider sourceRules = new RuleProvider("classpath:rules.json");
        RuleEngine sourceEngine = new RuleEngine(sourceRules);
        EvidenceService source = new EvidenceService(ledgerWithRealVerdicts(sourceEngine), sourceRules);
        EvidencePack pack = source.exportPack();

        // 全新实例：新账本 + 新规则提供者（模拟另一套部署把包导回来）
        AuditLedger importedLedger = new AuditLedger("");
        RuleProvider importedRules = new RuleProvider("classpath:rules.json");
        EvidenceService target = new EvidenceService(importedLedger, importedRules);
        EvidencePackReport importReport = target.importPack(pack);
        assertTrue(importReport.intact());
        assertEquals(6, importedLedger.size());

        // 接着原编号继续追加
        RuleEngine importedEngine = new RuleEngine(importedRules);
        for (int i = 7; i <= 9; i++) {
            AuditEvent event = new AuditEvent("evt-e-" + i, "bob", "READ", "doc-" + i,
                    "SUCCESS", Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
            importedLedger.append(event, importedEngine.evaluate(event));
        }
        List<AuditRecord> all = importedLedger.readAll();
        assertEquals(9, all.size());
        for (int i = 0; i < 9; i++) {
            assertEquals(i + 1, all.get(i).seq(), "导入后续写编号应连续不重号");
        }
        assertEquals(pack.tailHash(), all.get(5).hash(), "第 6 条仍是包内链尖");
        assertEquals(pack.tailHash(), all.get(6).prevHash(), "第 7 条应链接到包内链尖，不断档");
        assertTrue(importedLedger.verify().intact(), "导入+续写后整体校验应通过");
        assertEquals(9, importedLedger.digest().recordCount());

        // 导入实例上按当时规则复现历史结论，与原来对得上
        AuditRecord imported = all.get(2);
        ComplianceVerdict replayed = importedEngine.evaluate(
                imported.event(), importedRules.byVersion("v1").orElseThrow());
        assertEquals(imported.verdict().status(), replayed.status());
        assertEquals(imported.verdict().violations(), replayed.violations());
        TestLog.pass("导入 6 条后续写 3 条：seq=1..9 连续、链校验通过、历史结论按当时规则复现一致");
    }

    @Test
    void importRejectsTamperedPackAndNonEmptyLedger() {
        TestLog.caseStart("篡改的包应被拒绝导入；非空账本应拒绝导入");
        RuleProvider sourceRules = new RuleProvider("classpath:rules.json");
        EvidenceService source = new EvidenceService(
                ledgerWithRealVerdicts(new RuleEngine(sourceRules)), sourceRules);
        EvidencePack pack = source.exportPack();

        // 篡改的包：改条数声明
        EvidencePack tampered = new EvidencePack(pack.formatVersion(), pack.exportedAt(),
                pack.recordCount() + 1, pack.tailHash(), pack.records(), pack.ruleSets());
        EvidenceService target = new EvidenceService(new AuditLedger(""),
                new RuleProvider("classpath:rules.json"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> target.importPack(tampered));
        System.out.println("    篡改包导入被拒: " + e.getMessage());

        // 非空账本
        target.importPack(pack);
        IllegalStateException e2 = assertThrows(IllegalStateException.class,
                () -> target.importPack(pack));
        System.out.println("    非空账本导入被拒: " + e2.getMessage());
        TestLog.pass("核验未通过的包进不来；已导入过的账本拒绝重复导入");
    }
}
