package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.DigestVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.LedgerVerifier;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.DigestCheckReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：摘要核对副本 —— 一致副本确认同一份内容；末尾整段删减、内容改动均被识别并说清。 */
class DigestCopyCheckTest {

    private LedgerDigest digest;
    private List<AuditRecord> original;

    @BeforeEach
    void setUp() {
        AuditLedger ledger = new AuditLedger("");
        for (int i = 1; i <= 5; i++) {
            ledger.append(new AuditEvent("evt-c-" + i, "alice", "READ", "doc-" + i,
                    "SUCCESS", Instant.parse("2026-10-01T00:00:0" + i + "Z"), Map.of()),
                    ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        digest = ledger.digest();
        original = ledger.readAll();
    }

    @Test
    void identicalCopyMatches() {
        TestLog.caseStart("完整副本与摘要核对，应确认两边是同一份内容");
        DigestCheckReport report = DigestVerifier.check(digest, original);
        assertTrue(report.matches(), "完整副本应核对一致: " + report.details());
        assertEquals(5, report.digestCount());
        assertEquals(5, report.copyCount());
        assertEquals(0, report.missingCount());
        TestLog.pass(report.details().toString());
    }

    @Test
    void truncatedTailIsDetectedWithMissingRange() {
        TestLog.caseStart("副本末尾整段删掉 2 条（自身仍连贯），应被发现并说清缺了哪些");
        List<AuditRecord> truncated = new ArrayList<>(original.subList(0, 3));
        assertTrue(LedgerVerifier.verify(truncated).intact(),
                "前提：截断后的副本自身链校验是连贯的，单看副本发现不了问题");

        DigestCheckReport report = DigestVerifier.check(digest, truncated);
        assertFalse(report.matches(), "截断副本不能当成完好");
        assertEquals(2, report.missingCount());
        assertTrue(report.details().stream().anyMatch(d -> d.contains("seq=4") && d.contains("seq=5")
                        && d.contains("缺失")),
                "应说清缺少 seq=4 到 seq=5: " + report.details());
        TestLog.pass("检出末尾缺失 2 条: " + report.details());
    }

    @Test
    void contentModificationIsDetected() {
        TestLog.caseStart("篡改副本中第 2 条内容（不重算链），应被发现");
        List<AuditRecord> copy = new ArrayList<>(original);
        AuditRecord r2 = copy.get(1);
        AuditEvent forged = new AuditEvent(r2.event().eventId(), "mallory", r2.event().action(),
                r2.event().resource(), r2.event().result(), r2.event().timestamp(), r2.event().attributes());
        copy.set(1, new AuditRecord(r2.seq(), r2.storedAt(), forged, r2.verdict(), r2.prevHash(), r2.hash()));

        DigestCheckReport report = DigestVerifier.check(digest, copy);
        assertFalse(report.matches());
        assertTrue(report.details().stream().anyMatch(d -> d.contains("篡改")),
                "应指出内容被篡改: " + report.details());
        TestLog.pass("检出内容改动: " + report.details());
    }

    @Test
    void recomputedChainForgeryIsDetected() {
        TestLog.caseStart("篡改后把整条哈希链重算伪装自洽，指纹比对仍应发现");
        AuditEvent forged = new AuditEvent("evt-c-2", "mallory", "DELETE", "doc-2",
                "SUCCESS", Instant.parse("2026-10-01T00:00:02Z"), Map.of());
        List<AuditRecord> forgedCopy = ChainTools.forgeAndRecompute(original, 1, forged);
        assertTrue(LedgerVerifier.verify(forgedCopy).intact(),
                "前提：重算后的伪装副本自身链校验完全通过");

        DigestCheckReport report = DigestVerifier.check(digest, forgedCopy);
        assertFalse(report.matches(), "重算伪装也逃不过摘要指纹比对");
        assertTrue(report.details().stream().anyMatch(d -> d.contains("指纹") && d.contains("不符")),
                "应指出整体指纹与摘要不符: " + report.details());
        TestLog.pass("检出重算伪装: " + report.details());
    }
}
