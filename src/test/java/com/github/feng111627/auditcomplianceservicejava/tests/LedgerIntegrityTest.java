package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.LedgerVerifier;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：审计留存 —— 历史记录被篡改、删除、调换时，独立校验必须发现并指出具体记录。 */
class LedgerIntegrityTest {

    private AuditLedger ledger;

    @BeforeEach
    void setUp() {
        ledger = new AuditLedger("");
        for (int i = 1; i <= 5; i++) {
            ledger.append(new AuditEvent("evt-000" + i, "alice", "READ", "doc-" + i,
                    "SUCCESS", Instant.parse("2026-10-01T00:00:0" + i + "Z"), Map.of()),
                    ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
    }

    @Test
    void intactLedgerPassesVerification() {
        TestLog.suite("审计留存：完整性校验对篡改/删除/调换的检测");
        TestLog.caseStart("未改动的账本校验应通过");
        VerificationReport report = ledger.verify();
        assertTrue(report.intact());
        TestLog.pass("5 条原始记录校验通过，intact=true");
    }

    @Test
    void tamperedRecordIsDetectedAndLocated() {
        TestLog.caseStart("篡改第 3 条的 actor，校验应发现并指出 seq=3");
        List<AuditRecord> records = new ArrayList<>(ledger.readAll());
        AuditRecord original = records.get(2);
        AuditEvent forged = new AuditEvent(original.event().eventId(), "mallory",
                original.event().action(), original.event().resource(), original.event().result(),
                original.event().timestamp(), original.event().attributes());
        records.set(2, new AuditRecord(original.seq(), original.storedAt(), forged,
                original.verdict(), original.prevHash(), original.hash()));

        VerificationReport report = LedgerVerifier.verify(records);
        assertFalse(report.intact());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("篡改") && a.contains("seq=3")),
                "应指出 seq=3 被篡改: " + report.anomalies());
        TestLog.pass("检出篡改并定位: " + report.anomalies());
    }

    @Test
    void deletedRecordIsDetectedAndLocated() {
        TestLog.caseStart("删除第 3 条，校验应发现断档与链断裂");
        List<AuditRecord> records = new ArrayList<>(ledger.readAll());
        records.remove(2);

        VerificationReport report = LedgerVerifier.verify(records);
        assertFalse(report.intact());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("断档")),
                "应发现序号断档: " + report.anomalies());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("链断裂")),
                "应发现哈希链断裂: " + report.anomalies());
        TestLog.pass("检出删除: " + report.anomalies());
    }

    @Test
    void swappedRecordsAreDetectedAndLocated() {
        TestLog.caseStart("调换第 2、4 条位置，校验应发现乱序与链断裂");
        List<AuditRecord> records = new ArrayList<>(ledger.readAll());
        AuditRecord r2 = records.get(1);
        records.set(1, records.get(3));
        records.set(3, r2);

        VerificationReport report = LedgerVerifier.verify(records);
        assertFalse(report.intact());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("乱序") || a.contains("断档")),
                "应发现序号乱序: " + report.anomalies());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("链断裂")),
                "应发现哈希链断裂: " + report.anomalies());
        TestLog.pass("检出调换: " + report.anomalies());
    }
}
