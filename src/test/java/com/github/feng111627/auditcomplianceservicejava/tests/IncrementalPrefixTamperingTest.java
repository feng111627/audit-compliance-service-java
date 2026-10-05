package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.IncrementalVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.LedgerVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.IncrementalVerificationReport;
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

/**
 * 业务：增量核验 —— 摘要覆盖范围内的历史被改动（改内容、改内容并把自己的校验码改对、
 * 两条互换位置）必须检出并定位，且与整体核验对同一批记录的结论一致；
 * 诚实账本与新增部分异常的原有判定保持不变。
 */
class IncrementalPrefixTamperingTest {

    private AuditLedger ledger;
    private LedgerDigest trustedDigest;

    private static AuditEvent event(int i) {
        return new AuditEvent("evt-p-" + i, "alice", "READ", "doc-" + i,
                "SUCCESS", Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
    }

    @BeforeEach
    void setUp() {
        // 先落 5 条并保存可信摘要（模拟“上一回已确认可信”），再追加 5 条新增
        ledger = new AuditLedger("");
        for (int i = 1; i <= 5; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        trustedDigest = ledger.digest();
        for (int i = 6; i <= 10; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
    }

    @Test
    void honestLedgerStaysIntact() {
        TestLog.suite("增量核验：摘要覆盖范围内的历史改动必须检出，结论与整体核验一致");
        TestLog.caseStart("诚实账本：增量核验与整体核验均完好，只核新增 5 条");
        List<AuditRecord> records = ledger.readAll();
        IncrementalVerificationReport inc = IncrementalVerifier.verifySince(trustedDigest, records);
        assertTrue(inc.intact(), "诚实账本增量核验应完好: " + inc.anomalies());
        assertEquals(5, inc.anchorCount());
        assertEquals(5, inc.checkedNewCount(), "哈希重算只发生在 5 条新增记录上");
        assertTrue(LedgerVerifier.verify(records).intact());
        TestLog.pass("增量核验完好且只核新增部分，与整体核验结论一致");
    }

    @Test
    void coveredRecordContentChangedWithHashFixedIsDetected() {
        TestLog.caseStart("覆盖范围内 seq=3 内容被改、且这条自己的校验码被一并改对：增量核验必须检出");
        List<AuditRecord> records = new ArrayList<>(ledger.readAll());
        AuditRecord r3 = records.get(2);
        AuditEvent forged = new AuditEvent(r3.event().eventId(), "mallory", "DELETE",
                r3.event().resource(), r3.event().result(), r3.event().timestamp(), r3.event().attributes());
        // 攻击者把这条记录自己的 hash 也重算改对（单看这条自洽），但不动后续记录
        String fixedHash = RecordHasher.hash(r3.seq(), forged, r3.verdict(), r3.prevHash());
        records.set(2, new AuditRecord(r3.seq(), r3.storedAt(), forged, r3.verdict(), r3.prevHash(), fixedHash));

        boolean fullIntact = LedgerVerifier.verify(records).intact();
        IncrementalVerificationReport inc = IncrementalVerifier.verifySince(trustedDigest, records);
        assertFalse(fullIntact, "前提：整体核验能发现");
        assertFalse(inc.intact(), "增量核验必须同样发现（覆盖范围内链式衔接被破坏）: " + inc.anomalies());
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("seq=4") || a.contains("seq=3")),
                "应定位到被动过的位置附近: " + inc.anomalies());
        TestLog.pass("增量核验检出覆盖范围内的断链并定位: " + inc.anomalies());
    }

    @Test
    void coveredRecordsSwappedIsDetected() {
        TestLog.caseStart("覆盖范围内 seq=2 与 seq=4 两条记录被互换：增量核验必须检出并指出两个位置");
        List<AuditRecord> records = new ArrayList<>(ledger.readAll());
        records.set(1, ledger.readAll().get(3));
        records.set(3, ledger.readAll().get(1));

        boolean fullIntact = LedgerVerifier.verify(records).intact();
        IncrementalVerificationReport inc = IncrementalVerifier.verifySince(trustedDigest, records);
        assertFalse(fullIntact, "前提：整体核验能发现互换");
        assertFalse(inc.intact(), "增量核验必须同样发现互换: " + inc.anomalies());
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("seq=4") && a.contains("seq=2")
                        || a.contains("位置")),
                "应指出被互换的位置: " + inc.anomalies());
        TestLog.pass("增量核验检出覆盖范围内互换并定位: " + inc.anomalies());
    }

    @Test
    void coveredRecordContentChangedWithoutHashFixIsDetectedOnLedgerPath() throws Exception {
        TestLog.caseStart("覆盖范围内 seq=3 内容被改、校验码原封不动（落盘文件被改后重启）：账本增量核验必须检出");
        // 账本落盘 → 攻击者直接改文件里 seq=3 的内容（hash 字段不动）→ 重启恢复
        java.nio.file.Path file = java.nio.file.Files.createTempFile("audit-ledger-", ".jsonl");
        AuditLedger fileLedger = new AuditLedger(file.toString());
        for (int i = 1; i <= 5; i++) {
            fileLedger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        LedgerDigest trusted = fileLedger.digest();
        for (int i = 6; i <= 10; i++) {
            fileLedger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        List<AuditRecord> tampered = new ArrayList<>(fileLedger.readAll());
        AuditRecord r3 = tampered.get(2);
        AuditEvent forged = new AuditEvent(r3.event().eventId(), "mallory", "DELETE",
                r3.event().resource(), r3.event().result(), r3.event().timestamp(), r3.event().attributes());
        // 只改内容，hash/prevHash 字段原封不动（字段层面无任何不一致）
        tampered.set(2, new AuditRecord(r3.seq(), r3.storedAt(), forged, r3.verdict(), r3.prevHash(), r3.hash()));
        rewriteLedgerFile(file, tampered);

        AuditLedger reloaded = new AuditLedger(file.toString());
        boolean fullIntact = LedgerVerifier.verify(reloaded.readAll()).intact();
        IncrementalVerificationReport inc = reloaded.verifyIncremental(trusted);
        assertFalse(fullIntact, "前提：整体核验能发现");
        assertFalse(inc.intact(), "账本增量核验必须同样发现（存储层加载校验兜底）: " + inc.anomalies());
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("seq=3")),
                "应定位到 seq=3: " + inc.anomalies());
        assertEquals(5, inc.checkedNewCount(), "每次增量核验的完整校验仍只覆盖 5 条新增，代价不随历史增长");
        java.nio.file.Files.deleteIfExists(file);
        TestLog.pass("账本增量核验检出只改内容的覆盖范围篡改并定位 seq=3，与整体核验结论一致");
    }

    @Test
    void incrementalAndFullVerdictsAgreeOnEveryScenario() throws Exception {
        TestLog.caseStart("一致性汇总：同一批记录上，整体核验能发现的，增量核验必须都能发现");
        List<List<AuditRecord>> scenarios = new ArrayList<>();
        // 场景 1：诚实账本
        scenarios.add(ledger.readAll());
        // 场景 2：覆盖范围内改内容并把自己的校验码改对
        List<AuditRecord> hashFixed = new ArrayList<>(ledger.readAll());
        AuditRecord r3 = hashFixed.get(2);
        AuditEvent forged3 = new AuditEvent(r3.event().eventId(), "mallory", "DELETE",
                r3.event().resource(), r3.event().result(), r3.event().timestamp(), r3.event().attributes());
        hashFixed.set(2, new AuditRecord(r3.seq(), r3.storedAt(), forged3, r3.verdict(), r3.prevHash(),
                RecordHasher.hash(r3.seq(), forged3, r3.verdict(), r3.prevHash())));
        scenarios.add(hashFixed);
        // 场景 3：覆盖范围内两条互换
        List<AuditRecord> swapped = new ArrayList<>(ledger.readAll());
        swapped.set(1, ledger.readAll().get(3));
        swapped.set(3, ledger.readAll().get(1));
        scenarios.add(swapped);
        // 场景 4：新增部分被改
        List<AuditRecord> newPart = new ArrayList<>(ledger.readAll());
        AuditRecord r8 = newPart.get(7);
        newPart.set(7, new AuditRecord(r8.seq(), r8.storedAt(),
                new AuditEvent(r8.event().eventId(), "mallory", r8.event().action(), r8.event().resource(),
                        r8.event().result(), r8.event().timestamp(), r8.event().attributes()),
                r8.verdict(), r8.prevHash(), r8.hash()));
        scenarios.add(newPart);

        for (int s = 0; s < scenarios.size(); s++) {
            List<AuditRecord> records = scenarios.get(s);
            boolean full = LedgerVerifier.verify(records).intact();
            boolean inc = IncrementalVerifier.verifySince(trustedDigest, records).intact();
            assertTrue(full || !inc,
                    "场景 " + (s + 1) + "：整体核验发现的问题增量核验必须发现（full=" + full + ", inc=" + inc + "）");
        }
        // 账本路径（含存储层兜底）对“只改内容不改校验码”同样一致
        java.nio.file.Path file = java.nio.file.Files.createTempFile("audit-ledger-", ".jsonl");
        AuditLedger fileLedger = new AuditLedger(file.toString());
        for (int i = 1; i <= 5; i++) {
            fileLedger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        LedgerDigest trusted = fileLedger.digest();
        for (int i = 6; i <= 10; i++) {
            fileLedger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        List<AuditRecord> contentOnly = new ArrayList<>(fileLedger.readAll());
        AuditRecord cr3 = contentOnly.get(2);
        contentOnly.set(2, new AuditRecord(cr3.seq(), cr3.storedAt(),
                new AuditEvent(cr3.event().eventId(), "mallory", cr3.event().action(), cr3.event().resource(),
                        cr3.event().result(), cr3.event().timestamp(), cr3.event().attributes()),
                cr3.verdict(), cr3.prevHash(), cr3.hash()));
        rewriteLedgerFile(file, contentOnly);
        AuditLedger reloaded = new AuditLedger(file.toString());
        assertFalse(LedgerVerifier.verify(reloaded.readAll()).intact());
        assertFalse(reloaded.verifyIncremental(trusted).intact(),
                "账本路径对“只改内容不改校验码”必须与整体核验一致");
        java.nio.file.Files.deleteIfExists(file);
        TestLog.pass("4 类场景静态增量核验不漏报；账本路径对只改内容的篡改同样不漏报");
    }

    /** 把（可能被篡改的）记录按账本落盘格式重写进文件，模拟“存储层被直接改动”。 */
    private static void rewriteLedgerFile(java.nio.file.Path file, List<AuditRecord> records) throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper()
                .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        StringBuilder sb = new StringBuilder();
        for (AuditRecord r : records) {
            sb.append(mapper.writeValueAsString(r)).append(System.lineSeparator());
        }
        java.nio.file.Files.writeString(file, sb.toString());
    }
}
