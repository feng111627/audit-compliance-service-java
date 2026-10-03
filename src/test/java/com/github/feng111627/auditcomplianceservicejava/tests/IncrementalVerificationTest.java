package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.LedgerVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.IncrementalVerificationReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：增量核验 —— 从可信摘要往后只重算新增部分，结论与整体核验一致，更早部分被动过也能发现。 */
class IncrementalVerificationTest {

    private static AuditEvent event(int i) {
        return new AuditEvent("evt-i-" + i, "alice", "READ", "doc-" + i,
                "SUCCESS", Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
    }

    private static AuditLedger ledgerWith(int n) {
        AuditLedger ledger = new AuditLedger("");
        for (int i = 1; i <= n; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        return ledger;
    }

    @Test
    void cleanIncrementalAgreesWithFullVerification() {
        TestLog.suite("增量核验：与整体核验结论一致、代价只随新增部分增长");
        TestLog.caseStart("100 条时确认可信摘要，再追加 5 条，增量核验应通过且只重算 5 次哈希");
        AuditLedger ledger = ledgerWith(100);
        LedgerDigest trusted = ledger.digest();
        for (int i = 101; i <= 105; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        List<AuditRecord> copy = ledger.readAll();

        IncrementalVerificationReport inc = LedgerVerifier.verifyIncremental(trusted, copy);
        assertTrue(inc.intact(), "干净副本增量核验应通过: " + inc.anomalies());
        assertEquals(100, inc.trustedRecordCount());
        assertEquals(5, inc.newRecordCount());
        assertEquals(5, inc.recomputedHashes(), "哈希重算次数只与新增部分相关，与历史总长无关");

        VerificationReport full = LedgerVerifier.verify(copy);
        assertTrue(full.intact());
        assertEquals(full.intact(), inc.intact(), "增量与整体核验结论必须一致");
        TestLog.pass("历史 100 条 + 新增 5 条：增量核验仅重算 5 次哈希即下结论，与整体核验一致（均通过）");
    }

    @Test
    void costStaysConstantAsHistoryGrows() {
        TestLog.caseStart("历史从 100 涨到 1000，同样新增 3 条，重算次数都应是 3");
        for (int history : new int[]{100, 1000}) {
            AuditLedger ledger = ledgerWith(history);
            LedgerDigest trusted = ledger.digest();
            for (int i = history + 1; i <= history + 3; i++) {
                ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
            }
            IncrementalVerificationReport inc = LedgerVerifier.verifyIncremental(trusted, ledger.readAll());
            assertTrue(inc.intact());
            assertEquals(3, inc.recomputedHashes(),
                    "历史 " + history + " 条时新增 3 条，重算次数应仍为 3");
            System.out.println("    历史=" + history + " 新增=3 -> 重算哈希 " + inc.recomputedHashes() + " 次");
        }
        TestLog.pass("核验代价与历史总长无关：100 条与 1000 条历史下，新增 3 条都只重算 3 次");
    }

    @Test
    void tamperedNewRecordFailsBothIncrementalAndFull() {
        TestLog.caseStart("新增部分第 103 条被篡改，增量与整体核验都应发现");
        AuditLedger ledger = ledgerWith(105);
        LedgerDigest trusted = new LedgerDigest(100,
                ledger.readAll().get(99).hash(), Instant.now());
        List<AuditRecord> copy = new ArrayList<>(ledger.readAll());
        AuditRecord original = copy.get(102);
        AuditEvent forged = new AuditEvent(original.event().eventId(), "mallory",
                original.event().action(), original.event().resource(), original.event().result(),
                original.event().timestamp(), original.event().attributes());
        copy.set(102, new AuditRecord(original.seq(), original.storedAt(), forged,
                original.verdict(), original.prevHash(), original.hash()));

        IncrementalVerificationReport inc = LedgerVerifier.verifyIncremental(trusted, copy);
        VerificationReport full = LedgerVerifier.verify(copy);
        assertFalse(inc.intact());
        assertFalse(full.intact());
        assertEquals(full.intact(), inc.intact(), "结论必须一致");
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("seq=103")),
                "应定位到新增部分的 seq=103: " + inc.anomalies());
        TestLog.pass("新增部分篡改被两种核验同时检出: " + inc.anomalies());
    }

    @Test
    void tamperedPrefixIsNotMissedByIncremental() {
        TestLog.caseStart("可信前缀第 40 条被改动（改动者同步改了记录哈希），增量核验不能漏掉");
        AuditLedger ledger = ledgerWith(105);
        LedgerDigest trusted = new LedgerDigest(100,
                ledger.readAll().get(99).hash(), Instant.now());
        List<AuditRecord> copy = new ArrayList<>(ledger.readAll());
        // 改动前缀记录内容，并把该条哈希重算成与内容一致（更隐蔽的改法）
        AuditRecord original = copy.get(39);
        AuditEvent forged = new AuditEvent(original.event().eventId(), "mallory",
                original.event().action(), original.event().resource(), original.event().result(),
                original.event().timestamp(), original.event().attributes());
        String forgedHash = RecordHasher.hash(original.seq(), forged, original.verdict(), original.prevHash());
        copy.set(39, new AuditRecord(original.seq(), original.storedAt(), forged,
                original.verdict(), original.prevHash(), forgedHash));

        IncrementalVerificationReport inc = LedgerVerifier.verifyIncremental(trusted, copy);
        VerificationReport full = LedgerVerifier.verify(copy);
        assertFalse(full.intact(), "整体核验应发现前缀被改动");
        assertFalse(inc.intact(), "增量核验不能漏掉更早部分被动过");
        assertEquals(full.intact(), inc.intact());
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("前缀")),
                "应指出可信前缀异常: " + inc.anomalies());
        TestLog.pass("前缀改动未被漏检: " + inc.anomalies());
    }

    @Test
    void prefixRecomputedEntirelyStillFailsAnchor() {
        TestLog.caseStart("改动者把前缀整条链重算伪装连贯，锚点 tailHash 对不上应被发现");
        AuditLedger ledger = ledgerWith(105);
        LedgerDigest trusted = new LedgerDigest(100,
                ledger.readAll().get(99).hash(), Instant.now());
        List<AuditRecord> copy = new ArrayList<>(ledger.readAll());
        // 从第 40 条起把整条链重算：每条都自洽，但链尖必然偏离可信摘要
        String prev = copy.get(38).hash();
        for (int i = 39; i < copy.size(); i++) {
            AuditRecord r = copy.get(i);
            AuditEvent ev = i == 39
                    ? new AuditEvent(r.event().eventId(), "mallory", r.event().action(),
                            r.event().resource(), r.event().result(), r.event().timestamp(),
                            r.event().attributes())
                    : r.event();
            String hash = RecordHasher.hash(r.seq(), ev, r.verdict(), prev);
            copy.set(i, new AuditRecord(r.seq(), r.storedAt(), ev, r.verdict(), prev, hash));
            prev = hash;
        }

        IncrementalVerificationReport inc = LedgerVerifier.verifyIncremental(trusted, copy);
        assertFalse(inc.intact());
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("锚点")),
                "锚点 tailHash 对不上应被指出: " + inc.anomalies());
        TestLog.pass("整段重算的伪装被锚点识破: " + inc.anomalies());
    }

    @Test
    void copyShorterThanTrustedAnchorIsRejected() {
        TestLog.caseStart("副本比可信锚点还短（末尾被删到锚点之前），应明确拒绝");
        AuditLedger ledger = ledgerWith(105);
        LedgerDigest trusted = new LedgerDigest(100,
                ledger.readAll().get(99).hash(), Instant.now());
        List<AuditRecord> truncated = ledger.readAll().subList(0, 80);

        IncrementalVerificationReport inc = LedgerVerifier.verifyIncremental(trusted, truncated);
        assertFalse(inc.intact());
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("短于可信锚点")),
                "应指出缺少 seq=81..100: " + inc.anomalies());
        TestLog.pass("副本短于锚点被拒绝: " + inc.anomalies());
    }

    @Test
    void incrementalDigestChainingAcrossRounds() {
        TestLog.caseStart("两轮增量：每轮核验通过后生成新摘要，下一轮从它继续");
        AuditLedger ledger = ledgerWith(50);
        LedgerDigest trusted = ledger.digest();

        for (int i = 51; i <= 60; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        IncrementalVerificationReport round1 =
                LedgerVerifier.verifyIncremental(trusted, ledger.readAll());
        assertTrue(round1.intact());
        assertEquals(10, round1.recomputedHashes());
        LedgerDigest trusted2 = round1.toDigest();
        assertEquals(60, trusted2.recordCount());

        for (int i = 61; i <= 65; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        IncrementalVerificationReport round2 =
                LedgerVerifier.verifyIncremental(trusted2, ledger.readAll());
        assertTrue(round2.intact());
        assertEquals(5, round2.recomputedHashes());
        assertEquals(65, round2.toDigest().recordCount());
        assertTrue(LedgerVerifier.verify(ledger.readAll()).intact());
        TestLog.pass("50 -> 60 -> 65 两轮增量核验均通过，每轮只重算当轮新增，摘要可逐轮接力");
    }
}
