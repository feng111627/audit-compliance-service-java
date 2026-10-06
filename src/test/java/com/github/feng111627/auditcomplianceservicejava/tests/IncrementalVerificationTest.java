package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.IncrementalVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.LedgerVerifier;
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

/** 业务：增量核验 —— 以可信摘要为锚点只核对新增部分，结论与整体核验一致，且不漏掉更早历史被改动。 */
class IncrementalVerificationTest {

    private AuditLedger ledger;
    private LedgerDigest trustedDigest;

    private static AuditEvent event(int i) {
        return new AuditEvent("evt-i-" + i, "alice", "READ", "doc-" + i,
                "SUCCESS", Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
    }

    @BeforeEach
    void setUp() {
        // 先落 5 条并生成可信摘要（模拟“上一回已确认可信”），再追加 5 条新增
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
    void incrementalChecksOnlyNewPartAndAgreesWithFull() {
        TestLog.suite("增量核验：与整体核验结论一致、不漏历史改动、代价只跟新增相关");
        TestLog.caseStart("诚实账本：增量核验只算 5 条新增，结论与整体核验一致（均完好）");
        List<AuditRecord> records = ledger.readAll();
        IncrementalVerificationReport inc = IncrementalVerifier.verifySince(trustedDigest, records);
        assertTrue(inc.intact(), "增量核验应完好: " + inc.anomalies());
        assertEquals(5, inc.anchorCount());
        assertEquals(5, inc.checkedNewCount(), "只对 5 条新增做完整校验，不重算前 5 条历史");
        assertEquals(10, inc.totalCount());
        assertEquals(LedgerVerifier.verify(records).intact(), inc.intact(), "结论必须与整体核验一致");
        TestLog.pass("锚点=5 条，只核新增 5 条即给出完好结论，与整体核验一致");
    }

    @Test
    void newPartTamperingFailsBothIncrementalAndFull() {
        TestLog.caseStart("新增部分（seq=8）被篡改：增量与整体核验结论一致（均发现）");
        List<AuditRecord> records = new ArrayList<>(ledger.readAll());
        AuditRecord r8 = records.get(7);
        AuditEvent forged = new AuditEvent(r8.event().eventId(), "mallory", r8.event().action(),
                r8.event().resource(), r8.event().result(), r8.event().timestamp(), r8.event().attributes());
        records.set(7, new AuditRecord(r8.seq(), r8.storedAt(), forged, r8.verdict(), r8.prevHash(), r8.hash()));

        IncrementalVerificationReport inc = IncrementalVerifier.verifySince(trustedDigest, records);
        boolean fullIntact = LedgerVerifier.verify(records).intact();
        assertFalse(inc.intact());
        assertFalse(fullIntact);
        assertEquals(fullIntact, inc.intact(), "结论必须与整体核验一致");
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("seq=8")),
                "应定位到 seq=8: " + inc.anomalies());
        TestLog.pass("增量核验检出新增部分篡改并定位 seq=8，与整体核验结论一致");
    }

    @Test
    void earlierHistoryChangeIsNotMissed() {
        TestLog.caseStart("篡改前 5 条历史并把整条链重算伪装：整体核验被骗过，增量核验凭锚点发现");
        AuditEvent forged = new AuditEvent("evt-i-2", "mallory", "DELETE", "doc-2",
                "SUCCESS", Instant.parse("2026-10-01T00:00:02Z"), Map.of());
        List<AuditRecord> forgedChain = ChainTools.forgeAndRecompute(ledger.readAll(), 1, forged);
        assertTrue(LedgerVerifier.verify(forgedChain).intact(),
                "前提：重算伪装后的链条能通过整体核验（单看链条发现不了）");

        IncrementalVerificationReport inc = IncrementalVerifier.verifySince(trustedDigest, forgedChain);
        assertFalse(inc.intact(), "可信锚点必须揭穿对更早历史的重算伪装");
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("锚点")),
                "应指出可信锚点不匹配: " + inc.anomalies());
        TestLog.pass("增量核验凭可信锚点发现更早历史被改动: " + inc.anomalies());
    }

    @Test
    void earlierHistoryContentChangeWithOwnHashFixedIsNotMissed() {
        TestLog.caseStart("覆盖范围内 seq=3 内容被改且把自身校验码一并改对（不重算其后链）：不得漏报");
        List<AuditRecord> original = ledger.readAll();
        AuditRecord r3 = original.get(2);
        AuditEvent forged = ChainTools.actorTampered(r3, "mallory");
        List<AuditRecord> tampered = ChainTools.changeContentAndRehashSelf(original, 2, forged);
        assertEquals(com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher.hashOf(tampered.get(2)),
                tampered.get(2).hash(), "攻击前提：seq=3 自身校验码已被改对");
        boolean fullIntact = LedgerVerifier.verify(tampered).intact();
        assertFalse(fullIntact, "整体核验能在 seq=4 看出链断裂");

        // 线下路径（整体重算+锚定）
        IncrementalVerificationReport offline = IncrementalVerifier.verifySince(trustedDigest, tampered);
        assertFalse(offline.intact(), "旧实现只核边界第 5 条会漏报，修复后线下路径必须发现");
        assertEquals(fullIntact, offline.intact(), "结论必须与整体核验一致");
        // 账本锁内快速路径（MMR 山尖位置承诺）
        IncrementalVerificationReport live = ledger.verifyIncremental(trustedDigest);
        assertTrue(live.intact(), "未被改的活账本仍应完好");
        TestLog.pass("覆盖范围内中间记录被改（自身校验码改对）：线下路径定位到 seq=4 断链，与整体核验一致");
    }

    @Test
    void earlierHistorySwapIsNotMissed() {
        TestLog.caseStart("覆盖范围内 seq=2 与 seq=3 两条被整体互换：不得漏报，指出两个位置");
        List<AuditRecord> swapped = ChainTools.swapWholeRecords(ledger.readAll(), 1, 2);
        boolean fullIntact = LedgerVerifier.verify(swapped).intact();
        assertFalse(fullIntact, "整体核验能看出乱序/断链");

        IncrementalVerificationReport inc = IncrementalVerifier.verifySince(trustedDigest, swapped);
        assertFalse(inc.intact(), "旧实现只核边界第 5 条会漏报，修复后必须发现互换");
        assertEquals(fullIntact, inc.intact(), "结论必须与整体核验一致");
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("seq=2") && a.contains("seq=3")),
                "应指出互换的两个位置: " + inc.anomalies());
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("哈希链断裂")),
                "应有断链明细: " + inc.anomalies());
        TestLog.pass("覆盖范围内两条互换被检出，定位 seq=2/seq=3，与整体核验结论一致");
    }

    @Test
    void tailTruncationIsDetected() {
        TestLog.caseStart("可信摘要覆盖到 seq=10 后末尾整段删掉 3 条：增量核验发现缺失并说清缺了哪些");
        LedgerDigest trustedAt10 = ledger.digest();
        List<AuditRecord> truncated = new ArrayList<>(ledger.readAll().subList(0, 7));
        IncrementalVerificationReport inc = IncrementalVerifier.verifySince(trustedAt10, truncated);
        assertFalse(inc.intact());
        assertTrue(inc.anomalies().stream().anyMatch(a -> a.contains("seq=8") && a.contains("seq=10")
                        && a.contains("缺失")),
                "应说清缺少 seq=8 到 seq=10: " + inc.anomalies());
        TestLog.pass("检出末尾缺失 3 条: " + inc.anomalies());
    }

    @Test
    void zeroAnchorIncrementalEqualsFull() {
        TestLog.caseStart("锚点为空账本摘要（count=0）：增量核验覆盖全部，与整体核验逐条等价");
        LedgerDigest zeroAnchor = new LedgerDigest(0, com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher.GENESIS,
                Instant.now());
        List<AuditRecord> records = ledger.readAll();
        IncrementalVerificationReport inc = IncrementalVerifier.verifySince(zeroAnchor, records);
        assertTrue(inc.intact());
        assertEquals(10, inc.checkedNewCount(), "锚点为 0 时全部记录都算新增，等价于整体核验");
        assertEquals(LedgerVerifier.verify(records).intact(), inc.intact());
        TestLog.pass("count=0 锚点下增量核验=整体核验，结论一致");
    }
}
