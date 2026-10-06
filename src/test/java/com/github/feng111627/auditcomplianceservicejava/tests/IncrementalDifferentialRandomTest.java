package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.IncrementalVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.LedgerVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.MmrAccumulator;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.IncrementalVerificationReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：增量/整体核验结论一致性（随机差分）——随机锚点位置、随机篡改位置、
 * 随机篡改形态，快速路径（山尖由账本锁内同提交点提供）与整体核验对同一批
 * 被改记录的 intact 结论必须始终一致；诚实账本始终完好、不误伤。
 */
class IncrementalDifferentialRandomTest {

    private static AuditEvent event(int i) {
        return new AuditEvent("evt-r-" + i, "alice", "READ", "doc-" + i,
                "SUCCESS", Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
    }

    private static IncrementalVerificationReport fast(LedgerDigest digest, List<AuditRecord> records) {
        return IncrementalVerifier.verifySince(digest, records,
                MmrAccumulator.peaksFor(records.stream().map(AuditRecord::hash).toList()));
    }

    @Test
    void randomMutationsNeverCauseVerdictDisagreement() {
        TestLog.suite("增量核验差分：随机锚点/随机位置/随机形态下结论始终与整体核验一致");
        TestLog.caseStart("30 个随机账本 × 2 类局部篡改：快速路径结论与整体核验逐条一致");
        Random rnd = new Random(20261006L);
        int cases = 0;
        for (int round = 0; round < 30; round++) {
            int total = 1 + rnd.nextInt(30);
            int anchor = rnd.nextInt(total + 1); // 0..total
            AuditLedger ledger = new AuditLedger("");
            for (int i = 1; i <= total; i++) {
                ledger.append(event(round * 1000 + i),
                        ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
            }
            List<AuditRecord> base = ledger.readAll();
            LedgerDigest digest = digestAt(ledger, anchor);

            // 诚实对照：永远完好
            assertTrue(fast(digest, base).intact(),
                    "round=" + round + " anchor=" + anchor + " 诚实账本不得误伤");

            // 篡改点落在“摘要覆盖范围”内（含边界），这是旧实现漏报的区域
            if (anchor == 0) {
                continue;
            }
            int pos = rnd.nextInt(anchor); // 0..anchor-1

            // 形态 1：改内容 + 自身校验码改对（不重算其后链）
            AuditRecord r = base.get(pos);
            AuditEvent forged = ChainTools.actorTampered(r, "mallory-" + round);
            List<AuditRecord> m1 = ChainTools.changeContentAndRehashSelf(base, pos, forged);
            boolean full1 = LedgerVerifier.verify(m1).intact();
            IncrementalVerificationReport inc1 = fast(digest, m1);
            assertFalse(inc1.intact(), "round=" + round + " pos=" + pos + " 形态1不得漏报");
            assertEquals(full1, inc1.intact(), "round=" + round + " 形态1结论不一致");
            cases++;

            // 形态 2：与另一个随机位置整体互换
            if (total >= 2) {
                int other;
                do {
                    other = rnd.nextInt(total);
                } while (other == pos);
                List<AuditRecord> m2 = ChainTools.swapWholeRecords(base, pos, other);
                boolean full2 = LedgerVerifier.verify(m2).intact();
                IncrementalVerificationReport inc2 = fast(digest, m2);
                assertFalse(inc2.intact(), "round=" + round + " 互换 " + pos + "/" + other + " 不得漏报");
                assertEquals(full2, inc2.intact(), "round=" + round + " 形态2结论不一致");
                assertTrue(inc2.anomalies().stream().anyMatch(x -> x.contains("可信锚点不匹配")),
                        "互换必须报锚点不匹配");
                cases++;
            }
        }
        System.out.println("    [差分] 共验证 " + cases + " 个随机篡改用例，结论全部与整体核验一致 ✔");
        TestLog.pass("随机差分无漏报、无结论分歧，诚实账本全部完好");
    }

    /** 在指定条数处取摘要（构造一个恰好写到该位置的账本）。 */
    private static LedgerDigest digestAt(AuditLedger ledger, int anchor) {
        if (anchor == ledger.size()) {
            return ledger.digest();
        }
        List<AuditRecord> prefix = new ArrayList<>(ledger.readAll().subList(0, anchor));
        return com.github.feng111627.auditcomplianceservicejava.evidence.EvidenceService.digestOf(prefix);
    }
}
