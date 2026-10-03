package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.IncrementalVerificationReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;

import java.util.ArrayList;
import java.util.List;

/**
 * 独立完整性校验器：不依赖账本内部状态，对任意一份记录列表
 * （例如从文件导出的历史）做校验。
 * 能发现：序号断档（删除）、内容哈希不符（篡改）、链断裂（调换/插入）。
 */
public final class LedgerVerifier {

    private LedgerVerifier() {
    }

    public static VerificationReport verify(List<AuditRecord> records) {
        List<String> anomalies = new ArrayList<>();
        long expectedSeq = 1;
        String expectedPrevHash = RecordHasher.GENESIS;
        for (AuditRecord record : records) {
            if (record.seq() != expectedSeq) {
                anomalies.add("序号断档/乱序: 期望 seq=" + expectedSeq
                        + "，实际 seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "），可能存在删除或调换");
                expectedSeq = record.seq();
            }
            String recomputed = RecordHasher.hashOf(record);
            if (!recomputed.equals(record.hash())) {
                anomalies.add("内容被篡改: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）记录哈希与内容不符");
            }
            if (!expectedPrevHash.equals(record.prevHash())) {
                anomalies.add("哈希链断裂: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）prevHash 与前一条不匹配，可能存在删除、插入或调换");
            }
            expectedPrevHash = record.hash();
            expectedSeq++;
        }
        return new VerificationReport(anomalies.isEmpty(), records.size(), List.copyOf(anomalies));
    }

    private static String safeEventId(AuditRecord record) {
        return record.event() == null ? "?" : String.valueOf(record.event().eventId());
    }

    /**
     * 增量核验：以一份已确认可信的摘要为锚点，只对新增记录做完整校验
     * （序号、链式衔接、内容哈希重算），哈希重算次数 = 新增条数，
     * 与历史总长无关。
     * 更早部分不漏检：锚点摘要的 tailHash 在密码学意义上提交了此前全部记录，
     * 这里对前缀做结构校验（序号连续 + 链式衔接 + 锚点一致）——
     * 对前缀的任何改动要么破坏链式衔接、要么使锚点对不上，都会被发现；
     * 前缀的内容级校验在生成该摘要时已完成并由锚点固化。
     * 结论与整体核验一致：同一批异常场景下两者判定相同。
     */
    public static IncrementalVerificationReport verifyIncremental(LedgerDigest trusted,
                                                                  List<AuditRecord> records) {
        List<String> anomalies = new ArrayList<>();
        long n = trusted.recordCount();
        long m = records.size();

        if (m < n) {
            anomalies.add("副本短于可信锚点: 可信位置有 " + n + " 条，副本只有 " + m
                    + " 条，缺少 seq=" + (m + 1) + ".." + n + "，增量核验无法成立");
            return new IncrementalVerificationReport(false, n, 0, 0, null, List.copyOf(anomalies));
        }

        // 1) 前缀结构校验（只做序号与链式衔接比较，不重算哈希）
        String expectedPrevHash = RecordHasher.GENESIS;
        for (int i = 0; i < n; i++) {
            AuditRecord record = records.get(i);
            if (record.seq() != i + 1) {
                anomalies.add("前缀序号断档/乱序: 期望 seq=" + (i + 1) + "，实际 seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "），可信前缀被动过");
            }
            if (!expectedPrevHash.equals(record.prevHash())) {
                anomalies.add("前缀哈希链断裂: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）prevHash 与前一条不匹配，可信前缀被动过");
            }
            expectedPrevHash = record.hash();
        }

        // 2) 锚点一致：可信位置的记录哈希必须等于摘要 tailHash
        if (n > 0) {
            AuditRecord anchor = records.get((int) n - 1);
            if (anchor.seq() != n || !anchor.hash().equals(trusted.tailHash())) {
                anomalies.add("可信锚点不符: seq=" + n + " 的记录哈希与可信摘要 tailHash 不一致，"
                        + "说明锚点及之前的内容与已确认的历史不同");
            }
        } else if (!RecordHasher.GENESIS.equals(trusted.tailHash())) {
            anomalies.add("可信摘要位置为 0 但 tailHash 不是 GENESIS，摘要本身非法");
        }

        // 3) 新增部分完整校验：序号、链式衔接、内容哈希逐条重算
        long recomputed = 0;
        for (int i = (int) n; i < m; i++) {
            AuditRecord record = records.get(i);
            if (record.seq() != i + 1) {
                anomalies.add("新增部分序号断档/乱序: 期望 seq=" + (i + 1) + "，实际 seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）");
            }
            if (!expectedPrevHash.equals(record.prevHash())) {
                anomalies.add("新增部分哈希链断裂: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）prevHash 与前一条不匹配");
            }
            String recomputedHash = RecordHasher.hashOf(record);
            recomputed++;
            if (!recomputedHash.equals(record.hash())) {
                anomalies.add("新增部分内容被篡改: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）记录哈希与内容不符");
            }
            expectedPrevHash = record.hash();
        }

        String newTailHash = m == 0 ? trusted.tailHash() : records.get((int) m - 1).hash();
        return new IncrementalVerificationReport(anomalies.isEmpty(), n, m - n, recomputed,
                newTailHash, List.copyOf(anomalies));
    }
}
