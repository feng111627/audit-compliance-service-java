package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
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
}
