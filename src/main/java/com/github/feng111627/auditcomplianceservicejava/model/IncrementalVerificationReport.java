package com.github.feng111627.auditcomplianceservicejava.model;

import java.time.Instant;
import java.util.List;

/**
 * 增量核验结论：从一份已确认可信的摘要往后，只完整重算新增记录。
 * recomputedHashes 为实际重算哈希的次数（= 新增条数），
 * 与历史总长无关；newTailHash 可生成新的可信摘要，供下一轮增量核验。
 */
public record IncrementalVerificationReport(
        boolean intact,
        long trustedRecordCount,
        long newRecordCount,
        long recomputedHashes,
        String newTailHash,
        List<String> anomalies) {

    /** 核验通过时生成新的可信摘要，作为下一轮增量核验的锚点。 */
    public LedgerDigest toDigest() {
        if (!intact) {
            throw new IllegalStateException("核验未通过，不能生成可信摘要");
        }
        return new LedgerDigest(trustedRecordCount + newRecordCount, newTailHash, Instant.now());
    }
}
