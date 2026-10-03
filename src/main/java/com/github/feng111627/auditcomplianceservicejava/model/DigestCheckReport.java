package com.github.feng111627.auditcomplianceservicejava.model;

import java.util.List;

/**
 * 用存证摘要核对一份记录副本的结论。
 * matches=true 表示副本在摘要位置及之前与摘要完全一致（副本可以更新，即更长）。
 * 末尾被整段删掉时 matches=false，missingFromSeq/missingCount 说清少了哪些、少了多少。
 */
public record DigestCheckReport(
        boolean matches,
        long digestRecordCount,
        long copyRecordCount,
        Long missingFromSeq,
        long missingCount,
        List<String> anomalies) {

    public static DigestCheckReport of(long digestRecordCount, long copyRecordCount,
                                       Long missingFromSeq, long missingCount, List<String> anomalies) {
        return new DigestCheckReport(anomalies.isEmpty(), digestRecordCount, copyRecordCount,
                missingFromSeq, missingCount, List.copyOf(anomalies));
    }
}
