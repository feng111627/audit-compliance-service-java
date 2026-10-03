package com.github.feng111627.auditcomplianceservicejava.model;

import java.util.List;

/**
 * 证据包独立核验结论：哈希链完整性 + 条数/整体指纹一致性 +
 * 逐条结论按包内当时规则复现的比对结果。
 */
public record EvidencePackReport(
        boolean intact,
        long recordCount,
        long verdictsReproduced,
        List<String> anomalies) {

    public static EvidencePackReport of(long recordCount, long verdictsReproduced, List<String> anomalies) {
        return new EvidencePackReport(anomalies.isEmpty(), recordCount, verdictsReproduced,
                List.copyOf(anomalies));
    }
}
