package com.github.feng111627.auditcomplianceservicejava.model;

import java.time.Instant;

/**
 * 留存的一条审计记录。seq 单调递增无断档；hash 由本记录内容
 * 与前一条记录 hash 链式计算，用于完整性校验。
 */
public record AuditRecord(
        long seq,
        Instant storedAt,
        AuditEvent event,
        ComplianceVerdict verdict,
        String prevHash,
        String hash) {
}
