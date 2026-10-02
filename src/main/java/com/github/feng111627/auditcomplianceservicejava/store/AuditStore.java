package com.github.feng111627.auditcomplianceservicejava.store;

import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceDecision;

import java.util.List;
import java.util.Optional;

/** 只追加的审计账本：顺序编号 + 哈希链，本地文件留存。 */
public interface AuditStore {
    /** 串行化追加一条记录，返回分配的编号；并发调用编号不重复、不断档。 */
    AuditRecord append(AuditEvent event, ComplianceDecision decision, String eventSchemaVersion);

    List<AuditRecord> readAll();

    Optional<AuditRecord> findBySeq(long seq);

    IntegrityReport verifyIntegrity();
}
