package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 审计账本：按提交顺序追加记录，编号连续不重复；
 * 记录间哈希链保证历史完整性可独立校验。
 */
@Component
public class AuditLedger {

    /** 追加一条记录，返回分配好序号与哈希的完整记录。线程安全。 */
    public AuditRecord append(com.github.feng111627.auditcomplianceservicejava.model.AuditEvent event,
                              com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict verdict) {
        // TODO: 实现
        return null;
    }

    /** 按写入顺序读出全部记录。 */
    public List<AuditRecord> readAll() {
        // TODO: 实现
        return List.of();
    }

    /** 独立校验完整性：发现篡改、删除、调换并指出具体记录。 */
    public VerificationReport verify() {
        // TODO: 实现
        return null;
    }
}
