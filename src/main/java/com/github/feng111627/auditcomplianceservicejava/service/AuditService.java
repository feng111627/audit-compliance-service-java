package com.github.feng111627.auditcomplianceservicejava.service;

import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import org.springframework.stereotype.Service;

/**
 * 编排：逐条判定 -> 留存 -> 需要告警的异步转发。
 * 批量请求中单条失败不影响其他条。
 */
@Service
public class AuditService {

    /** 处理单条事件，返回处理结果（含结论；被留存的含记录）。 */
    public IngestResult ingest(AuditEvent event) {
        // TODO: 实现
        return null;
    }

    /** 按当时规则版本复现一条历史记录的结论。 */
    public ComplianceVerdict reproduce(AuditRecord record) {
        // TODO: 实现
        return null;
    }

    public record IngestResult(int index, ComplianceVerdict verdict, Long seq) {
    }
}
