package com.github.feng111627.auditcomplianceservicejava.forward;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 异步转发器：告警事件入队即返回，不拖慢接收；
 * 失败重试，重试耗尽进失败队列；按 eventId 去重避免重复投递成功。
 */
@Component
public class AlertForwarder {

    /** 提交一条待转发记录（立即返回）。 */
    public void submit(AuditRecord record) {
        // TODO: 实现
    }

    /** 查询失败队列。 */
    public List<DeadLetter> deadLetters() {
        // TODO: 实现
        return List.of();
    }

    /** 已成功投递的 eventId 数（用于测试与观测）。 */
    public long deliveredCount() {
        // TODO: 实现
        return 0;
    }

    public void shutdown() {
        // TODO: 实现
    }
}
