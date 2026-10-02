package com.github.feng111627.auditcomplianceservicejava.alert;

import com.github.feng111627.auditcomplianceservicejava.domain.AuditRecord;

import java.util.List;

/** 持久化发件箱：保证告警不丢、重启可恢复；重试耗尽进死信队列。 */
public interface AlertOutbox {
    /** 入队并落盘（接收路径调用，快、不访问下游）。 */
    void enqueue(AuditRecord record);

    List<OutboxEntry> pending();

    List<OutboxEntry> deadLetters();

    int retryDeadLetter(long seq);
}
