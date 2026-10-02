package com.github.feng111627.auditcomplianceservicejava.forward;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;

import java.time.Instant;

/**
 * 重试最终失败后进入失败队列的条目。
 */
public record DeadLetter(AuditRecord record, int attempts, String lastError, Instant failedAt) {
}
