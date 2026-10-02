package com.github.feng111627.auditcomplianceservicejava.alert;

import com.github.feng111627.auditcomplianceservicejava.domain.AuditRecord;

/** 需要转发告警的消息体，以 record seq 作为幂等键。 */
public record AlertMessage(long seq, String eventId, AuditRecord record) {
}
