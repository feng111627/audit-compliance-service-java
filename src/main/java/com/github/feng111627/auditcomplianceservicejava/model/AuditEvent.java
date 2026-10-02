package com.github.feng111627.auditcomplianceservicejava.model;

import java.time.Instant;
import java.util.Map;

/**
 * 接收到的原始审计事件。所有字段都可能缺失或格式错误，
 * 因此这里不做任何校验，仅承载输入。
 */
public record AuditEvent(
        String eventId,
        String actor,
        String action,
        String resource,
        String result,
        Instant timestamp,
        Map<String, String> attributes) {
}
