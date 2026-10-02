package com.github.feng111627.auditcomplianceservicejava.rules;

import java.util.List;

/**
 * 一条可配置合规规则（从 JSON 加载，改规则不用改代码）。
 * type 取值：REQUIRED / FORMAT / ALLOWED_VALUES / ALERT_WHEN。
 */
public record Rule(
        String id,
        String type,
        String field,
        String pattern,
        List<String> values,
        String message) {
}
