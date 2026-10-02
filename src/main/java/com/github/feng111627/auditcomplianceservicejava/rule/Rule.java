package com.github.feng111627.auditcomplianceservicejava.rule;

import java.util.List;

/**
 * 一条合规规则：conditions 全部命中时判定为 decision(DENY/ALLOW)。
 * DENY 命中 -> NON_COMPLIANT；没有任何规则命中 -> 默认 COMPLIANT。
 */
public record Rule(
        String id,
        String description,
        List<RuleCondition> conditions,
        String decision
) {
}
