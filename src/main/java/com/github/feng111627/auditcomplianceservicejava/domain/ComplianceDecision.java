package com.github.feng111627.auditcomplianceservicejava.domain;

import java.util.List;

/** 规则引擎对单条事件给出的合规结论。 */
public record ComplianceDecision(
        ComplianceStatus status,
        String ruleVersion,
        List<String> matchedRuleIds,
        List<String> reasons
) {
}
