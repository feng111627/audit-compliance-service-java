package com.github.feng111627.auditcomplianceservicejava.rule;

import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceDecision;

/** 规则引擎：按指定规则集版本对事件做合规判定。 */
public interface RuleEngine {
    /** 用当前生效规则集判定。 */
    ComplianceDecision evaluate(AuditEvent event);

    /** 用指定历史版本规则集判定（复现历史结论）。 */
    ComplianceDecision evaluate(AuditEvent event, RuleSet ruleSet);
}
