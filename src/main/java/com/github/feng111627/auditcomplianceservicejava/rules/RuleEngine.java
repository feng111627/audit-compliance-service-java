package com.github.feng111627.auditcomplianceservicejava.rules;

import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import org.springframework.stereotype.Component;

/**
 * 规则引擎：按当前规则集对事件做合规判定。
 */
@Component
public class RuleEngine {

    private final RuleProvider ruleProvider;

    public RuleEngine(RuleProvider ruleProvider) {
        this.ruleProvider = ruleProvider;
    }

    /** 用指定版本的规则集判定（用于历史结论复现）。 */
    public ComplianceVerdict evaluate(AuditEvent event, RuleSet ruleSet) {
        // TODO: 实现
        return null;
    }

    /** 用当前生效的规则集判定。 */
    public ComplianceVerdict evaluate(AuditEvent event) {
        return evaluate(event, ruleProvider.current());
    }
}
