package com.github.feng111627.auditcomplianceservicejava.rule;

import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceDecision;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceStatus;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 默认规则引擎。
 *
 * 规则语义（完全由配置文件决定，无需改代码）：
 * - 规则内 conditions 为 AND：所有条件都命中才算该规则命中；
 * - 支持的操作符：eq / neq / in（逗号分隔）/ startsWith / endsWith / contains / regex；
 * - 字段支持顶层 actor/action/resource/result/eventId/timestamp 与 attributes.xxx；
 * - 只要命中至少一条 DENY 规则即判 NON_COMPLIANT，命中规则按配置顺序全部列出，便于解释；
 * - 没有命中任何规则时默认 COMPLIANT。
 */
@Component
public class DefaultRuleEngine implements RuleEngine {

    private final RuleRepository ruleRepository;

    public DefaultRuleEngine(RuleRepository ruleRepository) {
        this.ruleRepository = ruleRepository;
    }

    @Override
    public ComplianceDecision evaluate(AuditEvent event) {
        return evaluate(event, ruleRepository.current());
    }

    @Override
    public ComplianceDecision evaluate(AuditEvent event, RuleSet ruleSet) {
        List<String> matched = new ArrayList<>();
        List<String> reasons = new ArrayList<>();
        boolean denyMatched = false;

        for (Rule rule : ruleSet.rules()) {
            if (matchesAll(event, rule)) {
                matched.add(rule.id());
                if ("DENY".equalsIgnoreCase(rule.decision())) {
                    denyMatched = true;
                    reasons.add("命中拒绝规则 " + rule.id()
                            + (rule.description() == null ? "" : "（" + rule.description() + "）"));
                } else {
                    reasons.add("命中允许规则 " + rule.id());
                }
            }
        }

        ComplianceStatus status = denyMatched ? ComplianceStatus.NON_COMPLIANT : ComplianceStatus.COMPLIANT;
        if (!denyMatched && reasons.isEmpty()) {
            reasons.add("未命中任何拒绝规则，按默认策略放行");
        }
        return new ComplianceDecision(status, ruleSet.version(), matched, reasons);
    }

    private boolean matchesAll(AuditEvent event, Rule rule) {
        for (RuleCondition condition : rule.conditions()) {
            if (!matchesOne(event, condition)) {
                return false;
            }
        }
        return true;
    }

    private boolean matchesOne(AuditEvent event, RuleCondition condition) {
        String actual = extractField(event, condition.field());
        String expected = condition.value();
        if (actual == null) {
            return false;
        }
        String op = condition.op() == null ? "eq" : condition.op();
        return switch (op) {
            case "eq" -> actual.equals(expected);
            case "neq" -> !actual.equals(expected);
            case "in" -> {
                for (String item : expected.split(",")) {
                    if (actual.equals(item.trim())) {
                        yield true;
                    }
                }
                yield false;
            }
            case "startsWith" -> actual.startsWith(expected);
            case "endsWith" -> actual.endsWith(expected);
            case "contains" -> actual.contains(expected);
            case "regex" -> actual.matches(expected);
            default -> throw new IllegalArgumentException("不支持的规则操作符: " + op);
        };
    }

    private String extractField(AuditEvent event, String field) {
        if (field.startsWith("attributes.")) {
            String key = field.substring("attributes.".length());
            Map<String, Object> attrs = event.getAttributes();
            if (attrs == null) {
                return null;
            }
            Object value = attrs.get(key);
            return value == null ? null : value.toString();
        }
        return switch (field) {
            case "actor" -> event.getActor();
            case "action" -> event.getAction();
            case "resource" -> event.getResource();
            case "result" -> event.getResult();
            case "eventId" -> event.getEventId();
            case "timestamp" -> event.getTimestamp();
            default -> throw new IllegalArgumentException("不支持的规则字段: " + field);
        };
    }
}
