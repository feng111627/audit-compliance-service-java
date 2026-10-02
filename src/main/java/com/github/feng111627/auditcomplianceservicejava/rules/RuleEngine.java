package com.github.feng111627.auditcomplianceservicejava.rules;

import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.FieldViolation;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 规则引擎：按规则集对事件做合规判定。
 * REQUIRED/FORMAT/ALLOWED_VALUES 产生违规（拒收原因）；
 * ALERT_WHEN 不产生违规，只把结论提升为 ALERT（需异步转发）。
 */
@Component
public class RuleEngine {

    private final RuleProvider ruleProvider;

    public RuleEngine(RuleProvider ruleProvider) {
        this.ruleProvider = ruleProvider;
    }

    /** 用当前生效的规则集判定。 */
    public ComplianceVerdict evaluate(AuditEvent event) {
        return evaluate(event, ruleProvider.current());
    }

    /** 用指定版本的规则集判定（用于历史结论复现）。 */
    public ComplianceVerdict evaluate(AuditEvent event, RuleSet ruleSet) {
        List<FieldViolation> violations = new ArrayList<>();
        boolean alert = false;
        for (Rule rule : ruleSet.rules()) {
            String value = fieldValue(event, rule.field());
            switch (rule.type()) {
                case "REQUIRED" -> {
                    if (value == null || value.isBlank()) {
                        violations.add(new FieldViolation(rule.field(), rule.id(), rule.message()));
                    }
                }
                case "FORMAT" -> {
                    if (value != null && !value.isBlank() && !matches(rule, value)) {
                        violations.add(new FieldViolation(rule.field(), rule.id(),
                                rule.message() + "，实际值: " + abbreviate(value)));
                    }
                }
                case "ALLOWED_VALUES" -> {
                    if (value != null && !value.isBlank() && !rule.values().contains(value)) {
                        violations.add(new FieldViolation(rule.field(), rule.id(),
                                rule.message() + "，实际值: " + abbreviate(value)));
                    }
                }
                case "ALERT_WHEN" -> {
                    if (value != null && rule.values().contains(value)) {
                        alert = true;
                    }
                }
                default -> throw new IllegalStateException("未知规则类型: " + rule.type());
            }
        }
        if (!violations.isEmpty()) {
            return ComplianceVerdict.rejected(violations, ruleSet.version());
        }
        return ComplianceVerdict.of(alert ? ComplianceStatus.ALERT : ComplianceStatus.ACCEPTED, ruleSet.version());
    }

    private boolean matches(Rule rule, String value) {
        try {
            return Pattern.compile(rule.pattern()).matcher(value).matches();
        } catch (PatternSyntaxException e) {
            throw new IllegalStateException("规则 " + rule.id() + " 正则非法: " + rule.pattern(), e);
        }
    }

    /** 支持 actor/action/resource/result/eventId/timestamp 及 attributes.<key>。 */
    private String fieldValue(AuditEvent event, String field) {
        if (field == null) {
            return null;
        }
        return switch (field) {
            case "eventId" -> event.eventId();
            case "actor" -> event.actor();
            case "action" -> event.action();
            case "resource" -> event.resource();
            case "result" -> event.result();
            case "timestamp" -> event.timestamp() == null ? null : event.timestamp().toString();
            default -> {
                if (field.startsWith("attributes.") && event.attributes() != null) {
                    yield event.attributes().get(field.substring("attributes.".length()));
                }
                yield null;
            }
        };
    }

    private String abbreviate(String value) {
        return value.length() <= 40 ? value : value.substring(0, 40) + "...";
    }
}
