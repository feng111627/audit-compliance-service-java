package com.github.feng111627.auditcomplianceservicejava.model;

import java.util.List;

/**
 * 一条事件的合规结论。ruleVersion 记录判定所用规则版本，
 * 以便规则升级后仍能按当时规则复现历史结论。
 */
public record ComplianceVerdict(
        ComplianceStatus status,
        List<FieldViolation> violations,
        String ruleVersion) {

    public static ComplianceVerdict rejected(List<FieldViolation> violations, String ruleVersion) {
        return new ComplianceVerdict(ComplianceStatus.REJECTED, List.copyOf(violations), ruleVersion);
    }

    public static ComplianceVerdict of(ComplianceStatus status, String ruleVersion) {
        return new ComplianceVerdict(status, List.of(), ruleVersion);
    }
}
