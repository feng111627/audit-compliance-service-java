package com.github.feng111627.auditcomplianceservicejava.model;

/**
 * 单个字段的违规描述：哪个字段、违反了哪条规则、具体原因。
 */
public record FieldViolation(String field, String ruleId, String reason) {
}
