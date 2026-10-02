package com.github.feng111627.auditcomplianceservicejava.rule;

/** 单个匹配条件：field（支持 attributes.xxx）、操作符、期望值。 */
public record RuleCondition(String field, String op, String value) {
}
