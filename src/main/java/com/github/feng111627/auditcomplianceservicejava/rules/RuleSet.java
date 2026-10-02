package com.github.feng111627.auditcomplianceservicejava.rules;

import java.util.List;

/**
 * 一份带版本号的规则集。版本号随规则文件内容变化，
 * 历史记录保存判定时的版本，可复现当时结论。
 */
public record RuleSet(String version, List<Rule> rules) {
}
