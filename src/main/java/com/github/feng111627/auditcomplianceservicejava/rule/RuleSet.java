package com.github.feng111627.auditcomplianceservicejava.rule;

import java.util.List;

/** 一个版本的规则集。版本号写入每条审计记录，历史记录按当时版本复现结论。 */
public record RuleSet(
        String version,
        String eventSchemaVersion,
        List<Rule> rules
) {
}
