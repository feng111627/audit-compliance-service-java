package com.github.feng111627.auditcomplianceservicejava.rule;

import java.util.List;

/** 规则仓库：从配置文件加载规则，留存每个历史版本，支持热刷新。 */
public interface RuleRepository {
    RuleSet current();
    RuleSet getVersion(String version);
    List<String> versions();
    /** 重新加载规则文件；新版本写入快照，已有版本不变。 */
    RuleSet reload();
}
