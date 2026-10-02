package com.github.feng111627.auditcomplianceservicejava.tests.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.auditcomplianceservicejava.config.AuditProperties;
import com.github.feng111627.auditcomplianceservicejava.rule.DefaultRuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rule.FileRuleRepository;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleRepository;
import com.github.feng111627.auditcomplianceservicejava.store.FileAuditStore;
import org.springframework.core.io.DefaultResourceLoader;

import java.nio.file.Path;

/** 测试用组件装配：每个测试使用独立临时目录，互不污染。 */
public final class TestContext {

    public final AuditProperties properties;
    public final ObjectMapper objectMapper;
    public final RuleRepository ruleRepository;
    public final RuleEngine ruleEngine;
    public final FileAuditStore store;

    private TestContext(AuditProperties properties, ObjectMapper objectMapper,
                        FileRuleRepository ruleRepository, DefaultRuleEngine ruleEngine,
                        FileAuditStore store) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.ruleRepository = ruleRepository;
        this.ruleEngine = ruleEngine;
        this.store = store;
    }

    public static TestContext create(Path tempDir) {
        AuditProperties props = new AuditProperties();
        props.setDataDir(tempDir.toString());
        props.setRulesLocation("classpath:rules/default-rules.json");
        ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
        FileRuleRepository repo = new FileRuleRepository(props, mapper, new DefaultResourceLoader());
        DefaultRuleEngine engine = new DefaultRuleEngine(repo);
        FileAuditStore auditStore = new FileAuditStore(props, mapper);
        return new TestContext(props, mapper, repo, engine, auditStore);
    }
}
