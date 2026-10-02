package com.github.feng111627.auditcomplianceservicejava.rules;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 规则提供者：从本地 JSON 文件加载规则集（默认 classpath:rules.json，
 * 可用 audit.rules.path 指向外部文件，改规则不用改代码），支持热加载；
 * 加载过的每个版本都保留，供历史记录按当时规则复现结论。
 */
@Component
public class RuleProvider {

    private static final Logger log = LoggerFactory.getLogger(RuleProvider.class);

    private final ObjectMapper mapper = new ObjectMapper();
    private final String rulesLocation;
    private final Map<String, RuleSet> history = new ConcurrentHashMap<>();
    private volatile RuleSet current;

    public RuleProvider(@Value("${audit.rules.path:classpath:rules.json}") String rulesLocation) {
        this.rulesLocation = rulesLocation;
        reload();
    }

    public RuleSet current() {
        return current;
    }

    public Optional<RuleSet> byVersion(String version) {
        return Optional.ofNullable(history.get(version));
    }

    /** 重新加载规则文件；加载成功后切换当前版本并留存历史版本。 */
    public synchronized void reload() {
        Resource resource = new DefaultResourceLoader().getResource(rulesLocation);
        try (InputStream in = resource.getInputStream()) {
            RuleSet loaded = mapper.readValue(in, RuleSet.class);
            if (loaded.version() == null || loaded.version().isBlank()) {
                throw new IllegalStateException("规则文件缺少 version 字段");
            }
            history.put(loaded.version(), loaded);
            this.current = loaded;
            log.info("规则集已加载: version={}, 规则数={}", loaded.version(), loaded.rules().size());
        } catch (IOException e) {
            throw new IllegalStateException("无法加载规则文件: " + rulesLocation, e);
        }
    }
}
