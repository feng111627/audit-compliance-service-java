package com.github.feng111627.auditcomplianceservicejava.rule;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.auditcomplianceservicejava.config.AuditProperties;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 从 JSON 文件加载规则，为每个版本在 dataDir/rule-snapshots 下留存不可变快照。
 *
 * 语义：
 * - 启动时加载当前规则文件，版本内容落快照；
 * - reload() 读到新版本 -> 留存新快照并切换；读到相同版本且内容一致 -> 原样返回；
 * - 同版本号但内容变化 -> 拒绝（保证“历史记录按当时规则复现”不会被同版本覆盖破坏）。
 */
@Repository
public class FileRuleRepository implements RuleRepository {

    private final AuditProperties properties;
    private final ObjectMapper objectMapper;
    private final ResourceLoader resourceLoader;
    private final Map<String, RuleSet> snapshots = new LinkedHashMap<>();
    private volatile RuleSet current;

    public FileRuleRepository(AuditProperties properties, ObjectMapper objectMapper,
                              ResourceLoader resourceLoader) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.resourceLoader = resourceLoader;
        loadInitial();
    }

    private void loadInitial() {
        try {
            Path snapshotDir = Path.of(properties.getDataDir(), "rule-snapshots");
            Files.createDirectories(snapshotDir);
            // 先恢复磁盘上已有的历史版本快照
            if (Files.isDirectory(snapshotDir)) {
                try (var stream = Files.list(snapshotDir)) {
                    stream.filter(p -> p.toString().endsWith(".json"))
                            .sorted(Comparator.comparing(Path::getFileName))
                            .forEach(this::loadSnapshot);
                }
            }
            applySource(false);
        } catch (IOException e) {
            throw new UncheckedIOException("初始化规则仓库失败: " + properties.getRulesLocation(), e);
        }
    }

    private void loadSnapshot(Path path) {
        try {
            RuleSet ruleSet = objectMapper.readValue(path.toFile(), RuleSet.class);
            validate(ruleSet);
            snapshots.put(ruleSet.version(), ruleSet);
            current = ruleSet;
        } catch (IOException e) {
            throw new UncheckedIOException("读取规则快照失败: " + path, e);
        }
    }

    @Override
    public synchronized RuleSet reload() {
        try {
            return applySource(true);
        } catch (IOException e) {
            throw new UncheckedIOException("重新加载规则失败: " + properties.getRulesLocation(), e);
        }
    }

    private RuleSet applySource(boolean allowNewVersion) throws IOException {
        String location = properties.getRulesLocation();
        Resource resource = resourceLoader.getResource(location);
        if (!resource.exists()) {
            throw new IOException("规则文件不存在: " + location);
        }
        String json;
        try (InputStream in = resource.getInputStream()) {
            json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        RuleSet loaded = objectMapper.readValue(json, RuleSet.class);
        validate(loaded);

        RuleSet existing = snapshots.get(loaded.version());
        if (existing != null) {
            // 同版本内容必须一致，否则拒绝覆盖
            String existingJson = objectMapper.writeValueAsString(existing);
            String loadedJson = objectMapper.writeValueAsString(loaded);
            if (!existingJson.equals(loadedJson)) {
                throw new IllegalStateException(
                        "规则版本 " + loaded.version() + " 的内容与已留存快照不一致，拒绝覆盖；"
                                + "修改规则请使用新的版本号");
            }
            current = existing;
            return existing;
        }

        if (!allowNewVersion && current != null && !snapshots.containsKey(loaded.version())) {
            // 启动恢复后，若文件版本是全新的，正常落快照（不视为热刷新）
        }

        // 留存不可变快照
        Path snapshotPath = Path.of(properties.getDataDir(), "rule-snapshots", loaded.version() + ".json");
        Files.createDirectories(snapshotPath.getParent());
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(snapshotPath.toFile(), loaded);
        snapshots.put(loaded.version(), loaded);
        current = loaded;
        return loaded;
    }

    private void validate(RuleSet ruleSet) {
        if (ruleSet == null || ruleSet.version() == null || ruleSet.version().isBlank()) {
            throw new IllegalArgumentException("规则集缺少 version");
        }
        if (ruleSet.eventSchemaVersion() == null || ruleSet.eventSchemaVersion().isBlank()) {
            throw new IllegalArgumentException("规则集 " + ruleSet.version() + " 缺少 eventSchemaVersion");
        }
        if (ruleSet.rules() == null) {
            throw new IllegalArgumentException("规则集 " + ruleSet.version() + " 的 rules 不能为 null");
        }
        for (Rule rule : ruleSet.rules()) {
            if (rule.id() == null || rule.id().isBlank()) {
                throw new IllegalArgumentException("规则集 " + ruleSet.version() + " 中存在缺少 id 的规则");
            }
            if (!"DENY".equalsIgnoreCase(rule.decision()) && !"ALLOW".equalsIgnoreCase(rule.decision())) {
                throw new IllegalArgumentException(
                        "规则 " + rule.id() + " 的 decision 必须是 DENY 或 ALLOW: " + rule.decision());
            }
        }
    }

    @Override
    public RuleSet current() {
        return current;
    }

    @Override
    public RuleSet getVersion(String version) {
        return snapshots.get(version);
    }

    @Override
    public List<String> versions() {
        return new ArrayList<>(snapshots.keySet());
    }
}
