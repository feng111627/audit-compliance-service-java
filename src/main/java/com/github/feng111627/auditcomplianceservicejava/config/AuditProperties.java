package com.github.feng111627.auditcomplianceservicejava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** 本地配置：存储目录、规则文件路径、转发退避与最大重试次数。 */
@ConfigurationProperties(prefix = "audit")
public class AuditProperties {
    private String dataDir = "audit-data";
    private String rulesLocation = "classpath:rules/default-rules.json";
    private long forwardIntervalMillis = 200;
    private long backoffBaseMillis = 100;
    private int maxAttempts = 5;

    public String getDataDir() { return dataDir; }
    public void setDataDir(String dataDir) { this.dataDir = dataDir; }
    public String getRulesLocation() { return rulesLocation; }
    public void setRulesLocation(String rulesLocation) { this.rulesLocation = rulesLocation; }
    public long getForwardIntervalMillis() { return forwardIntervalMillis; }
    public void setForwardIntervalMillis(long forwardIntervalMillis) { this.forwardIntervalMillis = forwardIntervalMillis; }
    public long getBackoffBaseMillis() { return backoffBaseMillis; }
    public void setBackoffBaseMillis(long backoffBaseMillis) { this.backoffBaseMillis = backoffBaseMillis; }
    public int getMaxAttempts() { return maxAttempts; }
    public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }
}
