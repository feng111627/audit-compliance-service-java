package com.github.feng111627.auditcomplianceservicejava.model;

import com.github.feng111627.auditcomplianceservicejava.rules.RuleSet;

import java.time.Instant;
import java.util.List;

/**
 * 可移植证据包：一段留存记录 + 判定当时所用的全部规则集版本 +
 * 整体指纹，序列化为单个 JSON 文件即可带走。
 * 拿到包的环境不需要部署本服务、不需要联网，即可独立核验：
 * 哈希链完整性、条数与整体指纹、以及逐条结论按当时规则复现是否一致。
 * 兼容范围：formatVersion 相同的包可互相导入；FORMAT_VERSION 升级时
 * 旧包是否可读以文档为准。
 */
public record EvidencePack(
        String formatVersion,
        Instant exportedAt,
        long recordCount,
        String tailHash,
        List<AuditRecord> records,
        List<RuleSet> ruleSets) {

    /** 当前证据包格式版本。 */
    public static final String FORMAT_VERSION = "evidence-pack/v1";
}
