package com.github.feng111627.auditcomplianceservicejava.evidence;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleSet;

import java.time.Instant;
import java.util.List;

/**
 * 可移植证据包：一段留存记录 + 对应的存证摘要 + 判定时所用的
 * 全部规则集版本。可导出为 JSON 交给未部署本服务、甚至离线的
 * 环境独立核验；导回本服务实例后可接着原有编号继续追加。
 */
public record EvidencePackage(
        String format,
        int formatVersion,
        Instant exportedAt,
        LedgerDigest digest,
        List<AuditRecord> records,
        List<RuleSet> ruleSets) {
}
