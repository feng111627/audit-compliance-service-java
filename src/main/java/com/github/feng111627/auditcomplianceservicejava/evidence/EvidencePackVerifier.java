package com.github.feng111627.auditcomplianceservicejava.evidence;

import com.github.feng111627.auditcomplianceservicejava.ledger.LedgerVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.EvidencePack;
import com.github.feng111627.auditcomplianceservicejava.model.EvidencePackReport;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleSet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 证据包独立核验器：不依赖 Spring、不依赖本服务部署、不需要联网。
 * 核验三件事：
 * 1) 记录哈希链完整（篡改/删除/调换被发现）；
 * 2) 条数与整体指纹和包声明一致；
 * 3) 每条结论用包内携带的当时版本规则集复现，与记录保存的结论一致。
 */
public final class EvidencePackVerifier {

    private EvidencePackVerifier() {
    }

    public static EvidencePackReport verify(EvidencePack pack) {
        List<String> anomalies = new ArrayList<>();

        if (!EvidencePack.FORMAT_VERSION.equals(pack.formatVersion())) {
            anomalies.add("证据包格式版本不兼容: 期望 " + EvidencePack.FORMAT_VERSION
                    + "，实际 " + pack.formatVersion());
            return EvidencePackReport.of(pack.records() == null ? 0 : pack.records().size(), 0, anomalies);
        }

        List<AuditRecord> records = pack.records() == null ? List.of() : pack.records();

        // 1) 哈希链完整性
        VerificationReport chain = LedgerVerifier.verify(records);
        anomalies.addAll(chain.anomalies());

        // 2) 条数与整体指纹
        if (records.size() != pack.recordCount()) {
            anomalies.add("条数不符: 包声明 " + pack.recordCount() + " 条，实际 " + records.size() + " 条");
        }
        String actualTail = records.isEmpty()
                ? RecordHasher.GENESIS : records.get(records.size() - 1).hash();
        if (!actualTail.equals(pack.tailHash())) {
            anomalies.add("整体指纹不符: 包声明 tailHash=" + pack.tailHash() + "，实际链尖=" + actualTail);
        }

        // 3) 结论按当时规则复现
        Map<String, RuleSet> ruleSets = new HashMap<>();
        for (RuleSet rs : pack.ruleSets() == null ? List.<RuleSet>of() : pack.ruleSets()) {
            ruleSets.put(rs.version(), rs);
        }
        RuleEngine engine = RuleEngine.offline();
        long reproduced = 0;
        for (AuditRecord record : records) {
            String version = record.verdict().ruleVersion();
            RuleSet ruleSet = ruleSets.get(version);
            if (ruleSet == null) {
                anomalies.add("seq=" + record.seq() + " 判定所用规则版本 " + version
                        + " 未随包携带，无法复现");
                continue;
            }
            ComplianceVerdict replayed = engine.evaluate(record.event(), ruleSet);
            ComplianceVerdict original = record.verdict();
            if (replayed.status() != original.status()
                    || !replayed.violations().equals(original.violations())) {
                anomalies.add("seq=" + record.seq() + " 结论复现不一致: 记录保存 "
                        + original.status() + "，按当时规则复现为 " + replayed.status());
            }
            reproduced++;
        }

        return EvidencePackReport.of(records.size(), reproduced, anomalies);
    }
}
