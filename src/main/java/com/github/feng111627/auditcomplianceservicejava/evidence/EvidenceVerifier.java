package com.github.feng111627.auditcomplianceservicejava.evidence;

import com.github.feng111627.auditcomplianceservicejava.ledger.LedgerVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.MmrAccumulator;
import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleSet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 证据包离线核验器：纯静态方法，不依赖 Spring 容器、账本实例或
 * 任何外部服务。拿到证据包 JSON 即可独立核验：
 * 1) 记录哈希链完整性（篡改/删除/调换）；
 * 2) 内嵌摘要与记录是否一致（条数 + 整体指纹）；
 * 3) 用内嵌的规则集版本逐条复现判定结论，与记录中保存的结论比对。
 */
public final class EvidenceVerifier {

    public static final String FORMAT = "audit-evidence";
    public static final int FORMAT_VERSION = 1;

    private EvidenceVerifier() {
    }

    public static VerificationReport verify(EvidencePackage pkg) {
        List<String> anomalies = new ArrayList<>();

        if (!FORMAT.equals(pkg.format())) {
            anomalies.add("未知的证据包格式: " + pkg.format() + "（期望 " + FORMAT + "）");
        }
        if (pkg.formatVersion() != FORMAT_VERSION) {
            anomalies.add("不支持的证据包格式版本: " + pkg.formatVersion()
                    + "（本核验器支持 " + FORMAT_VERSION + "）");
        }

        List<AuditRecord> records = pkg.records() == null ? List.of() : pkg.records();

        VerificationReport chain = LedgerVerifier.verify(records);
        if (!chain.intact()) {
            anomalies.addAll(chain.anomalies());
        }

        if (pkg.digest() == null) {
            anomalies.add("证据包缺少存证摘要");
        } else {
            if (pkg.digest().recordCount() != records.size()) {
                anomalies.add("摘要与记录不一致: 摘要声明 " + pkg.digest().recordCount()
                        + " 条，实际 " + records.size() + " 条");
            }
            String actualTail = records.isEmpty()
                    ? RecordHasher.GENESIS : records.get(records.size() - 1).hash();
            if (!actualTail.equals(pkg.digest().tailHash())) {
                anomalies.add("摘要整体指纹不符: 摘要承诺 " + pkg.digest().tailHash()
                        + "，记录实际链尾 " + actualTail);
            }
            // 新格式摘要携带 MMR 山尖：山尖形状必须与条数一致，取值必须能由记录重算出来
            if (pkg.digest().peaks() != null && !pkg.digest().peaks().isEmpty()) {
                if (!MmrAccumulator.isValidShape(pkg.digest().peaks(), records.size())) {
                    anomalies.add("摘要 MMR 山尖形状与记录条数 " + records.size() + " 不一致，摘要已损坏或被调包");
                } else {
                    List<String> actualPeaks = MmrAccumulator.peaksFor(
                            records.stream().map(AuditRecord::hash).toList());
                    if (!actualPeaks.equals(pkg.digest().peaks())) {
                        anomalies.add("摘要 MMR 山尖与记录重算结果不符: 记录的位置承诺与摘要承诺的不是同一份内容");
                    }
                }
            }
        }

        Map<String, RuleSet> ruleSetsByVersion = new HashMap<>();
        for (RuleSet rs : pkg.ruleSets() == null ? List.<RuleSet>of() : pkg.ruleSets()) {
            ruleSetsByVersion.put(rs.version(), rs);
        }
        for (AuditRecord record : records) {
            String version = record.verdict() == null ? null : record.verdict().ruleVersion();
            RuleSet ruleSet = version == null ? null : ruleSetsByVersion.get(version);
            if (ruleSet == null) {
                anomalies.add("结论无法复现: seq=" + record.seq() + " 判定所用规则版本 "
                        + version + " 未随证据包提供");
                continue;
            }
            ComplianceVerdict replayed = RuleEngine.evaluate(record.event(), ruleSet);
            ComplianceVerdict original = record.verdict();
            if (replayed.status() != original.status()
                    || !replayed.violations().equals(original.violations())) {
                anomalies.add("结论复现不一致: seq=" + record.seq() + " 按规则版本 " + version
                        + " 重放得到 " + replayed.status() + "，记录中保存的是 " + original.status());
            }
        }

        return new VerificationReport(anomalies.isEmpty(), records.size(), List.copyOf(anomalies));
    }
}
