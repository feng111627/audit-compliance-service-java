package com.github.feng111627.auditcomplianceservicejava.service;

import com.github.feng111627.auditcomplianceservicejava.domain.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceDecision;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleRepository;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleSet;
import com.github.feng111627.auditcomplianceservicejava.store.AuditStore;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 历史结论复现服务。
 *
 * 每条记录留存了当时的规则版本号和事件结构版本；复现时取该版本的不可变规则快照
 * 重新判定，比较状态与命中规则集合。事件结构/规则升级后，只要历史快照仍在，
 * 老记录就按老规则得出与当时一致的结论。
 */
@Service
public class ReplayService {
    private final AuditStore store;
    private final RuleRepository ruleRepository;
    private final RuleEngine ruleEngine;

    public ReplayService(AuditStore store, RuleRepository ruleRepository, RuleEngine ruleEngine) {
        this.store = store;
        this.ruleRepository = ruleRepository;
        this.ruleEngine = ruleEngine;
    }

    public ReplayReport replayAll() {
        List<AuditRecord> records = store.readAll();
        ReplayReport report = new ReplayReport();
        List<ReplayReport.Mismatch> mismatches = new java.util.ArrayList<>();

        for (AuditRecord record : records) {
            String version = record.getDecision() == null ? null : record.getDecision().ruleVersion();
            RuleSet ruleSet = version == null ? null : ruleRepository.getVersion(version);
            if (ruleSet == null) {
                mismatches.add(new ReplayReport.Mismatch(record.getSeq(),
                        record.getDecision() == null ? "null" : record.getDecision().status().name(),
                        "不可复现", version, "缺失",
                        "规则版本快照缺失: " + version + "，无法复现 seq=" + record.getSeq()));
                continue;
            }
            ComplianceDecision replayed = ruleEngine.evaluate(record.getEvent(), ruleSet);
            ComplianceDecision stored = record.getDecision();

            boolean sameStatus = replayed.status() == stored.status();
            boolean sameMatched = replayed.matchedRuleIds().equals(stored.matchedRuleIds());
            if (!sameStatus || !sameMatched) {
                mismatches.add(new ReplayReport.Mismatch(record.getSeq(),
                        stored.status().name(), replayed.status().name(),
                        stored.ruleVersion(), version,
                        "状态或命中规则不一致: 留存命中=" + stored.matchedRuleIds()
                                + "，复现命中=" + replayed.matchedRuleIds()));
            }
        }

        report.setConsistent(mismatches.isEmpty());
        report.setChecked(records.size());
        report.setMismatches(mismatches);
        return report;
    }
}
