package com.github.feng111627.auditcomplianceservicejava.evidence;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleProvider;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

/**
 * 证据包导出/导入编排。
 * 导出：取账本一致性快照 + 当前已知全部规则集版本，打成可移植证据包；
 * 导入：先做完整离线核验，通过才落入空账本并登记历史规则集，
 * 之后可接着原有编号继续追加。
 */
@Service
public class EvidenceService {

    private static final Logger log = LoggerFactory.getLogger(EvidenceService.class);

    private final AuditLedger ledger;
    private final RuleProvider ruleProvider;

    public EvidenceService(AuditLedger ledger, RuleProvider ruleProvider) {
        this.ledger = ledger;
        this.ruleProvider = ruleProvider;
    }

    /** 导出当前全部留存为证据包。摘要由快照本身推出，保证与包内记录自洽。 */
    public EvidencePackage export() {
        List<AuditRecord> snapshot = ledger.readAll();
        LedgerDigest digest = digestOf(snapshot);
        EvidencePackage pkg = new EvidencePackage(EvidenceVerifier.FORMAT,
                EvidenceVerifier.FORMAT_VERSION, Instant.now(), digest,
                snapshot, ruleProvider.all());
        log.info("已导出证据包: {} 条记录，整体指纹 {}", digest.recordCount(), digest.tailHash());
        return pkg;
    }

    /**
     * 导入证据包：离线核验通过才落账；导入后账本接着原有编号继续追加。
     * 内嵌规则集登记进规则提供者，历史记录仍可按当时版本复现结论。
     */
    public VerificationReport importPackage(EvidencePackage pkg) {
        VerificationReport report = EvidenceVerifier.verify(pkg);
        if (!report.intact()) {
            throw new IllegalArgumentException("证据包离线核验未通过，拒绝导入: " + report.anomalies());
        }
        ledger.importVerified(pkg.records());
        for (RuleSet ruleSet : pkg.ruleSets()) {
            ruleProvider.register(ruleSet);
        }
        log.info("证据包导入完成: {} 条记录，{} 个规则集版本", pkg.records().size(), pkg.ruleSets().size());
        return report;
    }

    /** 由一份记录快照推出其存证摘要（条数 + 链尾指纹）。 */
    public static LedgerDigest digestOf(List<AuditRecord> records) {
        String tail = records.isEmpty()
                ? RecordHasher.GENESIS : records.get(records.size() - 1).hash();
        return new LedgerDigest(records.size(), tail, Instant.now());
    }
}
