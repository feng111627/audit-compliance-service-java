package com.github.feng111627.auditcomplianceservicejava.evidence;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.EvidencePack;
import com.github.feng111627.auditcomplianceservicejava.model.EvidencePackReport;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleProvider;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleSet;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 证据包编排：导出时把一段留存连同判定当时所用的全部规则集版本
 * 打包成可移植证据包；导入时先独立核验，再把规则集登记进历史、
 * 把记录恢复到空账本，之后可接着原编号继续追加。
 */
@Service
public class EvidenceService {

    private final AuditLedger ledger;
    private final RuleProvider ruleProvider;

    public EvidenceService(AuditLedger ledger, RuleProvider ruleProvider) {
        this.ledger = ledger;
        this.ruleProvider = ruleProvider;
    }

    /** 导出当前全部留存为证据包（条数与指纹取自同一快照，自洽）。 */
    public EvidencePack exportPack() {
        List<AuditRecord> records = ledger.readAll();
        Set<String> versions = new LinkedHashSet<>();
        for (AuditRecord record : records) {
            versions.add(record.verdict().ruleVersion());
        }
        List<RuleSet> ruleSets = versions.stream()
                .map(v -> ruleProvider.byVersion(v).orElseThrow(() -> new IllegalStateException(
                        "记录引用的规则版本 " + v + " 已不在历史中，无法导出证据包")))
                .toList();
        String tailHash = records.isEmpty()
                ? RecordHasher.GENESIS : records.get(records.size() - 1).hash();
        return new EvidencePack(EvidencePack.FORMAT_VERSION, Instant.now(),
                records.size(), tailHash, records, ruleSets);
    }

    /**
     * 导入证据包：先独立核验（链完整性、条数与指纹、结论按当时规则复现），
     * 通过后登记规则集历史并恢复记录到空账本。
     */
    public EvidencePackReport importPack(EvidencePack pack) {
        EvidencePackReport report = EvidencePackVerifier.verify(pack);
        if (!report.intact()) {
            throw new IllegalArgumentException("证据包核验未通过，拒绝导入: " + report.anomalies());
        }
        for (RuleSet ruleSet : pack.ruleSets()) {
            ruleProvider.register(ruleSet);
        }
        ledger.restore(pack.records());
        return report;
    }
}
