package com.github.feng111627.auditcomplianceservicejava.service;

import com.github.feng111627.auditcomplianceservicejava.forward.AlertForwarder;
import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleProvider;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 编排：逐条判定 -> 合规的留存 -> 需要告警的异步转发。
 * 被拒收的事件不落账（保证账本序号连续无断档），原因逐条返回；
 * 批量请求中单条失败不影响其他条。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final RuleEngine ruleEngine;
    private final RuleProvider ruleProvider;
    private final AuditLedger ledger;
    private final AlertForwarder forwarder;

    public AuditService(RuleEngine ruleEngine, RuleProvider ruleProvider,
                        AuditLedger ledger, AlertForwarder forwarder) {
        this.ruleEngine = ruleEngine;
        this.ruleProvider = ruleProvider;
        this.ledger = ledger;
        this.forwarder = forwarder;
    }

    /** 处理单条事件：返回结论；合规事件返回账本序号，ALERT 事件异步转发。 */
    public IngestResult ingest(int index, AuditEvent event) {
        ComplianceVerdict verdict = ruleEngine.evaluate(event);
        if (verdict.status() == ComplianceStatus.REJECTED) {
            log.info("事件被拒收: index={}, eventId={}, 原因数={}",
                    index, event == null ? null : event.eventId(), verdict.violations().size());
            return new IngestResult(index, verdict, null);
        }
        AuditRecord record = ledger.append(event, verdict);
        if (verdict.status() == ComplianceStatus.ALERT) {
            forwarder.submit(record);
        }
        return new IngestResult(index, verdict, record.seq());
    }

    /** 只判定不落账：供调用方在落账前补充校验（如非法时间戳）。 */
    public ComplianceVerdict evaluateOnly(AuditEvent event) {
        return ruleEngine.evaluate(event);
    }

    /**
     * 按记录保存的规则版本复现当时的结论。
     * 规则已升级也不影响：只要该版本规则集仍在历史中即可复现。
     */
    public ComplianceVerdict reproduce(AuditRecord record) {
        String version = record.verdict().ruleVersion();
        RuleSet historical = ruleProvider.byVersion(version)
                .orElseThrow(() -> new IllegalStateException(
                        "找不到版本为 " + version + " 的历史规则集，无法复现"));
        return RuleEngine.evaluate(record.event(), historical);
    }

    /** 复现结论并与记录中保存的结论比对是否一致。 */
    public boolean reproduceMatches(AuditRecord record) {
        ComplianceVerdict replayed = reproduce(record);
        ComplianceVerdict original = record.verdict();
        return replayed.status() == original.status()
                && replayed.violations().equals(original.violations());
    }

    public record IngestResult(int index, ComplianceVerdict verdict, Long seq) {
    }
}
