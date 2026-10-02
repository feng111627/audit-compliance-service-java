package com.github.feng111627.auditcomplianceservicejava.service;

import com.github.feng111627.auditcomplianceservicejava.alert.AlertOutbox;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceDecision;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.domain.IngestResponse;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleRepository;
import com.github.feng111627.auditcomplianceservicejava.rule.RuleSet;
import com.github.feng111627.auditcomplianceservicejava.store.AuditStore;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 审计事件接收服务。
 *
 * - 逐条校验：缺字段/格式错只拒该条，不影响同批其它条目，更不会静默放行；
 * - 校验通过的事件赋确定性服务端事件ID（客户端未提供时生成 UUID），
 *   按加锁提交顺序追加到账本，结论与所用规则版本一起留存；
 * - NON_COMPLIANT 事件入告警发件箱（本地落盘、异步转发），不阻塞接收。
 */
@Service
public class AuditIngestService {

    private final AuditStore store;
    private final RuleRepository ruleRepository;
    private final RuleEngine ruleEngine;
    private final AlertOutbox outbox;

    public AuditIngestService(AuditStore store, RuleRepository ruleRepository,
                              RuleEngine ruleEngine, AlertOutbox outbox) {
        this.store = store;
        this.ruleRepository = ruleRepository;
        this.ruleEngine = ruleEngine;
        this.outbox = outbox;
    }

    public IngestResponse ingest(List<AuditEvent> events) {
        List<IngestResponse.ItemResult> results = new ArrayList<>();
        int accepted = 0;
        int rejected = 0;

        if (events == null) {
            events = List.of();
        }
        int index = 0;
        for (AuditEvent event : events) {
            IngestResponse.ItemResult item = new IngestResponse.ItemResult();
            item.setIndex(index);
            index++;
            if (event != null) {
                item.setClientEventId(event.getEventId());
            }

            List<String> rejectionReasons = validate(event);
            if (!rejectionReasons.isEmpty()) {
                item.setAccepted(false);
                item.setRejectionReasons(rejectionReasons);
                rejected++;
                results.add(item);
                continue;
            }

            if (event.getEventId() == null || event.getEventId().isBlank()) {
                event.setEventId("evt-" + UUID.randomUUID());
            }

            RuleSet ruleSet = ruleRepository.current();
            ComplianceDecision decision = ruleEngine.evaluate(event, ruleSet);
            AuditRecord record = store.append(event, decision, ruleSet.eventSchemaVersion());

            if (decision.status() == ComplianceStatus.NON_COMPLIANT) {
                outbox.enqueue(record);
            }

            item.setAccepted(true);
            item.setSeq(record.getSeq());
            item.setStoredEventId(record.getEventId());
            item.setComplianceStatus(decision.status());
            item.setRuleVersion(decision.ruleVersion());
            item.setReasons(decision.reasons());
            accepted++;
            results.add(item);
        }

        IngestResponse response = new IngestResponse();
        response.setAcceptedCount(accepted);
        response.setRejectedCount(rejected);
        response.setResults(results);
        return response;
    }

    /**
     * 结构与格式校验。actor/action/resource/result 必填且非空白；
     * timestamp 选填但给出时必须是 ISO-8601；result 取值受限。
     */
    List<String> validate(AuditEvent event) {
        List<String> reasons = new ArrayList<>();
        if (event == null) {
            reasons.add("事件为空（null），无法解析");
            return reasons;
        }
        requireNonBlank(event.getActor(), "actor(操作者)", reasons);
        requireNonBlank(event.getAction(), "action(动作)", reasons);
        requireNonBlank(event.getResource(), "resource(资源)", reasons);
        requireNonBlank(event.getResult(), "result(结果)", reasons);

        if (event.getResult() != null && !event.getResult().isBlank()
                && !List.of("SUCCESS", "FAILURE").contains(event.getResult())) {
            reasons.add("result(结果) 取值非法: '" + event.getResult() + "'，只允许 SUCCESS 或 FAILURE");
        }
        if (event.getAction() != null) {
            String action = event.getAction().trim();
            if (!event.getAction().equals(action) || !event.getAction().matches("[A-Z0-9_-]+")) {
                reasons.add("action(动作) 格式非法: '" + event.getAction()
                        + "'，只允许大写字母/数字/下划线/短横线");
            }
        }
        if (event.getTimestamp() != null && !event.getTimestamp().isBlank()) {
            try {
                OffsetDateTime.parse(event.getTimestamp());
            } catch (DateTimeParseException e) {
                reasons.add("timestamp(时间戳) 格式非法: '" + event.getTimestamp()
                        + "'，要求 ISO-8601，例如 2026-10-02T10:00:00Z");
            }
        }
        return reasons;
    }

    private void requireNonBlank(String value, String field, List<String> reasons) {
        if (value == null || value.isBlank()) {
            reasons.add("缺少必填字段 " + field);
        }
    }
}
