package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.evidence.EvidencePackage;
import com.github.feng111627.auditcomplianceservicejava.evidence.EvidenceService;
import com.github.feng111627.auditcomplianceservicejava.evidence.EvidenceVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleEngine;
import com.github.feng111627.auditcomplianceservicejava.rules.RuleProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：端到端（存证与证据包 REST）—— 空实例导入外部证据包、续写编号不断档、
 * 摘要/增量核验/副本核对/证据包导出接口全链路跑通。
 * 用独立配置启一个全新应用上下文，保证账本为空、可以走导入路径。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "audit.forward.retry-backoff-ms=151")
class EvidenceApiTest {

    @Autowired
    private TestRestTemplate rest;

    @Test
    void importThenContinueAndVerifyOverRest() {
        TestLog.suite("端到端：证据包导入->续写->摘要->增量核验->副本核对->导出（REST 全链路）");
        TestLog.caseStart("空实例导入外部证据包 4 条，REST 续写 2 条，全链路核验");

        // 在测试进程内手工构造一套“外部服务”的证据包（不经过被测实例）
        AuditLedger externalLedger = new AuditLedger("");
        RuleProvider externalRules = new RuleProvider("classpath:rules.json");
        RuleEngine externalEngine = new RuleEngine(externalRules);
        EvidenceService externalEvidence = new EvidenceService(externalLedger, externalRules);
        for (int i = 1; i <= 4; i++) {
            AuditEvent event = new AuditEvent("evt-ext-" + i, "alice", "READ", "doc-" + i,
                    "SUCCESS", Instant.parse("2026-10-01T00:00:0" + i + "Z"), Map.of());
            externalLedger.append(event, externalEngine.evaluate(event));
        }
        EvidencePackage pkg = externalEvidence.export();

        ResponseEntity<Map<String, Object>> importResp = rest.exchange("/api/audit/evidence/import",
                HttpMethod.POST, new HttpEntity<>(pkg), new ParameterizedTypeReference<>() {});
        assertEquals(HttpStatus.OK, importResp.getStatusCode(), "合法证据包导入应成功");
        assertEquals(Boolean.TRUE, importResp.getBody().get("intact"));
        System.out.println("    导入响应: " + importResp.getBody());

        List<Map<String, Object>> batch = List.of(
                Map.of("eventId", "evt-new-1", "actor", "bob", "action", "READ",
                        "resource", "doc-9", "result", "SUCCESS", "timestamp", "2026-10-02T01:00:00Z"),
                Map.of("eventId", "evt-new-2", "actor", "carol", "action", "READ",
                        "resource", "doc-10", "result", "SUCCESS", "timestamp", "2026-10-02T01:00:01Z"));
        Map<String, Object> ingestResp = rest.exchange("/api/audit/events", HttpMethod.POST,
                new HttpEntity<>(batch), new ParameterizedTypeReference<Map<String, Object>>() {}).getBody();
        assertEquals(2, ((Number) ingestResp.get("accepted")).longValue());

        List<AuditRecord> records = rest.exchange("/api/audit/records", HttpMethod.GET, null,
                new ParameterizedTypeReference<List<AuditRecord>>() {}).getBody();
        assertEquals(6, records.size(), "导入 4 条 + 续写 2 条");
        for (int i = 0; i < 6; i++) {
            assertEquals(i + 1, records.get(i).seq(), "导入后续写必须接着原编号、不重号不断档");
        }
        assertEquals(records.get(3).hash(), records.get(4).prevHash(), "续写必须链接到导入链尾");

        Map<String, Object> verify = rest.getForObject("/api/audit/verify", Map.class);
        assertEquals(Boolean.TRUE, verify.get("intact"));

        LedgerDigest digest = rest.getForObject("/api/audit/digest", LedgerDigest.class);
        assertEquals(6, digest.recordCount());
        assertEquals(records.get(5).hash(), digest.tailHash(), "REST 摘要指纹必须等于链尾哈希");

        Map<String, Object> inc = rest.exchange("/api/audit/verify/incremental", HttpMethod.POST,
                new HttpEntity<>(digest), new ParameterizedTypeReference<Map<String, Object>>() {}).getBody();
        assertEquals(Boolean.TRUE, inc.get("intact"), "以刚生成的摘要为锚点增量核验应完好");
        assertEquals(0, ((Number) inc.get("checkedNewCount")).intValue());

        EvidencePackage exported = rest.getForObject("/api/audit/evidence", EvidencePackage.class);
        assertTrue(EvidenceVerifier.verify(exported).intact(),
                "REST 导出的证据包必须能通过离线核验");
        assertEquals(digest.recordCount(), exported.digest().recordCount());

        Map<String, Object> copyOk = rest.exchange("/api/audit/verify/copy", HttpMethod.POST,
                new HttpEntity<>(Map.of("digest", digest, "records", exported.records())),
                new ParameterizedTypeReference<Map<String, Object>>() {}).getBody();
        assertEquals(Boolean.TRUE, copyOk.get("matches"), "完整副本应核对一致");

        Map<String, Object> copyTruncated = rest.exchange("/api/audit/verify/copy", HttpMethod.POST,
                new HttpEntity<>(Map.of("digest", digest, "records", exported.records().subList(0, 4))),
                new ParameterizedTypeReference<Map<String, Object>>() {}).getBody();
        assertEquals(Boolean.FALSE, copyTruncated.get("matches"), "截断副本不能当成完好");
        assertEquals(2, ((Number) copyTruncated.get("missingCount")).intValue());

        ResponseEntity<String> reimport = rest.exchange("/api/audit/evidence/import",
                HttpMethod.POST, new HttpEntity<>(exported), String.class);
        assertNotEquals(HttpStatus.OK, reimport.getStatusCode(), "非空账本必须拒绝再次导入");

        TestLog.pass("导入 4 条+续写 2 条 seq=1..6 连续；摘要/增量/副本核对/导出全部符合预期；重复导入被拒");
    }
}
