package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.forward.AlertForwarder;
import com.github.feng111627.auditcomplianceservicejava.forward.SimulatedDownstreamClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：端到端 —— 本地启动服务，批量接收、留存查询、完整性校验、失败队列全链路跑通。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiIntegrationTest {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private SimulatedDownstreamClient downstream;

    @Autowired
    private AlertForwarder forwarder;

    @Test
    void endToEndIngestVerifyAndDeadLetters() throws Exception {
        TestLog.suite("端到端：REST 全链路（接收->留存->校验->转发->失败队列）");
        TestLog.caseStart("批量提交 3 好 1 坏，验证逐条结论、留存顺序、完整性与异步转发");

        downstream.reset();
        List<Map<String, Object>> batch = List.of(
                Map.of("eventId", "evt-api-1", "actor", "alice", "action", "READ",
                        "resource", "doc-1", "result", "SUCCESS", "timestamp", "2026-10-02T01:00:00Z"),
                Map.of("eventId", "evt-api-2", "actor", "bob", "action", "DELETE",
                        "resource", "doc-2", "result", "FAILURE", "timestamp", "2026-10-02T01:00:01Z"),
                Map.of("actor", "carol", "action", "READ", "resource", "doc-3", "result", "SUCCESS"),
                Map.of("eventId", "evt-api-3", "actor", "dave", "action", "EXPORT",
                        "resource", "report", "result", "SUCCESS", "timestamp", "not-a-timestamp"));

        ResponseEntity<Map<String, Object>> resp = rest.exchange("/api/audit/events", HttpMethod.POST,
                new HttpEntity<>(batch), new ParameterizedTypeReference<>() {});
        Map<String, Object> body = resp.getBody();
        assertEquals(4, ((Number) body.get("total")).intValue());
        assertEquals(2, ((Number) body.get("accepted")).longValue(), "evt-api-1/2 合规，另两条被拒");
        assertEquals(2, ((Number) body.get("rejected")).longValue());
        System.out.println("    批量响应: total=" + body.get("total") + " accepted=" + body.get("accepted")
                + " rejected=" + body.get("rejected"));

        List<Map<String, Object>> records = rest.exchange("/api/audit/records", HttpMethod.GET, null,
                new ParameterizedTypeReference<List<Map<String, Object>>>() {}).getBody();
        assertEquals(2, records.size());
        assertEquals(1, ((Number) records.get(0).get("seq")).intValue());
        assertEquals(2, ((Number) records.get(1).get("seq")).intValue());
        System.out.println("    留存记录: seq=1 eventId=" + ((Map<?, ?>) records.get(0).get("event")).get("eventId")
                + ", seq=2 eventId=" + ((Map<?, ?>) records.get(1).get("event")).get("eventId"));

        Map<String, Object> verify = rest.getForObject("/api/audit/verify", Map.class);
        assertEquals(Boolean.TRUE, verify.get("intact"));
        System.out.println("    完整性校验: intact=" + verify.get("intact") + " checked=" + verify.get("checkedCount"));

        // evt-api-2 是 DELETE+FAILURE -> ALERT，应被异步转发到模拟下游
        assertTrue(forwarder.awaitIdle(5000));
        assertEquals(1, forwarder.deliveredCount());
        assertTrue(downstream.hasReceived("evt-api-2"));
        System.out.println("    异步转发: evt-api-2 已投递模拟下游，失败队列大小="
                + rest.getForObject("/api/forward/dead-letters", List.class).size());

        Map<String, Object> replay = rest.getForObject("/api/audit/records/1/reproduce", Map.class);
        assertEquals(Boolean.TRUE, replay.get("matches"));
        TestLog.pass("批量接收/留存/校验/转发/复现全链路通过");
    }
}
