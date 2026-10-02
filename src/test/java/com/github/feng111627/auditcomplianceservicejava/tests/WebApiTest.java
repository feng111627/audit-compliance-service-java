package com.github.feng111627.auditcomplianceservicejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.auditcomplianceservicejava.alert.AsyncAlertForwarder;
import com.github.feng111627.auditcomplianceservicejava.alert.FileAlertOutbox;
import com.github.feng111627.auditcomplianceservicejava.alert.SimulatedDownstreamClient;
import com.github.feng111627.auditcomplianceservicejava.service.AuditIngestService;
import com.github.feng111627.auditcomplianceservicejava.service.ReplayService;
import com.github.feng111627.auditcomplianceservicejava.tests.support.BusinessTestLogging;
import com.github.feng111627.auditcomplianceservicejava.tests.support.TestContext;
import com.github.feng111627.auditcomplianceservicejava.web.AuditController;
import com.github.feng111627.auditcomplianceservicejava.web.SimulatedDownstreamController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 业务：HTTP 接口端到端（standalone MockMvc，不起真实端口、不联网）。
 */
@ExtendWith(BusinessTestLogging.class)
class WebApiTest {

    @TempDir
    Path dir;

    private MockMvc mockMvc;
    private SimulatedDownstreamClient downstream;
    private AsyncAlertForwarder forwarder;
    private FileAlertOutbox outbox;

    @BeforeEach
    void setUp() {
        var ctx = TestContext.create(dir);
        ctx.properties.setBackoffBaseMillis(0);
        ctx.properties.setMaxAttempts(2);
        outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        downstream = new SimulatedDownstreamClient();
        forwarder = new AsyncAlertForwarder(outbox, downstream, ctx.properties);
        var ingest = new AuditIngestService(ctx.store, ctx.ruleRepository, ctx.ruleEngine, outbox);
        var replay = new ReplayService(ctx.store, ctx.ruleRepository, ctx.ruleEngine);
        var auditController = new AuditController(ingest, ctx.store, ctx.ruleRepository, replay,
                outbox, forwarder, new ObjectMapper());
        var downstreamController = new SimulatedDownstreamController(downstream);
        mockMvc = MockMvcBuilders.standaloneSetup(auditController, downstreamController).build();
    }

    @Test
    @DisplayName("HTTP接口: 整体JSON非法时返回400并说明原因，而不是静默或500")
    void malformedJsonReturns400() throws Exception {
        mockMvc.perform(post("/api/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("请求体不是合法 JSON"));
        System.out.println("畸形 JSON 被 400 拒收");
    }

    @Test
    @DisplayName("HTTP接口: 混合批次逐条出结论（拒收/合规/不合规），不合规进入发件箱")
    void mixedBatchReturnsPerItemResults() throws Exception {
        String body = """
                { "events": [
                  { "action": "READ", "resource": "r", "result": "SUCCESS" },
                  { "actor": "bob", "action": "READ", "resource": "doc-1", "result": "SUCCESS" },
                  { "actor": "eve", "action": "DELETE", "resource": "prod-db", "result": "SUCCESS" }
                ] }
                """;
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.acceptedCount").value(2))
                .andExpect(jsonPath("$.rejectedCount").value(1))
                .andExpect(jsonPath("$.results[0].accepted").value(false))
                .andExpect(jsonPath("$.results[0].rejectionReasons[0]").value(org.hamcrest.Matchers.containsString("actor")))
                .andExpect(jsonPath("$.results[1].complianceStatus").value("COMPLIANT"))
                .andExpect(jsonPath("$.results[2].complianceStatus").value("NON_COMPLIANT"))
                .andExpect(jsonPath("$.results[2].seq").value(2));
        assertEquals1Pending();
        System.out.println("混合批次：1拒2收，其中1条不合规入发件箱");
    }

    private void assertEquals1Pending() throws Exception {
        mockMvc.perform(get("/api/alerts/pending"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    @DisplayName("HTTP接口: 写入后完整性校验通过，记录可按seq查询，不存在的seq返回404")
    void integrityAndRecordEndpoints() throws Exception {
        String body = """
                { "events": [
                  { "actor": "bob", "action": "READ", "resource": "doc-1", "result": "SUCCESS" }
                ] }
                """;
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/integrity"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.recordCount").value(1));

        mockMvc.perform(get("/api/records/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.seq").value(1));

        mockMvc.perform(get("/api/records/999"))
                .andExpect(status().isNotFound());
        System.out.println("完整性=通过，单条查询正常，缺失记录404");
    }

    @Test
    @DisplayName("HTTP接口: 下游连不上重试耗尽后死信可查询，切换回OK并重放后清零")
    void deadLettersLifecycleViaApi() throws Exception {
        String body = """
                { "events": [
                  { "actor": "eve", "action": "DELETE", "resource": "prod-db", "result": "SUCCESS" }
                ] }
                """;
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/test/downstream/mode")
                        .contentType(MediaType.APPLICATION_JSON).content("""
                                { "mode": "UNREACHABLE" }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("UNREACHABLE"));

        forwarder.drain();
        forwarder.drain();

        mockMvc.perform(get("/api/alerts/dead-letters"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].status").value("DEAD"))
                .andExpect(jsonPath("$[0].seq").value(1));

        mockMvc.perform(post("/api/test/downstream/mode")
                        .contentType(MediaType.APPLICATION_JSON).content("""
                                { "mode": "OK" }
                                """))
                .andExpect(status().isOk());
        // 重放接口内部会立即 drain 一次
        mockMvc.perform(post("/api/alerts/dead-letters/1/retry"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/alerts/dead-letters"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
        System.out.println("死信产生->查询->下游恢复->重放成功，死信清零");
    }
}
