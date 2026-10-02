package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.alert.AlertMessage;
import com.github.feng111627.auditcomplianceservicejava.alert.AsyncAlertForwarder;
import com.github.feng111627.auditcomplianceservicejava.alert.FileAlertOutbox;
import com.github.feng111627.auditcomplianceservicejava.alert.OutboxEntry;
import com.github.feng111627.auditcomplianceservicejava.alert.SimulatedDownstreamClient;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.domain.IngestResponse;
import com.github.feng111627.auditcomplianceservicejava.service.AuditIngestService;
import com.github.feng111627.auditcomplianceservicejava.tests.support.BusinessTestLogging;
import com.github.feng111627.auditcomplianceservicejava.tests.support.TestContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 业务：告警异步转发 —— 故障、重试、幂等、死信、恢复。
 */
@ExtendWith(BusinessTestLogging.class)
class AlertForwardingTest {

    private AuditEvent nonCompliantEvent() {
        AuditEvent e = new AuditEvent();
        e.setActor("alice");
        e.setAction("DELETE");
        e.setResource("prod-db-1");
        e.setResult("SUCCESS");
        return e;
    }

    private AuditRecord ingestOneAlert(TestContext ctx, FileAlertOutbox outbox) {
        var svc = new AuditIngestService(ctx.store, ctx.ruleRepository, ctx.ruleEngine, outbox);
        IngestResponse resp = svc.ingest(List.of(nonCompliantEvent()));
        assertEquals(ComplianceStatus.NON_COMPLIANT, resp.getResults().get(0).getComplianceStatus());
        AuditRecord record = ctx.store.findBySeq(resp.getResults().get(0).getSeq()).orElseThrow();
        return record;
    }

    @Test
    @DisplayName("异步转发: 不合规事件入发件箱后异步投递成功，且只投递一次")
    void alertDeliveredOnce(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        var outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var downstream = new SimulatedDownstreamClient();
        var forwarder = new AsyncAlertForwarder(outbox, downstream, ctx.properties);

        AuditRecord record = ingestOneAlert(ctx, outbox);
        assertEquals(1, outbox.pending().size(), "先落盘 PENDING");
        assertEquals(0, downstream.getReceived().size(), "接收路径不得同步投递");

        int delivered = forwarder.drain();
        assertEquals(1, delivered);
        assertEquals(0, outbox.pending().size());
        // 再 drain 若干轮也不会重复投递
        forwarder.drain();
        forwarder.drain();
        assertEquals(1, downstream.getReceived().size());
        assertEquals(1, downstream.getDeliveredSeqs().size());
        assertTrue(downstream.getDeliveredSeqs().contains(record.getSeq()));
        System.out.println("告警 seq=" + record.getSeq() + " 投递成功，发件箱剩余 PENDING=0");
    }

    @Test
    @DisplayName("异步转发: 先连续失败2次再恢复，重试后成功，事件不丢且不重复")
    void retryAfterTransientFailuresSucceeds(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        ctx.properties.setBackoffBaseMillis(0);
        var outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var downstream = new SimulatedDownstreamClient();
        var forwarder = new AsyncAlertForwarder(outbox, downstream, ctx.properties);

        AuditRecord record = ingestOneAlert(ctx, outbox);
        downstream.failNextTimes(2);

        int first = forwarder.drain();
        assertEquals(0, first);
        assertEquals(1, outbox.pending().size());
        assertEquals(1, outbox.pending().get(0).getAttempts());

        int second = forwarder.drain();
        assertEquals(0, second);
        assertEquals(2, outbox.pending().get(0).getAttempts());

        int third = forwarder.drain();
        assertEquals(1, third);
        assertEquals(0, outbox.pending().size());
        assertEquals(1, downstream.getDeliveredSeqs().size());
        assertTrue(downstream.getDeliveredSeqs().contains(record.getSeq()));
        System.out.println("seq=" + record.getSeq() + " 经历2次失败后重试成功，最终投递1次");
    }

    @Test
    @DisplayName("异步转发: 下游始终连不上，重试达到上限进入死信队列且可查询")
    void persistentFailureGoesToDeadLetterQueue(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        ctx.properties.setBackoffBaseMillis(0);
        ctx.properties.setMaxAttempts(3);
        var outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var downstream = new SimulatedDownstreamClient();
        var forwarder = new AsyncAlertForwarder(outbox, downstream, ctx.properties);

        AuditRecord record = ingestOneAlert(ctx, outbox);
        downstream.setMode(SimulatedDownstreamClient.Mode.UNREACHABLE);

        forwarder.drain();
        forwarder.drain();
        forwarder.drain();

        assertEquals(0, outbox.pending().size());
        List<OutboxEntry> dead = outbox.deadLetters();
        assertEquals(1, dead.size());
        assertEquals(record.getSeq(), dead.get(0).getSeq());
        assertEquals(3, dead.get(0).getAttempts());
        assertNotNull(dead.get(0).getLastError());
        assertTrue(dead.get(0).getLastError().contains("connection refused"));
        System.out.println("死信队列: seq=" + dead.get(0).getSeq()
                + " attempts=" + dead.get(0).getAttempts() + " 原因=" + dead.get(0).getLastError());
    }

    @Test
    @DisplayName("异步转发: 下游恢复后可把死信重新入队并投递成功")
    void deadLetterCanBeReplayedAfterRecovery(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        ctx.properties.setBackoffBaseMillis(0);
        ctx.properties.setMaxAttempts(2);
        var outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var downstream = new SimulatedDownstreamClient();
        var forwarder = new AsyncAlertForwarder(outbox, downstream, ctx.properties);

        AuditRecord record = ingestOneAlert(ctx, outbox);
        downstream.setMode(SimulatedDownstreamClient.Mode.TIMEOUT);
        forwarder.drain();
        forwarder.drain();
        assertEquals(1, outbox.deadLetters().size());

        downstream.setMode(SimulatedDownstreamClient.Mode.OK);
        assertEquals(1, outbox.retryDeadLetter(record.getSeq()));
        forwarder.drain();

        assertEquals(0, outbox.deadLetters().size());
        assertEquals(0, outbox.pending().size());
        assertTrue(downstream.getDeliveredSeqs().contains(record.getSeq()));
        System.out.println("死信 seq=" + record.getSeq() + " 在下游恢复后重放成功");
    }

    @Test
    @DisplayName("异步转发: 重复回执/超时重试场景下同一条成功事件不会被重复投递")
    void duplicateAckDoesNotCauseDuplicateDelivery(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        ctx.properties.setBackoffBaseMillis(0);
        var outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var downstream = new SimulatedDownstreamClient();
        var forwarder = new AsyncAlertForwarder(outbox, downstream, ctx.properties);

        AuditRecord record = ingestOneAlert(ctx, outbox);
        downstream.setMode(SimulatedDownstreamClient.Mode.DUPLICATE_ACK);
        int delivered = forwarder.drain();
        assertEquals(1, delivered);
        // 下游每次都回重复成功回执，但发件箱已标记 DELIVERED，不会再投递
        forwarder.drain();
        forwarder.drain();
        AlertMessage onlyMessage = downstream.getReceived().get(0);
        assertEquals(record.getSeq(), onlyMessage.seq());
        assertEquals(1, downstream.getReceived().size(), "重复回执不得触发重复投递");
        System.out.println("重复回执场景下实际网络投递次数=" + downstream.getReceived().size());
    }

    @Test
    @DisplayName("异步转发: 投递中途“重启”，未完成的 PENDING 从文件恢复并最终送达，不丢不重")
    void pendingRecoversAcrossRestart(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        ctx.properties.setBackoffBaseMillis(0);
        var outbox1 = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var downstream1 = new SimulatedDownstreamClient();
        downstream1.setMode(SimulatedDownstreamClient.Mode.UNREACHABLE);
        var forwarder1 = new AsyncAlertForwarder(outbox1, downstream1, ctx.properties);

        AuditRecord record = ingestOneAlert(ctx, outbox1);
        forwarder1.drain();
        assertEquals(1, outbox1.pending().size(), "故障期间仍为 PENDING 并已持久化");

        // 模拟重启：用同一目录重建发件箱与转发器，下游恢复
        var outbox2 = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var downstream2 = new SimulatedDownstreamClient();
        var forwarder2 = new AsyncAlertForwarder(outbox2, downstream2, ctx.properties);
        forwarder2.drain();

        assertEquals(0, outbox2.pending().size());
        assertTrue(downstream2.getDeliveredSeqs().contains(record.getSeq()));
        assertEquals(1, downstream2.getReceived().size());
        System.out.println("重启恢复后 seq=" + record.getSeq() + " 送达，投递次数=" + downstream2.getReceived().size());
    }
}
