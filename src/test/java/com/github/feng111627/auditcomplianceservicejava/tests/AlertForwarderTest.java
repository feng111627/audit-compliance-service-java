package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.forward.AlertForwarder;
import com.github.feng111627.auditcomplianceservicejava.forward.SimulatedDownstreamClient;
import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：告警转发 —— 下游故障重试、最终失败进失败队列、去重不重复投递、接收不被拖慢。 */
class AlertForwarderTest {

    private static final int MAX_ATTEMPTS = 3;

    private SimulatedDownstreamClient downstream;
    private AlertForwarder forwarder;
    private AuditLedger ledger;

    @BeforeEach
    void setUp() {
        TestLog.suite("告警转发：故障重试、失败队列与去重语义");
        downstream = new SimulatedDownstreamClient();
        forwarder = new AlertForwarder(downstream, MAX_ATTEMPTS, 30);
        ledger = new AuditLedger("");
    }

    @AfterEach
    void tearDown() {
        forwarder.shutdown();
    }

    private AuditRecord alertRecord(String eventId) {
        return ledger.append(new AuditEvent(eventId, "bob", "DELETE", "db-" + eventId,
                        "FAILURE", Instant.now(), Map.of()),
                ComplianceVerdict.of(ComplianceStatus.ALERT, "v1"));
    }

    @Test
    void transientFailureIsRetriedAndEventuallyDeliveredOnce() throws Exception {
        TestLog.caseStart("下游前 2 次故障，第 3 次重试应成功，且只投递一次");
        downstream.failNextTimes(2);
        AuditRecord record = alertRecord("evt-retry-1");
        forwarder.submit(record);

        assertTrue(forwarder.awaitIdle(5000), "转发器应在限时内处理完");
        assertEquals(1, forwarder.deliveredCount());
        assertEquals(1, downstream.received().size(), "去重后下游只应收到一条");
        assertEquals(3, downstream.deliveryAttempts(), "应恰好尝试 3 次");
        assertTrue(forwarder.deadLetters().isEmpty());
        TestLog.pass("2 次故障后第 3 次重试成功，下游去重收到 1 条，失败队列为空");
    }

    @Test
    void persistentFailureLandsInDeadLetterQueue() throws Exception {
        TestLog.caseStart("下游持续故障超过最大重试次数，事件应进失败队列且不丢");
        downstream.failNextTimes(10);
        AuditRecord record = alertRecord("evt-dlq-1");
        forwarder.submit(record);

        assertTrue(forwarder.awaitIdle(5000));
        assertEquals(0, forwarder.deliveredCount());
        assertEquals(1, forwarder.deadLetters().size(), "最终失败应进失败队列");
        assertEquals("evt-dlq-1", forwarder.deadLetters().get(0).record().event().eventId());
        assertEquals(MAX_ATTEMPTS, forwarder.deadLetters().get(0).attempts());
        assertEquals(MAX_ATTEMPTS, downstream.deliveryAttempts());
        TestLog.pass("重试 " + MAX_ATTEMPTS + " 次后进入失败队列，事件内容完整可查: "
                + forwarder.deadLetters().get(0).lastError());
    }

    @Test
    void duplicateSubmissionAndDuplicateAckDoNotRedeliver() throws Exception {
        TestLog.caseStart("同一事件重复提交 + 下游重复回执，不应重复投递");
        AuditRecord record = alertRecord("evt-dup-1");
        forwarder.submit(record);
        forwarder.submit(record); // 重复提交应被忽略
        forwarder.submit(record);

        assertTrue(forwarder.awaitIdle(5000));
        assertEquals(1, forwarder.deliveredCount());
        assertEquals(1, downstream.received().size(), "下游只应实际收到一条");
        assertEquals(1, downstream.deliveryAttempts(), "只应投递一次");
        TestLog.pass("3 次提交只投递 1 次，下游幂等回执不造成重复计数");
    }

    @Test
    void submitDoesNotBlockWhenDownstreamIsDown() {
        TestLog.caseStart("下游持续故障时 submit 应立即返回，不拖慢事件接收");
        downstream.failNextTimes(100);
        long start = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            forwarder.submit(alertRecord("evt-noblock-" + i));
        }
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
        assertTrue(elapsedMillis < 1000, "100 次 submit 应在 1 秒内返回，实际 " + elapsedMillis + "ms");
        TestLog.pass("下游故障期间 100 次 submit 共耗时 " + elapsedMillis + "ms，接收不被拖慢");
    }
}
