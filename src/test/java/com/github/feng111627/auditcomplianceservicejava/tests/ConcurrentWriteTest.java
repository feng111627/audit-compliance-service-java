package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.alert.FileAlertOutbox;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.domain.IngestResponse;
import com.github.feng111627.auditcomplianceservicejava.service.AuditIngestService;
import com.github.feng111627.auditcomplianceservicejava.tests.support.BusinessTestLogging;
import com.github.feng111627.auditcomplianceservicejava.tests.support.TestContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 业务：按写入顺序留存 —— 并发写入与乱序输入。
 */
@ExtendWith(BusinessTestLogging.class)
class ConcurrentWriteTest {

    private AuditEvent event(String actor, int n, String timestamp) {
        AuditEvent e = new AuditEvent();
        e.setActor(actor);
        e.setAction("READ");
        e.setResource("res-" + n);
        e.setResult("SUCCESS");
        e.setTimestamp(timestamp);
        return e;
    }

    @Test
    @DisplayName("顺序留存: 8线程并发各写125条，编号1..1000不重复不断档，全部落盘")
    void concurrentWritesProduceGaplessUniqueSequence(@TempDir Path dir) throws Exception {
        var ctx = TestContext.create(dir);
        var outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var svc = new AuditIngestService(ctx.store, ctx.ruleRepository, ctx.ruleEngine, outbox);

        int threads = 8;
        int perThread = 125;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Long> assignedSeqs = new ConcurrentLinkedQueue<>();

        for (int t = 0; t < threads; t++) {
            final int threadNo = t;
            pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
                for (int i = 0; i < perThread; i++) {
                    int n = threadNo * perThread + i;
                    IngestResponse resp = svc.ingest(List.of(event("user-" + threadNo, n, null)));
                    assignedSeqs.add(resp.getResults().get(0).getSeq());
                }
            });
        }
        ready.await();
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        List<Long> seqs = new ArrayList<>(assignedSeqs);
        assertEquals(threads * perThread, seqs.size());
        assertEquals(threads * perThread, new HashSet<>(seqs).size(), "编号不得重复");
        Collections.sort(seqs);
        for (int i = 0; i < seqs.size(); i++) {
            assertEquals(i + 1L, seqs.get(i), "编号不得断档");
        }
        List<AuditRecord> stored = ctx.store.readAll();
        assertEquals(threads * perThread, stored.size(), "全部记录必须落盘");
        for (int i = 0; i < stored.size(); i++) {
            assertEquals(i + 1L, stored.get(i).getSeq(), "账本读出顺序即编号顺序");
        }
        System.out.println("并发写入完成：记录数=" + stored.size() + "，首条seq=1，末条seq="
                + stored.get(stored.size() - 1).getSeq());
    }

    @Test
    @DisplayName("顺序留存: 乱序时间戳输入时留存顺序仍等于提交顺序，时间戳仅作数据")
    void outOfOrderTimestampsFollowSubmissionOrder(@TempDir Path dir) {
        var ctx = TestContext.create(dir);
        var outbox = new FileAlertOutbox(ctx.properties, ctx.objectMapper);
        var svc = new AuditIngestService(ctx.store, ctx.ruleRepository, ctx.ruleEngine, outbox);

        // 提交顺序的时间戳故意从晚到早
        svc.ingest(List.of(event("a", 1, "2026-10-02T12:00:00Z")));
        svc.ingest(List.of(event("b", 2, "2026-10-01T09:00:00Z")));
        svc.ingest(List.of(event("c", 3, "2026-09-30T08:00:00Z")));

        List<AuditRecord> records = ctx.store.readAll();
        assertEquals("2026-10-02T12:00:00Z", records.get(0).getEvent().getTimestamp());
        assertEquals("2026-10-01T09:00:00Z", records.get(1).getEvent().getTimestamp());
        assertEquals("2026-09-30T08:00:00Z", records.get(2).getEvent().getTimestamp());
        System.out.println("乱序输入的留存时间戳顺序: "
                + records.stream().map(r -> r.getEvent().getTimestamp()).toList());
    }

    @Test
    @DisplayName("顺序留存: 账本可被重新打开（重启），新编号在历史最大编号后继续")
    void sequenceContinuesAcrossRestart(@TempDir Path dir) {
        var ctx1 = TestContext.create(dir);
        var outbox1 = new FileAlertOutbox(ctx1.properties, ctx1.objectMapper);
        new AuditIngestService(ctx1.store, ctx1.ruleRepository, ctx1.ruleEngine, outbox1)
                .ingest(List.of(event("a", 1, null)));

        // 模拟重启：用同一 dataDir 新建全部组件
        var ctx2 = TestContext.create(dir);
        var outbox2 = new FileAlertOutbox(ctx2.properties, ctx2.objectMapper);
        IngestResponse resp = new AuditIngestService(ctx2.store, ctx2.ruleRepository, ctx2.ruleEngine, outbox2)
                .ingest(List.of(event("b", 2, null)));

        assertEquals(2L, resp.getResults().get(0).getSeq());
        assertEquals(2, ctx2.store.readAll().size());
        System.out.println("重启后新分配编号=" + resp.getResults().get(0).getSeq());
    }
}
