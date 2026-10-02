package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：审计留存 —— 并发写入下序号唯一连续、读序等于提交序、完整性可校验。 */
class LedgerConcurrencyTest {

    @Test
    void concurrentAppendsProduceUniqueContiguousSequenceInCommitOrder() throws Exception {
        TestLog.suite("审计留存：并发写入的序号与顺序一致性");
        TestLog.caseStart("8 线程并发写入 800 条，序号应唯一、连续、无断档，读序=提交序");

        AuditLedger ledger = new AuditLedger("");
        int threads = 8, perThread = 100;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<List<Long>>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            int threadId = t;
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                List<Long> seqs = new ArrayList<>();
                for (int i = 0; i < perThread; i++) {
                    AuditEvent event = new AuditEvent("evt-" + threadId + "-" + i, "user" + threadId,
                            "READ", "res-" + i, "SUCCESS", Instant.now(), Map.of());
                    seqs.add(ledger.append(event,
                            ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1")).seq());
                }
                return seqs;
            }));
        }
        assertTrue(ready.await(10, java.util.concurrent.TimeUnit.SECONDS));
        go.countDown();

        Set<Long> allSeqs = new HashSet<>();
        for (Future<List<Long>> f : futures) {
            allSeqs.addAll(f.get());
        }
        pool.shutdown();

        int total = threads * perThread;
        assertEquals(total, allSeqs.size(), "序号不能重复");
        assertEquals(total, ledger.size());

        List<AuditRecord> records = ledger.readAll();
        for (int i = 0; i < total; i++) {
            assertEquals(i + 1, records.get(i).seq(), "读出的第 " + i + " 条序号应为 " + (i + 1));
        }

        VerificationReport report = ledger.verify();
        assertTrue(report.intact(), "并发写入后完整性校验应通过: " + report.anomalies());
        assertEquals(total, report.checkedCount());
        TestLog.pass("800 条并发写入：序号 1..800 唯一连续，读序与提交序一致，哈希链校验通过");
    }
}
