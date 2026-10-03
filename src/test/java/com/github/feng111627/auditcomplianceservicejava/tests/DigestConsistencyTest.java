package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.IncrementalVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：存证摘要 —— 摘要与账本一致；并发追加下生成的每份摘要都对应确定、自洽的留存位置。 */
class DigestConsistencyTest {

    private static AuditEvent event(int i) {
        return new AuditEvent("evt-d-" + i, "alice", "READ", "doc-" + i,
                "SUCCESS", Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
    }

    @Test
    void digestReflectsCurrentLedgerPosition() {
        TestLog.suite("存证摘要：一致性、并发生成与末尾删减/内容改动识别");
        TestLog.caseStart("空账本与追加 5 条后的摘要内容");
        AuditLedger ledger = new AuditLedger("");
        LedgerDigest empty = ledger.digest();
        assertEquals(0, empty.recordCount());
        assertEquals(RecordHasher.GENESIS, empty.tailHash());

        for (int i = 1; i <= 5; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        LedgerDigest digest = ledger.digest();
        List<AuditRecord> records = ledger.readAll();
        assertEquals(5, digest.recordCount());
        assertEquals(records.get(4).hash(), digest.tailHash(),
                "整体指纹必须等于第 5 条记录的链尾哈希");
        TestLog.pass("空账本指纹=GENESIS；5 条后摘要=(count=5, tailHash=" + digest.tailHash() + ")");
    }

    @Test
    void concurrentDigestsCorrespondToRealPositions() throws Exception {
        TestLog.caseStart("8 线程并发追加 800 条，同时另一线程连续生成 200 份摘要");
        AuditLedger ledger = new AuditLedger("");
        int threads = 8, perThread = 100, digestRounds = 200;
        ConcurrentLinkedQueue<LedgerDigest> digests = new ConcurrentLinkedQueue<>();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads + 1);

        for (int t = 0; t < threads; t++) {
            int base = t * perThread;
            pool.submit(() -> {
                await(start);
                for (int i = 1; i <= perThread; i++) {
                    ledger.append(event(base + i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
                }
            });
        }
        pool.submit(() -> {
            await(start);
            for (int i = 0; i < digestRounds; i++) {
                digests.add(ledger.digest());
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS), "并发追加与摘要生成都应在不停等的情况下完成");

        List<AuditRecord> finalRecords = ledger.readAll();
        assertEquals(threads * perThread, finalRecords.size());
        assertEquals(digestRounds, digests.size());
        for (LedgerDigest d : digests) {
            assertTrue(d.recordCount() <= finalRecords.size(),
                    "摘要位置不能超过最终账本长度: " + d.recordCount());
            String actualHashAtPosition = d.recordCount() == 0
                    ? RecordHasher.GENESIS
                    : finalRecords.get((int) d.recordCount() - 1).hash();
            assertEquals(actualHashAtPosition, d.tailHash(),
                    "每份摘要都必须对应最终账本中一个真实、自洽的前缀位置: count=" + d.recordCount());
            assertTrue(IncrementalVerifier.verifySince(d, finalRecords).intact(),
                    "以该摘要为锚点对最终账本做增量核验必须完好: count=" + d.recordCount());
        }
        TestLog.pass("200 份摘要全部对应最终账本的真实前缀位置，且以其为锚点的增量核验全部完好");
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
