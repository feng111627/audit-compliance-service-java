package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.DigestVerifier;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.DigestCheckReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：存证摘要 —— 任意时刻生成可发布的整体指纹，副本核对能发现末尾整段删减与内容改动。 */
class LedgerDigestTest {

    private static AuditEvent event(int i) {
        return new AuditEvent("evt-d-" + i, "alice", "READ", "doc-" + i,
                "SUCCESS", Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
    }

    private static AuditLedger ledgerWith(int n) {
        AuditLedger ledger = new AuditLedger("");
        for (int i = 1; i <= n; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        return ledger;
    }

    @Test
    void digestMatchesSameContentCopy() {
        TestLog.suite("存证摘要：生成、副本核对、删减与改动识别");
        TestLog.caseStart("10 条记录生成摘要，同内容副本核对应一致");
        AuditLedger ledger = ledgerWith(10);
        LedgerDigest digest = ledger.digest();
        assertEquals(10, digest.recordCount());

        DigestCheckReport report = DigestVerifier.check(digest, ledger.readAll());
        assertTrue(report.matches(), "同内容副本应核对一致: " + report.anomalies());
        assertNull(report.missingFromSeq());
        TestLog.pass("摘要 recordCount=10，副本核对一致，指纹=" + digest.tailHash().substring(0, 16) + "...");
    }

    @Test
    void digestGeneratedUnderConcurrentAppendsPinsARealPrefix() throws Exception {
        TestLog.caseStart("4 线程持续追加的同时生成 200 份摘要，每份都必须对应最终历史的一个真实前缀");
        AuditLedger ledger = new AuditLedger("");
        int threads = 4, perThread = 150;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> writers = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            int threadId = t;
            writers.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                for (int i = 0; i < perThread; i++) {
                    ledger.append(new AuditEvent("evt-c-" + threadId + "-" + i, "u" + threadId,
                            "READ", "res", "SUCCESS", Instant.now(), Map.of()),
                            ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
                }
                return null;
            }));
        }
        assertTrue(ready.await(10, TimeUnit.SECONDS));

        List<LedgerDigest> digests = new CopyOnWriteArrayList<>();
        Future<?> reader = pool.submit(() -> {
            go.await();
            for (int i = 0; i < 200; i++) {
                digests.add(ledger.digest()); // 生成摘要不停顿、不等待写入
            }
            return null;
        });
        go.countDown();
        for (Future<?> f : writers) {
            f.get();
        }
        reader.get();
        pool.shutdown();

        List<AuditRecord> finalHistory = ledger.readAll();
        assertEquals(threads * perThread, finalHistory.size());
        for (LedgerDigest digest : digests) {
            long pos = digest.recordCount();
            assertTrue(pos >= 0 && pos <= finalHistory.size(),
                    "摘要位置必须落在历史范围内: " + pos);
            String actualTail = pos == 0 ? "GENESIS" : finalHistory.get((int) pos - 1).hash();
            assertEquals(digest.tailHash(), actualTail,
                    "每份摘要都必须对应最终历史 seq=" + pos + " 处的真实链尖（确定、自洽的位置）");
        }
        TestLog.pass("并发追加 " + finalHistory.size() + " 条期间生成 " + digests.size()
                + " 份摘要，逐一核对均钉在最终历史的真实前缀上");
    }

    @Test
    void truncatedCopyIsDetectedWithMissingRange() {
        TestLog.caseStart("副本末尾整段删掉 3 条，核对应指出缺少 seq=8..10 共 3 条");
        AuditLedger ledger = ledgerWith(10);
        LedgerDigest digest = ledger.digest();
        List<AuditRecord> truncated = new ArrayList<>(ledger.readAll().subList(0, 7));

        DigestCheckReport report = DigestVerifier.check(digest, truncated);
        assertFalse(report.matches(), "末尾被删减的副本不能当成完好");
        assertEquals(8L, report.missingFromSeq());
        assertEquals(3L, report.missingCount());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("末尾缺失")),
                "应说明少了哪些、少了多少: " + report.anomalies());
        TestLog.pass("检出末尾整段删减: " + report.anomalies());
    }

    @Test
    void tamperedCopyIsDetected() {
        TestLog.caseStart("副本第 4 条内容被改动，核对应发现");
        AuditLedger ledger = ledgerWith(10);
        LedgerDigest digest = ledger.digest();
        List<AuditRecord> copy = new ArrayList<>(ledger.readAll());
        AuditRecord original = copy.get(3);
        AuditEvent forged = new AuditEvent(original.event().eventId(), "mallory",
                original.event().action(), original.event().resource(), original.event().result(),
                original.event().timestamp(), original.event().attributes());
        copy.set(3, new AuditRecord(original.seq(), original.storedAt(), forged,
                original.verdict(), original.prevHash(), original.hash()));

        DigestCheckReport report = DigestVerifier.check(digest, copy);
        assertFalse(report.matches());
        assertTrue(report.anomalies().stream().anyMatch(a -> a.contains("篡改")),
                "应发现内容改动: " + report.anomalies());
        TestLog.pass("检出内容改动: " + report.anomalies());
    }

    @Test
    void newerCopyStillMatchesDigest() {
        TestLog.caseStart("摘要生成后又追加 5 条，用更长的副本核对旧摘要仍应一致");
        AuditLedger ledger = ledgerWith(10);
        LedgerDigest digest = ledger.digest();
        for (int i = 11; i <= 15; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        DigestCheckReport report = DigestVerifier.check(digest, ledger.readAll());
        assertTrue(report.matches(), "摘要位置及之前一致即可，副本更新不影响: " + report.anomalies());
        assertEquals(10, report.digestRecordCount());
        assertEquals(15, report.copyRecordCount());
        TestLog.pass("旧摘要(10 条)对 15 条副本核对一致：摘要钉住的是位置，之后的新增不影响核对");
    }
}
