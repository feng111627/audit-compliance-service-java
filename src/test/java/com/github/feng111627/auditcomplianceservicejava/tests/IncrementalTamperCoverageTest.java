package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.AuditLedger;
import com.github.feng111627.auditcomplianceservicejava.ledger.IncrementalVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.LedgerVerifier;
import com.github.feng111627.auditcomplianceservicejava.ledger.MmrAccumulator;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceStatus;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.IncrementalVerificationReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：增量核验漏报复盘 —— 可信摘要覆盖范围内的中间记录被改（含把自身校验码
 * 一并改对）、两条记录被互换时，快速路径增量核验必须发现并定位，且结论与
 * 整体核验一致；诚实账本不受误伤；哈希开销只随新增条数增长；并发追加下结论
 * 对应确定自洽的留存位置。
 */
class IncrementalTamperCoverageTest {

    private AuditLedger ledger;
    private LedgerDigest trustedDigest;
    private List<AuditRecord> honest;

    private static AuditEvent event(int i) {
        return new AuditEvent("evt-t-" + i, "alice", "READ", "doc-" + i,
                "SUCCESS", Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of());
    }

    /** 快速路径：当前山尖由受信追加结构（账本）在锁内提供，诚实周期下只算新增。 */
    private IncrementalVerificationReport fast(LedgerDigest digest, List<AuditRecord> records) {
        List<String> currentPeaks = MmrAccumulator.peaksFor(
                records.stream().map(AuditRecord::hash).toList());
        return IncrementalVerifier.verifySince(digest, records, currentPeaks);
    }

    @BeforeEach
    void setUp() {
        ledger = new AuditLedger("");
        for (int i = 1; i <= 5; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        trustedDigest = ledger.digest();
        for (int i = 6; i <= 10; i++) {
            ledger.append(event(i), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        honest = ledger.readAll();
    }

    @Test
    void honestLedgerStaysIntact() {
        TestLog.suite("增量核验漏报复盘：覆盖范围内篡改/互换必须发现且与整体核验一致");
        TestLog.caseStart("诚实账本：快速路径完好，只计新增 5 条，与整体核验一致");
        IncrementalVerificationReport inc = fast(trustedDigest, honest);
        assertTrue(inc.intact(), "诚实账本不应被误伤: " + inc.anomalies());
        assertEquals(5, inc.anchorCount());
        assertEquals(5, inc.checkedNewCount());
        assertEquals(10, inc.totalCount());
        assertTrue(LedgerVerifier.verify(honest).intact());
        TestLog.pass("锚点=5、新增=5，诚实账本快速路径完好，无异常明细");
    }

    @Test
    void middleRecordContentChangedWithOwnHashRecomputedIsDetected() {
        TestLog.caseStart("覆盖范围内 seq=3 内容被改且自身校验码一并改对（不重算其后链）：必须发现并定位");
        AuditRecord r3 = honest.get(2);
        AuditEvent forged = ChainTools.actorTampered(r3, "mallory");
        List<AuditRecord> tampered = ChainTools.changeContentAndRehashSelf(honest, 2, forged);

        // 前提：攻击者确实把 seq=3 的自带校验码改对了
        assertEquals(
                com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher.hashOf(tampered.get(2)),
                tampered.get(2).hash(), "攻击构造前提：seq=3 自带校验码应已被改对");
        boolean fullIntact = LedgerVerifier.verify(tampered).intact();
        assertFalse(fullIntact, "整体核验应在 seq=4 处看出链断裂");

        IncrementalVerificationReport inc = fast(trustedDigest, tampered);
        assertFalse(inc.intact(), "旧实现会漏报：仅核边界第 5 条与新增段；修复后必须发现");
        assertEquals(fullIntact, inc.intact(), "增量与整体核验结论必须一致");
        List<String> a = inc.anomalies();
        assertTrue(a.stream().anyMatch(x -> x.contains("可信锚点不匹配")), "应有锚点总述: " + a);
        assertTrue(a.stream().anyMatch(x -> x.contains("seq=3")),
                "应指出异常涉及 seq=3: " + a);
        assertTrue(a.stream().anyMatch(x -> x.contains("哈希链断裂: seq=4")),
                "应定位到链断裂的具体位置 seq=4（seq=3 的内容已被改）: " + a);
        TestLog.pass("检出覆盖范围内篡改（自身校验码已改对）：" + a.get(0));
    }

    @Test
    void middleRecordContentChangedKeepingHashIsDetected() {
        TestLog.caseStart("覆盖范围内 seq=2 内容被改、校验码原样保留：线下副本路径直接定位，账本重启路径兜底");
        AuditRecord r2 = honest.get(1);
        List<AuditRecord> tampered =
                ChainTools.changeContentKeepHash(honest, 1, ChainTools.actorTampered(r2, "mallory"));
        boolean fullIntact = LedgerVerifier.verify(tampered).intact();
        assertFalse(fullIntact);

        // 不受信副本路径：逐条重算内容哈希，直接定位 seq=2
        IncrementalVerificationReport offline = IncrementalVerifier.verifySince(trustedDigest, tampered);
        assertFalse(offline.intact(), "线下副本路径必须凭内容重算发现");
        assertTrue(offline.anomalies().stream().anyMatch(x -> x.contains("内容被篡改: seq=2")),
                "线下路径应直接定位 seq=2 内容篡改: " + offline.anomalies());

        // 活账本路径：该形态只能来自持久化文件被改后重启（内存记录锁内追加、不可变），
        // 启动全量核验发现后并入增量结论，保证增量与整体核验一致
        IncrementalVerificationReport restarted = tamperedLedgerFile(trustedDigest, tampered);
        assertFalse(restarted.intact(), "账本从被改文件重启后，增量核验必须与整体核验一致地发现");
        assertTrue(restarted.anomalies().stream().anyMatch(x -> x.contains("内容被篡改: seq=2")),
                "重启路径应把启动核验定位的 seq=2 并入增量结论: " + restarted.anomalies());
        TestLog.pass("线下路径内容重算 + 账本重启启动核验，均定位 seq=2，与整体核验结论一致");
    }

    @Test
    void twoRecordsSwappedInsideCoveredHistoryIsDetected() {
        TestLog.caseStart("覆盖范围内 seq=2 与 seq=3 两条记录整体互换：必须发现并指出两个位置");
        List<AuditRecord> swapped = ChainTools.swapWholeRecords(honest, 1, 2);
        boolean fullIntact = LedgerVerifier.verify(swapped).intact();
        assertFalse(fullIntact, "整体核验应发现乱序/断链");

        IncrementalVerificationReport inc = fast(trustedDigest, swapped);
        assertFalse(inc.intact(), "旧实现会漏报：边界第 5 条哈希不变；修复后山尖位置承诺必须发现");
        assertEquals(fullIntact, inc.intact(), "增量与整体核验结论必须一致");
        List<String> a = inc.anomalies();
        assertTrue(a.stream().anyMatch(x -> x.contains("可信锚点不匹配")), "应有锚点总述: " + a);
        assertTrue(a.stream().anyMatch(x -> x.contains("seq=2") && x.contains("seq=3")),
                "应指出互换涉及的两个位置 seq=2、seq=3: " + a);
        assertTrue(a.stream().anyMatch(x -> x.contains("序号断档/乱序")), "应有乱序明细: " + a);
        assertTrue(a.stream().anyMatch(x -> x.contains("哈希链断裂")), "应有断链明细: " + a);
        TestLog.pass("检出覆盖范围内两条互换，定位 seq=2/seq=3: " + a.get(0));
    }

    @Test
    void incrementalAndFullAgreeAcrossAllMutationScenarios() {
        TestLog.caseStart("多场景矩阵：每种篡改下增量（快速+线下）结论都与整体核验一致");
        List<Scenario> scenarios = new ArrayList<>();
        // 覆盖范围内
        scenarios.add(new Scenario("覆盖段中间内容改+自身校验码改对",
                ChainTools.changeContentAndRehashSelf(honest, 2, ChainTools.actorTampered(honest.get(2), "mallory"))));
        scenarios.add(new Scenario("覆盖段中间内容改、校验码不动",
                ChainTools.changeContentKeepHash(honest, 1, ChainTools.actorTampered(honest.get(1), "mallory"))));
        scenarios.add(new Scenario("覆盖段两条互换",
                ChainTools.swapWholeRecords(honest, 1, 3)));
        scenarios.add(new Scenario("覆盖段与新增段跨界互换 seq=4/seq=7",
                ChainTools.swapWholeRecords(honest, 3, 6)));
        // 新增部分（原有能力不得退化）
        scenarios.add(new Scenario("新增段内容改+校验码改对",
                ChainTools.changeContentAndRehashSelf(honest, 7, ChainTools.actorTampered(honest.get(7), "mallory"))));
        scenarios.add(new Scenario("新增段内容改、校验码不动",
                ChainTools.changeContentKeepHash(honest, 7, ChainTools.actorTampered(honest.get(7), "mallory"))));
        // 整条链重算伪装
        scenarios.add(new Scenario("覆盖段篡改后整链重算伪装",
                ChainTools.forgeAndRecompute(honest, 1, ChainTools.actorTampered(honest.get(1), "mallory"))));

        for (Scenario s : scenarios) {
            boolean full = LedgerVerifier.verify(s.records()).intact();
            IncrementalVerificationReport fastReport = fast(trustedDigest, s.records());
            IncrementalVerificationReport offline = IncrementalVerifier.verifySince(trustedDigest, s.records());
            assertFalse(offline.intact(), "场景[" + s.name() + "]线下路径必须发现");
            if (s.name().contains("整链重算伪装")) {
                // 该场景单看链条整体核验发现不了（自洽），靠可信锚点识破——锚点比裸整体核验更强
                assertTrue(full, "场景[" + s.name() + "]前提：重算伪装后链条自身自洽");
                assertFalse(fastReport.intact(), "场景[" + s.name() + "]快速路径必须凭山尖识破伪装");
                assertTrue(fastReport.anomalies().stream().anyMatch(x -> x.contains("可信锚点不匹配")),
                        "场景[" + s.name() + "]应报锚点不匹配: " + fastReport.anomalies());
                System.out.println("    [矩阵] " + s.name() + " -> 整体核验被瞒过，山尖锚点识破 ✔");
                continue;
            }
            assertFalse(full, "场景[" + s.name() + "]整体核验应发现问题");
            assertEquals(full, offline.intact(), "场景[" + s.name() + "]线下结论与整体核验不一致");
            if (s.name().contains("校验码不动")) {
                // “只改内容、自带哈希不变”在活账本内存里不可能发生（记录锁内追加不可变），
                // 快速路径的承诺对象是记录自带哈希；该形态只可能由文件被改+重启引入，
                // 由启动全量核验并入结论（另见 middleRecordContentChangedKeepingHashIsDetected）
                assertFalse(tamperedLedgerFile(trustedDigest, s.records()).intact(),
                        "场景[" + s.name() + "]账本重启路径必须发现");
                System.out.println("    [矩阵] " + s.name() + " -> 线下路径 + 账本重启路径检出 ✔");
            } else {
                assertFalse(fastReport.intact(), "场景[" + s.name() + "]快速路径必须发现，不得漏报");
                assertEquals(full, fastReport.intact(), "场景[" + s.name() + "]快速路径结论与整体核验不一致");
                System.out.println("    [矩阵] " + s.name() + " -> 快速路径明细 " + fastReport.anomalies().size() + " 条 ✔");
            }
        }
        TestLog.pass("7 种篡改场景下，增量核验（快速/线下/重启）均与整体核验结论一致或更强，无漏报");
    }

    @Test
    void unchangedExistingLocalizationStaysTheSame() {
        TestLog.caseStart("不误伤、不退化：新增段篡改/序号断档/末尾删除的定位信息保持原样");
        // 新增段内容改：定位 seq=8
        List<AuditRecord> t1 = ChainTools.changeContentKeepHash(honest, 7, ChainTools.actorTampered(honest.get(7), "mallory"));
        IncrementalVerificationReport r1 = fast(trustedDigest, t1);
        assertFalse(r1.intact());
        assertTrue(r1.anomalies().stream().anyMatch(x -> x.contains("内容被篡改: seq=8")),
                "新增段篡改仍定位 seq=8: " + r1.anomalies());

        // 末尾整段删除：缺失范围 seq=8..seq=10
        List<AuditRecord> truncated = new ArrayList<>(honest.subList(0, 7));
        LedgerDigest at10 = ledger.digest();
        IncrementalVerificationReport r2 = fast(at10, truncated);
        assertFalse(r2.intact());
        assertTrue(r2.anomalies().get(0).contains("seq=8") && r2.anomalies().get(0).contains("seq=10")
                        && r2.anomalies().get(0).contains("缺失"),
                "末尾删除仍说清 seq=8 到 seq=10: " + r2.anomalies());

        // 新增段序号断档：删掉新增部分一条并把后续 prevHash 重接不上 -> 通过整体构造一个乱序副本
        List<AuditRecord> gap = new ArrayList<>(honest);
        AuditRecord r8 = gap.get(7);
        gap.set(7, new AuditRecord(r8.seq() + 1, r8.storedAt(), r8.event(), r8.verdict(), r8.prevHash(), r8.hash()));
        IncrementalVerificationReport r3 = fast(trustedDigest, gap);
        assertFalse(r3.intact());
        assertTrue(r3.anomalies().stream().anyMatch(x -> x.contains("序号断档/乱序") && x.contains("seq=9")),
                "新增段乱序仍定位期望 seq=8/实际 seq=9: " + r3.anomalies());
        TestLog.pass("新增段篡改定位 seq=8、末尾删除说清 seq=8..10、新增段乱序定位 seq=9，原有定位信息不变");
    }

    @Test
    void hashWorkGrowsOnlyWithNewRecords() {
        TestLog.caseStart("哈希开销只随新增条数增长：旧山尖+新增长度 m 的追加哈希数为 2m+O(log k)，与历史长度无关");
        // 先 1000 条取可信锚点，再加到 2000；不同新增条数下只从旧山尖恢复后对新增追加
        AuditLedger big = new AuditLedger("");
        for (int i = 1; i <= 1000; i++) {
            big.append(new AuditEvent("evt-big-" + i, "alice", "READ", "d", "SUCCESS",
                    Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of()),
                    ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        LedgerDigest anchorAt1000 = big.digest();
        for (int i = 1001; i <= 2000; i++) {
            big.append(new AuditEvent("evt-big-" + i, "alice", "READ", "d", "SUCCESS",
                    Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of()),
                    ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }

        for (int m : new int[]{1, 10, 100, 1000}) {
            List<AuditRecord> prefix = new ArrayList<>(big.readAll().subList(0, 1000 + m));
            // 快速路径结论完好（诚实数据）
            IncrementalVerificationReport report = fast(anchorAt1000, prefix);
            assertTrue(report.intact(), "m=" + m + " 诚实增量应完好: " + report.anomalies());
            assertEquals(m, report.checkedNewCount());
            // 从旧山尖恢复并只追加 m 条：每条 1 次叶子哈希，历史进位造成的合并
            // 至多 log2(k)+1 次（与 m 无关），界为 m + (m 自身合并) + log(k) ≤ 2m + log2(k)+1
            MmrAccumulator acc = MmrAccumulator.restore(anchorAt1000.peaks(), anchorAt1000.recordCount());
            int hashes = 0;
            for (int i = 1000; i < 1000 + m; i++) {
                hashes += acc.append(prefix.get(i).hash());
            }
            long bound = 2L * m + 11L; // log2(1000) 向上取整 +1
            assertTrue(hashes <= bound, "m=" + m + " 哈希次数 " + hashes + " 应 ≤ 2m+log2(1000)+1=" + bound);
            System.out.println("    [开销] 历史=1000, 新增=" + m + " 时追加哈希数=" + hashes
                    + "（界 2m+log k=" + bound + "） ✔");
        }
        // 关键不变量：历史从 1000 增到 99900，同样新增 100 条，追加哈希数不能随历史增长
        AuditLedger measured = new AuditLedger("");
        for (int i = 1; i <= 99900; i++) {
            measured.append(new AuditEvent("evt-h2-" + i, "alice", "READ", "d", "SUCCESS",
                    Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of()),
                    ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        LedgerDigest anchor99900 = measured.digest();
        for (int i = 99901; i <= 100000; i++) {
            measured.append(new AuditEvent("evt-h2-" + i, "alice", "READ", "d", "SUCCESS",
                    Instant.parse("2026-10-01T00:00:00Z").plusSeconds(i), Map.of()),
                    ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
        }
        List<AuditRecord> last100 = measured.readAll();
        MmrAccumulator accHuge = MmrAccumulator.restore(anchor99900.peaks(), 99900);
        int hashesHuge = 0;
        for (int i = 99900; i < 100000; i++) {
            hashesHuge += accHuge.append(last100.get(i).hash());
        }
        assertTrue(hashesHuge <= 2 * 100 + 20, "99900 条历史下新增 100 条，哈希数 " + hashesHuge + " 仍应 ≤220");
        assertTrue(measured.verifyIncremental(anchor99900).intact());
        System.out.println("    [开销] 历史=99900, 新增=100 时追加哈希数=" + hashesHuge + "（不随历史增长） ✔");
        TestLog.pass("从可信旧山尖追加 m 条的哈希运算为 2m+O(log k)，k 从 1000 到 99900 开销不随历史增长");
    }

    @Test
    void concurrentAppendsAndVerificationsAlwaysLandOnSelfConsistentPosition() throws Exception {
        TestLog.caseStart("8 线程持续追加 + 1 线程不停生成摘要/做增量核验：每份结论对应确定自洽位置");
        AuditLedger live = new AuditLedger("");
        int threads = 8, perThread = 100;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads + 2);
        ConcurrentLinkedQueue<LedgerDigest> digests = new ConcurrentLinkedQueue<>();
        AtomicInteger verdicts = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger();

        for (int t = 0; t < threads; t++) {
            int base = t * perThread;
            pool.submit(() -> {
                await(start);
                for (int i = 1; i <= perThread; i++) {
                    live.append(new AuditEvent("evt-cc-" + (base + i), "u", "READ", "d", "SUCCESS",
                            Instant.now(), Map.of()), ComplianceVerdict.of(ComplianceStatus.ACCEPTED, "v1"));
                }
            });
        }
        pool.submit(() -> {
            await(start);
            long until = System.currentTimeMillis() + 1500;
            while (System.currentTimeMillis() < until) {
                LedgerDigest d = live.digest();
                digests.add(d);
                IncrementalVerificationReport report = live.verifyIncremental(d);
                verdicts.incrementAndGet();
                if (!report.intact() || report.anchorCount() > report.totalCount()) {
                    failures.incrementAndGet();
                }
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        assertEquals(800, live.size());
        assertEquals(0, failures.get(), "并发期间所有增量核验都应对自洽位置给出完好结论");
        assertTrue(verdicts.get() > 50, "应实际执行了大量并发核验，实际 " + verdicts.get());
        // 回头再核对：并发期间每份摘要仍对应最终账本的真实前缀位置
        List<AuditRecord> finalRecords = live.readAll();
        for (LedgerDigest d : digests) {
            String actual = d.recordCount() == 0
                    ? com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher.GENESIS
                    : finalRecords.get((int) d.recordCount() - 1).hash();
            assertEquals(actual, d.tailHash(), "并发摘要必须对应真实前缀: count=" + d.recordCount());
            assertTrue(live.verifyIncremental(d).intact(), "事后复核该摘要仍完好: count=" + d.recordCount());
        }
        TestLog.pass("并发期间 " + verdicts.get() + " 次摘要+增量核验全部完好，"
                + digests.size() + " 份摘要事后复核均对应真实自洽位置");
    }

    /**
     * 模拟“持久化文件在离线期间被改”：把给定（可能已篡改的）记录写成 JSONL，
     * 再从该文件启动一个新账本，以可信摘要为锚点做增量核验。
     */
    private IncrementalVerificationReport tamperedLedgerFile(LedgerDigest digest, List<AuditRecord> fileRecords) {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper()
                    .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                    .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            Path dir = Files.createTempDirectory("ledger-tamper");
            Path file = dir.resolve("ledger.jsonl");
            StringBuilder sb = new StringBuilder();
            for (AuditRecord r : fileRecords) {
                sb.append(mapper.writeValueAsString(r)).append(System.lineSeparator());
            }
            Files.writeString(file, sb.toString());
            AuditLedger restarted = new AuditLedger(file.toString());
            return restarted.verifyIncremental(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private record Scenario(String name, List<AuditRecord> records) {
    }
}
