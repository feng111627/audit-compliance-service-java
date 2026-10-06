package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.IncrementalVerificationReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 增量核验器：以“上一回已确认可信”的摘要为锚点核验当前记录。
 *
 * 锚点由两部分组成：摘要的 tailHash（哈希链尾，承诺链式衔接）与 peaks
 * （MMR 山尖集，按位置承诺各山尖覆盖段内每条记录自带哈希的有序聚合）。
 *
 * 快速路径（{@link #verifySince(LedgerDigest, List, List)}，当前山尖由
 * {@link AuditLedger#verifyIncremental} 在同一把锁内提供）：
 *   1. 从可信旧山尖出发，只对新增的 m 条记录做 MMR 追加，哈希运算总量
 *      ≤ 2m（每条 1 次叶子哈希 + 生命周期内至多 1 次父节点合并），与已有
 *      历史长度无关，不会退化成从头重算整段历史；
 *   2. 期望山尖与当前山尖逐段比对：山尖形状只由条数决定，前 k 条中任何
 *      一段的记录被改（哪怕把自身校验码也改对、哪怕把整链重算伪装）或
 *      两条/两段位置被交换，对应山尖必然偏离；
 *   3. 山尖不一致时，按山尖覆盖的确定位置区间（哪一段、哪几个位置、多少条）
 *      与新增段做区间合并，只对合并后的区间重放与 {@link LedgerVerifier}
 *      完全同口径的三项检查（序号、内容重算哈希、prevHash），给出逐条定位；
 *   4. 山尖全部一致时只扫描新增段，代价 O(新增条数)。
 *
 * 因此对受信账本（记录由追加结构独占维护、不可被外部改写）而言，整体核验
 * 能发现的问题增量核验都能发现，两者对同一批记录结论一致。
 *
 * 无当前山尖的线下副本核验（{@link #verifySince(LedgerDigest, List)}）：
 * 调用方手上的副本可能“只改内容、不换自带哈希”，山尖对它不构成内容承诺，
 * 因此该入口直接做一次整体核验（与 LedgerVerifier 逐条等价）外加链尾锚定，
 * 不漏报但代价与副本总长相关；周期性线上核验请走账本的锁内快速路径。
 * 无 MMR 山尖的旧格式摘要同样按整体核验处理。
 */
public final class IncrementalVerifier {

    private IncrementalVerifier() {
    }

    /**
     * 只凭可信摘要与一份记录副本核验：整体核验（逐条三项检查）+ 链尾锚定。
     * 用于不受信副本（可能只改内容不改自带哈希），代价与副本总长相关。
     */
    public static IncrementalVerificationReport verifySince(LedgerDigest trusted, List<AuditRecord> records) {
        List<String> anomalies = new ArrayList<>();
        long k = trusted.recordCount();

        if (records.size() < k) {
            anomalies.add("末尾整段缺失: 可信摘要覆盖到 seq=" + k + "，当前只有 " + records.size()
                    + " 条，缺少 seq=" + (records.size() + 1) + " 到 seq=" + k
                    + "，共 " + (k - records.size()) + " 条");
            return new IncrementalVerificationReport(false, k, 0, records.size(), List.copyOf(anomalies));
        }

        // 线下副本不可信：逐条重算，内容改动（含没改校验码的）、断序、断链全部落位
        anomalies.addAll(LedgerVerifier.verify(records).anomalies());

        // 链尾锚定：抓住“重算整条链伪装自洽、整体核验单看看不出来”的前缀伪造
        if (k > 0 && !records.get((int) k - 1).hash().equals(trusted.tailHash())) {
            anomalies.add("可信锚点不匹配: seq=" + k + " 的哈希为 " + records.get((int) k - 1).hash()
                    + "，与可信摘要承诺的 " + trusted.tailHash() + " 不符，"
                    + "说明不晚于 seq=" + k + " 的历史被改动过（含重算哈希链的伪装）");
        }

        return new IncrementalVerificationReport(anomalies.isEmpty(), k, records.size() - k,
                records.size(), List.copyOf(anomalies));
    }

    /**
     * 锁内快速路径：可信摘要 + 记录 + 受信追加结构提供的当前山尖。
     * 当前山尖必须与记录来自同一个提交点（{@link AuditLedger#verifyIncremental}
     * 在同一把锁内取得），不能取自不受信的被核副本本身。
     */
    public static IncrementalVerificationReport verifySince(LedgerDigest trusted, List<AuditRecord> records,
                                                            List<String> currentPeaks) {
        List<String> anomalies = new ArrayList<>();
        long k = trusted.recordCount();
        int n = records.size();

        if (n < k) {
            anomalies.add("末尾整段缺失: 可信摘要覆盖到 seq=" + k + "，当前只有 " + n
                    + " 条，缺少 seq=" + (n + 1) + " 到 seq=" + k
                    + "，共 " + (k - n) + " 条");
            return new IncrementalVerificationReport(false, k, 0, n, List.copyOf(anomalies));
        }

        if (trusted.peaks() == null || trusted.peaks().isEmpty()) {
            // 旧格式锚点（无山尖）：不具备位置承诺，回退为整体核验，结论仍不漏报
            return verifySince(trusted, records);
        }
        if (!MmrAccumulator.isValidShape(trusted.peaks(), k)) {
            anomalies.add("可信锚点已损坏: 摘要的 MMR 山尖集形状与其 recordCount=" + k + " 不一致，"
                    + "无法据此核验（请改用来源可信、未被调包的摘要）");
            return new IncrementalVerificationReport(false, k, n - k, n, List.copyOf(anomalies));
        }
        if (currentPeaks == null || !MmrAccumulator.isValidShape(currentPeaks, n)) {
            anomalies.add("当前山尖已损坏: 山尖集形状与当前记录条数 " + n + " 不一致，"
                    + "无法据此做增量核验");
            return new IncrementalVerificationReport(false, k, n - k, n, List.copyOf(anomalies));
        }

        // 1) 从可信旧山尖出发，只追加新增记录的自带哈希，得到“前缀没被动过”时应有的山尖
        MmrAccumulator expected;
        try {
            expected = MmrAccumulator.restore(trusted.peaks(), k);
        } catch (IllegalArgumentException e) {
            anomalies.add("可信锚点已损坏: " + e.getMessage());
            return new IncrementalVerificationReport(false, k, n - k, n, List.copyOf(anomalies));
        }
        for (int i = (int) k; i < n; i++) {
            expected.append(records.get(i).hash());
        }
        List<String> expectedPeaks = expected.peaksHighToLow();

        // 2) 逐山尖比对，收集失配山尖覆盖的确定位置区间（粗定位）
        List<int[]> segments = MmrAccumulator.peakSegments(n);
        List<int[]> affected = new ArrayList<>();
        List<String> segmentDesc = new ArrayList<>();
        for (int p = 0; p < expectedPeaks.size(); p++) {
            if (!expectedPeaks.get(p).equals(currentPeaks.get(p))) {
                int[] seg = segments.get(p);
                affected.add(seg);
                String place = seg[1] < k ? "（落在可信摘要已覆盖的历史内）"
                        : seg[0] < k ? "（跨越锚点 seq=" + k + " 前后）"
                        : "（落在摘要之后新增部分）";
                segmentDesc.add("seq=" + (seg[0] + 1) + "..seq=" + (seg[1] + 1)
                        + "（" + (seg[1] - seg[0] + 1) + " 条）" + place);
            }
        }
        boolean tailMismatchOnly = false;
        if (affected.isEmpty() && k > 0 && !records.get((int) k - 1).hash().equals(trusted.tailHash())) {
            // 纵深防御：山尖一致时链尾理论上必然一致，仍显式报一次
            anomalies.add("可信锚点不匹配: seq=" + k + " 的哈希为 " + records.get((int) k - 1).hash()
                    + "，与可信摘要承诺的 " + trusted.tailHash() + " 不符，"
                    + "说明不晚于 seq=" + k + " 的历史被改动过（含重算哈希链的伪装）");
            tailMismatchOnly = true;
        }

        // 3) 待扫描区间 = 失配山尖段 ∪ 新增段 [k,n)，合并后每个位置只扫一次，明细不重复
        List<int[]> toScan = new ArrayList<>(affected);
        if (n > k) {
            toScan.add(new int[]{(int) k, n - 1});
        }
        ScanOutcome outcome = ScanOutcome.empty();
        for (int[] interval : merge(toScan)) {
            outcome = outcome.merge(scanRange(records, interval[0], interval[1] + 1));
        }
        anomalies.addAll(outcome.anomalies());

        // 4) 山尖失配时给出总述：先粗定位到山尖段，再用逐条核验结果收窄到精确位置与条数
        if (!affected.isEmpty()) {
            StringBuilder header = new StringBuilder();
            header.append("可信锚点不匹配: 山尖覆盖段 ").append(String.join("、", segmentDesc))
                    .append(" 与可信摘要承诺不符（锚点位置 seq=").append(k).append("）；")
                    .append("这些位置存在内容改动（含把自身校验码一并改对）、记录互换位置或重算哈希链的伪装。");
            if (outcome.hasAnomaly()) {
                int first = outcome.firstPos();
                int last = outcome.lastPos();
                // 最左侧若是 prevHash 衔接断裂，真正对不上的是“它和前一条”这两个位置
                int from = outcome.leftmostLinkOnly() && first > 0 ? first - 1 : first;
                header.append("逐条核验已精确定位: 异常落在 seq=").append(from + 1)
                        .append("..seq=").append(last + 1).append("，共 ").append(last - from + 1)
                        .append(" 条（位置相邻的链断裂表示其前一条被改或被换位）。逐条明细:");
            } else {
                header.append("该段每条记录自洽且链内衔接正常，属于整段重算哈希的伪装（山尖位置承诺仍能识破）。");
            }
            anomalies.add(0, header.toString());
        }

        return new IncrementalVerificationReport(anomalies.isEmpty() && !tailMismatchOnly, k, n - k, n,
                List.copyOf(anomalies));
    }

    /** 合并若干闭区间（可能重叠/相邻），返回升序互不相交的区间列表。 */
    private static List<int[]> merge(List<int[]> intervals) {
        List<int[]> sorted = intervals.stream()
                .sorted(Comparator.comparingInt(a -> a[0])).toList();
        List<int[]> merged = new ArrayList<>();
        for (int[] iv : sorted) {
            if (merged.isEmpty() || iv[0] > merged.get(merged.size() - 1)[1] + 1) {
                merged.add(new int[]{iv[0], iv[1]});
            } else {
                merged.get(merged.size() - 1)[1] = Math.max(merged.get(merged.size() - 1)[1], iv[1]);
            }
        }
        return merged;
    }

    /** 对 records[from..to) 重放整体核验的三项检查，口径与 LedgerVerifier 完全一致；收集异常位置。 */
    private static ScanOutcome scanRange(List<AuditRecord> records, int from, int to) {
        List<String> found = new ArrayList<>();
        int firstPos = Integer.MAX_VALUE;
        int lastPos = -1;
        boolean firstPosLinkOnly = false;
        long expectedSeq = (long) from + 1;
        String expectedPrevHash = from == 0 ? RecordHasher.GENESIS : records.get(from - 1).hash();
        for (int i = from; i < to && i < records.size(); i++) {
            AuditRecord record = records.get(i);
            boolean seqProblem = false;
            boolean contentProblem = false;
            boolean linkProblem = false;
            if (record.seq() != expectedSeq) {
                found.add("序号断档/乱序: 期望 seq=" + expectedSeq
                        + "，实际 seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "），可能存在删除或调换");
                seqProblem = true;
                expectedSeq = record.seq();
            }
            if (!RecordHasher.hashOf(record).equals(record.hash())) {
                found.add("内容被篡改: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）记录哈希与内容不符");
                contentProblem = true;
            }
            if (expectedPrevHash != null && !expectedPrevHash.equals(record.prevHash())) {
                found.add("哈希链断裂: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）prevHash 与前一条不匹配，可能存在删除、插入或调换");
                linkProblem = true;
            }
            if (seqProblem || contentProblem || linkProblem) {
                if (i < firstPos) {
                    firstPos = i;
                    // 最左侧异常若只含断链，被改/被换位的其实是它前一条，定位要向左扩
                    firstPosLinkOnly = linkProblem && !seqProblem && !contentProblem;
                }
                lastPos = i;
            }
            expectedPrevHash = record.hash();
            expectedSeq++;
        }
        return new ScanOutcome(found, firstPos, lastPos, firstPosLinkOnly);
    }

    /** 一次区间扫描的结果：明细列表 + 异常精确位置区间 + 最左是否仅为断链。 */
    private record ScanOutcome(List<String> anomalies, int firstPos, int lastPos, boolean leftmostLinkOnly) {

        static ScanOutcome empty() {
            return new ScanOutcome(List.of(), Integer.MAX_VALUE, -1, false);
        }

        ScanOutcome merge(ScanOutcome other) {
            if (other.anomalies.isEmpty()) {
                return this;
            }
            List<String> merged = new ArrayList<>(anomalies);
            merged.addAll(other.anomalies);
            int f = Math.min(firstPos, other.firstPos);
            int l = Math.max(lastPos, other.lastPos);
            boolean linkOnly = f == other.firstPos ? other.leftmostLinkOnly : leftmostLinkOnly;
            return new ScanOutcome(List.copyOf(merged), f, l, linkOnly);
        }

        boolean hasAnomaly() {
            return lastPos >= 0;
        }
    }

    private static String safeEventId(AuditRecord record) {
        return record.event() == null ? "?" : String.valueOf(record.event().eventId());
    }
}
