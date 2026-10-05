package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.IncrementalVerificationReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;

import java.util.ArrayList;
import java.util.List;

/**
 * 增量核验器：以“上一回已确认可信”的摘要为锚点，只对新增部分
 * 做完整校验（重算哈希、查序号连续、查链式衔接），哈希计算代价
 * 为 O(新增条数) + O(1) 边界检查，不随历史总长线性增长。
 *
 * 覆盖范围（前 k 条）不做哈希重算，但做 O(k) 的结构性检查
 * （纯字段比对：序号连续、prevHash 链式衔接、锚点哈希），因此能发现：
 *  - 记录被调换位置、序号被改、hash/prevHash 字段被改；
 *  - 内容被改且这条自己的 hash 被一并改对（后继链接必然断裂）；
 *  - 整段历史被重算伪装成自洽（第 k 条哈希偏离可信锚点）。
 * 唯一结构性检查发现不了的情形：只改内容、所有哈希字段原封不动
 * （此时字段层面无任何不一致，必须重算内容哈希才能发现）——该情形由
 * 账本存储层加载时的一次性全量校验兜底，见
 * {@link AuditLedger#verifyIncremental(LedgerDigest)}；对脱离账本的
 * 任意副本要同样结论，请用 LedgerVerifier 整体核验或 DigestVerifier 摘要核对。
 *
 * 前提：所用摘要本身来源可信（生成时前缀已确认完好），
 * 见 README“增量核验的适用范围与前提”。
 */
public final class IncrementalVerifier {

    private IncrementalVerifier() {
    }

    public static IncrementalVerificationReport verifySince(LedgerDigest trusted, List<AuditRecord> records) {
        List<String> anomalies = new ArrayList<>();
        long k = trusted.recordCount();

        if (records.size() < k) {
            anomalies.add("末尾整段缺失: 可信摘要覆盖到 seq=" + k + "，当前只有 " + records.size()
                    + " 条，缺少 seq=" + (records.size() + 1) + " 到 seq=" + k
                    + "，共 " + (k - records.size()) + " 条");
            return new IncrementalVerificationReport(false, k, 0, records.size(), List.copyOf(anomalies));
        }

        // 覆盖范围（前 k 条）的结构性检查（O(k) 纯字段比对，不重算哈希）：
        // 序号必须连续、prevHash 必须与前一条的 hash 衔接。
        // 调换位置、改序号、改 hash/prevHash 字段、改内容并把自己的 hash 改对
        // （后继链接必然断裂）都会在这里暴露并定位到具体位置。
        int prefixAnomalies = 0;
        String expectedPrefixPrevHash = RecordHasher.GENESIS;
        for (int i = 0; i < (int) k; i++) {
            AuditRecord record = records.get(i);
            long expectedPrefixSeq = i + 1L;
            if (record.seq() != expectedPrefixSeq) {
                prefixAnomalies++;
                anomalies.add("覆盖范围内序号断档/乱序: 第 " + expectedPrefixSeq + " 个位置的记录实际 seq="
                        + record.seq() + "（eventId=" + safeEventId(record)
                        + "），可信摘要覆盖的历史中存在删除、插入或调换");
            }
            if (!expectedPrefixPrevHash.equals(record.prevHash())) {
                prefixAnomalies++;
                anomalies.add("覆盖范围内哈希链断裂: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）prevHash 与"
                        + (i == 0 ? "GENESIS 初始值" : "前一条（位置 " + i + "）的哈希")
                        + "不匹配，可信摘要覆盖的历史被改动过"
                        + "（含只改内容并把这条自己的校验码改对的情况）");
            }
            expectedPrefixPrevHash = record.hash();
        }
        if (prefixAnomalies > 0) {
            anomalies.add("可信摘要覆盖范围（seq=1 到 seq=" + k + "）内共发现 " + prefixAnomalies
                    + " 处结构性异常，涉及该段历史被改动");
        }

        // 边界锚定（O(1)）：第 k 条是可信历史与新增部分的分界
        if (k > 0) {
            AuditRecord boundary = records.get((int) k - 1);
            if (!boundary.hash().equals(trusted.tailHash())) {
                anomalies.add("可信锚点不匹配: seq=" + k + " 的哈希为 " + boundary.hash()
                        + "，与可信摘要承诺的 " + trusted.tailHash() + " 不符，"
                        + "说明不晚于 seq=" + k + " 的历史被改动过（含重算哈希链的伪装）");
            }
            String recomputed = RecordHasher.hashOf(boundary);
            if (!recomputed.equals(boundary.hash())) {
                anomalies.add("边界记录内容被篡改: seq=" + k + " 记录哈希与内容不符");
            }
        }

        // 只对新增部分 k+1..n 做完整校验
        long expectedSeq = k + 1;
        String expectedPrevHash = trusted.tailHash();
        for (int i = (int) k; i < records.size(); i++) {
            AuditRecord record = records.get(i);
            if (record.seq() != expectedSeq) {
                anomalies.add("新增部分序号断档/乱序: 期望 seq=" + expectedSeq
                        + "，实际 seq=" + record.seq() + "（eventId=" + safeEventId(record) + "）");
                expectedSeq = record.seq();
            }
            if (!RecordHasher.hashOf(record).equals(record.hash())) {
                anomalies.add("新增部分内容被篡改: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）记录哈希与内容不符");
            }
            if (!expectedPrevHash.equals(record.prevHash())) {
                anomalies.add("新增部分哈希链断裂: seq=" + record.seq()
                        + "（eventId=" + safeEventId(record) + "）prevHash 与前一条（或可信锚点）不匹配");
            }
            expectedPrevHash = record.hash();
            expectedSeq++;
        }

        long newChecked = records.size() - k;
        return new IncrementalVerificationReport(anomalies.isEmpty(), k, newChecked,
                records.size(), List.copyOf(anomalies));
    }

    private static String safeEventId(AuditRecord record) {
        return record.event() == null ? "?" : String.valueOf(record.event().eventId());
    }
}
