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
 * 不漏掉更早部分被动过的关键：摘要的 tailHash 是对全部历史的链式承诺，
 * 任何对前 k 条的改动——即使把后续哈希全部重算伪装成自洽——都会让
 * 第 k 条的哈希偏离锚点，边界比对立即失败。前提：所用摘要本身来源可信
 * （生成时前缀已确认完好），见 README“增量核验的适用范围与前提”。
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
