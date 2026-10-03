package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.DigestCheckReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;

import java.util.ArrayList;
import java.util.List;

/**
 * 摘要核对器：不依赖账本内部状态，任何人拿着一份可信的存证摘要
 * 和一份记录副本即可独立核对两边是否为同一份内容。
 * 能发现：内容被改动（指纹不符/副本自身链异常）、末尾整段被删减
 * （指出缺失的 seq 范围与条数，绝不把截断的副本当成完好）。
 */
public final class DigestVerifier {

    private DigestVerifier() {
    }

    /**
     * 用摘要核对副本。副本条数多于摘要覆盖范围不算不匹配
     * （超出部分只是本摘要尚未覆盖），会在 details 中注明。
     */
    public static DigestCheckReport check(LedgerDigest digest, List<AuditRecord> copy) {
        List<String> details = new ArrayList<>();
        boolean matches = true;

        VerificationReport self = LedgerVerifier.verify(copy);
        if (!self.intact()) {
            matches = false;
            details.add("副本自身完整性校验未通过:");
            details.addAll(self.anomalies());
        }

        long k = digest.recordCount();
        if (copy.size() < k) {
            matches = false;
            long missing = k - copy.size();
            details.add("副本末尾整段缺失: 缺少 seq=" + (copy.size() + 1) + " 到 seq=" + k
                    + "，共 " + missing + " 条。副本自身看起来连贯，但与摘要承诺的历史不一致，不能视为完好");
        } else if (k > 0) {
            String copyFingerprint = copy.get((int) k - 1).hash();
            if (!copyFingerprint.equals(digest.tailHash())) {
                matches = false;
                details.add("前 " + k + " 条的整体指纹与摘要不符: 摘要承诺 " + digest.tailHash()
                        + "，副本实为 " + copyFingerprint + "，两边不是同一份内容");
            }
            if (copy.size() > k) {
                details.add("副本还包含摘要生成之后新增的 " + (copy.size() - k) + " 条"
                        + "（seq=" + (k + 1) + " 起），超出本摘要覆盖范围，需更新的摘要核对");
            }
        }

        if (matches) {
            details.add("副本与摘要一致: 覆盖 " + k + " 条，整体指纹 " + digest.tailHash() + " 匹配");
        }
        return new DigestCheckReport(matches, k, copy.size(),
                Math.max(0, k - copy.size()), List.copyOf(details));
    }
}
