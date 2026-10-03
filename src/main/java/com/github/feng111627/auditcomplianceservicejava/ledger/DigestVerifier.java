package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.DigestCheckReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;

import java.util.ArrayList;
import java.util.List;

/**
 * 摘要核对器：不依赖账本服务，任何人拿着一份已发布的存证摘要
 * 和自己手上的记录副本即可核对两边是不是同一份内容。
 * 能发现：内容改动（哈希链校验）、末尾整段删减（条数不足，
 * 并指出缺少的序号区间与条数）、摘要位置之前的任何不一致。
 */
public final class DigestVerifier {

    private DigestVerifier() {
    }

    /**
     * 用摘要核对副本。副本允许比摘要位置更新（更长）：
     * 只要摘要位置及之前的内容与摘要一致即视为同一份内容。
     */
    public static DigestCheckReport check(LedgerDigest digest, List<AuditRecord> copy) {
        List<String> anomalies = new ArrayList<>();

        // 1) 副本自身的哈希链与内容必须完好（发现内容改动、中间删除、调换）
        VerificationReport chain = LedgerVerifier.verify(copy);
        anomalies.addAll(chain.anomalies());

        // 2) 末尾整段删减：副本条数不足，指出缺少的序号区间与条数
        Long missingFromSeq = null;
        long missingCount = 0;
        if (copy.size() < digest.recordCount()) {
            missingFromSeq = (long) copy.size() + 1;
            missingCount = digest.recordCount() - copy.size();
            anomalies.add("末尾缺失: 摘要位置共有 " + digest.recordCount() + " 条，副本只有 "
                    + copy.size() + " 条，缺少 seq=" + missingFromSeq + ".." + digest.recordCount()
                    + " 共 " + missingCount + " 条，不能视为完好");
        }

        // 3) 摘要位置的整体指纹必须对得上（副本够长时）
        if (copy.size() >= digest.recordCount() && digest.recordCount() > 0) {
            AuditRecord atPosition = copy.get((int) digest.recordCount() - 1);
            if (atPosition.seq() != digest.recordCount()
                    || !atPosition.hash().equals(digest.tailHash())) {
                anomalies.add("整体指纹不符: 摘要位置 seq=" + digest.recordCount()
                        + " 的记录哈希与摘要 tailHash 不一致，副本与摘要不是同一份内容");
            }
        } else if (digest.recordCount() == 0 && !copy.isEmpty()) {
            // 摘要为空账本，副本非空：不算冲突，副本更新
        }

        return DigestCheckReport.of(digest.recordCount(), copy.size(),
                missingFromSeq, missingCount, anomalies);
    }
}
