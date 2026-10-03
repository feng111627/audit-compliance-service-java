package com.github.feng111627.auditcomplianceservicejava.model;

import java.util.List;

/**
 * 增量核验报告：以上一回可信摘要为锚点，只对新增的
 * checkedNewCount 条做完整校验，代价与新增量相关而非全量。
 * intact=false 时 anomalies 指出具体问题（含历史锚点不匹配、
 * 末尾缺失、新增部分篡改/断链等）。
 */
public record IncrementalVerificationReport(
        boolean intact,
        long anchorCount,
        long checkedNewCount,
        long totalCount,
        List<String> anomalies) {
}
