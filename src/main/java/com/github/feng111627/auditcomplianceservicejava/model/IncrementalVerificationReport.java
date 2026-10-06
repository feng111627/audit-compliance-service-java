package com.github.feng111627.auditcomplianceservicejava.model;

import java.util.List;

/**
 * 增量核验报告：以上一回可信摘要为锚点。锁内快速路径只对新增的
 * checkedNewCount 条做 MMR 追加与完整检查（哈希代价 2×新增+O(log 锚点)），
 * 并逐山尖比对位置承诺；失配山尖覆盖段再局部重放整体核验的三项检查定位。
 * intact=false 时 anomalies 指出具体问题：可信锚点（山尖/链尾）不匹配并给出
 * 山尖段与精确 seq 区间、历史锚点不匹配、末尾缺失、新增部分篡改/断链等。
 */
public record IncrementalVerificationReport(
        boolean intact,
        long anchorCount,
        long checkedNewCount,
        long totalCount,
        List<String> anomalies) {
}
