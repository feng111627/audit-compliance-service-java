package com.github.feng111627.auditcomplianceservicejava.model;

import java.time.Instant;

/**
 * 某一确定留存位置的存证摘要：截止到生成这一刻，
 * 账本共有 recordCount 条记录，整体指纹为 tailHash
 * （哈希链尾哈希，隐式承诺全部历史内容）。
 * 摘要可保存、可对外发布；任何人拿着摘要与一份记录副本
 * 即可独立核对两边是否为同一份内容。
 */
public record LedgerDigest(
        long recordCount,
        String tailHash,
        Instant generatedAt) {
}
