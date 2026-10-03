package com.github.feng111627.auditcomplianceservicejava.model;

import java.time.Instant;

/**
 * 存证摘要：某一确定留存位置的轻量凭证，可保存、可对外发布。
 * recordCount 为截止生成时刻的记录总数，tailHash 为该位置的整体指纹
 * （哈希链链尖，密码学意义上提交了此前全部记录内容）。
 * 别人拿到摘要后可用它核对自己手上的记录副本是否同为一份内容；
 * 也是增量核验的可信锚点。
 */
public record LedgerDigest(
        long recordCount,
        String tailHash,
        Instant generatedAt) {
}
