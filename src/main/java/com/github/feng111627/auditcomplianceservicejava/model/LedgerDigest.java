package com.github.feng111627.auditcomplianceservicejava.model;

import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;

import java.time.Instant;
import java.util.List;

/**
 * 某一确定留存位置的存证摘要：截止到生成这一刻，
 * 账本共有 recordCount 条记录，整体指纹为 tailHash
 * （哈希链尾哈希，承诺顺序与链式衔接），peaks 为该位置的
 * MMR 山尖集（高度从高到低，逐位置承诺每一段的记录内容与所处位置）。
 * 摘要可保存、可对外发布；任何人拿着摘要与一份记录副本
 * 即可独立核对两边是否为同一份内容。
 *
 * tailHash 单独只能证明“以这份前缀算出的链尾长什么样”，无法在不重算
 * 历史的前提下发现前缀内部被改、但改动点之后的链没有被重算的情况；
 * peaks 补上的正是这层位置承诺：只改某一条（哪怕把它自身哈希改对）、
 * 或交换其中两条的位置，都会让对应山尖偏离，而核验只需从可信旧山尖
 * 出发对新增记录做追加，开销只随新增条数增长。
 */
public record LedgerDigest(
        long recordCount,
        String tailHash,
        Instant generatedAt,
        List<String> peaks) {

    public LedgerDigest {
        peaks = peaks == null ? List.of() : List.copyOf(peaks);
    }

    public LedgerDigest(long recordCount, String tailHash, Instant generatedAt) {
        this(recordCount, tailHash, generatedAt, List.of());
    }

    /** 空账本摘要（count=0，指纹为 GENESIS，无山尖）。 */
    public static LedgerDigest empty(Instant generatedAt) {
        return new LedgerDigest(0, RecordHasher.GENESIS, generatedAt, List.of());
    }
}
