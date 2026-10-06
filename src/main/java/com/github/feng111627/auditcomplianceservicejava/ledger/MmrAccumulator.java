package com.github.feng111627.auditcomplianceservicejava.ledger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Merkle Mountain Range（MMR）增量累加器：
 * 对按提交顺序追加的记录哈希做位置承诺。内部只保留各高度的“山尖”，
 * 追加一条时沿高度向上合并，单条最坏 O(log n)，但每条记录在整个生命周期里
 * 最多各参与一次叶子哈希与一次父节点合并，因此连续追加 m 条的哈希运算
 * 总量 ≤ 2m，与已有历史长度无关（摊还 O(1)/条）。
 *
 * 山尖集（peaks）按高度从高到低排列，其形状只由记录总数 n 决定：
 * n 的二进制里从高到低的每个置 1 位对应一个山尖，该山尖覆盖
 * 2^height 条记录、占据确定的位置区间。因此一份可信山尖集不仅承诺了
 * 每段记录的内容，还承诺了记录所处的位置——只改内容或交换两段位置
 * 都会让对应山尖偏离。
 */
public final class MmrAccumulator {

    /** 内部状态：byHeight[h] = 高度 h 的当前山尖；null 表示该高度没有山尖。 */
    private final String[] byHeight = new String[64];
    private long count;

    public MmrAccumulator() {
    }

    /**
     * 从可信山尖集（高度从高到低）恢复一个累加器。
     * 山尖形状必须与 count 一致，否则抛出异常（摘要损坏/调包）。
     */
    public static MmrAccumulator restore(List<String> peaksHighToLow, long count) {
        if (!isValidShape(peaksHighToLow, count)) {
            throw new IllegalArgumentException(
                    "MMR 山尖集与记录条数不一致，摘要锚点已损坏: count=" + count
                            + "，山尖数=" + (peaksHighToLow == null ? 0 : peaksHighToLow.size()));
        }
        MmrAccumulator mmr = new MmrAccumulator();
        mmr.count = count;
        List<Integer> heights = peakHeights(count);
        for (int i = 0; i < heights.size(); i++) {
            mmr.byHeight[heights.get(i)] = peaksHighToLow.get(i);
        }
        return mmr;
    }

    /**
     * 追加一条记录哈希，返回本次追加实际进行的哈希运算次数（叶子 1 次 + 每次合并 1 次）。
     */
    public int append(String recordHash) {
        int hashes = 1;
        String h = leafHash(recordHash);
        int height = 0;
        while (byHeight[height] != null) {
            h = parentHash(byHeight[height], h);
            byHeight[height] = null;
            height++;
            hashes++;
        }
        byHeight[height] = h;
        count++;
        return hashes;
    }

    /** 当前山尖集，高度从高到低排列。 */
    public List<String> peaksHighToLow() {
        List<String> peaks = new ArrayList<>();
        for (int h = byHeight.length - 1; h >= 0; h--) {
            if (byHeight[h] != null) {
                peaks.add(byHeight[h]);
            }
        }
        return List.copyOf(peaks);
    }

    public long count() {
        return count;
    }

    /** 校验山尖集形状是否与 count 一致（山尖数量、每个山尖的高度只由 count 的二进制决定）。 */
    public static boolean isValidShape(List<String> peaksHighToLow, long count) {
        if (peaksHighToLow == null || count < 0) {
            return false;
        }
        return peakHeights(count).size() == peaksHighToLow.size()
                && peaksHighToLow.stream().allMatch(p -> p != null && !p.isEmpty());
    }

    /** 从一批记录哈希（按位置顺序）重算出 MMR 山尖集。 */
    public static List<String> peaksFor(List<String> recordHashes) {
        MmrAccumulator mmr = new MmrAccumulator();
        for (String recordHash : recordHashes) {
            mmr.append(recordHash);
        }
        return mmr.peaksHighToLow();
    }

    /**
     * count 个记录对应的山尖覆盖段（与 {@link #peaksHighToLow()} 同序）：
     * 每个元素是 {起始位置(0 基,含), 结束位置(0 基,含)}。
     */
    public static List<int[]> peakSegments(long count) {
        List<int[]> segments = new ArrayList<>();
        long start = 0;
        List<Integer> heights = peakHeights(count);
        for (int h : heights) {
            long size = 1L << h;
            segments.add(new int[]{(int) start, (int) (start + size - 1)});
            start += size;
        }
        return List.copyOf(segments);
    }

    /** count 的二进制置 1 位对应的山尖高度，按高度从高到低排列。 */
    private static List<Integer> peakHeights(long count) {
        List<Integer> heights = new ArrayList<>();
        for (int h = 63; h >= 0; h--) {
            if ((count & (1L << h)) != 0) {
                heights.add(h);
            }
        }
        return heights;
    }

    /** 叶子节点哈希：加域前缀，防止与内部节点/记录哈希混用造成歧义。 */
    static String leafHash(String recordHash) {
        return sha256("MMR-LEAF|" + recordHash);
    }

    /** 内部节点哈希：左（先出现的段）在前、右（后出现的段）在后，交换位置即不同。 */
    static String parentHash(String left, String right) {
        return sha256("MMR-NODE|" + left + "|" + right);
    }

    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : bytes) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
