package com.github.feng111627.auditcomplianceservicejava.model;

import java.util.List;

/**
 * 用存证摘要核对一份记录副本的结论。
 * matches=false 时 details 说明：内容不一致、末尾整段缺失
 * （指出缺失的 seq 范围与条数）或副本自身链异常。
 */
public record DigestCheckReport(
        boolean matches,
        long digestCount,
        long copyCount,
        long missingCount,
        List<String> details) {
}
