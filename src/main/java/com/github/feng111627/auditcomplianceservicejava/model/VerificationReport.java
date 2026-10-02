package com.github.feng111627.auditcomplianceservicejava.model;

import java.util.List;

/**
 * 完整性校验报告。intact=false 时 anomalies 指出具体哪些记录
 * 被篡改、删除或调换。
 */
public record VerificationReport(boolean intact, long checkedCount, List<String> anomalies) {
}
