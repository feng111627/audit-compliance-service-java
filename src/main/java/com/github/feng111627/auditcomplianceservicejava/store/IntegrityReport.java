package com.github.feng111627.auditcomplianceservicejava.store;

import java.util.List;

/** 账本完整性校验结果。 */
public class IntegrityReport {
    private boolean valid;
    private int recordCount;
    private String headHash;
    private List<Issue> issues;

    public boolean isValid() { return valid; }
    public void setValid(boolean valid) { this.valid = valid; }
    public int getRecordCount() { return recordCount; }
    public void setRecordCount(int recordCount) { this.recordCount = recordCount; }
    public String getHeadHash() { return headHash; }
    public void setHeadHash(String headHash) { this.headHash = headHash; }
    public List<Issue> getIssues() { return issues; }
    public void setIssues(List<Issue> issues) { this.issues = issues; }

    /** 发现的一处异常：类型（GAP/TAIL_MISSING/CONTENT_TAMPERED/CHAIN_BROKEN/HEAD_MISMATCH）、位置与说明。 */
    public record Issue(String type, Long seq, String expected, String actual, String detail) {
    }
}
