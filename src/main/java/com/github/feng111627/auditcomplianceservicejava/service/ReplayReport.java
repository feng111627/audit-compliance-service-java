package com.github.feng111627.auditcomplianceservicejava.service;

import java.util.List;

/** 历史结论按当时规则复现的结果。 */
public class ReplayReport {
    private boolean consistent;
    private int checked;
    private List<Mismatch> mismatches;

    public boolean isConsistent() { return consistent; }
    public void setConsistent(boolean consistent) { this.consistent = consistent; }
    public int getChecked() { return checked; }
    public void setChecked(int checked) { this.checked = checked; }
    public List<Mismatch> getMismatches() { return mismatches; }
    public void setMismatches(List<Mismatch> mismatches) { this.mismatches = mismatches; }

    /** 复现结论与留存结论不一致的一条。 */
    public record Mismatch(long seq, String storedStatus, String replayedStatus,
                           String storedRuleVersion, String replayedRuleVersion, String detail) {
    }
}
