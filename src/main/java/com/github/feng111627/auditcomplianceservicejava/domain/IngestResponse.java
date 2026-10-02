package com.github.feng111627.auditcomplianceservicejava.domain;

import java.util.List;

/** 批量接收的逐条响应：合法事件给出留存与结论，非法事件给出拒收原因。 */
public class IngestResponse {
    private int acceptedCount;
    private int rejectedCount;
    private List<ItemResult> results;

    public int getAcceptedCount() { return acceptedCount; }
    public void setAcceptedCount(int acceptedCount) { this.acceptedCount = acceptedCount; }
    public int getRejectedCount() { return rejectedCount; }
    public void setRejectedCount(int rejectedCount) { this.rejectedCount = rejectedCount; }
    public List<ItemResult> getResults() { return results; }
    public void setResults(List<ItemResult> results) { this.results = results; }

    /** 单条事件的处理结果，accepted=false 时 rejectionReasons 说明原因。 */
    public static class ItemResult {
        private int index;
        private String clientEventId;
        private boolean accepted;
        private Long seq;
        private String storedEventId;
        private ComplianceStatus complianceStatus;
        private String ruleVersion;
        private List<String> reasons;
        private List<String> rejectionReasons;

        public int getIndex() { return index; }
        public void setIndex(int index) { this.index = index; }
        public String getClientEventId() { return clientEventId; }
        public void setClientEventId(String clientEventId) { this.clientEventId = clientEventId; }
        public boolean isAccepted() { return accepted; }
        public void setAccepted(boolean accepted) { this.accepted = accepted; }
        public Long getSeq() { return seq; }
        public void setSeq(Long seq) { this.seq = seq; }
        public String getStoredEventId() { return storedEventId; }
        public void setStoredEventId(String storedEventId) { this.storedEventId = storedEventId; }
        public ComplianceStatus getComplianceStatus() { return complianceStatus; }
        public void setComplianceStatus(ComplianceStatus complianceStatus) { this.complianceStatus = complianceStatus; }
        public String getRuleVersion() { return ruleVersion; }
        public void setRuleVersion(String ruleVersion) { this.ruleVersion = ruleVersion; }
        public List<String> getReasons() { return reasons; }
        public void setReasons(List<String> reasons) { this.reasons = reasons; }
        public List<String> getRejectionReasons() { return rejectionReasons; }
        public void setRejectionReasons(List<String> rejectionReasons) { this.rejectionReasons = rejectionReasons; }
    }
}
