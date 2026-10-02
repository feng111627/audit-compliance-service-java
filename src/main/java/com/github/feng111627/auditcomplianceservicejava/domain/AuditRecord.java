package com.github.feng111627.auditcomplianceservicejava.domain;

/**
 * 按写入顺序留存的审计记录（链式哈希账本中的一行）。
 * seq 从 1 开始单调递增；entryHash 对本条除哈希外的字段做 SHA-256；
 * prevEntryHash 指向上一条记录的 entryHash（首条为全零）。
 */
public class AuditRecord {
    private long seq;
    private String eventId;
    private AuditEvent event;
    private ComplianceDecision decision;
    private long ingestTimeMillis;
    private String eventSchemaVersion;
    private String prevEntryHash;
    private String entryHash;

    public long getSeq() { return seq; }
    public void setSeq(long seq) { this.seq = seq; }
    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    public AuditEvent getEvent() { return event; }
    public void setEvent(AuditEvent event) { this.event = event; }
    public ComplianceDecision getDecision() { return decision; }
    public void setDecision(ComplianceDecision decision) { this.decision = decision; }
    public long getIngestTimeMillis() { return ingestTimeMillis; }
    public void setIngestTimeMillis(long ingestTimeMillis) { this.ingestTimeMillis = ingestTimeMillis; }
    public String getEventSchemaVersion() { return eventSchemaVersion; }
    public void setEventSchemaVersion(String eventSchemaVersion) { this.eventSchemaVersion = eventSchemaVersion; }
    public String getPrevEntryHash() { return prevEntryHash; }
    public void setPrevEntryHash(String prevEntryHash) { this.prevEntryHash = prevEntryHash; }
    public String getEntryHash() { return entryHash; }
    public void setEntryHash(String entryHash) { this.entryHash = entryHash; }
}
