package com.github.feng111627.auditcomplianceservicejava.alert;

/** 发件箱条目（持久化到本地 JSONL），状态 PENDING/DELIVERED/DEAD；attempts 为重试次数。 */
public class OutboxEntry {
    private long seq;
    private String eventId;
    private AlertMessage message;
    private String status;
    private int attempts;
    private long lastAttemptMillis;
    private String lastError;
    private long enqueueMillis;

    public long getSeq() { return seq; }
    public void setSeq(long seq) { this.seq = seq; }
    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    public AlertMessage getMessage() { return message; }
    public void setMessage(AlertMessage message) { this.message = message; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public int getAttempts() { return attempts; }
    public void setAttempts(int attempts) { this.attempts = attempts; }
    public long getLastAttemptMillis() { return lastAttemptMillis; }
    public void setLastAttemptMillis(long lastAttemptMillis) { this.lastAttemptMillis = lastAttemptMillis; }
    public String getLastError() { return lastError; }
    public void setLastError(String lastError) { this.lastError = lastError; }
    public long getEnqueueMillis() { return enqueueMillis; }
    public void setEnqueueMillis(long enqueueMillis) { this.enqueueMillis = enqueueMillis; }
}
