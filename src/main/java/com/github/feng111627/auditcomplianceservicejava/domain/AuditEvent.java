package com.github.feng111627.auditcomplianceservicejava.domain;

import java.util.LinkedHashMap;
import java.util.Map;

/** 接收到的审计事件。 */
public class AuditEvent {
    private String eventId;
    private String actor;
    private String action;
    private String resource;
    private String result;
    private String timestamp;
    private Map<String, Object> attributes = new LinkedHashMap<>();

    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }
    public String getResult() { return result; }
    public void setResult(String result) { this.result = result; }
    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
    public Map<String, Object> getAttributes() { return attributes; }
    public void setAttributes(Map<String, Object> attributes) { this.attributes = attributes; }
}
