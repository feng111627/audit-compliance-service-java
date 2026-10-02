package com.github.feng111627.auditcomplianceservicejava.alert;

/** 本地模拟的告警下游。 */
public interface DownstreamClient {
    ForwardResult send(AlertMessage message);
}
