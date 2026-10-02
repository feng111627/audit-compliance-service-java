package com.github.feng111627.auditcomplianceservicejava.model;

public enum ComplianceStatus {
    /** 通过合规判定 */
    ACCEPTED,
    /** 通过但触发告警，需要异步转发下游 */
    ALERT,
    /** 字段缺失或格式错误，被拒收 */
    REJECTED
}
