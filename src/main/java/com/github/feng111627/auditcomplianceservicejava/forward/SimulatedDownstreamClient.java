package com.github.feng111627.auditcomplianceservicejava.forward;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import org.springframework.stereotype.Component;

/**
 * 本地模拟下游：可配置故障、超时与重复回执，用于验证转发语义。
 */
@Component
public class SimulatedDownstreamClient implements DownstreamClient {

    @Override
    public String deliver(AuditRecord record) throws DownstreamException {
        // TODO: 实现
        return null;
    }
}
