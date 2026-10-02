package com.github.feng111627.auditcomplianceservicejava.forward;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;

/**
 * 下游接收方接口。本地用模拟实现，不依赖外部服务。
 */
public interface DownstreamClient {

    /**
     * 投递一条记录。
     *
     * @return 下游回执（可能重复）
     * @throws DownstreamException 连不上或超时
     */
    String deliver(AuditRecord record) throws DownstreamException;
}
