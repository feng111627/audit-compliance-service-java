package com.github.feng111627.auditcomplianceservicejava.alert;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 本地内存模拟的告警下游，不访问任何网络。
 *
 * 模式：
 * - OK            正常接收并持久幂等（同一 seq 重复投递返回 duplicate 回执，不重复入库）；
 * - UNREACHABLE   模拟连不上，直接失败；
 * - TIMEOUT       模拟超时：消息实际可能已到达也可能没到，调用方按失败重试，由幂等保证不重复；
 * - DUPLICATE_ACK 模拟“服务端实际已处理，但每次都返回成功重复回执”，验证调用方不重复投递。
 *
 * failNextTimes：让接下来的 N 次发送失败（无论模式），用于验证“先失败后成功”的重试。
 */
@Component
public class SimulatedDownstreamClient implements DownstreamClient {

    public enum Mode { OK, UNREACHABLE, TIMEOUT, DUPLICATE_ACK }

    private volatile Mode mode = Mode.OK;
    private volatile int failNextTimes = 0;
    private final Set<Long> deliveredSeqs = ConcurrentHashMap.newKeySet();
    private final List<AlertMessage> received = new CopyOnWriteArrayList<>();

    @Override
    public ForwardResult send(AlertMessage message) {
        if (failNextTimes > 0) {
            synchronized (this) {
                if (failNextTimes > 0) {
                    failNextTimes--;
                    return ForwardResult.fail("注入的临时故障");
                }
            }
        }
        switch (mode) {
            case UNREACHABLE -> {
                return ForwardResult.fail("下游连不上（模拟）：connection refused");
            }
            case TIMEOUT -> {
                // 超时语义：不把消息加入已接收，调用方必须重试
                return ForwardResult.fail("下游超时（模拟）：read timed out");
            }
            case DUPLICATE_ACK -> {
                boolean first = deliveredSeqs.add(message.seq());
                received.add(message);
                return ForwardResult.duplicate();
            }
            case OK -> {
                boolean first = deliveredSeqs.add(message.seq());
                received.add(message);
                return first ? ForwardResult.ok() : ForwardResult.duplicate();
            }
            default -> throw new IllegalStateException("未知模式: " + mode);
        }
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public Mode getMode() {
        return mode;
    }

    public void failNextTimes(int times) {
        this.failNextTimes = times;
    }

    /** 下游实际接收到（幂等去重前）的全部消息。 */
    public List<AlertMessage> getReceived() {
        return List.copyOf(received);
    }

    /** 下游幂等去重后真正留存的告警 seq 集合。 */
    public Set<Long> getDeliveredSeqs() {
        return Set.copyOf(deliveredSeqs);
    }

    public synchronized void reset() {
        mode = Mode.OK;
        failNextTimes = 0;
        deliveredSeqs.clear();
        received.clear();
    }
}
