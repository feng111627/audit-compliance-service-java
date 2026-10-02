package com.github.feng111627.auditcomplianceservicejava.forward;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 本地模拟下游：不依赖外部服务。
 * - 按 eventId 幂等：同一事件重复投递只算一次，返回相同回执（模拟重复回执场景）。
 * - 可编程故障：failNextTimes(n) 让接下来 n 次投递抛异常（连接失败/超时），
 *   用于验证重试与失败队列语义。
 */
@Component
public class SimulatedDownstreamClient implements DownstreamClient {

    private static final Logger log = LoggerFactory.getLogger(SimulatedDownstreamClient.class);

    private final AtomicInteger failNextTimes = new AtomicInteger(0);
    private final AtomicInteger deliveryAttempts = new AtomicInteger(0);
    private final Set<String> receivedEventIds = ConcurrentHashMap.newKeySet();
    private final Map<String, String> receipts = new ConcurrentHashMap<>();
    private final List<AuditRecord> received = new CopyOnWriteArrayList<>();

    @Override
    public String deliver(AuditRecord record) throws DownstreamException {
        deliveryAttempts.incrementAndGet();
        if (failNextTimes.getAndUpdate(n -> n > 0 ? n - 1 : 0) > 0) {
            log.warn("模拟下游故障: 投递 eventId={} 失败（连接超时）", record.event().eventId());
            throw new DownstreamException("模拟下游不可达/超时");
        }
        String eventId = record.event().eventId();
        // 幂等：重复投递返回相同回执，不重复计数
        return receipts.computeIfAbsent(eventId, id -> {
            receivedEventIds.add(id);
            received.add(record);
            log.info("模拟下游已接收: eventId={}, seq={}", id, record.seq());
            return "RECEIPT-" + id;
        });
    }

    /** 让接下来 n 次投递尝试失败。 */
    public void failNextTimes(int n) {
        failNextTimes.addAndGet(n);
    }

    /** 实际收到的去重后记录。 */
    public List<AuditRecord> received() {
        return List.copyOf(received);
    }

    /** 投递尝试总次数（含失败与重复）。 */
    public int deliveryAttempts() {
        return deliveryAttempts.get();
    }

    public boolean hasReceived(String eventId) {
        return receivedEventIds.contains(eventId);
    }

    public void reset() {
        failNextTimes.set(0);
        deliveryAttempts.set(0);
        receivedEventIds.clear();
        receipts.clear();
        received.clear();
    }
}
