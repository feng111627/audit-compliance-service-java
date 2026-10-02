package com.github.feng111627.auditcomplianceservicejava.forward;

import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 异步转发器：
 * - submit 只入队立即返回，转发快慢不影响事件接收；
 * - 单消费者线程按序投递，失败按固定间隔重试，重试耗尽进失败队列（可查询）；
 * - 按 eventId 去重：已成功投递的事件不会因重试、重复回执或重复提交而再次投递。
 */
@Component
public class AlertForwarder {

    private static final Logger log = LoggerFactory.getLogger(AlertForwarder.class);

    private final DownstreamClient downstream;
    private final int maxAttempts;
    private final long retryBackoffMillis;
    private final BlockingQueue<AuditRecord> queue = new LinkedBlockingQueue<>();
    private final List<DeadLetter> deadLetters = new CopyOnWriteArrayList<>();
    private final Set<String> deliveredEventIds = ConcurrentHashMap.newKeySet();
    private final Set<String> enqueuedEventIds = ConcurrentHashMap.newKeySet();
    private final AtomicLong inFlight = new AtomicLong(0);
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "alert-forwarder");
        t.setDaemon(true);
        return t;
    });

    public AlertForwarder(DownstreamClient downstream,
                          @Value("${audit.forward.max-attempts:3}") int maxAttempts,
                          @Value("${audit.forward.retry-backoff-ms:200}") long retryBackoffMillis) {
        this.downstream = downstream;
        this.maxAttempts = maxAttempts;
        this.retryBackoffMillis = retryBackoffMillis;
        worker.submit(this::consumeLoop);
    }

    /** 提交一条待转发记录（立即返回）。同一 eventId 重复提交会被忽略。 */
    public void submit(AuditRecord record) {
        String eventId = record.event().eventId();
        if (deliveredEventIds.contains(eventId) || !enqueuedEventIds.add(eventId)) {
            log.debug("eventId={} 已在队列或已投递，忽略重复提交", eventId);
            return;
        }
        inFlight.incrementAndGet();
        queue.offer(record);
    }

    /** 查询失败队列。 */
    public List<DeadLetter> deadLetters() {
        return List.copyOf(deadLetters);
    }

    /** 已成功投递（去重后）的事件数。 */
    public long deliveredCount() {
        return deliveredEventIds.size();
    }

    /** 等待队列清空（测试与优雅停机用）。 */
    public boolean awaitIdle(long timeoutMillis) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (System.currentTimeMillis() < deadline) {
            if (queue.isEmpty() && inFlight.get() == 0) {
                return true;
            }
            Thread.sleep(10);
        }
        return false;
    }

    private void consumeLoop() {
        while (!Thread.currentThread().isInterrupted()) {
            AuditRecord record;
            try {
                record = queue.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            try {
                deliverWithRetry(record);
            } finally {
                inFlight.decrementAndGet();
            }
        }
    }

    private void deliverWithRetry(AuditRecord record) {
        String eventId = record.event().eventId();
        if (deliveredEventIds.contains(eventId)) {
            return;
        }
        String lastError = "未知错误";
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                String receipt = downstream.deliver(record);
                deliveredEventIds.add(eventId);
                log.info("转发成功: eventId={}, seq={}, 回执={}, 第{}次尝试",
                        eventId, record.seq(), receipt, attempt);
                return;
            } catch (DownstreamException e) {
                lastError = e.getMessage();
                log.warn("转发失败（第{}/{}次）: eventId={}, 原因={}", attempt, maxAttempts, eventId, lastError);
                if (attempt < maxAttempts) {
                    try {
                        Thread.sleep(retryBackoffMillis);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
        deadLetters.add(new DeadLetter(record, maxAttempts, lastError, Instant.now()));
        log.error("转发最终失败，进入失败队列: eventId={}, seq={}", eventId, record.seq());
    }

    @PreDestroy
    public void shutdown() {
        worker.shutdownNow();
    }
}
