package com.github.feng111627.auditcomplianceservicejava.alert;

import com.github.feng111627.auditcomplianceservicejava.config.AuditProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 单线程后台转发器。
 *
 * 可靠性语义：
 * - 接收线程只做发件箱本地落盘，转发完全异步，不拖慢接收；
 * - 每次只投递到期（退避时间已过）的 PENDING 条目；成功（含重复回执）立即标 DELIVERED，
 *   因此同一条成功事件不会被再次投递（发件箱状态 + 下游幂等双重保证）；
 * - 连不上/超时只增加 attempts 与错误信息，等待下轮退避重试，事件不丢；
 * - 重试达到 maxAttempts 转为 DEAD，进入可查询失败队列，可经 API 重新入队；
 * - PENDING/DELIVERED/DEAD 全部在发件箱文件持久化，进程重启后自动恢复。
 */
@Component
public class AsyncAlertForwarder implements AlertForwarder {

    private static final Logger log = LoggerFactory.getLogger(AsyncAlertForwarder.class);

    private final AlertOutbox outbox;
    private final DownstreamClient downstream;
    private final AuditProperties properties;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ScheduledExecutorService scheduler;

    public AsyncAlertForwarder(AlertOutbox outbox, DownstreamClient downstream, AuditProperties properties) {
        this.outbox = outbox;
        this.downstream = downstream;
        this.properties = properties;
    }

    @Override
    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "alert-forwarder");
            t.setDaemon(true);
            return t;
        });
        long interval = properties.getForwardIntervalMillis();
        scheduler.scheduleWithFixedDelay(this::safeDrain, interval, interval, TimeUnit.MILLISECONDS);
        log.info("告警转发器已启动，轮询间隔 {}ms", interval);
    }

    @Override
    public void stop() {
        if (running.compareAndSet(true, false) && scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    private void safeDrain() {
        try {
            drain();
        } catch (RuntimeException e) {
            log.warn("转发循环异常（下轮继续）: {}", e.getMessage());
        }
    }

    @Override
    public int drain() {
        if (!(outbox instanceof FileAlertOutbox fileOutbox)) {
            return 0;
        }
        int delivered = 0;
        List<OutboxEntry> pending = outbox.pending();
        long now = System.currentTimeMillis();
        for (OutboxEntry entry : pending) {
            long backoff = entry.getAttempts() == 0
                    ? 0L
                    : properties.getBackoffBaseMillis() * (1L << Math.min(entry.getAttempts() - 1, 10));
            if (now - entry.getLastAttemptMillis() < backoff) {
                continue;
            }
            int attempts = entry.getAttempts() + 1;
            ForwardResult result;
            try {
                result = downstream.send(entry.getMessage());
            } catch (RuntimeException e) {
                result = ForwardResult.fail("抛异常: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }

            if (result.success()) {
                fileOutbox.update(entry.getSeq(), e -> {
                    e.setAttempts(attempts);
                    e.setLastAttemptMillis(now);
                    e.setLastError(null);
                    e.setStatus(FileAlertOutbox.DELIVERED);
                });
                delivered++;
                log.info("告警投递成功 seq={} duplicateAck={} attempts={}",
                        entry.getSeq(), result.duplicateAck(), attempts);
            } else {
                boolean giveUp = attempts >= properties.getMaxAttempts();
                String error = result.detail();
                fileOutbox.update(entry.getSeq(), e -> {
                    e.setAttempts(attempts);
                    e.setLastAttemptMillis(now);
                    e.setLastError(error);
                    if (giveUp) {
                        e.setStatus(FileAlertOutbox.DEAD);
                    }
                });
                if (giveUp) {
                    log.error("告警重试 {} 次仍失败，转入死信队列 seq={} 原因={}", attempts, entry.getSeq(), error);
                } else {
                    log.warn("告警投递失败，将退避重试 seq={} attempts={} 原因={}",
                            entry.getSeq(), attempts, error);
                }
            }
        }
        return delivered;
    }
}
