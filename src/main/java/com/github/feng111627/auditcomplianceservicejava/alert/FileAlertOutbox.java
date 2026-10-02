package com.github.feng111627.auditcomplianceservicejava.alert;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.auditcomplianceservicejava.config.AuditProperties;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditRecord;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * JSONL 发件箱：dataDir/alerts/outbox.jsonl
 *
 * - enqueue：PENDING 条目立即落盘（接收路径只做本地文件追加，不访问下游，不拖慢接收）；
 * - 投递状态变化后整体重写文件（本地模拟规模可接受），保证重启后 PENDING 继续重试、
 *   DELIVERED 不会被重复投递、DEAD 进入可查询失败队列；
 * - 同一 seq 重复入队忽略（幂等）。
 */
@Repository
public class FileAlertOutbox implements AlertOutbox {

    public static final String PENDING = "PENDING";
    public static final String DELIVERED = "DELIVERED";
    public static final String DEAD = "DEAD";

    private final AuditProperties properties;
    private final ObjectMapper objectMapper;
    private final Object lock = new Object();
    private final Path file;

    public FileAlertOutbox(AuditProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.file = Path.of(properties.getDataDir(), "alerts", "outbox.jsonl");
        try {
            Files.createDirectories(file.getParent());
            if (Files.notExists(file)) {
                Files.createFile(file);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("初始化告警发件箱失败: " + file, e);
        }
    }

    @Override
    public void enqueue(AuditRecord record) {
        synchronized (lock) {
            List<OutboxEntry> entries = load();
            if (entries.stream().anyMatch(e -> e.getSeq() == record.getSeq())) {
                return;
            }
            OutboxEntry entry = new OutboxEntry();
            entry.setSeq(record.getSeq());
            entry.setEventId(record.getEventId());
            entry.setMessage(new AlertMessage(record.getSeq(), record.getEventId(), record));
            entry.setStatus(PENDING);
            entry.setAttempts(0);
            entry.setEnqueueMillis(System.currentTimeMillis());
            appendLine(entry);
        }
    }

    @Override
    public List<OutboxEntry> pending() {
        synchronized (lock) {
            return load().stream().filter(e -> PENDING.equals(e.getStatus())).toList();
        }
    }

    @Override
    public List<OutboxEntry> deadLetters() {
        synchronized (lock) {
            return load().stream().filter(e -> DEAD.equals(e.getStatus())).toList();
        }
    }

    /** 手动让一条死信重新回到 PENDING；返回 1 成功、0 未找到。 */
    @Override
    public int retryDeadLetter(long seq) {
        synchronized (lock) {
            List<OutboxEntry> entries = load();
            Optional<OutboxEntry> found = entries.stream()
                    .filter(e -> e.getSeq() == seq && DEAD.equals(e.getStatus())).findFirst();
            if (found.isEmpty()) {
                return 0;
            }
            found.get().setStatus(PENDING);
            found.get().setAttempts(0);
            found.get().setLastError(null);
            rewrite(entries);
            return 1;
        }
    }

    /** 在锁内更新一条条目（转发器使用，避免读写竞争）。 */
    public void update(long seq, java.util.function.Consumer<OutboxEntry> mutator) {
        synchronized (lock) {
            List<OutboxEntry> entries = load();
            entries.stream().filter(e -> e.getSeq() == seq).findFirst().ifPresent(entry -> {
                mutator.accept(entry);
                rewrite(entries);
            });
        }
    }

    private List<OutboxEntry> load() {
        List<OutboxEntry> entries = new ArrayList<>();
        try (var lines = Files.lines(file, StandardCharsets.UTF_8)) {
            lines.filter(l -> !l.isBlank()).forEach(line -> {
                try {
                    entries.add(objectMapper.readValue(line, OutboxEntry.class));
                } catch (IOException e) {
                    throw new UncheckedIOException("解析发件箱行失败: " + line, e);
                }
            });
        } catch (IOException e) {
            throw new UncheckedIOException("读取发件箱失败: " + file, e);
        }
        return entries;
    }

    private void appendLine(OutboxEntry entry) {
        try {
            Files.writeString(file, objectMapper.writeValueAsString(entry) + System.lineSeparator(),
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("发件箱入队失败: seq=" + entry.getSeq(), e);
        }
    }

    private void rewrite(List<OutboxEntry> entries) {
        try {
            StringBuilder sb = new StringBuilder();
            for (OutboxEntry entry : entries) {
                sb.append(objectMapper.writeValueAsString(entry)).append(System.lineSeparator());
            }
            Path tmp = file.resolveSibling("outbox.jsonl.tmp");
            Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException("重写发件箱失败", e);
        }
    }
}
