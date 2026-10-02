package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.VerificationReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 审计账本：追加时在锁内分配序号并链接哈希，
 * 保证并发写入下序号唯一、连续、无断档，读出顺序即提交顺序。
 * 默认纯内存；配置 audit.ledger.path 后追加写入本地 JSONL 文件，
 * 重启时从文件恢复并先做一次完整性校验。
 */
@Component
public class AuditLedger {

    private static final Logger log = LoggerFactory.getLogger(AuditLedger.class);

    private final ReentrantLock lock = new ReentrantLock(true);
    private final List<AuditRecord> records = new ArrayList<>();
    private final Path persistPath;
    private final ObjectMapper mapper;
    private String tailHash = RecordHasher.GENESIS;

    public AuditLedger(@Value("${audit.ledger.path:}") String ledgerPath) {
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.persistPath = ledgerPath == null || ledgerPath.isBlank() ? null : Path.of(ledgerPath);
        if (persistPath != null) {
            loadFromFile();
        }
    }

    /** 追加一条记录，返回分配好序号与哈希的完整记录。线程安全。 */
    public AuditRecord append(AuditEvent event, ComplianceVerdict verdict) {
        lock.lock();
        try {
            long seq = records.size() + 1L;
            String hash = RecordHasher.hash(seq, event, verdict, tailHash);
            AuditRecord record = new AuditRecord(seq, Instant.now(), event, verdict, tailHash, hash);
            if (persistPath != null) {
                appendToFile(record);
            }
            records.add(record);
            tailHash = hash;
            return record;
        } finally {
            lock.unlock();
        }
    }

    /** 按写入顺序读出全部记录（快照）。 */
    public List<AuditRecord> readAll() {
        lock.lock();
        try {
            return List.copyOf(records);
        } finally {
            lock.unlock();
        }
    }

    /** 独立校验完整性：发现篡改、删除、调换并指出具体记录。 */
    public VerificationReport verify() {
        return LedgerVerifier.verify(readAll());
    }

    public long size() {
        lock.lock();
        try {
            return records.size();
        } finally {
            lock.unlock();
        }
    }

    private void appendToFile(AuditRecord record) {
        try {
            Files.createDirectories(persistPath.toAbsolutePath().getParent());
            Files.writeString(persistPath, mapper.writeValueAsString(record) + System.lineSeparator(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("审计记录落盘失败: " + persistPath, e);
        }
    }

    private void loadFromFile() {
        if (!Files.exists(persistPath)) {
            return;
        }
        try {
            List<String> lines = Files.readAllLines(persistPath);
            for (String line : lines) {
                if (line.isBlank()) {
                    continue;
                }
                AuditRecord record = mapper.readValue(line, AuditRecord.class);
                records.add(record);
                tailHash = record.hash();
            }
            VerificationReport report = LedgerVerifier.verify(records);
            if (!report.intact()) {
                log.warn("从文件恢复审计账本时发现完整性异常: {}", report.anomalies());
            } else {
                log.info("从 {} 恢复 {} 条审计记录，完整性校验通过", persistPath, records.size());
            }
        } catch (IOException e) {
            throw new UncheckedIOException("审计账本恢复失败: " + persistPath, e);
        }
    }
}
