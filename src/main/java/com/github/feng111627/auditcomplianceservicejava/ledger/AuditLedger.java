package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.IncrementalVerificationReport;
import com.github.feng111627.auditcomplianceservicejava.model.LedgerDigest;
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
    /**
     * 存储层（文件）加载时的完整性核验结论；纯内存账本或加载/导入校验通过时为 null。
     * 记录进入账本只有三条路——加载（此时全量校验一次）、追加（账本自己算哈希，
     * 自洽）、导入（导入前全量校验）——因此前缀完整性由账本持续维护，
     * 增量核验无需每次重算历史，只需把该结论并入。
     */
    private volatile VerificationReport storageVerification;

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

    /**
     * 生成当前留存位置的存证摘要。只在锁内读取序号与链尾哈希（O(1)），
     * 不等待进行中的写入；与追加共用同一把公平锁，因此每份摘要都对应
     * 一个确定、自洽的留存位置，事后拿账本前缀核对必然对得上。
     */
    public LedgerDigest digest() {
        lock.lock();
        try {
            return new LedgerDigest(records.size(), tailHash, Instant.now());
        } finally {
            lock.unlock();
        }
    }

    /**
     * 把一份已通过离线核验的记录整体导入空账本（证据包导回）。
     * 导入前重新做一次完整性校验；导入后 tailHash 接续导入链尾，
     * 后续 append 接着原有编号继续、不重号也不断档。
     * 非空账本拒绝导入，避免覆盖已有历史。
     */
    public void importVerified(List<AuditRecord> imported) {
        lock.lock();
        try {
            if (!records.isEmpty()) {
                throw new IllegalStateException("只能导入到空账本：当前已有 " + records.size() + " 条记录");
            }
            VerificationReport report = LedgerVerifier.verify(imported);
            if (!report.intact()) {
                throw new IllegalArgumentException("导入的记录未通过完整性校验: " + report.anomalies());
            }
            for (AuditRecord record : imported) {
                if (persistPath != null) {
                    appendToFile(record);
                }
                records.add(record);
            }
            tailHash = imported.isEmpty() ? RecordHasher.GENESIS : imported.get(imported.size() - 1).hash();
            storageVerification = null;
            log.info("已导入 {} 条审计记录，链尾哈希接续为 {}", imported.size(), tailHash);
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

    /**
     * 以“上一回已确认可信”的摘要为锚点，对当前账本做增量核验。
     * 每次调用代价 O(新增条数)：锁内取快照后由 IncrementalVerifier 做
     * 覆盖范围结构性检查（纯字段比对）+ 新增部分完整校验；
     * 再并入存储层加载时的一次性全量校验结论——“只改内容、哈希字段
     * 原封不动”这类必须重算内容哈希才能发现的覆盖范围篡改由它兜底，
     * 因此与整体核验（{@link #verify()}）对当前账本的结论一致。
     */
    public IncrementalVerificationReport verifyIncremental(LedgerDigest trusted) {
        IncrementalVerificationReport base = IncrementalVerifier.verifySince(trusted, readAll());
        VerificationReport storage = storageVerification;
        if (storage == null || storage.intact()) {
            return base;
        }
        List<String> anomalies = new ArrayList<>();
        anomalies.add("留存存储层在加载时未通过完整性校验（覆盖范围内的历史在账本外被改动过），"
                + "共 " + storage.anomalies().size() + " 处异常:");
        anomalies.addAll(storage.anomalies());
        anomalies.addAll(base.anomalies());
        return new IncrementalVerificationReport(false, base.anchorCount(),
                base.checkedNewCount(), base.totalCount(), List.copyOf(anomalies));
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
            storageVerification = report.intact() ? null : report;
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
