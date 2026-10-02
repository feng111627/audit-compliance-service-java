package com.github.feng111627.auditcomplianceservicejava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.auditcomplianceservicejava.config.AuditProperties;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.domain.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.domain.ComplianceDecision;
import org.springframework.stereotype.Repository;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * 基于本地 JSONL 文件的只追加审计账本。
 *
 * 编号：seq 从 1 开始，append 在同一把锁内完成“分配编号-计算哈希-追加落盘-更新头指针”，
 * 因此并发写入编号不重复、不断档，读顺序即提交（加锁）顺序。
 *
 * 完整性：
 * - contentHash = SHA-256(规范化 JSON(除两个哈希字段外的全部字段))，任何字段被改动都会导致不一致；
 * - entryHash   = SHA-256(prevEntryHash + "|" + contentHash)，把记录与前一条绑定；
 * - 调换两条记录会改变相邻 prevEntryHash 绑定，被发现；
 * - 删除中间记录会造成 seq 断档(GAP)或链断；删除头部会使链无法从全零起点衔接；
 * - 删除尾部会使头指针(head 文件)指向的哈希在账本中缺失(TAIL_MISSING)，头指针本身被改则 HEAD_MISMATCH。
 */
@Repository
public class FileAuditStore implements AuditStore {

    public static final String GENESIS_HASH = "0".repeat(64);

    private final AuditProperties properties;
    private final ObjectMapper objectMapper;
    private final Object lock = new Object();
    private final Path ledgerFile;
    private final Path headFile;

    public FileAuditStore(AuditProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        Path dir = Path.of(properties.getDataDir());
        this.ledgerFile = dir.resolve("audit-ledger.jsonl");
        this.headFile = dir.resolve("audit-head.txt");
        try {
            Files.createDirectories(dir);
            if (Files.notExists(ledgerFile)) {
                Files.createFile(ledgerFile);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("初始化审计账本失败: " + dir, e);
        }
    }

    @Override
    public AuditRecord append(AuditEvent event, ComplianceDecision decision, String eventSchemaVersion) {
        synchronized (lock) {
            List<AuditRecord> existing = readAllInternal();
            AuditRecord record = new AuditRecord();
            record.setSeq(existing.size() + 1L);
            record.setEventId(event.getEventId());
            record.setEvent(event);
            record.setDecision(decision);
            record.setIngestTimeMillis(System.currentTimeMillis());
            record.setEventSchemaVersion(eventSchemaVersion);
            record.setPrevEntryHash(existing.isEmpty()
                    ? GENESIS_HASH
                    : existing.get(existing.size() - 1).getEntryHash());

            String contentHash = sha256(canonicalContent(record));
            record.setEntryHash(sha256(record.getPrevEntryHash() + "|" + contentHash));

            persist(record);
            return record;
        }
    }

    private void persist(AuditRecord record) {
        try {
            String line = objectMapper.writeValueAsString(record) + System.lineSeparator();
            Files.writeString(ledgerFile, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            // 头指针与账本行落盘后更新（文件级 fsync 在此规模本地验证中以 flush 语义足够）
            Files.writeString(headFile, record.getSeq() + ":" + record.getEntryHash(),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("追加审计记录失败: seq=" + record.getSeq(), e);
        }
    }

    @Override
    public List<AuditRecord> readAll() {
        synchronized (lock) {
            return readAllInternal();
        }
    }

    private List<AuditRecord> readAllInternal() {
        List<AuditRecord> records = new ArrayList<>();
        if (Files.notExists(ledgerFile)) {
            return records;
        }
        try (BufferedReader reader = Files.newBufferedReader(ledgerFile, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                records.add(objectMapper.readValue(line, AuditRecord.class));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("读取审计账本失败: " + ledgerFile, e);
        }
        return records;
    }

    @Override
    public Optional<AuditRecord> findBySeq(long seq) {
        return readAll().stream().filter(r -> r.getSeq() == seq).findFirst();
    }

    /**
     * 独立校验：不依赖运行时内存状态，仅依据文件内容 + 头指针重新计算。
     */
    @Override
    public IntegrityReport verifyIntegrity() {
        synchronized (lock) {
            List<AuditRecord> records = readAllInternal();
            IntegrityReport report = new IntegrityReport();
            List<IntegrityReport.Issue> issues = new ArrayList<>();

            String expectedPrev = GENESIS_HASH;
            long expectedSeq = 1;
            String lastHash = GENESIS_HASH;

            for (AuditRecord record : records) {
                if (record.getSeq() != expectedSeq) {
                    issues.add(new IntegrityReport.Issue("GAP", expectedSeq,
                            String.valueOf(expectedSeq), String.valueOf(record.getSeq()),
                            "编号断档：期望 seq=" + expectedSeq + "，实际读到 seq=" + record.getSeq()
                                    + "（可能删除或丢失了记录）"));
                    expectedSeq = record.getSeq();
                }

                String recomputedContent = sha256(canonicalContent(record));
                String recomputedEntry = sha256(record.getPrevEntryHash() + "|" + recomputedContent);

                if (!record.getPrevEntryHash().equals(expectedPrev)) {
                    issues.add(new IntegrityReport.Issue("CHAIN_BROKEN", record.getSeq(),
                            expectedPrev, record.getPrevEntryHash(),
                            "前向哈希不匹配：记录的 prevEntryHash 与上一条的 entryHash 不一致（可能调换/删除了记录）"));
                }
                if (!record.getEntryHash().equals(recomputedEntry)) {
                    issues.add(new IntegrityReport.Issue("CONTENT_TAMPERED", record.getSeq(),
                            recomputedEntry, record.getEntryHash(),
                            "内容哈希不匹配：记录内容被改动，或 entryHash 被伪造"));
                }

                expectedPrev = record.getEntryHash();
                lastHash = record.getEntryHash();
                expectedSeq++;
            }

            // 头指针校验：防尾部删除 / 防头指针被改
            String headHash = null;
            if (Files.exists(headFile)) {
                try {
                    String head = Files.readString(headFile, StandardCharsets.UTF_8).trim();
                    int idx = head.indexOf(':');
                    if (idx > 0) {
                        long headSeq = Long.parseLong(head.substring(0, idx));
                        headHash = head.substring(idx + 1);
                        long actualCount = records.size();
                        if (headSeq != actualCount) {
                            issues.add(new IntegrityReport.Issue("TAIL_MISSING", actualCount + 1L,
                                    String.valueOf(headSeq), String.valueOf(actualCount),
                                    "头指针记录条数=" + headSeq + "，账本实际条数=" + actualCount
                                            + "（尾部记录可能被删除）"));
                        }
                        AuditRecord tail = records.isEmpty() ? null : records.get(records.size() - 1);
                        if (tail == null || !tail.getEntryHash().equals(headHash)) {
                            issues.add(new IntegrityReport.Issue("HEAD_MISMATCH",
                                    tail == null ? null : tail.getSeq(),
                                    tail == null ? "(无记录)" : tail.getEntryHash(), headHash,
                                    "头指针哈希与账本末尾不一致（头指针被改或尾部被删）"));
                        }
                    }
                } catch (IOException | NumberFormatException e) {
                    issues.add(new IntegrityReport.Issue("HEAD_MISMATCH", null, null, null,
                            "头指针文件无法解析: " + e.getMessage()));
                }
            } else if (!records.isEmpty()) {
                issues.add(new IntegrityReport.Issue("HEAD_MISSING", null, null, null,
                        "头指针文件丢失，无法确认尾部是否完整"));
            }

            report.setValid(issues.isEmpty());
            report.setRecordCount(records.size());
            report.setHeadHash(headHash != null ? headHash : lastHash);
            report.setIssues(issues);
            return report;
        }
    }

    /** 规范化参与哈希的内容：不含 prevEntryHash / entryHash，字段顺序固定。 */
    private String canonicalContent(AuditRecord r) {
        try {
            var node = objectMapper.createObjectNode();
            node.put("seq", r.getSeq());
            node.put("eventId", r.getEventId());
            node.set("event", objectMapper.valueToTree(r.getEvent()));
            node.set("decision", objectMapper.valueToTree(r.getDecision()));
            node.put("ingestTimeMillis", r.getIngestTimeMillis());
            node.put("eventSchemaVersion", r.getEventSchemaVersion());
            return objectMapper.writeValueAsString(node);
        } catch (IOException e) {
            throw new UncheckedIOException("规范化审计记录失败", e);
        }
    }

    static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
