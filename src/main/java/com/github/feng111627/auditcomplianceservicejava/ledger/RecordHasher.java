package com.github.feng111627.auditcomplianceservicejava.ledger;

import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;
import com.github.feng111627.auditcomplianceservicejava.model.ComplianceVerdict;
import com.github.feng111627.auditcomplianceservicejava.model.FieldViolation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;

/**
 * 记录哈希：对记录内容做确定性（字段顺序固定、Map 排序）序列化后
 * 与前一条记录哈希链式计算 SHA-256。
 */
public final class RecordHasher {

    public static final String GENESIS = "GENESIS";

    private RecordHasher() {
    }

    public static String hash(long seq, AuditEvent event, ComplianceVerdict verdict, String prevHash) {
        String canonical = canonical(seq, event, verdict, prevHash);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : bytes) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String hashOf(AuditRecord record) {
        return hash(record.seq(), record.event(), record.verdict(), record.prevHash());
    }

    /** 确定性序列化：所有字段按固定顺序拼接，attributes 按键排序。 */
    static String canonical(long seq, AuditEvent event, ComplianceVerdict verdict, String prevHash) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("seq=").append(seq).append('\n');
        sb.append("eventId=").append(nullSafe(event.eventId())).append('\n');
        sb.append("actor=").append(nullSafe(event.actor())).append('\n');
        sb.append("action=").append(nullSafe(event.action())).append('\n');
        sb.append("resource=").append(nullSafe(event.resource())).append('\n');
        sb.append("result=").append(nullSafe(event.result())).append('\n');
        sb.append("timestamp=").append(event.timestamp() == null ? "" : event.timestamp()).append('\n');
        sb.append("attributes={");
        if (event.attributes() != null) {
            TreeMap<String, String> sorted = new TreeMap<>(event.attributes());
            for (Map.Entry<String, String> e : sorted.entrySet()) {
                sb.append(e.getKey()).append('=').append(e.getValue()).append(';');
            }
        }
        sb.append("}\n");
        sb.append("status=").append(verdict.status()).append('\n');
        sb.append("ruleVersion=").append(nullSafe(verdict.ruleVersion())).append('\n');
        for (FieldViolation v : verdict.violations()) {
            sb.append("violation=").append(v.field()).append('|')
                    .append(v.ruleId()).append('|').append(v.reason()).append('\n');
        }
        sb.append("prevHash=").append(nullSafe(prevHash));
        return sb.toString();
    }

    private static String nullSafe(String s) {
        return s == null ? "" : s;
    }
}
