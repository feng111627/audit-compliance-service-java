package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;

import java.util.ArrayList;
import java.util.List;

/** 测试工具：构造“篡改后重算整条哈希链”的伪装副本（自洽但内容已变）。 */
final class ChainTools {

    private ChainTools() {
    }

    /** 把 records.get(index) 的事件替换为 forged，并从该位置起重算全部哈希链。 */
    static List<AuditRecord> forgeAndRecompute(List<AuditRecord> records, int index, AuditEvent forged) {
        List<AuditRecord> result = new ArrayList<>(records.size());
        String prevHash = RecordHasher.GENESIS;
        for (int i = 0; i < records.size(); i++) {
            AuditRecord r = records.get(i);
            AuditEvent event = i == index ? forged : r.event();
            String hash = RecordHasher.hash(r.seq(), event, r.verdict(), prevHash);
            result.add(new AuditRecord(r.seq(), r.storedAt(), event, r.verdict(), prevHash, hash));
            prevHash = hash;
        }
        return result;
    }
}
