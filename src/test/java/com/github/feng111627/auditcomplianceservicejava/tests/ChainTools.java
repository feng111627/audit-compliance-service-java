package com.github.feng111627.auditcomplianceservicejava.tests;

import com.github.feng111627.auditcomplianceservicejava.ledger.RecordHasher;
import com.github.feng111627.auditcomplianceservicejava.model.AuditEvent;
import com.github.feng111627.auditcomplianceservicejava.model.AuditRecord;

import java.util.ArrayList;
import java.util.List;

/** 测试工具：构造各种“只动局部、不重算整链”的篡改副本。 */
final class ChainTools {

    private ChainTools() {
    }

    /** 把 records.get(index) 的事件替换为 forged，并从该位置起重算全部哈希链（整条链自洽伪装）。 */
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

    /** 只改某一条的内容，把它“自身携带的校验码”也重算成能对上，但不触碰其后任何记录。 */
    static List<AuditRecord> changeContentAndRehashSelf(List<AuditRecord> records, int index, AuditEvent forged) {
        List<AuditRecord> result = new ArrayList<>(records);
        AuditRecord r = records.get(index);
        String selfHash = RecordHasher.hash(r.seq(), forged, r.verdict(), r.prevHash());
        result.set(index, new AuditRecord(r.seq(), r.storedAt(), forged, r.verdict(), r.prevHash(), selfHash));
        return result;
    }

    /** 只改某一条的内容，校验码原样保留（内容与自带哈希不符），其余记录不动。 */
    static List<AuditRecord> changeContentKeepHash(List<AuditRecord> records, int index, AuditEvent forged) {
        List<AuditRecord> result = new ArrayList<>(records);
        AuditRecord r = records.get(index);
        result.set(index, new AuditRecord(r.seq(), r.storedAt(), forged, r.verdict(), r.prevHash(), r.hash()));
        return result;
    }

    /** 整体交换两条记录所在的位置（记录携带的 seq/prevHash/hash 全部原样跟着走）。 */
    static List<AuditRecord> swapWholeRecords(List<AuditRecord> records, int i, int j) {
        List<AuditRecord> result = new ArrayList<>(records);
        AuditRecord tmp = result.get(i);
        result.set(i, result.get(j));
        result.set(j, tmp);
        return result;
    }

    /** 构造一个把 actor 改成 mallory 的伪造事件，其余字段不变。 */
    static AuditEvent actorTampered(AuditRecord r, String actor) {
        return new AuditEvent(r.event().eventId(), actor, r.event().action(),
                r.event().resource(), r.event().result(), r.event().timestamp(), r.event().attributes());
    }
}
