package com.github.feng111627.auditcomplianceservicejava.evidence;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.feng111627.auditcomplianceservicejava.model.EvidencePack;
import com.github.feng111627.auditcomplianceservicejava.model.EvidencePackReport;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 证据包离线核验工具：不启动 Spring、不连任何服务，
 * 在没有部署本服务的环境里用一条命令核验证据包真假。
 *
 * 用法：java -cp &lt;classes+依赖&gt; ...EvidencePackCli verify &lt;证据包.json&gt;
 * 退出码 0 = 核验通过，1 = 核验失败或用法错误。
 */
public final class EvidencePackCli {

    private EvidencePackCli() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !"verify".equals(args[0])) {
            System.err.println("用法: EvidencePackCli verify <证据包.json>");
            System.exit(1);
        }
        Path path = Path.of(args[1]);
        if (!Files.exists(path)) {
            System.err.println("文件不存在: " + path);
            System.exit(1);
        }
        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        EvidencePack pack = mapper.readValue(Files.readString(path), EvidencePack.class);
        EvidencePackReport report = EvidencePackVerifier.verify(pack);
        System.out.println("证据包: " + path);
        System.out.println("  格式版本: " + pack.formatVersion());
        System.out.println("  记录条数: " + report.recordCount());
        System.out.println("  结论复现: " + report.verdictsReproduced() + " 条逐条比对");
        if (report.intact()) {
            System.out.println("  结论: 核验通过 ✔ 哈希链完整、指纹一致、结论按当时规则复现一致");
            return;
        }
        System.out.println("  结论: 核验失败 ✗");
        report.anomalies().forEach(a -> System.out.println("    - " + a));
        System.exit(1);
    }
}
