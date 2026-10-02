package com.github.feng111627.auditcomplianceservicejava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 上下文冒烟测试：使用 target 下的临时数据目录，避免在工程根目录生成 audit-data。
 */
@SpringBootTest(properties = {
        "audit.data-dir=target/test-app-data",
        "audit.forward-interval-millis=600000"
})
public class ApplicationTests {
    @Test
    public void contentLoad() {
    }
}
