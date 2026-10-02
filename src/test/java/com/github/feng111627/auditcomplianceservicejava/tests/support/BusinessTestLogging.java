package com.github.feng111627.auditcomplianceservicejava.tests.support;

import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * 测试日志扩展：打印每个用例的业务模块、用例名/DisplayName 与结果，
 * 让 mvn test 的日志能直观看出覆盖了哪些业务场景。
 */
public class BusinessTestLogging implements BeforeTestExecutionCallback, AfterTestExecutionCallback {

    private static final String KEY = "startedAt";

    @Override
    public void beforeTestExecution(ExtensionContext context) {
        String module = context.getTestClass().map(Class::getSimpleName).orElse("?");
        getStore(context).put(KEY, System.currentTimeMillis());
        System.out.printf("%n[业务测试] >> 模块=%s 用例=%s%n", module, context.getDisplayName());
    }

    @Override
    public void afterTestExecution(ExtensionContext context) {
        String module = context.getTestClass().map(Class::getSimpleName).orElse("?");
        Long startedValue = getStore(context).get(KEY, Long.class);
        long started = startedValue == null ? System.currentTimeMillis() : startedValue;
        boolean failed = context.getExecutionException().isPresent();
        System.out.printf("[业务测试] << 模块=%s 用例=%s 结果=%s 耗时=%dms%n",
                module, context.getDisplayName(), failed ? "失败" : "通过",
                System.currentTimeMillis() - started);
    }

    private ExtensionContext.Store getStore(ExtensionContext context) {
        return context.getStore(ExtensionContext.Namespace.create(getClass(), context.getRequiredTestMethod()));
    }
}
