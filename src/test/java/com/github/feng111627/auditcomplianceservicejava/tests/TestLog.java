package com.github.feng111627.auditcomplianceservicejava.tests;

/** 测试日志辅助：让跑测试的日志能看清覆盖了哪些业务、用例与结果。 */
final class TestLog {

    private TestLog() {
    }

    static void suite(String business) {
        System.out.println("==============================================================");
        System.out.println("[业务覆盖] " + business);
        System.out.println("==============================================================");
    }

    static void caseStart(String name) {
        System.out.println("  [用例] " + name);
    }

    static void pass(String detail) {
        System.out.println("  [结果] 通过 ✔ " + detail);
    }
}
