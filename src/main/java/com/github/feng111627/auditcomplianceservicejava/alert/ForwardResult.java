package com.github.feng111627.auditcomplianceservicejava.alert;

/** 下游投递结果。 */
public record ForwardResult(boolean success, boolean duplicateAck, String detail) {
    public static ForwardResult ok() { return new ForwardResult(true, false, "delivered"); }
    public static ForwardResult duplicate() { return new ForwardResult(true, true, "duplicate ack"); }
    public static ForwardResult fail(String detail) { return new ForwardResult(false, false, detail); }
}
