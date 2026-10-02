package com.github.feng111627.auditcomplianceservicejava.alert;

/** 后台转发器：单线程异步扫描发件箱重试，带退避；成功不重复投递，最终失败进死信。 */
public interface AlertForwarder {
    void start();
    void stop();
    /** 立即驱动一次投递循环（主要供测试确定性验证）。 */
    int drain();
}
