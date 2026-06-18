/*
 * kcp_wrap.c - KCP 包装模块实现
 *
 * 封装 KCP (ikcp) 库的创建、销毁、参数配置和输入/输出操作。
 * 每个通道通过此模块管理一个独立的 KCP 实例。
 *
 * 上层 API 使用 uint8_t 类型的数据指针，内部适配到 ikcp 的 char 类型。
 * 所有错误路径均通过 LOG_ERROR 记录详细信息。
 */

#include "kcp_wrap.h"
#include "ikcp.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/* --------------------------------------------------------------------------
 * 内部常量
 * -------------------------------------------------------------------------- */

/*
 * KCP 内部定义 IKCP_WND_RCV = 128（参见 ikcp.c）。
 * ikcp_send() 将数据拆分为 mss 大小的段，段数 count 必须 < IKCP_WND_RCV，
 * 即 count <= 127，否则返回 -2。
 * 因此单次发送的数据长度上限为 127 * mss。
 */
#define KCP_MAX_SEND_SEGMENTS   127

/* ============================================================================
 * 公共函数实现
 * ============================================================================ */

/*
 * 创建 KCP 实例
 */
struct IKCPCB *kcp_wrap_create(IUINT32 conv, void *user)
{
    struct IKCPCB *kcp;

    kcp = ikcp_create(conv, user);
    if (!kcp) {
        LOG_ERROR("kcp_wrap_create: ikcp_create(conv=%u) failed - "
                  "returned NULL (likely out of memory)", conv);
        return NULL;
    }

    LOG_DEBUG("kcp_wrap_create: KCP instance created (conv=%u, kcp=%p)",
              conv, (void *)kcp);
    return kcp;
}

/*
 * 销毁 KCP 实例
 */
void kcp_wrap_destroy(struct IKCPCB *kcp)
{
    if (!kcp) {
        LOG_ERROR("kcp_wrap_destroy: null kcp pointer");
        return;
    }

    LOG_DEBUG("kcp_wrap_destroy: releasing KCP instance (conv=%u, kcp=%p)",
              kcp->conv, (void *)kcp);
    ikcp_release(kcp);
}

/*
 * 设置 KCP 输出回调
 *
 * KCP 内部的 output 回调签名为:
 *   int (*)(const char *buf, int len, struct IKCPCB *kcp, void *user)
 *
 * 本模块对外暴露的回调签名（kcp_output_cb_t）同为 4 参数:
 *   int (*)(const char *buf, int len, struct IKCPCB *kcp, void *user)
 *
 * 两者完全一致，无需适配。调用方通过 ikcp_create() 时传入的
 * user 指针即可在回调中获取 channel_t 上下文。
 */
void kcp_wrap_set_output(struct IKCPCB *kcp, kcp_output_cb_t cb)
{
    if (!kcp) {
        LOG_ERROR("kcp_wrap_set_output: null kcp pointer");
        return;
    }

    if (!cb) {
        LOG_ERROR("kcp_wrap_set_output: null callback pointer (kcp=%p)",
                  (void *)kcp);
        return;
    }

    ikcp_setoutput(kcp, cb);

    LOG_DEBUG("kcp_wrap_set_output: output callback set (kcp=%p, cb=%p)",
              (void *)kcp, (void *)cb);
}

/*
 * 配置 KCP 参数
 */
void kcp_wrap_set_params(struct IKCPCB *kcp, int mtu, int sndwnd, int rcvwnd,
                         int nodelay, int interval, int resend, int nc)
{
    int ret;

    if (!kcp) {
        LOG_ERROR("kcp_wrap_set_params: null kcp pointer");
        return;
    }

    /* C19: setmtu 必须在 nodelay/wndsize 之前调用，因为 nodelay 可能引用
     * interval 相关参数，且 wndsize 依赖 mss（由 setmtu 设置）。 */
    
    /* 设置 MTU（必须在 nodelay 和 wndsize 之前） */
    ret = ikcp_setmtu(kcp, mtu);
    if (ret != 0) {
        LOG_ERROR("kcp_wrap_set_params: ikcp_setmtu(mtu=%d) returned %d "
                  "(kcp=%p)", mtu, ret, (void *)kcp);
    }

    /* 设置 nodelay 模式: nodelay, interval, resend, nc */
    ret = ikcp_nodelay(kcp, nodelay, interval, resend, nc);
    if (ret != 0) {
        LOG_ERROR("kcp_wrap_set_params: ikcp_nodelay(nodelay=%d, interval=%d, "
                  "resend=%d, nc=%d) returned %d (kcp=%p)",
                  nodelay, interval, resend, nc, ret, (void *)kcp);
    }

    /* 设置发送/接收窗口 */
    ret = ikcp_wndsize(kcp, sndwnd, rcvwnd);
    if (ret != 0) {
        LOG_ERROR("kcp_wrap_set_params: ikcp_wndsize(sndwnd=%d, rcvwnd=%d) "
                  "returned %d (kcp=%p)",
                  sndwnd, rcvwnd, ret, (void *)kcp);
    }

    LOG_DEBUG("kcp_wrap_set_params: mtu=%d sndwnd=%d rcvwnd=%d "
              "nodelay=%d interval=%d resend=%d nc=%d (kcp=%p)",
              mtu, sndwnd, rcvwnd, nodelay, interval, resend, nc,
              (void *)kcp);
}

/*
 * 发送数据到 KCP（应用层 → KCP）
 *
 * 对 len 进行边界检查，防止超过 KCP 内部段数限制。
 * KCP 内部 ikcp_send() 将数据按 mss 分片，最多允许
 * (IKCP_WND_RCV - 1) = 127 个段。超出则返回 -1 并记录错误。
 */
int kcp_wrap_send(struct IKCPCB *kcp, const uint8_t *data, int len)
{
    int ret;
    int max_len;

    if (!kcp) {
        LOG_ERROR("kcp_wrap_send: null kcp pointer");
        return -1;
    }

    if (!data) {
        LOG_ERROR("kcp_wrap_send: null data pointer (kcp=%p)", (void *)kcp);
        return -1;
    }

    if (len < 0) {
        LOG_ERROR("kcp_wrap_send: negative length %d (kcp=%p)",
                  len, (void *)kcp);
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    /*
     * 边界检查: len 不能超过 KCP 单次发送上限。
     * KCP 内部 ikcp_send() 检查: count >= IKCP_WND_RCV (128) 即返回 -2，
     * 其中 count = (len + mss - 1) / mss。
     * 因此最大允许段数为 127，最大字节数为 127 * mss。
     */
    if (kcp->mss > 0) {
        /* 防御：kcp->mss 可能被设置为超大值（IUINT32），乘以 127 可能溢出 int。
         * 两主机场景下 mss ≤ KCP_MTU_PERFORMANCE=1478，安全；此检查为纵深防御。 */
        if (kcp->mss > (IUINT32)(INT_MAX / KCP_MAX_SEND_SEGMENTS)) {
            LOG_ERROR("kcp_wrap_send: mss=%u too large, would overflow max_len (kcp=%p)",
                      kcp->mss, (void *)kcp);
            return -1;
        }
        max_len = (int)kcp->mss * KCP_MAX_SEND_SEGMENTS;
        if (len > max_len) {
            LOG_ERROR("kcp_wrap_send: len=%d exceeds max %d "
                      "(mss=%u * %d segments) (kcp=%p)",
                      len, max_len, kcp->mss, KCP_MAX_SEND_SEGMENTS,
                      (void *)kcp);
            return -1;
        }
    }

    ret = ikcp_send(kcp, (const char *)data, len);
    if (ret < 0) {
        LOG_ERROR("kcp_wrap_send: ikcp_send(len=%d) returned %d (kcp=%p)",
                  len, ret, (void *)kcp);
        return -1;
    }

    return ret;
}

/*
 * 从 KCP 接收数据（KCP → 应用层）
 */
int kcp_wrap_recv(struct IKCPCB *kcp, uint8_t *buf, int size)
{
    int ret;

    if (!kcp) {
        LOG_ERROR("kcp_wrap_recv: null kcp pointer");
        return -1;
    }

    if (!buf) {
        LOG_ERROR("kcp_wrap_recv: null buffer pointer (kcp=%p)", (void *)kcp);
        return -1;
    }

    if (size <= 0) {
        LOG_ERROR("kcp_wrap_recv: invalid buffer size %d (kcp=%p)",
                  size, (void *)kcp);
        return -1;
    }

    ret = ikcp_recv(kcp, (char *)buf, size);
    if (ret == -1 || ret == -2) {
        /*
         * -1 = 接收队列为空
         * -2 = 队首 KCP 分片链尚未收齐，暂时没有完整应用消息
         * 二者都是 EAGAIN 语义，不是协议错误。
         */
        return 0;
    }
    if (ret < 0) {
        /* -3 等 = 真实错误（例如应用缓冲区不足） */
        LOG_ERROR("kcp_wrap_recv: ikcp_recv error %d (kcp=%p)", ret, (void *)kcp);
        return -1;
    }

    return ret;
}

/*
 * 将收到的数据段输入 KCP（网络 → KCP）
 */
int kcp_wrap_input(struct IKCPCB *kcp, const uint8_t *data, int len)
{
    int ret;

    if (!kcp) {
        LOG_ERROR("kcp_wrap_input: null kcp pointer");
        return -1;
    }

    if (!data) {
        LOG_ERROR("kcp_wrap_input: null data pointer (kcp=%p)", (void *)kcp);
        return -1;
    }

    if (len <= 0) {
        LOG_ERROR("kcp_wrap_input: invalid length %d (kcp=%p)",
                  len, (void *)kcp);
        return -1;
    }

    ret = ikcp_input(kcp, (const char *)data, (long)len);
    if (ret < 0) {
        LOG_ERROR("kcp_wrap_input: ikcp_input(len=%d) returned %d (kcp=%p)",
                  len, ret, (void *)kcp);
        return -1;
    }

    return 0;
}

/*
 * 更新 KCP 状态（驱动定时器）
 */
void kcp_wrap_update(struct IKCPCB *kcp, IUINT32 current_ms)
{
    if (!kcp) {
        LOG_ERROR("kcp_wrap_update: null kcp pointer");
        return;
    }

    ikcp_update(kcp, current_ms);
}

/*
 * 立即刷新 KCP 输出队列。
 *
 * ikcp_flush() 只要求 KCP 至少 update 过一次。首次发送时如果还未进入
 * 周期 update，则先执行一次 ikcp_update() 初始化内部时间基准；后续发送
 * 直接更新 current 并 flush，避免高吞吐场景攒到 10ms 周期后突发发送。
 */
void kcp_wrap_flush(struct IKCPCB *kcp, IUINT32 current_ms)
{
    if (!kcp) {
        LOG_ERROR("kcp_wrap_flush: null kcp pointer");
        return;
    }

    if (kcp->updated == 0) {
        ikcp_update(kcp, current_ms);
        return;
    }

    /* C18: 时间跳变检测 — 直接赋值 kcp->current 绕过 ikcp_check 保护。
     * 任何时间倒退（无论幅度）统一走 ikcp_update 路径，由 KCP 内部
     * ikcp_check 安全处理，避免破坏 KCP 内部定时器。 */
    if (current_ms < kcp->current) {
        IINT32 diff = kcp->current - current_ms;
        LOG_WARN("kcp_wrap_flush: time jump backward %d ms, "
                 "falling back to ikcp_update (kcp=%p)",
                 (int)diff, (void *)kcp);
        ikcp_update(kcp, current_ms);
        return;
    }

    /* L18: 时间前进跳跃已由上方 ikcp_update 处理；直接赋值安全 */
    kcp->current = current_ms;
    ikcp_flush(kcp);
}

/*
 * 获取 KCP 等待发送的字节数
 */
int kcp_wrap_waitsnd(struct IKCPCB *kcp)
{
    if (!kcp) {
        LOG_ERROR("kcp_wrap_waitsnd: null kcp pointer");
        return -1;
    }

    return ikcp_waitsnd(kcp);
}

/*
 * 检查 KCP 是否有待发送的数据
 */
int kcp_wrap_has_pending(struct IKCPCB *kcp)
{
    int pending;

    if (!kcp) {
        LOG_ERROR("kcp_wrap_has_pending: null kcp pointer");
        return 0;
    }

    pending = ikcp_waitsnd(kcp);
    return (pending > 0) ? 1 : 0;
}

/*
 * 获取当前毫秒时间戳
 *
 * 使用 CLOCK_MONOTONIC 获取单调递增时间，不受系统时间调整影响，
 * 适合驱动 KCP 内部定时器。
 */
IUINT32 kcp_wrap_clock(void)
{
    struct timespec ts;
    /* M7: fallback_ms 为静态变量，多线程环境下非安全。
     * 本模块仅在单线程 epoll 主循环中调用，故此设计可接受。
     * M23: 使用 _Thread_local 保证多线程场景下每个线程独立副本。 */
    static _Thread_local IUINT32 fallback_ms;

    /*
     * CLOCK_MONOTONIC is guaranteed on Linux 2.6+.
     * If it fails, the system is fundamentally broken.
     * Fall back to the last known good timestamp rather than abort(),
     * to avoid a DoS vector that would terminate the entire process.
     */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        LOG_ERROR("kcp_wrap_clock: CLOCK_MONOTONIC unavailable (%s), "
                  "continuing with stale value", strerror(errno));
        return fallback_ms;
    }

    fallback_ms = (IUINT32)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    return fallback_ms;
}
