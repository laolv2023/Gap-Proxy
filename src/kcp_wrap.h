/*
 * kcp_wrap.h - KCP 包装模块
 *
 * 封装 KCP (ikcp) 库的创建、销毁和输出回调绑定。
 * 为每个通道提供一个独立的 KCP 实例。
 */

#ifndef KCP_WRAP_H
#define KCP_WRAP_H

#include "types.h"
#include "ikcp.h"

/* KCP 输出回调函数类型
 * 当 KCP 需要发送数据段时，调用此回调将数据传递给 AF_PACKET 发送
 * 签名与 ikcp 库的 output 回调完全一致
 * @param buf         要发送的数据
 * @param len         数据长度
 * @param kcp         KCP 实例指针
 * @param user        用户数据指针（指向 channel_t）
 * @return            成功返回 0，失败返回 -1
 */
typedef int (*kcp_output_cb_t)(const char *buf, int len,
                                struct IKCPCB *kcp, void *user);

/* ============================================================================
 * 函数声明
 * ============================================================================ */

/*
 * 创建 KCP 实例
 * @param conv         会话 ID（使用 channel_id 作为 conv）
 * @param user         用户数据指针（指向 channel_t）
 * @return             成功返回 KCP 实例指针，失败返回 NULL
 */
struct IKCPCB *kcp_wrap_create(IUINT32 conv, void *user);

/*
 * 销毁 KCP 实例，释放所有资源
 * @param kcp KCP 实例指针
 */
void kcp_wrap_destroy(struct IKCPCB *kcp);

/*
 * 设置 KCP 输出回调
 * @param kcp    KCP 实例指针
 * @param cb     输出回调函数
 */
void kcp_wrap_set_output(struct IKCPCB *kcp, kcp_output_cb_t cb);

/*
 * 配置 KCP 参数
 * @param kcp      KCP 实例指针
 * @param mtu      MTU（最大传输单元）
 * @param sndwnd   发送窗口大小
 * @param rcvwnd   接收窗口大小
 * @param nodelay  nodelay 模式（0/1）
 * @param interval 内部更新间隔（毫秒）
 * @param resend   快速重传阈值
 * @param nc       是否禁用拥塞控制（0/1）
 */
void kcp_wrap_set_params(struct IKCPCB *kcp, int mtu, int sndwnd, int rcvwnd,
                         int nodelay, int interval, int resend, int nc);

/*
 * 发送数据到 KCP（应用层 → KCP）
 * @param kcp   KCP 实例指针
 * @param data  数据缓冲区
 * @param len   数据长度
 * @return      成功返回实际入队字节数，失败返回 -1
 */
int kcp_wrap_send(struct IKCPCB *kcp, const uint8_t *data, int len);

/*
 * 从 KCP 接收数据（KCP → 应用层）
 * @param kcp   KCP 实例指针
 * @param buf   接收缓冲区
 * @param size  缓冲区大小
 * @return      成功返回读取字节数，无数据返回 0，错误返回 -1
 */
int kcp_wrap_recv(struct IKCPCB *kcp, uint8_t *buf, int size);

/*
 * 将收到的数据段输入 KCP（网络 → KCP）
 * @param kcp   KCP 实例指针
 * @param data  数据段
 * @param len   数据段长度
 * @return      成功返回 0，失败返回 -1
 */
int kcp_wrap_input(struct IKCPCB *kcp, const uint8_t *data, int len);

/*
 * 更新 KCP 状态（驱动定时器）
 * @param kcp         KCP 实例指针
 * @param current_ms  当前时间戳（毫秒）
 */
void kcp_wrap_update(struct IKCPCB *kcp, IUINT32 current_ms);

/*
 * 立即刷新 KCP 输出队列
 * @param kcp         KCP 实例指针
 * @param current_ms  当前时间戳（毫秒）
 */
void kcp_wrap_flush(struct IKCPCB *kcp, IUINT32 current_ms);

/*
 * 获取 KCP 等待发送的字节数
 * @param kcp KCP 实例指针
 * @return    等待发送的字节数
 */
int kcp_wrap_waitsnd(struct IKCPCB *kcp);

/*
 * 检查 KCP 是否有待发送的数据
 * @param kcp KCP 实例指针
 * @return    有待发送数据返回 1，否则返回 0
 */
int kcp_wrap_has_pending(struct IKCPCB *kcp);

/*
 * 获取当前毫秒时间戳
 * @return 毫秒级时间戳
 */
IUINT32 kcp_wrap_clock(void);

#endif /* KCP_WRAP_H */
