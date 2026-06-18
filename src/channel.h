/*
 * channel.h - 通道管理模块
 *
 * 负责通道的完整生命周期管理：创建、状态机转换、哈希表查找、心跳检测。
 * 每个通道对应一个代理的端口映射。
 */

#ifndef CHANNEL_H
#define CHANNEL_H

#include "types.h"

/* ============================================================================
 * 函数声明
 * ============================================================================ */

/*
 * 初始化通道子系统
 * @param ctx          全局上下文
 * @param max_channels 最大通道数
 * @return             成功返回 0，失败返回 -1
 */
int channel_init(global_ctx_t *ctx, int max_channels);

/*
 * 关闭通道子系统，释放所有通道资源
 * @param ctx 全局上下文
 */
void channel_shutdown(global_ctx_t *ctx);

/*
 * 分配动态数据通道 ID
 * @param ctx          全局上下文
 * @param listener_idx listener 在 config.channels[] 中的 array index
 * @return             成功返回通道 ID，失败返回 0
 */
uint32_t alloc_channel_id(global_ctx_t *ctx, int listener_idx);

/*
 * 创建新通道
 * @param ctx        全局上下文
 * @param channel_id 通道 ID
 * @param role       通道角色（发起方/响应方）
 * @param listen_port 监听端口（frontend）
 * @param remote_port 远端端口
 * @param listen_addr 监听地址
 * @param remote_addr 远端地址
 * @param is_tcp     TCP 标志
 * @return           成功返回通道指针，失败返回 NULL
 */
channel_t *channel_create(global_ctx_t *ctx, uint32_t channel_id,
                          channel_role_t role,
                          uint16_t listen_port, uint16_t remote_port,
                          uint16_t source_port,
                          const char *listen_addr, const char *remote_addr,
                          uint8_t is_tcp);

/*
 * 销毁通道
 * @param ctx  全局上下文
 * @param ch   要销毁的通道
 */
void channel_destroy(global_ctx_t *ctx, channel_t *ch);

/*
 * 在哈希表中查找通道
 * @param ctx        全局上下文
 * @param channel_id 通道 ID
 * @return           找到返回通道指针，未找到返回 NULL
 */
channel_t *channel_find(global_ctx_t *ctx, uint32_t channel_id);

/*
 * 处理接收到的帧，路由到正确的通道
 * @param ctx     全局上下文
 * @param hdr     协议头
 * @param payload 负载数据
 * @param payload_len 负载长度
 * @return        成功返回 0，失败返回 -1
 */
int channel_process_frame(global_ctx_t *ctx, const myproto_hdr_t *hdr,
                          const uint8_t *payload, size_t payload_len);

/*
 * 发送控制帧（SYN/ACK/FIN/RST/PING/PONG）
 * @param ch    通道
 * @param flags 标志位
 * @return      成功返回 0，失败返回 -1
 */
int channel_send_ctrl(channel_t *ch, uint8_t flags);

/*
 * 发送数据帧
 * @param ch    通道
 * @param data  数据缓冲区
 * @param len   数据长度
 * @return      成功返回 0，失败返回 -1
 */
int channel_send_data(channel_t *ch, const uint8_t *data, size_t len);

/*
 * 处理通道心跳（由主循环定期调用）
 * @param ctx 全局上下文
 */
void channel_heartbeat(global_ctx_t *ctx);

/*
 * 处理通道超时检测（由主循环定期调用）
 * @param ctx 全局上下文
 */
void channel_timeout_check(global_ctx_t *ctx);

/*
 * 更新所有通道的 KCP 实例（由主循环定期调用）
 * @param ctx 全局上下文
 */
void channel_kcp_update(global_ctx_t *ctx);

/*
 * 遍历所有通道执行操作
 * @param ctx      全局上下文
 * @param callback 回调函数：参数为 (channel_t *, void *user_data)
 * @param user_data 用户数据
 */
typedef void (*channel_foreach_cb_t)(channel_t *ch, void *user_data);
void channel_foreach(global_ctx_t *ctx, channel_foreach_cb_t callback,
                     void *user_data);

/*
 * 获取活跃通道数
 * @param ctx 全局上下文
 * @return    活跃通道数
 */
int channel_count(global_ctx_t *ctx);

/*
 * 关闭所有通道（优雅关闭）
 * @param ctx 全局上下文
 */
void channel_close_all(global_ctx_t *ctx);

/* ---- 通道热重载辅助函数 ---- */
int  channel_config_changed(const channel_t *ch, const channel_config_t *cfg);
void channel_update_config(channel_t *ch, const channel_config_t *cfg);

#endif /* CHANNEL_H */
