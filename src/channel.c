/*
 * channel.c - 通道管理模块实现
 *
 * 负责通道的完整生命周期管理：创建、销毁、状态机转换、哈希表查找、
 * 帧分发、心跳检测、超时处理和 KCP 更新调度。
 *
 * 这是整个系统的核心模块，所有数据和控制帧通过此模块路由到正确的通道。
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                      通道状态机（Channel State Machine）                  ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                          ║
 * ║                        ┌─────────────┐                                   ║
 * ║                        │   CLOSED    │ ← 初始状态 / 终态                 ║
 * ║                        └──────┬──────┘                                   ║
 * ║                               │                                          ║
 * ║                    ┌──────────┴──────────┐                               ║
 * ║                    │                     │                               ║
 * ║              发起方发送 SYN        响应方收到 SYN                          ║
 * ║                    │                     │                               ║
 * ║              ┌─────▼──────┐       ┌──────▼──────┐                        ║
 * ║              │  SYN_SENT  │       │  SYN_RCVD   │                        ║
 * ║              └─────┬──────┘       └──────┬──────┘                        ║
 * ║                    │                     │                               ║
 * ║              收到 ACK              收到首个数据帧                          ║
 * ║                    │                     │                               ║
 * ║                    └──────────┬──────────┘                               ║
 * ║                               │                                          ║
 * ║                      ┌────────▼─────────┐                                ║
 * ║                      │   ESTABLISHED    │ ← 稳定数据传输状态              ║
 * ║                      └────────┬─────────┘                                ║
 * ║                               │                                          ║
 * ║                    ┌──────────┼──────────┐                               ║
 * ║                    │                     │                               ║
 * ║            本地主动关闭 FIN        收到对端 FIN                            ║
 * ║                    │                     │                               ║
 * ║              ┌─────▼──────┐       ┌──────▼──────┐                        ║
 * ║              │  FIN_SENT  │       │  FIN_RCVD   │                        ║
 * ║              └─────┬──────┘       └──────┬──────┘                        ║
 * ║                    │                     │                               ║
 * ║              收到 FIN              超时检查触发                           ║
 * ║                    │                     │                               ║
 * ║                    └──────────┬──────────┘                               ║
 * ║                               │                                          ║
 * ║                      ┌────────▼─────────┐                                ║
 * ║                      │    TIME_WAIT     │ ← 等待 30s 后销毁              ║
 * ║                      └────────┬─────────┘                                ║
 * ║                               │                                          ║
 * ║                         超时到期                                          ║
 * ║                               │                                          ║
 * ║                      ┌────────▼─────────┐                                ║
 * ║                      │     CLOSED       │ ← 销毁通道                     ║
 * ║                      └──────────────────┘                                ║
 * ║                                                                          ║
 * ║   【任意状态可接收 RST → 直接 CLOSED + 销毁】                              ║
 * ║   【SYN_SENT 超时重试 3 次失败 → CLOSED】                                 ║
 * ║   【ESTABLISHED / FIN_SENT 心跳超时 → CLOSED】                            ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

#include "channel.h"
#include "kcp_wrap.h"
#include "myproto.h"
#include "af_packet.h"
#include "proxy.h"
#include "crypto.h"
#include "plugin.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * 部分无网络单元测试只链接 channel.c，不链接 proxy.c。
 * 正式程序中 proxy.c 的强符号会覆盖这里的 no-op fallback。
 */
void __attribute__((weak))
proxy_update_kcp_backpressure(global_ctx_t *ctx, channel_t *ch)
{
    (void)ctx;
    (void)ch;
}

/* 测试场景弱符号：正式程序中 api.c 的强符号覆盖此 no-op fallback */
void __attribute__((weak))
log_output(int level, const char *fmt, ...)
{
    (void)level; (void)fmt;
}

/* ============================================================================
 * 模块级静态变量
 * ============================================================================ */

/*
 * 全局上下文指针，在 channel_init() 中设置。
 * 用于 kcp_output_cb 等需要访问全局配置（如加密密钥）的回调函数。
 */

/* ============================================================================
 * 内部辅助函数
 * ============================================================================ */

/*
 * channel_hash — 哈希函数：将 channel_id 映射到哈希表槽位
 *
 * 算法：channel_id % channel_hash_size（模运算）。
 * 哈希表大小 = max_channels × 2，限幅 [64, 65535]。
 * 采用链地址法（separate chaining）解决冲突：
 *   — 每个桶是 channel_t* 单链表头
 *   — 冲突的通道通过 hash_next 指针串联
 *   — 插入使用头插法（O(1)），查找需遍历链表
 *
 * 注意：channel_init() 调用者保证 g_ctx 非空，因此正常路径不会触发
 * g_ctx==NULL 回退到桶 0 的分支；该分支仅为防御性编程。
 */
static inline unsigned int channel_hash(uint32_t channel_id)
{
    if (!g_ctx) { LOG_WARN("channel_hash: g_ctx NULL, fallback to bucket 0"); return 0; }
    return channel_id % g_ctx->channel_hash_size;
}

/*
 * 在全局配置中查找与 channel_id 匹配的通道配置。
 *
 * 注意：此函数仅遍历静态配置表（channels[] 数组），按 channel_id 严格匹配。
 * 对于动态分配的通道 ID（≥ DYNAMIC_CHANNEL_BASE），本函数返回 NULL，
 * 调用者需要自行通过反向扫描 listener_base 区间来找到所属的 listener 配置。
 * 详见 channel_process_frame 中 SYN 帧处理逻辑的 Dynamic ID fallback 部分。
 *
 * 返回匹配的 channel_config_t 指针，未找到返回 NULL。
 */
static const channel_config_t *channel_lookup_config(uint32_t channel_id)
{
    int i;

    if (!g_ctx) {
        return NULL;
    }

    for (i = 0; i < g_ctx->config.channel_count; i++) {
        if (g_ctx->config.channels[i].enabled &&
            g_ctx->config.channels[i].channel_id == channel_id) {
            return &g_ctx->config.channels[i];
        }
    }

    return NULL;
}

/*
 * KCP 输出回调函数（静态）
 *
 * 当 KCP 需要发送数据段时调用此回调。
 * 将 KCP 数据封装为 MyProto 数据帧，通过 AF_PACKET 发送到对端。
 *
 * @param buf   KCP 待发送的数据段
 * @param len   数据段长度
 * @param user  用户数据指针（指向 channel_t）
 * @return      成功返回 0，失败返回 -1
 */
static int kcp_output_cb(const char *buf, int len, struct IKCPCB *kcp, void *user)
{
    channel_t *ch;
    uint8_t    frame_buf[MAX_FRAME_SIZE];
    uint8_t    flags      = 0;
    ssize_t    frame_len;
    ssize_t    sent;

    (void)kcp;  /* KCP 实例指针在回调中可用，当前通过 user 获取通道信息 */

    /* 参数校验 */
    if (!user) {
        LOG_ERROR("kcp_output_cb: null user pointer");
        return -1;
    }
    if (!buf) {
        LOG_ERROR("kcp_output_cb: null buf pointer");
        return -1;
    }
    if (len <= 0) {
        LOG_ERROR("kcp_output_cb: invalid length %d", len);
        return -1;
    }

    ch = (channel_t *)user;

    /* 确定加密设置 */
    if (g_ctx && crypto_is_enabled()) {
        flags = MPF_CRYPTO;
    }

    /* 构建 MyProto 数据帧 */
    frame_len = myproto_build_data_frame(frame_buf, sizeof(frame_buf),
                                         ch->channel_id, flags,
                                         (const uint8_t *)buf, (size_t)len,
                                         g_ctx ? g_ctx->config.crc_enabled : 0);
    if (frame_len < 0) {
        LOG_ERROR("kcp_output_cb: myproto_build_data_frame failed "
                  "(channel=%u, len=%d)", ch->channel_id, len);
        ch->stats.tx_errors++;
        return -1;
    }

    /* 通过 AF_PACKET 发送 */
    sent = af_packet_send(ch->raw_sock, ch->ifindex,
                          ch->peer_mac, ch->local_mac,
                          ch->ethertype,
                          frame_buf, (size_t)frame_len);
    if (sent < 0) {
        int saved_errno = errno;

        if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
            LOG_DEBUG("kcp_output_cb: AF_PACKET send buffer full "
                      "(channel=%u, frame_len=%zd), retrying",
                      ch->channel_id, frame_len);
            ch->stats.tx_errors++;
            errno = saved_errno;
            return -1;  /* C1: 必须返回-1告知KCP该段未送达, 否则数据静默丢失 */
        }

        if (saved_errno == ENOBUFS) {
            LOG_DEBUG("kcp_output_cb: AF_PACKET send buffer exhausted "
                      "(channel=%u, frame_len=%zd), KCP will retransmit",
                      ch->channel_id, frame_len);
            ch->stats.tx_errors++;
            errno = saved_errno;
            return -1;  /* permanent backpressure: tell KCP to retransmit later */
        }

        LOG_ERROR("kcp_output_cb: af_packet_send failed "
                  "(channel=%u, frame_len=%zd): %s",
                  ch->channel_id, frame_len, strerror(saved_errno));
        ch->stats.tx_errors++;
        errno = saved_errno;
        return -1;
    }

    /* 更新统计 */
    ch->stats.tx_frames++;
    ch->stats.tx_bytes += (uint64_t)frame_len;

    /* 更新最后活跃时间 */
    ch->last_active = time_now();

    LOG_DEBUG("kcp_output_cb: sent frame (channel=%u, kcp_len=%d, "
              "frame_len=%zd, flags=0x%02x)",
              ch->channel_id, len, frame_len, flags);

    return 0;
}

/*
 * 将通道插入哈希表
 */
static int channel_hash_insert(channel_t *ch)
{
    unsigned int idx;

    if (!g_ctx || !ch) {
        return -1;
    }

    idx = channel_hash(ch->channel_id);

    /* 检查是否已存在同 ID 的通道 */
    {
        channel_t *cur = g_ctx->channel_hash[idx];
        while (cur) {
            if (cur->channel_id == ch->channel_id) {
                LOG_ERROR("channel_hash_insert: channel %u already exists",
                          ch->channel_id);
                return -1;
            }
            cur = cur->hash_next;
        }
    }

    /* 头插法插入链表 */
    ch->hash_next = g_ctx->channel_hash[idx];
    g_ctx->channel_hash[idx] = ch;

    return 0;
}

/*
 * 从哈希表中移除通道
 */
static int channel_hash_remove(channel_t *ch)
{
    unsigned int idx;
    channel_t **pp;

    if (!g_ctx || !ch) {
        return -1;
    }

    idx = channel_hash(ch->channel_id);
    pp  = &g_ctx->channel_hash[idx];

    while (*pp) {
        if (*pp == ch) {
            *pp = ch->hash_next;
            ch->hash_next = NULL;
            return 0;
        }
        pp = &(*pp)->hash_next;
    }

    LOG_ERROR("channel_hash_remove: channel %u not found in hash table",
              ch->channel_id);
    return -1;
}

/*
 * 发送全局心跳控制帧（使用 channel_id=0xFFFF，不依赖 channel_t）
 */
static int channel_send_heartbeat_ctrl(global_ctx_t *ctx, uint8_t flags)
{
    uint8_t frame_buf[MAX_FRAME_SIZE];
    ssize_t frame_len;
    ssize_t sent;

    if (!ctx) {
        return -1;
    }

    frame_len = myproto_build_ctrl_frame(frame_buf, sizeof(frame_buf),
                                         HEARTBEAT_CH_ID, flags, 0);
    if (frame_len < 0) {
        LOG_ERROR("channel_send_heartbeat_ctrl: build failed (flags=0x%02x)",
                  flags);
        return -1;
    }

    sent = af_packet_send(ctx->raw_sock, ctx->ifindex,
                          ctx->peer_mac, ctx->local_mac,
                          ctx->ethertype,
                          frame_buf, (size_t)frame_len);
    if (sent < 0) {
        LOG_ERROR("channel_send_heartbeat_ctrl: send failed (flags=0x%02x): %s",
                  flags, strerror(errno));
        return -1;
    }

    LOG_DEBUG("channel_send_heartbeat_ctrl: sent (flags=0x%02x, len=%zd)",
              flags, frame_len);

    return 0;
}

/* ============================================================================
 * 公共函数实现
 * ============================================================================ */

/*
 * 初始化通道子系统（哈希表生命周期：创建阶段）
 *
 * 在程序启动时调用一次，完成以下工作：
 * 1. 保存全局上下文指针 (g_ctx)，供 kcp_output_cb 等回调使用
 * 2. 分配哈希表：大小为 max_channels * 2，限幅 [64, 65535]
 *    使用 calloc 确保所有桶初始为 NULL
 * 3. 重置通道计数为 0
 *
 * 哈希表采用链地址法（separate chaining）解决冲突：
 *   - 每个桶是 channel_t* 指针（单链表头）
 *   - 冲突的通道通过 hash_next 指针串联
 *   - 插入使用头插法（O(1)），查找需遍历链表
 *
 * @param ctx          全局上下文指针
 * @param max_channels 最大通道数（用于计算哈希表大小）
 * @return             成功返回 0，失败返回 -1
 */
int channel_init(global_ctx_t *ctx, int max_channels)
{
    uint32_t hash_size;

    if (!ctx) {
        LOG_ERROR("channel_init: null ctx pointer");
        return -1;
    }

    /* 保存全局上下文指针。
     * ── 生命周期依赖 ──
     * g_ctx 由 main.c 定义 (global_ctx_t *g_ctx = NULL)。
     * channel_init() 在 proxy_init() 之后调用（main.c 保证顺序），
     * 因此 proxy 已持有同一指针；channel_shutdown() 在 proxy_shutdown()
     * 之前调用，先清理通道再清理 proxy，避免悬空引用。 */
    g_ctx = ctx;

    /* 默认速率限制: 每秒最多创建 1000 个通道（防 SYN flood），
     * 采用 token bucket 算法，初始满 token */
    ctx->channel_create_max_per_sec = 1000;
    ctx->channel_create_timestamp   = kcp_wrap_clock();
    ctx->channel_create_tokens      = ctx->channel_create_max_per_sec;

    /* 计算哈希表大小：max_channels * 2，限幅 [64, 65535] */
    hash_size = (uint32_t)max_channels * 2;
    if (hash_size < 64) hash_size = 64;
    if (hash_size > 65535) hash_size = 65535;

    ctx->channel_hash = calloc(hash_size, sizeof(channel_t *));
    if (!ctx->channel_hash) {
        LOG_ERROR("channel_init: failed to allocate hash table (%u buckets)", hash_size);
        return -1;
    }
    ctx->channel_hash_size = hash_size;

    /* 重置通道计数 */
    ctx->channel_count = 0;

    LOG_INFO("Channel hash table allocated: %u buckets for up to %d channels",
             hash_size, max_channels);

    return 0;
}

/*
 * 关闭通道子系统（哈希表生命周期：销毁阶段）
 *
 * 在程序退出前调用一次，完成以下工作：
 * 1. 遍历哈希表所有桶，逐个销毁桶内链表中的所有通道
 *    - 每次取桶的第一个元素 (channel_hash[i]) 销毁
 *    - channel_destroy 内部调用 channel_hash_remove 从链表中摘除
 *    - 循环直到桶为空
 * 2. 释放哈希表内存 (free)
 * 3. 重置哈希表指针和大小，防止悬空引用
 * 4. 清除全局上下文指针 (g_ctx = NULL)
 *
 * 注意：销毁顺序很重要——必须先销毁所有通道（因为它们引用
 * g_ctx 中的资源），再释放哈希表本身，最后置空 g_ctx。
 */
void channel_shutdown(global_ctx_t *ctx)
{
    uint32_t i;

    if (!ctx) {
        LOG_ERROR("channel_shutdown: null ctx pointer");
        return;
    }

    LOG_DEBUG("channel_shutdown: destroying all channels (count=%d)",
              ctx->channel_count);

    /*
     * 第一遍：显式关闭所有 STATIC_LISTENER 的监听套接字。
     * channel_destroy() 保护 STATIC_LISTENER 的 listen_fd 不被关闭
     * （因为正常运行时这些 fd 由主循环管理），但在 shutdown 阶段
     * 必须显式释放以避免 fd 泄漏。
     */
    for (i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            if ((ch->flags & CH_FLAG_STATIC_LISTENER) &&
                ch->listen_fd >= 0) {
                LOG_DEBUG("channel_shutdown: closing STATIC_LISTENER "
                          "listen_fd=%d (channel=%u)",
                          ch->listen_fd, ch->channel_id);
                close(ch->listen_fd);
                ch->listen_fd = -1;
            }
            ch = ch->hash_next;
        }
    }

    /*
     * 第二遍：销毁所有通道。
     * 注意：channel_destroy 会修改链表，因此需要小心遍历。
     * 每次取桶的第一个元素销毁，直到桶为空。
     */
    for (i = 0; i < ctx->channel_hash_size; i++) {
        while (ctx->channel_hash[i]) {
            channel_t *ch = ctx->channel_hash[i];
            channel_destroy(ctx, ch);
        }
    }

    /* 释放哈希表内存 */
    free(ctx->channel_hash);
    ctx->channel_hash = NULL;
    ctx->channel_hash_size = 0;

    ctx->channel_count = 0;

    /* 清除全局上下文指针（先于 proxy_shutdown 置 NULL，
     * 确保 proxy 后续清理时不会访问已释放的通道资源） */
    g_ctx = NULL;

    LOG_DEBUG("channel_shutdown: all channels destroyed");
}

/*
 * 分配动态数据通道 ID。
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                          动态通道 ID 分配策略                            ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                          ║
 * ║  静态通道 ID 范围：0 ~ 65535（用户预配置的 channel_id）                   ║
 * ║  动态通道 ID 范围：DYNAMIC_CHANNEL_BASE(65536) 起                       ║
 * ║                                                                          ║
 * ║  每个 listener 拥有独立的 ID 区间：                                      ║
 * ║    listener_base[idx] = DYNAMIC_CHANNEL_BASE + idx * max_sessions        ║
 * ║    listener_next[idx] = 区间内下一个待尝试的 ID                          ║
 * ║                                                                          ║
 * ║  分配算法（Round-Robin 循环探测）：                                      ║
 * ║    1. 取 listener_next[idx] 当前值作为候选 ID                             ║
 * ║    2. listener_next[idx] 自增（指向下一个候选）                           ║
 * ║    3. 如果超出区间上限 [base, base+limit-1]，回绕到 base                 ║
 * ║    4. 在哈希表中查找该 ID 是否已被占用                                   ║
 * ║    5. 未被占用 → 返回该 ID；已占用 → 继续下一轮                          ║
 * ║    6. 遍历 limit 次仍未找到空闲 ID → 返回 0（资源耗尽）                   ║
 * ║                                                                          ║
 * ║  这种设计避免了线性扫描，同时保证 ID 在区间内均匀分布。                   ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * listener_idx: listener 在 g_ctx->config.channels[] 中的 array index。
 * 每个 listener 从 listener_base[idx] 开始，范围由 max_sessions 决定。
 */
#define DYNAMIC_CHANNEL_BASE 65536U

uint32_t alloc_channel_id(global_ctx_t *ctx, int listener_idx)
{
    if (listener_idx < 0 || listener_idx >= ctx->config.channel_count)
        return 0;

    uint32_t limit = (uint32_t)ctx->config.channels[listener_idx].max_sessions;
    if (limit == 0) limit = 1;

    uint32_t base = ctx->listener_base[listener_idx];
    uint32_t max  = base + limit - 1;

    for (uint32_t attempt = 0; attempt < limit; attempt++) {
        uint32_t id = ctx->listener_next[listener_idx]++;
        if (id > max) {
            ctx->listener_next[listener_idx] = base;
            id = ctx->listener_next[listener_idx]++;
        }
        if (channel_find(ctx, id) == NULL) return id;
    }
    return 0;
}

/*
 * 创建新通道
 */
channel_t *channel_create(global_ctx_t *ctx, uint32_t channel_id,
                          channel_role_t role,
                          uint16_t listen_port, uint16_t remote_port,
                          uint16_t source_port,
                          const char *listen_addr, const char *remote_addr,
                          uint8_t is_tcp)
{
    channel_t *ch;
    uint32_t   now;

    if (!ctx) {
        LOG_ERROR("channel_create: null ctx pointer");
        return NULL;
    }

    /* 检查最大通道数限制 */
    if (ctx->channel_count >= ctx->config.max_channels) {
        LOG_ERROR("channel_create: max channels reached (%d/%d)",
                  ctx->channel_count, ctx->config.max_channels);
        return NULL;
    }

    /* 速率限制 (token bucket)：仅针对运行期动态通道，静态 LISTENER 不受此限制。
     *
     * token bucket 算法：
     *   - 每次尝试创建消耗 1 个 token
     *   - token 以 max_per_sec/s 的速率匀速补充
     *   - bucket 容量 = max_per_sec（允许瞬时突发但不允许双倍爆发）
     *   - 使用 kcp_wrap_clock() 毫秒级时钟消除秒边界窗口
     */
    if (role != CHANNEL_ROLE_LISTENER &&
        ctx->channel_create_max_per_sec > 0) {
        uint32_t now_ms = kcp_wrap_clock();
        uint32_t elapsed;

        /* 处理时钟回绕 */
        if (now_ms >= ctx->channel_create_timestamp) {
            elapsed = now_ms - ctx->channel_create_timestamp;
        } else {
            elapsed = 0;  /* 时钟回绕，不补充 token */
        }

        if (elapsed > 0) {
            /* 使用 u64 乘法避免 uint32 溢出：elapsed(ms) * max_per_sec 在
             * ≈4295 秒（71 分钟）后溢出 32 位，导致 new_tokens 归零，
             * 通道限流永久失效。 */
            uint64_t new_tokens = ((uint64_t)elapsed * ctx->channel_create_max_per_sec) / 1000;

            /* 安全赋值：new_tokens 可能大于 channel_create_tokens(u32) 容量，
             * 先做上界裁剪再累加，避免 u64→u32 隐式截断绕过 cap 检查。 */
            if (new_tokens > (uint64_t)ctx->channel_create_max_per_sec) {
                ctx->channel_create_tokens = ctx->channel_create_max_per_sec;
            } else {
                ctx->channel_create_tokens += (uint32_t)new_tokens;
                if (ctx->channel_create_tokens > ctx->channel_create_max_per_sec)
                    ctx->channel_create_tokens = ctx->channel_create_max_per_sec;
            }
            ctx->channel_create_timestamp = now_ms;
        }

        if (ctx->channel_create_tokens == 0) {
            LOG_ERROR("channel_create: rate limit exceeded (%u/sec)",
                      ctx->channel_create_max_per_sec);
            return NULL;
        }
        ctx->channel_create_tokens--;
    }

    /* 检查是否已存在同 ID 通道 */
    if (channel_find(ctx, channel_id)) {
        LOG_ERROR("channel_create: channel %u already exists", channel_id);
        /* 退还已消费的令牌，防止攻击者用已知 channel_id 耗尽令牌桶 */
        if (role != CHANNEL_ROLE_LISTENER
            && ctx->channel_create_max_per_sec > 0
            && ctx->channel_create_tokens < ctx->channel_create_max_per_sec) {
            ctx->channel_create_tokens++;
        }
        return NULL;
    }

    /* 分配通道结构体并清零 */
    /*
     * D10-5: 全局内存配额检查（Memory Quota Check）
     *
     * ┌─────────────────────────────────────────────────────────────────┐
     * │ 在分配通道结构体之前，预先计算通道总内存开销并检查配额：          │
     * │                                                                  │
     * │ channel_overhead =                                                │
     * │   sizeof(channel_t)                                   通道结构体   │
     * │   + sizeof(ikcpcb)                                   KCP 协议栈   │
     * │   + kcp_send_window × kcp_mtu                        KCP 发送窗口 │
     * │   + kcp_recv_window × kcp_mtu                        KCP 接收窗口 │
     * │   + perf_proxy_recv_buf_max                          接收缓冲区   │
     * │                                                                  │
     * │ 若 ctx->global_memory_used + channel_overhead > max_bytes：            │
     * │   → 拒绝创建，返回 NULL（通道创建失败）                            │
     * │   → 日志记录当前/最大内存使用量（以 MB 为单位）                    │
     * │                                                                  │
     * │ 配额为 0 时跳过检查（向后兼容未配置内存限制的旧部署）。            │
     * └─────────────────────────────────────────────────────────────────┘
     */
    if (ctx->config.perf_max_memory_mb > 0) {
        size_t max_bytes = (size_t)ctx->config.perf_max_memory_mb * 1024 * 1024;
        size_t channel_overhead = sizeof(channel_t) + sizeof(ikcpcb)
                                + (size_t)ctx->config.kcp_send_window * ctx->config.kcp_mtu
                                + (size_t)ctx->config.kcp_recv_window * ctx->config.kcp_mtu
                                + (size_t)ctx->config.perf_proxy_recv_buf_max;
        if (ctx->global_memory_used + channel_overhead > max_bytes) {
            LOG_ERROR("channel_create: memory quota exceeded (%zu/%zu MB) for channel %u",
                      (ctx->global_memory_used + channel_overhead) / (1024*1024),
                      max_bytes / (1024*1024), channel_id);
            return NULL;
        }
    }

    ch = (channel_t *)calloc(1, sizeof(channel_t));
    if (!ch) {
        LOG_ERROR("channel_create: calloc failed for channel %u: %s",
                  channel_id, strerror(errno));
        return NULL;
    }
    ctx->global_memory_used += sizeof(channel_t);

    /* 获取当前时间戳 */
    now = time_now();

    /* ---- 初始化标识字段 ---- */
    ch->channel_id = channel_id;
    ch->state      = CHANNEL_CLOSED;
    ch->role       = role;

    /* ---- 初始化网络层字段（从全局上下文复制） ---- */
    ch->raw_sock  = ctx->raw_sock;
    ch->ifindex   = ctx->ifindex;
    ch->ethertype = ctx->ethertype;
    memcpy(ch->peer_mac,  ctx->peer_mac,  ETH_MAC_ADDR_LEN);
    memcpy(ch->local_mac, ctx->local_mac, ETH_MAC_ADDR_LEN);

    /* ---- 初始化本地套接字字段 ---- */
    ch->local_fd    = -1;
    ch->listen_fd   = -1;
    ch->listen_port = listen_port;
    ch->remote_port = remote_port;
    ch->source_port = source_port;
    ch->is_tcp      = is_tcp;

    if (listen_addr) {
        strncpy(ch->listen_addr, listen_addr, MAX_LISTEN_ADDR - 1);
        ch->listen_addr[MAX_LISTEN_ADDR - 1] = '\0';
    } else {
        ch->listen_addr[0] = '\0';
    }

    if (remote_addr) {
        strncpy(ch->remote_addr, remote_addr, MAX_REMOTE_ADDR - 1);
        ch->remote_addr[MAX_REMOTE_ADDR - 1] = '\0';
    } else {
        ch->remote_addr[0] = '\0';
    }

    /* ---- 初始化时间戳 ---- */
    ch->last_active    = now;
    ch->last_peer_seen = now;
    ch->created_at     = now;
    ch->syn_sent_at    = 0;
    ch->fin_rcvd_at    = 0;
    ch->last_ack_sent  = 0;

    /* ---- 初始化缓冲区 ---- */
    ch->recv_buf     = NULL;
    ch->recv_buf_len = 0;
    ch->recv_buf_cap = 0;

    /* ---- 初始化流控 ---- */
    ch->paused = 0;

    /* ---- 初始化重传计数 ---- */
    ch->syn_retry_count = 0;
    ch->fin_retry_count = 0;

    /* ---- 清零统计 ---- */
    memset(&ch->stats, 0, sizeof(ch->stats));

    /* ---- 初始化链表指针 ---- */
    ch->hash_next = NULL;

    /* ---- 创建 KCP 实例 ---- */
    ch->kcp = kcp_wrap_create((IUINT32)channel_id, (void *)ch);
    if (!ch->kcp) {
        LOG_ERROR("channel_create: kcp_wrap_create failed for channel %u",
                  channel_id);
        /* 回退 channel 内存分配计数 */
        if (ctx->global_memory_used >= sizeof(channel_t))
            ctx->global_memory_used -= sizeof(channel_t);
        free(ch);
        return NULL;
    }

    /* ---- 设置 KCP 输出回调 ---- */
    kcp_wrap_set_output(ch->kcp, kcp_output_cb);

    /* ---- 配置 KCP 参数 ---- */
    kcp_wrap_set_params(ch->kcp,
                        ctx->config.kcp_mtu,
                        ctx->config.kcp_send_window,
                        ctx->config.kcp_recv_window,
                        ctx->config.kcp_nodelay,
                        ctx->config.kcp_interval,
                        ctx->config.kcp_resend,
                        ctx->config.kcp_nc);

    /* ---- 插入哈希表 ---- */
    if (channel_hash_insert(ch) != 0) {
        LOG_ERROR("channel_create: hash insert failed for channel %u",
                  channel_id);
        if (ctx->global_memory_used >= sizeof(channel_t))
            ctx->global_memory_used -= sizeof(channel_t);
        kcp_wrap_destroy(ch->kcp);
        free(ch);
        return NULL;
    }

    ctx->channel_count++;

    LOG_DEBUG("channel_create: channel %u created (role=%d, is_tcp=%d, "
              "listen=%s:%u, remote=%s:%u)",
              channel_id, role, is_tcp,
              ch->listen_addr, ch->listen_port,
              ch->remote_addr, ch->remote_port);

    /*
     * 根据角色分叉初始化路径：
     *
     * ╔══════════════════════════════════════════════════════════════════╗
     * ║                     三种角色初始化路径                           ║
     * ╠══════════════════════════════════════════════════════════════════╣
     * ║                                                                  ║
     * ║  INITIATOR（发起方）：                                           ║
     * ║    → 状态设为 SYN_SENT                                          ║
     * ║    → 立即发送 SYN 帧尝试建立连接                                ║
     * ║    → 若发送失败不阻止创建，由 timeout_check 负责重试             ║
     * ║    → proxy_start_listen 由 main.c 统一调用                      ║
     * ║                                                                  ║
     * ║  RESPONDER（响应方）：                                           ║
     * ║    → 状态设为 SYN_RCVD                                          ║
     * ║    → 等待首个数据帧（而非 ACK）来确认连接建立                   ║
     * ║    → 由 channel_process_frame 处理后续的 ACK 发送                ║
     * ║                                                                  ║
     * ║  LISTENER（监听方）：                                            ║
     * ║    → 不发送 SYN，不设置 local_fd                                ║
     * ║    → 状态设为 ESTABLISHED（伪就绪，兼容现有流程）                ║
     * ║    → listen_fd 由 main.c 调用 proxy_start_listen 设置           ║
     * ║                                                                  ║
     * ╚══════════════════════════════════════════════════════════════════╝
     *
     * 发起方角色：立即发送 SYN 建立连接。
     * proxy_start_listen 由 main.c 统一调用，不在此处重复。
     */
    switch (role) {
    case CHANNEL_ROLE_INITIATOR:
        ch->state       = CHANNEL_SYN_SENT;
        ch->syn_sent_at = time_now();

        LOG_DEBUG("channel_create: sending initial SYN (channel=%u)",
                  channel_id);

        if (channel_send_ctrl(ch, MPF_SYN) != 0) {
            LOG_ERROR("channel_create: failed to send initial SYN "
                      "for channel %u", channel_id);
            /*
             * SYN 发送失败不阻止通道创建——重试机制
             * 会在 channel_timeout_check 中处理。
             */
        }
        break;
    case CHANNEL_ROLE_RESPONDER:
        ch->state = CHANNEL_SYN_RCVD;
        break;
    case CHANNEL_ROLE_LISTENER:
        /* Listener: 不发送 SYN，不设置 local_fd。
         * listen_fd 由 main.c 调用 proxy_start_listen 设置。 */
        ch->state = CHANNEL_ESTABLISHED;  /* 假装就绪以兼容现有流程 */
        break;
    default:
        ch->state = CHANNEL_CLOSED;
        break;
    }

    /* HP-7a: 业务插件 — 通道创建通知 */
    plugin_invoke_channel_create(ctx, ch);

    return ch;
}

/*
 * 销毁通道（清理顺序：哈希表→HP-7b→KCP→本地FD→监听FD→内存）
 *
 * 清理步骤严格按依赖关系排序：
 *   1. channel_hash_remove  —— 从哈希表摘除（HP-7b 之前，防重入 destroy）
 *   2. HP-7b 插件通知       —— ch 数据完整但已不可通过 channel_find 找到
 *   3. session_log           —— 会话关闭审计日志
 *   4. channel_count--       —— 更新全局计数
 *   5. kcp_wrap_destroy      —— 销毁 KCP 实例，释放协议栈资源
 *   6. proxy_close_local     —— 关闭与本地服务的 TCP/UDP 连接
 *   7. close(listen_fd)      —— 关闭监听套接字（STATIC_LISTENER 除外）
 *   8. free(ch)              —— 释放通道结构体内存
 *
 * STATIC_LISTENER 保护详见第 7 步注释。
 */
void channel_destroy(global_ctx_t *ctx, channel_t *ch)
{
    if (!ctx) {
        LOG_ERROR("channel_destroy: null ctx pointer");
        return;
    }
    if (!ch) {
        LOG_ERROR("channel_destroy: null ch pointer");
        return;
    }

    LOG_DEBUG("channel_destroy: destroying channel %u (state=%d)",
              ch->channel_id, ch->state);

    /* 先哈希表移除：防止插件在 HP-7b 中通过 channel_find 拿到同一 ch 并重入 destroy */
    if (channel_hash_remove(ch) == 0) {
        if (ctx->channel_count > 0)
            ctx->channel_count--;
    }

    /* 若销毁的是管理通道，清空 mgmt_channel 防止悬空指针 */
    if (ch->flags & CH_FLAG_MGMT_CHANNEL)
        ctx->mgmt.mgmt_channel = NULL;

    /* HP-7b: 业务插件 — 通道销毁通知（ch 仍完整，但已不可通过 channel_find 查找到） */
    plugin_invoke_channel_destroy(ctx, ch);

    /* 会话关闭日志：仅已建立或曾有数据收发的通道 */
    if (ctx->config.log_session_close &&
        (ch->state >= CHANNEL_ESTABLISHED ||
         ch->stats.tx_bytes > 0 || ch->stats.rx_bytes > 0)) {
        uint32_t now = time_now();
        uint32_t dur = (ch->created_at && now > ch->created_at) ? now - ch->created_at : 0;
        LOG_INFO("SESSION_CLOSE ts=%lu ch=%u role=%s proto=%s "
                 "src=%s:%u dst=%s:%u "
                 "tx=%lluB/%lluP rx=%lluB/%lluP dur=%us state=%d",
                 (unsigned long)time(NULL),
                 ch->channel_id,
                 ch->role == CHANNEL_ROLE_INITIATOR ? "initiator" :
                 ch->role == CHANNEL_ROLE_RESPONDER ? "responder" : "listener",
                 ch->is_tcp ? "tcp" : "udp",
                 ch->listen_addr, ch->listen_port,
                 ch->remote_addr, ch->remote_port,
                 (unsigned long long)ch->stats.tx_bytes,
                 (unsigned long long)ch->stats.tx_frames,
                 (unsigned long long)ch->stats.rx_bytes,
                 (unsigned long long)ch->stats.rx_frames,
                 dur, ch->state);
    }

    /*
     * 关闭本地连接套接字。
     * 注意：proxy_close_local() 内部通过 proxy.c 模块自身的
     * static g_ctx 引用全局上下文（用于 epoll 操作），
     * 而非通过参数传入 ctx。这是 proxy 模块的设计约定，
     * 与 channel_destroy 的 ctx 形参最终指向同一 global_ctx_t。
     */
    if (ch->local_fd >= 0) {
        proxy_close_local(ch);
        ch->local_fd = -1;
    }

    if (ch->recv_buf) {
        free(ch->recv_buf);
        ch->recv_buf = NULL;
        ch->recv_buf_len = 0;
        ch->recv_buf_cap = 0;
    }

    /* 销毁 KCP 实例 */
    if (ch->kcp) {
        kcp_wrap_destroy(ch->kcp);
        ch->kcp = NULL;
    }

    /* 关闭监听套接字（TCP/UDP 使用 close()，非 af_packet_close()）。
     *
     * ── STATIC_LISTENER 保护 ──
     * 静态监听通道（CH_FLAG_STATIC_LISTENER）的 listen_fd 属于全局配置，
     * 其生命周期与整个代理进程一致，不应在单个通道销毁时关闭。
     * 只有动态创建（如 RESPONDER）的 listen_fd 才在此处清理。
     * 清理步骤：先从 epoll 实例注销，再 close 文件描述符。 */
    if (ch->listen_fd >= 0 && !(ch->flags & CH_FLAG_STATIC_LISTENER)) {
        proxy_epoll_del(ctx, ch->listen_fd);
        close(ch->listen_fd);
        ch->listen_fd = -1;
    }

    /*
     * ── 释放通道内存并更新全局内存追踪 ──
     *
     * 内存追踪模型（对称配对）：
     *   — channel_create 中 ctx->global_memory_used += sizeof(channel_t)
     *   — channel_destroy 中 ctx->global_memory_used -= sizeof(channel_t)
     *
     * 安全保护：
     *   — 减法前检查 ctx->global_memory_used >= sizeof(channel_t)，防止下溢
     *     （可能由 double-free 或内存追踪 bug 导致）
     *
     * 注意：KCP 实例和接收缓冲区的内存已在前面步骤中释放
     * （kcp_wrap_destroy + free(recv_buf)），此处仅释放 channel_t 本体。
     */
    if (ctx->global_memory_used >= sizeof(channel_t))
        ctx->global_memory_used -= sizeof(channel_t);
    free(ch);

    LOG_DEBUG("channel_destroy: channel freed (remaining=%d)",
              ctx->channel_count);
}

/*
 * channel_find — 在哈希表中按 channel_id 查找通道
 *
 * 算法：channel_hash(channel_id) → 定位桶 → 遍历单链表 → 匹配 channel_id。
 *
 * 时间复杂度：
 *   — 平均 O(1)：哈希表大小为 max_channels×2，负载因子 < 0.5
 *   — 最坏 O(n)：所有通道哈希到同一桶（极端冲突，实际极少发生）
 *
 * 使用场景：
 *   — channel_process_frame：每个入站帧都先查找所属通道
 *   — channel_create：创建前检查 ID 是否已存在
 *   — main.c 配置热重载：查找旧通道以更新/销毁
 *
 * @return 找到返回通道指针，未找到返回 NULL
 */
channel_t *channel_find(global_ctx_t *ctx, uint32_t channel_id)
{
    unsigned int idx;
    channel_t   *cur;

    if (!ctx) {
        LOG_ERROR("channel_find: null ctx pointer");
        return NULL;
    }

    idx = channel_hash(channel_id);
    cur = ctx->channel_hash[idx];

    while (cur) {
        if (cur->channel_id == channel_id) {
            return cur;
        }
        cur = cur->hash_next;
    }

    return NULL;
}

/*
 * 处理接收到的帧——核心分发函数
 *
 * 根据帧类型（控制/数据）和标志位，将帧路由到正确的处理逻辑。
 * 这是整个系统数据路径的关键入口。
 */
int channel_process_frame(global_ctx_t *ctx, const myproto_hdr_t *hdr,
                          const uint8_t *payload, size_t payload_len)
{
    channel_t *ch = NULL;
    uint32_t   now;

    if (!ctx) {
        LOG_ERROR("channel_process_frame: null ctx pointer");
        return -1;
    }
    if (!hdr) {
        LOG_ERROR("channel_process_frame: null hdr pointer");
        return -1;
    }

    now = time_now();

    /* ========================================================================
     * 全局心跳通道 (channel_id=0xFFFF) 特殊处理
     * ======================================================================== */
    if (hdr->channel_id == HEARTBEAT_CH_ID) {
        if ((hdr->flags & MPF_CTRL_MASK) == MPF_PING) {
            LOG_DEBUG("channel_process_frame: global PING, responding PONG");
            /* PONG token bucket 限速 10/s，防止 PING flood 放大攻击 */
            {
                uint32_t pong_now = time_now();
                if (ctx->pong_ts != pong_now) {
                    ctx->pong_tokens = 10;
                    ctx->pong_ts    = pong_now;
                }
                if (ctx->pong_tokens > 0) {
                    ctx->pong_tokens--;
                    channel_send_heartbeat_ctrl(ctx, MPF_PONG);
                }
            }
            return 0;
        } else if ((hdr->flags & MPF_CTRL_MASK) == MPF_PONG) {
            LOG_DEBUG("channel_process_frame: global PONG received");
            ctx->last_global_heartbeat = now;
            return 0;
        } else {
            LOG_DEBUG("channel_process_frame: unknown frame type 0x%02x "
                      "on heartbeat channel, ignoring", hdr->flags);
            return 0;
        }
    }

    /* ========================================================================
     * 控制帧处理
     * ======================================================================== */
    if (IS_CTRL_FRAME(hdr->flags)) {

        switch (hdr->flags & MPF_CTRL_MASK) {

        /* ── SYN: 通道建立请求 ──
         *
         * 处理逻辑分两种情况：
         *
         * A) 通道不存在（首次 SYN）：
         *    1. 查找配置 → 2. 创建 RESPONDER → 3. 设置本地套接字
         *       → 4. 发送 ACK → 5. 状态转入 SYN_RCVD
         *
         * B) 通道已存在（SYN 重传）：
         *    - 拒绝在 FIN_SENT/FIN_RCVD/TIME_WAIT/CLOSED 状态的 SYN
         *      （防止"僵尸复活"）
         *    - ESTABLISHED 状态下忽略重复 SYN（已连接，无需处理）
         *    - 其他状态回复 ACK，刷新对端活跃时间
         */
        case MPF_SYN:
            LOG_DEBUG("channel_process_frame: SYN (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                /*
                 * ── RESPONDER 动态创建流程 ──
                 *
                 * 响应方收到 SYN 但哈希表中无此通道 → 新建 RESPONDER：
                 *
                 *   Step 1: channel_lookup_config 精确匹配 channel_id
                 *   Step 2: 若失败，反向扫描 listener_base 区间回退查找配置
                 *   Step 3: 用找到的 cfg（或默认值）调用 channel_create
                 *   Step 4: 根据节点类型设置本地套接字：
                 *     - FRONTEND: proxy_connect_remote → 连接远端服务
                 *     - BACKEND:  proxy_start_listen → 监听本地客户端
                 *   Step 5: 发送 ACK 确认连接建立
                 *
                 * 若任一步骤失败，发送 RST 并销毁通道。
                 *
                 * 响应方收到 SYN：查找配置或使用默认参数创建通道。
                 */
                const channel_config_t *cfg;
                uint16_t                lport = 0;
                uint16_t                rport = 0;
                const char             *laddr = "0.0.0.0";
                const char             *raddr = "0.0.0.0";
                uint8_t                 tcp   = 1;

                cfg = channel_lookup_config(hdr->channel_id);
                /*
                 * Dynamic ID fallback（动态 ID 回退查找）：
                 *
                 * channel_lookup_config 只按 channel_id 精确匹配静态配置表。
                 * 当收到动态分配的 channel_id（≥ DYNAMIC_CHANNEL_BASE）时，
                 * 精确匹配会失败。此时采用反向扫描策略：
                 *
                 *   从 channels[] 数组尾部向头部遍历，找到第一个满足
                 *     hdr->channel_id >= listener_base[idx]
                 *   的 listener 配置。
                 *
                 * 反向扫描的原因：listener_base 按 idx 递增单调排列，
                 * 从后往前扫描能更快命中高 idx 区间（动态 ID 通常较大）。
                 *
                 * 找到的 cfg 提供 listen_port/remote_port/listen_addr/
                 * remote_addr/is_tcp 等参数，用于创建 RESPONDER 通道。
                 */
                if (!cfg) {
                    for (int idx = g_ctx->config.channel_count - 1; idx >= 0; idx--) {
                        uint32_t limit = (uint32_t)g_ctx->config.channels[idx].max_sessions;
                        if (limit == 0) limit = 1;
                        if ((uint64_t)hdr->channel_id >= (uint64_t)g_ctx->listener_base[idx] &&
                            (uint64_t)hdr->channel_id < (uint64_t)g_ctx->listener_base[idx] + (uint64_t)limit) {
                            cfg = &g_ctx->config.channels[idx];
                            break;
                        }
                    }
                }
                if (cfg) {
                    lport = cfg->listen_port;
                    rport = cfg->remote_port;
                    laddr = cfg->listen_addr;
                    raddr = cfg->remote_addr;
                    tcp   = cfg->is_tcp;
                }

                ch = channel_create(ctx, hdr->channel_id,
                                    CHANNEL_ROLE_RESPONDER,
                                    lport, rport, 0,
                                    laddr, raddr, tcp);
                if (!ch) {
                    LOG_ERROR("channel_process_frame: "
                              "failed to create responder channel %u",
                              hdr->channel_id);
                    return -1;
                }

                /* Set up local socket for the new responder channel.
                 *
                 *   Backend:  RESPONDER connects to remote service (D:22).
                 *   Frontend: RESPONDER listens for local clients (after backend-initiated SYN). */
                if (g_ctx && g_ctx->config.node_type == NODE_TYPE_BACKEND) {
                    /* Backend: connect to remote_addr:remote_port */
                    if (proxy_connect_remote(ch) >= 0) {
                        channel_send_ctrl(ch, MPF_ACK);
                    } else {
                        LOG_ERROR("Failed to connect remote for "
                                  "dynamic channel %u, destroying", ch->channel_id);
                        channel_send_ctrl(ch, MPF_RST);
                        channel_destroy(ctx, ch);
                        return -1;
                    }
                } else if (g_ctx) {
                    /* Frontend: start listening for local clients */
                    if (proxy_start_listen(g_ctx, ch) < 0) {
                        LOG_ERROR("Failed to start listen for "
                                  "dynamic channel %u", ch->channel_id);
                        channel_send_ctrl(ch, MPF_RST);
                        ch->state = CHANNEL_CLOSED;
                        channel_destroy(ctx, ch);
                        return -1;
                    }
                    channel_send_ctrl(ch, MPF_ACK);
                }
            } else {
                /* Channel found — validate state before accepting SYN.
                 * Reject SYN on closing/closed channels to prevent stale revival.
                 * SYN_SENT (peer's retransmission) is OK. */
                if (ch->state == CHANNEL_FIN_SENT ||
                    ch->state == CHANNEL_FIN_RCVD ||
                    ch->state == CHANNEL_TIME_WAIT ||
                    ch->state == CHANNEL_CLOSED) {
                    LOG_WARN("channel_process_frame: "
                             "SYN for channel %u in closing state %d, ignoring",
                             hdr->channel_id, ch->state);
                    return 0;
                }
                /* ESTABLISHED: duplicate SYN, ignore (already connected) */
                if (ch->state == CHANNEL_ESTABLISHED) {
                    LOG_DEBUG("channel_process_frame: "
                              "ignoring duplicate SYN on ESTABLISHED channel %u",
                              hdr->channel_id);
                    return 0;
                }
                /* per-channel 防抖：1s 内不重复发送 ACK，防止 SYN flood 放大 */
                if (time_elapsed(ch->last_ack_sent) >= 1) {
                    channel_send_ctrl(ch, MPF_ACK);
                    ch->last_ack_sent = now;
                }
            }

            if (ch->state != CHANNEL_SYN_RCVD)
                ch->state = CHANNEL_SYN_RCVD;
            ch->last_peer_seen = now;
            ch->last_active    = now;

            LOG_DEBUG("channel_process_frame: "
                      "channel %u SYN → SYN_RCVD (responder)",
                      hdr->channel_id);
            break;

        /* ── ACK: 通道建立确认 ──
         *
         * 发起方收到 ACK 后从 SYN_SENT → ESTABLISHED。
         * 若为 BACKEND 节点且本地套接字未建立，则连接远端服务。
         * 非 SYN_SENT 状态下收到 ACK 直接忽略（可能是重复帧）。 */
        case MPF_ACK:
            LOG_DEBUG("channel_process_frame: ACK (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_DEBUG("channel_process_frame: "
                          "late ACK for unknown channel %u, dropping",
                          hdr->channel_id);
                return 0;
            }

            if (ch->state == CHANNEL_SYN_SENT) {
                ch->state = CHANNEL_ESTABLISHED;
                LOG_DEBUG("channel_process_frame: "
                          "channel %u SYN_SENT → ESTABLISHED",
                          hdr->channel_id);

                /* If we're a backend proxy responder, connect to local service */
                if (g_ctx && g_ctx->config.node_type == NODE_TYPE_BACKEND &&
                    ch->local_fd < 0) {
                    if (proxy_connect_remote(ch) < 0) {
                        LOG_ERROR("Failed to connect to remote service "
                                  "for channel %u", ch->channel_id);
                        channel_send_ctrl(ch, MPF_RST);
                        ch->state = CHANNEL_CLOSED;
                        channel_destroy(ctx, ch);
                        return -1;
                    }
                }
            } else if (ch->state == CHANNEL_SYN_RCVD) {
                /* 同时打开 (simultaneous open): 双方INITIATOR互发SYN */
                ch->state = CHANNEL_ESTABLISHED;
                LOG_DEBUG("channel_process_frame: "
                          "channel %u SYN_RCVD → ESTABLISHED (simultaneous)",
                          hdr->channel_id);
            } else {
                LOG_DEBUG("channel_process_frame: "
                          "ACK for channel %u in state %d (ignored)",
                          hdr->channel_id, ch->state);
            }

            ch->last_peer_seen = now;
            ch->last_active    = now;
            break;

        /* ── FIN: 通道关闭请求（四次挥手简化版）──
         *
         * 状态转换规则：
         *   ESTABLISHED/SYN_SENT/SYN_RCVD → FIN_RCVD（回送 FIN）
         *   FIN_SENT → TIME_WAIT（双方同时关闭，跳过 FIN_RCVD）
         *   FIN_RCVD/TIME_WAIT → 忽略（已在关闭路径中）
         *   CLOSED/其他 → 记录日志并忽略 */
        case MPF_FIN:
            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_DEBUG("FIN for unknown channel %u, ignoring",
                          hdr->channel_id);
                return 0;
            }
            LOG_DEBUG("Received FIN for channel %u (state=%d)",
                      ch->channel_id, ch->state);

            /* Only respond with FIN if in an active state */
            if (ch->state == CHANNEL_ESTABLISHED ||
                ch->state == CHANNEL_SYN_SENT ||
                ch->state == CHANNEL_SYN_RCVD) {
                channel_send_ctrl(ch, MPF_FIN);
                ch->state = CHANNEL_FIN_RCVD;
                ch->fin_rcvd_at = now;  /* 记录进入 FIN_RCVD 的时间戳，用于最小 2s 延迟 */
            } else if (ch->state == CHANNEL_FIN_SENT) {
                /* Both sides sent FIN simultaneously → proceed to TIME_WAIT */
                ch->state = CHANNEL_TIME_WAIT;
                ch->last_active = time_now();
            } else if (ch->state == CHANNEL_FIN_RCVD ||
                       ch->state == CHANNEL_TIME_WAIT) {
                /* Already closing, ignore duplicate FIN */
            } else {
                /* CLOSED or unknown state */
                LOG_DEBUG("FIN for channel %u in unexpected state %d",
                          ch->channel_id, ch->state);
            }
            ch->last_peer_seen = now;
            break;

        /* ── RST: 强制复位 ──
         *
         * 收到 RST 后无条件将通道状态置为 CLOSED 并立即销毁。
         * RST 是"硬关闭"信号，不经过 FIN 握手流程，
         * 通常由超时检测或异常错误触发。 */
        case MPF_RST:
            LOG_DEBUG("channel_process_frame: RST (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_DEBUG("channel_process_frame: "
                          "RST for unknown channel %u, ignoring",
                          hdr->channel_id);
                return 0;
            }

            LOG_DEBUG("channel_process_frame: "
                      "force closing channel %u due to RST",
                      hdr->channel_id);

            /* 保护 LISTENER/STATIC_LISTENER 不被 RST 销毁 */
            if ((ch->flags & CH_FLAG_STATIC_LISTENER) ||
                ch->role == CHANNEL_ROLE_LISTENER) {
                LOG_WARN("channel_process_frame: "
                         "ignoring RST on LISTENER channel %u",
                         hdr->channel_id);
                break;
            }

            ch->state = CHANNEL_CLOSED;
            channel_destroy(ctx, ch);
            break;

        /* ---- PING: 心跳探测 ---- */
        case MPF_PING:
            LOG_DEBUG("channel_process_frame: PING (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_DEBUG("channel_process_frame: "
                          "late PING for unknown channel %u, dropping",
                          hdr->channel_id);
                return 0;
            }

            /* 对已建立或正在关闭的通道回复 PONG（挥手期间仍应保持心跳） */
            if (ch->state == CHANNEL_ESTABLISHED ||
                ch->state == CHANNEL_FIN_SENT ||
                ch->state == CHANNEL_FIN_RCVD) {
                if (channel_send_ctrl(ch, MPF_PONG) != 0) {
                    LOG_ERROR("channel_process_frame: "
                              "failed to send PONG for channel %u",
                              hdr->channel_id);
                }
            }

            ch->last_peer_seen = now;
            ch->last_active    = now;
            break;

        /* ---- PONG: 心跳响应 ---- */
        case MPF_PONG:
            LOG_DEBUG("channel_process_frame: PONG (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_DEBUG("channel_process_frame: "
                          "late PONG for unknown channel %u, dropping",
                          hdr->channel_id);
                return 0;
            }

            ch->last_peer_seen = now;
            break;

        /* ---- 未知/组合控制标志 ---- */
        default:
            LOG_ERROR("channel_process_frame: "
                      "unknown control flags 0x%02x (channel=%u), dropping",
                      hdr->flags, hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);

            /*
             * R7-P2: 未知 CTL 帧 → RST 通知对端关闭通道
             *
             * 当收到无法识别的控制帧标志位组合时：
             *   — 若通道处于 ESTABLISHED 状态：发送 RST 通知对端立即关闭，
             *     防止半开连接残留（对端可能认为连接仍然有效）
             *   — 若通道处于非 ESTABLISHED 状态：仅丢弃帧，不发送 RST
             *     （通道尚未完全建立，无需通知）
             *   — 日志记录：LOG_ERROR 记录未知标志位 + LOG_INFO 记录 RST 发送
             */
            if (ch && ch->state == CHANNEL_ESTABLISHED) {
                channel_send_ctrl(ch, MPF_RST);
                LOG_INFO("Sent RST for channel %u (unknown CTL 0x%02x)",
                         hdr->channel_id, hdr->flags);
                ch->state = CHANNEL_CLOSED;
                channel_destroy(ctx, ch);
            }
            return -1;
        }

        return 0;
    }

    /* ════════════════════════════════════════════════════════════════════════
     * 数据帧处理（核心数据路径）
     *
     * 处理流程：
     *   1. 哈希表查找通道
     *   2. 若为加密帧 → 栈缓冲区解密（与 recv_buf 分离，避免冲突）
     *   3. kcp_wrap_input → 将数据送入 KCP 进行重组/排序
     *   4. kcp_wrap_recv 循环 → 从 KCP 读取完整消息
     *   5. proxy_write_to_local → 写入本地套接字交付给应用
     *
     * SYN_RCVD 状态下收到首个数据帧 → 自动转为 ESTABLISHED
     * 本地写入失败 → 关闭本地连接 + 发送 FIN 通知对端
     * ════════════════════════════════════════════════════════════════════════ */
    if (IS_DATA_FRAME(hdr->flags)) {

        LOG_DEBUG("channel_process_frame: DATA (channel=%u, len=%zu, "
                  "flags=0x%02x)",
                  hdr->channel_id, payload_len, hdr->flags);

        /* 查找通道 */
        ch = channel_find(ctx, hdr->channel_id);
        if (!ch) {
            /*
             * T11-4: 未知通道帧速率限制 — 防止 DoS flood 消耗 CPU
             *
             * ┌──────────────────────────────────────────────────────────────┐
             * │ Token Bucket 速率限制器：                                     │
             * │                                                              │
             * │ 攻击者可能向不存在的 channel_id 发送大量数据帧，              │
             * │ 每次 channel_find 失败后都会执行 LOG_DEBUG + 返回 -1，       │
             * │ 高频率下 CPU 消耗不可忽略。                                   │
             * │                                                              │
             * │ 此 token bucket 限制每秒最多处理 UNKNOWN_FRAME_MAX_PER_SEC   │
             * │ 个未知通道帧。超过限制的帧被静默丢弃（diag_rx_unknown_dropped │
             * │ 计数器递增），不打印日志，不消耗额外 CPU。                    │
             * │                                                              │
             * │ Token 以 UNKNOWN_FRAME_MAX_PER_SEC/s 速率匀速补充。          │
             * │ Bucket 容量 = UNKNOWN_FRAME_MAX_PER_SEC（允许瞬时突发）。    │
             * │                                                              │
             * │ 使用 kcp_wrap_clock() 毫秒级时钟消除秒边界窗口。             │
             * └──────────────────────────────────────────────────────────────┘
             */
            {
                uint32_t now_ms = kcp_wrap_clock();
                uint32_t elapsed = now_ms - ctx->unknown_frame_ts;
                if (elapsed > 1000 || elapsed == 0 || ctx->unknown_frame_ts == 0) {
                    ctx->unknown_frame_tokens = UNKNOWN_FRAME_MAX_PER_SEC;
                    ctx->unknown_frame_ts = now_ms;
                } else {
                    uint32_t new_tokens = (elapsed * UNKNOWN_FRAME_MAX_PER_SEC) / 1000;
                    ctx->unknown_frame_tokens += new_tokens;
                    if (ctx->unknown_frame_tokens > UNKNOWN_FRAME_MAX_PER_SEC)
                        ctx->unknown_frame_tokens = UNKNOWN_FRAME_MAX_PER_SEC;
                    ctx->unknown_frame_ts = now_ms;
                }
                if (ctx->unknown_frame_tokens == 0) {
                    ctx->diag_rx_unknown_dropped++;
                    return -1;  /* 静默丢弃，不打印日志 */
                }
                ctx->unknown_frame_tokens--;
            }

            LOG_DEBUG("channel_process_frame: "
                      "late DATA for unknown channel %u, dropping",
                      hdr->channel_id);
            return -1;
        }

        /* CLOSED 僵尸通道：收到 DATA 时发送 RST 通知对端并销毁 */
        if (ch->state == CHANNEL_CLOSED) {
            channel_send_ctrl(ch, MPF_RST);
            LOG_INFO("channel_process_frame: RST sent for CLOSED zombie channel %u",
                     hdr->channel_id);
            channel_destroy(ctx, ch);
            return -1;
        }

        /*
         * 更新对端活跃时间（数据帧也算活跃）
         */
        ch->last_peer_seen = now;

        /*
         * 使用栈缓冲区进行加解密，不使用 recv_buf。
         * recv_buf 仅用于 proxy_write_to_local /
         * proxy_handle_local_write 的待发送数据缓冲区，
         * 与 crypto 解密缓冲区职责分离，避免冲突。
         *
         * 解密帧存在"双重堆分配"：1) 此处 malloc decrypt_buf 用于解密；
         * 2) 解密后的明文通过 kcp_wrap_input() 进入 KCP，KCP 内部会再次
         * ikcp_alloc 拷贝到自己的段缓冲区。这是有意为之的设计：
         *   — 解密缓冲区是临时的、短生命周期，解密完成即可释放；
         *   — KCP 内部缓冲区需要长期持有（直到 ACK 或超时），生命周期不同；
         *   — 两者职责不同（crypto vs transport），合并会引入不必要的耦合。
         * 在正常 payload （≤1500 字节）下，每次数据帧产生约 3KB 临时堆开销，
         * 属于可接受范围。
         */
        {
            /* 堆分配避免 8KB 栈压力（与上层 64KB recv_buf/proxy_read_buf 叠加） */
            uint8_t       *decrypt_buf   = NULL;
            const uint8_t *kcp_input_data = payload;
            size_t         kcp_input_len  = payload_len;
            int            ret;

            /* 处理加密数据帧 */
            if (IS_CRYPTO_FRAME(hdr->flags)) {
                /* H2: 拒绝 payload_len==0 的加密帧, malloc(0) 行为未定义 */
                if (payload_len == 0) {
                    LOG_WARN("channel_process_frame: zero-payload crypto frame "
                             "(channel=%u)", hdr->channel_id);
                    ch->stats.rx_errors++;
                    return -1;
                }
                size_t decrypted_len = payload_len;

                if (payload_len > CHANNEL_RECV_BUF_SIZE) {
                    LOG_ERROR("channel_process_frame: "
                              "payload too large for crypto processing "
                              "(channel=%u, len=%zu, max=%d)",
                              hdr->channel_id, payload_len,
                              CHANNEL_RECV_BUF_SIZE);
                    ch->stats.crypto_errors++;
                    ch->stats.rx_errors++;
                    return -1;
                }

                decrypt_buf = malloc(payload_len);
                if (!decrypt_buf) {
                    LOG_ERROR("channel_process_frame: "
                              "malloc failed for decrypt buffer "
                              "(channel=%u, len=%zu)",
                              hdr->channel_id, payload_len);
                    ch->stats.rx_errors++;
                    return -1;
                }

                /*
                 * 复制 payload 到堆上的可写缓冲区，
                 * 并使用可变协议头副本，避免丢弃 const。
                 */
                memcpy(decrypt_buf, payload, payload_len);

                {
                    myproto_hdr_t mutable_hdr = *hdr;

                    ret = myproto_process_data_frame(&mutable_hdr,
                                                     decrypt_buf,
                                                     &decrypted_len);
                }

                if (ret != 0) {
                    LOG_ERROR("channel_process_frame: "
                              "crypto processing failed for channel %u",
                              hdr->channel_id);
                    ch->stats.crypto_errors++;
                    ch->stats.rx_errors++;
                    free(decrypt_buf);
                    return -1;
                }

                kcp_input_data = decrypt_buf;
                kcp_input_len  = decrypted_len;
            }

            /* 更新接收统计 */
            ch->stats.rx_frames++;
            ch->stats.rx_bytes += (uint64_t)kcp_input_len;

            /*
             * 将数据输入 KCP。
             * KCP 负责重组分片、排序和可靠交付。
             */
            ret = kcp_wrap_input(ch->kcp, kcp_input_data,
                                 (int)kcp_input_len);
            free(decrypt_buf);
            if (ret != 0) {
                LOG_ERROR("channel_process_frame: "
                          "kcp_wrap_input failed for channel %u (len=%zu)",
                          hdr->channel_id, kcp_input_len);
                ch->stats.rx_errors++;
                return -1;
            }

            /* SYN_RCVD → ESTABLISHED: KCP 成功接收首个数据段，连接确认 */
            if (ch->state == CHANNEL_SYN_RCVD) {
                ch->state = CHANNEL_ESTABLISHED;
                LOG_DEBUG("channel_process_frame: "
                          "channel %u SYN_RCVD → ESTABLISHED (first data)",
                          hdr->channel_id);
            }
        }

        /*
         * 从 KCP 读取重组后的数据并写入本地套接字。
         * KCP 可能通过多次 recv 调用交付多个完整消息。
         */
        {
            uint8_t kcp_buf[KCP_APP_RECV_BUF_SIZE];
            int     kcp_recv_len;

            while ((kcp_recv_len = kcp_wrap_recv(ch->kcp, kcp_buf,
                                                  (int)sizeof(kcp_buf))) > 0) {
                int write_ret;

                /*
                 * R8 审计修复：在从 KCP 取出数据前预检 recv_buf 剩余容量。
                 * 若 recv_buf 已接近上限（剩余空间不足一个 recv 块），
                 * 则暂停 recv，保留数据在 KCP 中，等待 EPOLLOUT 触发
                 * proxy_handle_local_write 排空缓冲区后继续。
                 * 避免从 KCP 取出数据后因 proxy_ensure_recv_buf 失败而
                 * 静默丢失数据 + 误关闭连接。
                 */
                {
                    int max_cap = (g_ctx && g_ctx->config.perf_proxy_recv_buf_max > 0)
                                  ? g_ctx->config.perf_proxy_recv_buf_max
                                  : PERF_PROXY_RECV_BUF_MAX;
                    if (ch->recv_buf_len > 0 &&
                        ch->recv_buf_len + (int)sizeof(kcp_buf) > max_cap) {
                        LOG_DEBUG("channel_process_frame: recv_buf near capacity "
                                  "(channel=%u, pending=%d, max=%d), "
                                  "pausing KCP recv",
                                  ch->channel_id, ch->recv_buf_len, max_cap);
                        break;
                    }
                }

                if (ch->local_fd < 0 &&
                    (ch->state == CHANNEL_FIN_SENT ||
                     ch->state == CHANNEL_FIN_RCVD ||
                     ch->state == CHANNEL_TIME_WAIT ||
                     ch->state == CHANNEL_CLOSED)) {
                    LOG_DEBUG("channel_process_frame: dropping late data "
                              "for closing channel %u (state=%d, len=%d)",
                              hdr->channel_id, ch->state, kcp_recv_len);
                    continue;
                }

                /* 管理通道数据路由 */
                if (ch->flags & CH_FLAG_MGMT_CHANNEL) {
                    mgmt_dispatch(ch, kcp_buf, kcp_recv_len);
                    continue;
                }

                /* HP-4: 业务插件 — 应用数据入站处理 */
                {
                    int plen = kcp_recv_len;
                    int ret  = plugin_invoke_app_data_in(ctx, ch, kcp_buf,
                                                          &plen, (int)sizeof(kcp_buf));
                    if (ret == PLUGIN_DROP) {
                        ch->stats.rx_dropped++;
                        continue;
                    }
                    /* 插件返回 OK 或 ERROR 后应用可能修改的 len，
                     * ERROR 也接受改写以简化边界情况处理 */
                    if (plen < 0 || plen > (int)sizeof(kcp_buf)) {
                        LOG_WARN("Plugin '%s': invalid len=%d (cap=%zu), dropping",
                                 "app_data_in", plen, sizeof(kcp_buf));
                        ch->stats.rx_errors++;
                        continue;
                    }
                    kcp_recv_len = plen;
                }

                write_ret = proxy_write_to_local(ch, kcp_buf, kcp_recv_len);
                if (write_ret == PROXY_WRITE_LOCAL_CLOSED) {
                    LOG_INFO("channel_process_frame: local peer closed "
                             "(channel=%u, len=%d), sending RST",
                             hdr->channel_id, kcp_recv_len);
                    proxy_close_local(ch);
                    if (channel_send_ctrl(ch, MPF_RST) < 0)
                        LOG_WARN("RST send failed for channel %u (local close)", ch->channel_id);
                    ch->state = CHANNEL_CLOSED;
                    channel_destroy(ctx, ch);
                    return 0;
                }
                if (write_ret < 0) {
                    LOG_ERROR("channel_process_frame: "
                              "proxy_write_to_local failed "
                              "(channel=%u, len=%d) — local connection lost, "
                              "initiating close",
                              hdr->channel_id, kcp_recv_len);

                    /*
                     * 本地连接断开了——关闭本地端，发送 FIN 通知对端，
                     * 然后进入 FIN_SENT 状态等待对端确认关闭。
                     */
                    proxy_close_local(ch);
                    channel_send_ctrl(ch, MPF_FIN);
                    /* 仅从活动状态进入 FIN_SENT，避免从 FIN_RCVD/TIME_WAIT 回退 */
                    if (ch->state == CHANNEL_ESTABLISHED ||
                        ch->state == CHANNEL_SYN_SENT ||
                        ch->state == CHANNEL_SYN_RCVD)
                        ch->state = CHANNEL_FIN_SENT;
                    ch->last_active = time_now();
                    return -1;
                }

                LOG_DEBUG("channel_process_frame: "
                          "delivered %d bytes to local (channel=%u)",
                          kcp_recv_len, hdr->channel_id);
            }

            if (kcp_recv_len < 0) {
                LOG_ERROR("channel_process_frame: "
                          "kcp_wrap_recv error for channel %u",
                          hdr->channel_id);
                ch->stats.rx_errors++;
                return -1;
            }
        }

        return 0;
    }

    /*
     * 既不是控制帧也不是数据帧——不应到达此处
     */
    LOG_ERROR("channel_process_frame: unknown frame type "
              "(channel=%u, flags=0x%02x)",
              hdr->channel_id, hdr->flags);
    return -1;
}

/*
 * channel_send_ctrl — 发送控制帧（SYN/FIN/RST/ACK/PING/PONG）
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ 控制帧发送流程：                                                      │
 * │                                                                      │
 * │ 1. myproto_build_ctrl_frame()  构建 MyProto 控制帧                    │
 * │    → 包含 channel_id + flags + CRC（若启用）                         │
 * │    → 输出到栈上的 frame_buf[MAX_FRAME_SIZE]                          │
 * │                                                                      │
 * │ 2. af_packet_send()            通过 AF_PACKET 原始套接字发送          │
 * │    → 携带 peer_mac / local_mac / ethertype                           │
 * │    → 直接写入链路层，绕过内核 TCP/IP 协议栈                           │
 * │                                                                      │
 * │ 3. 统计更新：                                                        │
 * │    → tx_frames++ / tx_bytes += frame_len                             │
 * │    → last_active = time_now()                                        │
 * │                                                                      │
 * │ 错误处理：发送失败时递增 tx_errors 计数器，返回 -1。                 │
 * │                                                                      │
 * │ 注意：本函数不执行通道状态检查，状态合法性由调用者保证。              │
 * │ 调用者（channel_process_frame / channel_timeout_check /               │
 * │ channel_heartbeat）在调用前已完成状态验证，                          │
 * │ 在此处重复检查会导致代码冗余和状态机不一致风险。                       │
 * └──────────────────────────────────────────────────────────────────────┘
 */
int channel_send_ctrl(channel_t *ch, uint8_t flags)
{
    uint8_t frame_buf[MAX_FRAME_SIZE];
    ssize_t frame_len;
    ssize_t sent;

    if (!ch) {
        LOG_ERROR("channel_send_ctrl: null ch pointer");
        return -1;
    }

    /* 构建 MyProto 控制帧 */
    frame_len = myproto_build_ctrl_frame(frame_buf, sizeof(frame_buf),
                                         ch->channel_id, flags, 0);
    if (frame_len < 0) {
        LOG_ERROR("channel_send_ctrl: myproto_build_ctrl_frame failed "
                  "(channel=%u, flags=0x%02x)", ch->channel_id, flags);
        ch->stats.tx_errors++;
        return -1;
    }

    /* 通过 AF_PACKET 发送 */
    sent = af_packet_send(ch->raw_sock, ch->ifindex,
                          ch->peer_mac, ch->local_mac,
                          ch->ethertype,
                          frame_buf, (size_t)frame_len);
    if (sent < 0) {
        LOG_ERROR("channel_send_ctrl: af_packet_send failed "
                  "(channel=%u, flags=0x%02x): %s",
                  ch->channel_id, flags, strerror(errno));
        ch->stats.tx_errors++;
        return -1;
    }

    /* 更新统计 */
    ch->stats.tx_frames++;
    ch->stats.tx_bytes += (uint64_t)frame_len;

    /* 更新最后活跃时间 */
    ch->last_active = time_now();

    LOG_DEBUG("channel_send_ctrl: sent (channel=%u, flags=0x%02x, "
              "frame_len=%zd)",
              ch->channel_id, flags, frame_len);

    return 0;
}

/*
 * channel_send_data — 发送数据帧（通过 KCP 可靠传输）
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ 数据发送路径（两阶段）：                                              │
 * │                                                                      │
 * │ 阶段 1（本函数）：                                                    │
 * │   数据通过 kcp_wrap_send() 送入 KCP 发送队列 → KCP 负责分段/排序     │
 * │                                                                      │
 * │ 阶段 2（kcp_output_cb 回调）：                                        │
 * │   KCP 在 flush/update 时将队列中的数据段通过 myproto_build_data_frame │
 * │   封装为 MyProto 数据帧 → af_packet_send 发送到对端                   │
 * │                                                                      │
 * │ 握手期数据排队：                                                      │
 * │   允许在 SYN_SENT 和 SYN_RCVD 状态下排队数据（如 SSH banner），      │
 * │   KCP 负责可靠交付，控制面 ACK/首个对端 DATA 完成状态推进。          │
 * │                                                                      │
 * │ 立即刷新（可选）：                                                    │
 * │   若 perf_kcp_immediate_flush 启用，数据入队后立即 kcp_wrap_flush，  │
 * │   避免高吞吐场景将大量 KCP 段攒到 10ms 周期后突发发送。              │
 * │                                                                      │
 * │ 注意：tx_frames/tx_bytes 统计在 kcp_output_cb（实际发送时）更新，   │
 * │ 而非在本函数中更新。                                                 │
 * └──────────────────────────────────────────────────────────────────────┘
 */
int channel_send_data(channel_t *ch, const uint8_t *data, size_t len)
{
    int ret;

    if (!ch) {
        LOG_ERROR("channel_send_data: null ch pointer");
        return -1;
    }
    if (!data) {
        LOG_ERROR("channel_send_data: null data pointer (channel=%u)",
                  ch->channel_id);
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    /*
     * 握手期允许排队数据：
     * - INITIATOR 在 SYN_SENT 时可能已经读到本地客户端首包（如 SSH banner）
     * - RESPONDER 在 SYN_RCVD 时可能已经读到后端服务首包
     * KCP 会负责可靠发送，控制面的 ACK/首个对端 DATA 会完成状态推进。
     */
    if (ch->state != CHANNEL_ESTABLISHED &&
        ch->state != CHANNEL_SYN_SENT &&
        ch->state != CHANNEL_SYN_RCVD) {
        LOG_ERROR("channel_send_data: channel %u cannot send data in state=%d",
                  ch->channel_id, ch->state);
        return -1;
    }

    /*
     * 数据通过 KCP 发送。
     * KCP 负责分段、排序和可靠交付。
     * 实际帧发送由 kcp_output_cb 处理。
     */
    /* H5: 防止 size_t→int 截断, KCP 内部使用 int 表示长度 */
    if (len > (size_t)INT_MAX) {
        LOG_ERROR("channel_send_data: len %zu exceeds INT_MAX", len);
        return -1;
    }
    ret = kcp_wrap_send(ch->kcp, data, (int)len);
    if (ret < 0) {
        LOG_ERROR("channel_send_data: kcp_wrap_send failed "
                  "(channel=%u, len=%zu)", ch->channel_id, len);
        return -1;
    }

    if (!g_ctx || g_ctx->config.perf_kcp_immediate_flush) {
        /*
         * 立即刷新，避免高吞吐场景将大量 KCP 段攒到 10ms 周期后突发发送。
         * 周期 update 仍负责 ACK、重传和超时驱动。
         */
        kcp_wrap_flush(ch->kcp, kcp_wrap_clock());
    }

    /* 更新最后活跃时间（数据入队即视为活跃） */
    ch->last_active = time_now();

    /*
     * 注意：此处不更新 tx_frames/tx_bytes 统计，
     * 因为这些统计在 kcp_output_cb 中由实际发送时更新。
     */

    LOG_DEBUG("channel_send_data: queued %d bytes into KCP (channel=%u)",
              ret, ch->channel_id);

    return 0;
}

/*
 * channel_heartbeat — 通道心跳机制（保持连接活跃）
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ 两级心跳策略：                                                        │
 * │                                                                      │
 * │ 第 1 级 — 全局心跳（channel_id=0xFFFF）：                             │
 * │   若距上次全局 PONG 响应在 heartbeat_interval 秒内 → 跳过逐通道心跳  │
 * │   否则发送全局 PING → 等待对端 PONG 响应                              │
 * │   目的：通过全局心跳快速确认对端存活，减少逐通道 PING 开销            │
 * │                                                                      │
 * │ 第 2 级 — 逐通道心跳（后备机制）：                                     │
 * │   仅当全局心跳失败时执行                                               │
 * │   遍历哈希表 → 对每个 ESTABLISHED 通道检查 last_active                │
 * │   → 超时 heartbeat_interval 则发送 PING                               │
 * │   目的：确保每个已建立的连接都有独立的存活确认                         │
 * │                                                                      │
 * │ 心跳间隔默认值：HEARTBEAT_INTERVAL（若配置为 0）                       │
 * │ 心跳仅在 ESTABLISHED 状态发送（SYN_SENT/SYN_RCVD 有独立重传机制）     │
 * └──────────────────────────────────────────────────────────────────────┘
 */
void channel_heartbeat(global_ctx_t *ctx)
{
    uint32_t   i;
    uint32_t   now;
    int        interval;
    int        global_hb_ok = 0;

    if (!ctx) {
        LOG_ERROR("channel_heartbeat: null ctx pointer");
        return;
    }

    now      = time_now();
    interval = ctx->config.heartbeat_interval;

    (void)now;  /* suppress unused warning when DEBUG is not defined */

    if (interval <= 0) {
        interval = HEARTBEAT_INTERVAL;
    }

    /*
     * 首先尝试全局心跳（channel_id=0xFFFF）。
     * 如果上一次全局心跳响应在 interval 秒内，则跳过发送。
     * 否则发送 PING，如果最近 interval 秒内收到过全局 PONG，
     * 则标记为成功，跳过逐通道心跳。
     */
    if (time_elapsed(ctx->last_global_heartbeat) < (uint32_t)interval) {
        /* 最近 interval 秒内收到过全局 PONG，对端存活确认 */
        global_hb_ok = 1;
    } else {
        /* 发送全局 PING，但不立即设置 global_hb_ok——
         * 等待对端回复 PONG 后由 channel_process_frame
         * 更新 last_global_heartbeat，下次心跳检查时生效。
         * 在此期间逐通道心跳作为后备继续工作。 */
        LOG_DEBUG("channel_heartbeat: sending global PING on channel 0x%04X "
                  "(now=%u, last_global=%u, elapsed=%u)",
                  HEARTBEAT_CH_ID, now, ctx->last_global_heartbeat,
                  time_elapsed(ctx->last_global_heartbeat));
        channel_send_heartbeat_ctrl(ctx, MPF_PING);
    }

    /*
     * 如果全局心跳已确认对端存活，跳过逐通道心跳。
     * 否则对每个 ESTABLISHED 通道单独发送 PING。
     */
    if (global_hb_ok) {
        LOG_DEBUG("channel_heartbeat: global heartbeat OK, skipping per-channel");
        return;
    }

    for (i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            /*
             * 仅对 ESTABLISHED 状态的通道发送心跳。
             * 保存 hash_next，防止 channel_send_ctrl 间接触发销毁。
             */
            channel_t *next = ch->hash_next;

            /* 跳过静态监听通道（不承载数据，不需心跳） */
            if (ch->flags & CH_FLAG_STATIC_LISTENER) {
                ch = next;
                continue;
            }

            if (ch->state == CHANNEL_ESTABLISHED) {
                if (time_elapsed(ch->last_active) >= (uint32_t)interval) {
                    LOG_DEBUG("channel_heartbeat: sending PING to channel %u "
                              "(last_active=%u, now=%u, elapsed=%u)",
                              ch->channel_id, ch->last_active, now,
                              time_elapsed(ch->last_active));

                    if (channel_send_ctrl(ch, MPF_PING) != 0) {
                        LOG_ERROR("channel_heartbeat: "
                                  "failed to send PING to channel %u",
                                  ch->channel_id);
                    }
                }
            }

            ch = next;
        }
    }
}

/*
 * channel_timeout_check — 通道超时检查（事件循环中定期调用）
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ 超时检查按照状态分层执行 5 项检查（按优先级排列）：                   │
 * │                                                                      │
 * │ 检查 0: CLOSED 僵尸通道清理                                           │
 * │   通道被创建但从未建立 → 立即销毁（无对端需通知）                     │
 * │                                                                      │
 * │ 检查 1: 心跳超时（ESTABLISHED）                                       │
 * │   last_peer_seen 超过 heartbeat_timeout → 发送 RST → 销毁通道        │
 * │                                                                      │
 * │ 检查 2: SYN 重传机制（SYN_SENT）                                     │
 * │   每 3 秒重传 SYN，超过 3 次 → 放弃 → 销毁通道                       │
 * │                                                                      │
 * │ 检查 3: SYN_RCVD 空闲超时                                             │
 * │   RESPONDER 在 SYN_RCVD 等待对端首个数据帧，超时 CHANNEL_IDLE_TIMEOUT │
 * │   (300s) → 发送 RST → 销毁通道（防止握手半完成的资源泄漏）           │
 * │                                                                      │
 * │ 检查 4: FIN_RCVD → TIME_WAIT 转换                                     │
 * │   收到 FIN 后立即转入 TIME_WAIT                                       │
 * │                                                                      │
 * │ 检查 5: TIME_WAIT 超时                                                │
 * │   等待 CHANNEL_GRACEFUL_TIMEOUT 秒 → 销毁通道（优雅关闭完成）        │
 * │                                                                      │
 * │ FIN_SENT 超时也在检查 1 路径处理（last_active 超时 → RST + 销毁）    │
 * │                                                                      │
 * │ STATIC_LISTENER 保护：静态监听通道不受超时机制约束，生命周期与进程一致│
 * └──────────────────────────────────────────────────────────────────────┘
 */
void channel_timeout_check(global_ctx_t *ctx)
{
    uint32_t   i;
    uint32_t   now;
    int        hb_timeout;

    if (!ctx) {
        LOG_ERROR("channel_timeout_check: null ctx pointer");
        return;
    }

    now        = time_now();
    hb_timeout = ctx->config.heartbeat_timeout;

    if (hb_timeout <= 0) {
        hb_timeout = HEARTBEAT_TIMEOUT;
    }

    for (i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            channel_t *next = ch->hash_next;

            /*
             * 跳过静态监听通道（STATIC_LISTENER）：
             *
             * 静态监听通道由配置文件定义，其生命周期与进程一致。
             * 它们不发送/接收数据，仅作为 accept() 的入口点，
             * 因此不受数据通道超时机制约束。
             *
             * 如果对 STATIC_LISTENER 应用心跳超时检查，会导致
             * 监听通道被误关闭，所有后续连接请求都将失败。
             */
            if (ch->flags & CH_FLAG_STATIC_LISTENER) {
                ch = next;
                continue;
            }

            /*
             * 检查 0: CLOSED 僵尸通道清理
             * 通道被创建但从未建立——立即销毁。
             */
            if (ch->state == CHANNEL_CLOSED) {
                LOG_WARN("channel_timeout_check: zombie CLOSED channel %u "
                         "detected, destroying", ch->channel_id);
                /* 通道从未建立对端连接，无需发送 RST */
                channel_destroy(ctx, ch);
                ch = next;
                continue;
            }

            /*
             * 检查 1: 心跳超时 / KCP dead_link 协同
             * 如果距最后一次收到对端数据超过 heartbeat_timeout 秒，
             * 且通道处于 ESTABLISHED 状态，则强制关闭。
             * FIN_SENT/FIN_RCVD 走优雅关闭超时路径。
             *
             * 同时检查 KCP 内部的 dead_link 状态：
             * KCP 重传次数超过 dead_link 阈值时会将 kcp->state 设为 -1，
             * MyProto 心跳超时需与此信号协同，避免重复等待已死链路。
             */
            if (ch->state == CHANNEL_ESTABLISHED) {
                int kcp_dead = (ch->kcp && ch->kcp->state == (IUINT32)-1);

                if (kcp_dead ||
                    time_elapsed(ch->last_peer_seen) >= (uint32_t)hb_timeout) {
                    LOG_ERROR("channel_timeout_check: "
                              "heartbeat timeout for channel %u "
                              "(last_peer_seen=%u, now=%u, elapsed=%u, "
                              "timeout=%d, kcp_dead=%d)",
                              ch->channel_id, ch->last_peer_seen, now,
                              time_elapsed(ch->last_peer_seen),
                              hb_timeout, kcp_dead);

                    /* 发送 RST 通知对端 */
                    channel_send_ctrl(ch, MPF_RST);

                    ch->state = CHANNEL_CLOSED;
                    channel_destroy(ctx, ch);

                    ch = next;
                    continue;
                }
            }

            if (ch->state == CHANNEL_FIN_SENT) {
                if (time_elapsed(ch->last_active) >=
                    (uint32_t)CHANNEL_GRACEFUL_TIMEOUT) {
                    LOG_INFO("channel_timeout_check: FIN_SENT timeout "
                             "for channel %u, destroying",
                             ch->channel_id);

                    channel_send_ctrl(ch, MPF_RST);
                    ch->state = CHANNEL_CLOSED;
                    channel_destroy(ctx, ch);

                    ch = next;
                    continue;
                }
            }

            /*
             * 检查 2: SYN 重传机制
             * 发起方在 SYN_SENT 状态，每 3 秒重传 SYN，
             * 重试次数超过 3 次则放弃。
             */
            if (ch->state == CHANNEL_SYN_SENT) {
                if (time_elapsed(ch->syn_sent_at) >= 3) {
                    ch->syn_retry_count++;

                    if (ch->syn_retry_count > 3) {
                        LOG_ERROR("channel_timeout_check: "
                                  "SYN retry exceeded for channel %u "
                                  "(retries=%u)",
                                  ch->channel_id, ch->syn_retry_count);

                        ch->state = CHANNEL_CLOSED;
                        channel_destroy(ctx, ch);

                        ch = next;
                        continue;
                    }

                    LOG_DEBUG("channel_timeout_check: "
                              "SYN retry %u for channel %u",
                              ch->syn_retry_count, ch->channel_id);

                    ch->syn_sent_at = now;
                    if (channel_send_ctrl(ch, MPF_SYN) != 0) {
                        LOG_ERROR("channel_timeout_check: "
                                  "SYN retry send failed for channel %u",
                                  ch->channel_id);
                    }
                }
            }

            /*
             * 检查 3: SYN_RCVD 空闲超时
             * RESPONDER 在 SYN_RCVD 状态下等待对端首个数据帧来完成握手。
             * 若对端在握手完成前崩溃/断连，该通道永远不会转入 ESTABLISHED，
             * 导致 KCP 实例和本地套接字永久泄漏。
             * 使用 CHANNEL_IDLE_TIMEOUT (300s) 作为兜底清理。
             */
            if (ch->state == CHANNEL_SYN_RCVD) {
                if (time_elapsed(ch->last_peer_seen) >=
                    (uint32_t)CHANNEL_IDLE_TIMEOUT) {
                    LOG_ERROR("channel_timeout_check: "
                              "SYN_RCVD idle timeout for channel %u "
                              "(last_peer_seen=%u, now=%u, elapsed=%u)",
                              ch->channel_id, ch->last_peer_seen, now,
                              time_elapsed(ch->last_peer_seen));

                    channel_send_ctrl(ch, MPF_RST);
                    ch->state = CHANNEL_CLOSED;
                    channel_destroy(ctx, ch);

                    ch = next;
                    continue;
                }
            }

            /*
             * 检查 4: FIN_RCVD → TIME_WAIT 转换
             * 收到 FIN 并回显 FIN 后，至少等待 2 秒再进入 TIME_WAIT，
             * 确保对端有足够时间收到我们回显的 FIN 并完成 FIN_SENT→TIME_WAIT 转换。
             * TIME_WAIT 阶段等待 CHANNEL_GRACEFUL_TIMEOUT 秒后彻底销毁。
             */
            if (ch->state == CHANNEL_FIN_RCVD) {
                if (time_elapsed(ch->fin_rcvd_at) < 2) {
                    /* 未满 2 秒最小延迟，继续等待 */
                    ch = next;
                    continue;
                }
                LOG_DEBUG("channel_timeout_check: "
                          "channel %u FIN_RCVD → TIME_WAIT",
                          ch->channel_id);

                ch->state       = CHANNEL_TIME_WAIT;
                ch->last_active = now;
            }

            /*
             * 检查 5: TIME_WAIT 超时
             * 优雅关闭后等待 CHANNEL_GRACEFUL_TIMEOUT 秒，然后彻底销毁。
             */
            if (ch->state == CHANNEL_TIME_WAIT) {
                if (time_elapsed(ch->last_active) >=
                    (uint32_t)CHANNEL_GRACEFUL_TIMEOUT) {
                    LOG_DEBUG("channel_timeout_check: "
                              "TIME_WAIT expired for channel %u, destroying",
                              ch->channel_id);

                    ch->state = CHANNEL_CLOSED;
                    channel_destroy(ctx, ch);

                    ch = next;
                    continue;
                }
            }

            ch = next;
        }
    }
}

/*
 * 更新所有通道的 KCP 实例
 *
 * 驱动 KCP 内部定时器，触发重传和确认处理。
 * 由主循环以固定间隔（KCP_UPDATE_INTERVAL ms）调用。
 */
void channel_kcp_update(global_ctx_t *ctx)
{
    uint32_t  i;
    IUINT32  current_ms;

    if (!ctx) {
        LOG_ERROR("channel_kcp_update: null ctx pointer");
        return;
    }

    current_ms = kcp_wrap_clock();

    for (i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            channel_t *next = ch->hash_next;

            if (ch->kcp) {
                kcp_wrap_update(ch->kcp, current_ms);
                proxy_update_kcp_backpressure(ctx, ch);
            }
            ch = next;
        }
    }
}

/*
 * 遍历所有通道
 *
 * 对哈希表中每个非 NULL 通道调用回调函数。
 * 回调期间通道可能被销毁，调用方需自行处理。
 */
void channel_foreach(global_ctx_t *ctx, channel_foreach_cb_t callback,
                     void *user_data)
{
    uint32_t i;

    if (!ctx) {
        LOG_ERROR("channel_foreach: null ctx pointer");
        return;
    }
    if (!callback) {
        LOG_ERROR("channel_foreach: null callback pointer");
        return;
    }

    for (i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            channel_t *next = ch->hash_next;

            callback(ch, user_data);

            ch = next;
        }
    }
}

/*
 * 获取活跃通道数
 */
int channel_count(global_ctx_t *ctx)
{
    if (!ctx) {
        LOG_ERROR("channel_count: null ctx pointer");
        return 0;
    }

    return ctx->channel_count;
}

/*
 * 比较通道配置是否变更（热重载检测）。
 *
 * 当配置文件被修改后，系统支持在不重启的情况下重新加载配置。
 * 此函数对比通道当前运行时参数与新配置，逐一检查五个关键字段：
 *   - listen_port：本地监听端口
 *   - remote_port：远端服务端口
 *   - listen_addr：本地监听地址
 *   - remote_addr：远端服务地址
 *   - is_tcp：传输协议类型（TCP=1, UDP=0）
 *
 * 任一字段不一致即视为配置变更，触发 channel_update_config 刷新。
 * 此机制实现了通道级别的增量配置热更新，避免全量重建。
 *
 * @return 1=有变更, 0=无变更
 */
int channel_config_changed(const channel_t *ch,
                           const channel_config_t *new_cfg)
{
    if (ch->listen_port != new_cfg->listen_port) return 1;
    if (ch->remote_port != new_cfg->remote_port) return 1;
    if (ch->source_port != new_cfg->source_port) return 1;
    if (strcmp(ch->listen_addr, new_cfg->listen_addr) != 0) return 1;
    if (strcmp(ch->remote_addr, new_cfg->remote_addr) != 0) return 1;
    if (ch->is_tcp != new_cfg->is_tcp) return 1;
    return 0;
}

/*
 * 将新配置写入通道对象（热重载执行函数）。
 *
 * 仅更新通道的应用层参数（端口、地址、协议类型），
 * 不触碰运行时状态（state、last_active 等）和 KCP 实例。
 * 这保证了配置热重载对正在传输的数据流无感知、无中断。
 *
 * 典型调用链：
 *   channel_config_changed() → 返回 1 → channel_update_config() → 完成热刷新
 */
void channel_update_config(channel_t *ch,
                           const channel_config_t *cfg)
{
    ch->listen_port = cfg->listen_port;
    ch->remote_port = cfg->remote_port;
    ch->source_port = cfg->source_port;
    strncpy(ch->listen_addr, cfg->listen_addr, MAX_LISTEN_ADDR - 1);
    ch->listen_addr[MAX_LISTEN_ADDR - 1] = '\0';
    strncpy(ch->remote_addr, cfg->remote_addr, MAX_REMOTE_ADDR - 1);
    ch->remote_addr[MAX_REMOTE_ADDR - 1] = '\0';
    ch->is_tcp = cfg->is_tcp;
}

/*
 * 关闭所有通道（优雅关闭）
 *
 * 对所有 ESTABLISHED 状态的通道发送 FIN，
 * 通知对端本端正在关闭，然后转换到 FIN_SENT 状态。
 */
void channel_close_all(global_ctx_t *ctx)
{
    uint32_t i;

    if (!ctx) {
        LOG_ERROR("channel_close_all: null ctx pointer");
        return;
    }

    LOG_DEBUG("channel_close_all: initiating graceful shutdown "
              "(count=%d)", ctx->channel_count);

    /*
     * 阶段一：排空所有 ESTABLISHED 通道的 KCP 发送队列。
     * 先 flush 再 update，确保在途数据优先于 FIN 发送，
     * 避免优雅关闭时丢弃未发送的 KCP 段。
     */
    for (int drain = 0; drain < 10; drain++) {
        int has_pending = 0;
        for (i = 0; i < ctx->channel_hash_size; i++) {
            channel_t *ch = ctx->channel_hash[i];
            while (ch) {
                channel_t *next = ch->hash_next;
                if (!(ch->flags & CH_FLAG_STATIC_LISTENER) &&
                    ch->role != CHANNEL_ROLE_LISTENER &&
                    ch->state == CHANNEL_ESTABLISHED &&
                    ch->kcp) {
                    kcp_wrap_flush(ch->kcp, kcp_wrap_clock());
                    if (kcp_wrap_has_pending(ch->kcp))
                        has_pending = 1;
                }
                ch = next;
            }
        }
        if (!has_pending) break;
        channel_kcp_update(ctx);
        /* shutdown 路径：忙等排空 KCP 发送队列，5ms 间隔可接受
         * （仅 channel_close_all 调用期间使用，非热路径） */
        usleep(5000);  /* 5ms */
    }

    /*
     * 阶段二：发送 FIN（或 RST）关闭所有通道。
     */
    for (i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            channel_t *next = ch->hash_next;

            if ((ch->flags & CH_FLAG_STATIC_LISTENER) ||
                ch->role == CHANNEL_ROLE_LISTENER) {
                ch = next;
                continue;
            }

            if (ch->state == CHANNEL_ESTABLISHED) {
                LOG_DEBUG("channel_close_all: sending FIN to channel %u",
                          ch->channel_id);

                if (channel_send_ctrl(ch, MPF_FIN) != 0) {
                    LOG_ERROR("channel_close_all: "
                              "failed to send FIN to channel %u",
                              ch->channel_id);
                }

                ch->state = CHANNEL_FIN_SENT;
                ch->last_active = time_now();
            } else if (ch->state == CHANNEL_SYN_SENT ||
                       ch->state == CHANNEL_SYN_RCVD) {
                channel_send_ctrl(ch, MPF_RST);
                ch->state = CHANNEL_CLOSED;
            }

            ch = next;
        }
    }

    LOG_DEBUG("channel_close_all: graceful shutdown complete");
}
