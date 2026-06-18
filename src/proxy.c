/*
 * proxy.c - 代理模块实现
 *
 * 负责本地 TCP/UDP 端口的监听、连接和数据桥接。
 * 支持frontend代理（监听本地→转发到远端）和backend代理（从 AF_PACKET 接收→连接本地服务）。
 *
 * 使用 edge-triggered epoll 进行高性能 I/O 事件处理。
 * 通过 ev.data.fd 存储文件描述符，proxy_find_channel_by_fd() 扫描哈希表查找通道。
 * TCP_NODELAY 确保低延迟，SO_REUSEADDR 支持快速重启。
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                      Proxy 代理架构概览                                   ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                          ║
 * ║   【Frontend 模式 — 面向客户端】                                          ║
 * ║                                                                          ║
 * ║   客户端 ──TCP/UDP──▶ [listen_fd] ──▶ KCP ──▶ AF_PACKET ──▶ 远端节点    ║
 * ║              connect     accept       编码     原始套接字                 ║
 * ║                                                                          ║
 * ║   数据流方向:                                                             ║
 * ║   客户端 → local_fd → proxy_handle_local_read() → channel_send_data()    ║
 * ║         → kcp_wrap_send() → kcp_output_cb() → af_packet_send()           ║
 * ║                                                                          ║
 * ║   【Backend 模式 — 面向服务端】                                           ║
 * ║                                                                          ║
 * ║   AF_PACKET ──▶ channel_process_frame() ──▶ KCP ──▶ local_fd ──▶ 本地服务║
 * ║   原始套接字     帧解析+解密               重组    connect    目标端口     ║
 * ║                                                                          ║
 * ║   数据流方向:                                                             ║
 * ║   AF_PACKET → channel_process_frame() → kcp_wrap_input()                 ║
 * ║            → kcp_wrap_recv() → proxy_write_to_local() → write()          ║
 * ║                                                                          ║
 * ║   【Epoll 事件循环】                                                      ║
 * ║                                                                          ║
 * ║   ┌──────────────────────────────────────────────────────────┐           ║
 * ║   │              epoll_wait(timeout=10ms)                     │           ║
 * ║   │                    │                                      │           ║
 * ║   │       ┌────────────┼────────────┐                        │           ║
 * ║   │       │            │            │                        │           ║
 * ║   │   raw_sock     listen_fd    local_fd                     │           ║
 * ║   │   (AF_PKT)    (新连接)    (数据I/O)                       │           ║
 * ║   │       │            │            │                        │           ║
 * ║   │   main.c      proxy_accept  proxy_handle_local_read      │           ║
 * ║   │   帧解析      (仅TCP)       proxy_handle_local_write     │           ║
 * ║   │       │            │            │                        │           ║
 * ║   │   channel_      创建新      EPOLLIN: 读取→KCP            │           ║
 * ║   │   process_      channel     EPOLLOUT: KCP→写入           │           ║
 * ║   │   frame                                                      │           ║
 * ║   └──────────────────────────────────────────────────────────┘           ║
 * ║                                                                          ║
 * ║   【IPv6 双栈支持】                                                       ║
 * ║   优先尝试 IPv6 (AF_INET6)，失败回退 IPv4 (AF_INET)。                     ║
 * ║   IPV6_V6ONLY=0 启用 IPv4 映射地址，实现双栈单套接字。                    ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "proxy.h"
#include "acl.h"
#include "channel.h"
#include "ikcp.h"
#include "kcp_wrap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* ============================================================================
 * 模块级常量
 * ============================================================================ */

/* 本地套接字读取栈缓冲区大小 */
#define PROXY_READ_BUF_SIZE     (64 * 1024)

/* KCP→本地套接字刷新时的栈缓冲区大小 */
#define PROXY_FLUSH_BUF_SIZE    (64 * 1024)

/* proxy_handle_local_read 已经关闭并释放动态通道 */
#define PROXY_LOCAL_READ_CLOSED (-2)

/* TCP read loop: 每次 epoll 通知最多读取次数，防止饥饿其他通道 */
#define MAX_READ_BURST 256

/* ============================================================================
 * 模块级静态变量
 * ============================================================================ */

/*
 * 全局上下文指针，在 proxy_init() 中设置。
 * 用于 proxy_connect_remote() 等不需要 ctx 参数的函数访问 epoll_fd。
 */

/* ============================================================================
 * 内部辅助函数（前向声明）
 * ============================================================================ */
static void proxy_set_tcp_sockbuf(int fd)
{
    int val = (g_ctx && g_ctx->config.perf_proxy_tcp_sockbuf > 0)
                  ? g_ctx->config.perf_proxy_tcp_sockbuf
                  : PERF_PROXY_TCP_SOCKBUF;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val)) < 0) {
        LOG_WARN("proxy_set_tcp_sockbuf: setsockopt(SO_RCVBUF) failed "
                 "(fd=%d, size=%d): %s", fd, val, strerror(errno));
    }

    val = (g_ctx && g_ctx->config.perf_proxy_tcp_sockbuf > 0)
              ? g_ctx->config.perf_proxy_tcp_sockbuf
              : PERF_PROXY_TCP_SOCKBUF;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)) < 0) {
        LOG_WARN("proxy_set_tcp_sockbuf: setsockopt(SO_SNDBUF) failed "
                 "(fd=%d, size=%d): %s", fd, val, strerror(errno));
    }
}

static int proxy_epoll_mod_events(global_ctx_t *ctx, int fd,
                                  void *ptr, uint32_t events);

static int proxy_recv_buf_max(void)
{
    if (g_ctx && g_ctx->config.perf_proxy_recv_buf_max > 0) {
        return g_ctx->config.perf_proxy_recv_buf_max;
    }
    return PERF_PROXY_RECV_BUF_MAX;
}

static int proxy_close_read_side(global_ctx_t *ctx, channel_t *ch,
                                 const char *reason)
{
    if (!ch) {
        return PROXY_LOCAL_READ_CLOSED;
    }

    LOG_INFO("proxy_handle_local_read: %s (channel=%u), closing session",
             reason ? reason : "local read side closed", ch->channel_id);

    proxy_close_local(ch);
    channel_send_ctrl(ch, MPF_RST);
    ch->state = CHANNEL_CLOSED;
    if (ctx && !(ch->flags & CH_FLAG_STATIC_LISTENER)) {
        channel_destroy(ctx, ch);
    }

    return PROXY_LOCAL_READ_CLOSED;
}

static int proxy_refresh_local_events(global_ctx_t *ctx, channel_t *ch)
{
    if (!ctx || !ch || ch->local_fd < 0) {
        return 0;
    }

    return proxy_epoll_mod_events(ctx, ch->local_fd, ch, proxy_get_events(ch));
}

static int proxy_finish_async_connect(channel_t *ch)
{
    int       so_err = 0;
    socklen_t so_len = sizeof(so_err);

    if (!ch) {
        return -1;
    }

    if (!ch->connect_pending) {
        return 0;
    }

    if (getsockopt(ch->local_fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) < 0) {
        LOG_ERROR("proxy_finish_async_connect: getsockopt(SO_ERROR) failed "
                  "(fd=%d, channel=%u): %s",
                  ch->local_fd, ch->channel_id, strerror(errno));
        return -1;
    }

    if (so_err != 0) {
        if (so_err == ECONNREFUSED ||
            so_err == EHOSTUNREACH ||
            so_err == ENETUNREACH ||
            so_err == ETIMEDOUT) {
            LOG_DEBUG("proxy_finish_async_connect: expected connect failure "
                      "(fd=%d, channel=%u): %s",
                      ch->local_fd, ch->channel_id, strerror(so_err));
        } else {
            LOG_INFO("proxy_finish_async_connect: async connect failed "
                     "(fd=%d, channel=%u): %s",
                     ch->local_fd, ch->channel_id, strerror(so_err));
        }
        errno = so_err;
        return -1;
    }

    ch->connect_pending = 0;
    LOG_DEBUG("proxy_finish_async_connect: async connect completed "
              "(fd=%d, channel=%u)",
              ch->local_fd, ch->channel_id);
    return 0;
}

/*
 * 查找 local_fd 或 listen_fd 匹配的通道。
 * 扫描哈希表 - O(n)，但 n ≤ MAX_CHANNELS (256)，实际使用中开销可忽略。
 */
static channel_t *proxy_find_channel_by_fd(global_ctx_t *ctx, int fd)
{
    uint32_t i;

    if (!ctx || fd < 0) {
        return NULL;
    }

    for (i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            if (ch->local_fd == fd || ch->listen_fd == fd) {
                return ch;
            }
            ch = ch->hash_next;
        }
    }

    return NULL;
}

/*
 * 修改 epoll 注册事件掩码（用于动态切换 EPOLLOUT）。
 * 在 edge-triggered 模式下，当 recv_buf 有待发送数据时，
 * 需要确保 EPOLLOUT 已注册以接收可写通知。
 */
static int proxy_epoll_mod_events(global_ctx_t *ctx, int fd,
                                  void *ptr, uint32_t events)
{
    struct epoll_event ev;

    (void)ptr;  /* 已改用 data.fd 存储 fd，ptr 保留兼容 */
    memset(&ev, 0, sizeof(ev));
    ev.events   = events;
    ev.data.fd  = fd;

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        LOG_ERROR("proxy_epoll_mod_events: epoll_ctl(EPOLL_CTL_MOD, fd=%d, "
                  "events=0x%x) failed: %s", fd, events, strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * 确保 local_fd 的 epoll 注册包含 EPOLLOUT。
 * 当 recv_buf 中新增了待发送数据时调用。
 */
static int proxy_ensure_epollout(global_ctx_t *ctx, channel_t *ch)
{
    uint32_t events;

    if (!ctx || !ch || ch->local_fd < 0) {
        return -1;
    }

    events = proxy_get_events(ch);
    return proxy_epoll_mod_events(ctx, ch->local_fd, ch, events);
}

static int proxy_ensure_recv_buf(channel_t *ch, int needed)
{
    int      new_cap;
    int      max_cap;
    uint8_t *new_buf;

    if (!ch || needed < 0) {
        return -1;
    }

    if (needed <= ch->recv_buf_cap) {
        return 0;
    }

    max_cap = proxy_recv_buf_max();
    if (needed > max_cap) {
        LOG_ERROR("proxy_ensure_recv_buf: pending buffer too large "
                  "(channel=%u, needed=%d, max=%d)",
                  ch->channel_id, needed, max_cap);
        return -1;
    }

    new_cap = ch->recv_buf_cap > 0 ? ch->recv_buf_cap : CHANNEL_RECV_BUF_SIZE;
    while (new_cap < needed) {
        if (new_cap > INT_MAX / 2 || new_cap > max_cap / 2) {
            new_cap = max_cap;
        } else {
            new_cap *= 2;
        }
    }

    new_buf = realloc(ch->recv_buf, (size_t)new_cap);
    if (!new_buf) {
        LOG_ERROR("proxy_ensure_recv_buf: realloc(%d) failed (channel=%u)",
                  new_cap, ch->channel_id);
        return -1;
    }

    ch->recv_buf = new_buf;
    ch->recv_buf_cap = new_cap;
    return 0;
}

/* ============================================================================
 * 公共 API 实现
 * ============================================================================ */

/*
 * 解析地址字符串并填充 sockaddr_storage。
 * 优先尝试 IPv6，然后回退到 IPv4。
 * 返回 AF_INET、AF_INET6，失败返回 -1。
 */
static int resolve_addr(const char *addr_str, uint16_t port,
                        struct sockaddr_storage *out_addr, socklen_t *out_len)
{
    memset(out_addr, 0, sizeof(*out_addr));

    /* 尝试 IPv6 */
    {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)out_addr;
        if (inet_pton(AF_INET6, addr_str, &in6->sin6_addr) == 1) {
            in6->sin6_family = AF_INET6;
            in6->sin6_port = htons(port);
            *out_len = sizeof(*in6);
            return AF_INET6;
        }
    }

    /* 回退到 IPv4 */
    {
        struct sockaddr_in *in4 = (struct sockaddr_in *)out_addr;
        if (inet_pton(AF_INET, addr_str, &in4->sin_addr) == 1) {
            in4->sin_family = AF_INET;
            in4->sin_port = htons(port);
            *out_len = sizeof(*in4);
            return AF_INET;
        }
    }

    return -1;
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_init — 初始化代理子系统
 *
 * 在 main() 启动阶段调用一次，是整个代理模块的生命周期入口。
 *
 * 初始化步骤:
 *   1. 保存全局上下文指针 g_ctx ← ctx
 *      目的: proxy_connect_remote() 等函数签名不携带 ctx 参数，
 *      通过模块级变量 g_ctx 间接访问 epoll_fd 等全局资源。
 *   2. 创建 epoll 实例 (epoll_create1 with EPOLL_CLOEXEC)
 *      EPOLL_CLOEXEC: exec() 时自动关闭 epoll fd，防止子进程继承。
 *      epoll 是整个事件循环的核心，后续所有本地套接字和 AF_PACKET 套接字
 *      都注册到这个 epoll 实例上。
 *
 * 调用时机: main() → proxy_init() → (初始化 epoll) → 创建通道 → 注册 fd
 * ────────────────────────────────────────────────────────────────────────── */
int proxy_init(global_ctx_t *ctx)
{
    if (!ctx) {
        LOG_ERROR("proxy_init: null context");
        return -1;
    }

    /* 保存全局上下文（供 proxy_connect_remote 使用）。
     * ── 生命周期依赖 ──
     * g_ctx 由 main.c 定义。proxy_init() 先于 channel_init() 调用，
     * channel 和 proxy 共享同一个 global_ctx_t 指针；
     * proxy_shutdown() 在 channel_shutdown() 之后调用（main.c 保证顺序）。 */
    g_ctx = ctx;

    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd < 0) {
        LOG_ERROR("proxy_init: epoll_create1 failed: %s", strerror(errno));
        return -1;
    }

    LOG_DEBUG("proxy_init: epoll_fd=%d created", ctx->epoll_fd);
    return 0;
}

/*
 * 关闭代理子系统
 */
void proxy_shutdown(global_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->epoll_fd >= 0) {
        LOG_DEBUG("proxy_shutdown: closing epoll_fd=%d", ctx->epoll_fd);
        close(ctx->epoll_fd);
        ctx->epoll_fd = -1;
    }

    g_ctx = NULL;
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_start_listen — 为通道创建监听套接字并注册到 epoll
 *
 * 这是代理子系统最核心的初始化函数之一，支持 TCP/UDP 双协议栈。
 *
 * TCP 路径:
 *   socket(SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC)
 *   → setsockopt(IPV6_V6ONLY=0)  启用 IPv4/IPv6 双栈
 *   → setsockopt(SO_REUSEADDR)   允许快速重启立即绑定端口
 *   → bind(listen_addr:port)     绑定监听地址
 *   → listen(fd, SOMAXCONN)      开始监听，backlog=系统最大值
 *   → epoll_ctl(ADD, EPOLLIN)    level-triggered 模式注册监听
 *     监听套接字使用 level-triggered (非 EPOLLET): 防止高并发下
 *     多个连接同时到达时丢失连接通知。
 *
 * UDP 路径:
 *   socket(SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC)
 *   → setsockopt(IPV6_V6ONLY=0, SO_REUSEADDR)
 *   → bind(listen_addr:port)
 *   → proxy_epoll_add(EPOLLIN|EPOLLET)  edge-triggered
 *     UDP 无连接概念，listen_fd ≡ local_fd (同一个套接字)，
 *     后续数据收发直接复用此 fd。
 *
 * IPv6 双栈支持:
 *   resolve_addr() 优先尝试 IPv6 (AF_INET6)，失败回退 IPv4 (AF_INET)。
 *   设置 IPV6_V6ONLY=0 后，IPv6 套接字可以接收 IPv4 映射地址的连接，
 *   实现单套接字同时处理 IPv4/IPv6 流量。
 * ────────────────────────────────────────────────────────────────────────── */
int proxy_start_listen(global_ctx_t *ctx, channel_t *ch)
{
    int                     fd;
    int                     optval;
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    int                     family;
    struct epoll_event      ev;

    if (!ctx || !ch) {
        LOG_ERROR("proxy_start_listen: null pointer");
        return -1;
    }

    family = resolve_addr(ch->listen_addr, ch->listen_port, &addr, &addr_len);
    if (family < 0) {
        LOG_ERROR("proxy_start_listen: invalid listen address '%s'", ch->listen_addr);
        return -1;
    }

    if (ch->is_tcp) {
        /* ---- TCP 监听套接字 ---- */
        fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            LOG_ERROR("proxy_start_listen: socket(TCP) failed: %s",
                      strerror(errno));
            return -1;
        }

        /* 启用 IPv6 双栈（IPv4 映射地址） */
        if (family == AF_INET6) {
            int no = 0;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) < 0) {
                LOG_WARN("proxy_start_listen: IPV6_V6ONLY=0 failed: %s", strerror(errno));
            }
        }

        /* SO_REUSEADDR: 允许快速重启时立即绑定端口 */
        optval = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_start_listen: setsockopt(SO_REUSEADDR) failed: %s",
                      strerror(errno));
            close(fd);
            return -1;
        }

        /* 绑定到监听地址和端口 */
        if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
            LOG_ERROR("proxy_start_listen: bind(%s:%u) failed: %s",
                      ch->listen_addr, ch->listen_port, strerror(errno));
            close(fd);
            return -1;
        }

        /* 开始监听 */
        if (listen(fd, SOMAXCONN) < 0) {
            LOG_ERROR("proxy_start_listen: listen() failed: %s",
                      strerror(errno));
            close(fd);
            return -1;
        }

        ch->listen_fd = fd;
        ch->local_fd  = -1;

        /*
         * 监听套接字使用 level-triggered (EPOLLIN)，
         * 确保不会因 edge-triggered 而在高并发下丢失连接。
         */
        memset(&ev, 0, sizeof(ev));
        ev.events   = EPOLLIN;
        ev.data.fd  = fd;
        if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            LOG_ERROR("proxy_start_listen: epoll_ctl(ADD, listen_fd=%d) "
                      "failed: %s", fd, strerror(errno));
            close(fd);
            ch->listen_fd = -1;
            return -1;
        }

        LOG_INFO("proxy_start_listen: TCP listening on %s:%u "
                 "(fd=%d, channel=%u, family=AF_INET%s)",
                 ch->listen_addr, ch->listen_port, fd, ch->channel_id,
                 (family == AF_INET6) ? "6" : "");

    } else {
        /* ---- UDP 套接字 ---- */
        fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            LOG_ERROR("proxy_start_listen: socket(UDP) failed: %s",
                      strerror(errno));
            return -1;
        }

        /* 启用 IPv6 双栈 */
        if (family == AF_INET6) {
            int no = 0;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) < 0) {
                LOG_WARN("proxy_start_listen: IPV6_V6ONLY=0 failed: %s", strerror(errno));
            }
        }

        /* SO_REUSEADDR */
        optval = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_start_listen: setsockopt(SO_REUSEADDR) "
                      "failed: %s", strerror(errno));
            close(fd);
            return -1;
        }

        /* 绑定 */
        if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
            LOG_ERROR("proxy_start_listen: bind(%s:%u) failed: %s",
                      ch->listen_addr, ch->listen_port, strerror(errno));
            close(fd);
            return -1;
        }

        /*
         * UDP 是无连接的：listen_fd 和 local_fd 指向同一个套接字。
         */
        ch->listen_fd = fd;
        ch->local_fd  = fd;

        /* 添加到 epoll（edge-triggered 用于 local I/O） */
        if (proxy_epoll_add(ctx, fd, ch) < 0) {
            close(fd);
            ch->listen_fd = -1;
            ch->local_fd  = -1;
            return -1;
        }

        LOG_INFO("proxy_start_listen: UDP bound to %s:%u "
                 "(fd=%d, channel=%u, family=AF_INET%s)",
                 ch->listen_addr, ch->listen_port, fd, ch->channel_id,
                 (family == AF_INET6) ? "6" : "");
    }

    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_accept — 接受监听套接字上的新 TCP 连接
 *
 * 两阶段 accept 循环（兼容 edge-triggered epoll）：
 *   1. accept4() 循环直到 EAGAIN，一次性消费所有待处理连接。
 *   2. 设置 TCP_NODELAY（禁用 Nagle）+ SO_KEEPALIVE（检测死连接）。
 *
 * 多会话模式 (STATIC_LISTENER + max_sessions >= 1)：
 *   - 通过 alloc_channel_id() 分配新的动态 channel_id
 *   - channel_create() 创建新的动态通道（INITIATOR 角色）
 *   - 复制网络层信息（raw_sock, ifindex, ethertype, local/peer MAC）
 *   - 将 client_fd 注册到 epoll 并返回继续 accept
 *
 * 单会话模式（默认/fallback）：
 *   - 将 client_fd 直接绑定到当前通道 ch->local_fd
 *   - 若通道已有活跃连接则关闭多余连接（每通道同一时间只服务一个客户端）
 * ────────────────────────────────────────────────────────────────────────── */
int proxy_accept(global_ctx_t *ctx, channel_t *ch)
{
    int client_fd;
    int optval;

    if (!ctx || !ch) {
        LOG_ERROR("proxy_accept: null pointer");
        return -1;
    }

    if (!ch->is_tcp) {
        LOG_ERROR("proxy_accept: called on non-TCP channel %u",
                  ch->channel_id);
        return -1;
    }

    if (ch->listen_fd < 0) {
        LOG_ERROR("proxy_accept: invalid listen_fd for channel %u",
                  ch->channel_id);
        return -1;
    }

    /*
     * 在循环中 accept，以兼容 edge-triggered epoll。
     * 一次 epoll 通知可能对应多个待处理连接。
     */
    while (1) {
        client_fd = accept4(ch->listen_fd, NULL, NULL,
                            SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* 所有待处理连接均已接受 */
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EMFILE || errno == ENFILE) {
                LOG_WARN("proxy_accept: FD limit reached, pausing accept");
                break;  /* 下次 epoll 事件再试，避免 busy-poll */
            }
            LOG_ERROR("proxy_accept: accept4() failed: %s", strerror(errno));
            return -1;
        }

        /* ── ACL 检查（仅 STATIC_LISTENER 通道）── */
        if (ch->flags & CH_FLAG_STATIC_LISTENER) {
            struct sockaddr_storage peer_addr;
            socklen_t peer_len = sizeof(peer_addr);

            if (getpeername(client_fd, (struct sockaddr *)&peer_addr,
                            &peer_len) == 0) {
                uint32_t ip;
                uint16_t port;
                if (extract_ip_port(&peer_addr, &ip, &port)) {
                    channel_acl_t *acl =
                        &ctx->config.channels[ch->listener_idx].client_acl;
                    if (!acl_check(acl, ip, port)) {
                        LOG_DEBUG("proxy_accept: ACL rejected ch=%u",
                                  ch->channel_id);
                        close(client_fd);
                        continue;
                    }
                }
            }
        }

        /*
         * 如果该通道已有活跃连接，关闭多余的新连接。
         * 每个通道同一时间只服务一个客户端。
         */
        if (ch->local_fd >= 0) {
            LOG_WARN("proxy_accept: channel %u busy (local_fd=%d), "
                     "closing extra connection fd=%d",
                     ch->channel_id, ch->local_fd, client_fd);
            close(client_fd);
            continue;
        }

        /* TCP_NODELAY: 禁用 Nagle 算法，确保低延迟 */
        optval = 1;
        if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_accept: setsockopt(TCP_NODELAY) failed: %s",
                      strerror(errno));
            close(client_fd);
            return -1;
        }
        /* 设置 TCP 套接字缓冲区大小（SO_RCVBUF/SO_SNDBUF）。
         * 两路径均已覆盖：此处为 accept 路径，proxy_connect_remote()
         * 在 connect 路径也调用 proxy_set_tcp_sockbuf()。 */
        proxy_set_tcp_sockbuf(client_fd);

        /* SO_KEEPALIVE: 检测死连接 */
        optval = 1;
        if (setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_accept: setsockopt(SO_KEEPALIVE) failed: %s",
                      strerror(errno));
            close(client_fd);
            return -1;
        }

        /*
         * 多会话模式：listener 标志 + max_sessions>=1 → 创建动态通道。
         * max_sessions=1 也使用动态通道，保持架构一致性：
         * listener 仅负责 accept，数据始终通过动态通道传输。
         */
        if ((ch->flags & CH_FLAG_STATIC_LISTENER) &&
            ch->listener_idx < ctx->config.channel_count &&
            ctx->config.channels[ch->listener_idx].max_sessions >= 1) {

            uint32_t new_id = alloc_channel_id(ctx, ch->listener_idx);
            if (new_id == 0) {
                LOG_WARN("proxy_accept: channel ID exhausted for listener %u",
                         ch->channel_id);
                close(client_fd);
                continue;
            }

            channel_t *new_ch = channel_create(ctx, new_id,
                                CHANNEL_ROLE_INITIATOR,
                                ch->listen_port, ch->remote_port, 0,
                                ch->listen_addr, ch->remote_addr,
                                ch->is_tcp);
            if (!new_ch) {
                close(client_fd);
                continue;
            }

            new_ch->raw_sock  = ch->raw_sock;
            new_ch->ifindex   = ch->ifindex;
            new_ch->ethertype = ch->ethertype;
            memcpy(new_ch->local_mac, ch->local_mac, ETH_MAC_ADDR_LEN);
            memcpy(new_ch->peer_mac,  ch->peer_mac,  ETH_MAC_ADDR_LEN);

            new_ch->local_fd = client_fd;
            if (proxy_epoll_add(ctx, client_fd, new_ch) < 0) {
                channel_destroy(ctx, new_ch);
                continue;
            }

            LOG_INFO("proxy_accept: new session chan=%u fd=%d (listener=%u)",
                     new_id, client_fd, ch->channel_id);
        } else {
            /* 单会话模式 */
            if (ch->local_fd >= 0) {
                LOG_WARN("proxy_accept: channel %u busy (local_fd=%d), "
                         "closing extra connection fd=%d",
                         ch->channel_id, ch->local_fd, client_fd);
                close(client_fd);
                continue;
            }

            ch->local_fd = client_fd;

            /* 添加到 epoll（edge-triggered 用于高性能数据收发） */
            if (proxy_epoll_add(ctx, client_fd, ch) < 0) {
                close(client_fd);
                ch->local_fd = -1;
                return -1;
            }

            LOG_INFO("proxy_accept: accepted connection fd=%d on channel %u "
                     "(listen_fd=%d)", client_fd, ch->channel_id, ch->listen_fd);

            return client_fd;
        }
    }

    /* 无新连接（EAGAIN），返回 -1 表示本次无连接 */
    return -1;
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_connect_remote — 连接到远端服务（backend 代理模式）
 *
 * 使用场景：backend 节点从 AF_PACKET 收到帧后，需要将数据转发到本地服务。
 *
 * 连接流程：
 *   1. resolve_addr() — 解析远端地址，优先 IPv6 回退 IPv4
 *   2. socket() — 创建非阻塞 TCP/UDP 套接字 (SOCK_NONBLOCK|SOCK_CLOEXEC)
 *   3. setsockopt(TCP_NODELAY) — 禁用 Nagle 算法确保低延迟（仅 TCP）
 *   4. 关闭旧 local_fd — 若通道已有旧连接，先从 epoll 移除并关闭
 *   5. connect() — 非阻塞连接，TCP 可能返回 EINPROGRESS
 *   6. epoll_ctl(ADD, EPOLLIN|EPOLLOUT|EPOLLET) — 加入 epoll 监控
 *      包含 EPOLLOUT：对于 TCP，connect 返回 EINPROGRESS 时，连接完成
 *      表现为套接字可写；对于 UDP，sendto 立即可用。
 *
 * 返回值：成功返回 fd, 失败返回 -1
 * ────────────────────────────────────────────────────────────────────────── */
int proxy_connect_remote(channel_t *ch)
{
    int                     fd;
    int                     optval;
    int                     ret;
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    int                     family;
    struct epoll_event      ev;
    global_ctx_t           *ctx;

    if (!ch) {
        LOG_ERROR("proxy_connect_remote: null channel");
        return -1;
    }

    ctx = g_ctx;
    if (!ctx || ctx->epoll_fd < 0) {
        LOG_ERROR("proxy_connect_remote: proxy not initialized");
        return -1;
    }

    family = resolve_addr(ch->remote_addr, ch->remote_port, &addr, &addr_len);
    if (family < 0) {
        LOG_ERROR("proxy_connect_remote: invalid remote_addr '%s' "
                  "(channel=%u)", ch->remote_addr, ch->channel_id);
        return -1;
    }

    /* 创建非阻塞套接字 */
    if (ch->is_tcp) {
        fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    } else {
        fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    }

    if (fd < 0) {
        LOG_ERROR("proxy_connect_remote: socket() failed: %s",
                  strerror(errno));
        return -1;
    }

    /* TCP_NODELAY */
    if (ch->is_tcp) {
        optval = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_connect_remote: setsockopt(TCP_NODELAY) "
                      "failed: %s", strerror(errno));
            close(fd);
            return -1;
        }
        proxy_set_tcp_sockbuf(fd);
    }

    /* 关闭旧的 local_fd（如果存在） */
    if (ch->local_fd >= 0) {
        LOG_WARN("proxy_connect_remote: closing old local_fd=%d "
                 "(channel=%u)", ch->local_fd, ch->channel_id);
        proxy_epoll_del(ctx, ch->local_fd);
        close(ch->local_fd);
    }

    /* 绑定源端口（若配置） */
    if (ch->source_port > 0) {
        optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        struct sockaddr_storage local_addr;
        socklen_t               local_addr_len = 0;
        memset(&local_addr, 0, sizeof(local_addr));
        if (family == AF_INET6) {
            struct sockaddr_in6 *l6 = (struct sockaddr_in6 *)&local_addr;
            l6->sin6_family = AF_INET6;
            l6->sin6_port   = htons(ch->source_port);
            local_addr_len  = sizeof(struct sockaddr_in6);
        } else {
            struct sockaddr_in *l4 = (struct sockaddr_in *)&local_addr;
            l4->sin_family      = AF_INET;
            l4->sin_port        = htons(ch->source_port);
            l4->sin_addr.s_addr = INADDR_ANY;
            local_addr_len      = sizeof(struct sockaddr_in);
        }
        if (bind(fd, (struct sockaddr *)&local_addr, local_addr_len) < 0) {
            LOG_ERROR("proxy_connect_remote: bind(src_port=%u) failed: %s",
                      ch->source_port, strerror(errno));
            close(fd);
            return -1;
        }
    }

    /* 非阻塞 connect */
    ret = connect(fd, (struct sockaddr *)&addr, addr_len);
    if (ret < 0 && errno != EINPROGRESS) {
        LOG_ERROR("proxy_connect_remote: connect(%s:%u) failed: %s",
                  ch->remote_addr, ch->remote_port, strerror(errno));
        close(fd);
        return -1;
    }

    ch->local_fd = fd;

    /*
     * 添加到 epoll。
     * 包含 EPOLLOUT：backend连接建立后，通过 EPOLLOUT 事件确认连接就绪。
     * 对于 TCP，connect 返回 EINPROGRESS 时，连接完成表现为套接字可写。
     */
    memset(&ev, 0, sizeof(ev));
    ev.events   = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd  = fd;
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERROR("proxy_connect_remote: epoll_ctl(ADD, fd=%d) failed: %s",
                  fd, strerror(errno));
        close(fd);
        ch->local_fd = -1;
        return -1;
    }

    if (ret == 0) {
        /* 本地连接立即成功（UDP 或同主机 TCP） */
        LOG_INFO("proxy_connect_remote: connected to %s:%u "
                 "(fd=%d, channel=%u, immediate)",
                 ch->remote_addr, ch->remote_port, fd, ch->channel_id);
        ch->connect_pending = 0;
    } else {
        /* 异步连接进行中 → 标志等待第一次 EPOLLOUT 时检查 SO_ERROR */
        LOG_INFO("proxy_connect_remote: connecting to %s:%u "
                 "(fd=%d, channel=%u, in progress)",
                 ch->remote_addr, ch->remote_port, fd, ch->channel_id);
        ch->connect_pending = 1;
    }

    return fd;
}

/*
 * 处理本地套接字的可读事件（应用→KCP 方向）
 */
int proxy_handle_local_read(global_ctx_t *ctx, channel_t *ch)
{
    static uint8_t buf[PROXY_READ_BUF_SIZE];
    ssize_t         n;
    size_t          total_read = 0;

    if (!ctx || !ch) {
        LOG_ERROR("proxy_handle_local_read: null pointer");
        return -1;
    }

    if (ch->local_fd < 0) {
        LOG_ERROR("proxy_handle_local_read: invalid local_fd for channel %u",
                  ch->channel_id);
        return -1;
    }

    if (ch->state == CHANNEL_FIN_SENT ||
        ch->state == CHANNEL_FIN_RCVD ||
        ch->state == CHANNEL_TIME_WAIT ||
        ch->state == CHANNEL_CLOSED) {
        LOG_DEBUG("proxy_handle_local_read: closing late local read on "
                  "channel %u in state=%d", ch->channel_id, ch->state);
        proxy_close_local(ch);
        return 0;
    }

    if (ch->is_tcp) {
        /*
         * TCP edge-triggered 模式：在循环中读取直到 EAGAIN。
         * 这样可以一次 epoll 通知消费所有可用数据。
         * MAX_READ_BURST 限制防止饥饿其他通道。
         */
        int read_burst = 0;
        proxy_update_kcp_backpressure(ctx, ch);
        if (ch->flags & CH_FLAG_KCP_READ_PAUSED) {
            return 0;
        }

        while (read_burst < MAX_READ_BURST) {
            n = read(ch->local_fd, buf, sizeof(buf));
            if (n > 0) {
                read_burst++;
                total_read += (size_t)n;

                /* 将数据送入 KCP */
                if (channel_send_data(ch, buf, (size_t)n) < 0) {
                    LOG_WARN("proxy_handle_local_read: channel_send_data "
                             "failed (channel=%u, len=%zd), pausing read",
                             ch->channel_id, n);
                    /* 不关闭连接：KCP 窗口满/临时失败可通过背压+重传恢复 */
                    ch->flags |= CH_FLAG_KCP_READ_PAUSED;
                    break;
                }

                proxy_update_kcp_backpressure(ctx, ch);
                if (ch->flags & CH_FLAG_KCP_READ_PAUSED) {
                    break;
                }
                continue;
            }

            if (n == 0) {
                /* EOF: 对端关闭连接，开始优雅关闭 */
                LOG_INFO("proxy_handle_local_read: EOF on fd=%d "
                         "(channel=%u), starting graceful close",
                         ch->local_fd, ch->channel_id);
                proxy_close_local(ch);
                channel_send_ctrl(ch, MPF_FIN);
                ch->state = CHANNEL_FIN_SENT;
                ch->last_active = time_now();
                return 0;
            }

            /* n < 0 */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* 所有可用数据已读取完毕 */
                break;
            }

            if (errno == EINTR) {
                continue;
            }

            if (errno == ECONNRESET) {
                return proxy_close_read_side(ctx, ch,
                                             "connection reset by peer");
            }

            LOG_INFO("proxy_handle_local_read: read(fd=%d) ended with %s "
                     "(channel=%u), treating as local close",
                     ch->local_fd, strerror(errno), ch->channel_id);
            return proxy_close_read_side(ctx, ch, "local read error");
        }
    } else {
        /*
         * UDP: loop to drain all available datagrams (edge-triggered).
         * Under ET epoll, multiple datagrams arriving together would
         * lose all but the first without this loop.
         */
        struct sockaddr_storage peer_addr;
        socklen_t               addr_len = sizeof(peer_addr);
        int                     burst_count = 0;  /* H6: 防止 UDP 洪泛饥饿 */

        while (1) {
            /* H6: MAX_READ_BURST 限制防止 UDP 数据报洪泛导致事件循环饥饿 */
            if (burst_count++ >= MAX_READ_BURST) {
                LOG_WARN("proxy_handle_local_read: UDP burst limit reached "
                         "on channel=%u, deferring to next epoll cycle",
                         ch->channel_id);
                break;
            }
            /* POSIX: addr_len 是值-结果参数，每次调用前必须重置 */
            addr_len = sizeof(peer_addr);
            n = recvfrom(ch->local_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&peer_addr, &addr_len);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                if (errno == EINTR) {
                    continue;
                }
                LOG_ERROR("proxy_handle_local_read: recvfrom(fd=%d) failed: %s "
                          "(channel=%u)",
                          ch->local_fd, strerror(errno), ch->channel_id);
                return -1;
            }
            if (n == 0) {
                continue;
            }

            total_read += (size_t)n;

            /* 将数据报送入 KCP */
            if (channel_send_data(ch, buf, (size_t)n) < 0) {
                LOG_WARN("proxy_handle_local_read: channel_send_data "
                         "failed (channel=%u, len=%zd), closing session",
                         ch->channel_id, n);
                return proxy_close_read_side(ctx, ch,
                                             "channel_send_data failed");
            }

            proxy_update_kcp_backpressure(ctx, ch);
            if (ch->flags & CH_FLAG_KCP_READ_PAUSED) {
                break;
            }
        }
    }

    LOG_DEBUG("proxy_handle_local_read: read %zu bytes from fd=%d (channel=%u)",
              total_read, ch->local_fd, ch->channel_id);

    if (total_read > (size_t)INT_MAX) {
        return INT_MAX;
    }

    return (int)total_read;
}

/*
 * proxy_handle_local_write — 处理本地套接字的可写事件 (KCP→应用方向)
 *
 * 当 epoll 报告 local_fd 可写 (EPOLLOUT) 时调用。
 * 将 recv_buf 中积压的 KCP 接收数据写入本地套接字。
 *
 * 处理流程:
 *   1. 若 recv_buf_len == 0:
 *      - 检查异步 connect 是否完成 (proxy_finish_async_connect)
 *        backend 模式下首次 EPOLLOUT 标志着 TCP connect 完成
 *      - 无待发送数据，返回 0
 *
 *   2. TCP 路径: write(local_fd, recv_buf, recv_buf_len)
 *      UDP 路径: sendto(local_fd, recv_buf, ..., remote_addr:port)
 *      UDP 必须用 sendto 指定目标地址，因为 UDP 套接字未 connect
 *
 *   3. 写结果处理:
 *      - EAGAIN/EWOULDBLOCK: 写阻塞，等待下次 EPOLLOUT，返回 0
 *      - EINTR: 被信号中断，同样等待下次通知
 *      - nwritten < recv_buf_len (部分写入): 将剩余数据 memmove 到
 *        recv_buf 头部，通过 proxy_epoll_mod_events 重新注册 EPOLLOUT
 *        (edge-triggered 模式下需显式重新注册才能再次收到通知)
 *      - nwritten == recv_buf_len (全部写入): 清空 recv_buf_len
 *      - 其他错误: 返回 -1
 */
int proxy_handle_local_write(channel_t *ch)
{
    ssize_t nwritten;

    /* 不变量：recv_buf_len == 0 时 recv_buf 可为任意状态；
     * recv_buf_len > 0 时必有 recv_buf != NULL 且 recv_buf_len <= recv_buf_cap。 */

    if (!ch) {
        LOG_ERROR("proxy_handle_local_write: null channel");
        return -1;
    }

    if (ch->local_fd < 0) {
        LOG_ERROR("proxy_handle_local_write: invalid local_fd for channel %u",
                  ch->channel_id);
        return -1;
    }

    if (ch->recv_buf_len == 0) {
        /* 检查异步 connect 是否成功完成（首次 EPOLLOUT 到达时） */
        if (proxy_finish_async_connect(ch) < 0) {
            return -1;
        }
        /* 没有待发送数据 */
        return 0;
    }

    if (!ch->recv_buf) {
        LOG_ERROR("proxy_handle_local_write: recv_buf missing "
                  "(channel=%u, pending=%d)",
                  ch->channel_id, ch->recv_buf_len);
        ch->recv_buf_len = 0;
        return -1;
    }

    /*
     * TCP: write() 直接写入已连接的套接字。
     * UDP: sendto() 写入未连接的套接字，需要显式指定目标地址。
     *      若对未连接 UDP 套接字使用 write()，将返回 EDESTADDRREQ。
     */
    if (ch->is_tcp) {
        nwritten = write(ch->local_fd, ch->recv_buf, (size_t)ch->recv_buf_len);
    } else {
        struct sockaddr_storage addr;
        socklen_t addr_len;
        if (resolve_addr(ch->remote_addr, ch->remote_port, &addr, &addr_len) < 0) {
            LOG_ERROR("proxy_handle_local_write: invalid remote_addr '%s' "
                      "(channel=%u)", ch->remote_addr, ch->channel_id);
            return -1;
        }
        nwritten = sendto(ch->local_fd, ch->recv_buf,
                          (size_t)ch->recv_buf_len, 0,
                          (struct sockaddr *)&addr, addr_len);
    }
    if (nwritten < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* 写阻塞，等待下次 EPOLLOUT */
            return 0;
        }
        if (errno == EINTR) {
            return 0;
        }
        LOG_ERROR("proxy_handle_local_write: write(fd=%d) failed: %s "
                  "(channel=%u)",
                  ch->local_fd, strerror(errno), ch->channel_id);
        return -1;
    }

    if (nwritten < ch->recv_buf_len) {
        /*
         * 部分写入：将剩余数据移到缓冲区头部。
         * 使用 memmove 以支持重叠内存区域。
         */
        memmove(ch->recv_buf,
                ch->recv_buf + nwritten,
                (size_t)(ch->recv_buf_len - nwritten));
        ch->recv_buf_len -= (int)nwritten;

        /* Re-arm EPOLLOUT for remaining data (edge-triggered won't fire again) */
        if (g_ctx) {
            proxy_epoll_mod_events(g_ctx, ch->local_fd, ch, proxy_get_events(ch));
        }

        LOG_DEBUG("proxy_handle_local_write: partial write %zd/%d bytes "
                  "on fd=%d (channel=%u)",
                  nwritten, ch->recv_buf_len + (int)nwritten,
                  ch->local_fd, ch->channel_id);
    } else {
        /* 全部写入完成 */
        ch->recv_buf_len = 0;

        LOG_DEBUG("proxy_handle_local_write: wrote %zd bytes on fd=%d "
                  "(channel=%u)",
                  nwritten, ch->local_fd, ch->channel_id);
    }

    return (int)nwritten;
}

/*
 * 从 KCP 接收缓冲区刷新数据到本地套接字
 */
int proxy_flush_to_local(channel_t *ch)
{
    static uint8_t buf[PROXY_FLUSH_BUF_SIZE];
    int     n;
    int     total_flushed = 0;

    if (!ch) {
        LOG_ERROR("proxy_flush_to_local: null channel");
        return -1;
    }

    if (!ch->kcp) {
        return 0;
    }

    /*
     * 从 KCP 循环接收数据并写入本地套接字。
     * 如果 recv_buf 已有待发送数据（上次写入未完成），
     * 新的数据会在 proxy_write_to_local 中追加到缓冲区。
     */
    while (1) {
        n = kcp_wrap_recv(ch->kcp, buf, sizeof(buf));
        if (n < 0) {
            LOG_ERROR("proxy_flush_to_local: kcp_wrap_recv failed "
                      "(channel=%u)", ch->channel_id);
            return -1;
        }
        if (n == 0) {
            /* 无更多数据 */
            break;
        }

        total_flushed += n;

        int wret = proxy_write_to_local(ch, buf, n);
        if (wret == PROXY_WRITE_LOCAL_CLOSED) {
            LOG_DEBUG("proxy_flush_to_local: local peer closed (channel=%u)", ch->channel_id);
            return -1;
        }
        if (wret < 0) {
            LOG_WARN("proxy_flush_to_local: write error %d (channel=%u)", wret, ch->channel_id);
            ch->stats.tx_errors++;
            return -1;
        }
        if (wret < n) {
            /*
             * 部分写入或阻塞：recv_buf 已满或写阻塞，
             * 停止刷新，等待下次 EPOLLOUT 继续。
             */
            LOG_DEBUG("proxy_flush_to_local: write stalled at %d bytes "
                      "(channel=%u), pending in recv_buf=%d",
                      total_flushed, ch->channel_id, ch->recv_buf_len);
            break;
        }
    }

    if (total_flushed > 0) {
        LOG_DEBUG("proxy_flush_to_local: flushed %d bytes to local_fd=%d "
                  "(channel=%u)",
                  total_flushed, ch->local_fd, ch->channel_id);
    }

    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_write_to_local — 将数据从 KCP 写入本地套接字（带缓冲管理）
 *
 * 三级缓冲策略，保证数据顺序和可靠性：
 *
 *   1. recv_buf 有积压 → 新数据追加到 recv_buf 尾部（保证顺序）
 *      若溢出则报错返回 -1。
 *
 *   2. recv_buf 为空 → 尝试直接 write()/sendto()
 *      - 全部写入成功 → 返回写入字节数
 *      - write() 返回 EAGAIN → 缓冲到 recv_buf，通过 proxy_ensure_epollout()
 *        确保 EPOLLOUT 已注册，等待下次可写通知
 *      - 部分写入（nwritten < len）→ 剩余数据移入 recv_buf，注册 EPOLLOUT
 *
 *   TCP 路径：write() 直接写入
 *   UDP 路径：sendto() 发送到远端地址（通过 resolve_addr 解析）
 *
 *   错误处理：EINTR（被信号中断）→ 转为缓冲模式；其他错误 → 返回 -1
 * ────────────────────────────────────────────────────────────────────────── */
int proxy_write_to_local(channel_t *ch, const uint8_t *data, int len)
{
    ssize_t nwritten;

    if (!ch || !data) {
        LOG_ERROR("proxy_write_to_local: null pointer");
        return -1;
    }

    if (len <= 0) {
        return 0;
    }

    if (ch->local_fd < 0) {
        LOG_ERROR("proxy_write_to_local: invalid local_fd for channel %u",
                  ch->channel_id);
        return -1;
    }

    /*
     * 如果 recv_buf 中已有待发送数据，将新数据追加到缓冲区尾部。
     * 这样可以保证数据顺序，避免新数据在旧数据之前发送。
     */
    if (ch->recv_buf_len > 0) {
        /* 防御性溢出检查：recv_buf_len + len 可能溢出 int（两主机场景下 recv_buf
         * 上限由 max_cap=16MB 约束，实际不会溢出；此检查为纵深防御。 */
        if (len > INT_MAX - ch->recv_buf_len) {
            LOG_ERROR("proxy_write_to_local: recv_buf overflow (channel=%u, "
                      "pending=%d, new=%d)", ch->channel_id, ch->recv_buf_len, len);
            return -1;
        }
        if (proxy_ensure_recv_buf(ch, ch->recv_buf_len + len) < 0) {
            LOG_ERROR("proxy_write_to_local: recv_buf overflow "
                      "(channel=%u, pending=%d, new=%d, capacity=%d)",
                      ch->channel_id, ch->recv_buf_len, len,
                      ch->recv_buf_cap);
            return -1;
        }

        memcpy(ch->recv_buf + ch->recv_buf_len, data, (size_t)len);
        ch->recv_buf_len += len;

        LOG_DEBUG("proxy_write_to_local: buffered %d bytes (total pending=%d, "
                  "channel=%u)", len, ch->recv_buf_len, ch->channel_id);
        return 0; /* 数据已缓冲，实际写入为 0 */
    }

    /* recv_buf 为空，尝试直接写入 */
    if (ch->is_tcp) {
        nwritten = write(ch->local_fd, data, (size_t)len);
    } else {
        /*
         * UDP: 使用 sendto 发送到远端地址。
         * 对于已连接的 UDP 套接字，也可用 send()，
         * 但 sendto 更通用。
         */
        struct sockaddr_storage addr;
        socklen_t addr_len;
        /* UDP 每次 sendto 前 resolve_addr；此路径为冷路径（仅在 recv_buf 空时触发） */
        if (resolve_addr(ch->remote_addr, ch->remote_port, &addr, &addr_len) < 0) {
            LOG_ERROR("proxy_write_to_local: invalid remote_addr '%s' "
                      "(channel=%u)", ch->remote_addr, ch->channel_id);
            return -1;
        }
        nwritten = sendto(ch->local_fd, data, (size_t)len, 0,
                          (struct sockaddr *)&addr, addr_len);
    }

    if (nwritten < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /*
             * 套接字写缓冲区满：将数据全部缓冲到 recv_buf，
             * 等待 EPOLLOUT 事件触发重试。
             */
            if (proxy_ensure_recv_buf(ch, len) < 0) {
                LOG_ERROR("proxy_write_to_local: data too large for recv_buf "
                          "(channel=%u, len=%d, capacity=%d)",
                          ch->channel_id, len, ch->recv_buf_cap);
                return -1;
            }
            memcpy(ch->recv_buf, data, (size_t)len);
            ch->recv_buf_len = len;

            /*
             * 确保 epoll 注册包含 EPOLLOUT，以便后续可写通知。
             * 需要 ctx 来操作 epoll，通过 g_ctx 获取。
             */
            if (g_ctx) {
                if (proxy_ensure_epollout(g_ctx, ch) < 0)
                    LOG_WARN("proxy_write_to_local: EPOLLOUT register failed (channel=%u)", ch->channel_id);
            }

            LOG_DEBUG("proxy_write_to_local: write would block, "
                      "buffered %d bytes (channel=%u)",
                      len, ch->channel_id);
            return 0;
        }

        if (errno == EINTR) {
            /* 被信号中断，尝试缓冲 */
            if (proxy_ensure_recv_buf(ch, len) < 0) {
                LOG_ERROR("proxy_write_to_local: data too large for recv_buf "
                          "(channel=%u, len=%d, capacity=%d)",
                          ch->channel_id, len, ch->recv_buf_cap);
                return -1;
            }
            memcpy(ch->recv_buf, data, (size_t)len);
            ch->recv_buf_len = len;
            /* 确保 EPOLLOUT 已注册，以便后续可写通知 */
            if (g_ctx) {
                if (proxy_ensure_epollout(g_ctx, ch) < 0)
                    LOG_WARN("proxy_write_to_local: EPOLLOUT register failed (channel=%u)", ch->channel_id);
            }
            return 0;
        }

        if (errno == ECONNRESET || errno == EPIPE) {
            LOG_INFO("proxy_write_to_local: local peer closed fd=%d "
                     "(channel=%u): %s",
                     ch->local_fd, ch->channel_id, strerror(errno));
            return PROXY_WRITE_LOCAL_CLOSED;
        }

        LOG_ERROR("proxy_write_to_local: write/sendto(fd=%d) failed: %s "
                  "(channel=%u)",
                  ch->local_fd, strerror(errno), ch->channel_id);
        return -1;
    }

    if (nwritten < len) {
        /*
         * 部分写入：将剩余数据缓冲到 recv_buf。
         * 这仅在 TCP 上可能发生（非阻塞套接字缓冲区满）。
         * UDP sendto 是原子的，部分写入不可达；
         * 若到达此处，说明内核行为异常，返回错误而非缓冲，
         * 避免将半个 datagram 拆分为两个独立报文。
         */
        if (!ch->is_tcp) {
            LOG_ERROR("proxy_write_to_local: partial UDP write %zd/%d "
                      "(channel=%u), dropping connection",
                      nwritten, len, ch->channel_id);
            return -1;
        }
        int remaining = len - (int)nwritten;
        if (proxy_ensure_recv_buf(ch, remaining) < 0) {
            LOG_ERROR("proxy_write_to_local: remaining data too large "
                      "(channel=%u, remaining=%d, capacity=%d)",
                      ch->channel_id, remaining, ch->recv_buf_cap);
            return -1;
        }
        memcpy(ch->recv_buf, data + nwritten, (size_t)remaining);
        ch->recv_buf_len = remaining;

        /* 确保 EPOLLOUT 已注册 */
        if (g_ctx) {
            if (proxy_ensure_epollout(g_ctx, ch) < 0)
                LOG_WARN("proxy_write_to_local: EPOLLOUT register failed (channel=%u)", ch->channel_id);
        }

        LOG_DEBUG("proxy_write_to_local: partial write %zd/%d bytes, "
                  "buffered %d (channel=%u)",
                  nwritten, len, remaining, ch->channel_id);
    }

    return (int)nwritten;
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_close_local — 关闭通道的本地连接 (完整清理)
 *
 * 这是代理模块的「彻底关闭」函数，关闭通道的所有本地套接字资源。
 *
 * 分三阶段清理 (处理 TCP 场景下 listen_fd 和 local_fd 是不同的套接字):
 *
 *   阶段 1 — 关闭 local_fd (数据连接):
 *     - proxy_epoll_del(ctx, ch->local_fd): 从 epoll 移除，防止事件循环
 *       继续收到已关闭 fd 的事件 (stale event)
 *     - close(ch->local_fd): 关闭套接字，释放内核资源
 *     - 若 listen_fd == local_fd (UDP 场景)，一并清除 listen_fd = -1
 *       (避免后续阶段 2 尝试关闭已被阶段 1 关闭的 fd)
 *
 *   阶段 2 — 关闭 listen_fd (监听套接字，仅 TCP):
 *     - 仅当 listen_fd 存在且与 local_fd 不同时执行 (即 TCP 监听套接字)
 *     - proxy_epoll_del + close，与阶段 1 相同的两阶段清理
 *
 *   阶段 3 — 清空 recv_buf_len:
 *     - 丢弃所有尚未发送给对端的数据
 *     - free(recv_buf) 释放动态缓冲区，防止内存泄漏
 *
 * 对比 proxy_stop_listen():
 *   proxy_close_local() — 完整关闭 (数据连接 + 监听 + 清空缓冲区)
 *   proxy_stop_listen() — 仅关闭监听套接字 (保留 local_fd 和 recv_buf)
 * 用途差异: proxy_close_local 用于连接结束/错误清理；
 *          proxy_stop_listen 用于热重载时临时关闭旧监听端口。
 * ────────────────────────────────────────────────────────────────────────── */
void proxy_close_local(channel_t *ch)
{
    global_ctx_t *ctx;

    if (!ch) {
        return;
    }

    ctx = g_ctx;

    /*
     * 关闭 local_fd。
     * 对于 UDP（listen_fd == local_fd），只关闭一次。
     */
    if (ch->local_fd >= 0) {
        LOG_DEBUG("proxy_close_local: closing local_fd=%d (channel=%u)",
                  ch->local_fd, ch->channel_id);

        if (ctx && ctx->epoll_fd >= 0) {
            proxy_epoll_del(ctx, ch->local_fd);
        }
        close(ch->local_fd);

        /* 如果是 UDP（listen_fd == local_fd），一并清除 listen_fd */
        if (ch->listen_fd == ch->local_fd) {
            ch->listen_fd = -1;
        }
        ch->local_fd = -1;
    }

    /*
     * 关闭 listen_fd（如果与 local_fd 不同，即 TCP 监听套接字）。
     */
    if (ch->listen_fd >= 0 && ch->listen_fd != ch->local_fd) {
        LOG_DEBUG("proxy_close_local: closing listen_fd=%d (channel=%u)",
                  ch->listen_fd, ch->channel_id);

        if (ctx && ctx->epoll_fd >= 0) {
            proxy_epoll_del(ctx, ch->listen_fd);
        }
        close(ch->listen_fd);
        ch->listen_fd = -1;
    }

    /* 清空接收缓冲区 */
    ch->recv_buf_len = 0;
    ch->recv_buf_cap = 0;
    free(ch->recv_buf);
    ch->recv_buf = NULL;
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_stop_listen — 优雅关闭 listener 的 listen_fd (不销毁动态子通道)
 *
 * 与 proxy_close_local() 的关键区别:
 *
 *   proxy_close_local()              proxy_stop_listen()
 *   ─────────────────────            ─────────────────────
 *   关闭 listen_fd + local_fd        仅关闭 listen_fd
 *   清空 recv_buf (丢弃缓冲数据)     不清空 recv_buf (子通道可能还有待发数据)
 *   释放 recv_buf 内存                不触碰 recv_buf
 *   修改 local_fd = -1              不修改 local_fd (动态子通道保持活跃)
 *   修改 listen_fd = -1              修改 listen_fd = -1
 *
 * 用途: 配置热重载 (config_reload_channels) 时，临时关闭旧监听端口，
 *       再在新端口重新监听。保证已建立的动态子通道不受影响，
 *       仅阻止新的入站连接到达旧端口。
 *
 * 适用场景:
 *   - reload 时修改 listen_addr / listen_port 配置
 *   - 先探测新端口可用 → 关闭旧端口 → 在新端口重新监听
 *   - 旧端口上的现存连接继续服务，直到自然结束
 * ────────────────────────────────────────────────────────────────────────── */
void proxy_stop_listen(global_ctx_t *ctx, channel_t *ch)
{
    if (!ctx || !ch) return;

    if (ch->listen_fd >= 0) {
        LOG_INFO("proxy_stop_listen: stopping listener channel=%u fd=%d",
                 ch->channel_id, ch->listen_fd);

        if (ctx->epoll_fd >= 0) {
            proxy_epoll_del(ctx, ch->listen_fd);
        }
        close(ch->listen_fd);
        ch->listen_fd = -1;
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_port_probe — bind 测试机制，用于热重载前端口可用性预检
 *
 * 原理 (try-bind-then-close):
 *   1. resolve_addr(addr, port) → 解析地址族 (IPv4/IPv6)
 *   2. socket(非阻塞, CLOEXEC)  → 创建临时 TCP/UDP 套接字
 *   3. setsockopt(SO_REUSEADDR) → 允许端口复用 (探测期间)
 *   4. bind(addr:port)          → 尝试绑定目标端口
 *   5. close(fd)                → 立即释放套接字 (端口也随之释放)
 *
 * 如果 bind 成功: 说明端口当前未被占用，新监听可安全启动。
 * 如果 bind 失败: 说明端口已被占用 (EADDRINUSE) 或权限不足，返回 -1。
 *
 * 用途 (热重载安全保证):
 *   config_reload_channels() 中，修改通道配置前先调用本函数探测新端口。
 *   避免出现「旧端口已关闭、新端口又因冲突而监听失败」的双输局面。
 *   探测成功后才关闭旧端口并启动新监听。
 *
 * 安全性:
 *   - SO_REUSEADDR 允许探测期间短暂绑定，不影响正在监听的套接字
 *   - 探测套接字在 bind 后立即 close，时间窗口极小
 *   - 非阻塞 + CLOEXEC 防止意外阻塞或 fd 泄漏
 *
 * @param addr    监听地址 (如 "0.0.0.0" 或 "::")
 * @param port    监听端口
 * @param is_tcp  1=TCP (SOCK_STREAM), 0=UDP (SOCK_DGRAM)
 * @return        0=端口可用, -1=端口不可用 (地址解析失败/套接字创建失败/bind失败)
 * ────────────────────────────────────────────────────────────────────────── */
int proxy_port_probe(const char *addr, uint16_t port, int is_tcp)
{
    int                     family;
    int                     fd;
    struct sockaddr_storage sa;
    socklen_t               sa_len;

    family = resolve_addr(addr, port, &sa, &sa_len);
    if (family < 0) return -1;

    fd = socket(family,
                is_tcp ? (SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)
                       : (SOCK_DGRAM  | SOCK_NONBLOCK | SOCK_CLOEXEC),
                0);
    if (fd < 0) return -1;

    int optval = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    /* port_probe 仅用于探测端口可用性，setsockopt 失败不影响探测结果 */

    if (bind(fd, (struct sockaddr *)&sa, sa_len) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_port_conflict — 扫描哈希表检测端口冲突
 *
 * 遍历 channel_hash 中的所有通道，检查是否存在活跃的 STATIC_LISTENER
 * 占用了相同的 listen_addr + listen_port 组合。
 *
 * 排除条件：
 *   - ch->channel_id == exclude_id（允许同一通道重绑定相同端口）
 *   - ch->flags 不包含 CH_FLAG_STATIC_LISTENER（动态子通道不占用监听端口）
 *   - ch->listen_fd < 0（已关闭的监听不参与冲突检测）
 *
 * @param exclude_id  排除的 channel_id（通常为当前正在检查的通道自身）
 * @return 1=有冲突（端口已被其他通道占用），0=无冲突
 * ────────────────────────────────────────────────────────────────────────── */
int proxy_port_conflict(global_ctx_t *ctx, const char *listen_addr,
                         uint16_t listen_port, uint32_t exclude_id)
{
    for (uint32_t i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            if ((ch->flags & CH_FLAG_STATIC_LISTENER) &&
                ch->listen_fd >= 0 &&
                ch->channel_id != exclude_id &&
                ch->listen_port == listen_port &&
                strcmp(ch->listen_addr, listen_addr) == 0) {
                return 1;
            }
            ch = ch->hash_next;
        }
    }
    return 0;
}

/*
 * 获取通道本地套接字的 epoll 事件掩码
 */
uint32_t proxy_get_events(channel_t *ch)
{
    uint32_t events = EPOLLET;

    if (!ch) {
        return 0;
    }

    if (!(ch->flags & CH_FLAG_KCP_READ_PAUSED)) {
        events |= EPOLLIN;
    }

    /*
     * 如果 recv_buf 中有待发送数据，注册 EPOLLOUT
     * 以便在套接字可写时收到通知。
     */
    if (ch->recv_buf_len > 0) {
        events |= EPOLLOUT;
    }

    return events;
}

void proxy_update_kcp_backpressure(global_ctx_t *ctx, channel_t *ch)
{
    int pending;

    if (!ctx || !ch || !ch->is_tcp || !ch->kcp || ch->local_fd < 0) {
        return;
    }

    pending = kcp_wrap_waitsnd(ch->kcp);
    if (pending < 0) {
        return;
    }

    int pause_waitsnd = (ctx->config.perf_kcp_read_pause_waitsnd > 0)
                            ? ctx->config.perf_kcp_read_pause_waitsnd
                            : PERF_KCP_READ_PAUSE_WAITSND;
    int resume_waitsnd = (ctx->config.perf_kcp_read_resume_waitsnd > 0)
                             ? ctx->config.perf_kcp_read_resume_waitsnd
                             : PERF_KCP_READ_RESUME_WAITSND;

    if (!(ch->flags & CH_FLAG_KCP_READ_PAUSED) &&
        pending >= pause_waitsnd) {
        ch->flags |= CH_FLAG_KCP_READ_PAUSED;
        LOG_DEBUG("proxy_update_kcp_backpressure: pause local read "
                  "(channel=%u, waitsnd=%d)", ch->channel_id, pending);
        proxy_refresh_local_events(ctx, ch);
        return;
    }

    if ((ch->flags & CH_FLAG_KCP_READ_PAUSED) &&
        pending <= resume_waitsnd) {
        ch->flags &= ~CH_FLAG_KCP_READ_PAUSED;
        LOG_DEBUG("proxy_update_kcp_backpressure: resume local read "
                  "(channel=%u, waitsnd=%d)", ch->channel_id, pending);
        proxy_refresh_local_events(ctx, ch);
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * proxy_handle_event — epoll 事件分发器 (代理模块核心事件路由)
 *
 * 这是整个代理模块最关键的事件处理函数。main.c 的事件循环收到 epoll_wait
 * 返回后，对每个触发的事件调用本函数进行分发。
 *
 * 两条处理路径 (通过 fd 角色区分):
 *
 *   ┌─ listen_fd 路径 (仅 TCP，listen_fd ≠ local_fd)
 *   │
 *   │  EPOLLERR / EPOLLHUP:
 *   │    → STATIC_LISTENER: 重建监听 (proxy_epoll_del + close + proxy_start_listen)
 *   │    → 非 STATIC_LISTENER: proxy_close_local + 标记 CHANNEL_CLOSED
 *   │
 *   │  EPOLLIN:
 *   │    → proxy_accept() 接受新 TCP 连接
 *   │
 *   └─ local_fd 路径 (TCP 数据连接 / UDP 统一套接字)
 *
 *      异步 connect 处理:
 *        connect_pending && (任何事件) → proxy_finish_async_connect()
 *        失败则关闭通道 + RST + destroy
 *
 *      EPOLLIN (优先于 EPOLLHUP/EPOLLERR 处理):
 *        当远端主动关闭时，内核同时置位 EPOLLIN|EPOLLHUP，
 *        必须先读取残留数据 (或 read()==0 得到 EOF)，再优雅关闭。
 *        → proxy_handle_local_read() 读取→KCP 方向
 *        → 返回 PROXY_LOCAL_READ_CLOSED 表示连接已关闭
 *
 *      EPOLLHUP (挂断):
 *        → 先尽力排空 KCP 接收缓冲区 (proxy_flush_to_local)
 *        → proxy_close_local + FIN 优雅关闭
 *
 *      EPOLLERR:
 *        → proxy_close_local + RST 强制关闭 + channel_destroy
 *
 *      EPOLLOUT (可写):
 *        → proxy_handle_local_write() KCP→写入方向
 *        → 写入完成后若 recv_buf 已清空，移除 EPOLLOUT 减少无谓通知
 *          (proxy_epoll_mod_events 更新事件掩码)
 *
 * fd 查找: proxy_find_channel_by_fd() 扫描哈希表 (O(n), n≤256)
 * ────────────────────────────────────────────────────────────────────────── */
int proxy_handle_event(global_ctx_t *ctx, int fd, uint32_t events)
{
    channel_t *ch;
    int        is_listen_fd;
    int        ret;

    if (!ctx) {
        LOG_ERROR("proxy_handle_event: null context");
        return -1;
    }

    if (fd < 0) {
        LOG_ERROR("proxy_handle_event: invalid fd %d", fd);
        /*
         * 尝试从 epoll 中删除坏 fd，防止无限循环。
         * epoll_ctl(DEL) 对无效 fd 会返回 EBADF，安全无害。
         */
        epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        return -1;
    }

    /* 查找 fd 对应的通道 */
    ch = proxy_find_channel_by_fd(ctx, fd);
    if (!ch) {
        LOG_DEBUG("proxy_handle_event: stale event for fd=%d, removing from epoll",
                  fd);
        epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        return 0;
    }

    /*
     * 判断 fd 角色。
     * 对于 UDP，listen_fd == local_fd，优先按 local_fd 处理。
     */
    is_listen_fd = (fd == ch->listen_fd && fd != ch->local_fd);

    if (is_listen_fd) {
        /* ---- 监听套接字事件 ---- */

        if (events & (EPOLLERR | EPOLLHUP)) {
            int so_err = 0;
            socklen_t so_len = sizeof(so_err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
            LOG_ERROR("proxy_handle_event: error on listen_fd=%d "
                      "(channel=%u, events=0x%x, so_error=%d)",
                      fd, ch->channel_id, events, so_err);
            if (ch->flags & CH_FLAG_STATIC_LISTENER) {
                /* Listener: 重建监听套接字 */
                if (ch->listen_fd >= 0) {
                    proxy_epoll_del(ctx, ch->listen_fd);
                    close(ch->listen_fd);
                    ch->listen_fd = -1;
                }
                if (proxy_start_listen(ctx, ch) < 0) {
                    LOG_ERROR("proxy_handle_event: listener rebuild failed (channel=%u)", ch->channel_id);
                }
            } else {
                proxy_close_local(ch);
                channel_destroy(ctx, ch);  /* 非静态监听通道：从哈希表移除 */
            }
            return -1;
        }

        if (events & EPOLLIN) {
            ret = proxy_accept(ctx, ch);
            if (ret < 0) {
                /* accept 返回 -1 可能是 EAGAIN（无连接），不算错误 */
                LOG_DEBUG("proxy_handle_event: proxy_accept returned %d "
                          "(channel=%u)", ret, ch->channel_id);
            }
        }

    } else {
        /* ---- 本地连接套接字事件 ---- */

        if (ch->connect_pending &&
            (events & (EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP))) {
            ret = proxy_finish_async_connect(ch);
            if (ret < 0) {
                proxy_close_local(ch);
                channel_send_ctrl(ch, MPF_RST);
                ch->state = CHANNEL_CLOSED;
                if (!(ch->flags & CH_FLAG_STATIC_LISTENER)) {
                    channel_destroy(ctx, ch);
                }
                return 0;
            }
        }

        /*
         * EPOLLIN 优先于 EPOLLHUP/EPOLLERR 处理：
         * 当远端主动关闭时，内核同时置位 EPOLLIN|EPOLLHUP，
         * 需先读取残留数据（或 EOF via read()==0），再关闭。
         */
        if (events & EPOLLIN) {
            ret = proxy_handle_local_read(ctx, ch);
            if (ret == PROXY_LOCAL_READ_CLOSED) {
                return 0;
            }
            if (ret < 0) {
                LOG_WARN("proxy_handle_event: proxy_handle_local_read "
                         "returned %d (channel=%u, fd=%d), closing session",
                         ret, ch->channel_id, fd);
                proxy_close_local(ch);
                channel_send_ctrl(ch, MPF_RST);
                ch->state = CHANNEL_CLOSED;
                if (!(ch->flags & CH_FLAG_STATIC_LISTENER)) {
                    channel_destroy(ctx, ch);
                }
                return 0;
            }

            if (ch->local_fd < 0) {
                return 0;
            }
        }

        if (events & EPOLLHUP) {
            LOG_INFO("proxy_handle_event: hangup on local_fd=%d "
                     "(channel=%u, events=0x%x), graceful close",
                     fd, ch->channel_id, events);

            /*
             * 在关闭本地连接前，尽力排空 KCP 接收缓冲区中
             * 尚未送达本地应用的残留数据。
             * 如果 local_fd 已不可写（对端关闭），flush
             * 会静默失败，不影响后续 cleanup。
             */
            if (ch->kcp) {
                (void)proxy_flush_to_local(ch);
            }

            proxy_close_local(ch);
            if (ch->state == CHANNEL_ESTABLISHED ||
                ch->state == CHANNEL_SYN_SENT ||
                ch->state == CHANNEL_SYN_RCVD) {
                channel_send_ctrl(ch, MPF_FIN);
                ch->state = CHANNEL_FIN_SENT;
                ch->last_active = time_now();
            }
            return 0;
        }

        if (events & EPOLLERR) {
            int so_err = 0;
            socklen_t so_len = sizeof(so_err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
            LOG_ERROR("proxy_handle_event: error on local_fd=%d "
                      "(channel=%u, events=0x%x, so_error=%d)",
                      fd, ch->channel_id, events, so_err);
            /* 尽可能排空 KCP 接收缓冲区中的残留数据 */
            if (ch->kcp) {
                (void)proxy_flush_to_local(ch);
            }
            proxy_close_local(ch);
            channel_send_ctrl(ch, MPF_RST);
            ch->state = CHANNEL_CLOSED;
            if (!(ch->flags & CH_FLAG_STATIC_LISTENER)) {
                channel_destroy(ctx, ch);
            }
            return -1;
        }

        if (events & EPOLLOUT) {
            ret = proxy_handle_local_write(ch);
            if (ret < 0) {
                LOG_ERROR("proxy_handle_event: proxy_handle_local_write "
                          "failed (channel=%u, fd=%d)",
                          ch->channel_id, fd);
                proxy_close_local(ch);
                return -1;
            }

            /*
             * 写操作完成后，如果 recv_buf 已清空，
             * 更新 epoll 注册以移除 EPOLLOUT，减少不必要的事件通知。
             */
            if (ch->recv_buf_len == 0) {
                uint32_t new_events = proxy_get_events(ch);
                proxy_epoll_mod_events(ctx, fd, ch, new_events);
            }
        }
    }

    return 0;
}

/*
 * proxy_epoll_add — 添加 fd 到 epoll (edge-triggered，关联通道指针)
 *
 * 注册策略:
 *   EPOLLIN:  监听可读事件 (数据到达 / 新连接)
 *   EPOLLET:  边缘触发模式 (edge-triggered)
 *             优势: 高性能，避免 level-triggered 的重复通知
 *             要求: 每次收到通知必须循环读取直到 EAGAIN，
 *                   否则剩余数据可能永远不会触发新通知
 *   data.fd:  存储 fd (main.c 通过 ev.data.fd 获取触发源)
 *
 * 注意: ptr 参数当前未使用 (已改用 data.fd 存储)，
 *       保留以兼容旧代码。通道查找通过 proxy_find_channel_by_fd 完成。
 *
 * 与 proxy_epoll_mod_events 的区别:
 *   - proxy_epoll_add:      EPOLL_CTL_ADD — 新 fd 首次注册
 *   - proxy_epoll_mod_events: EPOLL_CTL_MOD — 已有 fd 修改事件掩码
 *   - proxy_epoll_del:      EPOLL_CTL_DEL — 移除 fd
 */
int proxy_epoll_add(global_ctx_t *ctx, int fd, void *ptr)
{
    struct epoll_event ev;

    if (!ctx) {
        LOG_ERROR("proxy_epoll_add: null context");
        return -1;
    }

    if (fd < 0) {
        LOG_ERROR("proxy_epoll_add: invalid fd %d", fd);
        return -1;
    }

    if (ctx->epoll_fd < 0) {
        LOG_ERROR("proxy_epoll_add: epoll_fd not initialized");
        return -1;
    }

    /*
     * EPOLLIN:  监听可读事件
     * EPOLLET:  边缘触发模式（高性能，避免重复通知）
     * data.fd = fd:  存储 fd，main.c 通过 data.fd 获取触发源。
     */
    memset(&ev, 0, sizeof(ev));
    /* 默认仅注册 EPOLLIN|EPOLLET；调用方若 recv_buf 积压数据，
     * 必须通过 proxy_ensure_epollout() 主动添加 EPOLLOUT */
    ev.events   = EPOLLIN | EPOLLET;
    ev.data.fd  = fd;

    (void)ptr;  /* 已改用 data.fd 存储 fd，ptr 保留兼容 */

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERROR("proxy_epoll_add: epoll_ctl(EPOLL_CTL_ADD, fd=%d) "
                  "failed: %s", fd, strerror(errno));
        return -1;
    }

    LOG_DEBUG("proxy_epoll_add: added fd=%d to epoll (ptr=%p)", fd, ptr);

    return 0;
}

/*
 * proxy_epoll_del — 从 epoll 移除 fd (安全删除)
 *
 * 注意事项:
 *   - 忽略无效 fd (fd < 0): 静默返回 0，防止 double-close 恐慌
 *   - 忽略未初始化的 epoll (epoll_fd < 0): 静默返回 0
 *   - epoll_ctl(DEL) 传 NULL event: Linux 2.6.9+ 允许，
 *     内核会忽略 fd 参数中的 event 结构体
 *   - ENOENT: fd 未注册 (可能已被移除) → 不算错误
 *   - EBADF:   fd 已关闭 → 不算错误
 *   - 其他错误: LOG_ERROR 并返回 -1
 *
 * 调用时机:
 *   - proxy_close_local(): 关闭数据连接和监听套接字之前
 *   - proxy_stop_listen(): 仅关闭监听套接字之前
 *   - proxy_handle_event(): 收到 EPOLLERR/EPOLLHUP 后的清理
 */
int proxy_epoll_del(global_ctx_t *ctx, int fd)
{
    if (!ctx) {
        LOG_ERROR("proxy_epoll_del: null context");
        return -1;
    }

    if (fd < 0) {
        return 0; /* 静默忽略无效 fd */
    }

    if (ctx->epoll_fd < 0) {
        return 0;
    }

    /*
     * epoll_ctl(EPOLL_CTL_DEL) 在较新的内核上不需要 event 参数，
     * 内核 2.6.9+ 允许 NULL，会忽略 fd。
     */
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        /*
         * ENOENT 表示 fd 未注册（可能已被移除），不算错误。
         * EBADF  表示 fd 已关闭，也不算错误。
         */
        if (errno == ENOENT || errno == EBADF) {
            LOG_DEBUG("proxy_epoll_del: fd=%d already removed or closed", fd);
            return 0;
        }
        LOG_ERROR("proxy_epoll_del: epoll_ctl(EPOLL_CTL_DEL, fd=%d) "
                  "failed: %s", fd, strerror(errno));
        return -1;
    }

    LOG_DEBUG("proxy_epoll_del: removed fd=%d from epoll", fd);

    return 0;
}
