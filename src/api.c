/*
 * api.c — HTTP REST API 管理接口
 *
 * ============================================================================
 * 架构概述
 * ============================================================================
 * 基于 Mongoose 库（单文件 HTTP 服务器）的 RESTful 管理 API，提供集群监控、
 * 通道管理和配置推送功能。所有端点返回 JSON 格式响应。
 *
 * 线程模型：
 *   单线程、非阻塞。api_poll() 以 timeout=0 集成到主事件循环中，与 AF_PACKET
 *   帧处理、KCP 更新、管理消息处理共享同一 epoll 线程。所有 handler 直接访问
 *   全局上下文 g_ctx，无需互斥锁。
 *
 * 安全模型：
 *   ┌────────────────┬─────────────────────────────────────────────┐
 *   │ 认证 (Auth)     │ Bearer Token，通过 Authorization 头传输       │
 *   │ 速率限制         │ 基于客户端 IP 的滑动窗口计数器               │
 *   │ 写保护           │ Worker 节点拒绝 POST/PUT/DELETE             │
 *   │ 审计日志         │ API 操作写入环形日志缓冲区（/api/v1/logs）   │
 *   └────────────────┴─────────────────────────────────────────────┘
 *
 * 端点表（11 个路由）：
 *   ┌───────────────────────────┬──────┬──────────┬──────────────────────┐
 *   │ 路径                       │ 方法  │ 认证     │ 说明                  │
 *   ├───────────────────────────┼──────┼──────────┼──────────────────────┤
 *   │ /api/v1/status            │ GET  │ 是       │ 系统运行状态           │
 *   │ /api/v1/nodes             │ GET  │ 是       │ 集群节点列表           │
 *   │ /api/v1/nodes/<id>        │ GET  │ 是       │ 单节点详情             │
 *   │ /api/v1/channels          │ GET  │ 是       │ 通道列表               │
 *   │ /api/v1/channels          │ POST │ 是+写保护 │ 创建通道              │
 *   │ /api/v1/channels/<id>     │ GET  │ 是       │ 通道详情               │
 *   │ /api/v1/channels/<id>     │ PUT  │ 是+写保护 │ 更新通道              │
 *   │ /api/v1/channels/<id>     │ DELETE│ 是+写保护 │ 删除通道              │
 *   │ /api/v1/config            │ GET  │ 是       │ 当前配置（JSON）       │
 *   │ /api/v1/config/push       │ POST │ 是+写保护 │ Manager→Workers 推送   │
 *   │ /api/v1/config/version    │ GET  │ 是       │ 配置版本号             │
 *   │ /api/v1/stats             │ GET  │ 是       │ 全局统计               │
 *   │ /api/v1/logs              │ GET  │ 是       │ 环形日志缓冲区         │
 *   └───────────────────────────┴──────┴──────────┴──────────────────────┘
 *
 * 依赖：
 *   — mongoose.h：HTTP 服务器框架
 *   — json-c：JSON 序列化/反序列化
 *   — types.h：log_entry_t, rate_limit_entry_t, global_ctx_t
 * ============================================================================
 */

#include "api.h"
#include "channel.h"
#include "proxy.h"
#include "crypto.h"
#include "kcp_wrap.h"

#include "mongoose.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/random.h>

#ifndef VERSION
#define VERSION             "1.0.0"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <json-c/json.h>

extern void mgmt_track_spawned_instance(global_ctx_t *ctx, const char *node_id,
    const char *name, uint16_t ethertype, const char *node_type_str, int cpu_affinity,
    const char *channels_json);
extern int  mgmt_instance_channel_ctl(global_ctx_t *ctx, const char *node_id,
    const char *instance_name, int channel_id,
    const char *op, const char *payload_json);
extern void mgmt_untrack_spawned_instance(global_ctx_t *ctx, const char *node_id,
    const char *name);
extern int  mgmt_pending_register_spawn(global_ctx_t *ctx, const char *targets[],
                int n, const char *channels_json, int *seqs);
extern void mgmt_pending_release(global_ctx_t *ctx, int op_id);
extern void mgmt_pending_cleanup(global_ctx_t *ctx);
extern void mgmt_persist_dynamic_instances(global_ctx_t *ctx);

/* M11: 复用 crypto 模块预打开的 /dev/urandom fd，避免重复 open/close */
extern int g_urandom_fd;

/* ============================================================================
 * 模块级静态变量
 * ============================================================================ */

/* api_ctx：全局上下文指针的本地缓存。
 * 在 api_init() 中赋值，api_shutdown() 中清零。
 * 所有 handler 通过 api_ctx 访问配置、统计、日志等数据。 */
static global_ctx_t *api_ctx = NULL;

/* ============================================================================
 * 前向声明 — 遵循"先声明后定义"的编码约定
 * ============================================================================ */

static void api_ev_handler(struct mg_connection *c, int ev, void *ev_data);
static int  api_check_auth(struct mg_connection *c, struct mg_http_message *hm);
static int  api_check_rate_limit(struct mg_connection *c, struct mg_http_message *hm);
static void api_generate_token(char *buf, size_t len);

/* 端点 handler — 每个函数对应一个 HTTP 路由 */
static void api_handle_status(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_config(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_reload(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_channels(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_channel_by_id(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_stats(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_logs(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_nodes(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_node_by_id(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_node_instances(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_config_switch(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_instance_spawn(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_instance_spawn_batch(struct mg_connection *c,
                                             struct mg_http_message *hm);
static void api_handle_instance_kill(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_instance_channels(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_sessions(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_session_by_id(struct mg_connection *c, struct mg_http_message *hm);
static void api_handle_metrics(struct mg_connection *c, struct mg_http_message *hm);

/* 辅助函数 — 通道 CRUD 的具体实现 */
static void api_list_channels(struct mg_connection *c, struct mg_http_message *hm);
static void api_create_channel(struct mg_connection *c, struct mg_http_message *hm);
static void api_get_channel(struct mg_connection *c, uint32_t channel_id);
static void api_update_channel(struct mg_connection *c, struct mg_http_message *hm, uint32_t channel_id);
static void api_delete_channel(struct mg_connection *c, uint32_t channel_id);

/* ============================================================================
 * 公开 API — 生命周期管理
 * ============================================================================
 *
 * api_init() → api_poll() [每循环] → api_shutdown()
 *
 * 调用关系：
 *   main() → api_init()
 *   main() event loop → api_poll()
 *   main() cleanup() → api_shutdown()
 * ============================================================================
 */

/*
 * api_init — 初始化 HTTP API 服务器
 *
 * 行为：
 *   1. 检查 api_enabled 配置标志；false 则直接返回 0。
 *   2. 分配并初始化 Mongoose event manager。
 *   3. 监听指定地址:端口。
 *   4. 若未配置 auth_token，自动生成随机 token。
 *   5. 预计算 Authorization 头部字符串（"Bearer <token>"），存入
 *      ctx->api_auth_header 供 api_check_auth 比较。
 *   6. 若非 127.0.0.1 绑定，发出安全警告日志。
 *
 * @param ctx 全局上下文
 * @return    成功 0，失败 -1（内存不足/端口占用）
 */
int api_init(global_ctx_t *ctx)
{
    /* 配置中 API 被禁用 → 优雅退出 */
    if (!ctx->config.api_enabled) {
        LOG_INFO("API server disabled by configuration");
        return 0;
    }

    api_ctx = ctx;

    /* 分配 Mongoose 事件管理器（堆分配，在 api_shutdown 中释放） */
    struct mg_mgr *mgr = (struct mg_mgr *)calloc(1, sizeof(*mgr));
    if (!mgr) {
        LOG_ERROR("API server: out of memory");
        return -1;
    }
    mg_mgr_init(mgr);
    ctx->mg_mgr = mgr;

    /* 构建监听 URL："http://<addr>:<port>" */
    char url[128];
    snprintf(url, sizeof(url), "http://%s:%u",
             ctx->config.api_listen_addr,
             ctx->config.api_listen_port);

    ctx->api_listener = mg_http_listen(mgr, url, api_ev_handler, ctx);
    if (!ctx->api_listener) {
        LOG_WARN("API: mg_http_listen returned NULL on %s", url);
    } else {
        LOG_INFO("API server started on %s", url);
    }

    /* ── Token 生成：配置中无 token 时自动生成随机 token ──
     * 自动生成的 token 在启动日志中输出，管理员应复制到配置文件。
     * 重启后 token 变化（除非写入配置文件持久化）。 */
    if (ctx->config.api_auth_token[0] == '\0') {
        api_generate_token(ctx->config.api_auth_token,
                           sizeof(ctx->config.api_auth_token));
        LOG_INFO("API token auto-generated (save to config to persist)");
        /* L9: 自动生成 token 的 LOG_INFO 日志可被 /api/v1/logs 读取；
         * 管理员应在首次启动后将 token 写入配置文件持久化。 */
    }

    /* 预计算 "Bearer <token>" 字符串，避免每次鉴权都拼接 */
    snprintf(ctx->api_auth_header, sizeof(ctx->api_auth_header),
             "Bearer %s", ctx->config.api_auth_token);

    ctx->config.api_enabled = 1;

    /* 安全警告：非 127.0.0.1 监听时提醒用户 */
    if (strcmp(ctx->config.api_listen_addr, "127.0.0.1") != 0) {
        LOG_WARN("API server listening on %s — exposed to network", url);
    }

    LOG_INFO("API server started on %s", url);
    return 0;
}

/*
 * api_poll — Mongoose 事件轮询（集成到主事件循环）
 *
 * 调用时机：main() 事件循环每次迭代结束时调用。
 * timeout=0 表示非阻塞轮询：立即处理就绪的 HTTP 请求/响应，
 * 无就绪事件时立即返回，不阻塞 epoll_wait。
 *
 * @param ctx 全局上下文
 */
void api_poll(global_ctx_t *ctx)
{
    if (!ctx->config.api_enabled) return;
    struct mg_mgr *mgr = (struct mg_mgr *)ctx->mg_mgr;
    if (!mgr) return;

    /* TODO: Mongoose 7.17 event loop integration.
     * mg_mgr_poll(mgr, 1) uses Mongoose's internal epoll which does not
     * receive new connections when called from our main epoll loop.
     * Fix: register Mongoose's listener fd with our main epoll, then
     * call mg_mgr_poll(mgr, 0) on EPOLLIN. See api.h for details. */
    mg_mgr_poll(mgr, 0);
}

/*
 * api_shutdown — 停止 API 服务器并释放资源
 *
 * 行为：调用 mg_mgr_free 关闭所有连接 → free mgr → 清除指针。
 * 安全：幂等调用 — 多次调用不会 double-free（检查 api_enabled 标志）。
 */
void api_shutdown(global_ctx_t *ctx)
{
    if (!ctx->config.api_enabled) return;
    if (!ctx->mg_mgr) return;
    struct mg_mgr *mgr = (struct mg_mgr *)ctx->mg_mgr;
    ctx->mg_mgr       = NULL;
    ctx->api_listener = NULL;
    mg_mgr_free(mgr);
    free(mgr);
    ctx->config.api_enabled = 0;
    LOG_INFO("API server stopped");
    api_ctx           = NULL;
}

/* ============================================================================
 * 日志缓冲区 — 供 LOG 宏调用的运行时日志收集器
 * ============================================================================
 *
 * 主代码中的 LOG_INFO / LOG_WARN / LOG_ERROR 宏最终调用此函数，
 * 将格式化的日志消息写入 ctx->log_buffer（环形缓冲区）。
 *
 * 环形缓冲区特性：
 *   — 容量：LOG_BUF_SIZE (1000) 条
 *   — head 指针循环移动（head = (head+1) % LOG_BUF_SIZE）
 *   — 通过 /api/v1/logs 端点读取
 * ============================================================================
 */

/*
 * log_buffer_append — 向环形日志缓冲区追加一条日志
 *
 * @param ctx   全局上下文
 * @param level 日志级别（0=DEBUG, 1=INFO, 2=WARN, 3=ERROR）
 * @param fmt   printf 格式字符串
 * @param ...   可变参数
 */
void log_buffer_append(global_ctx_t *ctx, int level, const char *fmt, ...)
{
    log_entry_t *entry = &ctx->log_buffer[ctx->log_buffer_head];
    entry->timestamp = time(NULL);
    entry->level     = level;

    va_list args;
    va_start(args, fmt);
    vsnprintf(entry->message, LOG_ENTRY_MAX_LEN, fmt, args);
    va_end(args);

    /* head 指针循环前进 */
    ctx->log_buffer_head = (ctx->log_buffer_head + 1) % LOG_BUF_SIZE;
    if (ctx->log_buffer_count < LOG_BUF_SIZE) {
        ctx->log_buffer_count++;
    }
}

/* ============================================================================
 * log_output — 统一日志输出：stderr + 本地文件 + syslog
 *
 * 由 LOG_INFO/WARN/ERROR/AUDIT 宏调用，单点控制所有输出目标。
 * 文件以追加模式写入（O_APPEND），每次写入后 fflush 保证即时性。
 * ============================================================================ */
#include <syslog.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>

static FILE        *g_log_fp = NULL;       /* NULL=未打开或已关闭 */
static int          g_log_syslog = 0;       /* 0=未启用 */
static int          g_log_remote_fd = -1;   /* 远程 syslog UDP socket, -1=未启用 */
static struct sockaddr_storage g_log_remote_addr;
static socklen_t    g_log_remote_addrlen = 0;
static int          g_log_remote_facility = LOG_DAEMON;
static char         g_log_hostname[65] = "-"; /* 远程 syslog 主机名标识 */
static const char  *g_log_level_str[] = { "DEBUG", "INFO", "WARN", "ERROR", "AUDIT" };
static int          g_log_syslog_map[] = { LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERR, LOG_NOTICE };

/* log_shutdown — 关闭日志资源（fd 清理），cleanup 中在 api_shutdown 前调用 */
void log_shutdown(void)
{
    if (g_log_fp) { fclose(g_log_fp); g_log_fp = NULL; }
    if (g_log_remote_fd >= 0) { close(g_log_remote_fd); g_log_remote_fd = -1; }
}

void log_output(int level, const char *fmt, ...)
{
    if (level < 0 || level > 4) level = LOG_LVL_INFO;

    /* 格式化消息 */
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n < 0) return;

    /* 1. stderr */
    fprintf(stderr, "[%s] %s\n", g_log_level_str[level], buf);

    /* 2. 本地文件 */
    if (g_log_fp) {
        fprintf(g_log_fp, "[%s] %s\n", g_log_level_str[level], buf);
        fflush(g_log_fp);
    }

    /* 3. 本地 syslog */
    if (g_log_syslog) {
        syslog(g_log_syslog_map[level], "%s", buf);
    }

    /* 4. 远程 syslog (UDP, RFC 5424 简化格式) */
    if (g_log_remote_fd >= 0) {
        char pkt[1100];
        time_t now = time(NULL);
        struct tm tm;
        gmtime_r(&now, &tm);
        int pri = g_log_remote_facility * 8 + g_log_syslog_map[level];
        int plen = snprintf(pkt, sizeof(pkt),
            "<%d>1 %04d-%02d-%02dT%02d:%02d:%02dZ %s gapproxy - - - %s\n",
            pri, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            g_log_hostname, buf);
        if (plen > 0 && plen < (int)sizeof(pkt)) {
            ssize_t sret = sendto(g_log_remote_fd, pkt, (size_t)plen,
                                  MSG_DONTWAIT | MSG_NOSIGNAL,
                                  (struct sockaddr *)&g_log_remote_addr,
                                  g_log_remote_addrlen);
            if (sret < 0 && (errno == ENETUNREACH || errno == ECONNREFUSED ||
                             errno == EHOSTUNREACH)) {
                close(g_log_remote_fd);
                g_log_remote_fd = -1;
            }
        }
    }
}

void log_init(global_ctx_t *ctx)
{
    if (!ctx) return;

    /* 缓存主机名用于远程 syslog */
    strncpy(g_log_hostname, ctx->config.node.node_id[0] ? ctx->config.node.node_id : "gapproxy",
            sizeof(g_log_hostname) - 1);
    g_log_hostname[sizeof(g_log_hostname) - 1] = '\0';

    /* 本地文件 */
    if (ctx->config.log_file[0] != '\0') {
        g_log_fp = fopen(ctx->config.log_file, "a");
        if (g_log_fp) {
            setvbuf(g_log_fp, NULL, _IOLBF, 0); /* 行缓冲 */
            fprintf(g_log_fp, "--- gapproxy log started ---\n");
        }
    }

    /* syslog */
    if (ctx->config.log_syslog) {
        int facility = LOG_DAEMON;
        if (strcmp(ctx->config.log_syslog_facility, "local0") == 0) facility = LOG_LOCAL0;
        else if (strcmp(ctx->config.log_syslog_facility, "local1") == 0) facility = LOG_LOCAL1;
        else if (strcmp(ctx->config.log_syslog_facility, "local2") == 0) facility = LOG_LOCAL2;
        else if (strcmp(ctx->config.log_syslog_facility, "local3") == 0) facility = LOG_LOCAL3;
        else if (strcmp(ctx->config.log_syslog_facility, "local4") == 0) facility = LOG_LOCAL4;
        else if (strcmp(ctx->config.log_syslog_facility, "local5") == 0) facility = LOG_LOCAL5;
        else if (strcmp(ctx->config.log_syslog_facility, "local6") == 0) facility = LOG_LOCAL6;
        else if (strcmp(ctx->config.log_syslog_facility, "local7") == 0) facility = LOG_LOCAL7;
        openlog("gapproxy", LOG_PID | LOG_NDELAY, facility);
        g_log_syslog = 1;
        g_log_remote_facility = facility;
    }

    /* 远程 syslog (UDP) */
    if (ctx->config.log_syslog_remote[0] != '\0') {
        char host[64] = {0}, port[8] = "514";
        const char *colon = strchr(ctx->config.log_syslog_remote, ':');
        if (colon) {
            size_t hlen = (size_t)(colon - ctx->config.log_syslog_remote);
            if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
            memcpy(host, ctx->config.log_syslog_remote, hlen);
            strncpy(port, colon + 1, sizeof(port) - 1);
            port[sizeof(port) - 1] = '\0';
        } else {
            size_t hlen = strlen(ctx->config.log_syslog_remote);
            if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
            memcpy(host, ctx->config.log_syslog_remote, hlen);
            host[hlen] = '\0';
        }

        struct addrinfo hints = {0}, *res;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(host, port, &hints, &res) == 0) {
            g_log_remote_fd = socket(res->ai_family, SOCK_DGRAM, 0);
            if (g_log_remote_fd >= 0) {
                memcpy(&g_log_remote_addr, res->ai_addr, res->ai_addrlen);
                g_log_remote_addrlen = res->ai_addrlen;
                fprintf(stderr, "[INFO] Remote syslog enabled: %s:%s\n", host, port);
            }
            freeaddrinfo(res);
        }
    }
}

/* ============================================================================
 * 认证与授权
 * ============================================================================
 */

/*
 * api_check_auth — Bearer Token 认证
 *
 * 从 HTTP Authorization 头部提取 token，与预计算的 api_auth_header 比较。
 * 认证失败时回复 401 JSON 错误响应。
 *
 * @param c  Mongoose 连接
 * @param hm HTTP 消息（用于提取 Authorization 头部）
 * @return  1=已认证，0=未认证（已自动发送 401 响应）
 */
static int api_check_auth(struct mg_connection *c, struct mg_http_message *hm)
{
    struct mg_str *auth = mg_http_get_header(hm, "Authorization");
    if (!auth || auth->len == 0 || !api_ctx) {
        mg_http_reply(c, 401, "",
            "{\"status\":\"error\",\"message\":\"Unauthorized\"}\n");
        return 0;
    }

    /* 常数时间 Token 比较: 使用 volatile diff 异或累加，防止时序侧信道。
     * M11: 固定循环上限为两者较大值，防止长度分支泄露。 */
    const char *expected = api_ctx->api_auth_header;
    const char *provided = auth->buf;
    size_t elen = strlen(expected);
    volatile int diff = (elen != auth->len) ? 1 : 0;
    size_t max_len = (elen > auth->len) ? elen : auth->len;
    for (size_t i = 0; i < max_len; i++) {
        char e = (i < elen) ? expected[i] : 0;
        char p = (i < auth->len) ? provided[i] : 0;
        diff |= (e ^ p);
    }
    if (diff != 0) {
        mg_http_reply(c, 401, "",
            "{\"status\":\"error\",\"message\":\"Unauthorized\"}\n");
        return 0;
    }
    return 1;
}

/*
 * api_check_rate_limit — 基于 IP 的滑动窗口速率限制
 *
 * 算法：
 *   1. 清理窗口中过期的条目（now - window_start >= window）
 *   2. 查找当前客户端 IP 的条目
 *   3. 若不存在则创建，count 超过阈值则拒绝（429）
 *
 * 客户端 IP 来源优先级：X-Forwarded-For 头部 > 默认 127.0.0.1
 *
 * @param c  Mongoose 连接
 * @param hm HTTP 消息
 * @return  1=允许，0=限流（已自动发送 429 响应）
 */
static int api_check_rate_limit(struct mg_connection *c, struct mg_http_message *hm)
{
    (void)hm;  /* H4: X-Forwarded-For 已移除，仅用 c->rem */
    if (!api_ctx) return 1;

    /* H4: 仅使用连接 IP 做速率限制，忽略 X-Forwarded-For 防止 IP 欺骗绕过。
     * 通过 c->rem 获取 mongoose 层解析后的远端地址。 */
    char peer_buf[64] = "127.0.0.1";
    if (c->rem.is_ip6) {
        /* M17: IPv6 客户端使用 inet_ntop 正确解析, 防止所有 IPv6 共享同一桶 */
        inet_ntop(AF_INET6, c->rem.ip, peer_buf, sizeof(peer_buf));
    } else {
        inet_ntop(AF_INET, c->rem.ip, peer_buf, sizeof(peer_buf));
    }
    const char *peer = peer_buf;

    time_t now = time(NULL);
    int window = api_ctx->config.api_rate_limit_window;

    /* ── 步骤 1：清理过期条目 ──
     * 使用交换删除法（swap-with-last），O(1) 删除但改变顺序。
     * 顺序不重要因为条目由 IP 字符串索引。 */
    for (int i = 0; i < api_ctx->rate_limit_count; ) {
        if (now - api_ctx->rate_limits[i].window_start >= window) {
            api_ctx->rate_limits[i] = api_ctx->rate_limits[--api_ctx->rate_limit_count];
        } else {
            i++;
        }
    }

    /* ── 步骤 2：查找或创建当前 IP 的条目 ── */
    rate_limit_entry_t *entry = NULL;
    for (int i = 0; i < api_ctx->rate_limit_count; i++) {
        if (strcmp(api_ctx->rate_limits[i].ip, peer) == 0) {
            entry = &api_ctx->rate_limits[i];
            break;
        }
    }

    if (!entry) {
        /* 新 IP：检查是否超出容量 */
        if (api_ctx->rate_limit_count >= RATE_LIMIT_MAX_IPS) {
            mg_http_reply(c, 429, "",
                "{\"status\":\"error\",\"message\":\"Too many unique clients\"}\n");
            return 0;
        }
        entry = &api_ctx->rate_limits[api_ctx->rate_limit_count++];
        {
            size_t plen = strlen(peer);
            if (plen >= sizeof(entry->ip)) plen = sizeof(entry->ip) - 1;
            memcpy(entry->ip, peer, plen);
            entry->ip[plen] = '\0';
        }
        entry->count        = 0;
        entry->window_start = now;
    }

    /* ── 步骤 3：计数检查 ── */
    entry->count++;
    if (entry->count > api_ctx->config.api_rate_limit) {
        mg_http_reply(c, 429, "",
            "{\"status\":\"error\",\"message\":\"Rate limit exceeded\"}\n");
        return 0;
    }
    return 1;
}

/*
 * api_generate_token — 生成随机认证令牌
 *
 * 使用 /dev/urandom 读取 16 字节随机数，编码为 32 位十六进制字符串。
 * 仅在配置中未指定 auth_token 时调用。
 *
 * @param buf 输出缓冲区（至少 33 字节）
 * @param len 缓冲区大小
 */
static void api_generate_token(char *buf, size_t len)
{
    unsigned char rnd[16];

    /* 审计修复 C1: 优先使用 getrandom() (Linux >= 3.17)，失败回退到
     * /dev/urandom。若两者均不可用，记录 CRITICAL 错误并退出，绝不使用
     * 硬编码 token。 */
    int ok = 0;
    ssize_t gr = getrandom(rnd, sizeof(rnd), GRND_NONBLOCK);
    if (gr == (ssize_t)sizeof(rnd)) {
        ok = 1;
    } else {
        /* getrandom 失败，回退到 /dev/urandom（复用 crypto 模块预打开的 fd，
         * 避免重复 open/close，减少文件描述符压力） */
        if (g_urandom_fd >= 0) {
            if (read(g_urandom_fd, rnd, sizeof(rnd)) == (ssize_t)sizeof(rnd))
                ok = 1;
        }
    }

    /* L10: 仅在初始化阶段调用（非信号上下文），fprintf+_exit 此处安全 */
    if (!ok) {
        fprintf(stderr, "[CRITICAL] FATAL: No secure entropy source available "
                        "(getrandom and /dev/urandom both failed). "
                        "Cannot generate secure API token. Exiting.\n");
        _exit(1);
    }

    for (int i = 0; i < 16 && (size_t)(i * 2 + 1) < len; i++) {
        snprintf(buf + i * 2, 3, "%02x", rnd[i]);
    }
    if (len > 32) buf[32] = '\0';
}

/* ============================================================================
 * HTTP 事件路由 — api_ev_handler
 * ============================================================================
 *
 * 所有 HTTP 请求进入此函数。
 * 路由流程：
 *   MG_EV_HTTP_MSG → 认证检查 → 速率检查 → URI 匹配 → handler 派发
 *
 * 认证和速率限制在此集中执行，handler 无需重复检查。
 * ============================================================================
 */

static void api_ev_handler(struct mg_connection *c, int ev, void *ev_data)
{
    if (ev != MG_EV_HTTP_MSG) return;

    struct mg_http_message *hm = (struct mg_http_message *)ev_data;

    /* ── 集中认证 ── */
    if (!api_check_auth(c, hm)) return;

    /* ── 集中速率限制 ── */
    if (!api_check_rate_limit(c, hm)) return;

    /* ── URI 路由表 ──
     * 匹配顺序：精确路径优先，带参数路径其次。
     * mg_match 支持 # 通配符匹配 URI 路径段。 */
    if (mg_match(hm->uri, mg_str("/api/v1/status"), NULL)) {
        api_handle_status(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/config"), NULL)) {
        api_handle_config(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/reload"), NULL)) {
        api_handle_reload(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/sessions/#"), NULL)) {
        api_handle_session_by_id(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/sessions"), NULL)) {
        api_handle_sessions(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/channels/#"), NULL)) {
        api_handle_channel_by_id(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/channels"), NULL)) {
        api_handle_channels(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/stats"), NULL)) {
        api_handle_stats(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/metrics"), NULL)) {
        api_handle_metrics(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/logs"), NULL)) {
        api_handle_logs(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/nodes/#/instances"), NULL)) {
        api_handle_node_instances(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/nodes/#"), NULL)) {
        api_handle_node_by_id(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/nodes"), NULL)) {
        api_handle_nodes(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/config/switch"), NULL)) {
        api_handle_config_switch(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/instances/spawn-batch"), NULL)) {
        api_handle_instance_spawn_batch(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/instances/spawn"), NULL)) {
        api_handle_instance_spawn(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/instances/kill"), NULL)) {
        api_handle_instance_kill(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/v1/instances/channels"), NULL)) {
        api_handle_instance_channels(c, hm);
    } else {
        mg_http_reply(c, 404, "",
            "{\"status\":\"error\",\"message\":\"Not Found\"}\n");
    }
}

/* ============================================================================
 * Worker 写保护 — 非 Manager 节点禁止写操作
 * ============================================================================
 *
 * Worker 角色只能读取状态，不能创建/修改/删除通道或推送配置。
 * 此函数在 POST/PUT/DELETE handler 入口处调用。
 * ============================================================================
 */

static int api_check_write_access(struct mg_connection *c)
{
    if (!api_ctx) return 0;
    if (api_ctx->config.node.node_role == NODE_ROLE_WORKER) {
        mg_http_reply(c, 403, "",
            "{\"status\":\"error\",\"message\":\"Worker node: use manager API\"}\n");
        return 0;
    }
    return 1;
}

/* ============================================================================
 * 端点 handler 实现
 *
 * 每个 handler 遵循统一模式：
 *   1. 权限检查（如有需要）
 *   2. 构建 json-c 响应对象
 *   3. 序列化为 JSON 字符串
 *   4. mg_http_reply 返回
 *   5. json_object_put 释放
 * ============================================================================
 */

/* ──── GET /api/v1/status ────────────────────────────────────────────
 * 返回系统运行状态：节点身份、版本、运行时间、活跃通道数等。
 */
static void api_handle_status(struct mg_connection *c, struct mg_http_message *hm)
{
    (void)hm;
    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "node_id", json_object_new_string(api_ctx->config.node.node_id));
    json_object_object_add(obj, "version",  json_object_new_string(VERSION));
    json_object_object_add(obj, "role",     json_object_new_string(
        api_ctx->config.node.node_role == NODE_ROLE_MANAGER ? "manager" :
        api_ctx->config.node.node_role == NODE_ROLE_WORKER  ? "worker"  : "none"));
    json_object_object_add(obj, "uptime_seconds", json_object_new_int64(
        (int64_t)time_elapsed(api_ctx->start_time)));
    json_object_object_add(obj, "active_channels", json_object_new_int(api_ctx->channel_count));

    /* 新增: 管理与内存字段 */
    json_object_object_add(obj, "worker_count", json_object_new_int(api_ctx->mgmt.worker_count));
    json_object_object_add(obj, "config_version", json_object_new_int64((int64_t)api_ctx->mgmt.config_version));
    json_object_object_add(obj, "management_enabled", json_object_new_boolean(api_ctx->config.management.enabled));
    json_object_object_add(obj, "memory_used_bytes", json_object_new_int64((int64_t)api_ctx->global_memory_used));

    /* 新增: NIC 统计 */
    json_object *nic_obj = json_object_new_object();
    json_object_object_add(nic_obj, "rx_packets", json_object_new_int64((int64_t)api_ctx->nic.rx_packets));
    json_object_object_add(nic_obj, "tx_packets", json_object_new_int64((int64_t)api_ctx->nic.tx_packets));
    json_object_object_add(nic_obj, "rx_bytes",   json_object_new_int64((int64_t)api_ctx->nic.rx_bytes));
    json_object_object_add(nic_obj, "tx_bytes",   json_object_new_int64((int64_t)api_ctx->nic.tx_bytes));
    json_object_object_add(nic_obj, "rx_dropped", json_object_new_int64((int64_t)api_ctx->nic.rx_dropped));
    json_object_object_add(nic_obj, "tx_dropped", json_object_new_int64((int64_t)api_ctx->nic.tx_dropped));
    json_object_object_add(obj, "nic", nic_obj);

    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(obj);
}

/* ──── GET /api/v1/nodes ────────────────────────────────────────────
 * 返回集群节点列表：Manager 信息 + Workers 注册表。
 * 在 Manager 上返回完整信息；Worker 上仅返回自身。
 */
static void api_handle_nodes(struct mg_connection *c, struct mg_http_message *hm)
{
    (void)hm;
    json_object *obj = json_object_new_object();

    /* Manager 自身信息 */
    json_object *mgr_obj = json_object_new_object();
    json_object_object_add(mgr_obj, "node_id",     json_object_new_string(api_ctx->config.node.node_id));
    json_object_object_add(mgr_obj, "version",      json_object_new_string(VERSION));
    json_object_object_add(mgr_obj, "uptime_seconds", json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(mgr_obj, "config_version", json_object_new_int64((int64_t)api_ctx->mgmt.config_version));
    json_object_object_add(mgr_obj, "active_channels", json_object_new_int(api_ctx->channel_count));
    json_object_object_add(mgr_obj, "total_channels",  json_object_new_int(api_ctx->config.channel_count));
    json_object_object_add(obj, "manager", mgr_obj);

    /* Workers 注册表（仅 Manager 有数据） */
    json_object *workers_arr = json_object_new_array();
    for (int i = 0; i < api_ctx->mgmt.worker_count; i++) {
        mgmt_worker_t *w = &api_ctx->mgmt.workers[i];
        json_object *w_obj = json_object_new_object();
        json_object_object_add(w_obj, "node_id",    json_object_new_string(w->node_id));
        json_object_object_add(w_obj, "state",      json_object_new_string(
            w->state == MGMT_WORKER_STATE_ACTIVE   ? "ACTIVE" :
            w->state == MGMT_WORKER_STATE_DEGRADED ? "DEGRADED" : "JOINING"));
        json_object_object_add(w_obj, "registered_at", json_object_new_int64((int64_t)w->registered_at));
        json_object_object_add(w_obj, "last_seen",     json_object_new_int64((int64_t)w->last_seen));
        json_object_object_add(w_obj, "config_version", json_object_new_int64((int64_t)w->config_version));
        json_object_array_add(workers_arr, w_obj);
    }
    json_object_object_add(obj, "workers", workers_arr);
    json_object_object_add(obj, "total", json_object_new_int(api_ctx->mgmt.worker_count));

    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(obj);
}

/* ──── GET /api/v1/nodes/<id> ───────────────────────────────────────
 * 返回单个 Worker 节点的详细信息。
 */
static void api_handle_node_by_id(struct mg_connection *c, struct mg_http_message *hm)
{
    struct mg_str cap;
    if (!mg_match(hm->uri, mg_str("/api/v1/nodes/#"), &cap)) {
        mg_http_reply(c, 400, "", "{\"status\":\"error\",\"message\":\"Missing node ID\"}\n");
        return;
    }

    char node_id[65] = {0};
    size_t n = cap.len < sizeof(node_id)-1 ? cap.len : sizeof(node_id)-1;
    memcpy(node_id, cap.buf, n);

    /* 在注册表中查找 */
    mgmt_worker_t *w = NULL;
    for (int i = 0; i < api_ctx->mgmt.worker_count; i++) {
        if (strcmp(api_ctx->mgmt.workers[i].node_id, node_id) == 0) {
            w = &api_ctx->mgmt.workers[i];
            break;
        }
    }
    if (!w) {
        mg_http_reply(c, 404, "", "{\"status\":\"error\",\"message\":\"Node not found\"}\n");
        return;
    }

    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "node_id",        json_object_new_string(w->node_id));
    json_object_object_add(obj, "state",          json_object_new_string(
        w->state == MGMT_WORKER_STATE_ACTIVE  ? "ACTIVE"  :
        w->state == MGMT_WORKER_STATE_DEGRADED ? "DEGRADED" : "JOINING"));
    json_object_object_add(obj, "registered_at",  json_object_new_int64((int64_t)w->registered_at));
    json_object_object_add(obj, "last_seen",      json_object_new_int64((int64_t)w->last_seen));
    json_object_object_add(obj, "config_version", json_object_new_int64((int64_t)w->config_version));
    json_object_object_add(obj, "channel_id",     json_object_new_int64(w->channel_id));

    /* 新增: health_resp_count, degraded_since */
    json_object_object_add(obj, "health_resp_count", json_object_new_int(w->health_resp_count));
    json_object_object_add(obj, "degraded_since",    json_object_new_int64((int64_t)w->degraded_since));

    /* 新增: 计算该 Worker 的通道数 */
    {
        int w_ch_count = 0;
        for (uint32_t b = 0; b < api_ctx->channel_hash_size; b++) {
            channel_t *ch = api_ctx->channel_hash[b];
            while (ch) {
                /* 管理通道属于该 Worker */
                if (ch->flags & CH_FLAG_MGMT_CHANNEL) {
                    w_ch_count++;
                }
                ch = ch->hash_next;
            }
        }
        json_object_object_add(obj, "channel_count", json_object_new_int(w_ch_count));
    }

    /* 新增: config_version_delta (与 Manager 的差异) */
    {
        int64_t delta = (int64_t)api_ctx->mgmt.config_version - (int64_t)w->config_version;
        json_object_object_add(obj, "config_version_delta", json_object_new_int64(delta));
    }

    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(obj);
}

/* ──── GET /api/v1/nodes/<id>/instances ─────────────────────────────
 * 返回指定 Worker 上所有 SPAWN 实例的运行时可观测信息。
 */
static void api_handle_node_instances(struct mg_connection *c, struct mg_http_message *hm)
{
    struct mg_str cap;
    if (!mg_match(hm->uri, mg_str("/api/v1/nodes/#/instances"), &cap)) {
        mg_http_reply(c, 400, "", "{\"status\":\"error\",\"message\":\"Missing node ID\"}\n");
        return;
    }

    char node_id[65] = {0};
    size_t n = cap.len < sizeof(node_id)-1 ? cap.len : sizeof(node_id)-1;
    memcpy(node_id, cap.buf, n);

    mgmt_worker_t *w = NULL;
    for (int i = 0; i < api_ctx->mgmt.worker_count; i++) {
        if (strcmp(api_ctx->mgmt.workers[i].node_id, node_id) == 0) {
            w = &api_ctx->mgmt.workers[i];
            break;
        }
    }
    if (!w) {
        mg_http_reply(c, 404, "", "{\"status\":\"error\",\"message\":\"Node not found\"}\n");
        return;
    }

    json_object *arr = json_object_new_array();
    uint32_t now = time_now();
    for (int i = 0; i < w->instance_count; i++) {
        mgmt_worker_instance_t *inst = &w->instances[i];
        json_object *o = json_object_new_object();
        json_object_object_add(o, "instance_name",  json_object_new_string(inst->instance_name));
        json_object_object_add(o, "ethertype",       json_object_new_int(inst->ethertype));
        json_object_object_add(o, "node_type",       json_object_new_string(
            inst->node_type == NODE_TYPE_BACKEND ? "backend" : "frontend"));
        json_object_object_add(o, "cpu_affinity",    json_object_new_int(inst->cpu_affinity));
        json_object_object_add(o, "pid",             json_object_new_int((int)inst->pid));
        json_object_object_add(o, "spawned_at",      json_object_new_int64(inst->spawned_at));
        json_object_object_add(o, "uptime_sec",      json_object_new_int64(
            inst->spawned_at ? (int64_t)(now - inst->spawned_at) : 0));
        json_object_object_add(o, "restart_count",   json_object_new_int((int)inst->restart_count));
        json_object_array_add(arr, o);
    }

    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "node_id",  json_object_new_string(node_id));
    json_object_object_add(obj, "total",    json_object_new_int(w->instance_count));
    json_object_object_add(obj, "instances", arr);

    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(obj);
}

/* ──── GET /api/v1/config ───────────────────────────────────────────
 * 返回当前全局配置的完整 JSON 表示。
 */
static void api_handle_config(struct mg_connection *c, struct mg_http_message *hm)
{
    (void)hm;
    json_object *obj = json_object_new_object();

    /* 序列化节点配置 */
    json_object *node_obj = json_object_new_object();
    json_object_object_add(node_obj, "node_id",   json_object_new_string(api_ctx->config.node.node_id));
    json_object_object_add(node_obj, "node_role", json_object_new_string(
        api_ctx->config.node.node_role == NODE_ROLE_MANAGER ? "manager" :
        api_ctx->config.node.node_role == NODE_ROLE_WORKER  ? "worker"  : "none"));
    json_object_object_add(obj, "node", node_obj);

    /* 序列化通道配置 */
    json_object *ch_arr = json_object_new_array();
    for (int i = 0; i < api_ctx->config.channel_count; i++) {
        channel_config_t *cfg = &api_ctx->config.channels[i];
        json_object *ch_obj = json_object_new_object();
        json_object_object_add(ch_obj, "channel_id",   json_object_new_int(cfg->channel_id));
        json_object_object_add(ch_obj, "enabled",       json_object_new_boolean(cfg->enabled));
        json_object_object_add(ch_obj, "listen_port",   json_object_new_int(cfg->listen_port));
        json_object_object_add(ch_obj, "remote_port",   json_object_new_int(cfg->remote_port));
        json_object_object_add(ch_obj, "listen_addr",   json_object_new_string(cfg->listen_addr));
        json_object_object_add(ch_obj, "remote_addr",   json_object_new_string(cfg->remote_addr));
        json_object_object_add(ch_obj, "is_tcp",        json_object_new_boolean(cfg->is_tcp));
        json_object_object_add(ch_obj, "max_sessions",  json_object_new_int(cfg->max_sessions));
        json_object_array_add(ch_arr, ch_obj);
    }
    json_object_object_add(obj, "channels", ch_arr);
    json_object_object_add(obj, "channel_count", json_object_new_int(api_ctx->config.channel_count));

    /* 管理配置 */
    json_object *mgmt_obj = json_object_new_object();
    json_object_object_add(mgmt_obj, "enabled",             json_object_new_boolean(api_ctx->config.management.enabled));
    json_object_object_add(mgmt_obj, "keepalive_interval",   json_object_new_int(api_ctx->config.management.keepalive_interval));
    json_object_object_add(mgmt_obj, "keepalive_timeout",    json_object_new_int(api_ctx->config.management.keepalive_timeout));
    json_object_object_add(obj, "management", mgmt_obj);

    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(obj);
}

/* ──── POST /api/v1/reload ─────────────────────────────────────────
 * 触发热重载（重新读取配置文件）。
 * 仅 Manager 角色可调用。
 */
static void api_handle_reload(struct mg_connection *c, struct mg_http_message *hm)
{
    (void)hm;
    if (!api_check_write_access(c)) return;

    /* 使用 SIGHUP 的语义：设置 reload_requested 标志，主循环检测到后执行 */
    api_ctx->reload_requested = 1;
    mg_http_reply(c, 200, "",
        "{\"status\":\"ok\",\"message\":\"Reload requested\"}\n");
}

/* ──── GET /api/v1/channels ─────────────────────────────────────────
 * 返回所有通道的列表（含运行状态）。
 */
static void api_handle_channels(struct mg_connection *c, struct mg_http_message *hm)
{
    if (mg_strcmp(mg_str("GET"), hm->method) == 0) {
        api_list_channels(c, hm);
    } else if (mg_strcmp(mg_str("POST"), hm->method) == 0) {
        api_create_channel(c, hm);
    } else {
        mg_http_reply(c, 405, "",
            "{\"status\":\"error\",\"message\":\"Method Not Allowed\"}\n");
    }
}

/* ──── /api/v1/channels/<id> (GET/PUT/DELETE) ────────────────────── */
static void api_handle_channel_by_id(struct mg_connection *c, struct mg_http_message *hm)
{
    struct mg_str cap;
    if (!mg_match(hm->uri, mg_str("/api/v1/channels/#"), &cap)) {
        mg_http_reply(c, 400, "", "{\"status\":\"error\",\"message\":\"Missing channel ID\"}\n");
        return;
    }
    uint32_t channel_id = 0;
    {
        char chid_buf[16];
        size_t n = cap.len < sizeof(chid_buf)-1 ? cap.len : sizeof(chid_buf)-1;
        memcpy(chid_buf, cap.buf, n);
        chid_buf[n] = '\0';
        channel_id = (uint32_t)strtoul(chid_buf, NULL, 10);
    }

    /* C8: 拒绝超出数组边界的 channel_id，防止越界访问 */
    if (channel_id >= MAX_CHANNELS) {
        mg_http_reply(c, 404, "",
            "{\"status\":\"error\",\"message\":\"Channel not found\"}\n");
        return;
    }

    if (mg_strcmp(mg_str("GET"), hm->method) == 0) {
        api_get_channel(c, channel_id);
    } else if (mg_strcmp(mg_str("PUT"), hm->method) == 0) {
        api_update_channel(c, hm, channel_id);
    } else if (mg_strcmp(mg_str("DELETE"), hm->method) == 0) {
        api_delete_channel(c, channel_id);
    } else {
        mg_http_reply(c, 405, "", "{\"status\":\"error\",\"message\":\"Method Not Allowed\"}\n");
    }
}

/* ──── GET /api/v1/stats ────────────────────────────────────────────
 * 返回全局统计：总帧数、字节数、错误数等。
 * 统计来自 ctx->stats 聚合。
 */
static void api_handle_stats(struct mg_connection *c, struct mg_http_message *hm)
{
    (void)hm;
    /* 遍历哈希表所有通道汇聚统计 */
    uint64_t total_tx = 0, total_rx = 0, total_retrans = 0, total_errors = 0;
    uint64_t total_tx_bytes = 0, total_rx_bytes = 0;
    int ch_count = 0;
    json_object *ch_arr = json_object_new_array();

    for (uint32_t b = 0; b < api_ctx->channel_hash_size; b++) {
        channel_t *ch = api_ctx->channel_hash[b];
        while (ch) {
            total_tx      += ch->stats.tx_frames;
            total_rx      += ch->stats.rx_frames;
            total_tx_bytes += ch->stats.tx_bytes;
            total_rx_bytes += ch->stats.rx_bytes;
            total_retrans += ch->stats.retransmits;
            total_errors  += ch->stats.tx_errors + ch->stats.rx_errors + ch->stats.crc_errors + ch->stats.crypto_errors;

            /* 每个通道的运行时统计 */
            json_object *ch_obj = json_object_new_object();
            json_object_object_add(ch_obj, "channel_id", json_object_new_int(ch->channel_id));
            json_object_object_add(ch_obj, "state", json_object_new_string(
                ch->state == CHANNEL_ESTABLISHED ? "ESTABLISHED" :
                ch->state == CHANNEL_SYN_SENT   ? "SYN_SENT" :
                ch->state == CHANNEL_SYN_RCVD   ? "SYN_RCVD" :
                ch->state == CHANNEL_CLOSED     ? "CLOSED" : "UNKNOWN"));
            json_object_object_add(ch_obj, "tx_frames",   json_object_new_int64((int64_t)ch->stats.tx_frames));
            json_object_object_add(ch_obj, "rx_frames",   json_object_new_int64((int64_t)ch->stats.rx_frames));
            json_object_object_add(ch_obj, "tx_bytes",    json_object_new_int64((int64_t)ch->stats.tx_bytes));
            json_object_object_add(ch_obj, "rx_bytes",    json_object_new_int64((int64_t)ch->stats.rx_bytes));
            json_object_object_add(ch_obj, "retransmits", json_object_new_int64((int64_t)ch->stats.retransmits));
            json_object_object_add(ch_obj, "errors",      json_object_new_int64(
                (int64_t)(ch->stats.tx_errors + ch->stats.rx_errors + ch->stats.crc_errors + ch->stats.crypto_errors)));
            {
                int rtt = 0;
                if (ch->kcp) rtt = (int)ch->kcp->rx_srtt;
                json_object_object_add(ch_obj, "rtt_ms", json_object_new_int(rtt));
            }
            json_object_array_add(ch_arr, ch_obj);

            ch_count++;
            ch = ch->hash_next;
        }
    }

    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "total_channels",     json_object_new_int(ch_count));
    json_object_object_add(obj, "total_tx_frames",    json_object_new_int64((int64_t)total_tx));
    json_object_object_add(obj, "total_rx_frames",    json_object_new_int64((int64_t)total_rx));
    json_object_object_add(obj, "total_tx_bytes",     json_object_new_int64((int64_t)total_tx_bytes));
    json_object_object_add(obj, "total_rx_bytes",     json_object_new_int64((int64_t)total_rx_bytes));
    json_object_object_add(obj, "total_retransmits",  json_object_new_int64((int64_t)total_retrans));
    json_object_object_add(obj, "total_errors",       json_object_new_int64((int64_t)total_errors));
    json_object_object_add(obj, "config_version",     json_object_new_int64((int64_t)api_ctx->mgmt.config_version));
    json_object_object_add(obj, "channels", ch_arr);

    /* 新增: NIC 统计段 */
    json_object *nic_obj = json_object_new_object();
    json_object_object_add(nic_obj, "rx_packets", json_object_new_int64((int64_t)api_ctx->nic.rx_packets));
    json_object_object_add(nic_obj, "tx_packets", json_object_new_int64((int64_t)api_ctx->nic.tx_packets));
    json_object_object_add(nic_obj, "rx_bytes",   json_object_new_int64((int64_t)api_ctx->nic.rx_bytes));
    json_object_object_add(nic_obj, "tx_bytes",   json_object_new_int64((int64_t)api_ctx->nic.tx_bytes));
    json_object_object_add(nic_obj, "rx_dropped", json_object_new_int64((int64_t)api_ctx->nic.rx_dropped));
    json_object_object_add(nic_obj, "tx_dropped", json_object_new_int64((int64_t)api_ctx->nic.tx_dropped));
    json_object_object_add(obj, "nic", nic_obj);

    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(obj);
}

/* ──── GET /api/v1/logs ────────────────────────────────────────────
 * 返回环形日志缓冲区内容（最多 1000 条）。
 */
static void api_handle_logs(struct mg_connection *c, struct mg_http_message *hm)
{
    /* 解析可选的 ?channel_id=N 查询参数 */
    char chid_buf[16] = {0};
    int filter_enabled = 0;
    uint32_t filter_chid = 0;
    if (mg_http_get_var(&hm->query, "channel_id", chid_buf, sizeof(chid_buf)) > 0) {
        filter_chid = (uint32_t)strtoul(chid_buf, NULL, 10);
        filter_enabled = 1;
    }

    json_object *arr = json_object_new_array();
    int count = api_ctx->log_buffer_count;
    int start = (api_ctx->log_buffer_head - count + LOG_BUF_SIZE) % LOG_BUF_SIZE;

    for (int i = 0; i < count; i++) {
        int idx = (start + i) % LOG_BUF_SIZE;
        log_entry_t *entry = &api_ctx->log_buffer[idx];

        /* 如果指定了 channel_id 过滤，跳过不匹配的条目 */
        if (filter_enabled && entry->channel_id != filter_chid) continue;

        json_object *e = json_object_new_object();
        json_object_object_add(e, "timestamp", json_object_new_int64((int64_t)entry->timestamp));
        const char *level_str = "DEBUG";
        if (entry->level == 1) level_str = "INFO";
        else if (entry->level == 2) level_str = "WARN";
        else if (entry->level == 3) level_str = "ERROR";
        json_object_object_add(e, "level",   json_object_new_string(level_str));
        json_object_object_add(e, "message", json_object_new_string(entry->message));
        if (entry->channel_id != 0) {
            json_object_object_add(e, "channel_id", json_object_new_int(entry->channel_id));
        }
        json_object_array_add(arr, e);
    }

    const char *s = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(arr);
}

/* ──── GET /api/v1/sessions ──────────────────────────────────────────
 * 遍历哈希表所有通道，返回运行时会话列表。
 */
static void api_handle_sessions(struct mg_connection *c, struct mg_http_message *hm)
{
    (void)hm;
    json_object *arr = json_object_new_array();
    uint32_t now = time_now();

    for (uint32_t b = 0; b < api_ctx->channel_hash_size; b++) {
        channel_t *ch = api_ctx->channel_hash[b];
        while (ch) {
            json_object *obj = json_object_new_object();
            json_object_object_add(obj, "channel_id", json_object_new_int(ch->channel_id));
            json_object_object_add(obj, "state", json_object_new_string(
                ch->state == CHANNEL_ESTABLISHED ? "ESTABLISHED" :
                ch->state == CHANNEL_SYN_SENT   ? "SYN_SENT" :
                ch->state == CHANNEL_SYN_RCVD   ? "SYN_RCVD" :
                ch->state == CHANNEL_CLOSED     ? "CLOSED" : "UNKNOWN"));
            json_object_object_add(obj, "role", json_object_new_string(
                ch->role == CHANNEL_ROLE_INITIATOR ? "initiator" :
                ch->role == CHANNEL_ROLE_RESPONDER ? "responder" :
                ch->role == CHANNEL_ROLE_LISTENER  ? "listener"  : "unknown"));
            json_object_object_add(obj, "protocol",  json_object_new_string(ch->is_tcp ? "tcp" : "udp"));
            {
                int rtt = 0;
                if (ch->kcp) rtt = (int)ch->kcp->rx_srtt;
                json_object_object_add(obj, "rtt_ms", json_object_new_int(rtt));
            }
            json_object_object_add(obj, "tx_bytes",    json_object_new_int64((int64_t)ch->stats.tx_bytes));
            json_object_object_add(obj, "rx_bytes",    json_object_new_int64((int64_t)ch->stats.rx_bytes));
            json_object_object_add(obj, "retransmits", json_object_new_int64((int64_t)ch->stats.retransmits));
            json_object_object_add(obj, "last_active_sec", json_object_new_int64(
                (int64_t)(now - ch->last_active)));
            json_object_object_add(obj, "uptime_sec", json_object_new_int64(
                (int64_t)(now - ch->created_at)));
            json_object_array_add(arr, obj);
            ch = ch->hash_next;
        }
    }

    const char *s = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(arr);
}

/* ──── GET /api/v1/sessions/<id> ─────────────────────────────────────
 * 返回单个会话完整运行时详情（包含 KCP 内部窗口）。
 */
static void api_handle_session_by_id(struct mg_connection *c, struct mg_http_message *hm)
{
    struct mg_str cap;
    if (!mg_match(hm->uri, mg_str("/api/v1/sessions/#"), &cap)) {
        mg_http_reply(c, 400, "", "{\"status\":\"error\",\"message\":\"Missing session ID\"}\n");
        return;
    }
    uint32_t channel_id = 0;
    {
        char chid_buf[16];
        size_t n = cap.len < sizeof(chid_buf)-1 ? cap.len : sizeof(chid_buf)-1;
        memcpy(chid_buf, cap.buf, n);
        chid_buf[n] = '\0';
        channel_id = (uint32_t)strtoul(chid_buf, NULL, 10);
    }

    if (channel_id >= MAX_CHANNELS) {
        mg_http_reply(c, 404, "", "{\"status\":\"error\",\"message\":\"Session not found\"}\n");
        return;
    }

    channel_t *ch = channel_find(api_ctx, channel_id);
    if (!ch) {
        mg_http_reply(c, 404, "", "{\"status\":\"error\",\"message\":\"Session not found\"}\n");
        return;
    }

    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "channel_id", json_object_new_int(ch->channel_id));
    json_object_object_add(obj, "state", json_object_new_string(
        ch->state == CHANNEL_ESTABLISHED ? "ESTABLISHED" :
        ch->state == CHANNEL_SYN_SENT   ? "SYN_SENT" :
        ch->state == CHANNEL_SYN_RCVD   ? "SYN_RCVD" :
        ch->state == CHANNEL_CLOSED     ? "CLOSED" : "UNKNOWN"));
    json_object_object_add(obj, "role", json_object_new_string(
        ch->role == CHANNEL_ROLE_INITIATOR ? "initiator" :
        ch->role == CHANNEL_ROLE_RESPONDER ? "responder" :
        ch->role == CHANNEL_ROLE_LISTENER  ? "listener"  : "unknown"));
    json_object_object_add(obj, "protocol",  json_object_new_string(ch->is_tcp ? "tcp" : "udp"));
    json_object_object_add(obj, "listen_addr", json_object_new_string(ch->listen_addr));
    json_object_object_add(obj, "listen_port", json_object_new_int(ch->listen_port));
    json_object_object_add(obj, "remote_addr", json_object_new_string(ch->remote_addr));
    json_object_object_add(obj, "remote_port", json_object_new_int(ch->remote_port));
    json_object_object_add(obj, "flags",       json_object_new_int(ch->flags));
    json_object_object_add(obj, "local_fd",    json_object_new_int(ch->local_fd));
    json_object_object_add(obj, "listen_fd",   json_object_new_int(ch->listen_fd));
    json_object_object_add(obj, "cb_open",     json_object_new_boolean(
        api_ctx->cb_open[ch->channel_id] != 0));

    /* ── KCP 内部窗口 ── */
    {
        json_object *kc = json_object_new_object();
        if (ch->kcp) {
            json_object_object_add(kc, "snd_una",  json_object_new_int64((int64_t)ch->kcp->snd_una));
            json_object_object_add(kc, "snd_nxt",  json_object_new_int64((int64_t)ch->kcp->snd_nxt));
            json_object_object_add(kc, "rcv_nxt",  json_object_new_int64((int64_t)ch->kcp->rcv_nxt));
            json_object_object_add(kc, "snd_wnd",  json_object_new_int((int)ch->kcp->snd_wnd));
            json_object_object_add(kc, "rcv_wnd",  json_object_new_int((int)ch->kcp->rcv_wnd));
            json_object_object_add(kc, "rmt_wnd",  json_object_new_int((int)ch->kcp->rmt_wnd));
            json_object_object_add(kc, "cwnd",     json_object_new_int((int)ch->kcp->cwnd));
            json_object_object_add(kc, "inflight", json_object_new_int64(
                (int64_t)(ch->kcp->snd_nxt - ch->kcp->snd_una)));
            json_object_object_add(kc, "rx_srtt",  json_object_new_int((int)ch->kcp->rx_srtt));
            json_object_object_add(kc, "rx_rto",   json_object_new_int((int)ch->kcp->rx_rto));
        } else {
            json_object_object_add(kc, "snd_una",  json_object_new_int(0));
            json_object_object_add(kc, "snd_nxt",  json_object_new_int(0));
            json_object_object_add(kc, "rcv_nxt",  json_object_new_int(0));
            json_object_object_add(kc, "snd_wnd",  json_object_new_int(0));
            json_object_object_add(kc, "rcv_wnd",  json_object_new_int(0));
            json_object_object_add(kc, "rmt_wnd",  json_object_new_int(0));
            json_object_object_add(kc, "cwnd",     json_object_new_int(0));
            json_object_object_add(kc, "inflight", json_object_new_int(0));
            json_object_object_add(kc, "rx_srtt",  json_object_new_int(0));
            json_object_object_add(kc, "rx_rto",   json_object_new_int(0));
        }
        json_object_object_add(obj, "kcp", kc);
    }

    /* ── 运行时统计 ── */
    {
        json_object *rt = json_object_new_object();
        json_object_object_add(rt, "tx_frames",    json_object_new_int64((int64_t)ch->stats.tx_frames));
        json_object_object_add(rt, "rx_frames",    json_object_new_int64((int64_t)ch->stats.rx_frames));
        json_object_object_add(rt, "tx_bytes",     json_object_new_int64((int64_t)ch->stats.tx_bytes));
        json_object_object_add(rt, "rx_bytes",     json_object_new_int64((int64_t)ch->stats.rx_bytes));
        json_object_object_add(rt, "retransmits",  json_object_new_int64((int64_t)ch->stats.retransmits));
        {
            int64_t errs = (int64_t)(ch->stats.tx_errors + ch->stats.rx_errors +
                                     ch->stats.crc_errors + ch->stats.crypto_errors);
            json_object_object_add(rt, "errors", json_object_new_int64(errs));
        }
        json_object_object_add(rt, "last_active_sec", json_object_new_int64(
            (int64_t)time_elapsed(ch->last_active)));
        json_object_object_add(rt, "uptime_sec", json_object_new_int64(
            (int64_t)time_elapsed(ch->created_at)));
        json_object_object_add(obj, "runtime", rt);
    }

    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(obj);
}

/* ──── GET /api/v1/metrics ──────────────────────────────────────────
 * Prometheus text 格式输出，提供面向监控系统的指标端点。
 */
static void api_handle_metrics(struct mg_connection *c, struct mg_http_message *hm)
{
    (void)hm;

    /* 收集所有通道统计 */
    uint64_t total_tx_frames = 0, total_rx_frames = 0;
    uint64_t total_tx_bytes = 0, total_rx_bytes = 0;
    uint64_t total_retrans = 0, total_errors = 0;
    int active_channels = 0;

    for (uint32_t b = 0; b < api_ctx->channel_hash_size; b++) {
        channel_t *ch = api_ctx->channel_hash[b];
        while (ch) {
            total_tx_frames += ch->stats.tx_frames;
            total_rx_frames += ch->stats.rx_frames;
            total_tx_bytes  += ch->stats.tx_bytes;
            total_rx_bytes  += ch->stats.rx_bytes;
            total_retrans   += ch->stats.retransmits;
            total_errors    += ch->stats.tx_errors + ch->stats.rx_errors +
                               ch->stats.crc_errors + ch->stats.crypto_errors;
            active_channels++;
            ch = ch->hash_next;
        }
    }

    int64_t uptime = (int64_t)time_elapsed(api_ctx->start_time);

    /* 构建 Prometheus text 输出 */
    char buf[4096];
    int off = 0;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_channels_active Number of active channels\n"
        "# TYPE gapproxy_channels_active gauge\n"
        "gapproxy_channels_active %d\n\n", active_channels);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_tx_frames_total Total transmitted frames\n"
        "# TYPE gapproxy_tx_frames_total counter\n"
        "gapproxy_tx_frames_total %llu\n\n",
        (unsigned long long)total_tx_frames);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_rx_frames_total Total received frames\n"
        "# TYPE gapproxy_rx_frames_total counter\n"
        "gapproxy_rx_frames_total %llu\n\n",
        (unsigned long long)total_rx_frames);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_tx_bytes_total Total transmitted bytes\n"
        "# TYPE gapproxy_tx_bytes_total counter\n"
        "gapproxy_tx_bytes_total %llu\n\n",
        (unsigned long long)total_tx_bytes);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_rx_bytes_total Total received bytes\n"
        "# TYPE gapproxy_rx_bytes_total counter\n"
        "gapproxy_rx_bytes_total %llu\n\n",
        (unsigned long long)total_rx_bytes);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_retransmits_total Total retransmissions\n"
        "# TYPE gapproxy_retransmits_total counter\n"
        "gapproxy_retransmits_total %llu\n\n",
        (unsigned long long)total_retrans);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_errors_total Total errors\n"
        "# TYPE gapproxy_errors_total counter\n"
        "gapproxy_errors_total %llu\n\n",
        (unsigned long long)total_errors);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_nic_rx_packets NIC received packets\n"
        "# TYPE gapproxy_nic_rx_packets counter\n"
        "gapproxy_nic_rx_packets %llu\n\n",
        (unsigned long long)api_ctx->nic.rx_packets);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_nic_tx_packets NIC transmitted packets\n"
        "# TYPE gapproxy_nic_tx_packets counter\n"
        "gapproxy_nic_tx_packets %llu\n\n",
        (unsigned long long)api_ctx->nic.tx_packets);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_uptime_seconds Process uptime in seconds\n"
        "# TYPE gapproxy_uptime_seconds gauge\n"
        "gapproxy_uptime_seconds %lld\n\n",
        (long long)uptime);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    off += snprintf(buf + off, sizeof(buf) - off,
        "# HELP gapproxy_workers_count Number of managed workers\n"
        "# TYPE gapproxy_workers_count gauge\n"
        "gapproxy_workers_count %d\n\n",
        api_ctx->mgmt.worker_count);
    if (off < 0 || (size_t)off >= sizeof(buf) - 512) goto metrics_done;

    /* 按 channel_id 标签输出各通道指标 */
    for (uint32_t b = 0; b < api_ctx->channel_hash_size; b++) {
        channel_t *ch = api_ctx->channel_hash[b];
        while (ch) {
            off += snprintf(buf + off, sizeof(buf) - off,
                "gapproxy_tx_frames_total{channel_id=\"%u\"} %llu\n",
                ch->channel_id, (unsigned long long)ch->stats.tx_frames);
            off += snprintf(buf + off, sizeof(buf) - off,
                "gapproxy_rx_frames_total{channel_id=\"%u\"} %llu\n",
                ch->channel_id, (unsigned long long)ch->stats.rx_frames);
            off += snprintf(buf + off, sizeof(buf) - off,
                "gapproxy_tx_bytes_total{channel_id=\"%u\"} %llu\n",
                ch->channel_id, (unsigned long long)ch->stats.tx_bytes);
            off += snprintf(buf + off, sizeof(buf) - off,
                "gapproxy_rx_bytes_total{channel_id=\"%u\"} %llu\n",
                ch->channel_id, (unsigned long long)ch->stats.rx_bytes);
            off += snprintf(buf + off, sizeof(buf) - off,
                "gapproxy_retransmits_total{channel_id=\"%u\"} %llu\n",
                ch->channel_id, (unsigned long long)ch->stats.retransmits);
            {
                uint64_t cerr = ch->stats.tx_errors + ch->stats.rx_errors +
                                ch->stats.crc_errors + ch->stats.crypto_errors;
                off += snprintf(buf + off, sizeof(buf) - off,
                    "gapproxy_errors_total{channel_id=\"%u\"} %llu\n",
                    ch->channel_id, (unsigned long long)cerr);
            }
            if ((size_t)off >= sizeof(buf) - 512) break; /* 缓冲区保护 */
            ch = ch->hash_next;
        }
        if ((size_t)off >= sizeof(buf) - 512) break;
    }

metrics_done:
    mg_http_reply(c, 200, "Content-Type: text/plain; charset=utf-8\r\n",
                  "%s", buf);
}

/* ──── POST /api/v1/config/switch ────────────────────────────────────
 * 向指定 Worker 发送配置切换指令，触发其 master 进程重载 kcp-multi.json。
 *
 * 请求体（JSON）：
 *   { "target_node_id": "<Worker的node_id>", "config_path": "/path/to/kcp-multi.json" }
 *
 * 仅 Manager 角色可调用（Worker 拒绝写操作）。
 *
 * 流程：
 *   1. 校验 Manager 角色 + 写保护
 *   2. 解析 target_node_id / config_path
 *   3. 校验 target 是否在注册表中且状态为 ACTIVE
 *   4. 调用 mgmt_send_instance_command("CONFIG_SWITCH", ...)
 *   5. 返回 202 Accepted（异步操作，结果通过 SWITCH_ACK 异步返回）
 *
 * 注意：本端点仅触发切换，不等待 Worker 侧完成。
 *       Worker 的 master_graceful_reload 可能耗时数百毫秒，
 *       调用方应通过 GET /api/v1/nodes/<id> 轮询 Worker 状态
 *       或监听 SWITCH_ACK（需 P0-2 ACK handler 支持）。
 */
static void api_handle_config_switch(struct mg_connection *c, struct mg_http_message *hm)
{
    if (!api_check_write_access(c)) return;

    /* Worker 校验（仅 Manager 可下发指令） */
    if (!api_ctx || api_ctx->config.node.node_role != NODE_ROLE_MANAGER) {
        mg_http_reply(c, 403, "",
            "{\"status\":\"error\",\"message\":\"Only manager can switch config\"}\n");
        return;
    }

    /* 解析 JSON body */
    struct json_object *body = json_tokener_parse(hm->body.buf);
    if (!body) {
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Invalid JSON\"}\n");
        return;
    }

    json_object *j_target = json_object_object_get(body, "target_node_id");
    json_object *j_path   = json_object_object_get(body, "config_path");

    const char *target_node_id = j_target ? json_object_get_string(j_target) : NULL;
    const char *config_path    = j_path   ? json_object_get_string(j_path)   : NULL;

    if (!target_node_id || target_node_id[0] == '\0' ||
        !config_path    || config_path[0]    == '\0') {
        json_object_put(body);
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Missing target_node_id or config_path\"}\n");
        return;
    }
    if (strstr(config_path, "..")) {
        json_object_put(body);
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"config_path must not contain '..'\"}\n");
        return;
    }

    /* 校验 config_path 仅含安全字符，防止 JSON 注入 */
    {
        const char *cp = config_path;
        while (*cp) {
            if (!((*cp >= 'a' && *cp <= 'z') ||
                  (*cp >= 'A' && *cp <= 'Z') ||
                  (*cp >= '0' && *cp <= '9') ||
                  *cp == '/' || *cp == '.' || *cp == '-' || *cp == '_')) {
                json_object_put(body);
                mg_http_reply(c, 400, "",
                    "{\"status\":\"error\",\"message\":\"config_path contains invalid characters\"}\n");
                return;
            }
            cp++;
        }
        if ((size_t)(cp - config_path) > MAX_CONFIG_PATH - 1) {
            json_object_put(body);
            mg_http_reply(c, 400, "",
                "{\"status\":\"error\",\"message\":\"config_path too long\"}\n");
            return;
        }
    }

    /* 校验 target 是否在注册表中 */
    mgmt_worker_t *w = NULL;
    for (int i = 0; i < api_ctx->mgmt.worker_count; i++) {
        if (strcmp(api_ctx->mgmt.workers[i].node_id, target_node_id) == 0) {
            w = &api_ctx->mgmt.workers[i];
            break;
        }
    }
    if (!w) {
        json_object_put(body);
        mg_http_reply(c, 404, "",
            "{\"status\":\"error\",\"message\":\"Target worker not found\"}\n");
        return;
    }
    if (w->state != MGMT_WORKER_STATE_ACTIVE) {
        json_object_put(body);
        mg_http_reply(c, 503, "",
            "{\"status\":\"error\",\"message\":\"Target worker not active\"}\n");
        return;
    }

    /* 序列化 payload: {"config_path":"..."} */
    char payload[512];
    int plen = snprintf(payload, sizeof(payload),
        "\"config_path\":\"%s\"", config_path);
    if (plen < 0 || plen >= (int)sizeof(payload)) {
        json_object_put(body);
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"config_path too long\"}\n");
        return;
    }

    int ret = mgmt_send_instance_command(api_ctx, "CONFIG_SWITCH",
                                          target_node_id, payload);
    json_object_put(body);

    if (ret < 0) {
        mg_http_reply(c, 500, "",
            "{\"status\":\"error\",\"message\":\"Failed to send command\"}\n");
    } else {
        mg_http_reply(c, 202, "Content-Type: application/json\r\n",
            "{\"status\":\"accepted\",\"target\":\"%s\",\"seq\":%llu}\n",
            target_node_id, (unsigned long long)api_ctx->mgmt.mgmt_seq);
    }
}

/* ──── POST /api/v1/instances/spawn ───────────────────────────────
 * 向指定 Worker 发送 SPAWN_INSTANCE 指令，远程创建新 Worker 进程。
 *
 * 请求体（JSON）：
 *   {
 *     "target":         "<Worker 的 node_id>",
 *     "instance_name":  "frontend-web",
 *     "ethertype":      34998,
 *     "node_type":      "frontend" | "backend",
 *     "cpu_affinity":   0,
 *     "channels":       [ ... ]
 *   }
 *
 * 仅 Manager 角色可调用。Worker 拒绝写操作。
 * 返回 202 Accepted（异步，结果通过 SPAWN_ACK 返回）。
 */
static void api_handle_instance_spawn(struct mg_connection *c, struct mg_http_message *hm)
{
    if (!api_check_write_access(c)) return;
    if (!api_ctx || api_ctx->config.node.node_role != NODE_ROLE_MANAGER) {
        mg_http_reply(c, 403, "",
            "{\"status\":\"error\",\"message\":\"Only manager can spawn instances\"}\n");
        return;
    }
    if (hm->body.len == 0 || hm->body.len > 65535) {
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Body too large\"}\n");
        return;
    }

    /* 解析并校验必填字段 */
    struct json_object *body = json_tokener_parse(hm->body.buf);
    if (!body) {
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Invalid JSON\"}\n");
        return;
    }

    json_object *j_target = json_object_object_get(body, "target");
    json_object *j_name   = json_object_object_get(body, "instance_name");
    json_object *j_eth    = json_object_object_get(body, "ethertype");

    const char *target       = j_target ? json_object_get_string(j_target) : NULL;
    const char *instance_name = j_name   ? json_object_get_string(j_name)   : NULL;

    if (!target || target[0] == '\0' ||
        !instance_name || instance_name[0] == '\0') {
        json_object_put(body);
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Missing target or instance_name\"}\n");
        return;
    }
    if (strlen(instance_name) > 63) {
        json_object_put(body);
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"instance_name too long\"}\n");
        return;
    }

    /* 校验 ethertype 范围 */
    if (j_eth) {
        int eth = json_object_get_int(j_eth);
        if (eth < 0x0600 || eth > 0xFFFF) {
            json_object_put(body);
            mg_http_reply(c, 400, "",
                "{\"status\":\"error\",\"message\":\"ethertype must be 0x0600-0xFFFF\"}\n");
            return;
        }
    }

    /* payload = 整个请求体（去除外层后就是 SPAWN_INSTANCE 的 payload） */
    const char *payload_str = json_object_to_json_string(body);
    int ret = mgmt_send_instance_command(api_ctx, "SPAWN_INSTANCE",
                                          target, payload_str);
    if (ret < 0) {
        json_object_put(body);
        mg_http_reply(c, 500, "",
            "{\"status\":\"error\",\"message\":\"Failed to send SPAWN command\"}\n");
    } else {
        /* 追踪实例：在 json_object_put 前提取所有字段 */
        json_object *j_nt = json_object_object_get(body, "node_type");
        json_object *j_ca = json_object_object_get(body, "cpu_affinity");
        int eth = j_eth ? json_object_get_int(j_eth) : 0x0600;
        int ca  = j_ca ? json_object_get_int(j_ca) : -1;
        const char *nt = j_nt ? json_object_get_string(j_nt) : "frontend";

        /* 提取 channels 用于持久化 */
        char channels_json[4096] = {0};
        json_object *jch = json_object_object_get(body, "channels");
        if (jch) {
            const char *chs = json_object_to_json_string(jch);
            if (chs) { strncpy(channels_json, chs, 4095); channels_json[4095] = '\0'; }
            /* M12: strncpy + 显式 '\0' 终止确保无缓冲区溢出，正确 */
        }

        json_object_put(body);

        mgmt_track_spawned_instance(api_ctx, target, instance_name,
                                     (uint16_t)eth, nt, ca, channels_json);
        mg_http_reply(c, 202, "Content-Type: application/json\r\n",
            "{\"status\":\"accepted\",\"instance\":\"%s\",\"target\":\"%s\"}\n",
            instance_name, target);
    }
}

/* ──── POST /api/v1/instances/spawn-batch ──────────────────────────
 * 批量 SPAWN：all-or-nothing 事务语义。
 *
 * 流程:
 *   1. 解析 targets[] 和 channels/ethertype 等共享配置
 *   2. 注册 pending op
 *   3. 向所有 target 并行发送 SPAWN_INSTANCE
 *   4. 非阻塞轮询等待全部 ACK (最长 PENDING_TIMEOUT_SEC 秒)
 *   5. 全部成功 → mgmt_persist_dynamic_instances + 200
 *   6. 任一失败/超时 → 向已成功的发送 KILL 回退 + 500
 * ────────────────────────────────────────────────────────────────── */
static void api_handle_instance_spawn_batch(struct mg_connection *c,
                                            struct mg_http_message *hm)
{
    if (api_ctx->config.node.node_role != NODE_ROLE_MANAGER) {
        mg_http_reply(c, 403, "",
            "{\"status\":\"error\",\"message\":\"Only manager can spawn instances\"}\n");
        return;
    }

    char jbuf[16384] = {0};
    int blen = (int)hm->body.len;
    if (blen <= 0 || blen >= (int)sizeof(jbuf) - 1) {
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Invalid JSON body\"}\n");
        return;
    }
    memcpy(jbuf, hm->body.buf, (size_t)blen);
    struct json_object *body = json_tokener_parse(jbuf);
    if (!body) {
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Invalid JSON\"}\n");
        return;
    }

    /* 解析 targets — 必须是数组 */
    struct json_object *j_targets = json_object_object_get(body, "targets");
    if (!j_targets || !json_object_is_type(j_targets, json_type_array)) {
        json_object_put(body);
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"'targets' array required\"}\n");
        return;
    }
    int n_targets = json_object_array_length(j_targets);
    if (n_targets <= 0 || n_targets > PENDING_OP_TARGET_MAX) {
        json_object_put(body);
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"targets count 1-%d\"}\n",
            PENDING_OP_TARGET_MAX);
        return;
    }

    /* 收集 target node_id 字符串（需拷贝，body 会 json_object_put） */
    char target_ids[PENDING_OP_TARGET_MAX][65];
    const char *targets[PENDING_OP_TARGET_MAX];
    int targets_seq[PENDING_OP_TARGET_MAX];
    memset(targets_seq, -1, sizeof(targets_seq));
    for (int i = 0; i < n_targets; i++) {
        struct json_object *jt = json_object_array_get_idx(j_targets, i);
        const char *s = json_object_get_string(jt);
        if (s) { strncpy(target_ids[i], s, 64); target_ids[i][64] = '\0'; }
        else   { target_ids[i][0] = '\0'; }
        targets[i] = target_ids[i];
    }

    /* 提取共享配置（在 json_object_put 之前） */
    struct json_object *j_eth = json_object_object_get(body, "ethertype");
    struct json_object *j_ch  = json_object_object_get(body, "channels");
    int eth = 0x0600;
    if (j_eth) eth = json_object_get_int(j_eth);
    const char *nt_default = "frontend";
    struct json_object *j_nt = json_object_object_get(body, "node_type");
    if (j_nt) nt_default = json_object_get_string(j_nt);
    char node_type[32];
    strncpy(node_type, nt_default ? nt_default : "frontend", 31);
    node_type[31] = '\0';

    int cpu_aff = -1;
    struct json_object *j_ca = json_object_object_get(body, "cpu_affinity");
    if (j_ca) cpu_aff = json_object_get_int(j_ca);

    char channels_json[4096] = {0};
    if (j_ch) {
        const char *chs = json_object_to_json_string(j_ch);
        if (chs) { strncpy(channels_json, chs, 4095); channels_json[4095] = '\0'; }
    }

    /* 对每个 target 发送 SPAWN_INSTANCE，并记录 seq */
    int base_seq = 0;
    for (int i = 0; i < n_targets; i++) {
        const char *pl = json_object_to_json_string(body);
        int ret = mgmt_send_instance_command(api_ctx, "SPAWN_INSTANCE",
                                              targets[i], pl);
        if (ret < 0) {
            json_object_put(body);
            mg_http_reply(c, 500, "",
                "{\"status\":\"error\",\"message\":\"Failed to send to %s\"}\n",
                targets[i]);
            return;
        }
        /* 记录 seq: mgmt_seq 刚被 mgmt_build_prefix 递增 */
        if (i == 0) base_seq = (int)(api_ctx->mgmt.mgmt_seq - 1);
        targets_seq[i] = base_seq + i;
    }
    json_object_put(body);

    /* 注册 pending op — 在此之后 SPAWN_ACK 会被自动路由 */
    int op_id = mgmt_pending_register_spawn(api_ctx, targets,
                                            n_targets, channels_json,
                                            targets_seq);
    if (op_id < 0) {
        mg_http_reply(c, 503, "",
            "{\"status\":\"error\",\"message\":\"Too many pending operations\"}\n");
        return;
    }

    /* 非阻塞轮询等待全部 ACK */
    time_t deadline = time(NULL) + PENDING_TIMEOUT_SEC;
    pending_op_t *op = &api_ctx->mgmt.pending_ops[op_id];

    while (time(NULL) < deadline) {
        mg_mgr_poll((struct mg_mgr *)api_ctx->mg_mgr, 100);  /* 100ms 让 Mongoose 处理 ACK */
        if (op->n_done >= op->n_targets) break;
    }

    /* 判断结果 */
    if (op->n_success == op->n_targets) {
        /* 全部成功 → 持久化 */
        for (int i = 0; i < n_targets; i++) {
            char iname[128];
            snprintf(iname, sizeof(iname), "%s-%d", targets[i], op_id);
            mgmt_track_spawned_instance(api_ctx, targets[i], iname,
                                         (uint16_t)eth, node_type, cpu_aff,
                                         channels_json);
        }
        mgmt_persist_dynamic_instances(api_ctx);
        mgmt_pending_release(api_ctx, op_id);

        mg_http_reply(c, 200, "Content-Type: application/json\r\n",
            "{\"status\":\"ok\",\"targets\":%d,\"spawned\":%d}\n",
            n_targets, op->n_success);
    } else {
        /* 部分失败或超时 → 回退已成功的 */
        fprintf(stderr, "[ERROR] SPAWN_BATCH[%d]: partial failure (%d/%d)\n",
                op_id, op->n_success, op->n_targets);

        for (int i = 0; i < n_targets; i++) {
            if (op->targets[i].acked && op->targets[i].success) {
                fprintf(stderr, "[INFO] SPAWN_BATCH: killing %s (rollback)\n",
                        targets[i]);
                char kill_payload[256];
                snprintf(kill_payload, sizeof(kill_payload),
                         "{\"instance_name\":\"batch-%d\",\"ethertype\":%d}",
                         op_id, eth);
                mgmt_send_instance_command(api_ctx, "KILL_INSTANCE",
                                            targets[i], kill_payload);
            }
        }
        mgmt_pending_release(api_ctx, op_id);

        char detail[256];
        snprintf(detail, sizeof(detail),
                 "{\"status\":\"error\",\"message\":\"%d/%d targets failed\","
                 "\"success\":%d,\"failed\":%d}",
                 op->n_targets - op->n_success, op->n_targets,
                 op->n_success, op->n_targets - op->n_success);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
            "%s\n", detail);
    }
}

/* ──── POST /api/v1/instances/channels ──────────────────────────────
 * 永久删除 SPAWN Worker 实例的静态通道。
 */
static void api_handle_instance_channels(struct mg_connection *c,
                                          struct mg_http_message *hm)
{
	if (!api_check_write_access(c)) return;

	if (mg_strcmp(mg_str("POST"), hm->method) != 0) {
		mg_http_reply(c, 405, "",
			"{\"status\":\"error\",\"message\":\"Method Not Allowed\"}\n");
		return;
	}
	/* 防止恶意超大 body 耗尽内存 — 65535 与 MGMT_MSG_MAX_LEN 对齐 */
	if (hm->body.len > 65535) {
		mg_http_reply(c, 413, "",
			"{\"status\":\"error\",\"message\":\"Payload Too Large\"}\n");
		return;
	}
	struct json_object *body = json_tokener_parse(hm->body.buf);
	if (!body) {
		mg_http_reply(c, 400, "",
			"{\"status\":\"error\",\"message\":\"Invalid JSON\"}\n");
		return;
	}
	json_object *j_target = json_object_object_get(body, "target");
	json_object *j_iname  = json_object_object_get(body, "instance_name");
	json_object *j_chid   = json_object_object_get(body, "channel_id");
	json_object *j_op     = json_object_object_get(body, "op");
	const char *target        = j_target ? json_object_get_string(j_target) : NULL;
	const char *instance_name = j_iname  ? json_object_get_string(j_iname)  : NULL;
	int         channel_id    = j_chid   ? json_object_get_int(j_chid)      : 0;
	const char *op            = j_op     ? json_object_get_string(j_op)     : "del";
	/* 白名单校验: 当前仅支持 "del" 操作 */
	if (strcmp(op, "del") != 0) {
		json_object_put(body);
		mg_http_reply(c, 400, "",
			"{\"status\":\"error\",\"message\":\"Unsupported operation\"}\n");
		return;
	}
	if (!target || target[0] == '\0' || !instance_name || instance_name[0] == '\0') {
		json_object_put(body);
		mg_http_reply(c, 400, "",
			"{\"status\":\"error\",\"message\":\"Missing target or instance_name\"}\n");
		return;
	}
	if (channel_id == 0) {
		json_object_put(body);
		mg_http_reply(c, 400, "",
			"{\"status\":\"error\",\"message\":\"channel_id must be > 0\"}\n");
		return;
	}
	int ret = mgmt_instance_channel_ctl(api_ctx, target, instance_name,
	                                     channel_id, op,
	                                     json_object_to_json_string(body));
	json_object_put(body);
	if (ret == 0)
		mg_http_reply(c, 200, "Content-Type: application/json\r\n",
			"{\"status\":\"ok\",\"instance\":\"%s\",\"channel_id\":%d}\n",
			instance_name, channel_id);
	else
		mg_http_reply(c, 404, "",
			"{\"status\":\"error\",\"message\":\"Instance not found\"}\n");
}

/* ──── POST /api/v1/instances/kill ─────────────────────────────────
 * 向指定 Worker 发送 KILL_INSTANCE 指令，远程终止 Worker 进程。
 *
 * 请求体（JSON）：
 *   { "target": "<Worker 的 node_id>", "instance_name": "frontend-web" }
 *
 * 仅 Manager 角色可调用。
 * 返回 202 Accepted（异步，结果通过 KILL_ACK 返回）。
 */
static void api_handle_instance_kill(struct mg_connection *c, struct mg_http_message *hm)
{
    if (!api_check_write_access(c)) return;
    if (!api_ctx || api_ctx->config.node.node_role != NODE_ROLE_MANAGER) {
        mg_http_reply(c, 403, "",
            "{\"status\":\"error\",\"message\":\"Only manager can kill instances\"}\n");
        return;
    }

    struct json_object *body = json_tokener_parse(hm->body.buf);
    if (!body) {
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Invalid JSON\"}\n");
        return;
    }

    json_object *j_target = json_object_object_get(body, "target");
    json_object *j_name   = json_object_object_get(body, "instance_name");
    json_object *j_eth    = json_object_object_get(body, "ethertype");

    const char *target       = j_target ? json_object_get_string(j_target) : NULL;
    const char *instance_name = j_name   ? json_object_get_string(j_name)   : NULL;
    int         ethertype     = j_eth    ? (int)json_object_get_int(j_eth)  : 0;

    if (!target || target[0] == '\0' ||
        !instance_name || instance_name[0] == '\0') {
        json_object_put(body);
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Missing target or instance_name\"}\n");
        return;
    }

    /* ethertype 必填: Master 侧按 ethertype 匹配 Worker 子进程 */
    if (ethertype == 0) {
        json_object_put(body);
        mg_http_reply(c, 400, "",
            "{\"status\":\"error\",\"message\":\"Missing or invalid ethertype\"}\n");
        return;
    }

    int ret = mgmt_send_instance_command(api_ctx, "KILL_INSTANCE",
                                          target, json_object_to_json_string(body));
    json_object_put(body);

    if (ret < 0) {
        mg_http_reply(c, 500, "",
            "{\"status\":\"error\",\"message\":\"Failed to send KILL command\"}\n");
    } else {
        mgmt_untrack_spawned_instance(api_ctx, target, instance_name);
        mg_http_reply(c, 202, "Content-Type: application/json\r\n",
            "{\"status\":\"accepted\",\"instance\":\"%s\",\"target\":\"%s\"}\n",
            instance_name, target);
    }
}

/* ──── GET /api/v1/config/version ──────────────────────────────────
 * 返回当前配置版本号（用于 Worker 确认是否落后于 Manager）。
 */

/* ============================================================================
 * 通道 CRUD 辅助函数
 * ============================================================================
 *
 * 通道操作通过操作哈希表（channel_hash）和全局配置数组（config.channels[]）
 * 完成。创建/更新/删除是同步的，返回时已生效。
 * ============================================================================
 */

/*
 * api_list_channels — 列出所有通道
 *
 * 遍历全局通道哈希表，返回每个通道的配置和运行时统计。
 */
static void api_list_channels(struct mg_connection *c, struct mg_http_message *hm)
{
    (void)hm;
    json_object *arr = json_object_new_array();

    for (uint32_t b = 0; b < api_ctx->channel_hash_size; b++) {
        channel_t *ch = api_ctx->channel_hash[b];
        while (ch) {
            json_object *obj = json_object_new_object();
            json_object_object_add(obj, "channel_id",  json_object_new_int(ch->channel_id));
            json_object_object_add(obj, "state",       json_object_new_string(
                ch->state == CHANNEL_ESTABLISHED ? "ESTABLISHED" :
                ch->state == CHANNEL_SYN_SENT   ? "SYN_SENT" :
                ch->state == CHANNEL_SYN_RCVD   ? "SYN_RCVD" :
                ch->state == CHANNEL_CLOSED     ? "CLOSED" : "UNKNOWN"));

            json_object_object_add(obj, "listen_port", json_object_new_int(ch->listen_port));
            json_object_object_add(obj, "remote_port", json_object_new_int(ch->remote_port));
            json_object_object_add(obj, "listen_addr", json_object_new_string(ch->listen_addr));
            json_object_object_add(obj, "remote_addr", json_object_new_string(ch->remote_addr));
            json_object_object_add(obj, "is_tcp",      json_object_new_boolean(ch->is_tcp));

            /* 从配置中读取 max_sessions */
            int ms = 1;
            if ((ch->flags & CH_FLAG_STATIC_LISTENER) &&
                ch->listener_idx < api_ctx->config.channel_count) {
                ms = api_ctx->config.channels[ch->listener_idx].max_sessions;
            }
            json_object_object_add(obj, "max_sessions", json_object_new_int(ms));

            /* 附加运行时统计 */
            json_object_object_add(obj, "tx_frames",    json_object_new_int64((int64_t)ch->stats.tx_frames));
            json_object_object_add(obj, "rx_frames",    json_object_new_int64((int64_t)ch->stats.rx_frames));
            json_object_object_add(obj, "retransmits",  json_object_new_int64((int64_t)ch->stats.retransmits));

            /* 新增: cb_open (断路器状态) */
            json_object_object_add(obj, "cb_open", json_object_new_boolean(
                api_ctx->cb_open[ch->channel_id] != 0));

            /* 新增: active (是否有对应运行时通道) — 哈希表中存在即 active */
            json_object_object_add(obj, "active", json_object_new_boolean(1));

            json_object_array_add(arr, obj);
            ch = ch->hash_next;
        }
    }

    const char *s = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(arr);
}

/*
 * api_create_channel — 创建新通道
 *
 * 从 POST body 中解析通道配置 → 分配 channel_id → 创建通道 → 启动监听。
 * 需要 Manager 角色。
 */
static void api_create_channel(struct mg_connection *c, struct mg_http_message *hm)
{
    if (!api_check_write_access(c)) return;

    /* 解析 JSON body */
    struct json_object *body = json_tokener_parse(hm->body.buf);
    if (!body) {
        mg_http_reply(c, 400, "", "{\"status\":\"error\",\"message\":\"Invalid JSON\"}\n");
        return;
    }

    /* 提取参数（带默认值） */
    json_object *j_chid = json_object_object_get(body, "channel_id");
    json_object *j_lp   = json_object_object_get(body, "listen_port");
    json_object *j_rp   = json_object_object_get(body, "remote_port");
    json_object *j_ra   = json_object_object_get(body, "remote_addr");
    json_object *j_la   = json_object_object_get(body, "listen_addr");
    json_object *j_tcp  = json_object_object_get(body, "is_tcp");
    json_object *j_sp   = json_object_object_get(body, "source_port");

    uint32_t channel_id = j_chid ? (uint32_t)json_object_get_int(j_chid) : 0;
    int listen_port     = j_lp   ? json_object_get_int(j_lp)   : 0;
    int remote_port     = j_rp   ? json_object_get_int(j_rp)   : 0;
    const char *raddr   = j_ra   ? json_object_get_string(j_ra) : NULL;
    const char *laddr   = j_la   ? json_object_get_string(j_la) : NULL;
    int is_tcp          = j_tcp  ? json_object_get_boolean(j_tcp) : 0;
    int source_port     = j_sp   ? json_object_get_int(j_sp)   : 0;
    int max_sessions     = 1;

    json_object *j_ms = json_object_object_get(body, "max_sessions");
    if (j_ms) {
        int ms = json_object_get_int(j_ms);
        if (ms > 0 && ms <= 256) max_sessions = ms;
    }

    if (!raddr) raddr = "0.0.0.0";
    if (!laddr) laddr = "127.0.0.1";
    if (listen_port <= 0 || remote_port <= 0 || channel_id == 0) {
        json_object_put(body);
        mg_http_reply(c, 400, "", "{\"status\":\"error\",\"message\":\"Missing required fields\"}\n");
        return;
    }

    /* 检查 channel_id 是否已被占用 */
    if (channel_find(api_ctx, channel_id)) {
        json_object_put(body);
        mg_http_reply(c, 409, "", "{\"status\":\"error\",\"message\":\"Channel ID conflict\"}\n");
        return;
    }

    /* 追加到全局 channels[] 配置数组 */
    if (api_ctx->config.channel_count >= MAX_CHANNELS) {
        json_object_put(body);
        mg_http_reply(c, 507, "", "{\"status\":\"error\",\"message\":\"Channel limit reached\"}\n");
        return;
    }

    channel_config_t *cfg = &api_ctx->config.channels[api_ctx->config.channel_count++];
    memset(cfg, 0, sizeof(*cfg));
    cfg->channel_id   = channel_id;
    cfg->listen_port  = (uint16_t)listen_port;
    cfg->remote_port  = (uint16_t)remote_port;
    cfg->is_tcp       = (uint8_t)is_tcp;
    cfg->source_port  = (uint16_t)source_port;
    cfg->max_sessions = (uint16_t)max_sessions;
    cfg->enabled      = 1;
    strncpy(cfg->remote_addr, raddr, MAX_LISTEN_ADDR - 1);
    strncpy(cfg->listen_addr, laddr, MAX_LISTEN_ADDR - 1);
    cfg->remote_addr[MAX_LISTEN_ADDR - 1] = '\0';
    cfg->listen_addr[MAX_LISTEN_ADDR - 1] = '\0';

    json_object_put(body);

    /* 创建运行时通道 */
    channel_t *new_ch = channel_create(api_ctx, channel_id, CHANNEL_ROLE_LISTENER,
        cfg->listen_port, cfg->remote_port, cfg->source_port,
        cfg->listen_addr, cfg->remote_addr, cfg->is_tcp);
    if (!new_ch) {
        api_ctx->config.channel_count--;
        mg_http_reply(c, 500, "", "{\"status\":\"error\",\"message\":\"Channel creation failed\"}\n");
        return;
    }

    /* 复制网络层参数 */
    new_ch->raw_sock  = api_ctx->raw_sock;
    new_ch->ifindex   = api_ctx->ifindex;
    new_ch->ethertype = api_ctx->config.ethertype;
    memcpy(new_ch->local_mac, api_ctx->local_mac, ETH_MAC_ADDR_LEN);
    memcpy(new_ch->peer_mac,  api_ctx->peer_mac,  ETH_MAC_ADDR_LEN);
    new_ch->flags    |= CH_FLAG_STATIC_LISTENER;
    new_ch->listener_idx = (uint8_t)(api_ctx->config.channel_count - 1);

    /* 启动代理监听 */
    if (api_ctx->config.node_type == NODE_TYPE_FRONTEND) {
        if (proxy_start_listen(api_ctx, new_ch) != 0) {
            channel_destroy(api_ctx, new_ch);
            api_ctx->config.channel_count--;
            mg_http_reply(c, 500, "", "{\"status\":\"error\",\"message\":\"Listen start failed\"}\n");
            return;
        }
    }

    mg_http_reply(c, 201, "",
        "{\"status\":\"ok\",\"channel_id\":%u}\n", channel_id);

    /* Manager: push updated config */
    if (api_ctx->config.node.node_role == NODE_ROLE_MANAGER) {
        api_ctx->mgmt.config_version++;
        mgmt_push_config_to_all(api_ctx, NULL);
    }
}

/*
 * api_get_channel — 获取单个通道详情
 *
 * @param channel_id 通道标识符
 */
static void api_get_channel(struct mg_connection *c, uint32_t channel_id)
{
    channel_t *ch = channel_find(api_ctx, channel_id);
    if (!ch) {
        mg_http_reply(c, 404, "", "{\"status\":\"error\",\"message\":\"Channel not found\"}\n");
        return;
    }

    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "channel_id",  json_object_new_int(ch->channel_id));
    json_object_object_add(obj, "state",       json_object_new_string(
        ch->state == CHANNEL_ESTABLISHED ? "ESTABLISHED" :
        ch->state == CHANNEL_SYN_SENT   ? "SYN_SENT"    :
        ch->state == CHANNEL_SYN_RCVD   ? "SYN_RCVD"    : "CLOSED"));
    json_object_object_add(obj, "listen_port", json_object_new_int(ch->listen_port));
    json_object_object_add(obj, "remote_port", json_object_new_int(ch->remote_port));
    json_object_object_add(obj, "listen_addr", json_object_new_string(ch->listen_addr));
    json_object_object_add(obj, "remote_addr", json_object_new_string(ch->remote_addr));
    json_object_object_add(obj, "is_tcp",      json_object_new_boolean(ch->is_tcp));
    json_object_object_add(obj, "tx_frames",   json_object_new_int64((int64_t)ch->stats.tx_frames));
    json_object_object_add(obj, "rx_frames",   json_object_new_int64((int64_t)ch->stats.rx_frames));
    json_object_object_add(obj, "retransmits", json_object_new_int64((int64_t)ch->stats.retransmits));
    json_object_object_add(obj, "flags",       json_object_new_int(ch->flags));
    json_object_object_add(obj, "dynamic_channels", json_object_new_int(0)); /* 简化：未统计子通道 */

    /* 新增: runtime 运行时统计段 */
    {
        json_object *rt = json_object_new_object();
        json_object_object_add(rt, "state", json_object_new_string(
            ch->state == CHANNEL_ESTABLISHED ? "ESTABLISHED" :
            ch->state == CHANNEL_SYN_SENT   ? "SYN_SENT"    :
            ch->state == CHANNEL_SYN_RCVD   ? "SYN_RCVD"    : "CLOSED"));
        {
            int rtt = 0, cw = 0, sw = 0;
            if (ch->kcp) {
                rtt = (int)ch->kcp->rx_srtt;
                cw  = (int)ch->kcp->cwnd;
                sw  = (int)ch->kcp->snd_wnd;
            }
            json_object_object_add(rt, "rtt_ms",  json_object_new_int(rtt));
            json_object_object_add(rt, "cwnd",    json_object_new_int(cw));
            json_object_object_add(rt, "snd_wnd", json_object_new_int(sw));
        }
        json_object_object_add(rt, "tx_frames",    json_object_new_int64((int64_t)ch->stats.tx_frames));
        json_object_object_add(rt, "rx_frames",    json_object_new_int64((int64_t)ch->stats.rx_frames));
        json_object_object_add(rt, "tx_bytes",     json_object_new_int64((int64_t)ch->stats.tx_bytes));
        json_object_object_add(rt, "rx_bytes",     json_object_new_int64((int64_t)ch->stats.rx_bytes));
        json_object_object_add(rt, "retransmits",  json_object_new_int64((int64_t)ch->stats.retransmits));
        {
            int64_t errs = (int64_t)(ch->stats.tx_errors + ch->stats.rx_errors +
                                     ch->stats.crc_errors + ch->stats.crypto_errors);
            json_object_object_add(rt, "errors", json_object_new_int64(errs));
        }
        json_object_object_add(rt, "last_active_sec", json_object_new_int64(
            (int64_t)time_elapsed(ch->last_active)));
        json_object_object_add(rt, "local_fd", json_object_new_int(ch->local_fd));
        json_object_object_add(rt, "cb_open",  json_object_new_boolean(
            api_ctx->cb_open[ch->channel_id] != 0));
        json_object_object_add(obj, "runtime", rt);
    }

    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", s);
    json_object_put(obj);
}

/*
 * api_update_channel — 更新通道配置
 *
 * 当前仅支持更新 max_sessions。其他字段需要通道重建。
 */
static void api_update_channel(struct mg_connection *c, struct mg_http_message *hm, uint32_t channel_id)
{
    if (!api_check_write_access(c)) return;

    channel_t *ch = channel_find(api_ctx, channel_id);
    if (!ch) {
        mg_http_reply(c, 404, "", "{\"status\":\"error\",\"message\":\"Channel not found\"}\n");
        return;
    }

    struct json_object *body = json_tokener_parse(hm->body.buf);
    if (!body) {
        mg_http_reply(c, 400, "", "{\"status\":\"error\",\"message\":\"Invalid JSON\"}\n");
        return;
    }

    json_object *j_ms = json_object_object_get(body, "max_sessions");
    if (j_ms && (ch->flags & CH_FLAG_STATIC_LISTENER) &&
        ch->listener_idx < api_ctx->config.channel_count) {
        int v = json_object_get_int(j_ms);
        if (v >= 1 && v <= 256) {
            api_ctx->config.channels[ch->listener_idx].max_sessions = (uint16_t)v;
        }
    }
    json_object_put(body);
    mg_http_reply(c, 200, "", "{\"status\":\"ok\",\"message\":\"Updated\"}\n");
}

/*
 * api_delete_channel — 删除通道
 *
 * 销毁运行时通道并移除配置数组中的条目。
 * 注意：仅操作 listener 通道，其动态子通道不受影响（由超时机制回收）。
 */
static void api_delete_channel(struct mg_connection *c, uint32_t channel_id)
{
    if (!api_check_write_access(c)) return;

    channel_t *ch = channel_find(api_ctx, channel_id);
    if (!ch) {
        mg_http_reply(c, 404, "", "{\"status\":\"error\",\"message\":\"Channel not found\"}\n");
        return;
    }

    if (!(ch->flags & CH_FLAG_STATIC_LISTENER)) {
        mg_http_reply(c, 400, "", "{\"status\":\"error\",\"message\":\"Cannot delete dynamic channel\"}\n");
        return;
    }

    /* 从配置数组中移除（swap-with-last 模式） */
    if (ch->listener_idx < api_ctx->config.channel_count) {
        int idx = ch->listener_idx;
        if (idx < api_ctx->config.channel_count - 1) {
            api_ctx->config.channels[idx] = api_ctx->config.channels[api_ctx->config.channel_count - 1];
            /* 更新被移动的通道的 listener_idx */
            channel_t *moved = channel_find(api_ctx, api_ctx->config.channels[idx].channel_id);
            if (moved) moved->listener_idx = (uint8_t)idx;
        }
        api_ctx->config.channel_count--;
    }

    channel_destroy(api_ctx, ch);
    mg_http_reply(c, 200, "", "{\"status\":\"ok\",\"message\":\"Deleted\"}\n");

    /* Manager: push updated config */
    if (api_ctx->config.node.node_role == NODE_ROLE_MANAGER) {
        api_ctx->mgmt.config_version++;
        mgmt_push_config_to_all(api_ctx, NULL);
    }
}

/* ============================================================================
 * TEST_BUILD 测试桥接 — 暴露静态 handler 供单元测试使用
 * ============================================================================ */
#ifdef TEST_BUILD

/* 允许测试代码设置 api_ctx */
void test_api_set_ctx(global_ctx_t *ctx)
{
    api_ctx = ctx;
}

global_ctx_t *test_api_get_ctx(void)
{
    return api_ctx;
}

/* 暴露认证和速率限制检查 */
int test_api_check_auth(struct mg_connection *c, struct mg_http_message *hm)
{
    return api_check_auth(c, hm);
}

int test_api_check_rate_limit(struct mg_connection *c, struct mg_http_message *hm)
{
    return api_check_rate_limit(c, hm);
}

void test_api_generate_token(char *buf, size_t len)
{
    api_generate_token(buf, len);
}

/* ── 端点 handler 包装 ── */
void test_api_handle_status(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_status(c, hm);
}

void test_api_handle_config(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_config(c, hm);
}

void test_api_handle_nodes(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_nodes(c, hm);
}

void test_api_handle_node_by_id(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_node_by_id(c, hm);
}

void test_api_handle_node_instances(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_node_instances(c, hm);
}

void test_api_handle_channels(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_channels(c, hm);
}

void test_api_handle_channel_by_id(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_channel_by_id(c, hm);
}

void test_api_handle_stats(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_stats(c, hm);
}

void test_api_handle_logs(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_logs(c, hm);
}

void test_api_handle_sessions(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_sessions(c, hm);
}

void test_api_handle_session_by_id(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_session_by_id(c, hm);
}

void test_api_handle_metrics(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_metrics(c, hm);
}

void test_api_handle_config_switch(struct mg_connection *c, struct mg_http_message *hm)
{
    api_handle_config_switch(c, hm);
}

#endif /* TEST_BUILD */
