/*
 * main.c - Gap-Proxy 入口点
 *
 * 负责配置加载、验证、信号处理、主事件循环和清理。
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                          启动序列（Startup Sequence）                     ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                          ║
 * ║   1. 命令行参数解析                                                       ║
 * ║      -v / --version : 打印版本号                                        ║
 * ║      -h / --help    : 打印帮助信息                                      ║
 * ║      <config.json>  : 配置文件路径（必需）                               ║
 * ║                                                                          ║
 * ║   2. 初始化全局上下文 (global_ctx_t)                                       ║
 * ║      memset 清零，raw_sock=-1, epoll_fd=-1, running=1                    ║
 * ║                                                                          ║
 * ║   3. 加载配置文件 (config_load)                                           ║
 * ║      解析 JSON 配置：网卡、EtherType、MAC、KCP参数、加密、通道列表        ║
 * ║                                                                          ║
 * ║   4. 验证配置 (validate_config)                                           ║
 * ║      检查接口名、EtherType范围、KCP参数、通道ID唯一性、加密密钥            ║
 * ║                                                                          ║
 * ║   4b. 初始化加密模块 (crypto_init)                                        ║
 * ║      解析 hex 密钥 → 设置 SM4 加解密上下文 → 派生 SM3-HMAC 子密钥        ║
 * ║                                                                          ║
 * ║   5. 安装信号处理器 (setup_signals)                                       ║
 * ║      SIGINT/SIGTERM → 设置 running=0                                     ║
 * ║      SIGHUP         → 设置 reload_requested=1                           ║
 * ║      SIGPIPE        → 忽略（防止对已关闭socket写导致进程退出）            ║
 * ║                                                                          ║
 * ║   6. 初始化代理子系统 (proxy_init)                                        ║
 * ║      创建 epoll 实例 (epoll_create1 with EPOLL_CLOEXEC)                  ║
 * ║                                                                          ║
 * ║   7. 初始化通道子系统 (channel_init)                                      ║
 * ║      分配哈希表 (max_channels * 2 个桶，限制 [64, 65535])                 ║
 * ║                                                                          ║
 * ║   8. 创建 AF_PACKET 原始套接字 (af_packet_create)                         ║
 * ║      socket(AF_PACKET, SOCK_RAW, ethertype) → bind → 非阻塞 → TPACKET_V2 ║
 * ║                                                                          ║
 * ║   9. 获取本地 MAC 地址 (af_packet_get_mac)                                ║
 * ║      若配置未指定，通过 SIOCGIFHWADDR ioctl 自动获取                     ║
 * ║                                                                          ║
 * ║   10. 确定对端 MAC 地址                                                   ║
 * ║       若配置未指定 → 使用广播地址 FF:FF:FF:FF:FF:FF，启动自动学习         ║
 * ║                                                                          ║
 * ║   11. 自动设置 NIC MTU (可选)                                             ║
 * ║       SIOCSIFMTU ioctl                                                  ║
 * ║                                                                          ║
 * ║   12. 设置 BPF 过滤器 (af_packet_set_bpf)                                 ║
 * ║      仅接收匹配 EtherType 的帧，内核级过滤减少用户态开销                  ║
 * ║                                                                          ║
 * ║   13. 创建通道并启动代理监听                                              ║
 * ║      对于每个配置的通道:                                                   ║
 * ║        - channel_create() 创建通道 + KCP 实例                             ║
 * ║        - proxy_start_listen() 绑定监听端口 + 加入 epoll (frontend)        ║
 * ║                                                                          ║
 * ║   14. 将 AF_PACKET 套接字加入 epoll                                       ║
 * ║                                                                          ║
 * ║   15. 初始化时间基准 (kcp_wrap_clock + time)                               ║
 * ║                                                                          ║
 * ║   16. 主事件循环                                                          ║
 * ║       epoll_wait(10ms) → 处理 AF_PACKET 帧 + 代理 I/O                    ║
 * ║       → 周期任务 (KCP更新 + 心跳 + 超时检查，每10ms)                      ║
 * ║       → 统计输出 (每60秒)                                                 ║
 * ║       → 配置热重载 (SIGHUP 触发)                                         ║
 * ║                                                                          ║
 * ║   17. 清理退出 (cleanup)                                                  ║
 * ║       优雅关闭所有通道 → KCP缓冲区排空 → 释放所有资源                      ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <sched.h>
#include <sys/stat.h>

#include "types.h"

extern void mgmt_request_instance_sync(global_ctx_t *ctx);
extern void mgmt_load_dynamic_instances(global_ctx_t *ctx);
extern void mgmt_persist_dynamic_instances(global_ctx_t *ctx);

/* 前向声明 */
static void master_handle_spawn_request(void);
static void master_handle_kill_request(void);
static void master_handle_config_switch(void);
#include "af_packet.h"
#include "myproto.h"
#include "kcp_wrap.h"
#include "channel.h"
#include "acl.h"
#include "proxy.h"
#include "crypto.h"
#include "api.h"
#include "plugin.h"

#define VERSION             "1.0.0"
#define EPOLL_MAX_EVENTS    64
#define EPOLL_TIMEOUT_MS    10
#define PERIODIC_INTERVAL_MS 10
#define STATS_INTERVAL_SEC  60

/* ---- 全局上下文指针（信号处理器需要访问） ---- */
global_ctx_t *volatile g_ctx = NULL;

/* ---- 前向声明 ---- */
static void cleanup(global_ctx_t *ctx);
static void build_listener_bases(global_ctx_t *ctx);
static int  config_reload(global_ctx_t *ctx, const char *config_path);
static void handle_channel_ctl(global_ctx_t *ctx);
static void config_reload_channels(global_ctx_t *ctx, const global_config_t *new_cfg);
static int  validate_config(global_config_t *config);
static int  ctl_socket_init(global_ctx_t *ctx);
static void ctl_socket_accept(global_ctx_t *ctx);
int  ctl_execute_json(global_ctx_t *ctx, json_object *root, int *a, int *d, int *e);
static int  channel_ctl_add(global_ctx_t *ctx, const channel_config_t *cfg);
static int  channel_ctl_del(global_ctx_t *ctx, uint32_t channel_id);

#define FRONTEND_FD_RESERVE 32

static int count_open_fds(void)
{
    /* ── 统计进程当前打开的文件描述符数量 ──
     * 通过遍历 /proc/self/fd 目录获取精确的 fd 计数。
     * 跳过 "." 和 ".." 目录项，每个其他条目代表一个打开的 fd。
     *
     * @return 打开的 fd 数量，opendir 失败时返回 -1 */
    DIR *dir;
    struct dirent *ent;
    int count = 0;

    /* 打开 /proc/self/fd 目录 —— 每个已打开的 fd 在这里都有一个符号链接 */
    dir = opendir("/proc/self/fd");
    if (!dir) {
        return -1;               /* 无法访问 /proc（如受限容器环境） */
    }

    /* 遍历目录条目，跳过 . 和 .. */
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        count++;                 /* 每个非元数据条目 = 一个打开的 fd */
    }

    closedir(dir);
    return count;
}

static int ensure_listener_fd_budget(global_ctx_t *ctx,
                                     int additional_listeners,
                                     const char *phase,
                                     uint32_t channel_id)
{
    /* ── FD 预算检查 ──
     * 防止 frontend 节点因创建过多 listener socket 而耗尽文件描述符限制。
     *
     * 预算模型:
     *   projected = open_fds + additional_listeners + FRONTEND_FD_RESERVE
     *
     * 如果 projected > soft limit (RLIMIT_NOFILE)，则拒绝继续创建 listener，
     * 并给出调整建议（减少 listen_port_range 或提高 ulimit -n）。
     *
     * 仅在 frontend 节点（需要为每个 listener 创建监听 socket）且
     * additional_listeners > 0 时检查。
     *
     * @param ctx                  全局上下文
     * @param additional_listeners 即将新增的 listener 数量
     * @param phase                调用阶段描述（"startup"/"config_reload"/"ctl_add"）
     * @param channel_id           触发检查的通道 ID（用于日志）
     * @return                     0=预算充足, -1=预算不足 */
    struct rlimit rl;
    int open_fds;
    rlim_t projected;

    /* 非 frontend 或无新增 listener 时跳过检查 */
    if (!ctx || ctx->config.node_type != NODE_TYPE_FRONTEND ||
        additional_listeners <= 0) {
        return 0;
    }

    /* 获取进程 fd 软限制 */
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        LOG_WARN("fd budget check skipped during %s: getrlimit failed: %s",
                 phase, strerror(errno));
        return 0;                /* 无法获取限制 → 跳过检查（不阻塞操作） */
    }

    /* 无限限制 → 无需检查 */
    if (rl.rlim_cur == RLIM_INFINITY) {
        return 0;
    }

    /* 统计当前已打开的 fd 数 */
    open_fds = count_open_fds();
    if (open_fds < 0) {
        LOG_WARN("fd budget check skipped during %s: cannot inspect /proc/self/fd: %s",
                 phase, strerror(errno));
        return 0;                /* 无法统计 → 跳过（不阻塞操作） */
    }

    /* 预算计算: 当前 + 新增 + 预留余量（32 个 fd 用于临时/内部用途） */
    projected = (rlim_t)open_fds +
                (rlim_t)additional_listeners +
                (rlim_t)FRONTEND_FD_RESERVE;
    if (projected <= rl.rlim_cur) {
        return 0;                /* 预算充足 */
    }

    /* 预算不足：记录详细信息并拒绝 */
    LOG_ERROR("fd budget insufficient during %s: open_fds=%d, need_listeners=%d, "
              "reserve=%d, soft_limit=%llu, channel=%u. "
              "Reduce listen_port_range/listener count or raise 'ulimit -n'.",
              phase, open_fds, additional_listeners, FRONTEND_FD_RESERVE,
              (unsigned long long)rl.rlim_cur, channel_id);
    return -1;
}

/* ──────────────────────────────────────────────────────────────────────────
 * signal_handler — 统一信号处理器
 *
 * 处理四种信号，全部通过设置全局标志位实现异步通知，信号处理器本身 O(1)：
 *
 *   SIGINT  / SIGTERM  → g_ctx->running = 0
 *     优雅退出：主循环检测到 running=0 后跳出，执行 cleanup() 清理资源。
 *
 *   SIGHUP             → g_ctx->reload_requested = 1
 *     配置热重载：主循环或 epoll_wait(EINTR) 路径检测到后调用 config_reload()。
 *
 *   SIGUSR1            → g_ctx->ctl_requested = 1
 *     通道快速增删：检测到后调用 handle_channel_ctl() 解析 control JSON 文件。
 *
 *   SIGPIPE            → SIG_IGN（在 setup_signals 中设置）
 *     忽略，防止向已关闭的 socket 写入导致进程异常退出。
 * ────────────────────────────────────────────────────────────────────────── */
static void signal_handler(int signum)
{
    /* ── 统一信号处理器 ──
     * 所有信号处理均为无阻塞的 O(1) 操作：仅设置全局标志位。
     * 实际逻辑延迟到主循环的同步点（epoll_wait EINTR 路径或循环体顶部）执行。
     *
     * SIGINT/SIGTERM → running=0    (主循环退出，触发 cleanup)
     * SIGHUP         → reload_requested=1 (配置热重载)
     * SIGUSR1        → ctl_requested=1    (通道快速增删) */

    if (g_ctx == NULL) return;   /* 上下文未初始化时忽略所有信号 */

    switch (signum) {
    case SIGINT:
    case SIGTERM:
        /* 优雅退出：设置 running=0，主循环检测后跳出并执行 cleanup() */
        g_ctx->running = 0;
        break;
    case SIGHUP:
        /* 热重载：标记 reload_requested，在 epoll EINTR 路径中调用 config_reload() */
        g_ctx->reload_requested = 1;
        break;
    case SIGUSR1:
        /* 通道控制：标记 ctl_requested，主循环检测后调用 handle_channel_ctl() */
        g_ctx->ctl_requested = 1;
        break;
    default:
        break;
    }
}

#ifndef TEST_BUILD
static int setup_signals(global_ctx_t *ctx)
{
    struct sigaction sa;

    g_ctx = ctx;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGUSR1);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGINT handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGTERM handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGHUP handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGUSR1 handler: %s", strerror(errno));
        return -1;
    }

    /* SIGPIPE 忽略，防止对已关闭的 socket 写入导致进程退出 */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGPIPE handler: %s", strerror(errno));
        return -1;
    }
    /* SIGUSR2 忽略（worker 不使用此信号，默认 terminate 会导致异常退出） */
    if (sigaction(SIGUSR2, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGUSR2 handler: %s", strerror(errno));
        return -1;
    }

    /* 解除 master fork 时继承的阻塞信号（master-worker 模式） */
    {
        sigset_t unblock;
        sigemptyset(&unblock);
        sigaddset(&unblock, SIGINT);
        sigaddset(&unblock, SIGTERM);
        sigaddset(&unblock, SIGHUP);
        sigaddset(&unblock, SIGUSR1);
        sigaddset(&unblock, SIGCHLD);
        sigaddset(&unblock, SIGUSR2);
        sigaddset(&unblock, SIGURG);
        sigprocmask(SIG_UNBLOCK, &unblock, NULL);
    }

    return 0;
}
#endif /* TEST_BUILD */

/* ---- MAC 地址解析 ---- */
static int parse_mac_string(const char *str, uint8_t mac[ETH_MAC_ADDR_LEN])
{
    unsigned int values[ETH_MAC_ADDR_LEN];
    int n;

    if (str == NULL || strlen(str) == 0)
        return -1;

    n = sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]);
    if (n != ETH_MAC_ADDR_LEN)
        return -1;

    for (int i = 0; i < ETH_MAC_ADDR_LEN; i++) {
        if (values[i] > 255)
            return -1;
        mac[i] = (uint8_t)values[i];
    }

    return 0;
}

static int mac_is_zero(const uint8_t mac[ETH_MAC_ADDR_LEN])
{
    for (int i = 0; i < ETH_MAC_ADDR_LEN; i++) {
        if (mac[i] != 0) return 0;
    }
    return 1;
}

/* Return 1 if mac is broadcast (all 0xFF) */
static int mac_is_broadcast(const uint8_t mac[ETH_MAC_ADDR_LEN])
{
    for (int i = 0; i < ETH_MAC_ADDR_LEN; i++)
        if (mac[i] != 0xFF) return 0;
    return 1;
}

/* ──────────────────────────────────────────────────────────────────────────
 * config_load — 解析 JSON 配置文件
 *
 * 从 JSON 文件中逐字段解析全局配置，包括：
 *   - interface / ethertype / peer_mac / local_mac
 *   - kcp: KCP 参数
 *   - node_type / max_channels / heartbeat_*
 *   - encryption / crc_enabled / auto_set_nic_mtu / nic_mtu
 *   - pid_file / instance_name
 *   - channels[] 通道列表
 *
 * @param path    JSON 配置文件路径
 * @param config  输出：填充后的全局配置结构体
 * @return        0=成功, -1=解析或分配失败
 * ────────────────────────────────────────────────────────────────────────── */

/* ── ACL 解析辅助 ── */

static uint32_t cidr_prefix_to_mask(int prefix_len)
{
    if (prefix_len <= 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFF;
    /* 显式 uint32_t 字面量防止 0xFFFFFFFF(32-bit int) << 32 UB */
    return htonl((0xFFFFFFFFu << (unsigned)(32 - prefix_len)));
}

static void parse_acl(json_object *obj, channel_acl_t *acl)
{
    memset(acl, 0, sizeof(*acl));

    json_object *acl_obj = json_object_object_get(obj, "client_acl");
    if (!acl_obj) return;

    acl->enabled = 1;
    json_object *arr;

    if (json_object_object_get_ex(acl_obj, "ips", &arr) &&
        json_object_is_type(arr, json_type_array)) {
        int count = json_object_array_length(arr);
        for (int i = 0; i < count; i++) {
            if (acl->ip_count >= MAX_ACL_IPS) { break; }
            const char *str = json_object_get_string(
                json_object_array_get_idx(arr, (size_t)i));
            acl_ip_entry_t *entry = &acl->ips[acl->ip_count];
            const char *slash = strchr(str, '/');
            const char *dash  = strchr(str, '-');
            if (slash) {
                entry->type = ACL_IP_CIDR;
                char addr_buf[64];
                size_t len = (size_t)(slash - str);
                if (len < sizeof(addr_buf)) {
                    memcpy(addr_buf, str, len); addr_buf[len] = '\0';
                    entry->addr = inet_addr(addr_buf);
                } else { continue; }
                entry->mask_or_end = cidr_prefix_to_mask(atoi(slash + 1));
            } else if (dash) {
                entry->type = ACL_IP_RANGE;
                char start_buf[64];
                size_t len = (size_t)(dash - str);
                if (len < sizeof(start_buf)) {
                    memcpy(start_buf, str, len); start_buf[len] = '\0';
                    entry->addr = inet_addr(start_buf);
                } else { continue; }
                entry->mask_or_end = inet_addr(dash + 1);
            } else {
                entry->type = ACL_IP_SINGLE;
                entry->addr = inet_addr(str);
            }
            if (entry->addr == INADDR_NONE && entry->type != ACL_IP_CIDR) { continue; }
            /* H8: 拒绝 0.0.0.0（通配地址 INADDR_ANY）和 255.255.255.255（INADDR_NONE） */
            if (entry->addr == INADDR_ANY) { continue; }
            acl->ip_count++;
        }
    }
    if (json_object_object_get_ex(acl_obj, "ports", &arr) &&
        json_object_is_type(arr, json_type_array)) {
        int count = json_object_array_length(arr);
        for (int i = 0; i < count; i++) {
            if (acl->port_count >= MAX_ACL_PORTS) { break; }
            const char *str = json_object_get_string(
                json_object_array_get_idx(arr, (size_t)i));
            acl_port_entry_t *entry = &acl->ports[acl->port_count];
            const char *dash = strchr(str, '-');
            if (dash) {
                entry->type = ACL_PORT_RANGE;
                entry->port_start = (uint16_t)atoi(str);
                entry->port_end   = (uint16_t)atoi(dash + 1);
            } else {
                entry->type = ACL_PORT_SINGLE;
                entry->port_start = (uint16_t)atoi(str);
                entry->port_end   = entry->port_start;
            }
            acl->port_count++;
        }
    }
}

static int parse_port_range_value(json_object *obj, uint16_t *start, uint16_t *end)
{
    int a;
    int b;

    if (!obj || !start || !end) {
        return -1;
    }

    if (json_object_is_type(obj, json_type_array)) {
        if (json_object_array_length(obj) != 2) {
            return -1;
        }
        a = json_object_get_int(json_object_array_get_idx(obj, 0));
        b = json_object_get_int(json_object_array_get_idx(obj, 1));
    } else {
        const char *s = json_object_get_string(obj);
        char *tail = NULL;

        if (!s || !s[0]) {
            return -1;
        }

        errno = 0;
        long first = strtol(s, &tail, 10);
        if (errno != 0 || tail == s || *tail != '-') {
            return -1;
        }

        errno = 0;
        char *endptr = NULL;
        long second = strtol(tail + 1, &endptr, 10);
        if (errno != 0 || endptr == tail + 1 || *endptr != '\0') {
            return -1;
        }

        a = (int)first;
        b = (int)second;
    }

    if (a < 1 || a > 65535 || b < 1 || b > 65535 || a > b) {
        return -1;
    }

    *start = (uint16_t)a;
    *end = (uint16_t)b;
    return 0;
}

int config_load(const char *path, global_config_t *config)
{
    struct json_object *root = NULL;
    struct json_object *obj = NULL;
    struct json_object *tmp = NULL;
    int ret = -1;  /* 默认失败; 所有 goto cleanup 路径在 ret=0 之前均正确返回 -1 */

    root = json_object_from_file(path);
    if (root == NULL) {
        LOG_ERROR("config_load: Failed to parse config file: %s: %s", path, strerror(errno));
        goto cleanup;  /* json_object_put(NULL) is safe per json-c API */
    }

    /* 注意：调用方负责初始化 config（memset 或 memcpy 现有配置）。
     * 本函数仅覆盖 JSON 中出现的字段，不重置未出现的字段。*/

    /* ---- interface ---- */
    if (json_object_object_get_ex(root, "interface", &tmp)) {
        if (json_object_is_type(tmp, json_type_string)) {
            const char *s = json_object_get_string(tmp);
            if (s) {
                /* strncpy with manual NUL termination is intentional */
                strncpy(config->interface, s, MAX_INTERFACE_NAME - 1);
                config->interface[MAX_INTERFACE_NAME - 1] = '\0';
            }
        }
    }

    /* ---- ethertype ---- */
    if (json_object_object_get_ex(root, "ethertype", &tmp)) {
        int raw_ethertype = json_object_get_int(tmp);
        if (raw_ethertype < 0x0600 || raw_ethertype > 0xFFFF) {
            LOG_ERROR("config_load: Ethertype 0x%04X out of range [0x0600, 0xFFFF]", raw_ethertype);
            goto cleanup;
        }
        config->ethertype = (uint16_t)raw_ethertype;
    } else {
        config->ethertype = 0x88B5;   /* 默认 EtherType */
    }

    /* ---- peer_mac ---- */
    if (json_object_object_get_ex(root, "peer_mac", &tmp)) {
        if (json_object_is_type(tmp, json_type_string)) {
            const char *s = json_object_get_string(tmp);
            if (s && strlen(s) > 0) {
                if (parse_mac_string(s, config->peer_mac) != 0) {
                    LOG_ERROR("config_load: Invalid peer_mac format: %s", s);
                    goto cleanup;
                }
            }
        }
        /* empty string: leave as zeros (auto-discovery) */
    }

    /* ---- local_mac ---- */
    if (json_object_object_get_ex(root, "local_mac", &tmp)) {
        if (json_object_is_type(tmp, json_type_string)) {
            const char *s = json_object_get_string(tmp);
            if (s && strlen(s) > 0) {
                if (parse_mac_string(s, config->local_mac) != 0) {
                    LOG_ERROR("config_load: Invalid local_mac format: %s", s);
                    goto cleanup;
                }
            }
        }
    }

    /* ---- kcp object ---- */
    if (json_object_object_get_ex(root, "kcp", &obj)) {
        if (json_object_object_get_ex(obj, "mtu", &tmp))
            config->kcp_mtu = json_object_get_int(tmp);
        else
            config->kcp_mtu = KCP_MTU_CONSERVATIVE;

        if (json_object_object_get_ex(obj, "sndwnd", &tmp))
            config->kcp_send_window = json_object_get_int(tmp);
        else
            config->kcp_send_window = KCP_SEND_WINDOW;

        if (json_object_object_get_ex(obj, "rcvwnd", &tmp))
            config->kcp_recv_window = json_object_get_int(tmp);
        else
            config->kcp_recv_window = KCP_RECV_WINDOW;

        if (json_object_object_get_ex(obj, "nodelay", &tmp))
            config->kcp_nodelay = json_object_get_int(tmp);
        else
            config->kcp_nodelay = KCP_NODELAY;

        if (json_object_object_get_ex(obj, "interval", &tmp))
            config->kcp_interval = json_object_get_int(tmp);
        else
            config->kcp_interval = KCP_INTERVAL;

        if (json_object_object_get_ex(obj, "resend", &tmp))
            config->kcp_resend = json_object_get_int(tmp);
        else
            config->kcp_resend = KCP_RESEND;

        if (json_object_object_get_ex(obj, "nc", &tmp))
            config->kcp_nc = json_object_get_int(tmp);
        else
            config->kcp_nc = KCP_NC;
    } else {
        /* 未指定 kcp 配置，使用默认值 */
        config->kcp_mtu         = KCP_MTU_CONSERVATIVE;
        config->kcp_send_window = KCP_SEND_WINDOW;
        config->kcp_recv_window = KCP_RECV_WINDOW;
        config->kcp_nodelay     = KCP_NODELAY;
        config->kcp_interval    = KCP_INTERVAL;
        config->kcp_resend      = KCP_RESEND;
        config->kcp_nc          = KCP_NC;
    }

    /* ---- performance object ---- */
    config->perf_af_packet_sndbuf = PERF_AF_PACKET_SNDBUF;
    config->perf_af_packet_rcvbuf = PERF_AF_PACKET_RCVBUF;
    config->perf_af_packet_send_retry_max = PERF_AF_PACKET_SEND_RETRY_MAX;
    config->perf_af_packet_send_wait_ms = PERF_AF_PACKET_SEND_WAIT_MS;
    config->perf_proxy_tcp_sockbuf = PERF_PROXY_TCP_SOCKBUF;
    config->perf_proxy_recv_buf_max = PERF_PROXY_RECV_BUF_MAX;
    config->perf_kcp_read_pause_waitsnd = PERF_KCP_READ_PAUSE_WAITSND;
    config->perf_kcp_read_resume_waitsnd = PERF_KCP_READ_RESUME_WAITSND;
    config->perf_kcp_immediate_flush = PERF_KCP_IMMEDIATE_FLUSH;
    config->perf_max_frames_per_cycle = PERF_MAX_FRAMES_PER_CYCLE;

    if (json_object_object_get_ex(root, "performance", &obj)) {
        if (json_object_object_get_ex(obj, "af_packet_sndbuf", &tmp))
            config->perf_af_packet_sndbuf = json_object_get_int(tmp);
        if (json_object_object_get_ex(obj, "af_packet_rcvbuf", &tmp))
            config->perf_af_packet_rcvbuf = json_object_get_int(tmp);
        if (json_object_object_get_ex(obj, "af_packet_send_retry_max", &tmp))
            config->perf_af_packet_send_retry_max = json_object_get_int(tmp);
        if (json_object_object_get_ex(obj, "af_packet_send_wait_ms", &tmp))
            config->perf_af_packet_send_wait_ms = json_object_get_int(tmp);
        if (json_object_object_get_ex(obj, "proxy_tcp_sockbuf", &tmp))
            config->perf_proxy_tcp_sockbuf = json_object_get_int(tmp);
        if (json_object_object_get_ex(obj, "proxy_recv_buf_max", &tmp))
            config->perf_proxy_recv_buf_max = json_object_get_int(tmp);
        if (json_object_object_get_ex(obj, "kcp_read_pause_waitsnd", &tmp))
            config->perf_kcp_read_pause_waitsnd = json_object_get_int(tmp);
        if (json_object_object_get_ex(obj, "kcp_read_resume_waitsnd", &tmp))
            config->perf_kcp_read_resume_waitsnd = json_object_get_int(tmp);
        if (json_object_object_get_ex(obj, "kcp_immediate_flush", &tmp))
            config->perf_kcp_immediate_flush = json_object_get_boolean(tmp) ? 1 : 0;
        if (json_object_object_get_ex(obj, "max_frames_per_cycle", &tmp))
            config->perf_max_frames_per_cycle = json_object_get_int(tmp);
    }

    /* ---- node_type ---- */
    if (json_object_object_get_ex(root, "node_type", &tmp)) {
        if (json_object_is_type(tmp, json_type_string)) {
            const char *s = json_object_get_string(tmp);
            if (s && strcmp(s, "backend") == 0) {
                config->node_type = NODE_TYPE_BACKEND;
            } else {
                config->node_type = NODE_TYPE_FRONTEND;
            }
        } else {
            config->node_type = NODE_TYPE_FRONTEND;
        }
    } else {
        config->node_type = NODE_TYPE_FRONTEND;
    }

    /* ---- max_channels ---- */
    if (json_object_object_get_ex(root, "max_channels", &tmp)) {
        config->max_channels = json_object_get_int(tmp);
    } else {
        config->max_channels = 65536;
    }

    /* ---- heartbeat_interval ---- */
    if (json_object_object_get_ex(root, "heartbeat_interval", &tmp)) {
        config->heartbeat_interval = json_object_get_int(tmp);
    } else {
        config->heartbeat_interval = HEARTBEAT_INTERVAL;
    }

    /* ---- heartbeat_timeout ---- */
    if (json_object_object_get_ex(root, "heartbeat_timeout", &tmp)) {
        config->heartbeat_timeout = json_object_get_int(tmp);
    } else {
        config->heartbeat_timeout = HEARTBEAT_TIMEOUT;
    }

    /* ---- encryption object ---- */
    if (json_object_object_get_ex(root, "encryption", &obj)) {
        if (json_object_object_get_ex(obj, "enabled", &tmp)) {
            config->encryption.enabled = json_object_get_boolean(tmp) ? 1 : 0;
        }

        if (json_object_object_get_ex(obj, "sm4_key", &tmp)) {
            if (json_object_is_type(tmp, json_type_string)) {
                const char *hex_key = json_object_get_string(tmp);
                if (hex_key && strlen(hex_key) > 0) {
                    size_t key_len = strlen(hex_key);
                    if (key_len != SM4_KEY_HEX_LEN) {
                        LOG_ERROR("config_load: SM4 key must be %d hex characters (%d bytes)",
                                  SM4_KEY_HEX_LEN, SM4_KEY_BIN_LEN);
                        goto cleanup;
                    }
                    /* strncpy with manual NUL termination is intentional */
                    strncpy(config->encryption.sm4_key, hex_key, SM4_KEY_HEX_LEN);
                    config->encryption.sm4_key[SM4_KEY_HEX_LEN] = '\0';
                }
            }
        }
    }

    /* ---- crc_enabled ---- */
    if (json_object_object_get_ex(root, "crc_enabled", &tmp)) {
        config->crc_enabled = json_object_get_boolean(tmp) ? 1 : 0;
    } else {
        config->crc_enabled = 0;  // Default: disabled (was 1)
    }

    /* ---- auto_set_nic_mtu ---- */
    if (json_object_object_get_ex(root, "auto_set_nic_mtu", &tmp)) {
        config->auto_set_nic_mtu = json_object_get_boolean(tmp) ? 1 : 0;
    }

    /* ---- nic_mtu ---- */
    if (json_object_object_get_ex(root, "nic_mtu", &tmp)) {
        config->nic_mtu = json_object_get_int(tmp);
    } else {
        config->nic_mtu = ETH_MTU;
    }

    /* ---- auto_kcp_mtu ---- */
    if (json_object_object_get_ex(root, "auto_kcp_mtu", &tmp)) {
        config->auto_kcp_mtu = json_object_get_boolean(tmp) ? 1 : 0;
    }

    /* ---- pid_file ---- */
    if (json_object_object_get_ex(root, "pid_file", &tmp)) {
        if (json_object_is_type(tmp, json_type_string)) {
            const char *s = json_object_get_string(tmp);
            if (s) {
                /* strncpy with manual NUL termination is intentional */
                strncpy(config->pid_file, s, MAX_PID_PATH - 1);
                config->pid_file[MAX_PID_PATH - 1] = '\0';
            }
        }
    }

    /* ---- instance_name ---- */
    if (json_object_object_get_ex(root, "instance_name", &tmp)) {
        if (json_object_is_type(tmp, json_type_string)) {
            const char *s = json_object_get_string(tmp);
            if (s) {
                /* strncpy with manual NUL termination is intentional */
                strncpy(config->instance_name, s, MAX_LISTEN_ADDR - 1);
                config->instance_name[MAX_LISTEN_ADDR - 1] = '\0';
            } else {
                /* strncpy with manual NUL termination is intentional */
                strncpy(config->instance_name, "default", MAX_LISTEN_ADDR - 1);
            }
        } else {
            /* strncpy with manual NUL termination is intentional */
            strncpy(config->instance_name, "default", MAX_LISTEN_ADDR - 1);
        }
    } else {
        /* strncpy with manual NUL termination is intentional */
        strncpy(config->instance_name, "default", MAX_LISTEN_ADDR - 1);
    }

    /* ---- node ---- */
    {
        struct json_object *node_obj;
        if (json_object_object_get_ex(root, "node", &node_obj)) {
            if (json_object_object_get_ex(node_obj, "node_id", &tmp)) {
                if (json_object_is_type(tmp, json_type_string)) {
                    const char *s = json_object_get_string(tmp);
                    if (s) { strncpy(config->node.node_id, s, 64); config->node.node_id[64] = '\0'; }
                }
            }
            if (json_object_object_get_ex(node_obj, "node_role", &tmp)) {
                if (json_object_is_type(tmp, json_type_string)) {
                    const char *s = json_object_get_string(tmp);
                    if (s) {
                        if (strcmp(s, "manager") == 0) config->node.node_role = NODE_ROLE_MANAGER;
                        else if (strcmp(s, "worker") == 0) config->node.node_role = NODE_ROLE_WORKER;
                    }
                }
            }
        }
    }

    /* ---- management ---- */
    {
        struct json_object *mgmt_obj;
        if (json_object_object_get_ex(root, "management", &mgmt_obj)) {
            if (json_object_object_get_ex(mgmt_obj, "enabled", &tmp))
                config->management.enabled = json_object_get_boolean(tmp) ? 1 : 0;
            if (config->management.enabled) {
                if (json_object_object_get_ex(mgmt_obj, "channel_id", &tmp))
                    config->management.channel_id = (uint16_t)json_object_get_int(tmp);
                if (json_object_object_get_ex(mgmt_obj, "listen_port", &tmp))
                    config->management.listen_port = (uint16_t)json_object_get_int(tmp);
                if (json_object_object_get_ex(mgmt_obj, "manager_port", &tmp))
                    config->management.manager_port = (uint16_t)json_object_get_int(tmp);
                if (json_object_object_get_ex(mgmt_obj, "keepalive_interval", &tmp))
                    config->management.keepalive_interval = json_object_get_int(tmp);
                if (json_object_object_get_ex(mgmt_obj, "keepalive_timeout", &tmp))
                    config->management.keepalive_timeout = json_object_get_int(tmp);
                if (json_object_object_get_ex(mgmt_obj, "reconnect_interval", &tmp))
                    config->management.reconnect_interval = json_object_get_int(tmp);
            }
        }
    }

    /* ---- api: REST API 服务器配置 ---- */
    if (json_object_object_get_ex(root, "api_enabled", &tmp))
        config->api_enabled = json_object_get_boolean(tmp) ? 1 : 0;
    if (json_object_object_get_ex(root, "api_listen_port", &tmp))
        config->api_listen_port = (uint16_t)json_object_get_int(tmp);
    if (json_object_object_get_ex(root, "api_listen_addr", &tmp)) {
        if (json_object_is_type(tmp, json_type_string)) {
            const char *s = json_object_get_string(tmp);
            if (s) { strncpy(config->api_listen_addr, s, 31); config->api_listen_addr[31] = '\0'; }
        }
    }
    if (json_object_object_get_ex(root, "api_auth_token", &tmp)) {
        if (json_object_is_type(tmp, json_type_string)) {
            const char *s = json_object_get_string(tmp);
            if (s) { strncpy(config->api_auth_token, s, 64); config->api_auth_token[64] = '\0'; }
        }
    }

    /* ---- channels array ---- */
    if (json_object_object_get_ex(root, "channels", &obj)) {
        int arr_len = json_object_array_length(obj);
        if (arr_len > MAX_CHANNELS) {
            LOG_ERROR("config_load: Too many channels in config (%d), max is %d", arr_len, MAX_CHANNELS);
            goto cleanup;
        }
        config->channel_count = 0;
        for (int i = 0; i < arr_len; i++) {
            struct json_object *ch_obj = json_object_array_get_idx(obj, i);
            channel_config_t base_cfg;
            uint16_t listen_start = 0;
            uint16_t listen_end = 0;
            uint16_t remote_start = 0;
            uint16_t remote_end = 0;
            uint32_t range_len = 1;
            uint8_t has_listen_range = 0;
            uint8_t has_remote_range = 0;

            memset(&base_cfg, 0, sizeof(base_cfg));

            if (json_object_object_get_ex(ch_obj, "channel_id", &tmp)) {
                int raw_id = json_object_get_int(tmp);
                if (raw_id <= 0) {
                    LOG_ERROR("config_load: Channel %d: channel_id must be > 0, got %d",
                              config->channel_count, raw_id);
                    goto cleanup;
                }
                base_cfg.channel_id = (uint32_t)raw_id;
            }

            if (json_object_object_get_ex(ch_obj, "listen_port_range", &tmp)) {
                if (parse_port_range_value(tmp, &listen_start, &listen_end) != 0) {
                    LOG_ERROR("config_load: Channel %d (id=%u): invalid listen_port_range",
                              config->channel_count, base_cfg.channel_id);
                    goto cleanup;
                }
                has_listen_range = 1;
            } else if (json_object_object_get_ex(ch_obj, "listen_port", &tmp)) {
                listen_start = (uint16_t)json_object_get_int(tmp);
                listen_end = listen_start;
            }

            if (json_object_object_get_ex(ch_obj, "remote_port_range", &tmp)) {
                if (parse_port_range_value(tmp, &remote_start, &remote_end) != 0) {
                    LOG_ERROR("config_load: Channel %d (id=%u): invalid remote_port_range",
                              config->channel_count, base_cfg.channel_id);
                    goto cleanup;
                }
                has_remote_range = 1;
            } else if (json_object_object_get_ex(ch_obj, "remote_port", &tmp)) {
                remote_start = (uint16_t)json_object_get_int(tmp);
                if (has_listen_range) {
                    uint32_t listen_len = (uint32_t)listen_end - listen_start + 1;
                    if ((uint32_t)remote_start + listen_len - 1 > 65535) {
                        LOG_ERROR("config_load: Channel %d (id=%u): remote_port base %u "
                                  "cannot cover listen_port_range length %u",
                                  config->channel_count, base_cfg.channel_id,
                                  remote_start, listen_len);
                        goto cleanup;
                    }
                    remote_end = (uint16_t)(remote_start + listen_len - 1);
                } else {
                    remote_end = remote_start;
                }
            }

            if (has_listen_range || has_remote_range) {
                if (!has_listen_range) {
                    LOG_ERROR("config_load: Channel %d (id=%u): remote_port_range requires "
                              "listen_port_range",
                              config->channel_count, base_cfg.channel_id);
                    goto cleanup;
                }

                uint32_t listen_len = (uint32_t)listen_end - listen_start + 1;
                uint32_t remote_len = (uint32_t)remote_end - remote_start + 1;
                if (listen_len != remote_len) {
                    LOG_ERROR("config_load: Channel %d (id=%u): listen_port_range and "
                              "remote_port_range lengths differ (%u vs %u)",
                              config->channel_count, base_cfg.channel_id,
                              listen_len, remote_len);
                    goto cleanup;
                }
                range_len = listen_len;
            }

            if (json_object_object_get_ex(ch_obj, "listen_addr", &tmp)) {
                if (json_object_is_type(tmp, json_type_string)) {
                    const char *s = json_object_get_string(tmp);
                    if (s) {
                        /* strncpy with manual NUL termination is intentional */
                        strncpy(base_cfg.listen_addr, s, MAX_LISTEN_ADDR - 1);
                        base_cfg.listen_addr[MAX_LISTEN_ADDR - 1] = '\0';
                    }
                }
            }

            if (json_object_object_get_ex(ch_obj, "remote_addr", &tmp)) {
                if (json_object_is_type(tmp, json_type_string)) {
                    const char *s = json_object_get_string(tmp);
                    if (s) {
                        /* strncpy with manual NUL termination is intentional */
                        strncpy(base_cfg.remote_addr, s, MAX_REMOTE_ADDR - 1);
                        base_cfg.remote_addr[MAX_REMOTE_ADDR - 1] = '\0';
                    }
                }
            }

            if (json_object_object_get_ex(ch_obj, "is_tcp", &tmp)) {
                base_cfg.is_tcp = json_object_get_boolean(tmp) ? 1 : 0;
            }

            if (json_object_object_get_ex(ch_obj, "enabled", &tmp))
                base_cfg.enabled = json_object_get_boolean(tmp) ? 1 : 0;
            else {
                base_cfg.enabled = 1;
                LOG_DEBUG("config_load: channel[%d] (id=%u): 'enabled' not set, defaulting to 1",
                          config->channel_count, base_cfg.channel_id);
            }

            /* max_sessions: 0=默认1，上限65535 */
            if (json_object_object_get_ex(ch_obj, "max_sessions", &tmp)) {
                int ms = json_object_get_int(tmp);
                if (ms > 65535) {
                    LOG_WARN("Channel %d (id=%u): max_sessions %d exceeds 65535, capping",
                             config->channel_count, base_cfg.channel_id, ms);
                    base_cfg.max_sessions = 65535;
                } else {
                    base_cfg.max_sessions = (ms > 0) ? (uint16_t)ms : 1;
                }
            } else {
                base_cfg.max_sessions = 1;
            }

            /* source_port: backend 连接远端时指定的源端口（0=内核随机） */
            if (json_object_object_get_ex(ch_obj, "source_port", &tmp)) {
                base_cfg.source_port = (uint16_t)json_object_get_int(tmp);
            }

            /* 客户端 IP/端口 ACL */
            parse_acl(ch_obj, &base_cfg.client_acl);

            if ((uint64_t)base_cfg.channel_id + range_len - 1 > UINT32_MAX) {
                LOG_ERROR("config_load: Channel %d (id=%u): expanded channel_id range overflows",
                          config->channel_count, base_cfg.channel_id);
                goto cleanup;
            }

            if ((uint32_t)config->channel_count + range_len > MAX_CHANNELS) {
                LOG_ERROR("config_load: Too many channels after range expansion (%u), max is %d",
                          (uint32_t)config->channel_count + range_len,
                          MAX_CHANNELS);
                goto cleanup;
            }

            for (uint32_t offset = 0; offset < range_len; offset++) {
                channel_config_t *ch_cfg = &config->channels[config->channel_count];
                *ch_cfg = base_cfg;
                ch_cfg->channel_id = base_cfg.channel_id + offset;
                ch_cfg->listen_port = (uint16_t)(listen_start + offset);
                ch_cfg->remote_port = (uint16_t)(remote_start + offset);
                config->channel_count++;
            }
        }
    }

    ret = 0;

cleanup:
    json_object_put(root);
    return ret;
}

/* ── 配置验证 ── */
int validate_config(global_config_t *config)
{
    /* ── 阶段 1: 网络基础设施校验 ── */

    /* interface 不能为空 */
    if (config->interface[0] == '\0') {
        LOG_ERROR("Interface must be specified");
        return -1;
    }

    /* ethertype 校验：避免保留范围 0x0000-0x05FF
     * 0x0000-0x05DC: IEEE 802.3 长度字段
     * 0x05DD-0x05FF: SNAP 保留
     * 0x0600+:      合法 EtherType（0x0800=IPv4, 0x0806=ARP, 0x8100=VLAN...） */
    if (config->ethertype < 0x0600) {
        LOG_ERROR("Ethertype 0x%04X is invalid or in reserved range", config->ethertype);
        return -1;
    }
    if (config->ethertype == 0x8100) {
        LOG_ERROR("VLAN EtherType (0x8100) is not supported");
        return -1;
    }

    /* 如果指定了 peer_mac，校验格式（非全零即视为已指定） */
    if (!mac_is_zero(config->peer_mac)) {
        LOG_INFO("Peer MAC configured: %02x:%02x:%02x:%02x:%02x:%02x",
                 config->peer_mac[0], config->peer_mac[1], config->peer_mac[2],
                 config->peer_mac[3], config->peer_mac[4], config->peer_mac[5]);
    }

    /* ── 阶段 2: KCP 参数校验 ── */

    /* 自动计算 kcp_mtu（如果 auto_kcp_mtu 启用且用户未显式设置）
     * 公式: kcp_mtu = nic_mtu - ETH_HDR(14) - myproto_hdr(12) - [crypto_overhead(28)]
     * 例如: nic_mtu=1500, 未加密 → kcp_mtu = 1500-14-12 = 1474
     *       nic_mtu=1500, SM4加密 → kcp_mtu = 1500-14-12-28 = 1446 */
    if (config->auto_kcp_mtu && config->kcp_mtu <= 0) {
        int overhead = ETH_HDR_SIZE + MYPROTO_HDR_SIZE;           /* 14 + 12 = 26 */
        if (config->encryption.enabled)
            overhead += CRYPTO_OVERHEAD;                         /* +28 = 54 */
        config->kcp_mtu = config->nic_mtu - overhead;
        LOG_INFO("auto_kcp_mtu: nic_mtu=%d overhead=%d => kcp_mtu=%d%s",
                 config->nic_mtu, overhead, config->kcp_mtu,
                 config->encryption.enabled ? " (encrypted)" : "");
    }

    /* KCP 核心参数范围检查 */
    if (config->kcp_mtu <= 0) {
        LOG_ERROR("kcp.mtu must be > 0, got %d", config->kcp_mtu);
        return -1;
    }
    if (config->kcp_send_window <= 0) {
        LOG_ERROR("kcp.sndwnd must be > 0, got %d", config->kcp_send_window);
        return -1;
    }
    if (config->kcp_recv_window <= 0) {
        LOG_ERROR("kcp.rcvwnd must be > 0, got %d", config->kcp_recv_window);
        return -1;
    }
    if (config->kcp_interval < 1 || config->kcp_interval > 500) {
        LOG_ERROR("kcp.interval must be in [1, 500], got %d", config->kcp_interval);
        return -1;
    }
    if (config->kcp_nodelay < 0 || config->kcp_nodelay > 1) {
        LOG_ERROR("kcp.nodelay must be 0 or 1, got %d", config->kcp_nodelay);
        return -1;
    }
    if (config->kcp_resend < 0 || config->kcp_resend > 10) {
        LOG_ERROR("kcp.resend must be in [0, 10], got %d", config->kcp_resend);
        return -1;
    }
    if (config->kcp_nc < 0 || config->kcp_nc > 1) {
        LOG_ERROR("kcp.nc must be 0 or 1, got %d", config->kcp_nc);
        return -1;
    }

    /* ── 阶段 3: 性能参数校验 ── */

    /* heartbeat_interval >= 0（0 = 禁用心跳） */
    if (config->heartbeat_interval < 0) {
        LOG_ERROR("heartbeat_interval must be >= 0, got %d", config->heartbeat_interval);
        return -1;
    }
    if (config->heartbeat_timeout < 0) {
        LOG_ERROR("heartbeat_timeout must be >= 0, got %d", config->heartbeat_timeout);
        return -1;
    }

    /* AF_PACKET 发送/接收缓冲区：0=使用系统默认，非零需 ≥4KB */
    if (config->perf_af_packet_sndbuf != 0 &&
        config->perf_af_packet_sndbuf < 4096) {
        LOG_ERROR("performance.af_packet_sndbuf must be >= 4096, got %d",
                  config->perf_af_packet_sndbuf);
        return -1;
    }
    if (config->perf_af_packet_rcvbuf != 0 &&
        config->perf_af_packet_rcvbuf < 4096) {
        LOG_ERROR("performance.af_packet_rcvbuf must be >= 4096, got %d",
                  config->perf_af_packet_rcvbuf);
        return -1;
    }
    /* AF_PACKET 发送重试次数: 上限 100
     * retry_max=1000 * wait_ms=1ms = 1s 会阻塞事件循环，收紧至 100 */
    if (config->perf_af_packet_send_retry_max < 0 ||
        config->perf_af_packet_send_retry_max > 100) {
        LOG_ERROR("performance.af_packet_send_retry_max must be in [0, 100], got %d",
                  config->perf_af_packet_send_retry_max);
        return -1;
    }
    if (config->perf_af_packet_send_wait_ms < 0 ||
        config->perf_af_packet_send_wait_ms > 100) {
        LOG_ERROR("performance.af_packet_send_wait_ms must be in [0, 100], got %d",
                  config->perf_af_packet_send_wait_ms);
        return -1;
    }
    /* 代理端 TCP socket 缓冲区 */
    if (config->perf_proxy_tcp_sockbuf != 0 &&
        config->perf_proxy_tcp_sockbuf < 4096) {
        LOG_ERROR("performance.proxy_tcp_sockbuf must be >= 4096, got %d",
                  config->perf_proxy_tcp_sockbuf);
        return -1;
    }
    /* 代理端接收缓冲区上限 */
    if (config->perf_proxy_recv_buf_max != 0 &&
        config->perf_proxy_recv_buf_max < KCP_APP_RECV_BUF_SIZE) {
        LOG_ERROR("performance.proxy_recv_buf_max must be >= %d, got %d",
                  KCP_APP_RECV_BUF_SIZE, config->perf_proxy_recv_buf_max);
        return -1;
    }
    /* KCP 读暂停/恢复阈值 */
    if (config->perf_kcp_read_pause_waitsnd < 0) {
        LOG_ERROR("performance.kcp_read_pause_waitsnd must be >= 0, got %d",
                  config->perf_kcp_read_pause_waitsnd);
        return -1;
    }
    if (config->perf_kcp_read_resume_waitsnd < 0) {
        LOG_ERROR("performance.kcp_read_resume_waitsnd must be >= 0, got %d",
                  config->perf_kcp_read_resume_waitsnd);
        return -1;
    }
    /* resume_waitsnd 必须 ≤ pause_waitsnd（否则永远无法恢复） */
    {
        int pause_waitsnd = (config->perf_kcp_read_pause_waitsnd > 0)
                                ? config->perf_kcp_read_pause_waitsnd
                                : PERF_KCP_READ_PAUSE_WAITSND;
        int resume_waitsnd = (config->perf_kcp_read_resume_waitsnd > 0)
                                 ? config->perf_kcp_read_resume_waitsnd
                                 : PERF_KCP_READ_RESUME_WAITSND;
        if (resume_waitsnd > pause_waitsnd) {
            LOG_ERROR("performance.kcp_read_resume_waitsnd must be <= pause_waitsnd, got %d > %d",
                      resume_waitsnd, pause_waitsnd);
            return -1;
        }
    }
    /* KCP 立即刷新开关（0 或 1） */
    if (config->perf_kcp_immediate_flush < 0 ||
        config->perf_kcp_immediate_flush > 1) {
        LOG_ERROR("performance.kcp_immediate_flush must be 0 or 1, got %d",
                  config->perf_kcp_immediate_flush);
        return -1;
    }
    /* 每周期最大帧处理数: 0=关闭限制, 非零需在 [1, 1000000] */
    if (config->perf_max_frames_per_cycle != 0 &&
        (config->perf_max_frames_per_cycle < 1 ||
         config->perf_max_frames_per_cycle > 1000000)) {
        LOG_ERROR("performance.max_frames_per_cycle must be in [1, 1000000], got %d",
                  config->perf_max_frames_per_cycle);
        return -1;
    }

    /* ── 阶段 4: 节点类型与容量校验 ── */

    /* node_type 校验: 必须是 frontend 或 backend */
    if (config->node_type != NODE_TYPE_FRONTEND && config->node_type != NODE_TYPE_BACKEND) {
        LOG_ERROR("Invalid node_type: %d", config->node_type);
        return -1;
    }

    /* max_channels 验证: [1, MAX_CHANNELS]
     * 此值决定通道哈希表的桶数（max_channels * 2），影响内存开销 */
    if (config->max_channels < 1 || config->max_channels > MAX_CHANNELS) {
        LOG_ERROR("max_channels %d out of range [1, %d]", config->max_channels, MAX_CHANNELS);
        return -1;
    }

    /* 至少有一个通道（管理/API 模式除外） */
    if (config->channel_count == 0
        && !config->management.enabled
        && !config->api_enabled) {
        LOG_ERROR("At least one channel must be configured (or enable management/API)");
        return -1;
    }

    /* ── 阶段 5: keepalive / 内存上限校验 ── */

    /* 管理模块 keepalive 参数下限检查 */
    if (config->management.enabled) {
        if (config->management.keepalive_interval < 1) {
            LOG_ERROR("management.keepalive_interval must be >= 1, got %d",
                      config->management.keepalive_interval);
            return -1;
        }
        if (config->management.keepalive_timeout < config->management.keepalive_interval) {
            LOG_ERROR("management.keepalive_timeout (%d) must be >= keepalive_interval (%d)",
                      config->management.keepalive_timeout,
                      config->management.keepalive_interval);
            return -1;
        }
        if (config->management.reconnect_interval < 1) {
            LOG_ERROR("management.reconnect_interval must be >= 1, got %d",
                      config->management.reconnect_interval);
            return -1;
        }
    }

    /* 内存配额上限校验: max_memory_mb ∈ [0, 65536]
     * 0=不限制，最大值 64GB */
    if (config->perf_max_memory_mb < 0 || config->perf_max_memory_mb > 65536) {
        LOG_ERROR("performance.max_memory_mb must be in [0, 65536], got %d",
                  config->perf_max_memory_mb);
        return -1;
    }

    /* channel_count=0 仅 WARN（允许 management-only 模式，但数据面不可用） */
    if (config->channel_count == 0) {
        LOG_WARN("channel_count=0: no data channels configured — relay will drop all traffic");
    }

    /* ── 阶段 6: 通道 ID 唯一性和有效性校验 ── */

    for (int i = 0; i < config->channel_count; i++) {
        const channel_config_t *ch = &config->channels[i];

        /* channel_id 必须 > 0（0 保留给管理通道） */
        if (ch->channel_id == 0) {
            LOG_ERROR("Channel %d: channel_id must be > 0", i);
            return -1;
        }

        /* listen_port 必须是合法端口号 */
        if (ch->listen_port < 1) {
            LOG_ERROR("Channel %d (id=%u): listen_port %u out of range [1, 65535]",
                      i, ch->channel_id, ch->listen_port);
            return -1;
        }

        /* remote_port 必须是合法端口号 */
        if (ch->remote_port < 1) {
            LOG_ERROR("Channel %d (id=%u): remote_port %u out of range [1, 65535]",
                      i, ch->channel_id, ch->remote_port);
            return -1;
        }

        /* listen_addr 和 remote_addr 进行完整性提示 */
        if (ch->listen_addr[0] == '\0')
            LOG_WARN("Channel %d (id=%u): listen_addr is empty (will default to 0.0.0.0)",
                     i, ch->channel_id);
        if (ch->remote_addr[0] == '\0')
            LOG_WARN("Channel %d (id=%u): remote_addr is empty",
                     i, ch->channel_id);

        /* max_sessions 必须 > 0 */
        if (ch->max_sessions == 0) {
            LOG_ERROR("Channel %d (id=%u): max_sessions must be > 0, got 0",
                      i, ch->channel_id);
            return -1;
        }

        /* channel_id 唯一性检查：O(n²) 但 channel 数量通常较小 */
        for (int j = i + 1; j < config->channel_count; j++) {
            if (ch->channel_id == config->channels[j].channel_id) {
                LOG_ERROR("Duplicate channel_id %u at indices %d and %d",
                          ch->channel_id, i, j);
                return -1;
            }
        }
    }

    /* ── 阶段 7: 加密配置校验 ── */

    if (config->encryption.enabled) {
        /* 加密已启用但未提供密钥 */
        if (config->encryption.sm4_key[0] == '\0') {
            LOG_ERROR("Encryption is enabled but no sm4_key provided "
                      "(need %d hex characters)", SM4_KEY_HEX_LEN);
            return -1;
        }
        /* SM4 密钥必须是 32 字符 hex 字符串（128 位） */
        if (strlen(config->encryption.sm4_key) != SM4_KEY_HEX_LEN) {
            LOG_ERROR("Encryption sm4_key must be exactly %d hex characters, got %zu",
                      SM4_KEY_HEX_LEN, strlen(config->encryption.sm4_key));
            return -1;
        }
    }

    LOG_INFO("Configuration validated successfully: %s, %d channels, ethertype=0x%04X",
             config->node_type == NODE_TYPE_FRONTEND ? "frontend" : "backend",
             config->channel_count, config->ethertype);

    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * master_config_load — 解析多实例配置文件 (kcp-multi.json)
 *
 * 格式：
 *   { "shared": { <全局默认配置> },
 *     "instances": [ { <实例差异化配置> }, ... ] }
 *
 * shared 字段与单实例 config.json 兼容，instances[] 中字段覆盖 shared。
 * 必填的实例级字段：ethertype、channels
 *
 * @param path    多实例配置文件路径
 * @param config  输出：填充后的 master 配置
 * @return        0=成功, -1=失败
 * ────────────────────────────────────────────────────────────────────────── */
static int master_config_load(const char *path, master_config_t *config)
{
    json_object *root = NULL, *shared_obj = NULL, *inst_arr = NULL, *tmp = NULL;
    int ret = -1;

    memset(config, 0, sizeof(*config));
    config->worker_count = 0;

    root = json_object_from_file(path);
    if (!root) {
        LOG_ERROR("Failed to parse master config file: %s", path);
        return -1;
    }

    /* ── 1. 解析 shared 默认配置 ── */
    if (!json_object_object_get_ex(root, "shared", &shared_obj)) {
        LOG_ERROR("Master config missing 'shared' section");
        goto cleanup;
    }

    /* interface */
    if (json_object_object_get_ex(shared_obj, "interface", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s) {
            strncpy(config->shared.interface, s, MAX_INTERFACE_NAME - 1);
            config->shared.interface[MAX_INTERFACE_NAME - 1] = '\0';
        }
    }

    /* node_type */
    if (json_object_object_get_ex(shared_obj, "node_type", &tmp)) {
        const char *s = json_object_get_string(tmp);
        config->shared.node_type = (s && strcmp(s, "backend") == 0)
            ? NODE_TYPE_BACKEND : NODE_TYPE_FRONTEND;
    } else {
        config->shared.node_type = NODE_TYPE_FRONTEND;
    }

    /* KCP defaults */
    config->shared.kcp_mtu = KCP_MTU_CONSERVATIVE;
    config->shared.kcp_send_window = KCP_SEND_WINDOW;
    config->shared.kcp_recv_window = KCP_RECV_WINDOW;
    config->shared.kcp_nodelay = KCP_NODELAY;
    config->shared.kcp_interval = KCP_INTERVAL;
    config->shared.kcp_resend = KCP_RESEND;
    config->shared.kcp_nc = KCP_NC;

    {
        json_object *kcp_obj = NULL;
        if (json_object_object_get_ex(shared_obj, "kcp", &kcp_obj)) {
            if (json_object_object_get_ex(kcp_obj, "mtu", &tmp))
                config->shared.kcp_mtu = json_object_get_int(tmp);
            if (json_object_object_get_ex(kcp_obj, "sndwnd", &tmp))
                config->shared.kcp_send_window = json_object_get_int(tmp);
            if (json_object_object_get_ex(kcp_obj, "rcvwnd", &tmp))
                config->shared.kcp_recv_window = json_object_get_int(tmp);
            if (json_object_object_get_ex(kcp_obj, "nodelay", &tmp))
                config->shared.kcp_nodelay = json_object_get_int(tmp);
            if (json_object_object_get_ex(kcp_obj, "interval", &tmp))
                config->shared.kcp_interval = json_object_get_int(tmp);
            if (json_object_object_get_ex(kcp_obj, "resend", &tmp))
                config->shared.kcp_resend = json_object_get_int(tmp);
            if (json_object_object_get_ex(kcp_obj, "nc", &tmp))
                config->shared.kcp_nc = json_object_get_int(tmp);
        }
    }

    /* heartbeat */
    config->shared.heartbeat_interval = HEARTBEAT_INTERVAL;
    config->shared.heartbeat_timeout  = HEARTBEAT_TIMEOUT;
    if (json_object_object_get_ex(shared_obj, "heartbeat_interval", &tmp))
        config->shared.heartbeat_interval = json_object_get_int(tmp);
    if (json_object_object_get_ex(shared_obj, "heartbeat_timeout", &tmp))
        config->shared.heartbeat_timeout = json_object_get_int(tmp);

    /* encryption */
    {
        json_object *enc_obj = NULL;
        if (json_object_object_get_ex(shared_obj, "encryption", &enc_obj)) {
            if (json_object_object_get_ex(enc_obj, "enabled", &tmp))
                config->shared.encryption.enabled = json_object_get_boolean(tmp) ? 1 : 0;
            if (json_object_object_get_ex(enc_obj, "sm4_key", &tmp)) {
                const char *hex_key = json_object_get_string(tmp);
                if (hex_key && strlen(hex_key) == SM4_KEY_HEX_LEN) {
                    strncpy(config->shared.encryption.sm4_key, hex_key, SM4_KEY_HEX_LEN);
                    config->shared.encryption.sm4_key[SM4_KEY_HEX_LEN] = '\0';
                }
            }
        }
    }

    /* crc / mtu / max_channels */
    config->shared.crc_enabled = 0;
    config->shared.auto_set_nic_mtu = 0;
    config->shared.nic_mtu = ETH_MTU;
    config->shared.max_channels = 65536;
    if (json_object_object_get_ex(shared_obj, "crc_enabled", &tmp))
        config->shared.crc_enabled = json_object_get_boolean(tmp) ? 1 : 0;
    if (json_object_object_get_ex(shared_obj, "auto_set_nic_mtu", &tmp))
        config->shared.auto_set_nic_mtu = json_object_get_boolean(tmp) ? 1 : 0;
    if (json_object_object_get_ex(shared_obj, "nic_mtu", &tmp))
        config->shared.nic_mtu = json_object_get_int(tmp);
    if (json_object_object_get_ex(shared_obj, "auto_kcp_mtu", &tmp))
        config->shared.auto_kcp_mtu = json_object_get_boolean(tmp) ? 1 : 0;
    if (json_object_object_get_ex(shared_obj, "max_channels", &tmp))
        config->shared.max_channels = json_object_get_int(tmp);

    /* peer_mac / local_mac */
    if (json_object_object_get_ex(shared_obj, "peer_mac", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s && strlen(s) > 0) parse_mac_string(s, config->shared.peer_mac);
    }
    if (json_object_object_get_ex(shared_obj, "local_mac", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s && strlen(s) > 0) parse_mac_string(s, config->shared.local_mac);
    }

    /* performance — use defaults, overridden if present */
    config->shared.perf_af_packet_sndbuf = PERF_AF_PACKET_SNDBUF;
    config->shared.perf_af_packet_rcvbuf = PERF_AF_PACKET_RCVBUF;
    config->shared.perf_af_packet_send_retry_max = PERF_AF_PACKET_SEND_RETRY_MAX;
    config->shared.perf_af_packet_send_wait_ms = PERF_AF_PACKET_SEND_WAIT_MS;
    config->shared.perf_proxy_tcp_sockbuf = PERF_PROXY_TCP_SOCKBUF;
    config->shared.perf_proxy_recv_buf_max = PERF_PROXY_RECV_BUF_MAX;
    config->shared.perf_kcp_read_pause_waitsnd = PERF_KCP_READ_PAUSE_WAITSND;
    config->shared.perf_kcp_read_resume_waitsnd = PERF_KCP_READ_RESUME_WAITSND;
    config->shared.perf_kcp_immediate_flush = PERF_KCP_IMMEDIATE_FLUSH;
    config->shared.perf_max_frames_per_cycle = PERF_MAX_FRAMES_PER_CYCLE;
    {
        json_object *perf_obj = NULL;
        if (json_object_object_get_ex(shared_obj, "performance", &perf_obj)) {
            if (json_object_object_get_ex(perf_obj, "af_packet_sndbuf", &tmp))
                config->shared.perf_af_packet_sndbuf = json_object_get_int(tmp);
            if (json_object_object_get_ex(perf_obj, "af_packet_rcvbuf", &tmp))
                config->shared.perf_af_packet_rcvbuf = json_object_get_int(tmp);
            if (json_object_object_get_ex(perf_obj, "af_packet_send_retry_max", &tmp))
                config->shared.perf_af_packet_send_retry_max = json_object_get_int(tmp);
            if (json_object_object_get_ex(perf_obj, "af_packet_send_wait_ms", &tmp))
                config->shared.perf_af_packet_send_wait_ms = json_object_get_int(tmp);
            if (json_object_object_get_ex(perf_obj, "proxy_tcp_sockbuf", &tmp))
                config->shared.perf_proxy_tcp_sockbuf = json_object_get_int(tmp);
            if (json_object_object_get_ex(perf_obj, "proxy_recv_buf_max", &tmp))
                config->shared.perf_proxy_recv_buf_max = json_object_get_int(tmp);
            if (json_object_object_get_ex(perf_obj, "kcp_read_pause_waitsnd", &tmp))
                config->shared.perf_kcp_read_pause_waitsnd = json_object_get_int(tmp);
            if (json_object_object_get_ex(perf_obj, "kcp_read_resume_waitsnd", &tmp))
                config->shared.perf_kcp_read_resume_waitsnd = json_object_get_int(tmp);
            if (json_object_object_get_ex(perf_obj, "kcp_immediate_flush", &tmp))
                config->shared.perf_kcp_immediate_flush = json_object_get_boolean(tmp) ? 1 : 0;
            if (json_object_object_get_ex(perf_obj, "max_frames_per_cycle", &tmp))
                config->shared.perf_max_frames_per_cycle = json_object_get_int(tmp);
        }
    }

    /* master pid_file */
    if (json_object_object_get_ex(root, "pid_file", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s) {
            strncpy(config->pid_file, s, MAX_PID_PATH - 1);
            config->pid_file[MAX_PID_PATH - 1] = '\0';
        }
    }

    /* daemonize */
    if (json_object_object_get_ex(root, "daemonize", &tmp))
        config->daemonize = json_object_get_boolean(tmp) ? 1 : 0;

    /* ── 2. 解析 instances[] 数组 ──
     * 遍历每个实例，解析其差异化配置。
     * 每个实例必填 ethertype，可选覆盖 KCP/加密/心跳/CRC 等参数。
     * channels 通过堆分配 (calloc) 存储，函数结束时不释放（所有权转移给调用者）。 */
    if (!json_object_object_get_ex(root, "instances", &inst_arr) ||
        !json_object_is_type(inst_arr, json_type_array)) {
        LOG_ERROR("Master config missing 'instances' array");
        goto cleanup;
    }

    int inst_count = json_object_array_length(inst_arr);
    if (inst_count > MAX_INSTANCES) {
        LOG_ERROR("Too many instances (%d), max is %d", inst_count, MAX_INSTANCES);
        goto cleanup;
    }
    config->instance_count = inst_count;

    for (int i = 0; i < inst_count; i++) {
        json_object *inst_obj = json_object_array_get_idx(inst_arr, (size_t)i);
        instance_config_t *inst = &config->instances[i];

        memset(inst, 0, sizeof(*inst));
        inst->cpu_affinity = -1;       /* -1 = 不绑定 CPU */
        /* 标记所有可覆盖字段为 "使用 shared 默认值" (-1 = 未设置) */
        inst->kcp_mtu = -1;
        inst->auto_kcp_mtu = -1;
        inst->kcp_send_window = -1;
        inst->kcp_recv_window = -1;
        inst->kcp_nodelay = -1;
        inst->kcp_interval = -1;
        inst->kcp_resend = -1;
        inst->kcp_nc = -1;
        inst->heartbeat_interval = -1;
        inst->heartbeat_timeout = -1;
        inst->crc_enabled = -1;        /* -1 = 使用 shared 默认值 */
        inst->encryption_enabled = -1; /* -1 = 使用 shared 默认值 */

        /* instance_name (required for identification) */
        if (json_object_object_get_ex(inst_obj, "instance_name", &tmp)) {
            const char *s = json_object_get_string(tmp);
            if (s) {
                strncpy(inst->instance_name, s, MAX_LISTEN_ADDR - 1);
                inst->instance_name[MAX_LISTEN_ADDR - 1] = '\0';
            }
        }
        if (inst->instance_name[0] == '\0') {
            snprintf(inst->instance_name, MAX_LISTEN_ADDR, "instance-%d", i);
            LOG_WARN("Auto-generated instance name: %s", inst->instance_name);
        }

        /* source: 读取 JSON 中的标记，缺省 "static" */
        if (json_object_object_get_ex(inst_obj, "source", &tmp)) {
            const char *s = json_object_get_string(tmp);
            if (s) { strncpy(inst->source, s, 15); inst->source[15] = '\0'; }
        } else {
            strncpy(inst->source, "static", 15);
        }

        /* node_id (可选): 覆盖 shared.node.node_id，未设置时继承 shared */
        if (json_object_object_get_ex(inst_obj, "node_id", &tmp)) {
            const char *s = json_object_get_string(tmp);
            if (s) {
                strncpy(inst->node_id, s, 64);
                inst->node_id[64] = '\0';
            }
        }

        /* ethertype (required) */
        if (json_object_object_get_ex(inst_obj, "ethertype", &tmp)) {
            inst->ethertype = (uint16_t)json_object_get_int(tmp);
        } else {
            LOG_ERROR("Instance '%s': ethertype is required", inst->instance_name);
            goto cleanup;
        }
        if (inst->ethertype < 0x0600) {
            LOG_ERROR("Instance '%s': ethertype 0x%04X < 0x0600 (reserved)",
                      inst->instance_name, inst->ethertype);
            goto cleanup;
        }

        /* pid_file */
        if (json_object_object_get_ex(inst_obj, "pid_file", &tmp)) {
            const char *s = json_object_get_string(tmp);
            if (s) {
                strncpy(inst->pid_file, s, MAX_PID_PATH - 1);
                inst->pid_file[MAX_PID_PATH - 1] = '\0';
            }
        }

        /* cpu_affinity */
        if (json_object_object_get_ex(inst_obj, "cpu_affinity", &tmp))
            inst->cpu_affinity = json_object_get_int(tmp);

        /* auto_kcp_mtu override (-1 = use shared) */
        if (json_object_object_get_ex(inst_obj, "auto_kcp_mtu", &tmp))
            inst->auto_kcp_mtu = json_object_get_boolean(tmp) ? 1 : 0;

        /* node_type override */
        if (json_object_object_get_ex(inst_obj, "node_type", &tmp)) {
            const char *s = json_object_get_string(tmp);
            inst->node_type = (s && strcmp(s, "backend") == 0)
                ? NODE_TYPE_BACKEND : NODE_TYPE_FRONTEND;
        } else {
            inst->node_type = NODE_TYPE_FRONTEND; /* sentinel: use shared */
        }

        /* heartbeat overrides */
        if (json_object_object_get_ex(inst_obj, "heartbeat_interval", &tmp))
            inst->heartbeat_interval = json_object_get_int(tmp);
        if (json_object_object_get_ex(inst_obj, "heartbeat_timeout", &tmp))
            inst->heartbeat_timeout = json_object_get_int(tmp);

        /* crc override */
        if (json_object_object_get_ex(inst_obj, "crc_enabled", &tmp))
            inst->crc_enabled = json_object_get_boolean(tmp) ? 1 : 0;

        /* encryption override */
        {
            json_object *enc_obj = NULL;
            if (json_object_object_get_ex(inst_obj, "encryption", &enc_obj)) {
                if (json_object_object_get_ex(enc_obj, "enabled", &tmp))
                    inst->encryption_enabled = json_object_get_boolean(tmp) ? 1 : 0;
                if (json_object_object_get_ex(enc_obj, "sm4_key", &tmp)) {
                    const char *hex_key = json_object_get_string(tmp);
                    if (hex_key && strlen(hex_key) == SM4_KEY_HEX_LEN) {
                        strncpy(inst->sm4_key, hex_key, SM4_KEY_HEX_LEN);
                        inst->sm4_key[SM4_KEY_HEX_LEN] = '\0';
                    }
                }
            }
        }

        /* KCP overrides */
        {
            json_object *kcp_obj = NULL;
            if (json_object_object_get_ex(inst_obj, "kcp", &kcp_obj)) {
                if (json_object_object_get_ex(kcp_obj, "mtu", &tmp))
                    inst->kcp_mtu = json_object_get_int(tmp);
                if (json_object_object_get_ex(kcp_obj, "sndwnd", &tmp))
                    inst->kcp_send_window = json_object_get_int(tmp);
                if (json_object_object_get_ex(kcp_obj, "rcvwnd", &tmp))
                    inst->kcp_recv_window = json_object_get_int(tmp);
                if (json_object_object_get_ex(kcp_obj, "nodelay", &tmp))
                    inst->kcp_nodelay = json_object_get_int(tmp);
                if (json_object_object_get_ex(kcp_obj, "interval", &tmp))
                    inst->kcp_interval = json_object_get_int(tmp);
                if (json_object_object_get_ex(kcp_obj, "resend", &tmp))
                    inst->kcp_resend = json_object_get_int(tmp);
                if (json_object_object_get_ex(kcp_obj, "nc", &tmp))
                    inst->kcp_nc = json_object_get_int(tmp);
            }
        }

        /* peer_mac / local_mac override */
        if (json_object_object_get_ex(inst_obj, "peer_mac", &tmp)) {
            const char *s = json_object_get_string(tmp);
            if (s) {
                strncpy(inst->peer_mac_str, s, sizeof(inst->peer_mac_str) - 1);
                inst->peer_mac_str[sizeof(inst->peer_mac_str) - 1] = '\0';
            }
        }
        if (json_object_object_get_ex(inst_obj, "local_mac", &tmp)) {
            const char *s = json_object_get_string(tmp);
            if (s) {
                strncpy(inst->local_mac_str, s, sizeof(inst->local_mac_str) - 1);
                inst->local_mac_str[sizeof(inst->local_mac_str) - 1] = '\0';
            }
        }

        /* channels[] (required per instance) */
        if (json_object_object_get_ex(inst_obj, "channels", &tmp)) {
            int arr_len = json_object_array_length(tmp);
            if (arr_len > MAX_CHANNELS) {
                LOG_ERROR("Instance '%s': too many channels (%d)", inst->instance_name, arr_len);
                goto cleanup;
            }
            inst->channels = calloc((size_t)arr_len, sizeof(channel_config_t));
            if (!inst->channels) {
                LOG_ERROR("Instance '%s': out of memory for channels", inst->instance_name);
                goto cleanup;
            }
            inst->channel_count = 0;
            inst->channel_capacity = arr_len;
            for (int ci = 0; ci < arr_len; ci++) {
                json_object *ch_obj = json_object_array_get_idx(tmp, (size_t)ci);
                channel_config_t *ch_cfg = &inst->channels[inst->channel_count];
                json_object *field = NULL;

                memset(ch_cfg, 0, sizeof(*ch_cfg));
                ch_cfg->is_tcp = 1;
                if (json_object_object_get_ex(ch_obj, "enabled", &field))
                    ch_cfg->enabled = json_object_get_boolean(field) ? 1 : 0;
                else
                    ch_cfg->enabled = 1;
                ch_cfg->max_sessions = 1;

                if (json_object_object_get_ex(ch_obj, "channel_id", &field)) {
                    int raw = json_object_get_int(field);
                    if (raw <= 0) {
                        LOG_ERROR("Instance '%s' channel %d: invalid channel_id",
                                  inst->instance_name, ci);
                        goto cleanup;
                    }
                    ch_cfg->channel_id = (uint32_t)raw;
                }
                if (json_object_object_get_ex(ch_obj, "listen_port", &field))
                    ch_cfg->listen_port = (uint16_t)json_object_get_int(field);
                if (json_object_object_get_ex(ch_obj, "remote_port", &field))
                    ch_cfg->remote_port = (uint16_t)json_object_get_int(field);
                if (json_object_object_get_ex(ch_obj, "listen_addr", &field)) {
                    const char *s = json_object_get_string(field);
                    if (s) {
                        strncpy(ch_cfg->listen_addr, s, MAX_LISTEN_ADDR - 1);
                        ch_cfg->listen_addr[MAX_LISTEN_ADDR - 1] = '\0';
                    }
                }
                if (json_object_object_get_ex(ch_obj, "remote_addr", &field)) {
                    const char *s = json_object_get_string(field);
                    if (s) {
                        strncpy(ch_cfg->remote_addr, s, MAX_REMOTE_ADDR - 1);
                        ch_cfg->remote_addr[MAX_REMOTE_ADDR - 1] = '\0';
                    }
                }
                if (json_object_object_get_ex(ch_obj, "is_tcp", &field))
                    ch_cfg->is_tcp = json_object_get_boolean(field) ? 1 : 0;
                if (json_object_object_get_ex(ch_obj, "max_sessions", &field)) {
                    int ms = json_object_get_int(field);
                    ch_cfg->max_sessions = (ms > 0 && ms <= 65535) ? (uint16_t)ms : 1;
                }
                if (json_object_object_get_ex(ch_obj, "source_port", &field))
                    ch_cfg->source_port = (uint16_t)json_object_get_int(field);
                inst->channel_count++;
            }
        }
        if (inst->channel_count == 0) {
            LOG_WARN("Instance '%s': no channels configured", inst->instance_name);
        }
    }

    /* ── Instance name 去重检查 ── */
    for (int i = 0; i < config->instance_count; i++) {
        for (int j = i + 1; j < config->instance_count; j++) {
            if (strcmp(config->instances[i].instance_name,
                       config->instances[j].instance_name) == 0) {
                LOG_ERROR("Duplicate instance_name '%s'",
                          config->instances[i].instance_name);
                ret = -1;
                goto cleanup;
            }
        }
    }

    /* ── EtherType 去重检查：两台实例同 EtherType 导致帧重复 ── */
    for (int i = 0; i < config->instance_count; i++) {
        for (int j = i + 1; j < config->instance_count; j++) {
            if (config->instances[i].ethertype == config->instances[j].ethertype) {
                LOG_ERROR("EtherType conflict: instances '%s' and '%s' both use 0x%04X",
                          config->instances[i].instance_name,
                          config->instances[j].instance_name,
                          config->instances[i].ethertype);
                ret = -1;
                goto cleanup;
            }
        }
    }

    /* ── CPU affinity 冲突检测 ── */
    {
        int seen[MAX_INSTANCES];
        memset(seen, 0, sizeof(seen));
        for (int i = 0; i < inst_count; i++) {
            int ca = config->instances[i].cpu_affinity;
            if (ca >= 0) {
                if (ca >= MAX_INSTANCES) {
                    LOG_ERROR("Instance '%s': cpu_affinity %d out of range [0, %d)",
                              config->instances[i].instance_name,
                              ca, MAX_INSTANCES);
                    ret = -1;
                    goto cleanup;
                }
                if (seen[ca]) {
                    /* WARN is correct: CPU affinity collision is not fatal;
                     * the OS scheduler will time-share the CPU core. */
                    LOG_WARN("CPU affinity collision: '%s' and '%s' both bound to CPU %d",
                             config->instances[seen[ca] - 1].instance_name,
                             config->instances[i].instance_name, ca);
                } else {
                    seen[ca] = i + 1;
                }
            }
        }
    }

    ret = 0;  /* 全部解析成功 */

cleanup:
    if (ret != 0) {
        /* 解析失败时释放各实例的 channels 堆分配（防止内存泄漏） */
        for (int i = 0; i < config->instance_count; i++) {
            free(config->instances[i].channels);
            config->instances[i].channels = NULL;
        }
    }
    json_object_put(root);   /* 释放 json-c 根对象 */
    return ret;
}

/* ──────────────────────────────────────────────────────────────────────────
 * master_config_free — 释放 master_config_t 中的堆分配资源
 *
 * 包括: worker heartbeat pipe fd + 各实例的 channels 数组。
 * ────────────────────────────────────────────────────────────────────────── */
static void master_config_free(master_config_t *cfg)
{
    if (!cfg) return;
    for (int i = 0; i < cfg->worker_count; i++) {
        if (cfg->workers[i].heartbeat_fd >= 0) {
            close(cfg->workers[i].heartbeat_fd);
            cfg->workers[i].heartbeat_fd = -1;
        }
    }
    for (int i = 0; i < cfg->instance_count; i++) {
        free(cfg->instances[i].channels);
        cfg->instances[i].channels = NULL;
    }
    free(cfg);
}

/* ──────────────────────────────────────────────────────────────────────────
 * build_instance_global_config — 将实例配置合并为完整的 global_config_t
 *
 * shared 提供 baseline，instance 中的非默认值覆盖对应字段。
 * 这个函数在 worker fork 前由 master 调用，生成的 global_config_t
 * 通过 fork 继承给 worker 子进程。
 *
 * @param inst    实例差异化配置
 * @param master  master 配置（含 shared 默认值）
 * @param out     输出：合并后的完整配置
 * ────────────────────────────────────────────────────────────────────────── */
static void build_instance_global_config(const instance_config_t *inst,
                                          const master_config_t *master,
                                          global_config_t *out)
{
    /* ── 字段合并：shared 默认值 + instance 覆盖 → 完整 global_config_t ──
     *
     * 合并策略（三层优先级）:
     *   1. 先从 master->shared 全量复制基线配置
     *   2. 再逐字段检查 instance 是否提供了非默认值，有则覆盖
     *   3. 必覆盖的实例级字段: ethertype, instance_name, pid_file, channels
     *
     * "非默认值"判定: int=0/负值→不覆盖, 字符串为空→不覆盖, 指针为NULL→不覆盖 */

    /* 第一层: 从 shared 复制 baseline（所有字段的默认值） */
    memcpy(out, &master->shared, sizeof(global_config_t));
    out->heartbeat_fd = -1;          /* standalone 默认无 watchdog pipe */
    /* 清零 shared 的 channels 字段，避免与 instance channels 双重拷贝 */
    out->channel_count = 0;
    memset(out->channels, 0, sizeof(out->channels));

    /* ── 第二层: 实例级必覆盖字段 ── */

    /* ethertype — 必须由实例指定（不可从 shared 继承） */
    out->ethertype = inst->ethertype;

    /* instance_name — 实例名称（用于日志标识和 socket 文件命名） */
    if (inst->instance_name[0] != '\0') {
        strncpy(out->instance_name, inst->instance_name, MAX_LISTEN_ADDR - 1);
        out->instance_name[MAX_LISTEN_ADDR - 1] = '\0';
    }

    /* node_id — 管理节点标识（Manager 侧 Worker 唯一标识）。
     * 实例未指定时继承 shared.node.node_id（向后兼容） */
    if (inst->node_id[0] != '\0') {
        strncpy(out->node.node_id, inst->node_id, 64);
        out->node.node_id[64] = '\0';
    }

    /* pid_file — 每个实例的 PID 文件路径 */
    if (inst->pid_file[0] != '\0') {
        strncpy(out->pid_file, inst->pid_file, MAX_PID_PATH - 1);
        out->pid_file[MAX_PID_PATH - 1] = '\0';
    }

    /* ── 第三层: 可选覆盖字段（仅当实例提供了非默认值） ── */

    /* node_type: 覆盖 shared 默认值（frontend/backend） */
    if (inst->node_type != NODE_TYPE_FRONTEND ||
        (inst->node_type == NODE_TYPE_BACKEND))
        out->node_type = inst->node_type;

    /* 心跳参数覆盖 */
    if (inst->heartbeat_interval > 0)
        out->heartbeat_interval = inst->heartbeat_interval;
    if (inst->heartbeat_timeout > 0)
        out->heartbeat_timeout = inst->heartbeat_timeout;

    /* CRC 覆盖（-1 = 未设置，非负 = 已显式指定） */
    if (inst->crc_enabled >= 0)
        out->crc_enabled = (uint8_t)inst->crc_enabled;

    /* 加密覆盖: enabled 标记 + sm4_key */
    if (inst->encryption_enabled >= 0)
        out->encryption.enabled = (uint8_t)inst->encryption_enabled;
    if (inst->sm4_key[0] != '\0') {
        strncpy(out->encryption.sm4_key, inst->sm4_key, SM4_KEY_HEX_LEN);
        out->encryption.sm4_key[SM4_KEY_HEX_LEN] = '\0';
    }

    /* KCP 参数覆盖（非零才覆盖，保留 shared 默认值） */
    if (inst->kcp_mtu > 0) out->kcp_mtu = inst->kcp_mtu;
    if (inst->auto_kcp_mtu >= 0) out->auto_kcp_mtu = inst->auto_kcp_mtu;
    if (inst->kcp_send_window > 0) out->kcp_send_window = inst->kcp_send_window;
    if (inst->kcp_recv_window > 0) out->kcp_recv_window = inst->kcp_recv_window;
    if (inst->kcp_nodelay >= 0) out->kcp_nodelay = inst->kcp_nodelay;
    if (inst->kcp_interval > 0) out->kcp_interval = inst->kcp_interval;
    if (inst->kcp_resend >= 0) out->kcp_resend = inst->kcp_resend;
    if (inst->kcp_nc >= 0) out->kcp_nc = inst->kcp_nc;

    /* MAC 地址覆盖: 字符串非空则解析为二进制 */
    if (inst->peer_mac_str[0] != '\0')
        parse_mac_string(inst->peer_mac_str, out->peer_mac);
    if (inst->local_mac_str[0] != '\0')
        parse_mac_string(inst->local_mac_str, out->local_mac);

    /* channels — 从堆分配的实例 channels 复制到 global_config_t */
    if (inst->channel_count <= 0 || inst->channel_count >= MAX_CHANNELS) {
        LOG_ERROR("Instance '%s': channel_count %d out of range [1, %d]",
                  inst->instance_name, inst->channel_count, MAX_CHANNELS);
        out->channel_count = 0;      /* 安全清零，让 validate_config 捕获 */
    } else {
        out->channel_count = inst->channel_count;
        if (inst->channel_count > 0 && inst->channels) {
            memcpy(out->channels, inst->channels,
                   (size_t)inst->channel_count * sizeof(channel_config_t));
        }
    }
}

/* ── 命令行使用说明 ── */
static void print_usage(const char *prog)
{
    printf("Usage:\n");
    printf("  Standalone mode:\n");
    printf("    %s <config.json>\n", prog);
    printf("  Master-Worker mode (multi-instance):\n");
    printf("    %s --master <kcp-multi.json>\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -v, --version  Print version string\n");
    printf("  -h, --help     Print this help message\n");
    printf("  --master       Run as master process managing multiple workers\n");
    printf("\n");
    printf("Gap-Proxy tunnel v" VERSION "\n");
}

static void print_version(void)
{
    printf("gapproxy v" VERSION "\n");
}

/* ---- PID 文件 ---- */
static int write_pid_file(const char *path)
{
    if (!path || !path[0]) return 0;

    FILE *f = fopen(path, "w");
    if (!f) {
        LOG_ERROR("Cannot write PID file %s: %s", path, strerror(errno));
        return -1;
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);
    LOG_INFO("PID %d written to %s", getpid(), path);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Master-Worker 多实例架构 (Nginx 风格)
 *
 * Master 进程：
 *   - 解析 kcp-multi.json，fork worker 子进程
 *   - 仅处理信号（SIGCHLD 回收子进程、SIGHUP 优雅重载、SIGTERM 优雅关闭）
 *   - 不进数据面，不持有 raw_sock / epoll / KCP
 *
 * Worker 进程：
 *   - 运行现有的单实例启动序列 + 事件循环
 *   - 与 standalone 模式共享 100% 的代码路径（worker_run）
 *   - CPU affinity 由 master 在 fork 后设置
 *
 * 优雅重载流程（SIGHUP）：
 *   1. master 重新加载 kcp-multi.json
 *   2. fork 新 worker（新配置）
 *   3. 新 worker 就绪后，SIGTERM 旧 worker
 *   4. 旧 worker 排水 → 退出 → master reap
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Master 进程的全局状态（信号处理器只能访问全局变量） */
static master_config_t *g_master_cfg = NULL;
static char g_master_config_path[512] = {0};  /* 主配置文件路径，用于派生缓存路径 */
static volatile sig_atomic_t g_master_running = 1;

/* Master 进程 worker 管理表（双重：g_master_cfg->workers[] + 本地索引） */

/* ──────────────────────────────────────────────────────────────────────────
 * worker_run — worker 进程的完整启动序列 + 主循环
 *
 * 此函数是 worker 进程（无论是 standalone main() 还是 master fork 的
 * 子进程）的唯一入口点。唯一区别是 standalone 模式 config_path 有效，
 * master-worker 模式 config_path 为 NULL（不走重载路径）。
 *
 * @param config      已构建好的全局配置
 * @param config_path 配置文件路径（NULL = master-worker 模式，无热重载）
 * @return            0=正常退出, 非0=启动失败
 * ────────────────────────────────────────────────────────────────────────── */

static void collect_nic_stats(global_ctx_t *ctx);

static int worker_run(const global_config_t *config, const char *config_path)
{
    /* ── worker 进程完整启动序列 + 主事件循环 ──
     *
     * 此函数是 worker 进程的唯一入口点（无论是 standalone main() 还是
     * master fork 的子进程）。唯一区别是 standalone 模式 config_path 有效
     * （支持热重载），master-worker 模式 config_path 为 NULL（热重载由 master
     * 通过 fork 新 worker + 排空旧 worker 实现）。
     *
     * 启动序列（约 15 步）严格按照依赖顺序执行，任一步失败立即清理退出。 */

    global_ctx_t *ctx;
    uint32_t       last_periodic_ms = 0;
    uint32_t       last_stats_sec = 0;
    int            ret;

    /* 分配并零初始化全局上下文 */
    ctx = calloc(1, sizeof(global_ctx_t));
    if (!ctx) {
        fprintf(stderr, "[ERROR] FATAL: unable to allocate global context\n");
        return 1;
    }

    /* Block SIGTERM/SIGINT before g_ctx assignment to close the race window
     * between g_ctx becoming non-NULL and setup_signals installing handlers.
     * setup_signals() will unblock them after handlers are installed. */
    {
        sigset_t block_init;
        sigemptyset(&block_init);
        sigaddset(&block_init, SIGTERM);
        sigaddset(&block_init, SIGINT);
        sigprocmask(SIG_BLOCK, &block_init, NULL);
    }
    /* calloc already zero-initialized; no memset needed */

    g_ctx = ctx;
    ctx->raw_sock = -1;              /* 初始化为 -1（cleanup 检查此值避免 double-close） */
    ctx->epoll_fd = -1;              /* 同上 */
    ctx->ctl_sock_fd = -1;           /* 同上 */
    ctx->running  = 1;              /* 主循环守卫标志 */
    ctx->reload_requested = 0;      /* SIGHUP 触发 */
    ctx->ctl_requested    = 0;      /* SIGUSR1 触发 */
    ctx->start_time = time_now();   /* 记录启动时间，供 API uptime_seconds 使用 */
    ctx->master_pid = getppid();    /* 记录父 master PID，用于 SPAWN/KILL 信号 */
    ctx->heartbeat_fd = config->heartbeat_fd;   /* master-worker 模式通过 fork 传递 */
    if (ctx->heartbeat_fd <= 0) ctx->heartbeat_fd = -1;  /* standalone 或无 watchdog */
    ctx->last_heartbeat_sent = time_now();

    /* 复制配置（堆分配，避免 config 释放后悬空） */
    memcpy(&ctx->config, config, sizeof(global_config_t));
    if (config_path) {
        strncpy(ctx->config_path, config_path, sizeof(ctx->config_path) - 1);
        ctx->config_path[sizeof(ctx->config_path) - 1] = '\0';
    }

    /* ── 验证配置 ──
     * 在创建任何系统资源之前进行配置校验，确保及早失败且不留残留资源 */
    if (validate_config(&ctx->config) != 0) {
        LOG_ERROR("Configuration validation failed");
        g_ctx = NULL;
        free(ctx);
        return 1;
    }

    /* 配置 AF_PACKET 性能参数（全局静态缓存，非 per-instance） */
    af_packet_configure(ctx->config.perf_af_packet_sndbuf,
                        ctx->config.perf_af_packet_rcvbuf,
                        ctx->config.perf_af_packet_send_retry_max,
                        ctx->config.perf_af_packet_send_wait_ms);

    /* ── 加密模块初始化 ──
     * SM4-CBC 加解密 + SM3-HMAC 消息认证，基于 Nettle 库 */
    if (ctx->config.encryption.enabled) {
        if (crypto_init(&ctx->config.encryption) < 0) {
            LOG_ERROR("Failed to initialize crypto module");
            g_ctx = NULL;
            free(ctx);
            return 1;
        }
        LOG_INFO("Crypto initialized (SM4-CBC + SM3-HMAC via Nettle)");
    }

    /* ── 安装信号处理器 ──
     * SIGINT/SIGTERM→退出, SIGHUP→热重载, SIGUSR1→通道控制, SIGPIPE→忽略 */
    if (setup_signals(ctx) != 0) {
        LOG_ERROR("Failed to setup signal handlers");
        crypto_cleanup();
        g_ctx = NULL;
        free(ctx);
        return 1;
    }

    /* ── 初始化代理子系统 ──
     * 创建 epoll 实例 (EPOLL_CLOEXEC)，后续所有 I/O 事件通过 epoll 驱动 */
    if (proxy_init(ctx) != 0) {
        LOG_ERROR("Failed to initialize proxy subsystem");
        crypto_cleanup();
        g_ctx = NULL;
        free(ctx);
        return 1;
    }

    /* D10-8: 初始化 OOM 应急缓冲池
     * 预分配少量内存，在系统内存耗尽时可释放用于关键操作 */
    ctx->emergency_pool_used = 0;

    /* ── 初始化通道子系统 ──
     * 分配哈希表 (max_channels * 2 个桶)，用于 O(1) 通道查找 */
    if (channel_init(ctx, ctx->config.max_channels) != 0) {
        LOG_ERROR("Failed to initialize channel subsystem");
        cleanup(ctx);               /* cleanup 会安全处理已初始化的资源 */
        free(ctx);
        return 1;
    }
    /* 构建 listener 动态 ID 池基址表 */
    build_listener_bases(ctx);

    /* ── 创建 AF_PACKET 原始套接字 ──
     * socket(AF_PACKET, SOCK_RAW, htons(ethertype)) → bind to interface → 非阻塞 →
     * setsockopt TPACKET_V2 → 使用 TPACKET_V2 环形缓冲区（零拷贝接收） */
    {
        uint16_t ethertype_n = htons(ctx->config.ethertype);

        /* 冲突检测：检查是否有其他进程在同一接口上使用相同 EtherType */
        if (af_packet_detect_conflict(ctx->config.interface,
                                       ctx->config.ethertype) != 0) {
            LOG_WARN("AF_PACKET conflict detected on %s (EtherType=0x%04X)",
                     ctx->config.interface, ctx->config.ethertype);
        }

        ctx->raw_sock = af_packet_create(ctx->config.interface, ethertype_n, &ctx->ifindex);
        if (ctx->raw_sock < 0) {
            LOG_ERROR("Failed to create AF_PACKET socket on %s", ctx->config.interface);
            cleanup(ctx);
            free(ctx);
            return 1;
        }
        ctx->ethertype = ethertype_n;    /* 网络字节序的 EtherType */
        LOG_INFO("AF_PACKET socket created on %s, ifindex=%d", ctx->config.interface, ctx->ifindex);
    }

    /* ── 获取本地 MAC ──
     * 若配置中未指定 local_mac，通过 SIOCGIFHWADDR ioctl 从网卡自动获取 */
    if (mac_is_zero(ctx->config.local_mac)) {
        if (af_packet_get_mac(ctx->raw_sock, ctx->config.interface, ctx->local_mac) == 0) {
            LOG_INFO("Auto-discovered local MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                     ctx->local_mac[0], ctx->local_mac[1], ctx->local_mac[2],
                     ctx->local_mac[3], ctx->local_mac[4], ctx->local_mac[5]);
        } else {
            LOG_ERROR("Failed to auto-discover local MAC on %s", ctx->config.interface);
            cleanup(ctx);
            free(ctx);
            return 1;
        }
    } else {
        memcpy(ctx->local_mac, ctx->config.local_mac, ETH_MAC_ADDR_LEN);
    }

    /* ── 对端 MAC 确定 ──
     * 未配置对端 MAC 时使用广播 FF:FF:FF:FF:FF:FF，并启用自动学习 (peer_mac_learned=0)
     * 已配置则直接使用，无需自动学习 (peer_mac_learned=1) */
    if (mac_is_zero(ctx->config.peer_mac)) {
        LOG_INFO("Peer MAC not configured — using auto-discovery (broadcast initially)");
        memset(ctx->peer_mac, 0xFF, ETH_MAC_ADDR_LEN);  /* 广播地址 */
        ctx->peer_mac_learned = 0;                       /* 启动自动学习 */
    } else {
        memcpy(ctx->peer_mac, ctx->config.peer_mac, ETH_MAC_ADDR_LEN);
        ctx->peer_mac_learned = 1;                        /* 已确定，无需学习 */
    }

    /* ── 自动设置 NIC MTU ── */
    if (ctx->config.auto_set_nic_mtu) {
        if (af_packet_set_mtu(ctx->raw_sock, ctx->config.interface, ctx->config.nic_mtu) == 0) {
            LOG_INFO("NIC MTU set to %d on %s", ctx->config.nic_mtu, ctx->config.interface);
        } else {
            LOG_WARN("Failed to set NIC MTU to %d on %s", ctx->config.nic_mtu, ctx->config.interface);
        }
    }

    /* ── 设置 BPF 过滤器 ── */
    if (af_packet_set_bpf(ctx->raw_sock, ctx->ethertype) != 0) {
        LOG_ERROR("Failed to set BPF filter for ethertype 0x%04X", ctx->config.ethertype);
        cleanup(ctx);
        free(ctx);
        return 1;
    }
    LOG_INFO("BPF filter set for ethertype 0x%04X", ctx->config.ethertype);

    /* ── 初始化日志子系统（文件 + syslog）── */
    log_init(ctx);

    /* ── 初始化 API 服务器（非致命）── */
    if (api_init(ctx) != 0) {
        LOG_WARN("API server failed to start, continuing without API");
    }

    /* ── 初始化业务插件（非致命，失败时已回滚）── */
    if (plugin_init_all(ctx) < 0) {
        LOG_WARN("Plugin init failed, continuing without plugins");
        /* 已 init 的插件已由 plugin_init_all 内部回滚 */
    }

    /* ── 初始化管理模块（非致命）── */
    if (ctx->config_path[0])
        strncpy(ctx->mgmt.config_path, ctx->config_path,
                sizeof(ctx->mgmt.config_path) - 1);
    if (mgmt_init(ctx) != 0) {
        LOG_WARN("Management module init failed, continuing without mgmt");
    } else {
        /* Manager 重启后恢复持久化的动态实例追踪 */
        mgmt_load_dynamic_instances(ctx);
    }

    /* ── 创建通道并启动代理监听 ──
     * 对每个配置的通道: channel_create() 创建 KCP 隧道 → proxy_start_listen() 在 TCP/UDP
     * 端口上监听用户流量。frontend 在此处检查 FD 预算。 */
    if (ctx->config.node_type == NODE_TYPE_FRONTEND &&
        ensure_listener_fd_budget(ctx, ctx->config.channel_count,
                                  "startup", 0) != 0) {
        cleanup(ctx);
        free(ctx);
        return 1;
    }

    for (int i = 0; i < ctx->config.channel_count; i++) {
        channel_config_t *ch_cfg = &ctx->config.channels[i];
        channel_t *ch = channel_create(ctx, ch_cfg->channel_id,
                                        CHANNEL_ROLE_LISTENER,
                                        ch_cfg->listen_port, ch_cfg->remote_port,
                                        ch_cfg->source_port,
                                        ch_cfg->listen_addr, ch_cfg->remote_addr,
                                        ch_cfg->is_tcp);
        if (ch == NULL) {
            LOG_ERROR("Failed to create channel id=%u", ch_cfg->channel_id);
            cleanup(ctx);
            free(ctx);
            return 1;
        }
        /* 为通道注入网络层上下文（从全局 ctx 继承） */
        ch->raw_sock = ctx->raw_sock;
        ch->ifindex  = ctx->ifindex;
        memcpy(ch->local_mac, ctx->local_mac, ETH_MAC_ADDR_LEN);
        memcpy(ch->peer_mac,  ctx->peer_mac,  ETH_MAC_ADDR_LEN);
        ch->ethertype = ctx->ethertype;
        ch->flags        = CH_FLAG_STATIC_LISTENER;   /* 静态配置的 listener */
        ch->listener_idx = (uint16_t)i;               /* 在 listener 列表中的索引 */

        /* 仅 frontend 启动代理监听（backend 只处理 AF_PACKET 帧） */
        if (ctx->config.node_type == NODE_TYPE_FRONTEND) {
            if (proxy_start_listen(ctx, ch) != 0) {
                LOG_ERROR("Failed to start listen for channel id=%u", ch_cfg->channel_id);
                cleanup(ctx);
                free(ctx);
                return 1;
            }
        }
        LOG_INFO("Channel %u created: listen=%s:%u -> remote=%s:%u [%s]",
                 ch_cfg->channel_id,
                 ch_cfg->listen_addr, ch_cfg->listen_port,
                 ch_cfg->remote_addr, ch_cfg->remote_port,
                 ch_cfg->is_tcp ? "TCP" : "UDP");
    }

    /* ── AF_PACKET 加入 epoll ── */
    ret = proxy_epoll_add(ctx, ctx->raw_sock, NULL);
    if (ret != 0) {
        LOG_ERROR("Failed to add raw socket to epoll");
        cleanup(ctx);
        free(ctx);
        return 1;
    }

    /* ── Ctl socket init + epoll ── */
    ctx->ctl_sock_fd = -1;
    if (ctl_socket_init(ctx) == 0) {
        struct epoll_event ev;
        ev.events   = EPOLLIN;
        ev.data.ptr = NULL;
        ev.data.fd  = ctx->ctl_sock_fd;
        if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->ctl_sock_fd, &ev) < 0) {
            LOG_WARN("Failed to add ctl socket to epoll: %s (ctl API disabled)", strerror(errno));
            unlink(ctx->ctl_sock_path);
            close(ctx->ctl_sock_fd);
            ctx->ctl_sock_fd = -1;
        }
    }

    /* ── 初始化时间基准 ── */
    last_periodic_ms = kcp_wrap_clock();
    last_stats_sec   = time(NULL);

    LOG_INFO("Gap-Proxy v" VERSION " started. "
             "Instance: %s, Mode: %s, interface: %s, ethertype: 0x%04X, channels: %d",
             ctx->config.instance_name,
             ctx->config.node_type == NODE_TYPE_FRONTEND ? "frontend" : "backend",
             ctx->config.interface, ctx->config.ethertype, ctx->config.channel_count);

    /* 写入 PID 文件 */
    write_pid_file(ctx->config.pid_file);

    /* ── 主事件循环 ──
     *
     * 架构: 单线程 epoll 驱动的事件循环，超时 EPOLL_TIMEOUT_MS (10ms)。
     * 三类事件: AF_PACKET 帧到达 / ctl socket 连接 / 代理 I/O。
     * 周期任务: KCP 更新 + 心跳 + 超时检查 (每 PERIODIC_INTERVAL_MS=10ms)。
     * 统计输出: 每 60s 一次。
     * 热重载: SIGHUP → epoll EINTR 路径中调用 config_reload()。 */
    {
        struct epoll_event events[EPOLL_MAX_EVENTS];  /* 最多 64 个就绪事件 */

        while (ctx->running) {
            /* 阻塞等待 I/O 事件，超时 10ms 用于驱动周期任务 */
            int nfds = epoll_wait(ctx->epoll_fd, events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);

            if (nfds < 0) {
                if (errno == EINTR) {
                    /* ── 信号中断路径 ──
                     * epoll_wait 被信号打断（如 SIGHUP/SIGUSR1）。
                     * 在此同步处理热重载和通道控制请求，避免异步竞争。 */
                    /* 先清零标志再执行 reload，防止 reload 期间并发 SIGHUP
                     * 丢失: 信号处理器仅设置 reload_requested=1，若在
                     * config_reload() 完成后才清零，期间到达的 SIGHUP 会被覆盖。 */
                    if (ctx->reload_requested && config_path) {
                        ctx->reload_requested = 0;
                        if (config_reload(ctx, config_path) == 0) {
                            LOG_INFO("Configuration reloaded (SIGHUP)");
                        }
                    }
                    if (ctx->ctl_requested) {
                        handle_channel_ctl(ctx);   /* 通道增删 */
                        ctx->ctl_requested = 0;
                    }
                    continue;                      /* 返回 epoll_wait */
                }
                /* 真正的 epoll 错误（非信号中断）—— 致命 */
                LOG_ERROR("epoll_wait failed: %s", strerror(errno));
                break;
            }

            /* ── 每次循环迭代检查信号标志 ──
             * reload/ctl 可能在非 EINTR 路径（如超时返回 nfds=0）被设置，
             * 在此检查确保及时处理。 */
            if (ctx->reload_requested && config_path) {
                ctx->reload_requested = 0;
                if (config_reload(ctx, config_path) == 0)
                    LOG_INFO("Configuration reloaded (SIGHUP)");
            }
            if (ctx->ctl_requested) {
                handle_channel_ctl(ctx);
                ctx->ctl_requested = 0;
            }

            /* ── 事件分发循环 ── */
            int max_frames_per_cycle = ctx->config.perf_max_frames_per_cycle;
            for (int i = 0; i < nfds; i++) {
                int fd = events[i].data.fd;
                uint32_t ev = events[i].events;
                if (fd == ctx->raw_sock) {
                    /* ═══════════════════════════════════════════════════════
                     * AF_PACKET 帧接收与处理（数据面主路径）
                     *
                     * 每周期最多处理 max_frames_per_cycle 帧，防止单次循环
                     * 占用过长时间。帧处理流水线:
                     *   af_packet_recv → myproto_parse_frame → CRC 校验
                     *   → MAC 学习确认 → channel_process_frame
                     * ═══════════════════════════════════════════════════════ */
                    int frame_count = 0;
                    while (frame_count < max_frames_per_cycle) {
                        uint8_t buf[MAX_FRAME_SIZE];
                        uint8_t src_mac[ETH_MAC_ADDR_LEN];
                        uint8_t dst_mac[ETH_MAC_ADDR_LEN];
                        uint16_t ethtype;
                        ssize_t len = af_packet_recv(ctx->raw_sock, buf, sizeof(buf),
                                                     src_mac, dst_mac, &ethtype);
                        if (len < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) break;  /* 无更多帧 */
                            LOG_ERROR("af_packet_recv failed: %s", strerror(errno));
                            break;
                        }
                        if (len == 0) break;          /* 空帧，无数据 */

                        /* M22: 二次 ethertype 校验，防御 BPF 失效 */
                        if (ethtype != ctx->config.ethertype) {
                            LOG_WARN("af_packet_recv: unexpected ethertype "
                                     "0x%04X (expected 0x%04X), dropping",
                                     ethtype, ctx->config.ethertype);
                            continue;
                        }

                        frame_count++;

                        /* 解析 myproto 协议头: channel_id, flags, seq, ack... */
                        const uint8_t *payload;
                        size_t         payload_len;
                        myproto_hdr_t  hdr;
                        if (myproto_parse_frame(buf, (size_t)len, &hdr, &payload, &payload_len) != 0)
                            continue;                 /* 协议格式错误，丢弃帧 */

                        /* CRC 校验（跳过控制帧，它们自带认证） */
                        if (ctx->config.crc_enabled && !IS_CTRL_FRAME(hdr.flags)) {
                            if (myproto_verify_crc(buf, (size_t)len) < 0) continue;
                        }

                        /* ═══════════════════════════════════════════════════
                         * MAC 地址自动学习（多帧确认防欺骗）
                         *
                         * 当对端 MAC 未配置时 (peer_mac_learned=0)，通过接收到的
                         * 帧源 MAC 自动学习。为防单帧欺骗劫持 peer_mac，采用
                         * "多帧确认" 机制:
                         *
                         *   1. 首帧 → 记录候选 MAC + 启动确认窗口 (PEER_MAC_CONFIRM_WINDOW)
                         *   2. 窗口内收到同源 MAC → 计数+1，达到 PEER_MAC_CONFIRM_MIN 则确认学习
                         *   3. 窗口内收到不同源 MAC → 忽略（等窗口超时）
                         *   4. 窗口超时 → 切换到新候选 MAC 重新计数
                         *
                         * 仅学习来自已知通道或管理通道 (channel_id=0) 的帧，
                         * 防止攻击者通过无效 channel_id 的帧触发 MAC 学习。
                         * ═══════════════════════════════════════════════════ */
                        if (ctx->peer_mac_learned == 0 && !mac_is_broadcast(src_mac) && !mac_is_zero(src_mac)) {
                            /* 验证帧的 channel_id 是否指向已知通道 */
                            int frame_known = (channel_find(ctx, hdr.channel_id) != NULL)
                                           || (hdr.channel_id == 0);
                            if (!frame_known) {
                                /* 未知 channel_id：不学习，不计数（安全防护） */
                            } else if (ctx->peer_mac_confirm_count == 0) {
                                /* 首个候选：记录 MAC + 计数 = 1 + 启动时间窗口 */
                                memcpy(ctx->peer_mac_confirm_mac, src_mac, ETH_MAC_ADDR_LEN);
                                ctx->peer_mac_confirm_count = 1;
                                ctx->peer_mac_confirm_ts = time_now();
                            } else if (memcmp(ctx->peer_mac_confirm_mac, src_mac, ETH_MAC_ADDR_LEN) == 0
                                       && time_elapsed(ctx->peer_mac_confirm_ts) < PEER_MAC_CONFIRM_WINDOW) {
                                /* 同源 MAC，窗口内 → 累加确认计数 */
                                ctx->peer_mac_confirm_count++;
                                if (ctx->peer_mac_confirm_count >= PEER_MAC_CONFIRM_MIN) {
                                    /* 确认阈值达成 → 学习该 MAC 并同步到所有通道 */
                                    memcpy(ctx->peer_mac, src_mac, ETH_MAC_ADDR_LEN);
                                    ctx->peer_mac_learned = 1;
                                    LOG_INFO("Auto-learned peer MAC (confirmed x%d): %02x:%02x:%02x:%02x:%02x:%02x",
                                             ctx->peer_mac_confirm_count,
                                             src_mac[0], src_mac[1], src_mac[2],
                                             src_mac[3], src_mac[4], src_mac[5]);
                                    /* 将学习到的 MAC 同步到所有通道 */
                                    for (uint32_t hi = 0; hi < ctx->channel_hash_size; hi++) {
                                        channel_t *ch = ctx->channel_hash[hi];
                                        while (ch) {
                                            memcpy(ch->peer_mac, ctx->peer_mac, ETH_MAC_ADDR_LEN);
                                            ch = ch->hash_next;
                                        }
                                    }
                                }
                            } else if (time_elapsed(ctx->peer_mac_confirm_ts) >= PEER_MAC_CONFIRM_WINDOW) {
                                /* 窗口超时：切换到新候选 MAC 重新计数 */
                                memcpy(ctx->peer_mac_confirm_mac, src_mac, ETH_MAC_ADDR_LEN);
                                ctx->peer_mac_confirm_count = 1;
                                ctx->peer_mac_confirm_ts = time_now();
                            }
                            /* else: 窗口内收到不同源 MAC → 忽略（等待窗口超时） */
                        }

                        /* 将解析后的帧送入通道处理 */
                        channel_process_frame(ctx, &hdr, payload, payload_len);
                    }
                    if (frame_count >= max_frames_per_cycle)
                        LOG_WARN("Reached max frames per cycle (%d)", max_frames_per_cycle);
                } else if (ctx->ctl_sock_fd >= 0 && fd == ctx->ctl_sock_fd) {
                    /* ctl socket 有新连接 */
                    ctl_socket_accept(ctx);
                } else {
                    /* 代理 fd（TCP/UDP 用户流量） */
                    proxy_handle_event(ctx, fd, ev);
                }
            }

            /* ── 周期任务: KCP 更新 + 心跳 + 超时检查 ──
             * 每 PERIODIC_INTERVAL_MS (10ms) 执行一次。
             * 使用 kcp_wrap_clock() 获取单调毫秒时间戳，处理 32 位环绕。 */
            {
                uint32_t now_ms = kcp_wrap_clock();
                if (now_ms - last_periodic_ms >= PERIODIC_INTERVAL_MS || last_periodic_ms > now_ms) {
                    /* KCP 协议栈更新: ikcp_update() 驱动重传、确认、流量控制 */
                    channel_kcp_update(ctx);
                    /* 心跳发送: 对端心跳超时检测（带 channel_id 心跳帧） */
                    channel_heartbeat(ctx);
                    /* 超时检查: 清理无流量的动态子通道 */
                    channel_timeout_check(ctx);

                    /* ── watchdog: 向 master 发送心跳 ──
                     * 每 WATCHDOG_HEARTBEAT_INTERVAL 写一字节到 pipe，
                     * master 侧非阻塞 read 验证 worker 存活。
                     * 注意：worker 通过 getppid() 获取 master PID，若 master 死亡
                     * 且 PID 被复用，可能向无关进程发送信号；EPIPE 检测可缓解此风险。 */
                    if (ctx->heartbeat_fd >= 0 &&
                        time_elapsed(ctx->last_heartbeat_sent) >= WATCHDOG_HEARTBEAT_INTERVAL) {
                        uint8_t beat = 0xFF;
                        if (write(ctx->heartbeat_fd, &beat, 1) < 0) {
                            if (errno == EPIPE) {
                                LOG_ERROR("Master pipe broken — exiting");
                                ctx->running = 0;       /* master 已死，worker 也退出 */
                            }
                            /* EAGAIN/EINTR: 跳过，下次周期重试 */
                        } else {
                            ctx->last_heartbeat_sent = time_now();
                        }
                    }

                    last_periodic_ms = now_ms;
                }
            }

            /* ── 统计输出（每 60 秒） ── */
            {
                uint32_t now_sec = (uint32_t)time(NULL);
                if (now_sec - last_stats_sec >= 60 || last_stats_sec > now_sec) {
                    /* channel_count=0 持续 60s → 自毁退出（无数据通道则无存在意义） */
                    if (ctx->config.channel_count == 0
                        && time_elapsed(ctx->start_time) > 60) {
                        LOG_ERROR("No data channels after 60s — self-terminating");
                        ctx->running = 0;
                    }
                    LOG_INFO("Stats: %d active channels, %d total", channel_count(ctx), ctx->config.channel_count);

                    /* ── 运行时自诊断 ──
                     * 定期输出未知通道帧丢弃统计（可能为扫描/洪水攻击信号） */
                    if (now_sec - ctx->diag_last_diag_ts >= DIAG_INTERVAL_SEC
                        || ctx->diag_last_diag_ts == 0) {
                        if (ctx->diag_rx_unknown_dropped > 0) {
                            LOG_WARN("Diag: %llu unknown-channel frames dropped (possible scan/flood)",
                                     (unsigned long long)ctx->diag_rx_unknown_dropped);
                        }
                        ctx->diag_last_diag_ts = now_sec;
                    }

                    /* ── NIC 统计采集 ── */
                    collect_nic_stats(ctx);

                    last_stats_sec = now_sec;
                }
            }
        }

        /* ── API 服务器轮询 ──
         * 每次循环非阻塞检查 HTTP API 请求（统计接口等） */
        api_poll(ctx);

        /* ── 管理模块定期任务 ──
         * 管理通道保活、重连、配置推送等 */
        mgmt_periodic(ctx);
    }

    /* ── 主循环退出: 优雅关闭 ──
     * 按逆序清理所有资源（通道→KCP排空→代理→加密→AF_PACKET→epoll） */
    cleanup(ctx);
    free(ctx);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * collect_nic_stats — 从 /proc/net/dev 采集网卡统计
 *
 * 解析 /proc/net/dev，匹配 ctx->config.interface 对应的行，
 * 提取 rx/tx packets/bytes/dropped/errors，写入 ctx->nic
 * 并保存上一次快照到 ctx->nic_prev 用于速率计算。
 * ────────────────────────────────────────────────────────────────────────── */
static void collect_nic_stats(global_ctx_t *ctx)
{
    FILE *fp;
    char line[512];
    char ifname[64];

    fp = fopen("/proc/net/dev", "r");
    if (!fp) return;

    /* 跳过前两行（表头） */
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return; }
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return; }

    /* 保存上一次快照 */
    ctx->nic_prev = ctx->nic;

    while (fgets(line, sizeof(line), fp)) {
        /* 解析接口名（去除冒号和前导空格） */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (sscanf(p, "%63[^:]", ifname) != 1) continue;

        if (strcmp(ifname, ctx->config.interface) != 0) continue;

        /* 跳过接口名和冒号后的空格 */
        p = strchr(p, ':');
        if (!p) break;
        p++;

        /* 解析统计字段：
         * Receive:  bytes packets errs drop fifo frame compressed multicast
         * Transmit: bytes packets errs drop fifo colls carrier compressed */
        uint64_t rx_bytes, rx_packets, rx_errs, rx_drop;
        uint64_t tx_bytes, tx_packets, tx_errs, tx_drop;
        if (sscanf(p, "%llu %llu %llu %llu %*u %*u %*u %*u %llu %llu %llu %llu",
                   (unsigned long long *)&rx_bytes,
                   (unsigned long long *)&rx_packets,
                   (unsigned long long *)&rx_errs,
                   (unsigned long long *)&rx_drop,
                   (unsigned long long *)&tx_bytes,
                   (unsigned long long *)&tx_packets,
                   (unsigned long long *)&tx_errs,
                   (unsigned long long *)&tx_drop) == 8) {
            ctx->nic.rx_bytes    = rx_bytes;
            ctx->nic.rx_packets  = rx_packets;
            ctx->nic.rx_errors   = rx_errs;
            ctx->nic.rx_dropped  = rx_drop;
            ctx->nic.tx_bytes    = tx_bytes;
            ctx->nic.tx_packets  = tx_packets;
            ctx->nic.tx_errors   = tx_errs;
            ctx->nic.tx_dropped  = tx_drop;
        }
        break;
    }

    fclose(fp);
}

/* ──────────────────────────────────────────────────────────────────────────
 * spawn_worker — fork 一个 worker 子进程
 *
 * Master 在 fork 前已调用 build_instance_global_config() 构建好完整配置。
 * 子进程通过 fork 继承这个配置的内存，直接调用 worker_run()。
 *
 * CPU affinity：若 instance->cpu_affinity >= 0，在子进程中设置。
 *
 * heartbeat pipe: fork 前创建 pipe，子进程持有写端，父进程持有读端。
 * 子进程通过 fork 继承的 gcfg->heartbeat_fd 获得写端 fd。
 *
 * slot 复用: NULL = 新槽位 (worker_count++); 非 NULL = 复用已有槽位 (重启用)。
 *            复用时自动关闭旧的 heartbeat_fd。
 *
 * @param inst   实例配置
 * @param gcfg   已构建的 global_config_t（会被修改: heartbeat_fd 赋值为写端）
 * @param index  实例在 master->instances[] 中的索引
 * @param slot   目标 worker_info_t 槽位（NULL = 追加新槽位）
 * @return       PID (>0) 成功, -1 失败
 * ────────────────────────────────────────────────────────────────────────── */

/* ──────────────────────────────────────────────────────────────────────────
 * master_spawn_from_sync — mgmt.c 回调：从 INSTANCE_SYNC_RESP 恢复实例
 *
 * 与 master_handle_spawn_request 共享 spawn_worker 逻辑，但不写配置文件。
 * ────────────────────────────────────────────────────────────────────────── */


static pid_t spawn_worker(const instance_config_t *inst,
                           global_config_t *gcfg,
                           int index,
                           worker_info_t *slot)
{
    int pipefd[2] = {-1, -1};

    /* 创建 heartbeat pipe */
    if (pipe(pipefd) < 0) {
        LOG_ERROR("heartbeat pipe() failed for instance '%s': %s",
                  inst->instance_name, strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        LOG_ERROR("fork failed for instance '%s': %s", inst->instance_name, strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* ── 子进程（worker） ── */

        close(pipefd[0]);              /* 关闭读端（子进程只写 heartbeat） */

        /* ═══════════════════════════════════════════════════════════════════
         * R9-X1 / R2-C1: close_range — 防止 fd 泄漏
         *
         * 问题: fork 后子进程继承父进程（master）的所有 fd，包括:
         *   - 其他 worker 的 heartbeat pipe 读端
         *   - ctl socket
         *   - API socket
         *   - 管理模块 socket
         *   这些 fd 在子进程中无用却占据资源，累积可耗尽 ulimit。
         *
         * 解决: 遍历所有可能的 fd (3..maxfd-1)，关闭除 pipefd[1] 外的所有 fd。
         *       fd 0/1/2 (stdin/stdout/stderr) 保留。
         *       使用 sysconf(_SC_OPEN_MAX) 获取上限，上限异常时回退到 65536。
         *       Linux 5.9+ 优先使用 close_range(2)，回退到循环 close()。
         * ═══════════════════════════════════════════════════════════════════ */
        {
            int maxfd = (int)sysconf(_SC_OPEN_MAX);
            if (maxfd <= 0 || maxfd > 1048576) maxfd = 65536;
#ifdef SYS_close_range
            /* 关闭两个区间以保护 heartbeat pipe 写端:
             *   (3, pipefd[1]-1) 和 (pipefd[1]+1, maxfd-1) */
            if (pipefd[1] > 3) {
                if (syscall(SYS_close_range, 3, (unsigned)(pipefd[1] - 1), 0) != 0)
                    goto fd_fallback;
            }
            if ((unsigned)(pipefd[1] + 1) <= (unsigned)(maxfd - 1)) {
                if (syscall(SYS_close_range, (unsigned)(pipefd[1] + 1),
                            (unsigned)(maxfd - 1), 0) != 0)
                    goto fd_fallback;
            }
            goto fd_cleanup_done;
    fd_fallback:
#endif
            for (int fd = 3; fd < maxfd; fd++) {
                if (fd != pipefd[1])
                    close(fd);
            }
#ifdef SYS_close_range
fd_cleanup_done:
#endif
            ;
        }

        fcntl(pipefd[1], F_SETFD, 0);  /* 清除 CLOEXEC（若父进程设置了） */
        {
            int flags2 = fcntl(pipefd[1], F_GETFL, 0);
            if (flags2 >= 0) fcntl(pipefd[1], F_SETFL, flags2 | O_NONBLOCK);
        }
        gcfg->heartbeat_fd = pipefd[1];  /* worker 通过此 fd 向 master 发心跳 */

        /* 设置 CPU 亲和性（如果实例配置了 cpu_affinity >= 0）
         * 将 worker 进程绑定到指定 CPU 核心，减少上下文切换和缓存抖动 */
        if (inst->cpu_affinity >= 0) {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET((unsigned)inst->cpu_affinity, &cpuset);
            if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
                LOG_WARN("Failed to set CPU affinity for instance '%s' to core %d: %s",
                         inst->instance_name, inst->cpu_affinity, strerror(errno));
            } else {
                LOG_INFO("Instance '%s' bound to CPU %d", inst->instance_name, inst->cpu_affinity);
            }
        }

        /* 运行 worker（永不返回，worker_run 内部通过 _exit 退出） */
        int rc = worker_run(gcfg, NULL);
        _exit(rc);                     /* 直接 _exit，不做任何 atexit 清理 */
    }

    /* ── 父进程（master） ── */

    close(pipefd[1]);                  /* 关闭写端（master 只读 heartbeat） */

    /* 设置读端为非阻塞，避免 watchdog_check_heartbeats 中 read() 阻塞主循环 */
    {
        int flags = fcntl(pipefd[0], F_GETFL, 0);
        if (flags >= 0) fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }

    /* 分配或复用 worker_info 槽位 */
    worker_info_t *w;
    if (slot) {
        /* ── 复用已有槽位（重启场景） ── */
        w = slot;
        if (w->heartbeat_fd >= 0) {
            close(w->heartbeat_fd);   /* 关闭旧 pipe 读端 */
        }
        w->restart_count++;           /* 累加重启计数（用于限流） */
        w->last_restart_at = time_now();
    } else {
        /* ── 新槽位（首次启动） ── */
        if (g_master_cfg->worker_count >= MAX_INSTANCES) {
            LOG_ERROR("spawn_worker: worker limit reached (%d)", MAX_INSTANCES);
            close(pipefd[0]);         /* pipefd[1] 已在父进程侧关闭 */
            return -1;
        }
        w = &g_master_cfg->workers[g_master_cfg->worker_count];
        w->restart_count = 0;
        w->last_restart_at = 0;
        g_master_cfg->worker_count++;
    }

    /* 填充 worker 管理信息 */
    w->pid = pid;
    w->instance_index = index;
    w->state = WORKER_STARTING;       /* 等待首次心跳确认 */
    w->started_at = time_now();
    w->exit_signal_sent_at = 0;
    w->restart_at = 0;
    w->exit_code = 0;
    w->heartbeat_fd = pipefd[0];      /* master 侧读端 */
    w->last_heartbeat = time_now();   /* 初始化为当前时间，避免立即超时假阳性 */
    w->heartbeat_missed = 0;

    LOG_INFO("Spawned worker for instance '%s' (pid=%d, ethertype=0x%04X, channels=%d)%s",
             inst->instance_name, pid, inst->ethertype, inst->channel_count,
             slot ? " [restart]" : "");
    return pid;
}

/* ──────────────────────────────────────────────────────────────────────────
 * reap_workers — 非阻塞回收已退出的 worker 子进程
 *
 * 遍历 workers[]，对每个 RUNNING/EXITING 状态的 worker 调用 waitpid(WNOHANG)。
 * 已退出的 worker 状态设为 WORKER_DEAD，供 master 感知和可选重启。
 *
 * @return 本次回收的 worker 数量
 * ────────────────────────────────────────────────────────────────────────── */
static int reap_workers(void)
{
    /* 注意: WORKER_STARTING 状态的 worker 不在此跳过 —— waitpid(WNOHANG)
     * 本身非阻塞，若 worker 在启动早期崩溃退出，此处会被立即回收。
     * 启动宽容期超时由 watchdog_check_heartbeats() 通过
     * WATCHDOG_STARTUP_GRACE 单独处理，与本函数正交。 */
    int reaped = 0;
    for (int i = 0; i < g_master_cfg->worker_count; i++) {
        worker_info_t *w = &g_master_cfg->workers[i];
        if (w->state == WORKER_DEAD || w->state == WORKER_RESTART_PENDING) continue;

        int status;
        pid_t result = waitpid(w->pid, &status, WNOHANG);
        if (result == 0) {
            /* 仍存活 — 状态由 watchdog_check_heartbeats 通过首次心跳确认 RUNNING */
            continue;
        }
        if (result < 0) {
            /* ECHILD: 进程已被回收（不应该发生，但安全跳过）
             * EINTR:  被信号中断（下次循环重试） */
            if (errno == ECHILD) w->state = WORKER_DEAD;
            continue;
        }

        /* 已退出 */
        w->state = WORKER_DEAD;
        reaped++;
        const char *reason = "unknown";
        if (WIFEXITED(status)) {
            w->exit_code = WEXITSTATUS(status);
            reason = "exited";
        } else if (WIFSIGNALED(status)) {
            w->exit_code = -(int)WTERMSIG(status);
            reason = "killed by signal";
        }
        LOG_INFO("Worker pid=%d (instance %d) %s (exit_code=%d, status=%d)",
                 w->pid, w->instance_index, reason, w->exit_code, status);
    }
    return reaped;
}

void master_spawn_from_sync(instance_config_t *inst)
{
    if (!g_master_cfg) {
        LOG_ERROR("master_spawn_from_sync: g_master_cfg is NULL (not a master process)");
        return;
    }
    if (g_master_cfg->worker_count >= MAX_INSTANCES) {
        LOG_WARN("Sync spawn: worker limit %d reached", MAX_INSTANCES);
        return;
    }

    /* 去重：跳过已运行的 Worker */
    for (int i = 0; i < g_master_cfg->worker_count; i++) {
        int idx = g_master_cfg->workers[i].instance_index;
        if (idx >= 0 && idx < g_master_cfg->instance_count &&
            strcmp(g_master_cfg->instances[idx].instance_name,
                   inst->instance_name) == 0) {
            LOG_DEBUG("Sync spawn: '%s' already running, skip", inst->instance_name);
            return;
        }
    }

    global_config_t *gcfg = calloc(1, sizeof(global_config_t));
    if (!gcfg) return;
    build_instance_global_config(inst, g_master_cfg, gcfg);

    /* EtherType 冲突检测：与已有实例比较 */
    for (int i = 0; i < g_master_cfg->instance_count; i++) {
        if (g_master_cfg->instances[i].ethertype == inst->ethertype) {
            LOG_ERROR("Sync spawn: EtherType 0x%04X conflicts with instance '%s'",
                      inst->ethertype, g_master_cfg->instances[i].instance_name);
            free(gcfg);
            return;
        }
    }

    if (validate_config(gcfg) != 0) {
        LOG_ERROR("Sync spawn: config validation failed for '%s'", inst->instance_name);
        free(gcfg);
        return;
    }

    int idx = g_master_cfg->worker_count;
    if (spawn_worker(inst, gcfg, idx, NULL) < 0) {
        LOG_ERROR("Sync spawn: fork failed for '%s'", inst->instance_name);
        free(gcfg);
        return;
    }
    free(gcfg);
    /* spawn_worker 内部已递增 worker_count，此处不再重复递增 */
    /* 同步 g_master_cfg->instances[] */
    if (g_master_cfg->instance_count < MAX_INSTANCES) {
        int ii = g_master_cfg->instance_count++;
        memcpy(&g_master_cfg->instances[ii], inst, sizeof(*inst));
    }
    LOG_INFO("Sync spawn: '%s' restored (eth=0x%04X, pid=%d)",
             inst->instance_name, inst->ethertype,
             g_master_cfg->workers[idx].pid);
}

/* ──────────────────────────────────────────────────────────────────────────
 * stop_worker — 向指定 worker 发送 SIGTERM（优雅退出）
 *
 * 标记 worker 状态为 WORKER_EXITING，记录发送时间戳用于超时检测。
 * ────────────────────────────────────────────────────────────────────────── */
static void stop_worker(worker_info_t *w)
{
    if (w->state == WORKER_DEAD || w->state == WORKER_EXITING ||
        w->state == WORKER_RESTART_PENDING) return;

    w->state = WORKER_EXITING;
    w->exit_signal_sent_at = time_now();
    kill(w->pid, SIGTERM);
    LOG_INFO("Sent SIGTERM to worker pid=%d (instance %d)", w->pid, w->instance_index);
}

/* ──────────────────────────────────────────────────────────────────────────
 * stop_all_workers — 对所有存活 worker 发送 SIGTERM
 *
 * 用于 master 收到 SIGTERM/SIGINT 时的优雅关闭。
 * ────────────────────────────────────────────────────────────────────────── */
static void stop_all_workers(void)
{
    for (int i = 0; i < g_master_cfg->worker_count; i++) {
        stop_worker(&g_master_cfg->workers[i]);
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * kill_stuck_workers — 强制 SIGKILL 超时未退出的 worker
 *
 * 遍历所有 EXITING 状态的 worker，若超过 WORKER_GRACEFUL_TIMEOUT 秒
 * 仍未退出，发送 SIGKILL。
 * ────────────────────────────────────────────────────────────────────────── */
static void kill_stuck_workers(void)
{
    for (int i = 0; i < g_master_cfg->worker_count; i++) {
        worker_info_t *w = &g_master_cfg->workers[i];
        if (w->state != WORKER_EXITING) continue;
        if (w->exit_signal_sent_at == 0) continue;
        if (time_elapsed(w->exit_signal_sent_at) < WORKER_GRACEFUL_TIMEOUT) continue;

        LOG_WARN("Worker pid=%d (instance %d) graceful timeout, sending SIGKILL",
                 w->pid, w->instance_index);
        kill(w->pid, SIGKILL);
        w->exit_code = -SIGKILL;
        w->exit_signal_sent_at = 0;  /* 标记已发送 SIGKILL，防止 watchdog 重复发送 */
        /* 立即非阻塞回收，防止僵尸进程 */
        {
            int status;
            pid_t r = waitpid(w->pid, &status, WNOHANG);
            if (r > 0) {
                w->state = WORKER_DEAD;
                w->pid = 0;
            }
        }
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * master_graceful_reload — SIGHUP 触发的优雅重载
 *
 * 流程：
 *   1. 重新加载 kcp-multi.json
 *   2. 标记当前所有存活 worker 为 "old generation"
 *   3. 为新配置中的每个 instance 生成 global_config_t 并 fork 新 worker
 *   4. 新 worker 全部 fork 完成后，SIGTERM 旧 generation worker
 *   5. 旧 worker 排水 → 退出 → master reap
 *
 * @param config_path 多实例配置文件路径
 * @param skipped_out 输出：被跳过的实例数（OOM/验证失败），可为 NULL
 * ────────────────────────────────────────────────────────────────────────── */
static int master_graceful_reload(const char *config_path, int *skipped_out)
{
    /*
     * 重入保护：防止 SIGHUP 与 SIGURG(CONFIG_SWITCH) 或多次快速信号
     * 触发并发重载。master_main 的信号循环是同步的，但一次重载内部的
     * usleep() 可能让后续信号排队，导致连续多次重载。此标志确保同一
     * 时刻只有一个重载在执行，后续请求在循环中被静默跳过。
     */
    static int reload_in_progress = 0;
    if (reload_in_progress) {
        LOG_WARN("Master reload already in progress, skipping");
        return -1;
    }
    reload_in_progress = 1;

    master_config_t *new_cfg = calloc(1, sizeof(master_config_t));
    if (!new_cfg) {
        LOG_ERROR("Master reload: out of memory");
        reload_in_progress = 0;
        return -1;
    }

    if (master_config_load(config_path, new_cfg) != 0) {
        LOG_ERROR("Master reload: failed to load %s", config_path);
        master_config_free(new_cfg);
        reload_in_progress = 0;
        return -1;
    }

    /* 更新配置路径（可能已变更） */
    strncpy(g_master_config_path, config_path, sizeof(g_master_config_path) - 1);

    LOG_INFO("Master reload: new config loaded (%d instances)", new_cfg->instance_count);

    /* 保存旧 worker 信息 */
    worker_info_t old_workers[MAX_INSTANCES];
    int old_count = g_master_cfg->worker_count;
    memcpy(old_workers, g_master_cfg->workers, (size_t)old_count * sizeof(worker_info_t));

    /* 临时切换到新配置以让 spawn_worker 填充 new_cfg->workers[]。
     * 先 fork 所有新 Worker，成功后再永久切换 g_master_cfg，
     * 避免切换后 fork 失败导致孤儿 Worker。 */
    master_config_t *old_cfg = g_master_cfg;
    g_master_cfg = new_cfg;
    g_master_cfg->worker_count = 0;

    /* Fork 新 worker，统计跳过数 */
    int skipped = 0;
    for (int i = 0; i < g_master_cfg->instance_count; i++) {
        global_config_t *gcfg = calloc(1, sizeof(global_config_t));
        if (!gcfg) { skipped++; continue; }
        build_instance_global_config(&g_master_cfg->instances[i], g_master_cfg, gcfg);

        if (validate_config(gcfg) != 0) {
            LOG_ERROR("Master reload: instance '%s' config validation failed, skipping",
                      g_master_cfg->instances[i].instance_name);
            free(gcfg);
            skipped++;
            continue;
        }
        if (spawn_worker(&g_master_cfg->instances[i], gcfg, i, NULL) < 0) {
            LOG_ERROR("Master reload: spawn failed for instance '%s', skipping",
                      g_master_cfg->instances[i].instance_name);
            free(gcfg);
            skipped++;
            continue;
        }
        free(gcfg);
    }

    /* 等待新 worker 启动（给予初始化时间），检查是否有 worker 立即失败 */
    usleep(200000); /* 200ms — 足够 worker 完成初始化或快速失败 */
    reap_workers();
    int new_dead = 0;
    for (int i = 0; i < g_master_cfg->worker_count; i++) {
        if (g_master_cfg->workers[i].state == WORKER_DEAD) new_dead++;
    }
    if (new_dead > 0) {
        LOG_ERROR("Master reload: %d new worker(s) failed to start, "
                  "rolling back to old config", new_dead);
        /* 终止所有新 worker */
        for (int i = 0; i < g_master_cfg->worker_count; i++) {
            if (g_master_cfg->workers[i].state != WORKER_DEAD)
                stop_worker(&g_master_cfg->workers[i]);
        }
        /* 等待新 Worker 退出后再回滚配置，避免孤儿进程 */
        {
            uint32_t rollback_start = time_now();
            while (time_elapsed(rollback_start) < WORKER_GRACEFUL_TIMEOUT) {
                int alive = 0;
                for (int i = 0; i < g_master_cfg->worker_count; i++) {
                    if (g_master_cfg->workers[i].state != WORKER_DEAD) {
                        int status;
                        if (waitpid(g_master_cfg->workers[i].pid, &status, WNOHANG) > 0)
                            g_master_cfg->workers[i].state = WORKER_DEAD;
                        else
                            alive = 1;
                    }
                }
                if (!alive) break;
                usleep(50000);
            }
            /* 超时未退出则 SIGKILL */
            for (int i = 0; i < g_master_cfg->worker_count; i++) {
                if (g_master_cfg->workers[i].state != WORKER_DEAD) {
                    kill(g_master_cfg->workers[i].pid, SIGKILL);
                    waitpid(g_master_cfg->workers[i].pid, NULL, 0);
                }
            }
        }
        /* 回滚配置 */
        g_master_cfg = old_cfg;
        master_config_free(new_cfg);
        if (skipped_out) *skipped_out = skipped;
        reload_in_progress = 0;
        return -1;
    }

    /* 新 worker 全部启动后，优雅关闭旧 worker */
    LOG_INFO("Master reload: %d new workers spawned, stopping %d old workers",
             g_master_cfg->worker_count, old_count);
    for (int i = 0; i < old_count; i++) {
        if (old_workers[i].state != WORKER_DEAD)
            stop_worker(&old_workers[i]);
    }

    /* 回收旧 Worker 退出状态（防止僵尸进程）并关闭 heartbeat fd */
    for (int i = 0; i < old_count; i++) {
        if (old_workers[i].pid > 0) {
            int status;
            uint32_t wait_start = time_now();
            /* 带超时的阻塞等待：最多等待 WORKER_GRACEFUL_TIMEOUT 秒 */
            while (waitpid(old_workers[i].pid, &status, WNOHANG) == 0) {
                if (time_elapsed(wait_start) > WORKER_GRACEFUL_TIMEOUT) {
                    LOG_WARN("Master reload: old worker pid=%d timeout, sending SIGKILL",
                             old_workers[i].pid);
                    kill(old_workers[i].pid, SIGKILL);
                    /* 最后尝试回收 */
                    waitpid(old_workers[i].pid, &status, 0);
                    break;
                }
                usleep(50000);  /* 50ms polling interval */
            }
            LOG_DEBUG("Master reload: old worker pid=%d reaped (status=%d)",
                      old_workers[i].pid, status);
        }
        if (old_workers[i].heartbeat_fd > 0)
            close(old_workers[i].heartbeat_fd);
    }

    /* 延迟释放旧配置（等待旧 worker 完全退出后释放） */
    master_config_free(old_cfg);
    if (skipped_out) *skipped_out = skipped;

    /* 所有新 Worker 已启动 → 安全提交 spawn 缓存 */

    reload_in_progress = 0;
    return 0;
}

static int setup_master_signals(void)
{
    /* Block signals for synchronous delivery via sigtimedwait */
    sigset_t block_mask;
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGCHLD);
    sigaddset(&block_mask, SIGHUP);
    sigaddset(&block_mask, SIGINT);
    sigaddset(&block_mask, SIGTERM);
    sigaddset(&block_mask, SIGUSR1);
    sigaddset(&block_mask, SIGUSR2);
    sigaddset(&block_mask, SIGURG);

    if (sigprocmask(SIG_BLOCK, &block_mask, NULL) < 0) {
        LOG_ERROR("Failed to block master signals: %s", strerror(errno));
        return -1;
    }

    /* SIGPIPE ignored (prevent crash on closed socket writes) */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, NULL);

    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * master_main — Master 进程主循环
 *
 * 1. 加载多实例配置
 * 2. fork 所有 worker
 * 3. 进入信号驱动的主循环：
 *    - SIGCHLD → reap_workers
 *    - SIGHUP  → master_graceful_reload
 *    - SIGTERM → stop_all_workers → wait → exit
 *
 * @param config_path 多实例配置文件路径
 * @return            0=正常退出, 非0=启动失败
 * ────────────────────────────────────────────────────────────────────────── */

/* ──────────────────────────────────────────────────────────────────────────
 * master_handle_spawn_request — 处理管理 worker 发来的 SPAWN 请求
 */
static void master_handle_spawn_request(void)
{
    /* C7: 使用 open(O_NOFOLLOW) 替代 fopen, 消除 TOCTOU 竞态窗口 */
    int fd = open(SPAWN_REQUEST_FILE, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno != ENOENT)
            LOG_ERROR("Spawn request file open failed: %s", strerror(errno));
        return;
    }
    unlink(SPAWN_REQUEST_FILE);   /* 提前清理：关闭 TOCTOU 窗口 */

    struct stat st;
    long fsize = (fstat(fd, &st) == 0) ? st.st_size : 0;
    char *fbuf = NULL;
    struct json_object *root = NULL;
    if (fsize > 0 && fsize < 65536) {
        fbuf = (char *)malloc((size_t)fsize + 1);
        if (fbuf) {
            ssize_t nr = read(fd, fbuf, (size_t)fsize);
            if (nr > 0) fbuf[nr] = '\0';
            root = json_tokener_parse(fbuf);
            free(fbuf);
        }
    }
    close(fd);

    if (!root) {
        FILE *resp = fopen(SPAWN_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"invalid JSON\"}\n"); fclose(resp); }
        return;
    }

    struct json_object *tmp;
    const char *name = "unnamed";
    uint16_t ethertype = 0;
    uint8_t  node_type = NODE_TYPE_FRONTEND;
    int      cpu_affinity = -1;

    if (json_object_object_get_ex(root, "instance_name", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s) name = s;
    }
    /* 去重：检查 instance_name 是否与已有实例冲突 */
    for (int i = 0; i < g_master_cfg->instance_count; i++) {
        if (strcmp(g_master_cfg->instances[i].instance_name, name) == 0) {
            LOG_ERROR("Spawn: instance_name '%s' already exists", name);
            json_object_put(root);
            FILE *resp = fopen(SPAWN_RESPONSE_FILE, "w");
            if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"duplicate instance_name\"}\n"); fclose(resp); }
            return;
        }
    }
    if (json_object_object_get_ex(root, "ethertype", &tmp))
        ethertype = (uint16_t)json_object_get_int(tmp);
    if (json_object_object_get_ex(root, "node_type", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s && strcmp(s, "backend") == 0) node_type = NODE_TYPE_BACKEND;
    }
    if (json_object_object_get_ex(root, "cpu_affinity", &tmp))
        cpu_affinity = json_object_get_int(tmp);

    if (cpu_affinity >= MAX_INSTANCES) {
        LOG_WARN("cpu_affinity %d >= MAX_INSTANCES (%d), resetting to -1",
                 cpu_affinity, MAX_INSTANCES);
        cpu_affinity = -1;
    }

    if (ethertype < 0x0600 || ethertype == 0x8100) {
        json_object_put(root);
        FILE *resp = fopen(SPAWN_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"invalid ethertype (VLAN not allowed)\"}\n"); fclose(resp); }
        return;
    }

    instance_config_t inst;
    memset(&inst, 0, sizeof(inst));
    channel_config_t local_channels[SPAWN_MAX_CHANNELS];  /* 栈分配，SPAWN_MAX_CHANNELS 受控避免栈溢出 */
    inst.channels = local_channels;

    strncpy(inst.instance_name, name, sizeof(inst.instance_name) - 1);
    inst.ethertype    = ethertype;
    inst.node_type    = node_type;
    inst.cpu_affinity = cpu_affinity;

    struct json_object *ch_arr;
    if (json_object_object_get_ex(root, "channels", &ch_arr)) {
        int n = json_object_array_length(ch_arr);
        if (n > SPAWN_MAX_CHANNELS) n = SPAWN_MAX_CHANNELS;
        inst.channel_count = 0;
        for (int i = 0; i < n; i++) {
            struct json_object *ch = json_object_array_get_idx(ch_arr, i);
            if (!ch) continue;
            channel_config_t *cfg = &inst.channels[inst.channel_count];
            memset(cfg, 0, sizeof(*cfg));
            if (json_object_object_get_ex(ch, "channel_id", &tmp))
                cfg->channel_id = (uint32_t)json_object_get_int(tmp);
            if (json_object_object_get_ex(ch, "listen_port", &tmp))
                cfg->listen_port = (uint16_t)json_object_get_int(tmp);
            if (json_object_object_get_ex(ch, "remote_port", &tmp))
                cfg->remote_port = (uint16_t)json_object_get_int(tmp);
            {
                struct json_object *j;
                if (json_object_object_get_ex(ch, "listen_addr", &j)) {
                    const char *s = json_object_get_string(j);
                    if (s) { strncpy(cfg->listen_addr, s, MAX_LISTEN_ADDR - 1);
                             cfg->listen_addr[MAX_LISTEN_ADDR - 1] = '\0'; }
                }
                if (json_object_object_get_ex(ch, "remote_addr", &j)) {
                    const char *s = json_object_get_string(j);
                    if (s) { strncpy(cfg->remote_addr, s, MAX_REMOTE_ADDR - 1);
                             cfg->remote_addr[MAX_REMOTE_ADDR - 1] = '\0'; }
                }
            }
            if (json_object_object_get_ex(ch, "is_tcp", &tmp))
                cfg->is_tcp = (uint8_t)json_object_get_boolean(tmp);
            if (json_object_object_get_ex(ch, "max_sessions", &tmp))
                cfg->max_sessions = (uint16_t)json_object_get_int(tmp);
            if (cfg->max_sessions == 0) cfg->max_sessions = 1;
            if (json_object_object_get_ex(ch, "enabled", &tmp))
                cfg->enabled = json_object_get_boolean(tmp) ? 1 : 0;
            else
                cfg->enabled = 1;
            inst.channel_count++;
        }
    }
    json_object_put(root);

    global_config_t *gcfg = calloc(1, sizeof(global_config_t));
    if (!gcfg) {
        FILE *resp = fopen(SPAWN_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"OOM\"}\n"); fclose(resp); }
        return;
    }
    build_instance_global_config(&inst, g_master_cfg, gcfg);

    if (validate_config(gcfg) != 0) {
        free(gcfg);
        FILE *resp = fopen(SPAWN_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"validation failed\"}\n"); fclose(resp); }
        return;
    }

    if (g_master_cfg->worker_count >= MAX_INSTANCES) {
        LOG_ERROR("Spawn: worker limit %d reached", MAX_INSTANCES);
        free(gcfg);
        FILE *resp = fopen(SPAWN_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"worker limit reached\"}\n"); fclose(resp); }
        return;
    }

    int idx = g_master_cfg->worker_count;
    if (spawn_worker(&inst, gcfg, idx, NULL) < 0) {
        free(gcfg);
        FILE *resp = fopen(SPAWN_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"fork failed\"}\n"); fclose(resp); }
        return;
    }
    free(gcfg);

    FILE *resp = fopen(SPAWN_RESPONSE_FILE, "w");
    if (resp) {
        worker_info_t *w = &g_master_cfg->workers[idx];
        fprintf(resp, "{\"status\":\"ok\",\"pid\":%d,\"name\":\"%s\"}\n", w->pid, name);
        fclose(resp);
    }
    LOG_INFO("Spawned worker '%s' (pid=%d, ethertype=0x%04X)", name,
             g_master_cfg->workers[idx].pid, ethertype);

    /* 将实例加入 instances[] 数组，保证重启恢复时 watchdog 可正确索引 */
    if (g_master_cfg->instance_count < MAX_INSTANCES) {
        int iidx = g_master_cfg->instance_count;
        g_master_cfg->instances[iidx] = inst;
        g_master_cfg->instance_count++;
        /* 修正 workers[].instance_index 指向新槽位 */
        g_master_cfg->workers[idx].instance_index = iidx;
    }

    /* 动态实例由 Manager 侧追踪，Worker 重启后通过 INSTANCE_SYNC 恢复 */
    if (g_ctx) mgmt_persist_dynamic_instances(g_ctx);
}

/* ──────────────────────────────────────────────────────────────────────────
 * master_handle_channel_ctl_forward — 处理 Worker 转发来的 CHANNEL_CTL
 *
 * 管理通道收到带 instance_name 的 CHANNEL_CTL → 写 CHANNEL_CTL_FILE
 * → SIGUSR1 → Master 在此函数处理。
 * Master 查找同 instance_name 的子 Worker PID，写入其 ctl.json 并发信号。
 * ────────────────────────────────────────────────────────────────────────── */
static void master_handle_channel_ctl_forward(void)
{
    FILE *cf = fopen(CHANNEL_CTL_FILE, "r");
    if (!cf) return;
    unlink(CHANNEL_CTL_FILE);

    fseek(cf, 0, SEEK_END);
    long cfsize = ftell(cf);
    struct json_object *ctl_root = NULL;
    if (cfsize > 0 && cfsize < 65536) {
        char *cfbuf = (char *)malloc((size_t)cfsize + 1);
        if (cfbuf) {
            rewind(cf);
            size_t nr = fread(cfbuf, 1, (size_t)cfsize, cf);
            cfbuf[nr] = '\0';
            ctl_root = json_tokener_parse(cfbuf);
            free(cfbuf);
        }
    }
    fclose(cf);
    if (!ctl_root) return;

    struct json_object *jinst, *jpl;
    if (json_object_object_get_ex(ctl_root, "instance_name", &jinst)
        && json_object_object_get_ex(ctl_root, "payload", &jpl)) {
        const char *inst_name = json_object_get_string(jinst);
        for (int wi = 0; wi < g_master_cfg->worker_count; wi++) {
            int ii = g_master_cfg->workers[wi].instance_index;
            if (ii >= 0 && ii < g_master_cfg->instance_count
                && strcmp(g_master_cfg->instances[ii].instance_name, inst_name) == 0) {
                pid_t child_pid = g_master_cfg->workers[wi].pid;
                if (child_pid > 0 && g_master_cfg->workers[wi].state == WORKER_RUNNING) {
                    /* 构造子进程的 ctl.json 路径（与 handle_channel_ctl 相同算法） */
                    char ctl_path[512];
                    size_t clen = strnlen(g_master_config_path, sizeof(g_master_config_path) - 1);
                    if (clen > 5 && strcmp(g_master_config_path + clen - 5, ".json") == 0) {
                        snprintf(ctl_path, sizeof(ctl_path), "%.*s-ctl.json", (int)(clen - 5), g_master_config_path);
                    } else {
                        snprintf(ctl_path, sizeof(ctl_path), "%s-ctl.json", g_master_config_path);
                    }
                    FILE *ctl_f = fopen(ctl_path, "w");
                    if (ctl_f) {
                        const char *pl_str = json_object_to_json_string(jpl);
                        fprintf(ctl_f, "%s\n", pl_str ? pl_str : "[]");
                        fclose(ctl_f);
                        kill(child_pid, SIGUSR1);
                    }
                }
                break;
            }
        }
    }
    json_object_put(ctl_root);
}

static void master_handle_kill_request(void)
{
    FILE *f = fopen(KILL_REQUEST_FILE, "r");
    if (!f) return;
    unlink(KILL_REQUEST_FILE);   /* 提前清理 */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    char *fbuf = NULL;
    struct json_object *root = NULL;
    if (fsize > 0 && fsize < 65536) {
        fbuf = (char *)malloc((size_t)fsize + 1);
        if (fbuf) {
            rewind(f);
            size_t nr = fread(fbuf, 1, (size_t)fsize, f);
            fbuf[nr] = '\0';
            root = json_tokener_parse(fbuf);
            free(fbuf);
        }
    }
    fclose(f);

    if (!root) {
        FILE *resp = fopen(KILL_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"invalid JSON\"}\n"); fclose(resp); }
        return;
    }

    struct json_object *tmp;
    uint16_t target_ethertype = 0;
    if (json_object_object_get_ex(root, "ethertype", &tmp))
        target_ethertype = (uint16_t)json_object_get_int(tmp);
    json_object_put(root);

    if (target_ethertype == 0) {
        FILE *resp = fopen(KILL_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"missing ethertype\"}\n"); fclose(resp); }
        return;
    }

    for (int i = 0; i < g_master_cfg->worker_count; i++) {
        worker_info_t *w = &g_master_cfg->workers[i];
        if (w->state == WORKER_DEAD ||
            w->state == WORKER_RESTART_PENDING ||
            w->state == WORKER_EXITING) continue;
        instance_config_t *inst = &g_master_cfg->instances[w->instance_index];
        if (inst->ethertype == target_ethertype) {
            int inst_idx = w->instance_index;
            stop_worker(w);
            /* 重启抑制：将 restart_count 设为上限，防止 watchdog 自动重启此 Worker */
            w->restart_count = WATCHDOG_MAX_RESTARTS;
            LOG_INFO("Killed worker pid=%d (ethertype=0x%04X)", w->pid, target_ethertype);

            /* 从 instances[] 移除条目，防止重启时复活 */
            if (inst_idx >= 0 && inst_idx < g_master_cfg->instance_count) {
                if (inst_idx < g_master_cfg->instance_count - 1)
                    memmove(&g_master_cfg->instances[inst_idx],
                            &g_master_cfg->instances[inst_idx + 1],
                            (size_t)(g_master_cfg->instance_count - inst_idx - 1)
                            * sizeof(instance_config_t));
                g_master_cfg->instance_count--;
                for (int j = 0; j < g_master_cfg->worker_count; j++)
                    if (g_master_cfg->workers[j].instance_index > inst_idx)
                        g_master_cfg->workers[j].instance_index--;
            }

            FILE *resp = fopen(KILL_RESPONSE_FILE, "w");
            if (resp) { fprintf(resp, "{\"status\":\"ok\",\"pid\":%d}\n", w->pid); fclose(resp); }
            return;
        }
    }
    FILE *resp = fopen(KILL_RESPONSE_FILE, "w");
    if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"worker not found\"}\n"); fclose(resp); }
}

/* ──────────────────────────────────────────────────────────────────────────
 * master_handle_config_switch — 处理管理 worker 发来的 CONFIG_SWITCH 请求
 *
 * 读取 SWITCH_CONFIG_REQUEST_FILE，提取 config_path，用其作为参数调用
 * master_graceful_reload。响应写入 SWITCH_CONFIG_RESPONSE_FILE。
 * ────────────────────────────────────────────────────────────────────────── */
static void master_handle_config_switch(void)
{
    FILE *f = fopen(SWITCH_CONFIG_REQUEST_FILE, "r");
    if (!f) { LOG_ERROR("Config switch request file not found"); return; }
    unlink(SWITCH_CONFIG_REQUEST_FILE);   /* 提前清理 */

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    char *fbuf = NULL;
    struct json_object *root = NULL;
    if (fsize > 0 && fsize < 65536) {
        fbuf = (char *)malloc((size_t)fsize + 1);
        if (fbuf) {
            rewind(f);
            size_t nr = fread(fbuf, 1, (size_t)fsize, f);
            fbuf[nr] = '\0';
            root = json_tokener_parse(fbuf);
            free(fbuf);
        }
    }
    fclose(f);

    if (!root) {
        FILE *resp = fopen(SWITCH_CONFIG_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"invalid JSON\"}\n"); fclose(resp); }
        return;
    }

    struct json_object *tmp;
    const char *new_path = NULL;
    if (json_object_object_get_ex(root, "config_path", &tmp))
        new_path = json_object_get_string(tmp);

    if (!new_path || new_path[0] == '\0') {
        json_object_put(root);
        FILE *resp = fopen(SWITCH_CONFIG_RESPONSE_FILE, "w");
        if (resp) { fprintf(resp, "{\"status\":\"error\",\"message\":\"missing config_path\"}\n"); fclose(resp); }
        return;
    }

    LOG_INFO("Config switch requested: %s", new_path);
    int skipped = 0;
    int ret = master_graceful_reload(new_path, &skipped);

    FILE *resp = fopen(SWITCH_CONFIG_RESPONSE_FILE, "w");
    if (resp) {
        if (ret == 0)
            fprintf(resp,
                "{\"status\":\"ok\",\"config_path\":\"%s\",\"skipped\":%d}\n",
                new_path, skipped);
        else
            fprintf(resp,
                "{\"status\":\"error\",\"message\":\"reload failed\",\"skipped\":%d}\n",
                skipped);
        fclose(resp);
    }
    json_object_put(root);
}

/* ──────────────────────────────────────────────────────────────────────────
 * watchdog_check_heartbeats — 检查所有 worker 的心跳 pipe
 *
 * 对每个非 DEAD/RESTART_PENDING 的 worker，非阻塞 drain pipe。
 * 读到数据 → 更新 last_heartbeat，清零 missed 计数。
 * 超时 → 累加 missed 计数，达到阈值则 SIGTERM。
 *
 * 新启动 worker（WORKER_STARTING）享有 WATCHDOG_STARTUP_GRACE 宽容期。
 * ────────────────────────────────────────────────────────────────────────── */
static void watchdog_check_heartbeats(void)
{
    /* ── 心跳检查：遍历所有 worker 的心跳 pipe ──
     *
     * 对每个非 DEAD/RESTART_PENDING/EXITING 状态的 worker:
     *   - 非阻塞 read() drain pipe
     *   - 读到数据 → 更新 last_heartbeat，清零 missed 计数，确认 RUNNING
     *   - 无数据 + 超时 → 累加 missed 计数
     *   - missed ≥ WATCHDOG_HEARTBEAT_MAX_MISS → SIGTERM worker
     *
     * 新启动 worker (WORKER_STARTING) 享有 WATCHDOG_STARTUP_GRACE 宽容期，
     * 避免初始化期间的假性超时。 */

    for (int i = 0; i < g_master_cfg->worker_count; i++) {
        worker_info_t *w = &g_master_cfg->workers[i];

        /* 跳过已死亡、正在重启、或正在退出的 worker */
        if (w->state == WORKER_DEAD || w->state == WORKER_RESTART_PENDING ||
            w->state == WORKER_EXITING) continue;
        if (w->heartbeat_fd < 0) continue;

        /* 新 worker 启动宽容期：给予初始化时间（默认 5 秒） */
        if (w->state == WORKER_STARTING &&
            time_elapsed(w->started_at) < WATCHDOG_STARTUP_GRACE)
            continue;

        /* 非阻塞 drain pipe：worker 每 heartbeat_interval 向 pipe 写入一字节 */
        uint8_t buf[64];
        ssize_t n = read(w->heartbeat_fd, buf, sizeof(buf));
        if (n > 0) {
            /* 收到心跳 → 更新 */
            w->last_heartbeat = time_now();
            w->heartbeat_missed = 0;
            if (w->state == WORKER_STARTING)
                w->state = WORKER_RUNNING;        /* 首次心跳确认 → 进入 RUNNING */
            continue;
        }

        /* 无数据可读 (EAGAIN) 或错误 → 检查是否超时 */
        if (time_elapsed(w->last_heartbeat) > WATCHDOG_HEARTBEAT_TIMEOUT) {
            w->heartbeat_missed++;
            LOG_WARN("Worker pid=%d (inst %d) heartbeat lost (missed=%d/%d)",
                     w->pid, w->instance_index,
                     w->heartbeat_missed, WATCHDOG_HEARTBEAT_MAX_MISS);

            /* 连续超时达到阈值 → 终止无响应 worker */
            if (w->heartbeat_missed >= WATCHDOG_HEARTBEAT_MAX_MISS) {
                LOG_ERROR("Worker pid=%d heartbeat lost — killing", w->pid);
                w->state = WORKER_EXITING;
                w->exit_signal_sent_at = time_now();
                kill(w->pid, SIGTERM);             /* 先 SIGTERM，留出排水时间 */
            }
        }
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * watchdog_restart_workers — 自动重启已死 worker
 *
 * Phase 1: WORKER_DEAD → 检查条件 → WORKER_RESTART_PENDING（带延迟）
 * Phase 2: WORKER_RESTART_PENDING & 延迟已过 → spawn_worker（复用槽位）
 *
 * 抑制条件: Master 关闭中 / 重启次数超窗口上限。
 * ────────────────────────────────────────────────────────────────────────── */
static void watchdog_restart_workers(void)
{
    /* ── 自动重启已死 worker ──
     *
     * 两阶段状态机:
     *
     *   Phase 1: WORKER_DEAD → WORKER_RESTART_PENDING（带延迟）
     *     - 检查重启窗口限制（restart_count < MAX_RESTARTS in WINDOW 秒）
     *     - 超出限制则永久放弃该 worker
     *     - 否则设置 restart_at (当前时间 + RESTART_DELAY)，进入 PENDING
     *
     *   Phase 2: WORKER_RESTART_PENDING & 延迟已过 → spawn_worker（复用槽位）
     *     - 重新构建 global_config_t
     *     - 验证配置
     *     - fork 新 worker 复用原有 worker_info 槽位
     *
     * 抑制条件: Master 关闭中 (g_master_running=0) 时不重启。 */

    if (!g_master_running) return;   /* master 正在关闭 — 不启动新 worker */

    for (int i = 0; i < g_master_cfg->worker_count; i++) {
        worker_info_t *w = &g_master_cfg->workers[i];

        /* ── Phase 1: DEAD → PENDING ── */
        if (w->state == WORKER_DEAD) {
            /* 检查重启窗口: 若距离上次重启超过 WINDOW 秒，重置计数 */
            if (w->last_restart_at > 0 &&
                time_elapsed(w->last_restart_at) > WATCHDOG_RESTART_WINDOW) {
                w->restart_count = 0;        /* 窗口过期，重置 */
            }

            /* 重启次数超限 → 永久放弃 */
            if (w->restart_count >= WATCHDOG_MAX_RESTARTS) {
                LOG_ERROR("Worker (inst %d): max restarts (%d) in %ds, giving up",
                          w->instance_index,
                          WATCHDOG_MAX_RESTARTS, WATCHDOG_RESTART_WINDOW);
                continue;                    /* 永久 DEAD */
            }

            /* 进入 PENDING 状态，设置延迟重启时间 */
            w->state = WORKER_RESTART_PENDING;
            w->restart_at = time_now() + WATCHDOG_RESTART_DELAY;
            LOG_WARN("Worker (inst %d, exit=%d) died — restart in %ds (attempt %d/%d)",
                     w->instance_index, w->exit_code,
                     WATCHDOG_RESTART_DELAY, w->restart_count + 1, WATCHDOG_MAX_RESTARTS);
            continue;
        }

        /* ── Phase 2: PENDING → spawn ── */
        if (w->state == WORKER_RESTART_PENDING) {
            /* 延迟未到 → 继续等待 */
            if (time_elapsed(w->restart_at) == 0) continue;

            const instance_config_t *inst = &g_master_cfg->instances[w->instance_index];

            /* 重新构建完整配置 */
            global_config_t *gcfg = calloc(1, sizeof(global_config_t));
            if (!gcfg) {
                LOG_ERROR("OOM during restart of inst %d", w->instance_index);
                continue;
            }
            build_instance_global_config(inst, g_master_cfg, gcfg);

            /* 重新验证（配置可能在 worker 死亡期间被修改） */
            if (validate_config(gcfg) != 0) {
                LOG_ERROR("Config validation failed restart inst %d", w->instance_index);
                free(gcfg);
                w->restart_count++;
                w->last_restart_at = time_now();
                w->state = WORKER_DEAD;          /* 永久错误：通过 Phase 1 有限重试 */
                continue;
            }

            /* fork 新 worker（复用 slot=w，restart_count 在 spawn_worker 中递增） */
            if (spawn_worker(inst, gcfg, w->instance_index, w) < 0) {
                LOG_ERROR("fork failed during restart of inst %d", w->instance_index);
                free(gcfg);
                continue;
            }
            free(gcfg);                          /* spawn_worker 内部已复制所需字段 */
        }
    }
}

static int master_main(const char *config_path)
{
    master_config_t *cfg = calloc(1, sizeof(master_config_t));
    if (!cfg) {
        LOG_ERROR("Failed to allocate master config");
        return 1;
    }

    /* 1. 加载配置 */
    if (master_config_load(config_path, cfg) != 0) {
        LOG_ERROR("Failed to load master config: %s", config_path);
        master_config_free(cfg);
        return 1;
    }

    /* 记录配置路径（用于派生缓存文件路径） */
    strncpy(g_master_config_path, config_path, sizeof(g_master_config_path) - 1);

    g_master_cfg = cfg;

    /* 恢复 Manager 侧动态实例追踪（持久化在配置文件中） */
    if (g_ctx) {
        strncpy(g_ctx->mgmt.config_path, config_path, MAX_CONFIG_PATH - 1);
        g_ctx->mgmt.config_path[MAX_CONFIG_PATH - 1] = '\0';
        mgmt_load_dynamic_instances(g_ctx);
    }

    LOG_INFO("Master starting with %d instances on interface '%s'",
             cfg->instance_count, cfg->shared.interface);

    /* 守护进程化（可选） — 必须在 write_pid_file 之前 */
    if (cfg->daemonize) {
        if (daemon(0, 0) != 0) {
            LOG_ERROR("Failed to daemonize: %s", strerror(errno));
            master_config_free(cfg);
            return 1;
        }
    }

    /* 写入 master PID 文件（daemon 化后 PID 可能已变） */
    if (cfg->pid_file[0] != '\0') {
        write_pid_file(cfg->pid_file);
    }

    /* 设置 master 信号处理 */
    if (setup_master_signals() != 0) {
        master_config_free(cfg);
        return 1;
    }

    /* Fork 所有初始 worker */
    for (int i = 0; i < cfg->instance_count; i++) {
        global_config_t *gcfg = calloc(1, sizeof(global_config_t));
        if (!gcfg) {
            LOG_ERROR("Master: out of memory for instance config");
            continue;
        }
        build_instance_global_config(&cfg->instances[i], cfg, gcfg);

        if (validate_config(gcfg) != 0) {
            LOG_ERROR("Master: instance '%s' config validation failed, skipping",
                      cfg->instances[i].instance_name);
            free(gcfg);
            continue;
        }
        if (spawn_worker(&cfg->instances[i], gcfg, i, NULL) < 0) {
            LOG_ERROR("Master: failed to spawn instance '%s'",
                      cfg->instances[i].instance_name);
        }
        free(gcfg);
    }

    LOG_INFO("Master ready: %d workers running", cfg->worker_count);

    /* 所有 Worker 已启动 → 安全提交 spawn 缓存 */

    /* 6. 主循环：信号驱动 + watchdog 周期任务 */
    {
        sigset_t wait_mask;
        sigemptyset(&wait_mask);
        sigaddset(&wait_mask, SIGCHLD);
        sigaddset(&wait_mask, SIGHUP);
        sigaddset(&wait_mask, SIGINT);
        sigaddset(&wait_mask, SIGTERM);
        sigaddset(&wait_mask, SIGUSR1);
        sigaddset(&wait_mask, SIGUSR2);
        sigaddset(&wait_mask, SIGURG);

        struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
        /*
         * 批量信号处理计数器：防止信号风暴（如 SIGCHLD flood）导致
         * watchdog 周期任务（心跳检测、自动重启）被无限推迟。
         * 每处理 MAX_SIGNALS_PER_BATCH 个信号后，强制执行一次 watchdog
         * 周期，即使仍有未决信号排队。
         */
        #define MAX_SIGNALS_PER_BATCH 16
        int signals_in_batch = 0;

        while (g_master_running) {
            siginfo_t info;
            int sig = sigtimedwait(&wait_mask, &info, &timeout);

            if (sig < 0) {
                if (errno == EAGAIN) {
                    /* timeout — watchdog periodic tasks */
                    watchdog_check_heartbeats();
                    watchdog_restart_workers();
                    kill_stuck_workers();

                    /* ── 动态实例同步状态机 ── */
                    if (g_ctx) {
                        uint32_t st = g_ctx->mgmt.sync_state;
                        if (st == INSTANCE_SYNC_PENDING) {
                            /* 每 3s 重发一次，5 次无响应 → RETRYING 退避 */
                            if (time_elapsed(g_ctx->mgmt.sync_last_attempt) >= 3) {
                                if (g_ctx->mgmt.sync_retry_count >= 5) {
                                    g_ctx->mgmt.sync_state = INSTANCE_SYNC_RETRYING;
                                    LOG_INFO("Instance sync: no response, switching to RETRYING");
                                } else {
                                    mgmt_request_instance_sync(g_ctx);
                                    g_ctx->mgmt.sync_retry_count++;
                                }
                            }
                        } else if (st == INSTANCE_SYNC_RETRYING) {
                            int delay = 5;
                            for (int r = 0; r < g_ctx->mgmt.sync_retry_count && r < 5; r++)
                                delay *= 2;
                            if (delay > 120) delay = 120;
                            if (time_elapsed(g_ctx->mgmt.sync_last_attempt) > delay) {
                                g_ctx->mgmt.sync_state = INSTANCE_SYNC_PENDING;
                                LOG_INFO("Instance sync: retrying (attempt %d, delay %ds)",
                                         g_ctx->mgmt.sync_retry_count + 1, delay);
                            }
                        }
                    }

                    timeout.tv_sec = 1;
                    timeout.tv_nsec = 0;
                    signals_in_batch = 0;
                }
                continue;
            }

            /* signal received */
            signals_in_batch++;

            /*
             * 达到批量上限：强制执行 watchdog 并重置计数器，
             * 防止连续信号（如 SIGCHLD 风暴）饿死 watchdog。
             */
            if (signals_in_batch >= MAX_SIGNALS_PER_BATCH) {
                watchdog_check_heartbeats();
                watchdog_restart_workers();
                kill_stuck_workers();
                timeout.tv_sec = 1;
                timeout.tv_nsec = 0;
                signals_in_batch = 0;
            } else {
                /* retry immediately for pending signals */
                timeout.tv_sec = 0;
                timeout.tv_nsec = 0;
            }

            switch (sig) {
            case SIGCHLD:
                reap_workers();
                break;
            case SIGHUP:
                if (master_graceful_reload(config_path, NULL) != 0) {
                    LOG_ERROR("Master graceful reload failed");
                }
                break;
            case SIGINT:
            case SIGTERM:
                g_master_running = 0;
                break;
            case SIGUSR1:
                /* SIGUSR1 语义过载：同时承载 SPAWN 请求与 CHANNEL_CTL 转发。
                 * 判定逻辑：master_handle_spawn_request() 通过检查
                 * SPAWN_REQUEST_FILE 是否存在来判定是否为 SPAWN 请求；
                 * master_handle_channel_ctl_forward() 则检查
                 * CHANNEL_CTL_FILE。两者互不冲突，可安全先后调用。 */
                master_handle_spawn_request();
                master_handle_channel_ctl_forward();
                break;
            case SIGUSR2:
                master_handle_kill_request();
                break;
            case SIGURG:
                master_handle_config_switch();
                break;
            default:
                LOG_WARN("master_watchdog: unexpected signal %d", sig);
                break;
            }
        }
    }

    /* 7. 优雅关闭 */
    LOG_INFO("Master shutting down...");
    stop_all_workers();

    /* 等待 worker 退出（最多 WORKER_GRACEFUL_TIMEOUT 秒） */
    {
        uint32_t shutdown_start = time_now();
        while (time_elapsed(shutdown_start) < WORKER_GRACEFUL_TIMEOUT) {
            reap_workers();
            kill_stuck_workers();

            /* 检查是否所有 worker 都已退出 */
            int alive = 0;
            for (int i = 0; i < g_master_cfg->worker_count; i++) {
                if (g_master_cfg->workers[i].state != WORKER_DEAD) { alive = 1; break; }
            }
            if (!alive) break;

            usleep(100000); /* 100ms */
        }
    }

    /* 最终清理：SIGKILL 仍存活的 worker */
    for (int i = 0; i < g_master_cfg->worker_count; i++) {
        worker_info_t *w = &g_master_cfg->workers[i];
        if (w->state != WORKER_DEAD) {
            LOG_WARN("Force killing worker pid=%d", w->pid);
            kill(w->pid, SIGKILL);
        }
    }

    /* 移除 master PID 文件 */
    if (g_master_cfg->pid_file[0] != '\0') {
        unlink(g_master_cfg->pid_file);
        LOG_INFO("Master PID file %s removed", g_master_cfg->pid_file);
    }

    LOG_INFO("Master exited");
    master_config_free(g_master_cfg);
    return 0;
}

#define DYNAMIC_CHANNEL_BASE 65536U

/* ──────────────────────────────────────────────────────────────────────────
 * build_listener_bases — 构建 listener ID 池基址
 *
 * 为每个 listener 分配一段连续的 channel_id 范围，用于多会话模式下的
 * 动态子通道 ID 分配。
 *
 * 算法：从 DYNAMIC_CHANNEL_BASE (65536) 开始，每个 listener 获得
 *       max_sessions 个 ID 的空间。listener_base[i] 记录起始偏移，
 *       listener_next[i] 记录下一个可分配的 ID（由 alloc_channel_id 消费）。
 *
 * 例如：channel[0].max_sessions=5 → 使用 ID 65536-65540
 *       channel[1].max_sessions=3 → 使用 ID 65541-65543
 *       ...
 *
 * limit=0 时自动提升为 1，确保每个 listener 至少有一个动态 ID 可用。
 * ────────────────────────────────────────────────────────────────────────── */
static void build_listener_bases(global_ctx_t *ctx)
{
    /* ── 构建 listener 动态 ID 池基址表 ──
     *
     * 从 DYNAMIC_CHANNEL_BASE (65536) 开始，为每个静态 listener 分配一段连续的
     * channel_id 范围，用于多会话模式下动态子通道的 ID 分配。
     *
     * listener_base[i] = 该 listener 可用 ID 范围的起始值
     * listener_next[i] = 下一个可分配的 ID（由 alloc_channel_id() 消费并递增）
     *
     * 例如: channel[0].max_sessions=5 → 预留 ID 范围 65536-65540
     *       channel[1].max_sessions=3 → 预留 ID 范围 65541-65543
     *
     * limit=0 时自动提升为 1，确保每个 listener 至少有一个动态 ID 可用。 */

    uint32_t offset = DYNAMIC_CHANNEL_BASE;          /* 起始基址: 65536 */
    for (int i = 0; i < ctx->config.channel_count; i++) {
        uint32_t limit = (uint32_t)ctx->config.channels[i].max_sessions;
        if (limit == 0) limit = 1;                    /* 至少预留 1 个 ID */
        /* 溢出保护：offset + limit 不得回绕 */
        if (offset > UINT32_MAX - limit) {
            LOG_ERROR("listener_base overflow at channel %d: offset=%u + limit=%u exceeds UINT32_MAX",
                      i, offset, limit);
            ctx->listener_base[i] = offset;
            ctx->listener_next[i] = offset;
            break;
        }
        ctx->listener_base[i] = offset;               /* 记录起始值 */
        ctx->listener_next[i] = offset;               /* 初始化可分配指针 */
        offset += limit;                              /* 移动到下一个 listener 的基址 */
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * cleanup — 优雅关闭，严格的逆序清理
 *
 * 关闭顺序（与初始化顺序相反）：
 *   1. channel_close_all()        — 遍历所有通道，发送 FIN 控制帧
 *   2. KCP 缓冲区排空              — 循环 channel_kcp_update() + usleep(10ms)
 *                                    最多 20 次（200ms），确保在途数据尽力发送
 *   3. channel_shutdown()         — 销毁所有通道 + 释放哈希表
 *   4. proxy_shutdown()           — 关闭 epoll_fd
 *   5. crypto_cleanup()           — 释放 SM4/SM3 上下文
 *   6. af_packet_close()          — 关闭 AF_PACKET 原始套接字
 *   7. close(epoll_fd)            — 关闭 epoll 实例
 *   8. unlink(pid_file)           — 删除 PID 文件
 *
 * 设计考量：先排空 KCP 缓冲区再销毁通道，确保关闭前的数据尽可能送达对端。
 * 每步操作都会检查 fd >= 0 以避免 double-close。
 * ────────────────────────────────────────────────────────────────────────── */
static void cleanup(global_ctx_t *ctx)
{
    /* ── 优雅关闭：严格的逆序清理 ──
     *
     * 关闭顺序（与初始化顺序严格相反）:
     *   1. channel_close_all()      — 遍历所有通道，发送 FIN 控制帧
     *   2. KCP 缓冲区排空           — 循环 channel_kcp_update() + usleep(10ms)
     *                                最多 20 次 (200ms)，尽力排空在途数据
     *   3. channel_shutdown()       — 销毁所有通道 + 释放哈希表
     *   4. proxy_shutdown()         — 关闭代理子系统
     *   5. crypto_cleanup()         — 释放 SM4/SM3 上下文
     *   6. api_shutdown()           — 停止 HTTP API 服务器
     *   7. mgmt_shutdown()          — 关闭管理模块连接
     *   8. af_packet_close()        — 关闭 AF_PACKET 原始套接字
     *   9. close(epoll_fd)          — 关闭 epoll 实例
     *   10. unlink(ctl_sock)        — 移除 ctl Unix domain socket
     *   11. unlink(pid_file)        — 删除 PID 文件
     *
     * 设计原则：
     *   - 先排空 KCP 缓冲区再销毁通道，确保关闭前的数据尽可能送达对端
     *   - 每步操作前检查 fd >= 0，防止 double-close
     *   - ctx==NULL 时无操作（防御性编程） */

    if (ctx == NULL) return;

    /* 阶段 1: 关闭所有活跃通道（发送 FIN 帧通知对端） */
    if (ctx->channel_hash) {
        channel_close_all(ctx);
    }

    /* 阶段 2: KCP 缓冲区排空（尽力而为）
     * 循环调用 channel_kcp_update() 驱动 KCP 重传和排空，
     * 每次迭代间 usleep(10ms) 给内核时间发送数据。最多 200ms。 */
    {
        int drain_attempts;
        for (drain_attempts = 0; drain_attempts < 20; drain_attempts++) {
            channel_kcp_update(ctx);
            usleep(10000);          /* 10ms */
        }
    }

    /* 阶段 3: 关闭插件（在通道销毁之前，插件可安全访问 channel 数据） */
    plugin_shutdown_all(ctx);

    /* 阶段 4-5: 销毁通道、代理、加密（插件已关闭，不再引用） */
    channel_shutdown(ctx);
    proxy_shutdown(ctx);
    if (ctx->heartbeat_fd >= 0) {
        close(ctx->heartbeat_fd);
        ctx->heartbeat_fd = -1;
    }
    crypto_cleanup();

    /* 阶段 6-7: 关闭日志、API 与管理模块 */
    log_shutdown();
    api_shutdown(ctx);
    mgmt_shutdown(ctx);

    /* 阶段 8: 关闭 AF_PACKET 套接字 */
    if (ctx->raw_sock >= 0) {
        af_packet_close(ctx->raw_sock);
        ctx->raw_sock = -1;
    }

    /* 阶段 9: 关闭 epoll 实例 */
    if (ctx->epoll_fd >= 0) {
        close(ctx->epoll_fd);
        ctx->epoll_fd = -1;
    }

    /* 阶段 10: 移除 ctl socket 文件并关闭 */
    if (ctx->ctl_sock_fd >= 0) {
        unlink(ctx->ctl_sock_path);
        close(ctx->ctl_sock_fd);
        ctx->ctl_sock_fd = -1;
    }

    /* 阶段 11: 删除 PID 文件 */
    if (ctx->config.pid_file[0]) {
        unlink(ctx->config.pid_file);
        LOG_INFO("PID file %s removed", ctx->config.pid_file);
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * config_reload_channels — 4 步算法：Mark → Diff → Clean → Update
 *
 * Step 1 — Mark（标记）：
 *   遍历哈希表中所有通道，对 CH_FLAG_STATIC_LISTENER 设置 CH_FLAG_RELOAD_MARKED。
 *
 * Step 2 — Diff（差异对比）：
 *   遍历新配置 channels[]，对比旧通道：
 *     情况 A: channel_id 已存在 + 旧通道是 STATIC_LISTENER
 *       - 清除 RELOAD_MARKED 标志
 *       - enabled=false → 移除 STATIC_LISTENER → channel_destroy()
 *       - 配置有变更 → proxy_port_probe() 预检 → proxy_stop_listen() →
 *         channel_update_config() → proxy_start_listen()
 *       - 无变更 → 仅更新 listener_idx
 *     情况 B: channel_id 不存在 + enabled=true
 *       - proxy_port_conflict() 端口冲突检测
 *       - channel_create() → 复制网络层信息 → proxy_start_listen()
 *
 * Step 3 — Clean（清理）：
 *   再次扫描哈希表，清理仍带 RELOAD_MARKED 的旧 listener
 *   （说明新配置中已不存在，执行 channel_destroy）。
 *
 * Step 4 — Update（更新 channels[] 数组）：
 *   将新配置通道复制到 updated_channels[]；
 *   保留旧配置中已不存在但数组空间仍有的 disabled 条目（保持索引稳定）。
 *   最后 memcpy 到 ctx->config.channels。
 * ────────────────────────────────────────────────────────────────────────── */
static void config_reload_channels(global_ctx_t *ctx,
                                   const global_config_t *new_cfg)
{
    /* ── 4 步算法：Mark → Diff → Clean → Update ──
     *
     * 这是 SIGHUP 触发的通道热重载的核心。采用"双缓冲区"策略:
     *   1. 首先在临时缓冲区 updated_channels[] (MAX_CHANNELS * sizeof(channel_config_t))
     *      中构建新配置，
     *   2. 然后通过 memset + memcpy 原子性地替换 ctx->config.channels[]，
     *   3. channel_count 最后更新，确保 reader 看到一致的数据。
     *
     * 因为 config_reload 在主线程 epoll EINTR 路径中调用（单线程），
     * 不存在并发读写问题，但"先清零后复制 + 计数字段最后更新"仍提供了原子性语义。 */

    /* Step 1: 标记所有现存的 listener 通道 */
    for (uint32_t i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            if (ch->flags & CH_FLAG_STATIC_LISTENER)
                ch->flags |= CH_FLAG_RELOAD_MARKED;
            ch = ch->hash_next;
        }
    }

    /* Step 2: 遍历新配置，匹配 + 增/改 */
    for (int i = 0; i < new_cfg->channel_count; i++) {
        const channel_config_t *new_ch = &new_cfg->channels[i];
        channel_t *old_ch = channel_find(ctx, new_ch->channel_id);

        if (old_ch && (old_ch->flags & CH_FLAG_STATIC_LISTENER)) {
            /* 情况 A: channel_id 已存在 */
            old_ch->flags &= ~CH_FLAG_RELOAD_MARKED;

            if (!new_ch->enabled) {
                /* 禁用：清除 STATIC_LISTENER → channel_destroy */
                old_ch->flags &= ~CH_FLAG_STATIC_LISTENER;
                channel_destroy(ctx, old_ch);
                LOG_INFO("config_reload: channel %u disabled and destroyed",
                         new_ch->channel_id);
                continue;
            }

            /* ACL 变更检测（channel_config_changed 不接收 ctx） */
            int acl_changed = (memcmp(
                &ctx->config.channels[old_ch->listener_idx].client_acl,
                &new_ch->client_acl,
                sizeof(channel_acl_t)) != 0);

            if (channel_config_changed(old_ch, new_ch) || acl_changed) {
                /* 修改通道：预检 → 关闭旧 listener → 更新配置 → 启动新 */
                if (ctx->config.node_type == NODE_TYPE_FRONTEND) {
                    if (proxy_port_probe(new_ch->listen_addr,
                                          new_ch->listen_port,
                                          new_ch->is_tcp) != 0) {
                        LOG_ERROR("config_reload: port %s:%u unavailable for "
                                  "channel %u, keeping old listener unchanged",
                                  new_ch->listen_addr, new_ch->listen_port,
                                  old_ch->channel_id);
                        continue;
                    }
                }

                proxy_stop_listen(ctx, old_ch);
                channel_update_config(old_ch, new_ch);
                old_ch->listener_idx = (uint16_t)i;

                if (ctx->config.node_type == NODE_TYPE_FRONTEND) {
                    if (proxy_start_listen(ctx, old_ch) != 0) {
                        LOG_ERROR("config_reload: new listen failed for "
                                  "channel %u after config change",
                                  old_ch->channel_id);
                    }
                }
                LOG_INFO("config_reload: channel %u updated", old_ch->channel_id);
            } else {
                /* 无变更，仅更新 listener_idx */
                old_ch->listener_idx = (uint16_t)i;
            }

        } else if (new_ch->enabled) {
            /* 情况 B: channel_id 不存在 → 新建 */
            if (ctx->config.node_type == NODE_TYPE_FRONTEND &&
                proxy_port_conflict(ctx, new_ch->listen_addr,
                                     new_ch->listen_port,
                                     new_ch->channel_id)) {
                LOG_ERROR("config_reload: port %s:%u already in use, "
                          "skipping new channel %u",
                          new_ch->listen_addr, new_ch->listen_port,
                          new_ch->channel_id);
                continue;
            }
            if (ensure_listener_fd_budget(ctx, 1, "config_reload",
                                          new_ch->channel_id) != 0) {
                continue;
            }

            channel_t *ch = channel_create(ctx, new_ch->channel_id,
                                           CHANNEL_ROLE_LISTENER,
                                           new_ch->listen_port,
                                           new_ch->remote_port,
                                           new_ch->source_port,
                                           new_ch->listen_addr,
                                           new_ch->remote_addr,
                                           new_ch->is_tcp);
            if (!ch) {
                LOG_ERROR("config_reload: failed to create channel %u",
                          new_ch->channel_id);
                continue;
            }

            ch->raw_sock  = ctx->raw_sock;
            ch->ifindex   = ctx->ifindex;
            memcpy(ch->local_mac, ctx->local_mac, ETH_MAC_ADDR_LEN);
            memcpy(ch->peer_mac,  ctx->peer_mac,  ETH_MAC_ADDR_LEN);
            ch->ethertype = ctx->ethertype;
            ch->flags     = CH_FLAG_STATIC_LISTENER;
            ch->listener_idx = (uint16_t)i;

            if (ctx->config.node_type == NODE_TYPE_FRONTEND) {
                if (proxy_start_listen(ctx, ch) != 0) {
                    LOG_ERROR("config_reload: listen failed for new channel %u",
                              new_ch->channel_id);
                    ch->flags &= ~CH_FLAG_STATIC_LISTENER;
                    channel_destroy(ctx, ch);
                    continue;
                }
            }
            LOG_INFO("config_reload: channel %u created", new_ch->channel_id);
        }
    }

    /* Step 3: 清理未匹配的旧 listener（仍带 RELOAD_MARKED）
     * 这些通道在新配置中不存在（既没匹配也没被显式禁用），需要销毁。
     * 保护管理通道 (channel_id=0): STATIC_LISTENER+MGMT 组合永不销毁。
     * 保存 hash_next 在 channel_destroy 之前，因为销毁可能修改哈希链表。 */
    for (uint32_t i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            channel_t *next = ch->hash_next;
            if ((ch->flags & CH_FLAG_STATIC_LISTENER) &&
                (ch->flags & CH_FLAG_RELOAD_MARKED) &&
                !(ch->flags & CH_FLAG_MGMT_CHANNEL)) {
                uint32_t removed_id = ch->channel_id;
                ch->flags &= ~CH_FLAG_STATIC_LISTENER;
                channel_destroy(ctx, ch);
                LOG_INFO("config_reload: channel %u removed", removed_id);
            } else {
                ch->flags &= ~CH_FLAG_RELOAD_MARKED;  /* 清除临时标记 */
            }
            ch = next;
        }
    }

    /* Step 4: 刷新 channels[] 数组（保留 disabled 条目保持索引稳定）
     *
     * 双缓冲区替换策略:
     *   A. 先填入新配置中的所有 channel
     *   B. 再追加旧配置中存在但新配置中不存在的 disabled 条目
     *      （保持索引稳定，供统计和诊断使用）
     *   C. memset 清零 → memcpy 新内容 → channel_count 最后更新
     *      （简单且安全的原子替换，单线程无需内存屏障） */
    channel_config_t *updated_channels = calloc(MAX_CHANNELS, sizeof(channel_config_t));
    if (!updated_channels) {
        LOG_ERROR("config_reload_channels: failed to allocate updated_channels");
        return;
    }
    int updated_count = 0;

    for (int i = 0; i < new_cfg->channel_count; i++) {
        updated_channels[updated_count++] = new_cfg->channels[i];
    }

    for (int i = 0; i < ctx->config.channel_count; i++) {
        const channel_config_t *old = &ctx->config.channels[i];
        int found = 0;
        for (int j = 0; j < new_cfg->channel_count; j++) {
            if (new_cfg->channels[j].channel_id == old->channel_id) {
                found = 1;
                break;
            }
        }
        if (!found && updated_count < MAX_CHANNELS) {
            updated_channels[updated_count] = *old;
            updated_channels[updated_count].enabled = 0;  /* 标记为禁用 */
            updated_count++;
        }
    }

    /* 原子替换：先清零旧数组，再复制新内容，最后更新计数。
     * 由于 config_reload 在主线程 epoll EINTR 路径中调用（单线程），
     * 不存在并发读写问题。channel_count 最后更新，确保原子性语义。 */
    memset(ctx->config.channels, 0, sizeof(ctx->config.channels));
    memcpy(ctx->config.channels, updated_channels,
           (size_t)updated_count * sizeof(channel_config_t));
    ctx->config.channel_count = updated_count;
    free(updated_channels);
}

/* ──────────────────────────────────────────────────────────────────────────
 * config_reload — SIGHUP 触发的配置热重载
 *
 * 两阶段重载策略：
 *
 *   阶段一：软参数更新（no-restart）
 *     直接应用到运行中的配置，无需重启任何通道：
 *     - crc_enabled, heartbeat_interval, heartbeat_timeout
 *     - KCP 参数（nodelay, interval, resend, nc, send/recv window）
 *       更新到 config 并通过 ikcp_wndsize() + ikcp_nodelay() 应用到所有通道的 kcp 实例
 *
 *   阶段二：通道 diff 更新（通过 config_reload_channels）
 *     对比新旧 channels[] 数组，执行增/改/删操作。
 *     修改现有通道时先 proxy_port_probe() 预检新端口可用性，
 *     再 proxy_stop_listen() → channel_update_config() → proxy_start_listen()。
 *     best-effort 策略：单个通道失败不回滚，继续处理后续通道。
 *
 *   加密配置变更检测：若 encryption.enabled 或 sm4_key 变化，
 *   先 crypto_cleanup() 再 crypto_init() 重新初始化加密模块。
 *
 * @param ctx         全局上下文
 * @param config_path 配置文件路径
 * @return            0=成功, -1=加载或验证失败
 * ────────────────────────────────────────────────────────────────────────── */
static int config_reload(global_ctx_t *ctx, const char *config_path)
{
    /* ── 阶段一：加载和验证新配置 ──
     * 使用堆分配临时的 global_config_t，先验证再应用，
     * 避免半解析的配置覆盖运行中的配置。 */

    global_config_t *new_cfg = calloc(1, sizeof(global_config_t));
    if (!new_cfg) return -1;   /* OOM */

    /* 关键：从当前配置继承所有字段（作为 baseline），
     * config_load 仅覆盖 JSON 中出现的字段。
     * 这对于管理通道推送的部分配置（仅含 channels）至关重要——
     * 未出现在 JSON 中的字段保持当前值不变。 */
    memcpy(new_cfg, &ctx->config, sizeof(global_config_t));

    if (config_load(config_path, new_cfg) != 0) {
        LOG_ERROR("Config reload: failed to load %s", config_path);
        free(new_cfg);
        return -1;
    }

    if (validate_config(new_cfg) != 0) {
        LOG_ERROR("Config reload: validation failed");
        free(new_cfg);
        return -1;
    }

    /* ── 阶段二：通道 diff 与增删改（best-effort，失败不回滚） ── */
    config_reload_channels(ctx, new_cfg);

    /* 重建动态通道 ID 区间分配表。
     * config_reload_channels 可能改变 channel_count 和各 listener 的
     * max_sessions，listener_base/listener_next 必须同步更新，
     * 否则后续 alloc_channel_id 和 channel_process_frame 中的
     * 动态 ID 反向查找会产生越界或错误绑定。 */
    build_listener_bases(ctx);

    /* ── 阶段三：软参数更新（不重启通道） ──
     * 以下参数直接应用到运行中的配置，无需重启任何通道: */

    /* CRC 和心跳参数（每次检查时从 g_ctx->config 实时读取，无需 per-channel 缓存） */
    ctx->config.crc_enabled        = new_cfg->crc_enabled;
    ctx->config.heartbeat_interval = new_cfg->heartbeat_interval;
    ctx->config.heartbeat_timeout  = new_cfg->heartbeat_timeout;

    /* KCP 参数：先更新全局配置，再通过 ikcp_wndsize/ikcp_nodelay 同步到所有通道 */
    ctx->config.kcp_nodelay        = new_cfg->kcp_nodelay;
    ctx->config.kcp_interval       = new_cfg->kcp_interval;
    ctx->config.kcp_resend         = new_cfg->kcp_resend;
    ctx->config.kcp_nc             = new_cfg->kcp_nc;
    ctx->config.kcp_send_window    = new_cfg->kcp_send_window;
    ctx->config.kcp_recv_window    = new_cfg->kcp_recv_window;

    /* AF_PACKET 和代理性能参数 */
    ctx->config.perf_af_packet_sndbuf = new_cfg->perf_af_packet_sndbuf;
    ctx->config.perf_af_packet_rcvbuf = new_cfg->perf_af_packet_rcvbuf;
    ctx->config.perf_af_packet_send_retry_max =
        new_cfg->perf_af_packet_send_retry_max;
    ctx->config.perf_af_packet_send_wait_ms =
        new_cfg->perf_af_packet_send_wait_ms;
    ctx->config.perf_proxy_tcp_sockbuf = new_cfg->perf_proxy_tcp_sockbuf;
    ctx->config.perf_proxy_recv_buf_max = new_cfg->perf_proxy_recv_buf_max;
    ctx->config.perf_kcp_read_pause_waitsnd =
        new_cfg->perf_kcp_read_pause_waitsnd;
    ctx->config.perf_kcp_read_resume_waitsnd =
        new_cfg->perf_kcp_read_resume_waitsnd;
    ctx->config.perf_kcp_immediate_flush =
        new_cfg->perf_kcp_immediate_flush;
    ctx->config.perf_max_frames_per_cycle =
        new_cfg->perf_max_frames_per_cycle;

    /* 重新配置 AF_PACKET 全局参数（全局静态缓存，非 per-instance） */
    af_packet_configure(ctx->config.perf_af_packet_sndbuf,
                        ctx->config.perf_af_packet_rcvbuf,
                        ctx->config.perf_af_packet_send_retry_max,
                        ctx->config.perf_af_packet_send_wait_ms);

    /* ── KCP 参数同步到所有活跃通道 ──
     * 遍历哈希表，对每个持有 kcp 实例的通道调用 ikcp_wndsize() 和 ikcp_nodelay()
     * 以立即生效，无需重建 KCP 实例。 */
    for (uint32_t i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            if (ch->kcp) {
                ikcp_wndsize(ch->kcp, ctx->config.kcp_send_window, ctx->config.kcp_recv_window);
                ikcp_nodelay(ch->kcp, ctx->config.kcp_nodelay, ctx->config.kcp_interval,
                            ctx->config.kcp_resend, ctx->config.kcp_nc);
            }
            ch = ch->hash_next;
        }
    }

    /* ── 加密配置变更检测 ──
     * 如果加密设置发生变化，先 cleanup 旧上下文再 init 新上下文。
     * 这是一个破坏性操作——在途加密帧可能解密失败——因此仅在配置变更时执行。 */
    if (new_cfg->encryption.enabled != ctx->config.encryption.enabled ||
        strcmp(new_cfg->encryption.sm4_key, ctx->config.encryption.sm4_key) != 0) {
        crypto_cleanup();
        ctx->config.encryption = new_cfg->encryption;
        if (ctx->config.encryption.enabled) {
            if (crypto_init(&ctx->config.encryption) < 0) {
                LOG_ERROR("Config reload: crypto re-init failed, encryption disabled");
                ctx->config.encryption.enabled = 0;   /* 失败降级：关闭加密 */
            }
        }
    }

    LOG_INFO("Configuration reloaded successfully");

    /* Manager 模式: 推送新配置到所有受管 worker */
    if (ctx->config.node.node_role == NODE_ROLE_MANAGER
        && ctx->config.management.enabled) {
        ctx->mgmt.config_version++;                   /* 递增版本号 */
    }

    free(new_cfg);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * handle_channel_ctl — SIGUSR1 触发的通道快速增删
 *
 * 控制文件命名规则：config.json → config-ctl.json
 *
 * JSON 控制文件格式（单个或数组）：
 *   { "op": "add", "channel_id": 100, "listen_port": 8080, ... }
 *   { "op": "del", "channel_id": 100 }
 *
 * 处理流程：
 *   1. json_object_from_file() 读取控制文件
 *   2. 遍历每个命令，调用 channel_ctl_add() 或 channel_ctl_del()
 *   3. 统计 added/deleted/errors 数量
 *   4. 清空控制文件（fopen("w") + fclose，实现幂等处理）
 *
 * 幂等性保证：控制文件被处理后立即清空，即使重复触发 SIGUSR1
 * 也不会重复执行相同的命令。
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * 解析 JSON 中的单个通道配置。
 */
static int ctl_parse_channel(json_object *ch_obj, channel_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled  = 1;
    cfg->is_tcp   = 1;

    json_object *tmp;
    if (json_object_object_get_ex(ch_obj, "channel_id", &tmp))
        cfg->channel_id = (uint32_t)json_object_get_int64(tmp);
    else { LOG_ERROR("ctl: missing channel_id"); return -1; }

    if (json_object_object_get_ex(ch_obj, "listen_port", &tmp))
        cfg->listen_port = (uint16_t)json_object_get_int(tmp);
    if (json_object_object_get_ex(ch_obj, "remote_port", &tmp))
        cfg->remote_port = (uint16_t)json_object_get_int(tmp);
    if (json_object_object_get_ex(ch_obj, "source_port", &tmp))
        cfg->source_port = (uint16_t)json_object_get_int(tmp);
    if (json_object_object_get_ex(ch_obj, "listen_addr", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s) { strncpy(cfg->listen_addr, s, MAX_LISTEN_ADDR - 1); }
        cfg->listen_addr[MAX_LISTEN_ADDR - 1] = '\0';
    }
    if (json_object_object_get_ex(ch_obj, "remote_addr", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s) { strncpy(cfg->remote_addr, s, MAX_REMOTE_ADDR - 1); }
        cfg->remote_addr[MAX_REMOTE_ADDR - 1] = '\0';
    }
    if (json_object_object_get_ex(ch_obj, "is_tcp", &tmp))
        cfg->is_tcp = (uint8_t)json_object_get_int(tmp);
    if (json_object_object_get_ex(ch_obj, "max_sessions", &tmp)) {
        int ms = json_object_get_int(tmp);
        cfg->max_sessions = (ms > 0 && ms <= 65535) ? (uint16_t)ms : 1;
    }
    parse_acl(ch_obj, &cfg->client_acl);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * channel_ctl_add — O(1) 添加新 listener 通道
 *
 * 快速添加流程（不经过 config_reload 的完整 diff 算法）：
 *   1. channel_find() 检查 ID 是否已存在（O(1) 哈希查找）
 *   2. proxy_port_conflict() 端口冲突检测（仅 frontend）
 *   3. channel_create() 创建通道
 *   4. 复制网络层信息（raw_sock, ifindex, MAC, ethertype）
 *   5. 设置 CH_FLAG_STATIC_LISTENER + listener_idx
 *   6. proxy_start_listen() 启动监听（仅 frontend）
 *   7. 追加到 ctx->config.channels[] 数组末尾
 *   8. build_listener_bases() 重建 ID 池基址
 *
 * 不触发通道 diff，不重载配置文件，仅操作单个通道。
 * ────────────────────────────────────────────────────────────────────────── */

/* ──────────────────────────────────────────────────────────────────────────
 * ctl_execute_json — 执行 JSON 格式的通道控制命令（单个对象或数组）
 *
 * 从 handle_channel_ctl（文件模式）和 ctl_socket_accept（socket模式）
 * 共用。执行结果通过 added/deleted/errors 返回。
 * ────────────────────────────────────────────────────────────────────────── */
int ctl_execute_json(global_ctx_t *ctx, json_object *root,
                             int *added, int *deleted, int *errors)
{
    *added = *deleted = *errors = 0;
    int is_array = json_object_is_type(root, json_type_array);
    int count    = is_array ? (int)json_object_array_length(root) : 1;

    for (int i = 0; i < count; i++) {
        json_object *cmd = is_array ? json_object_array_get_idx(root, (size_t)i) : root;
        json_object *tmp;
        if (!json_object_object_get_ex(cmd, "op", &tmp)) { (*errors)++; continue; }
        const char *op = json_object_get_string(tmp);
        if (!op) { (*errors)++; continue; }

        if (strcmp(op, "add") == 0) {
            channel_config_t cfg;
            if (ctl_parse_channel(cmd, &cfg) == 0 && channel_ctl_add(ctx, &cfg) == 0)
                (*added)++;
            else (*errors)++;
        } else if (strcmp(op, "del") == 0) {
            json_object *id_obj;
            if (json_object_object_get_ex(cmd, "channel_id", &id_obj)) {
                if (channel_ctl_del(ctx, (uint32_t)json_object_get_int64(id_obj)) == 0)
                    (*deleted)++;
                else (*errors)++;
            } else (*errors)++;
        } else {
            LOG_ERROR("ctl: unknown op '%s'", op);
            (*errors)++;
        }
    }
    LOG_INFO("ctl: processed %d ops (add=%d del=%d errors=%d)", count, *added, *deleted, *errors);
    return (*errors > 0) ? -1 : 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * ctl_socket_init — 创建 Unix domain socket 用于通道管理 API
 *
 * Socket 路径：/tmp/kcp-<instance_name>.sock
 * ────────────────────────────────────────────────────────────────────────── */
static int ctl_socket_init(global_ctx_t *ctx)
{
    const char *name = ctx->config.instance_name;
    if (!name[0] || strcmp(name, "default") == 0)
        name = "afpacket";
    snprintf(ctx->ctl_sock_path, sizeof(ctx->ctl_sock_path),
             "/tmp/kcp-%s.sock", name);

    /* ═══════════════════════════════════════════════════════════════════
     * R6-S1: TOCTOU 修复 —— 先 bind 再 unlink
     *
     * 传统的先检查（stat/unlink）再 bind 存在 TOCTOU 竞争:
     *   Time A: stat() 检查 socket 是否存在 → 存在
     *   Time B: 攻击者 unlink() + symlink() 替换
     *   Time C: bind() 绑定到攻击者控制的路径
     *
     * 修复方案: 直接 bind()，仅在 EADDRINUSE 时才 unlink 旧 socket
     * 并重试一次。bind 成功后 chmod 0600 限制本地访问权限。
     * ═══════════════════════════════════════════════════════════════════ */
    int retry = 0;          /* 只允许一次重试 */

    /* 创建 Unix domain stream socket */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_WARN("ctl socket: socket() failed: %s (ctl API disabled)", strerror(errno));
        ctx->ctl_sock_fd = -1;
        return -1;          /* 非致命: ctl API 不可用但数据面正常工作 */
    }

    /* 设置为非阻塞，避免 accept() 阻塞事件循环 */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        LOG_WARN("ctl socket: fcntl(O_NONBLOCK) failed: %s (ctl API disabled)", strerror(errno));
        close(fd);
        ctx->ctl_sock_fd = -1;
        return -1;
    }

    /* 构建 Unix domain socket 地址结构 */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    {
        size_t slen = strlen(ctx->ctl_sock_path);
        if (slen >= sizeof(addr.sun_path)) slen = sizeof(addr.sun_path) - 1;
        memcpy(addr.sun_path, ctx->ctl_sock_path, slen);
        addr.sun_path[slen] = '\0';
    }

retry_bind:
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno == EADDRINUSE && retry == 0) {
            /* 旧 socket 残留（前次进程异常退出未清理）：unlink 后重试一次 */
            unlink(ctx->ctl_sock_path);
            retry = 1;
            goto retry_bind;
        }
        /* 真正的绑定失败（权限、路径等） */
        LOG_WARN("ctl socket: bind(%s) failed: %s (ctl API disabled)",
                 ctx->ctl_sock_path, strerror(errno));
        close(fd);
        ctx->ctl_sock_fd = -1;
        return -1;
    }

    /* 限制权限：仅 owner 可读写（0600） */
    chmod(ctx->ctl_sock_path, 0600);

    /* 开始监听，backlog=128（ctl 管理接口为低并发） */
    if (listen(fd, 128) < 0) {
        LOG_WARN("ctl socket: listen() failed: %s", strerror(errno));
        close(fd);
        unlink(ctx->ctl_sock_path);
        ctx->ctl_sock_fd = -1;
        return -1;
    }

    ctx->ctl_sock_fd = fd;
    LOG_INFO("Ctl API listening on %s", ctx->ctl_sock_path);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * ctl_socket_accept — 处理一个 ctl socket 连接（请求-应答）
 * ────────────────────────────────────────────────────────────────────────── */
static void ctl_socket_accept(global_ctx_t *ctx)
{
    int client;
    while (1) {
        /* 循环 accept 所有就绪连接（非阻塞模式） */
        do {
            client = accept(ctx->ctl_sock_fd, NULL, NULL);
        } while (client < 0 && errno == EINTR);   /* 信号中断则重试 */
        if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;  /* 无更多连接 */
            break;
        }

        /* ═══════════════════════════════════════════════════════════════
         * T11-3: SO_PEERCRED 权限验证
         *
         * 通过 SO_PEERCRED 获取对端进程的 uid，仅允许:
         *   - root (uid=0)
         *   - 与当前进程相同 uid 的用户
         *
         * 这防止低权限用户通过 ctl socket 执行通道增删操作。
         * getsockopt 失败时静默放行（向后兼容不支持 SO_PEERCRED 的平台）。
         * ═══════════════════════════════════════════════════════════════ */
        {
            struct ucred cred;
            socklen_t clen = sizeof(cred);
            uid_t my_uid = getuid();
            if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cred, &clen) == 0) {
                if (cred.uid != 0 && cred.uid != my_uid) {
                    LOG_AUDIT("ctl socket: rejected uid=%u from %s (my uid=%u)",
                              (unsigned)cred.uid, ctx->ctl_sock_path, (unsigned)my_uid);
                    dprintf(client, "{\"status\":\"error\",\"msg\":\"permission denied\"}\n");
                    close(client);
                    continue;            /* 拒绝该连接，继续处理下一个 */
                }
            }
            /* getsockopt 失败时静默放行 */
        }

        /* 设置 1 秒读超时，防止恶意客户端只连接不发送 */
        {
            struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }

        /* 读取请求 JSON（最多 64KB） */
        char buf[65536];
        ssize_t n;
        do {
            n = read(client, buf, sizeof(buf) - 1);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) { close(client); continue; }
        buf[n] = '\0';
        /* 去除尾部的换行符 */
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = '\0';

        /* 解析 JSON 请求 */
        json_object *root = json_tokener_parse(buf);
        if (!root) {
            dprintf(client, "{\"status\":\"error\",\"msg\":\"invalid JSON\"}\n");
            close(client);
            continue;
        }

        /* 执行相同的 ctl_execute_json 逻辑（与 SIGUSR1 文件模式共享） */
        int added, deleted, errors;
        int ret = ctl_execute_json(ctx, root, &added, &deleted, &errors);
        json_object_put(root);

        /* 返回 JSON 应答 */
        if (ret == 0)
            dprintf(client, "{\"status\":\"ok\",\"added\":%d,\"deleted\":%d}\n", added, deleted);
        else
            dprintf(client, "{\"status\":\"error\",\"added\":%d,\"deleted\":%d,\"errors\":%d}\n",
                    added, deleted, errors);
        close(client);               /* 请求-应答模式：每次连接处理一个请求后关闭 */
    }
}

static int channel_ctl_add(global_ctx_t *ctx, const channel_config_t *cfg)
{
    /* ── O(1) 快速添加 listener 通道 ──
     *
     * 直接操作通道哈希表和 channels[] 数组，不经过 config_reload 的完整 diff 流程。
     * 适用于 SIGUSR1 触发的通道控制文件或 ctl socket 的动态管理请求。
     *
     * 检查清单:
     *   1. channel_id 是否已存在？
     *   2. channel_count 是否已达 MAX_CHANNELS？
     *   3. 端口是否已被占用？（仅 frontend）
     *   4. FD 预算是否充足？（仅 frontend）
     *   5. channel_create() 是否成功？
     *   6. proxy_start_listen() 是否成功？（仅 frontend）
     *
     * 全部通过后：追加到 channels[] 末尾 → 重建 listener 基址表。 */

    /* 检查 1: channel_id 是否已存在（O(1) 哈希查找） */
    if (channel_find(ctx, cfg->channel_id)) {
        LOG_ERROR("ctl_add: channel %u already exists", cfg->channel_id);
        return -1;
    }

    /* 检查 2: 通道数量上限 — 到达时先压缩墓碑再试 */
    if (ctx->config.channel_count >= MAX_CHANNELS) {
        int live = 0;
        for (int i = 0; i < ctx->config.channel_count; i++)
            if (ctx->config.channels[i].enabled) live++;
        int dead = ctx->config.channel_count - live;

        if (dead > 0 && live < MAX_CHANNELS) {
            int dst = 0;
            for (int src = 0; src < ctx->config.channel_count; src++)
                if (ctx->config.channels[src].enabled)
                    ctx->config.channels[dst++] = ctx->config.channels[src];

            int old_count = ctx->config.channel_count;
            ctx->config.channel_count = live;

            for (uint32_t h = 0; h < ctx->channel_hash_size; h++) {
                channel_t *c = ctx->channel_hash[h];
                while (c) {
                    if (c->flags & CH_FLAG_STATIC_LISTENER) {
                        for (int k = 0; k < live; k++) {
                            if (ctx->config.channels[k].channel_id == c->channel_id) {
                                c->listener_idx = (uint16_t)k;
                                break;
                            }
                        }
                    }
                    c = c->hash_next;
                }
            }
            build_listener_bases(ctx);
            LOG_INFO("ctl_add: compacted %d tombstones (channel_count %d→%d)",
                     dead, old_count, live);
        } else {
            LOG_ERROR("ctl_add: channel limit reached (%d/%d, live=%d)",
                      ctx->config.channel_count, MAX_CHANNELS, live);
            return -1;
        }
    }

    /* 检查 3: 端口冲突（仅 frontend） */
    if (ctx->config.node_type == NODE_TYPE_FRONTEND &&
        proxy_port_conflict(ctx, cfg->listen_addr, cfg->listen_port, 0)) {
        LOG_ERROR("ctl_add: port %s:%u already in use", cfg->listen_addr, cfg->listen_port);
        return -1;
    }

    /* 检查 4: FD 预算 */
    if (ensure_listener_fd_budget(ctx, 1, "ctl_add", cfg->channel_id) != 0) {
        return -1;
    }

    /* 检查 5: 创建通道 */
    channel_t *ch = channel_create(ctx, cfg->channel_id, CHANNEL_ROLE_LISTENER,
                                    cfg->listen_port, cfg->remote_port,
                                    cfg->source_port,
                                    cfg->listen_addr, cfg->remote_addr, cfg->is_tcp);
    if (!ch) { LOG_ERROR("ctl_add: create failed for %u", cfg->channel_id); return -1; }

    /* 注入网络层上下文 */
    ch->raw_sock  = ctx->raw_sock;
    ch->ifindex   = ctx->ifindex;
    memcpy(ch->local_mac, ctx->local_mac, ETH_MAC_ADDR_LEN);
    memcpy(ch->peer_mac,  ctx->peer_mac,  ETH_MAC_ADDR_LEN);
    ch->ethertype = ctx->ethertype;
    ch->flags     = CH_FLAG_STATIC_LISTENER;            /* 标记为静态 listener */
    ch->listener_idx = (uint16_t)ctx->config.channel_count;  /* 新通道在数组末尾 */

    /* 检查 6: 启动代理监听（仅 frontend） */
    if (ctx->config.node_type == NODE_TYPE_FRONTEND) {
        if (proxy_start_listen(ctx, ch) != 0) {
            ch->flags &= ~CH_FLAG_STATIC_LISTENER;      /* 清除标记 */
            channel_destroy(ctx, ch);                   /* 回滚 */
            return -1;
        }
    }

    /* 成功: 追加到 channels[] 末尾 + 重建 ID 池基址 */
    ctx->config.channels[ctx->config.channel_count++] = *cfg;
    build_listener_bases(ctx);     /* 重新计算所有 listener 的动态 ID 范围 */
    LOG_INFO("ctl: channel %u added (listen=%s:%u)", cfg->channel_id, cfg->listen_addr, cfg->listen_port);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * config_apply_from_mgmt — Worker 侧：接收 Manager 推送的 JSON 配置并热加载
 *
 * 流程：
 *   1. 将 config_json 写入临时文件
 *   2. 调用 config_reload() 走标准 4 步热重载流程
 *   3. 成功返回 0，失败返回 -1
 * ────────────────────────────────────────────────────────────────────────── */
int config_apply_from_mgmt(global_ctx_t *ctx, const char *config_json)
{
    char path[256], path_tmp[256];
    char safe_id[65];
    FILE *fp = NULL;
    int fd, len;
    size_t j = 0;

    if (!ctx || !config_json) return -1;

    /* 防御：过滤 node_id 中的路径分隔符，防止目录穿越 */
    if (ctx->config.node.node_id[0]) {
        j = 0;
        for (size_t i = 0; i < sizeof(ctx->config.node.node_id)
             && ctx->config.node.node_id[i]; i++) {
            char c = ctx->config.node.node_id[i];
            /* 拒绝路径分隔符；'..' 序列会被自然阻止 */
            if (c == '/' || c == '\\') continue;
            if (j < sizeof(safe_id) - 1)
                safe_id[j++] = c;
        }
        safe_id[j] = '\0';
    }
    if (j == 0) memcpy(safe_id, "unknown", 8);

    snprintf(path, sizeof(path), "/tmp/kcp-mgmt-config-%s.json", safe_id);
    snprintf(path_tmp, sizeof(path_tmp), "/tmp/kcp-mgmt-config-%s.XXXXXX", safe_id);

    /* 原子写入：mkstemp 创建唯一临时文件，fwrite 后 rename 到目标路径。 */
    fd = mkstemp(path_tmp);
    if (fd < 0) {
        LOG_ERROR("config_apply_from_mgmt: mkstemp failed: %s", strerror(errno));
        return -1;
    }
    fp = fdopen(fd, "w");
    if (!fp) {
        LOG_ERROR("config_apply_from_mgmt: fdopen failed: %s", strerror(errno));
        close(fd);
        unlink(path_tmp);
        return -1;
    }

    len = (int)strlen(config_json);
    if (fwrite(config_json, 1, (size_t)len, fp) != (size_t)len) {
        LOG_ERROR("config_apply_from_mgmt: write failed to %s", path_tmp);
        fclose(fp);
        unlink(path_tmp);
        return -1;
    }
    if (fclose(fp) != 0) {
        LOG_ERROR("config_apply_from_mgmt: close failed: %s", strerror(errno));
        unlink(path_tmp);
        return -1;
    }
    if (rename(path_tmp, path) != 0) {
        LOG_ERROR("config_apply_from_mgmt: rename %s → %s failed: %s",
                  path_tmp, path, strerror(errno));
        unlink(path_tmp);
        return -1;
    }

    LOG_INFO("config_apply_from_mgmt: written %d bytes to %s, applying reload", len, path);
    return config_reload(ctx, path);
}

/* ──────────────────────────────────────────────────────────────────────────
 * channel_ctl_del — O(1) 删除 listener 通道
 *
 * 快速删除流程：
 *   1. channel_find() 查找通道（O(1) 哈希查找）
 *   2. 检查是否为 STATIC_LISTENER（非 listener 不可通过 ctl 删除）
 *   3. proxy_stop_listen() 关闭监听套接字（保留动态子通道）
 *   4. 清除 CH_FLAG_STATIC_LISTENER
 *   5. channel_destroy() 销毁通道（释放 KCP、哈希表条目）
 *   6. 在 channels[] 数组中标记 enabled=0
 *
 * 注意：本函数只关闭 listener 自身，不影响其动态子通道。
 *       子通道由 channel_timeout_check() 按超时自动回收。
 * ────────────────────────────────────────────────────────────────────────── */
static int channel_ctl_del(global_ctx_t *ctx, uint32_t channel_id)
{
    /* ── O(1) 快速删除 listener 通道 ──
     *
     * 本函数只关闭 listener 自身的监听套接字，不影响其动态子通道。
     * 子通道由 channel_timeout_check() 按超时自动回收。
     *
     * 删除流程:
     *   1. O(1) 哈希查找通道
     *   2. 验证是 STATIC_LISTENER（拒绝删除动态子通道或不存在通道）
     *   3. 关闭代理监听套接字（释放端口）
     *   4. 清除 STATIC_LISTENER 标志
     *   5. 销毁通道（释放 KCP + 哈希表条目）
     *   6. 在 channels[] 中标记 enabled=0（保留索引稳定） */

    /* O(1) 哈希查找 */
    channel_t *ch = channel_find(ctx, channel_id);
    if (!ch || !(ch->flags & CH_FLAG_STATIC_LISTENER)) {
        LOG_ERROR("ctl_del: listener %u not found", channel_id);
        return -1;
    }
    if (ch->flags & CH_FLAG_MGMT_CHANNEL) {
        LOG_ERROR("ctl_del: refusing to delete management channel %u", channel_id);
        return -1;
    }

    /* 停止代理监听（关闭 TCP/UDP 监听套接字，释放端口） */
    proxy_stop_listen(ctx, ch);

    /* 清除 listener 标志 + 销毁通道 */
    ch->flags &= ~CH_FLAG_STATIC_LISTENER;
    channel_destroy(ctx, ch);

    /* 在 channels[] 数组中标记为禁用（保留条目以维护索引稳定） */
    for (int i = 0; i < ctx->config.channel_count; i++) {
        if (ctx->config.channels[i].channel_id == channel_id) {
            ctx->config.channels[i].enabled = 0;
            break;
        }
    }

    /* ── 惰性墓碑压缩：当失效条目超过一半时，原地压缩数组 ──
     *
     * 压缩流程（等价于 config_reload 的 channels[] 重建，但更轻量）:
     *   1. 统计 live 条目数，compress_threshold = channel_count / 2
     *   2. 如果 enabled=0 条目 > live 条目，触发压缩
     *   3. 双指针原地压缩：dst 指针指向目标位置，src 扫描所有条目，
     *      enabled=1 → 拷贝到 dst，dst++；enabled=0 → 跳过
     *   4. channel_count = live_count（收缩）
     *   5. 遍历哈希表更新所有 STATIC_LISTENER 的 listener_idx（查找新索引）
     *   6. build_listener_bases() 重建 ID 池 */
    {
        int live = 0;
        for (int i = 0; i < ctx->config.channel_count; i++)
            if (ctx->config.channels[i].enabled) live++;

        int dead = ctx->config.channel_count - live;
        if (dead > live) {
            /* 原地压缩 */
            int dst = 0;
            for (int src = 0; src < ctx->config.channel_count; src++) {
                if (ctx->config.channels[src].enabled)
                    ctx->config.channels[dst++] = ctx->config.channels[src];
            }

            int old_count = ctx->config.channel_count;
            ctx->config.channel_count = live;

            /* 同步更新所有 STATION_LISTENER 通道的 listener_idx:
             *   遍历哈希表，对每个 STATION_LISTENER 通道，在压缩后的
             *   channels[] 中按 channel_id 查找新索引 */
            for (uint32_t h = 0; h < ctx->channel_hash_size; h++) {
                channel_t *c = ctx->channel_hash[h];
                while (c) {
                    if (c->flags & CH_FLAG_STATIC_LISTENER) {
                        for (int k = 0; k < live; k++) {
                            if (ctx->config.channels[k].channel_id == c->channel_id) {
                                c->listener_idx = (uint16_t)k;
                                break;
                            }
                        }
                    }
                    c = c->hash_next;
                }
            }

            build_listener_bases(ctx);
            LOG_INFO("ctl: compacted channels array (%d→%d, %d tombstones removed)",
                     old_count, live, dead);
        }
    }

    LOG_INFO("ctl: channel %u removed", channel_id);
    return 0;
}

static void handle_channel_ctl(global_ctx_t *ctx)
{
    /* 注：ctl_path 派生自 config_path，未做 realpath 规范化；
     * 需管理员确保 config_path 安全（非符号链接、非受控目录）。 */
    char ctl_path[512];
    size_t len = strnlen(ctx->config_path, sizeof(ctx->config_path) - 1);
    if (len > 5 && strcmp(ctx->config_path + len - 5, ".json") == 0) {
        snprintf(ctl_path, sizeof(ctl_path), "%.*s-ctl.json", (int)(len - 5), ctx->config_path);
    } else {
        snprintf(ctl_path, sizeof(ctl_path), "%s-ctl.json", ctx->config_path);
    }

    json_object *root = json_object_from_file(ctl_path);
    if (!root) return;

    int added, deleted, errors;
    ctl_execute_json(ctx, root, &added, &deleted, &errors);
    json_object_put(root);

    /* 清空控制文件（幂等处理）。
     * 先 unlink 再 fopen("w") 避免 TOCTOU 竞争：
     * 若攻击者将 ctl_path 替换为符号链接，fopen("w") 可能
     * 写入任意文件。unlink 确保仅删除我们自己的文件。 */
    unlink(ctl_path);
    FILE *f = fopen(ctl_path, "w");
    if (f) fclose(f);
}

/* ---- 通道热重载 ---- */

/* ──────────────────────────────────────────────────────────────────────────
 * main — 程序入口，13 步启动序列
 *
 *   1. 命令行参数解析 (-v/-h/<config.json>)
 *   2. 初始化全局上下文 (memset, raw_sock=-1, epoll_fd=-1, running=1)
 *   3. config_load() — 解析 JSON 配置文件
 *   4. validate_config() — 配置合法性校验
 *   4b. crypto_init() — SM4/SM3 加密模块初始化（若启用）
 *   5. setup_signals() — 安装 SIGHUP/SIGUSR1/SIGINT/SIGTERM/SIGPIPE
 *   6. proxy_init() — 创建 epoll 实例 (EPOLL_CLOEXEC)
 *   7. channel_init() — 分配哈希表 (max_channels*2 个桶)
 *      build_listener_bases() — 构建动态 ID 池基址
 *   8. af_packet_create() — AF_PACKET 原始套接字 (TPACKET_V2)
 *   9. af_packet_get_mac() — 自动获取本地 MAC（若未配置）
 *   10. 对端 MAC 确定（未配置→广播地址 FF:FF:FF:FF:FF:FF，启动自动学习）
 *   11. af_packet_set_mtu() — 自动设置 NIC MTU（可选）
 *   12. af_packet_set_bpf() — BPF 内核级 EtherType 过滤
 *   13. 遍历 channels[] → channel_create() + proxy_start_listen()
 *
 *   14. proxy_epoll_add(raw_sock) — AF_PACKET 加入 epoll
 *   15. 初始化时间基准 (kcp_wrap_clock, time)
 *   16. 主事件循环
 *   17. cleanup() — 优雅关闭
 * ────────────────────────────────────────────────────────────────────────── */
#ifndef TEST_BUILD
int main(int argc, char *argv[])
{
    const char *config_path = NULL;
    int         master_mode = 0;

    /* ── 命令行参数解析 ── */
    {
        int opt;
        static struct option long_opts[] = {
            {"version", no_argument, 0, 'v'},
            {"help",    no_argument, 0, 'h'},
            {"master",  no_argument, 0, 'M'},
            {0, 0, 0, 0}
        };

        while ((opt = getopt_long(argc, argv, "vh", long_opts, NULL)) != -1) {
            switch (opt) {
            case 'v':
                print_version();
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'M':
                master_mode = 1;
                break;
            default:
                print_usage(argv[0]);
                return 1;
            }
        }

        if (optind < argc) {
            config_path = argv[optind];
        } else {
            LOG_ERROR("Config file path is required");
            print_usage(argv[0]);
            return 1;
        }
    }

    /* ── 路由 ── */
    if (master_mode) {
        return master_main(config_path);
    }

    /* ── Standalone 模式（向后兼容） ── */
    global_config_t config;
    memset(&config, 0, sizeof(config));

    if (config_load(config_path, &config) != 0) {
        LOG_ERROR("Failed to load config from %s", config_path);
        return 1;
    }

    int rc = worker_run(&config, config_path);
    return rc;
}
#endif /* !TEST_BUILD */
