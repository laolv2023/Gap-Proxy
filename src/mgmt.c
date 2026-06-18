/*
 * mgmt.c — 集群管理模块
 *
 * ============================================================================
 * 架构概述
 * ============================================================================
 * 管理模块实现一个轻量级集中式管理协议，通过专用管理通道（channel_id=0）在
 * Manager ↔ Worker 之间传输 JSON 格式的控制消息。
 *
 * 角色模型：
 *   Manager — 集群中心节点，拥有全局配置。接收 Worker 注册，分发配置，定期
 *             健康检查。所有 Worker 共享同一个管理通道。
 *   Worker  — 执行节点。启动时向 Manager 注册，接收配置推送，响应健康检查。
 *   None    — 传统模式（向后兼容），管理模块完全闲置。
 *
 * 管理协议消息类型（全部以 JSON lines 格式，由 '\n' 分隔）：
 *   ┌──────────────────┬──────────┬──────────────────────────────────────┐
 *   │ 消息类型          │ 方向      │ 说明                                  │
 *   ├──────────────────┼──────────┼──────────────────────────────────────┤
 *   │ NODE_REGISTER     │ W → M   │ Worker 注册，含 node_id/version      │
 *   │ NODE_REGISTER_ACK │ M → W   │ Manager 确认注册                      │
 *   │ CONFIG_PUSH       │ M → W   │ Manager 推送 channels 配置            │
 *   │ CONFIG_ACK        │ W → M   │ Worker 确认配置已应用                  │
 *   │ HEALTH_CHECK      │ M → W   │ Manager 定期发送存活探测               │
 *   │ HEALTH_RESP       │ W → M   │ Worker 响应健康检查，含通道统计         │
 *   │ SPAWN_INSTANCE    │ M → W   │ Manager 下发 SPAWN 指令                │
 *   │ SPAWN_ACK         │ W → M   │ Worker 回复 SPAWN 结果                 │
 *   │ KILL_INSTANCE     │ M → W   │ Manager 下发 KILL 指令                 │
 *   │ KILL_ACK          │ W → M   │ Worker 回复 KILL 结果                  │
 *   │ CONFIG_SWITCH     │ M → W   │ Manager 下发配置切换指令                │
 *   │ SWITCH_ACK        │ W → M   │ Worker 回复切换结果                    │
 *   └──────────────────┴──────────┴──────────────────────────────────────┘
 *
 * 注意：CONFIG_SWITCH 改变的是 Worker 侧 master 进程的部署拓扑
 * （kcp-multi.json），与 CONFIG_PUSH 推送的 KCP 通道配置正交。
 * Worker 重启后自动重新注册并接收 Manager 的通道配置推送。
 *
 * 数据流：
 *   Manager 侧: config_reload() → config_version++ → mgmt_push_config_to_all()
 *               → 序列化 channels[] 为 JSON → channel_send_data(ch_id=0)
    off = snprintf(msg, MGMT_MSG_MAX_LEN,
        "%s,\"config\":{\"channels\":[", prefix);
    if (off < 0 || off >= MGMT_MSG_MAX_LEN) { free(msg); return; }
 *
 * 资源模型：
 *   — 管理通道 (ch_id=0) 在 mgmt_init() 中创建，mgmt_shutdown() 中销毁。
 *   — Worker 注册表存储在 ctx->mgmt.workers[]（定长数组，最多 64 个）。
 *   — 消息解析为简单字符串扫描（无 json-c 依赖），适合嵌入式部署。
 *   — 每条入站/出站 JSON 消息以 \n 结束，兼容 line-delimited JSON 流。
 *
 * 安全注意事项：
 *   — 地址字段（remote_addr/listen_addr）通过 mgmt_escape_json() 转义，
 *     防止 JSON 注入破坏 CONFIG_PUSH 消息格式。
 *   — mgmt_dispatch() 使用堆分配替代 64KB 栈帧，避免栈溢出。
 *   — 消息长度硬限制为 65536 字节（MGMT_MSG_MAX_LEN）。
 * ============================================================================
 */

#include "types.h"
#include "channel.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <json-c/json.h>

/* 外部函数: mgmt_handle_channel_ctl 会调用 ctl_execute_json
 * 该函数定义在 main.c 中，最初为 static，现已导出为全局符号
 * 用于管理通道远程通道增删操作 */
extern int ctl_execute_json(global_ctx_t *ctx, json_object *root,
                            int *added, int *deleted, int *errors);

/* forward: 在 mgmt_handle_register_ack 中触发 INSTANCE_SYNC */
void mgmt_request_instance_sync(global_ctx_t *ctx);

/* 前向声明 */
static void bytes_to_hex(const uint8_t *in, int in_len, char *out);
static int  hex_to_bytes(const char *hex, uint8_t *out, int out_len);
static void mgmt_handle_instance_sync_req(global_ctx_t *ctx, const char *msg);
static void mgmt_handle_instance_sync_resp(global_ctx_t *ctx, const char *msg);
void mgmt_persist_dynamic_instances(global_ctx_t *ctx);

/* ── 常量 ────────────────────────────────────────────────────── */
#ifndef VERSION
#define VERSION             "1.0.0"
#endif

/* ── 内部常量 ────────────────────────────────────────────────────── */

/* 管理消息最大长度限制。超过此值的消息被静默丢弃。
 * 65536 = 64KB 为典型配置 JSON 压缩后的上限，覆盖数百个 channel 配置。 */
#define MGMT_MSG_MAX_LEN    65536

/* ============================================================================
 * 内部辅助函数 — 消息发送与 Worker 查找
 * ============================================================================ */

/*
 * mgmt_send_raw — 将原始 JSON 字符串发送到管理通道
 *
 * 调用时机：所有管理协议消息（注册、配置推送、健康检查等）最终都通过此函
 * 数将序列化后的 JSON 写入 KCP 管理通道。
 *
 * @param ctx  全局上下文，用于访问 ctx->mgmt.mgmt_channel
 * @param json 已序列化的 JSON 字符串（不含尾零也可，以 len 为准）
 * @param len  消息字节长度
 * @return     成功返回发送字节数，管理通道未建立返回 -1
 *
 * 注意：调用方负责确保 json 指向有效内存、len 不超过 MGMT_MSG_MAX_LEN。
 */
static int mgmt_send_raw(global_ctx_t *ctx, const char *json, int len)
{
    if (!ctx->mgmt.mgmt_channel) return -1;

    /* HMAC 签名：若配置了 shared_secret 且加密已启用，对整个消息体计算 HMAC-SM3 */
    if (ctx->config.management.shared_secret[0] != '\0' && crypto_is_enabled()) {
        char *signed_msg = (char *)malloc((size_t)len + 80);
        if (!signed_msg) return -1;
        memcpy(signed_msg, json, (size_t)len);

        /* 计算 HMAC(shared_secret + message) */
        uint8_t hmac[32];
        char hmac_hex[65];
        /* M3: shared_secret 的 strlen 已缓存在 secret_len 中，避免循环中重复计算。
         * 后续所有引用均使用 secret_len 而非重复调用 strlen。 */
        const int secret_len = (int)strlen(ctx->config.management.shared_secret);
        int auth_len = secret_len + len;
        char *auth_buf = (char *)malloc((size_t)auth_len + 1);
        if (!auth_buf) { free(signed_msg); return -1; }
        memcpy(auth_buf, ctx->config.management.shared_secret,
               (size_t)secret_len);
        memcpy(auth_buf + secret_len,
               json, (size_t)len);
        auth_buf[auth_len] = '\0';

        if (crypto_hmac_sign((const uint8_t *)auth_buf, auth_len, hmac) != 0) {
            /* 审计修复 C4: free 前擦除含 shared_secret 的堆缓冲区 */
            memset(auth_buf, 0, (size_t)auth_len);
            __asm__ __volatile__("" : : "r"(auth_buf) : "memory");
            free(auth_buf); free(signed_msg); return -1;
        }
        /* 审计修复 C4: free 前擦除含 shared_secret 的堆缓冲区 */
        memset(auth_buf, 0, (size_t)auth_len);
        __asm__ __volatile__("" : : "r"(auth_buf) : "memory");
        free(auth_buf);
        bytes_to_hex(hmac, 32, hmac_hex);

        /* 将 "}\n" 替换为 ,"auth":"<hex>"}\n */
        if (len >= 2 && json[len - 2] == '}' && json[len - 1] == '\n')
            len -= 2;
        len += snprintf(signed_msg + len, 80, ",\"auth\":\"%s\"}\n", hmac_hex);

        int ret = channel_send_data(ctx->mgmt.mgmt_channel,
                                     (const uint8_t *)signed_msg, (size_t)len);
        free(signed_msg);
        return ret;
    }

    return channel_send_data(ctx->mgmt.mgmt_channel,
                             (const uint8_t *)json, (size_t)len);
}

/*
 * mgmt_find_worker — 在 Worker 注册表中按 node_id 查找
 *
 * 时间复杂度 O(n)，n 最大为 MGMT_MAX_WORKERS(64)。
 * 当前实现为线性扫描；在 64 个 Worker 下开销可忽略。
 *
 * @param ctx     全局上下文
 * @param node_id 要查找的节点标识符（null-terminated）
 * @return        找到返回 Worker 记录指针，未找到返回 NULL
 *
 * 安全：node_id 不可为 NULL；调用方已在 mgmt_handle_register /
 *       mgmt_handle_health_resp 中验证参数。
 */
static mgmt_worker_t *mgmt_find_worker(global_ctx_t *ctx, const char *node_id)
{
    for (int i = 0; i < ctx->mgmt.worker_count; i++) {
        if (strcmp(ctx->mgmt.workers[i].node_id, node_id) == 0)
            return &ctx->mgmt.workers[i];
    }
    return NULL;
}

/* 查找或预分配 Worker 条目（用于持久化恢复时 Worker 可能还未注册） */
static mgmt_worker_t *mgmt_find_or_create_worker(global_ctx_t *ctx, const char *node_id)
{
    mgmt_worker_t *w = mgmt_find_worker(ctx, node_id);
    if (w) return w;
    if (ctx->mgmt.worker_count >= MGMT_MAX_WORKERS) return NULL;
    int idx = ctx->mgmt.worker_count++;
    memset(&ctx->mgmt.workers[idx], 0, sizeof(mgmt_worker_t));
    strncpy(ctx->mgmt.workers[idx].node_id, node_id, 64);
    ctx->mgmt.workers[idx].state = 0; /* JOINING */
    return &ctx->mgmt.workers[idx];
}

/*
 * mgmt_build_prefix — 构建管理消息的 JSON 公共头部
 *
 * 所有管理消息都以以下固定字段开始：
 *   {"type":"<消息类型>","seq":<序号>,"ts":<时间戳>,"node_id":"<节点ID>"
 *
 * 其中 seq 由 ctx->mgmt.mgmt_seq 自增（uint32_t，约 42 亿后回绕），
 * ts 由 time_now() 获取。
 *
 * @param buf   输出缓冲区
 * @param size  缓冲区大小（字节）
 * @param type  消息类型字符串（如 "NODE_REGISTER"）
 * @param ctx   全局上下文
 * @return      写入的字节数（不含尾零）；若 snprintf 截断则返回值 ≥ size
 *
 * 调用方惯例：所有调用方均使用 buf[256] ~ buf[512] 的栈缓冲区，
 * sizeof(buf) 远大于前缀的典型长度（~60 字节），因此截断风险极低。
 */
static int mgmt_build_prefix(char *buf, size_t size, const char *type,
                              global_ctx_t *ctx)
{
    return snprintf(buf, size,
        "{\"type\":\"%s\",\"seq\":%llu,\"ts\":%u,\"node_id\":\"%s\"",
        type, (unsigned long long)++ctx->mgmt.mgmt_seq, time_now(),
        ctx->config.node.node_id);
}

/*
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ hex 编解码辅助函数（T11-2: HMAC 认证）                               │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │ hex_to_bytes  — 将十六进制字符串转换为字节数组（用于解码 auth 字段）   │
 * │ bytes_to_hex  — 将字节数组转换为十六进制字符串（用于编码 HMAC 输出）   │
 * │                                                                      │
 * │ 安全注意：                                                            │
 * │  — hex_to_bytes 要求输入长度为 out_len*2，否则返回 0（拒绝截断攻击）   │
 * │  — sscanf 格式 %2x 每次读 2 个十六进制字符，无缓冲区溢出风险            │
 * │  — bytes_to_hex 的 out 缓冲区由调用方保证大小为 in_len*2+1             │
 * └──────────────────────────────────────────────────────────────────────┘
 */
static int hex_to_bytes(const char *hex, uint8_t *out, int out_len)
{
    if (!hex || !out) return 0;
    int len = (int)strlen(hex);
    if (len != out_len * 2) return 0;
    for (int i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return 0;
        out[i] = (uint8_t)byte;
    }
    return 1;
}

static void bytes_to_hex(const uint8_t *in, int in_len, char *out)
{
    for (int i = 0; i < in_len; i++)
        sprintf(out + i * 2, "%02x", in[i]);
    out[in_len * 2] = '\0';
}

/*
 * mgmt_send_register — Worker 向 Manager 发送注册请求
 *
 * 调用时机：mgmt_init() 完成管理通道创建后，worker 角色自动调用。
 * 消息格式：{"type":"NODE_REGISTER","seq":N,"ts":N,"node_id":"X",
 *            "version":"1.0.0","uptime_seconds":0}\n
 */
static void mgmt_send_register(global_ctx_t *ctx)
{
    char buf[512];
    int off = mgmt_build_prefix(buf, sizeof(buf), "NODE_REGISTER", ctx);
    off += snprintf(buf + off, sizeof(buf) - off,
        ",\"version\":\"%s\",\"uptime_seconds\":0", VERSION);

    off += snprintf(buf + off, sizeof(buf) - off, "}\n");
    if (mgmt_send_raw(ctx, buf, off) < 0)
        LOG_WARN("mgmt_send_register: NODE_REGISTER send failed");
}

/*
 * mgmt_send_register_ack — Manager 向 Worker 确认注册
 *
 * 调用时机：mgmt_handle_register() 将 Worker 加入注册表后立即调用。
 * 消息格式：{"type":"NODE_REGISTER_ACK","seq":N,...,"status":"ok",...}\n
 *
 * 当前实现为无状态 ACK（不携带 ref_seq），因为 Manager 侧消息处理是同步的。
 */
static void mgmt_send_register_ack(global_ctx_t *ctx)
{
    char buf[256];
    int off = mgmt_build_prefix(buf, sizeof(buf), "NODE_REGISTER_ACK", ctx);
    off += snprintf(buf + off, sizeof(buf) - off,
        ",\"status\":\"ok\",\"manager_version\":\"%s\"}\n", VERSION);
    mgmt_send_raw(ctx, buf, off);
}

/* ============================================================================
 * JSON 字段解析 — 轻量级字符串扫描器
 * ============================================================================
 *
 * 设计理由：避免引入 libjson-c 依赖，降低二进制尺寸和部署复杂度。
 * 解析器基于 strstr / strchr / strtol 的字符串扫描，仅支持单层、单行 JSON。
 *
 * 约束：
 *   — 仅解析 "field":"value" 和 "field":123 格式，不支持嵌套对象。
 *   — 字段名区分大小写，与 JSON 标准一致。
 *   — value 字符串不支持转义序列（如 \n、\uXXXX）。对于管理协议足够。
 * ============================================================================
 */

/*
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ 轻量级 JSON 解析器 — 三个核心函数                                    │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │ mgmt_parse_type(msg, type_out, size)                                 │
 * │   提取 "type":"..." 字段值，用于 mgmt_dispatch 消息路由。            │
 * │                                                                      │
 * │ mgmt_parse_int(msg, field, val)                                      │
 * │   提取 "field":N 整数字段值。双重安全校验：                           │
 * │     ① 首字符必须是数字或负号（拒绝 "field": 后跟 } ] " 等）          │
 * │     ② strtol 必须消费字符（end != p）                                │
 * │   修复了原始代码无条件返回成功的审计缺陷（S1）。                      │
 * │                                                                      │
 * │ mgmt_parse_str(msg, field, val, size)                                │
 * │   提取 "field":"..." 字符串字段值。自动截断超过 size-1 的值。        │
 * │   注意：不支持 \" 转义序列（管理协议无需此功能）。                   │
 * │                                                                      │
 * │ 设计取舍：使用 strstr/strchr/strtol 字符串扫描替代 libjson-c，       │
 * │ 降低二进制尺寸和部署复杂度，适合嵌入式场景。                          │
 * └──────────────────────────────────────────────────────────────────────┘
 */

/*
 * mgmt_parse_type — 提取 JSON 消息中的 type 字段值
 *
 * 扫描模式：\"type\":\"...\"，提取引号内的字符串。
 * 这是 mgmt_dispatch() 调用的第一个解析函数，用于确定消息路由。
 *
 * @param msg      单行 JSON 消息字符串
 * @param type_out 输出缓冲区（接收 type 值）
 * @param size     type_out 的大小（字节）
 * @return         成功返回 0，失败返回 -1（无 type 字段 或 值过长）
 */
static int mgmt_parse_type(const char *msg, char *type_out, size_t size)
{
    /* 定位 "type":" 的起始位置 */
    const char *p = strstr(msg, "\"type\":\"");
    if (!p) return -1;
    p += 8;  /* 跳过 "type":" 共 8 个字符 */

    /* 查找闭合引号 */
    const char *end = strchr(p, '"');
    if (!end || (size_t)(end - p) >= size) return -1;

    /* 复制 type 值并以 \0 终止 */
    memcpy(type_out, p, end - p);
    type_out[end - p] = '\0';
    return 0;
}

/*
 * mgmt_parse_int — 提取 JSON 消息中的整数字段值
 *
 * 扫描模式：\"field\":N，其中 N 为可选负号的十进制整数。
 * 使用 strtol() 进行转换，并验证：
 *   1. 值以数字或负号开头（拒绝空值、字符串等）
 *   2. strtol 的 end 指针前进（拒绝纯空白/非数字）
 *
 * @param msg   单行 JSON 消息字符串
 * @param field 字段名
 * @param val   输出：解析后的整数值
 * @return      成功返回 0，失败返回 -1
 */
static int mgmt_parse_int(const char *msg, const char *field, int *val)
{
    char key[64];
    snprintf(key, sizeof(key), "\"%s\":", field);
    const char *p = strstr(msg, key);
    if (!p) return -1;
    p += strlen(key);

    /* ── 安全校验 1：首字符必须是数字或负号 ──
     * 拒绝 "field": 后跟随 } ] " 等非数值字符的情况。
     * 此检查是审计 S1 修复的产物（原代码无条件返回成功）。 */
    if (*p != '-' && (*p < '0' || *p > '9')) return -1;

    char *end;
    *val = (int)strtol(p, &end, 10);

    /* ── 安全校验 2：strtol 必须消费了字符 ──
     * 当 p 指向空字符串或纯空白时，end == p。 */
    if (end == p) return -1;
    return 0;
}

/*
 * mgmt_parse_str — 提取 JSON 消息中的字符串字段值
 *
 * 扫描模式：\"field\":\"...\"，提取引号内的字符串。
 * 自动截断超过 size-1 的值（确保 \0 终止）。
 *
 * @param msg   单行 JSON 消息字符串
 * @param field 字段名
 * @param val   输出缓冲区
 * @param size  val 的大小（字节）
 * @return      成功返回 0，失败返回 -1
 */
static int mgmt_parse_str(const char *msg, const char *field,
                           char *val, size_t size)
{
    char key[64];
    snprintf(key, sizeof(key), "\"%s\":\"", field);
    const char *p = strstr(msg, key);
    if (!p) return -1;
    p += strlen(key);  /* 跳过 "field":" 到达值的第一个字符 */

    /* 查找闭合引号 — 注意：此解析器不支持值内部的转义引号 \" */
    const char *end = p;
    while (*end) {
        if (*end == '\\' && end[1]) { end += 2; continue; }
        if (*end == '"') break;
        end++;
    }
    if (!*end) return -1;

    size_t n = (size_t)(end - p);
    if (n >= size) n = size - 1;  /* 截断至缓冲区最大容纳量 */
    memcpy(val, p, n);
    val[n] = '\0';
    return 0;
}

/* ============================================================================
 * JSON 字符串安全转义
 * ============================================================================
 *
 * 用途：在手动构建 JSON 字符串时，对动态值（如用户配置的 IP 地址）进行
 * 转义，防止其中的特殊字符破坏 JSON 结构。
 *
 * 转义规则（RFC 8259 最小集）：
 *   \\ → \\\\
 *   "  → \\"
 * ============================================================================
 */

/*
 * mgmt_escape_json — 转义字符串以安全写入 JSON 双引号内
 *
 * @param buf   输出缓冲区
 * @param size  缓冲区大小（字节）
 * @param src   待转义的源字符串（可为 NULL）
 * @return      写入的字节数（不含尾零）
 */
static int mgmt_escape_json(char *buf, size_t size, const char *src)
{
    size_t pos = 0;
    buf[0] = '\0';
    if (!src) return 0;

    for (const char *s = src; *s && pos + 7 < size; s++) {
        if (*s == '\\' || *s == '"') {
            if (pos + 2 >= size) break;
            buf[pos++] = '\\';
            buf[pos++] = *s;
        } else if ((unsigned char)*s < 0x20) {
            /* 控制字符 → \\u00XX 编码 (RFC 8259) */
            if (pos + 7 >= size) break;
            {
                int n = snprintf(buf + pos, 7, "\\u%04x", (unsigned char)*s);
                if (n < 0 || n >= 7) break;  /* M2: 检查 snprintf 截断/错误 */
                pos += n;
            }
        } else {
            buf[pos++] = *s;
        }
    }
    if (pos < size) buf[pos] = '\0';
    return (int)pos;
}

/* ============================================================================
 * 消息分发 — 按 type 字段路由到具体处理器
 * ============================================================================
 *
 * 消息处理模型：
 *   mgmt_dispatch() 作为统一入口，提取 type 字段后分发。
 *   每个 handle 函数检查本节点角色是否匹配（Manager/Worker）。不匹配则静默
 *   丢弃，避免消息误投到错误角色。
 * ============================================================================
 */

/*
 * mgmt_handle_register — 处理 Worker 的 NODE_REGISTER 请求（Manager 侧）
 *
 * 流程：
 *   1. 解析 node_id → 在注册表中查找
 *   2. 若不存在 → 分配新槽位（检查 MGMT_MAX_WORKERS 上限）
 *   3. 若存在 → 更新状态为 ACTIVE、刷新 last_seen
 *   4. 回复 NODE_REGISTER_ACK
 *   5. 推送最新配置到所有 Worker（包括新注册的节点）
 *
 *   注意：若 Worker 因 CONFIG_SWITCH 重启后重新注册（相同 node_id），
 *   本函数复用已有注册表条目并立即通过 CONFIG_PUSH 下发当前 Manager 侧
 *   通道配置。CONFIG_SWITCH 作用于 master 拓扑层（kcp-multi.json），
 *   通道配置始终以 Manager 的 CONFIG_PUSH 为准——两条控制路径正交，
 *   不会互相覆盖。
 *
 * 安全：仅 NODE_ROLE_MANAGER 执行。Worker 角色收到此消息直接返回。
 */
static void mgmt_handle_register(global_ctx_t *ctx, const char *msg)
{
    /* 角色校验：非 Manager 节点不应处理注册请求 */
    if (ctx->config.node.node_role != NODE_ROLE_MANAGER) return;

    /* HMAC 验证由 mgmt_dispatch 统一完成，此处不再重复验证 */

    /* 提取 node_id（必填字段，缺失则丢弃消息） */
    char node_id[65] = {0};
    if (mgmt_parse_str(msg, "node_id", node_id, sizeof(node_id)) != 0)
        return;

    mgmt_worker_t *w = mgmt_find_worker(ctx, node_id);
    if (!w) {
        /* ── 新 Worker：分配注册表槽位 ── */
        if (ctx->mgmt.worker_count >= MGMT_MAX_WORKERS) {
            LOG_WARN("Worker registry full (%d), rejecting %s",
                     MGMT_MAX_WORKERS, node_id);
            return;
        }
        w = &ctx->mgmt.workers[ctx->mgmt.worker_count++];

        /* 安全拷贝 node_id（截断至 64 字节并确保 \0 终止） */
        size_t n = strlen(node_id);
        if (n >= sizeof(w->node_id)) n = sizeof(w->node_id) - 1;
        memcpy(w->node_id, node_id, n);
        w->node_id[n] = '\0';

        /* 初始化注册元数据 */
        w->channel_id      = 0;           /* Worker 未分配数据通道 ID */
        w->registered_at   = time_now();  /* 注册时间戳（CLOCK_MONOTONIC） */
        w->config_version  = 0;           /* 即将通过 CONFIG_PUSH 更新 */
        w->degraded_since  = 0;
        w->health_resp_count = 0;

        LOG_INFO("Worker registered: %s (total: %d)",
                 node_id, ctx->mgmt.worker_count);
    }

    /* 刷新在线状态（无论是新注册还是重连） */
    w->state     = MGMT_WORKER_STATE_ACTIVE;
    w->last_seen = time_now();
    w->degraded_since = 0;
    w->health_resp_count = 0;

    /*
     * R6-S4: 防重放检测 — 拒绝旧的或重复的 seq
     *
     * 检测逻辑：
     *   从消息中解析 seq 字段 → 与 Worker 记录的最后序列号 (last_seq) 比较。
     *   若 msg_seq > 0 且 msg_seq ≤ last_seq，则判定为重放攻击，拒绝消息。
     *
     * 边界情况：
     *   — msg_seq == 0（未携带 seq 或解析失败）：跳过检测（向后兼容）
     *   — seq 回绕（uint32_t 约 42 亿后归零）：简单比较会误判，但实际运行中
     *     Worker 重启会重置 last_seq，Manager 重启会重新初始化 workers 数组，
     *     因此正常运维场景下不会触发回绕问题。
     *
     * 旁路记录：检测到重放时通过 LOG_AUDIT 写入审计日志。
     */
    {
        int seq_int = 0;
        if (mgmt_parse_int(msg, "seq", &seq_int) != 0) {
            LOG_WARN("NODE_REGISTER from %s: missing seq field, refusing", node_id);
            return;
        }
        uint64_t msg_seq = (uint64_t)(seq_int >= 0 ? seq_int : 0);
        if (msg_seq > 0 && msg_seq <= w->last_seq) {
            LOG_AUDIT("NODE_REGISTER replay detected for %s (seq=%llu <= last=%llu)",
                      node_id, (unsigned long long)msg_seq,
                      (unsigned long long)w->last_seq);
            return;
        }
        w->last_seq = msg_seq;
    }

    /* 回复 ACK + 推送最新配置 */
    mgmt_send_register_ack(ctx);
    mgmt_push_config_to_all(ctx, NULL);
}

/*
 * mgmt_handle_register_ack — 处理 Manager 的注册确认（Worker 侧）
 *
 * 当前为占位实现：仅输出日志。Worker 注册流程是单向的（发送 → 接收 ACK
 * 即完成），无需额外状态转换。
 */
static void mgmt_handle_register_ack(global_ctx_t *ctx, const char *msg)
{
    (void)msg;  /* 当前未解析 ACK 内容 */
    if (ctx->config.node.node_role != NODE_ROLE_WORKER) return;
    ctx->mgmt.worker_registered = 1;
    LOG_INFO("Manager acknowledged registration");

    /* 注册成功后启动 INSTANCE_SYNC：向 Manager 查询已知的动态实例 */
    if (ctx->mgmt.sync_state == INSTANCE_SYNC_IDLE)
        mgmt_request_instance_sync(ctx);
}

/*
 * mgmt_handle_health_check — 处理 Manager 的健康检查（Worker 侧）
 *
 * 返回当前 Worker 的通道统计信息，包含：
 *   — active_channels：当前活跃通道数
 *   — total_channels：配置的总通道数
 *   — state：固定 "ACTIVE"（Worker 处于运行状态即视为健康）
 *
 * 安全：仅 NODE_ROLE_WORKER 执行。
 */
static void mgmt_handle_health_check(global_ctx_t *ctx, const char *msg)
{
    (void)msg;
    if (ctx->config.node.node_role != NODE_ROLE_WORKER) return;

    char resp[384];
    int off = mgmt_build_prefix(resp, sizeof(resp), "HEALTH_RESP", ctx);
    off += snprintf(resp + off, sizeof(resp) - off,
        ",\"active_channels\":%d,\"total_channels\":%d,"
        "\"state\":\"ACTIVE\"}\n",
        ctx->channel_count, ctx->config.channel_count);
    mgmt_send_raw(ctx, resp, off);
}

/*
 * mgmt_handle_health_resp — 处理 Worker 的健康响应（Manager 侧）
 *
 * 收到 Worker 的 HEALTH_RESP 后：
 *   1. 更新 last_seen 时间戳
 *   2. 若 Worker 之前处于 DEGRADED 状态，恢复为 ACTIVE 并记录恢复日志
 *
 * 安全：仅 NODE_ROLE_MANAGER 执行。如果 Worker 不在注册表中则丢弃（可能
 *       是健康检查响应晚于 Worker 超时被清理）。
 */
static void mgmt_handle_health_resp(global_ctx_t *ctx, const char *msg)
{
    if (ctx->config.node.node_role != NODE_ROLE_MANAGER) return;

    char node_id[65] = {0};
    if (mgmt_parse_str(msg, "node_id", node_id, sizeof(node_id)) != 0)
        return;

    mgmt_worker_t *w = mgmt_find_worker(ctx, node_id);
    if (w) {
        w->last_seen = time_now();
        if (w->state == MGMT_WORKER_STATE_DEGRADED) {
            /*
             * 防止 HEALTH_RESP 幽灵回复：Worker 可能在回复后立即崩溃，
             * 单次响应不足以确认存活。要求连续 2 次 HEALTH_RESP
             * （间隔至少一个 keepalive_interval）才恢复为 ACTIVE。
             */
            w->health_resp_count++;
            if (w->health_resp_count >= 2) {
                w->state = MGMT_WORKER_STATE_ACTIVE;
                w->degraded_since = 0;
                w->health_resp_count = 0;
                LOG_INFO("Worker %s recovered (confirmed after %d responses)",
                         node_id, w->health_resp_count);
            }
        } else {
            /* ACTIVE 状态下持续重置计数 */
            w->health_resp_count = 0;
        }
    }
}

/*
 * mgmt_handle_spawn_instance — 处理 Manager 的 SPAWN 指令（Worker 侧）
 *
 * 流程：
 *   1. 从 JSON 消息中提取 payload（含 ethertype、node_type、channels）
 *   2. 写入 /tmp/kcp-spawn.json
 *   3. 发送 SIGUSR1 给父 master 进程
 *   4. 轮询等待 /tmp/kcp-spawn-resp.json
 *   5. 读响应 → 构建 SPAWN_ACK 发回 Manager
 *
 * 安全：仅 NODE_ROLE_WORKER 执行。
 */

/* 发送 SPAWN_ACK 错误响应（Worker → Manager），所有 worker 侧失败路径调用 */
static void mgmt_send_spawn_ack_error(global_ctx_t *ctx, int ref_seq, const char *msg)
{
    char ack[256];
    int off = mgmt_build_prefix(ack, sizeof(ack), "SPAWN_ACK", ctx);
    off += snprintf(ack + off, sizeof(ack) - off,
        ",\"ref_seq\":%d,\"status\":\"error\",\"message\":\"%s\"}\n",
        ref_seq, msg ? msg : "unknown");
    mgmt_send_raw(ctx, ack, off);
}

static void mgmt_handle_spawn_instance(global_ctx_t *ctx, const char *msg)
{
    if (ctx->config.node.node_role != NODE_ROLE_WORKER) return;
    if (ctx->master_pid <= 0) {
        LOG_WARN("SPAWN_INSTANCE: no master_pid (standalone mode?)");
        return;
    }

    /* 提前提取 seq，用于所有错误路径的 ACK */
    int push_seq = 0;
    mgmt_parse_int(msg, "seq", &push_seq);

    /* 仅处理发给本节点的指令 */
    char target[65] = {0};
    if (mgmt_parse_str(msg, "target", target, sizeof(target)) != 0)
        { mgmt_send_spawn_ack_error(ctx, push_seq, "missing target"); return; }
    if (strcmp(target, ctx->config.node.node_id) != 0) return;

    /* 提取 payload：从 "payload":{ 开始用括号计数找到匹配的 } */
    const char *p = strstr(msg, "\"payload\":{");
    if (!p) { mgmt_send_spawn_ack_error(ctx, push_seq, "missing payload"); return; }
    p += 11;
    int depth = 1, in_string = 0;
    const char *end = p;
    while (*end && depth > 0) {
        if (in_string) {
            if (*end == '"' && *(end - 1) != '\\') in_string = 0;
        } else {
            if (*end == '"') in_string = 1;
            else if (*end == '{') depth++;
            else if (*end == '}') depth--;
        }
        end++;
    }
    if (depth != 0) { mgmt_send_spawn_ack_error(ctx, push_seq, "malformed payload"); return; }
    end--;

    /* 写入请求文件 */
    FILE *f = fopen(SPAWN_REQUEST_FILE, "w");
    if (!f) { mgmt_send_spawn_ack_error(ctx, push_seq, "io error"); return; }
    fprintf(f, "{%.*s}\n", (int)(end - p), p);
    fclose(f);

    /* 通知 master */
    kill(ctx->master_pid, SIGUSR1);

    /* 轮询等待 master 响应 */
    char ack[512];
    for (int i = 0; i < SPAWN_WAIT_RETRIES; i++) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = SPAWN_WAIT_US * 1000L };
        while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {}
        FILE *resp = fopen(SPAWN_RESPONSE_FILE, "r");
        if (!resp) continue;
        /* 读第一行即可 */
        char line[256] = {0};
        if (fgets(line, sizeof(line), resp)) {
            unlink(SPAWN_RESPONSE_FILE);
            fclose(resp);
            int off = mgmt_build_prefix(ack, sizeof(ack), "SPAWN_ACK", ctx);
            off += snprintf(ack + off, sizeof(ack) - off,
                ",\"ref_seq\":%d,\"status\":\"ok\",\"detail\":%s}\n",
                push_seq, line);
            mgmt_send_raw(ctx, ack, off);
            return;
        }
        fclose(resp);
    }
    /* 超时：清理响应文件残留，发送错误 ACK */
    unlink(SPAWN_RESPONSE_FILE);
    {
        int off = mgmt_build_prefix(ack, sizeof(ack), "SPAWN_ACK", ctx);
        off += snprintf(ack + off, sizeof(ack) - off,
            ",\"ref_seq\":%d,\"status\":\"error\",\"message\":\"timeout\"}\n", push_seq);
        mgmt_send_raw(ctx, ack, off);
    }
}

/*
 * mgmt_handle_kill_instance — 处理 Manager 的 KILL 指令（Worker 侧）
 *
 * 流程：
 *   1. 从 JSON 消息中提取 ethertype（标识要杀的 worker 实例）
 *   2. 写入 /tmp/kcp-kill.json
 *   3. 发送 SIGUSR2 给父 master 进程
 *   4. 轮询等待 /tmp/kcp-kill-resp.json
 *   5. 读响应 → 构建 KILL_ACK 发回 Manager
 */
static void mgmt_handle_kill_instance(global_ctx_t *ctx, const char *msg)
{
    if (ctx->config.node.node_role != NODE_ROLE_WORKER) return;
    if (ctx->master_pid <= 0) return;

    char target[65] = {0};
    if (mgmt_parse_str(msg, "target", target, sizeof(target)) != 0)
        return;
    if (strcmp(target, ctx->config.node.node_id) != 0) return;

    /* 提取 payload：从 "payload":{ 开始用括号计数找到匹配的 } */
    const char *p = strstr(msg, "\"payload\":{");
    if (!p) return;
    p += 11;  /* 跳过 "payload":{ → 到达 payload 内部 */
    int depth = 1, in_string = 0;
    const char *end = p;
    while (*end && depth > 0) {
        if (in_string) {
            if (*end == '"' && *(end - 1) != '\\') in_string = 0;
        } else {
            if (*end == '"') in_string = 1;
            else if (*end == '{') depth++;
            else if (*end == '}') depth--;
        }
        end++;
    }
    if (depth != 0) return;
    end--;

    /* 写入 kill 请求文件（仅 payload 内容） */
    FILE *f = fopen(KILL_REQUEST_FILE, "w");
    if (!f) return;
    fprintf(f, "{%.*s}\n", (int)(end - p), p);
    fclose(f);

    kill(ctx->master_pid, SIGUSR2);

    int push_seq = 0;
    mgmt_parse_int(msg, "seq", &push_seq);
    char ack[512];
    for (int i = 0; i < SPAWN_WAIT_RETRIES; i++) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = SPAWN_WAIT_US * 1000L };
        while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {}
        FILE *resp = fopen(KILL_RESPONSE_FILE, "r");
        if (!resp) continue;
        char line[256] = {0};
        if (fgets(line, sizeof(line), resp)) {
            unlink(KILL_RESPONSE_FILE);
            fclose(resp);
            int off = mgmt_build_prefix(ack, sizeof(ack), "KILL_ACK", ctx);
            off += snprintf(ack + off, sizeof(ack) - off,
                ",\"ref_seq\":%d,\"status\":\"ok\",\"detail\":%s}\n",
                push_seq, line);
            mgmt_send_raw(ctx, ack, off);
            return;
        }
        fclose(resp);
    }
    /* 超时：清理响应文件残留，发送错误 ACK */
    unlink(KILL_RESPONSE_FILE);
    {
        int off = mgmt_build_prefix(ack, sizeof(ack), "KILL_ACK", ctx);
        off += snprintf(ack + off, sizeof(ack) - off,
            ",\"ref_seq\":%d,\"status\":\"error\",\"message\":\"timeout\"}\n", push_seq);
        mgmt_send_raw(ctx, ack, off);
    }
}

/*
 * mgmt_handle_config_switch — 处理 Manager 的 CONFIG_SWITCH 指令（Worker 侧）
 *
 * 流程（与 SPAWN_INSTANCE 对称）：
 *   1. 提取 payload 中的 config_path
 *   2. 写入 SWITCH_CONFIG_REQUEST_FILE
 *   3. 发送 SIGURG 给父 master 进程
 *   4. 轮询等待 SWITCH_CONFIG_RESPONSE_FILE
 *   5. 读响应 → 构建 SWITCH_ACK 发回 Manager
 */
static void mgmt_handle_config_switch(global_ctx_t *ctx, const char *msg)
{
    if (ctx->config.node.node_role != NODE_ROLE_WORKER) return;
    if (ctx->master_pid <= 0) {
        LOG_WARN("CONFIG_SWITCH: no master_pid (standalone mode?)");
        return;
    }

    char target[65] = {0};
    if (mgmt_parse_str(msg, "target", target, sizeof(target)) != 0) return;
    if (strcmp(target, ctx->config.node.node_id) != 0) return;

    const char *p = strstr(msg, "\"payload\":{");
    if (!p) return;
    p += 11;
    int depth = 1, in_string = 0;
    const char *end = p;
    while (*end && depth > 0) {
        if (in_string) {
            if (*end == '"' && *(end - 1) != '\\') in_string = 0;
        } else {
            if (*end == '"') in_string = 1;
            else if (*end == '{') depth++;
            else if (*end == '}') depth--;
        }
        end++;
    }
    if (depth != 0) return;
    end--;

    FILE *f = fopen(SWITCH_CONFIG_REQUEST_FILE, "w");
    if (!f) return;
    fprintf(f, "{%.*s}\n", (int)(end - p), p);
    fclose(f);

    kill(ctx->master_pid, SIGURG);

    int push_seq = 0;
    mgmt_parse_int(msg, "seq", &push_seq);
    char ack[512];
    for (int i = 0; i < SPAWN_WAIT_RETRIES; i++) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = SPAWN_WAIT_US * 1000L };
        while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {}
        FILE *resp = fopen(SWITCH_CONFIG_RESPONSE_FILE, "r");
        if (!resp) continue;
        char line[256] = {0};
        if (fgets(line, sizeof(line), resp)) {
            unlink(SWITCH_CONFIG_RESPONSE_FILE);
            fclose(resp);
            /* 去除尾随换行符 */
            size_t llen = strlen(line);
            while (llen > 0 && (line[llen-1] == '\n' || line[llen-1] == '\r'))
                line[--llen] = '\0';
            /* 提取 status 和 skipped 用于 ACK 状态报告 */
            char status[16] = {0};
            int skipped = -1;
            mgmt_parse_str(line, "status", status, sizeof(status));
            mgmt_parse_int(line, "skipped", &skipped);
            /*
             * R9-X2: skipped > 0 告警
             *
             * 当 master 进程返回的响应中 skipped > 0 时，意味着 CONFIG_SWITCH
             * 操作中部分实例的配置被跳过（可能是因为 node_id 不匹配、配置无效等）。
             *
             * 处理策略：
             *   — 仍然发送 SWITCH_ACK（携带 skipped 计数），告知 Manager
             *     切换操作已部分完成
             *   — 通过 LOG_WARN 记录告警，便于运维人员排查被跳过的实例
             *   — 不重试：重试策略由 Manager 在上层决定
             */
            if (skipped > 0) {
                LOG_WARN("CONFIG_SWITCH: %d instance(s) skipped — possible config error", skipped);
            }
            int off = mgmt_build_prefix(ack, sizeof(ack), "SWITCH_ACK", ctx);
            off += snprintf(ack + off, sizeof(ack) - off,
                ",\"ref_seq\":%d,\"status\":\"%s\",\"skipped\":%d,\"detail\":%s}\n",
                push_seq, status[0] ? status : "unknown", skipped, line);
            mgmt_send_raw(ctx, ack, off);
            return;
        }
        fclose(resp);
    }
    /* 超时：清理响应文件残留，发送错误 ACK */
    unlink(SWITCH_CONFIG_RESPONSE_FILE);
    {
        int off = mgmt_build_prefix(ack, sizeof(ack), "SWITCH_ACK", ctx);
        off += snprintf(ack + off, sizeof(ack) - off,
            ",\"ref_seq\":%d,\"status\":\"error\",\"message\":\"timeout\"}\n", push_seq);
        mgmt_send_raw(ctx, ack, off);
    }
}

/* ============================================================================
 * Worker→Manager ACK 处理器（Manager 侧）
 * ============================================================================
 *
 * 以下 4 个 handler 处理 Worker 发回的确认消息。所有 ACK 共享同一模式：
 *   1. 提取 node_id → 在注册表中定位 Worker
 *   2. 刷新 last_seen（心跳等效）
 *   3. 记录日志（含 ref_seq 和 status 用于运维排障）
 *   4. 若 status=error，记录 WARN 级别日志
 *
 * 注：v1.0 不实现重试/回滚，仅记录状态供外部监控系统消费。
 * ============================================================================
 */

/*
 * mgmt_handle_ack_common — 通用 ACK 处理核心
 *
 * @param ctx     全局上下文
 * @param msg     JSON 消息
 * @param ack_type 人类可读的 ACK 类型名（用于日志）
 */
static void mgmt_handle_ack_common(global_ctx_t *ctx, const char *msg,
                                   const char *ack_type)
{
    if (ctx->config.node.node_role != NODE_ROLE_MANAGER) return;

    char node_id[65] = {0};
    if (mgmt_parse_str(msg, "node_id", node_id, sizeof(node_id)) != 0)
        return;

    mgmt_worker_t *w = mgmt_find_worker(ctx, node_id);
    if (!w) {
        LOG_WARN("%s from unknown worker %s (ignored)", ack_type, node_id);
        return;
    }

    /* ACK 等同于心跳：刷新 last_seen */
    w->last_seen = time_now();

    /* 解析 ref_seq 和 status */
    int ref_seq = -1;
    mgmt_parse_int(msg, "ref_seq", &ref_seq);

    char status[16] = {0};
    mgmt_parse_str(msg, "status", status, sizeof(status));

    if (strcmp(status, "ok") == 0) {
        LOG_INFO("%s from %s OK (ref_seq=%d)", ack_type, node_id, ref_seq);

        /* CONFIG_ACK: 更新 Worker 的 config_version */
        if (strcmp(ack_type, "CONFIG_ACK") == 0) {
            uint64_t ver = 0;
            char vbuf[32];
            if (mgmt_parse_str(msg, "version", vbuf, sizeof(vbuf)) == 0)
                ver = (uint64_t)strtoull(vbuf, NULL, 10);
            if (ver > 0) w->config_version = ver;
        }
    } else {
        char detail[128] = {0};
        mgmt_parse_str(msg, "message", detail, sizeof(detail));
        if (detail[0] == '\0')
            mgmt_parse_str(msg, "detail", detail, sizeof(detail));
        LOG_WARN("%s from %s FAILED (ref_seq=%d, reason=%s)",
                 ack_type, node_id, ref_seq,
                 detail[0] ? detail : "unknown");
    }
}

static void mgmt_handle_config_ack(global_ctx_t *ctx, const char *msg)
    { mgmt_handle_ack_common(ctx, msg, "CONFIG_ACK"); }

/* ============================================================================
 * Pending 操作管理 — Manager 侧跟踪批次操作（如 batch SPAWN）
 * ============================================================================ */

/* 查找空闲 pending_op 槽位 */
static pending_op_t *mgmt_pending_alloc(global_ctx_t *ctx)
{
    for (int i = 0; i < PENDING_OP_MAX; i++) {
        if (!ctx->mgmt.pending_ops[i].active) {
            memset(&ctx->mgmt.pending_ops[i], 0, sizeof(pending_op_t));
            ctx->mgmt.pending_ops[i].op_id = i;
            ctx->mgmt.pending_ops[i].active = 1;
            return &ctx->mgmt.pending_ops[i];
        }
    }
    return NULL;
}

/* 注册批次 SPAWN — 返回 op_id，-1 表示槽位已满 */
int mgmt_pending_register_spawn(global_ctx_t *ctx, const char *targets[],
                                 int n, const char *channels_json, int *seqs)
{
    pending_op_t *op = mgmt_pending_alloc(ctx);
    if (!op) return -1;

    op->type   = PENDING_SPAWN_BATCH;
    op->n_targets = (n < PENDING_OP_TARGET_MAX) ? n : PENDING_OP_TARGET_MAX;
    op->deadline  = time(NULL) + PENDING_TIMEOUT_SEC;
    if (channels_json) {
        strncpy(op->channels_json, channels_json, sizeof(op->channels_json) - 1);
    }

    for (int i = 0; i < op->n_targets; i++) {
        op->targets[i].worker_id = -1;
        op->targets[i].send_seq  = (seqs ? seqs[i] : -1);
        if (targets[i]) {
            mgmt_worker_t *w = mgmt_find_worker(ctx, targets[i]);
            op->targets[i].worker_id = w ? (int)(w - ctx->mgmt.workers) : -1;
        }
    }
    return op->op_id;
}

/* 路由 SPAWN_ACK 到匹配的 pending op（按 seq+node_id 双重匹配） */
static void mgmt_pending_spawn_ack(global_ctx_t *ctx, const char *msg)
{
    char node_id[65] = {0};
    if (mgmt_parse_str(msg, "node_id", node_id, sizeof(node_id)) != 0)
        return;

    int ref_seq = -1;
    mgmt_parse_int(msg, "ref_seq", &ref_seq);

    char status[16] = {0};
    mgmt_parse_str(msg, "status", status, sizeof(status));

    /* 在活跃的 SPAWN_BATCH pending ops 中匹配 node_id + ref_seq */
    for (int i = 0; i < PENDING_OP_MAX; i++) {
        pending_op_t *op = &ctx->mgmt.pending_ops[i];
        if (!op->active || op->type != PENDING_SPAWN_BATCH) continue;

        for (int j = 0; j < op->n_targets; j++) {
            if (op->targets[j].acked) continue;
            if (op->targets[j].worker_id < 0 ||
                (size_t)op->targets[j].worker_id >= MGMT_MAX_WORKERS) continue;

            mgmt_worker_t *w = &ctx->mgmt.workers[op->targets[j].worker_id];
            if (w->node_id[0] && strcmp(w->node_id, node_id) == 0) {
                /* ref_seq 匹配: 确保 ACK 属于此 pending op */
                if (ref_seq >= 0 && op->targets[j].send_seq >= 0 &&
                    ref_seq != op->targets[j].send_seq) continue;

                op->targets[j].acked   = 1;
                op->targets[j].success = (strcmp(status, "ok") == 0);
                op->n_done++;
                if (op->targets[j].success) op->n_success++;
                LOG_INFO("PENDING[%d]: %s SPAWN_ACK %s (ref=%d) [%d/%d done]",
                         i, node_id, status, ref_seq, op->n_done, op->n_targets);
                return;
            }
        }
    }
    /* 无匹配 pending op — 异步 SPAWN_ACK（来自单次 SPAWN），仅日志 */
    LOG_INFO("SPAWN_ACK(orphan) from %s: status=%s seq=%d",
             node_id, status, ref_seq);
}

/* 清理过期 pending ops（由 API 轮询或定时器调用） */
void mgmt_pending_cleanup(global_ctx_t *ctx)
{
    time_t now = time(NULL);
    for (int i = 0; i < PENDING_OP_MAX; i++) {
        pending_op_t *op = &ctx->mgmt.pending_ops[i];
        if (!op->active) continue;
        if (now > op->deadline) {
            LOG_WARN("PENDING[%d]: timeout (%d/%d done, %d success)",
                     i, op->n_done, op->n_targets, op->n_success);
            memset(op, 0, sizeof(pending_op_t));
        }
    }
}

/* 完成并释放 pending op */
void mgmt_pending_release(global_ctx_t *ctx, int op_id)
{
    if (op_id < 0 || op_id >= PENDING_OP_MAX) return;
    memset(&ctx->mgmt.pending_ops[op_id], 0, sizeof(pending_op_t));
}

static void mgmt_handle_spawn_ack(global_ctx_t *ctx, const char *msg)
{
    char node_id[65] = {0};
    if (mgmt_parse_str(msg, "node_id", node_id, sizeof(node_id)) != 0) return;

    /* 更新 worker 心跳 */
    mgmt_worker_t *w = mgmt_find_worker(ctx, node_id);
    if (w) w->last_seen = time_now();

    /* 如果 Manager 侧有活跃的 pending 批次操作，路由到批次 */
    if (ctx->config.node.node_role == NODE_ROLE_MANAGER)
        mgmt_pending_spawn_ack(ctx, msg);
    else
        mgmt_handle_ack_common(ctx, msg, "SPAWN_ACK");
}

static void mgmt_handle_kill_ack(global_ctx_t *ctx, const char *msg)
    { mgmt_handle_ack_common(ctx, msg, "KILL_ACK"); }

static void mgmt_handle_switch_ack(global_ctx_t *ctx, const char *msg)
    { mgmt_handle_ack_common(ctx, msg, "SWITCH_ACK"); }

/* ──────────────────────────────────────────────────────────────────────────
 * mgmt_handle_channel_ctl_ack — 处理 Worker 的 CHANNEL_CTL_ACK
 *
 * 在通用 ACK 处理（心跳刷新 + 状态日志）基础上，额外解析通道操作详情
 * （added/deleted/errors），提供细粒度的操作结果审计。
 * ────────────────────────────────────────────────────────────────────────── */
static void mgmt_handle_channel_ctl_ack(global_ctx_t *ctx, const char *msg)
{
    if (ctx->config.node.node_role != NODE_ROLE_MANAGER) return;

    char node_id[65] = {0};
    if (mgmt_parse_str(msg, "node_id", node_id, sizeof(node_id)) != 0) return;

    mgmt_worker_t *w = mgmt_find_worker(ctx, node_id);
    if (!w) {
        LOG_WARN("CHANNEL_CTL_ACK from unknown worker %s (ignored)", node_id);
        return;
    }
    w->last_seen = time_now();

    int ref_seq = -1;
    mgmt_parse_int(msg, "ref_seq", &ref_seq);

    char status[16] = {0};
    mgmt_parse_str(msg, "status", status, sizeof(status));

    int added = 0, deleted = 0, errors = 0;
    mgmt_parse_int(msg, "added", &added);
    mgmt_parse_int(msg, "deleted", &deleted);
    mgmt_parse_int(msg, "errors", &errors);

    if (strcmp(status, "ok") == 0) {
        LOG_INFO("CHANNEL_CTL_ACK from %s OK (seq=%d, +%d -%d err=%d)",
                 node_id, ref_seq, added, deleted, errors);
    } else {
        char detail[128] = {0};
        mgmt_parse_str(msg, "message", detail, sizeof(detail));
        LOG_WARN("CHANNEL_CTL_ACK from %s FAILED (seq=%d, +%d -%d err=%d, reason=%s)",
                 node_id, ref_seq, added, deleted, errors,
                 detail[0] ? detail : "unknown");
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * mgmt_handle_channel_ctl — 处理 Manager 远程 ctl 指令（CHANNEL_CTL）
 *
 * 允许 Manager 通过管理通道远程执行与本地 ctl socket 相同的通道增删操作。
 * 核心实现复用 ctl_execute_json()（与 ctl_socket_accept 共用同一逻辑）。
 *
 * 消息格式:
 *   {"type":"CHANNEL_CTL","seq":N,"ts":N,"node_id":"M","target":"W",
 *    "payload":[{"op":"add","channel_id":1,...},{"op":"del","channel_id":2}]}
 *
 * 响应:
 *   {"type":"CHANNEL_CTL_ACK","seq":N,"ts":N,"node_id":"W",
 *    "ref_seq":N,"status":"ok","added":1,"deleted":1,"errors":0}
 *
 * 安全: 管理通道已通过 HMAC 认证（shared_secret），因此不需要额外的
 *       SO_PEERCRED 检查。通道增删受 channel_ctl_add / channel_ctl_del
 *       内置的端口冲突/ID合法性/FD预算检查保护。
 * ────────────────────────────────────────────────────────────────────────── */
static void mgmt_handle_channel_ctl(global_ctx_t *ctx, const char *msg)
{
    /* 仅 Worker 执行（Manager 本身没有通道可管理） */
    if (ctx->config.node.node_role != NODE_ROLE_WORKER) return;

    /* 提取 target 字段: 仅处理发给本节点的指令 */
    char target[65] = {0};
    if (mgmt_parse_str(msg, "target", target, sizeof(target)) != 0)
        return;
    if (strcmp(target, ctx->config.node.node_id) != 0) return;

    /* 提取 payload（与 SPAWN_INSTANCE 相同的括号计数法） */
    const char *p = strstr(msg, "\"payload\":");
    if (!p) return;
    p = strchr(p, '[');           /* 找到 JSON 数组的 '[' */
    if (!p) { p = strstr(msg, "\"payload\":{"); /* 单个对象: 找 '{' */
        /* 注意: 单对象 payload 在自身 JSON 无嵌套花括号时是安全的。
         * 但若未来单个对象内部出现 {}（如嵌套的 extra 字段），
         * 当前括号计数法会将内部 '}' 误认为 payload 结束符。
         * 建议：标准化为始终使用数组包装或改用完整 JSON 解析器。 */
        if (p) p = strchr(p, '{');
    }
    if (!p) return;

    /* 计数括号解析到匹配的 ']' 或 '}'（跳过 JSON 字符串内的括号） */
    char open = *p, close = (open == '[') ? ']' : '}';
    int depth = 1, in_string = 0;
    const char *end = p + 1;
    while (*end && depth > 0) {
        if (in_string) {
            if (*end == '"' && *(end - 1) != '\\') in_string = 0;
        } else {
            if (*end == '"') in_string = 1;
            else if (*end == open)  depth++;
            else if (*end == close) depth--;
        }
        end++;
    }
    if (depth != 0) return;

    /* 构造完整 JSON: "[...]" 或 "{...}" */
    size_t plen = (size_t)(end - p);
    char *payload_json = (char *)malloc(plen + 1);
    if (!payload_json) return;
    memcpy(payload_json, p, plen);
    payload_json[plen] = '\0';

    json_object *root = json_tokener_parse(payload_json);
    /* 保留 payload_json 给 instance_name 转发路径使用 */
    /* free(payload_json) — 延迟释放 */
    (void)payload_json;
    if (!root) {
        /* JSON 解析失败 → 回复错误 ACK */
        char buf[256];
        int off = mgmt_build_prefix(buf, sizeof(buf), "CHANNEL_CTL_ACK", ctx);
        int ref_seq = 0;
        mgmt_parse_int(msg, "seq", &ref_seq);
        off += snprintf(buf + off, sizeof(buf) - off,
            ",\"ref_seq\":%d,\"status\":\"error\","
            "\"message\":\"invalid JSON payload\"}\n", ref_seq);
        free(payload_json);
        mgmt_send_raw(ctx, buf, off);
        return;
    }

    /* 若 payload 包含 instance_name 且非本机 → 转发给 Master
     * 必须在 ctl_execute_json 之前检查，防止：
     *   (a) 在 Worker 本进程错误执行通道操作
     *   (b) 转发路径中 json_object_put(root) 双重释放 */
    char inst_name[65] = {0};
    int has_inst = mgmt_parse_str(msg, "instance_name", inst_name,
                                  sizeof(inst_name));
    if (has_inst == 0 && inst_name[0] != '\0'
        && strcmp(inst_name, ctx->config.node.node_id) != 0) {
        /* 写入请求文件，由 Master 转发给子进程 */
        FILE *cf = fopen(CHANNEL_CTL_FILE, "w");
        if (cf) {
            fprintf(cf, "{\"instance_name\":\"%s\",\"payload\":%s}\n",
                    inst_name, payload_json);
            fclose(cf);
        }
        free(payload_json);
        json_object_put(root);
        kill(ctx->master_pid, SIGUSR1);
        /* 不在此回复 ACK — 子进程完成后由其自身路径处理 */
        return;
    }

    /* 本地执行: 复用 ctl_execute_json（与 ctl socket 同一逻辑） */
    int added = 0, deleted = 0, errors = 0;
    int ret = ctl_execute_json(ctx, root, &added, &deleted, &errors);
    json_object_put(root);
    free(payload_json);

    /* 提取请求的 seq，构造 CHANNEL_CTL_ACK */
    int ref_seq = 0;
    mgmt_parse_int(msg, "seq", &ref_seq);

    char buf[512];
    int off = mgmt_build_prefix(buf, sizeof(buf), "CHANNEL_CTL_ACK", ctx);
    off += snprintf(buf + off, sizeof(buf) - off,
        ",\"ref_seq\":%d,\"status\":\"%s\","
        "\"added\":%d,\"deleted\":%d,\"errors\":%d}\n",
        ref_seq, (ret == 0) ? "ok" : "partial",
        added, deleted, errors);
    mgmt_send_raw(ctx, buf, off);

    LOG_INFO("CHANNEL_CTL from Manager: added=%d deleted=%d errors=%d",
             added, deleted, errors);
}

/* C4: CONFIG_PUSH handler — Worker 侧接收 Manager 推送的通道配置。
 * 提取 "config" 子对象, 调用 config_apply_from_mgmt() 应用热加载。 */
static void mgmt_handle_config_push(global_ctx_t *ctx, const char *msg)
{
    /* 版本守卫：Worker 仅接受比自己现有版本更新的配置 */
    uint64_t push_ver = 0;
    if (ctx->config.node.node_role == NODE_ROLE_WORKER) {
        char ver_buf[32];
        if (mgmt_parse_str(msg, "config_version", ver_buf, sizeof(ver_buf)) == 0)
            push_ver = (uint64_t)strtoull(ver_buf, NULL, 10);
        if (push_ver > 0 && push_ver <= ctx->mgmt.applied_config_version) {
            LOG_DEBUG("CONFIG_PUSH: version %llu <= applied %llu, skipping",
                      (unsigned long long)push_ver,
                      (unsigned long long)ctx->mgmt.applied_config_version);
            return;
        }
    }

    const char *p = strstr(msg, "\"config\":{");
    if (!p) { LOG_ERROR("CONFIG_PUSH: missing config field"); return; }
    p += 9; /* 跳过 "config": */
    /* 括号计数提取 config 对象（含 in_string 状态追踪转义） */
    int depth = 0, in_string = 0;
    const char *start = p;
    const char *end = p;
    for (; *end; end++) {
        if (in_string) {
            if (*end == '\\') { end++; continue; }  /* 跳过转义字符 */
            if (*end == '"')  in_string = 0;
            continue;
        }
        if (*end == '"')      { in_string = 1; continue; }
        if (*end == '{')      depth++;
        else if (*end == '}') { depth--; if (depth == 0) break; }
    }
    if (depth != 0 || end == p) { LOG_ERROR("CONFIG_PUSH: malformed config"); return; }
    size_t clen = (size_t)(end - start) + 1;
    char *config_json = (char *)malloc(clen + 1);
    if (!config_json) return;
    memcpy(config_json, start, clen);
    config_json[clen] = '\0';
    config_apply_from_mgmt(ctx, config_json);
    free(config_json);

    /* Worker 侧记录已应用版本号，防止旧配置覆盖新配置 */
    if (ctx->config.node.node_role == NODE_ROLE_WORKER && push_ver > 0)
        ctx->mgmt.applied_config_version = push_ver;

    /* 发送 CONFIG_ACK 告知 Manager 配置已应用 */
    if (ctx->config.node.node_role == NODE_ROLE_WORKER &&
        ctx->mgmt.mgmt_channel) {
        char ack[256];
        int off = snprintf(ack, sizeof(ack),
                 "{\"type\":\"CONFIG_ACK\",\"status\":\"ok\",\"version\":%llu}",
                 (unsigned long long)(push_ver > 0 ? push_ver : ctx->mgmt.applied_config_version));
        mgmt_send_raw(ctx, ack, off);
    }
}

/* ============================================================================
 * 公开接口
 * ============================================================================
 *
 * 以下 6 个函数构成管理模块对外的完整 API：
 *   mgmt_init()          — 初始化管理通道
 *   mgmt_dispatch()      — 消息分发入口（由 channel.c 调用）
 *   mgmt_send_to_worker()— 向指定 Worker 发送消息（v1.0 简化为广播）
 *   mgmt_push_config_to_all() — 向所有 Worker 广播最新配置
 *   mgmt_periodic()      — 定期任务：健康检查 + 超时检测
 *   mgmt_shutdown()      — 清理管理通道资源
 * ============================================================================
 */

/*
 * mgmt_init — 初始化管理模块
 *
 * 调用时机：main() 启动流程中，在通道创建之前调用。
 *
 * 行为（根据节点角色）：
 *   — NODE_ROLE_NONE：立即返回 0，不创建管理通道。
 *   — Manager/Worker：应用默认参数（keepalive=5s, timeout=30s, reconnect=3s），
 *     创建 channel_id=0 的管理通道（LISTENER 角色），设置 CH_FLAG_MGMT_CHANNEL
 *     和 CH_FLAG_STATIC_LISTENER 标志。
 *   — Worker 额外操作：自动发送 NODE_REGISTER 到 Manager。
 *
 * @param ctx 全局上下文
 * @return    成功 0，失败 -1（通道创建失败）
 */
int mgmt_init(global_ctx_t *ctx)
{
    /* 未启用管理模块 → 跳过 */
    if (!ctx->config.management.enabled) return 0;

    /* 未配置管理角色 → 跳过 */
    if (!ctx->config.node.node_role ||
        ctx->config.node.node_role == NODE_ROLE_NONE) {
        return 0;
    }

    /* C5: Manager 角色强制要求 shared_secret, 防止管理通道无认证可操作 */
    if (ctx->config.node.node_role == NODE_ROLE_MANAGER &&
        ctx->config.management.shared_secret[0] == '\0') {
        LOG_ERROR("mgmt_init: Manager requires shared_secret for management security");
        return -1;
    }

    /* 应用管理参数的默认值（配置文件中未设置时） */
    if (ctx->config.management.keepalive_interval == 0)
        ctx->config.management.keepalive_interval = 5;
    if (ctx->config.management.keepalive_timeout == 0)
        ctx->config.management.keepalive_timeout = 30;
    if (ctx->config.management.reconnect_interval == 0)
        ctx->config.management.reconnect_interval = 3;
    ctx->config.management.enabled = 1;

    /* 创建管理通道 (channel_id=0, LISTENER 角色, 非 TCP 模式) */
    channel_t *ch = channel_create(ctx, 0, CHANNEL_ROLE_LISTENER,
        ctx->config.management.listen_port,
        ctx->config.management.manager_port,
        0,
        "0.0.0.0", "", 0);
    if (!ch) {
        LOG_WARN("Management channel creation failed");
        return -1;
    }

    /* 设置管理标志：MGMT 标志使 channel_process_frame 路由到此模块；
     * STATIC_LISTENER 防止热重载时被意外销毁。 */
    ch->flags |= CH_FLAG_MGMT_CHANNEL;
    ch->flags |= CH_FLAG_STATIC_LISTENER;

    /* 网络层参数：管理通道共享主 AF_PACKET 套接字和网络配置 */
    ch->raw_sock  = ctx->raw_sock;
    ch->ifindex   = ctx->ifindex;
    ch->ethertype = ctx->ethertype;
    memcpy(ch->local_mac, ctx->local_mac, ETH_MAC_ADDR_LEN);
    memcpy(ch->peer_mac,  ctx->peer_mac,  ETH_MAC_ADDR_LEN);

    ctx->mgmt.mgmt_channel = ch;

    LOG_INFO("Management channel 0 created (role=%s)",
             ctx->config.node.node_role == NODE_ROLE_MANAGER
             ? "manager" : "worker");

    /* Worker 角色：主动向 Manager 发送注册请求 */
    if (ctx->config.node.node_role == NODE_ROLE_WORKER) {
        mgmt_send_register(ctx);
    }

    return 0;
}

/*
 * mgmt_dispatch — 管理消息分发入口
 *
 * 调用时机：channel.c 的 channel_process_frame() 检测到 CH_FLAG_MGMT_CHANNEL
 * 标志后调用此函数，而非 proxy_write_to_local()。
 *
 * 处理流程：
 *   1. 参数校验（NULL channel、非正长度、超大长度）
 *   2. 堆分配缓冲区（替代 64KB 栈帧，防止栈溢出）
 *   3. 提取 type 字段 → 路由到对应 handle 函数
 *   4. 释放缓冲区
 *
 * 安全：
 *   — 每条退出路径均释放 msg 缓冲区。
 *   — 使用 g_ctx 全局指针获取上下文（管理通道不存储 ctx 指针）。
 *
 * @param ch   管理通道指针
 * @param data KCP 接收缓冲区中的原始数据
 * @param len  数据长度
 */
void mgmt_dispatch(channel_t *ch, uint8_t *data, int len)
{
    /* ── 参数校验 ── */
    if (!ch || len <= 0 || len >= MGMT_MSG_MAX_LEN) return;

    /*
     * ── 堆分配消息缓冲区（避开 64KB 栈帧） ──
     *
     * 安全设计：
     *   管理消息最大可达 MGMT_MSG_MAX_LEN（65536 字节 = 64KB）。
     *   若在栈上分配此缓冲区，64KB 栈帧在某些嵌入式/受限环境下
     *   可能导致栈溢出（stack overflow）。因此使用 malloc 堆分配。
     *
     * 内存安全：
     *   — 每条退出路径均确保 free(msg)（包括 type 解析失败、g_ctx 为空等边界情况）
     *   — msg[len] = '\0' 保证字符串安全终止
     */
    char *msg = (char *)malloc((size_t)len + 1);
    if (!msg) return;

    memcpy(msg, data, (size_t)len);
    msg[len] = '\0';

    /* ── 提取 type 字段并路由 ── */
    char type[32];
    if (mgmt_parse_type(msg, type, sizeof(type)) != 0) { free(msg); return; }

    /* 全局上下文指针安全校验（main.c 在信号处理/启动前已赋值） */
    if (!g_ctx) { free(msg); return; }
    global_ctx_t *ctx = g_ctx;

    /* ── HMAC 认证：验证消息完整性 ── */
    if (ctx->config.management.shared_secret[0] != '\0') {
        /* 提取 auth 字段 */
        char auth_hex[65] = {0};
        int auth_ok = 0;
        if (mgmt_parse_str(msg, "auth", auth_hex, sizeof(auth_hex)) == 0
            && auth_hex[0] != '\0') {
            /* 从消息中移除 "auth":"..." 字段（原地修改，在 "auth" 前插入 '}'） */
            char *auth_pos = strstr(msg, "\"auth\":\"");
            if (auth_pos) {
                /* 找到 auth 字段的结束位置（auth 值闭合引号） */
                char *end = strchr(auth_pos + 8, '"');
                if (end) {
                    /* 检查 auth 是否为最后一个 JSON 字段 */
                    if (end[1] == '}') {
                        /* 末字段: ,"auth":"<hex>"} → 直接替换为 } */
                        if (auth_pos > msg)
                            memmove(auth_pos - 1, end + 1, strlen(end + 1) + 1);
                    } else if (end[2] == '"') {
                        /* 非末字段: ,"auth":"<hex>","next":...} → 跳过 auth */
                        end = strchr(end + 1, '"');
                        if (end) {
                        if (auth_pos > msg)
                            memmove(auth_pos - 1, end + 1, strlen(end + 1) + 1);
                        }
                    }
                }
            }
            /* 验证 HMAC: shared_secret + stripped_msg */
            int slen = (int)strlen(ctx->config.management.shared_secret);
            int mlen = (int)strlen(msg);
            char *verify_buf = (char *)malloc((size_t)(slen + mlen + 1));
            if (verify_buf) {
                memcpy(verify_buf, ctx->config.management.shared_secret, (size_t)slen);
                memcpy(verify_buf + slen, msg, (size_t)mlen);
                verify_buf[slen + mlen] = '\0';
                uint8_t computed[32];
                if (crypto_hmac_sign((const uint8_t *)verify_buf, slen + mlen, computed) == 0) {
                    /* 审计修复 C3: 先 hex_to_bytes 解码 auth_hex 为字节数组，
                     * 再用 volatile XOR 循环做常数时间比较，替代非恒时的 strcmp。 */
                    uint8_t expected_auth[32];
                    if (hex_to_bytes(auth_hex, expected_auth, 32)) {
                        volatile int diff = 0;
                        for (int i = 0; i < 32; i++)
                            diff |= (expected_auth[i] ^ computed[i]);
                        if (diff == 0)
                            auth_ok = 1;
                        else
                            LOG_AUDIT("HMAC mismatch for type=%s from node_id",
                                      type);
                    } else {
                        LOG_AUDIT("HMAC auth hex decode failed for type=%s", type);
                    }
                }
                /* 审计修复 C4: free 前擦除含 shared_secret 的堆缓冲区 */
                memset(verify_buf, 0, (size_t)(slen + mlen));
                __asm__ __volatile__("" : : "r"(verify_buf) : "memory");
                free(verify_buf);
            }
        }
        if (!auth_ok) {
            LOG_AUDIT("Message rejected: HMAC verification failed (type=%s)", type);
            free(msg);
            return;
        }
    }

    /* type → handle 映射表（字符串比较，O(1) 分发） */
    if (strcmp(type, "NODE_REGISTER") == 0)
        mgmt_handle_register(ctx, msg);
    else if (strcmp(type, "NODE_REGISTER_ACK") == 0)
        mgmt_handle_register_ack(ctx, msg);
    else if (strcmp(type, "HEALTH_CHECK") == 0)
        mgmt_handle_health_check(ctx, msg);
    else if (strcmp(type, "HEALTH_RESP") == 0)
        mgmt_handle_health_resp(ctx, msg);
    else if (strcmp(type, "SPAWN_INSTANCE") == 0)
        mgmt_handle_spawn_instance(ctx, msg);
    else if (strcmp(type, "KILL_INSTANCE") == 0)
        mgmt_handle_kill_instance(ctx, msg);
    else if (strcmp(type, "CONFIG_SWITCH") == 0)
        mgmt_handle_config_switch(ctx, msg);
    else if (strcmp(type, "CONFIG_ACK") == 0)
        mgmt_handle_config_ack(ctx, msg);
    else if (strcmp(type, "SPAWN_ACK") == 0)
        mgmt_handle_spawn_ack(ctx, msg);
    else if (strcmp(type, "KILL_ACK") == 0)
        mgmt_handle_kill_ack(ctx, msg);
    else if (strcmp(type, "SWITCH_ACK") == 0)
        mgmt_handle_switch_ack(ctx, msg);
    else if (strcmp(type, "CHANNEL_CTL_ACK") == 0)
        mgmt_handle_channel_ctl_ack(ctx, msg);
    else if (strcmp(type, "CHANNEL_CTL") == 0)
        mgmt_handle_channel_ctl(ctx, msg);
    else if (strcmp(type, "INSTANCE_SYNC_REQ") == 0)
        mgmt_handle_instance_sync_req(ctx, msg);
    else if (strcmp(type, "INSTANCE_SYNC_RESP") == 0)
        mgmt_handle_instance_sync_resp(ctx, msg);
    else if (strcmp(type, "CONFIG_PUSH") == 0)
        mgmt_handle_config_push(ctx, msg);
    /* 未知 type → 静默丢弃（log 在 DEBUG 级别输出） */

    free(msg);
}

/*
 * mgmt_send_to_worker — 向指定 Worker 发送 JSON 消息
 *
 * v1.0 实现为广播：所有 Worker 共享同一个管理通道，因此忽略 node_id
 * 参数，直接广播到通道。未来版本可利用 mgmt_worker_t.channel_id 实现
 * 点对点发送。
 *
 * @param ctx      全局上下文
 * @param node_id  目标 Worker ID（v1.0 忽略）
 * @param json_msg 已序列化的 JSON 消息
 * @param len      消息字节长度
 * @return         mgmt_send_raw 的返回值
 */
int mgmt_send_to_worker(global_ctx_t *ctx, const char *node_id,
                         const char *json_msg, int len)
{
    (void)node_id;  /* v1.0: 广播到唯一管理通道 */
    return mgmt_send_raw(ctx, json_msg, len);
}

/*
 * mgmt_push_config_to_all — 向所有 Worker（或指定 Worker）推送最新配置
 *
 * @param ctx               全局上下文
 * @param target_node_id    目标 Worker 的 node_id（NULL 或空字符串 = 广播所有）
 *
 * 调用时机：
 *   — Manager 侧 config_reload() 成功后
 *   — Worker 新注册后（mgmt_handle_register 调用）
 *   — API POST /api/v1/config/push
 *
 * 实现细节：
 *   遍历 ctx->config.channels[]，将 enabled 通道序列化为 JSON，
 *   附加 config_version 字段，通过管理通道广播。
 *
 * 序列化策略：
 *   使用手动 snprintf 构建 JSON（而非 json-c），以减少依赖。
 *   remote_addr/listen_addr 经过 mgmt_escape_json() 转义。
 *
 * 安全：
 *   — 仅在 Manager 角色执行
 *   — 管理通道未建立或 disabled 时静默返回
 */
void mgmt_push_config_to_all(global_ctx_t *ctx, const char *target_node_id)
{
    if (!ctx->mgmt.mgmt_channel || !ctx->config.management.enabled)
        return;
    if (ctx->config.node.node_role != NODE_ROLE_MANAGER) return;

    /* ── 构建消息前缀（含 config_version + 可选 target） ── */
    char prefix[320];
    int off = mgmt_build_prefix(prefix, sizeof(prefix), "CONFIG_PUSH", ctx);
    {
        int wr = snprintf(prefix + off, sizeof(prefix) - (size_t)off,
            ",\"config_version\":%llu",
            (unsigned long long)ctx->mgmt.config_version);
        if (wr < 0 || (size_t)wr >= sizeof(prefix) - (size_t)off) return;
        off += wr;
    }
    if (target_node_id && target_node_id[0]) {
        int wr = snprintf(prefix + off, sizeof(prefix) - (size_t)off,
            ",\"target\":\"%s\"", target_node_id);
        if (wr < 0 || (size_t)wr >= sizeof(prefix) - (size_t)off) return;
        off += wr;
    }

    /* ── 序列化 channels 数组 ──
     * 格式：{"channels":[{"channel_id":1,...},...]}
     * 仅推送 enabled=true 的通道，disabled 通道在 Worker 侧也不应启动。 */
    char *msg = (char *)malloc(MGMT_MSG_MAX_LEN);
    if (!msg) return;
    off = snprintf(msg, MGMT_MSG_MAX_LEN,
        "%s,\"config\":{\"channels\":[", prefix);
    if (off < 0 || off >= MGMT_MSG_MAX_LEN) { free(msg); return; }

    int first = 1;  /* 逗号分隔控制：第一个元素不加逗号 */
    for (int i = 0; i < ctx->config.channel_count; i++) {
        channel_config_t *c = &ctx->config.channels[i];
        if (!c->enabled) continue;

        /* ── 安全转义地址字符串 ──
         * 用户可自由配置 remote_addr/listen_addr，其中可能包含引号、
         * 反斜杠等 JSON 特殊字符。不转义将破坏 CONFIG_PUSH 消息格式。*/
        char escaped_remote[256], escaped_listen[256];
        mgmt_escape_json(escaped_remote, sizeof(escaped_remote), c->remote_addr);
        mgmt_escape_json(escaped_listen, sizeof(escaped_listen), c->listen_addr);

        {
            int remain = MGMT_MSG_MAX_LEN - off;
            if (remain <= 1) { free(msg); return; }
            off += snprintf(msg + off, (size_t)remain,
                "%s{\"channel_id\":%u,\"listen_port\":%u,\"remote_port\":%u,"
                "\"is_tcp\":%s,\"max_sessions\":%u,\"remote_addr\":\"%s\","
                "\"listen_addr\":\"%s\"}",
                first ? "" : ",",
                c->channel_id, c->listen_port, c->remote_port,
                c->is_tcp ? "true" : "false", c->max_sessions,
                escaped_remote, escaped_listen);
        }
        first = 0;
    }
    {
        int remain = MGMT_MSG_MAX_LEN - off;
        if (remain > 0)
            off += snprintf(msg + off, (size_t)remain, "]}}\n");
    }

    mgmt_send_raw(ctx, msg, off);
    free(msg);
    LOG_INFO("Config pushed to all workers (version %llu)",
             (unsigned long long)ctx->mgmt.config_version);
}

/*
 * mgmt_periodic — 管理模块定期任务
 *
 * 调用时机：main() 事件循环每次迭代后调用。
 *
 * Manager 侧行为：
 *   — 按 keepalive_interval 周期发送 HEALTH_CHECK 到管理通道
 *   — 检测超时 Worker（last_seen 超过 keepalive_timeout）标记为 DEGRADED
 *
 * Worker 侧行为：
 *   — 当前为空（Worker 被动响应健康检查）
 *
 * 注意：本函数使用 static 变量 last_health 跟踪上次健康检查时间。
 * 在单线程 epoll 模型下无需锁保护。
 *
 * @param ctx 全局上下文
 */
void mgmt_periodic(global_ctx_t *ctx)
{
    /* static 变量：跨调用保持的最后一次健康检查时间戳 */
    static uint32_t last_health = 0;
    /* 上一次 CONFIG_PUSH 重推时间戳（定期重推确保最终一致性） */
    static uint32_t last_config_repush = 0;
    uint32_t now = time_now();

    if (!ctx->config.management.enabled) return;

    if (ctx->config.node.node_role == NODE_ROLE_MANAGER) {
        /* ── Manager: 定期健康检查 ── */
        if (now - last_health >= (uint32_t)ctx->config.management.keepalive_interval) {
            last_health = now;

            /* 广播 HEALTH_CHECK（所有 Worker 共享一个管理通道） */
            char check[256];
            int off = mgmt_build_prefix(check, sizeof(check), "HEALTH_CHECK", ctx);
            off += snprintf(check + off, sizeof(check) - off, "}\n");
            mgmt_send_raw(ctx, check, off);

            /* ── 超时检测：扫描注册表，标记超时 Worker 为 DEGRADED ──
             * 仅检测 ACTIVE 状态（避免重复标记已 DEGRADED 的节点）。
             * 超时阈值 = keepalive_timeout（默认 30 秒）。
             * 注意：DEGRADED 状态的恢复由 mgmt_handle_health_resp 完成。*/
            for (int i = 0; i < ctx->mgmt.worker_count; i++) {
                mgmt_worker_t *w = &ctx->mgmt.workers[i];
                if (w->state != MGMT_WORKER_STATE_DEGRADED
                    && time_elapsed(w->last_seen)
                       > ctx->config.management.keepalive_timeout) {
                    w->state = MGMT_WORKER_STATE_DEGRADED;
                    w->degraded_since = now;
                    w->health_resp_count = 0;
                    LOG_WARN("Worker %s timed out (degraded)", w->node_id);
                }
            }

            /* ── DEGRADED 过期清理 ──
             * 对连续 DEGRADED 超过 10×keepalive_timeout 的 Worker，
             * 从注册表中移除（swap-with-last 压缩数组）。
             * 使用 degraded_since（降级时刻）而非 last_seen（最后心跳时刻）
             * 作为清理计时起点，确保清理发生在确认为降级之后。
             * 10×timeout（默认300s）给予 Worker 重启周期充足的容错窗口。*/
            int cleanup_timeout = ctx->config.management.keepalive_timeout * 10;
            if (cleanup_timeout < 120) cleanup_timeout = 120;  /* 最少 120s */
            for (int i = 0; i < ctx->mgmt.worker_count; ) {
                mgmt_worker_t *w = &ctx->mgmt.workers[i];
                if (w->state == MGMT_WORKER_STATE_DEGRADED
                    && w->degraded_since > 0
                    && time_elapsed(w->degraded_since) > cleanup_timeout) {
                    LOG_INFO("Removing stale worker %s (degraded for %us)",
                             w->node_id, (unsigned)time_elapsed(w->degraded_since));
                    /*
                     * D10-7: 断路器审计日志（Circuit Breaker Audit）
                     *
                     * 当 Worker 持续 DEGRADED 超过 10×keepalive_timeout（默认 300s）
                     * 后，Manager 从注册表中永久移除该 Worker。
                     *
                     * 断路器元语：
                     *   — Circuit Breaker OPEN：Worker 被永久移除，不再接收其消息。
                     *   — 移除采用 swap-with-last 数组压缩策略（O(1) 删除）。
                     *   — LOG_AUDIT 写入不可变审计日志，供安全审计/监控系统消费。
                     *
                     * 容错窗口：10×timeout（最少 120s）给予 Worker 重启充足时间。
                     */
                    LOG_AUDIT("Circuit breaker OPEN: worker %s removed after %us degraded",
                              w->node_id, (unsigned)time_elapsed(w->degraded_since));
                    /* swap-with-last 移除 */
                    if (i < ctx->mgmt.worker_count - 1)
                        ctx->mgmt.workers[i] = ctx->mgmt.workers[ctx->mgmt.worker_count - 1];
                    ctx->mgmt.worker_count--;
                    /* 不递增 i，检查交换来的新元素 */
                } else {
                    i++;
                }
            }
            /* ── 定期 CONFIG_PUSH 重推 ──
             * 防止网络丢包导致 Worker 配置不一致。每 3×keepalive_interval
             * 向所有 Worker 重新广播最新配置。Worker 侧 config_apply_from_mgmt
             * 是幂等的（相同配置不会重复热加载），因此重推无副作用。 */
            if (ctx->mgmt.worker_count > 0
                && now - last_config_repush
                   >= (uint32_t)ctx->config.management.keepalive_interval * 3) {
                last_config_repush = now;
                if (ctx->mgmt.config_version > 0) {
                    LOG_INFO("Periodic config re-push (version %llu) to %d workers",
                             (unsigned long long)ctx->mgmt.config_version, ctx->mgmt.worker_count);
                    mgmt_push_config_to_all(ctx, NULL);
                }
            }
        }
    } else if (ctx->config.node.node_role == NODE_ROLE_WORKER) {
        /* ── Worker: 注册重试 ──
         * 若 mgmt_init 发送的 NODE_REGISTER 未获 Manager ACK，
         * 按 reconnect_interval 周期重发注册请求。 */
        static uint32_t last_retry = 0;
        if (!ctx->mgmt.worker_registered
            && ctx->mgmt.mgmt_channel
            && now - last_retry >= (uint32_t)ctx->config.management.reconnect_interval) {
            last_retry = now;
            LOG_INFO("Retrying registration with Manager...");
            mgmt_send_register(ctx);
        }
        /* ── 管理通道活跃度检测 ──
         * 已注册后若长期未收到 Manager 的任何消息（心跳、配置推送等），
         * 说明管理通道可能已中断（KCP 断开但 channel 未被销毁）。
         * 重置 worker_registered 触发重注册，使 Worker 重新加入集群。 */
        if (ctx->mgmt.worker_registered
            && ctx->mgmt.mgmt_channel
            && time_elapsed(ctx->mgmt.mgmt_channel->last_peer_seen)
               > (uint32_t)ctx->config.management.keepalive_timeout * 2) {
            LOG_WARN("Management channel idle for %us, resetting registration",
                     time_elapsed(ctx->mgmt.mgmt_channel->last_peer_seen));
            ctx->mgmt.worker_registered = 0;
            last_retry = 0;  /* 立即触发重试 */
        }
    }
}

/*
 * mgmt_shutdown — 清理管理模块资源
 *
 * 调用时机：main() 的 cleanup() 函数中，在 api_shutdown 之后、
 * 其他通道销毁之前调用。
 *
 * 行为：销毁管理通道（channel_destroy 会释放 KCP 实例、关闭 socket、
 * 清理哈希表条目），并将 mgmt_channel 指针置 NULL。
 *
 * 安全：幂等调用 — 多次调用 mgmt_shutdown 是安全的（mgmt_channel 为 NULL
 * 时直接返回 LOG_INFO）。
 */

/*
 * mgmt_send_instance_command — Manager 向指定 Worker 发送 SPAWN/KILL 指令
 *
 * @param ctx      全局上下文
 * @param type     消息类型 (\"SPAWN_INSTANCE\" / \"KILL_INSTANCE\")
 * @param target_node_id  目标 Worker 的 node_id
 * @param payload_json    指令负载（JSON 对象字符串，不含外层花括号）
 * @return         成功 0，失败 -1
 */
int mgmt_send_instance_command(global_ctx_t *ctx, const char *type,
                               const char *target_node_id,
                               const char *payload_json)
{
    if (!ctx->mgmt.mgmt_channel || !ctx->config.management.enabled)
        return -1;

    size_t plen = payload_json ? strlen(payload_json) : 0;
    size_t need = 256 + plen;
    if (need > MGMT_MSG_MAX_LEN) {
        LOG_ERROR("mgmt_send_instance_command: payload too large (%zu > %d)",
                  need, MGMT_MSG_MAX_LEN);
        return -1;   /* 拒绝超大 payload，不截断 */
    }
    char *buf = (char *)malloc(need);
    if (!buf) return -1;

    int off = mgmt_build_prefix(buf, need, type, ctx);
    int rem = (int)(need - (size_t)off);
    int wr = snprintf(buf + off, rem > 0 ? (size_t)rem : 0,
        ",\"target\":\"%s\",\"payload\":{%s}}\n",
        target_node_id, payload_json ? payload_json : "");
    /*
     * 截断告警：
     *   当 payload 过大导致 snprintf 输出被截断时（wr < 0 表示编码错误，
     *   wr >= rem 表示输出超过剩余缓冲区），记录 WARN 并返回 -1。
     *
     * 这不是静默截断 — 调用方（api.c）会收到 -1 返回值并向上传播错误。
     * Manager 端不会误以为指令已成功送达。
     */
    if (wr < 0 || wr >= rem) {
        LOG_WARN("mgmt_send_instance_command: payload truncated (%d/%d)", wr, rem);
        free(buf);
        return -1;
    }
    off += wr;
    int ret = mgmt_send_raw(ctx, buf, off);
    free(buf);
    return ret;
}

/* ──────────────────────────────────────────────────────────────────────────
 * mgmt_track_spawned_instance — Manager 侧：记录已 SPAWN 的实例
 *
 * 在 SPAWN_INSTANCE 成功发送后调用，将实例信息存入对应 Worker 的追踪列表。
 * Worker 重启后通过 INSTANCE_SYNC 恢复。
 * ────────────────────────────────────────────────────────────────────────── */
void mgmt_track_spawned_instance(global_ctx_t *ctx, const char *node_id,
                                 const char *instance_name, uint16_t ethertype,
                                 const char *node_type_str, int cpu_affinity,
                                 const char *channels_json)
{
    if (ctx->config.node.node_role != NODE_ROLE_MANAGER) return;
    mgmt_worker_t *w = mgmt_find_worker(ctx, node_id);
    if (!w) return;

    /* 去重 */
    for (int i = 0; i < w->instance_count; i++) {
        if (strcmp(w->instances[i].instance_name, instance_name) == 0) return;
    }
    if (w->instance_count >= MGMT_MAX_INSTANCES_PER_WORKER) return;

    int idx = w->instance_count++;
    strncpy(w->instances[idx].instance_name, instance_name, sizeof(w->instances[idx].instance_name) - 1);
    w->instances[idx].instance_name[sizeof(w->instances[idx].instance_name) - 1] = '\0';
    w->instances[idx].ethertype    = ethertype;
    w->instances[idx].node_type    = (strcmp(node_type_str, "backend") == 0)
                                    ? NODE_TYPE_BACKEND : NODE_TYPE_FRONTEND;
    w->instances[idx].cpu_affinity = cpu_affinity;
    if (channels_json) {
        strncpy(w->instances[idx].channels_json, channels_json, 4095);
        w->instances[idx].channels_json[4095] = '\0';
    }
    /* 可观测运行时字段 */
    w->instances[idx].pid           = 0;             /* Manager侧无Worker子进程PID */
    w->instances[idx].spawned_at    = time_now();
    w->instances[idx].restart_count = 0;
    LOG_INFO("Manager: tracked instance '%s' on %s", instance_name, node_id);

    /* 持久化到 Manager 配置文件 */
    mgmt_persist_dynamic_instances(ctx);
}

/* ──────────────────────────────────────────────────────────────────────────
 * mgmt_untrack_spawned_instance — Manager 侧：移除已 KILL 的实例
 * ────────────────────────────────────────────────────────────────────────── */
void mgmt_untrack_spawned_instance(global_ctx_t *ctx, const char *node_id,
                                   const char *instance_name)
{
    if (ctx->config.node.node_role != NODE_ROLE_MANAGER) return;
    mgmt_worker_t *w = mgmt_find_worker(ctx, node_id);
    if (!w) return;

    for (int i = 0; i < w->instance_count; i++) {
        if (strcmp(w->instances[i].instance_name, instance_name) == 0) {
            if (i < w->instance_count - 1)
                memmove(&w->instances[i], &w->instances[i + 1],
                        (size_t)(w->instance_count - i - 1)
                        * sizeof(mgmt_worker_instance_t));
            w->instance_count--;
            LOG_INFO("Manager: untracked instance '%s' on %s",
                     instance_name, node_id);
            mgmt_persist_dynamic_instances(ctx);
            return;
        }
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * mgmt_send_channel_ctl — Manager 向远程 Worker 发送通道增删指令
 *
 * 将本地 ctl socket 命令的 JSON 数组/对象直接嵌入 payload，通过管理通道
 * 发送给 target_node_id 指定的 Worker。Worker 收到后调用 ctl_execute_json
 * 执行，结果通过 CHANNEL_CTL_ACK 返回。
 *
 * 使用示例：
 *   mgmt_send_channel_ctl(ctx, "worker-sh-01",
 *       "[{\"op\":\"add\",\"channel_id\":100,...},{\"op\":\"del\",\"channel_id\":200}]");
 *
 * @param ctx             全局上下文
 * @param target_node_id  目标 Worker 的 node_id
 * @param ctl_json        通道控制 JSON（数组或对象字符串，如 "[...]" 或 "{...}"）
 * @return                成功 0，失败 -1
 * ────────────────────────────────────────────────────────────────────────── */
int mgmt_send_channel_ctl(global_ctx_t *ctx, const char *target_node_id,
                          const char *ctl_json)
{
    if (!ctx->mgmt.mgmt_channel || !ctx->config.management.enabled)
        return -1;
    if (!target_node_id || !ctl_json) return -1;

    size_t plen = strlen(ctl_json);
    size_t need = 256 + plen;
    if (need > MGMT_MSG_MAX_LEN) {
        LOG_ERROR("mgmt_send_channel_ctl: payload too large (%zu > %d)",
                  need, MGMT_MSG_MAX_LEN);
        return -1;
    }

    char *buf = (char *)malloc(need);
    if (!buf) return -1;

    int off = mgmt_build_prefix(buf, need, "CHANNEL_CTL", ctx);
    int rem = (int)(need - (size_t)off);
    int wr = snprintf(buf + off, rem > 0 ? (size_t)rem : 0,
        ",\"target\":\"%s\",\"payload\":%s}\n",
        target_node_id, ctl_json);
    if (wr < 0 || wr >= rem) {
        LOG_WARN("mgmt_send_channel_ctl: payload truncated (%d/%d)", wr, rem);
        free(buf);
        return -1;
    }
    off += wr;
    int ret = mgmt_send_raw(ctx, buf, off);
    free(buf);
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 动态实例持久化 — Manager 配置文件中的 instances[] 数组
 *
 * Manager 重启后从配置文件恢复已 SPAWN 的实例追踪列表。
 * 格式：instances[] 中 source:"dynamic" 的条目。
 * ═══════════════════════════════════════════════════════════════════════════ */

void mgmt_persist_dynamic_instances(global_ctx_t *ctx)
{
    if (!ctx->mgmt.config_path[0]) return;

    struct json_object *root = json_object_from_file(ctx->mgmt.config_path);
    if (!root) return;

    /* 重建 instances 数组：只保留 source != "dynamic" 的条目 + 当前动态实例 */
    struct json_object *old_instances = json_object_object_get(root, "instances");
    struct json_object *new_instances = json_object_new_array();

    /* 保留非 dynamic 条目 */
    if (old_instances) {
        int n = json_object_array_length(old_instances);
        for (int i = 0; i < n; i++) {
            struct json_object *inst = json_object_array_get_idx(old_instances, i);
            struct json_object *jsrc = json_object_object_get(inst, "source");
            const char *sr = jsrc ? json_object_get_string(jsrc) : "";
            if (strcmp(sr, "dynamic") != 0) {
                json_object_get(inst);
                json_object_array_add(new_instances, inst);
            }
        }
    }

    /* 追加所有动态实例 */
    for (int i = 0; i < ctx->mgmt.worker_count; i++) {
        mgmt_worker_t *w = &ctx->mgmt.workers[i];
        for (int j = 0; j < w->instance_count; j++) {
            struct json_object *inst = json_object_new_object();
            json_object_object_add(inst, "source", json_object_new_string("dynamic"));
            json_object_object_add(inst, "worker_node", json_object_new_string(w->node_id));
            json_object_object_add(inst, "instance_name",
                json_object_new_string(w->instances[j].instance_name));
            json_object_object_add(inst, "ethertype",
                json_object_new_int((int)w->instances[j].ethertype));
            json_object_object_add(inst, "node_type",
                json_object_new_string((w->instances[j].node_type == NODE_TYPE_BACKEND)
                    ? "backend" : "frontend"));
            json_object_object_add(inst, "cpu_affinity",
                json_object_new_int(w->instances[j].cpu_affinity));
            if (w->instances[j].channels_json[0]) {
                struct json_object *channels_json =
                    json_tokener_parse(w->instances[j].channels_json);
                if (!channels_json)
                    channels_json = json_object_new_array();
                json_object_object_add(inst, "channels", channels_json);
            }
            json_object_array_add(new_instances, inst);
        }
    }

    json_object_object_del(root, "instances");
    json_object_object_add(root, "instances", new_instances);
    /* 原子写入：mkstemp + write + fsync + rename */
    {
        char tmp_path[MAX_CONFIG_PATH + 16];
        snprintf(tmp_path, sizeof(tmp_path), "%s.XXXXXX", ctx->mgmt.config_path);
        int fd = mkstemp(tmp_path);
        if (fd < 0) {
            LOG_WARN("mgmt_persist_dynamic_instances: mkstemp failed: %s",
                     strerror(errno));
        } else {
            const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
            if (!json_str) {
                LOG_WARN("mgmt_persist_dynamic_instances: json_object_to_json_string_ext returned NULL");
                unlink(tmp_path);
                close(fd);
                json_object_put(root);
                return;
            }
            size_t slen = strlen(json_str);
            if (write(fd, json_str, slen) == (ssize_t)slen && fsync(fd) == 0)
                rename(tmp_path, ctx->mgmt.config_path);
            else {
                LOG_WARN("mgmt_persist_dynamic_instances: write/fsync failed: %s",
                         strerror(errno));
                unlink(tmp_path);
            }
            close(fd);
        }
    }
    json_object_put(root);
}

/* ──────────────────────────────────────────────────────────────────────────
 * mgmt_instance_channel_ctl — 永久删除 SPAWN 实例的静态通道
 */
__attribute__((used))
int mgmt_instance_channel_ctl(global_ctx_t *ctx, const char *node_id,
                               const char *instance_name,
                               int channel_id, const char *op,
                               const char *payload_json)
{
    if (!ctx || !node_id || !instance_name) return -1;
    /* payload_json 为协议扩展预留参数，当前实现中通过 channels_json
     * 字段直接操作，故此处未使用。保留该参数以兼容未来协议版本。 */
    (void)payload_json;

    mgmt_worker_t *w = NULL;
    int idx = -1;
    for (int i = 0; i < ctx->mgmt.worker_count; i++) {
        if (strcmp(ctx->mgmt.workers[i].node_id, node_id) == 0) {
            w = &ctx->mgmt.workers[i];
            for (int j = 0; j < w->instance_count; j++) {
                if (strcmp(w->instances[j].instance_name, instance_name) == 0) {
                    idx = j; break;
                }
            }
            break;
        }
    }
    if (!w || idx < 0) return -1;

    struct json_object *ch_arr = NULL;
    if (w->instances[idx].channels_json[0]) {
        ch_arr = json_tokener_parse(w->instances[idx].channels_json);
    }
    if (!ch_arr || !json_object_is_type(ch_arr, json_type_array)) {
        if (ch_arr) json_object_put(ch_arr);
        ch_arr = json_object_new_array();
    }

    if (strcmp(op, "del") == 0) {
        int len = json_object_array_length(ch_arr);
        struct json_object *new_arr = json_object_new_array();
        for (int i = 0; i < len; i++) {
            struct json_object *ch = json_object_array_get_idx(ch_arr, i);
            struct json_object *j_id = json_object_object_get(ch, "channel_id");
            if (j_id && json_object_get_int(j_id) == channel_id) continue;
            /* json_object_get(ch) 增加引用计数，由 new_arr 持有该引用。
             * new_arr 在 json_object_put 时统一释放，无需手动管理。 */
            json_object_array_add(new_arr, json_object_get(ch));
        }
        json_object_put(ch_arr);
        ch_arr = new_arr;
    }

    const char *chs = json_object_to_json_string(ch_arr);
    if (chs) {
        size_t chs_len = strlen(chs);
        if (chs_len >= 4096) {
            LOG_WARN("channels_json truncated: len=%zu exceeds 4095 bytes", chs_len);
        }
        strncpy(w->instances[idx].channels_json, chs, 4095);
        w->instances[idx].channels_json[4095] = '\0';
    }
    json_object_put(ch_arr);

    mgmt_persist_dynamic_instances(ctx);

    if (ctx->mgmt.mgmt_channel && ctx->config.management.enabled) {
        char payload_buf[512];
        snprintf(payload_buf, sizeof(payload_buf),
                 "[{\"op\":\"%s\",\"channel_id\":%d}]", op, channel_id);
        char buf[2048];
        int off = mgmt_build_prefix(buf, sizeof(buf), "CHANNEL_CTL", ctx);
        off += snprintf(buf + off, sizeof(buf) - off,
            ",\"target\":\"%s\",\"instance_name\":\"%s\",\"payload\":%s}\n",
            node_id, instance_name, payload_buf);
        if (off < (int)sizeof(buf))
            mgmt_send_raw(ctx, buf, off);
    }

    return 0;
}


void mgmt_load_dynamic_instances(global_ctx_t *ctx)
{
    if (!ctx->mgmt.config_path[0]) return;
    struct json_object *root = json_object_from_file(ctx->mgmt.config_path);
    if (!root) return;

    struct json_object *instances = json_object_object_get(root, "instances");
    if (!instances) { json_object_put(root); return; }

    int n = json_object_array_length(instances);
    int loaded = 0;
    for (int i = 0; i < n; i++) {
        struct json_object *inst = json_object_array_get_idx(instances, i);
        struct json_object *jsrc = json_object_object_get(inst, "source");
        const char *sr = jsrc ? json_object_get_string(jsrc) : "";
        if (strcmp(sr, "dynamic") != 0) continue;

        struct json_object *jwn = json_object_object_get(inst, "worker_node");
        struct json_object *jnm = json_object_object_get(inst, "instance_name");
        struct json_object *jet = json_object_object_get(inst, "ethertype");
        struct json_object *jnt = json_object_object_get(inst, "node_type");
        struct json_object *jca = json_object_object_get(inst, "cpu_affinity");

        const char *wn = jwn ? json_object_get_string(jwn) : NULL;
        const char *nm = jnm ? json_object_get_string(jnm) : NULL;
        if (!wn || !nm) continue;

        uint16_t eth = jet ? (uint16_t)json_object_get_int(jet) : 0x0600;
        const char *nt = jnt ? json_object_get_string(jnt) : "frontend";
        int ca = jca ? json_object_get_int(jca) : -1;

        /* 存入对应 Worker 的追踪列表（Worker 可能还未注册，预先分配） */
        mgmt_worker_t *w = mgmt_find_or_create_worker(ctx, wn);
        if (!w || w->instance_count >= MGMT_MAX_INSTANCES_PER_WORKER) continue;
        int idx = w->instance_count++;
        strncpy(w->instances[idx].instance_name, nm, sizeof(w->instances[idx].instance_name) - 1);
        w->instances[idx].instance_name[sizeof(w->instances[idx].instance_name) - 1] = '\0';
        w->instances[idx].ethertype    = eth;
        w->instances[idx].node_type    = (strcmp(nt, "backend") == 0)
                                        ? NODE_TYPE_BACKEND : NODE_TYPE_FRONTEND;
        w->instances[idx].cpu_affinity = ca;
        struct json_object *jch = json_object_object_get(inst, "channels");
        if (jch) {
            const char *ch_str = json_object_to_json_string(jch);
            if (ch_str) {
                strncpy(w->instances[idx].channels_json, ch_str, 4095);
                w->instances[idx].channels_json[4095] = '\0';
            }
        }
        loaded++;
    }
    json_object_put(root);
    if (loaded > 0)
        LOG_INFO("Manager: loaded %d dynamic instances from config", loaded);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 动态实例同步 (INSTANCE_SYNC_REQ / INSTANCE_SYNC_RESP)
 *
 * Worker 重启后主动向 Manager 请求动态实例列表，替代配置文件中的实例缓存。
 * 流程：Worker 发送 REQ → Manager 回复 RESP（含实例名/ethertype/...）
 * ═══════════════════════════════════════════════════════════════════════════ */

void mgmt_request_instance_sync(global_ctx_t *ctx)
{
    if (!ctx->mgmt.mgmt_channel || !ctx->mgmt.worker_registered)
        return;

    char buf[512];
    int off = mgmt_build_prefix(buf, sizeof(buf), "INSTANCE_SYNC_REQ", ctx);
    off += snprintf(buf + off, sizeof(buf) - off, "}\n");
    mgmt_send_raw(ctx, buf, off);
    ctx->mgmt.sync_state = INSTANCE_SYNC_PENDING;
    ctx->mgmt.sync_last_attempt = time_now();
    LOG_INFO("Instance sync: sent INSTANCE_SYNC_REQ");
}

/* Manager 侧：收到 Worker 的同步请求，回复实例列表 */
static void mgmt_handle_instance_sync_req(global_ctx_t *ctx, const char *msg)
{
    if (ctx->config.node.node_role != NODE_ROLE_MANAGER) return;

    char node_id[65] = {0};
    mgmt_parse_str(msg, "node_id", node_id, sizeof(node_id));

    /* 查找此 Worker 注册表 */
    mgmt_worker_t *w = mgmt_find_worker(ctx, node_id);
    int inst_count = w ? w->instance_count : 0;

    char *buf = (char *)malloc(MGMT_MSG_MAX_LEN);
    if (!buf) return;
    int off = mgmt_build_prefix(buf, MGMT_MSG_MAX_LEN, "INSTANCE_SYNC_RESP", ctx);

    off += snprintf(buf + off, MGMT_MSG_MAX_LEN - (size_t)off,
        ",\"node_id\":\"%s\",\"instance_count\":%d,\"instances\":[",
        node_id, inst_count);

    for (int i = 0; i < inst_count; i++) {
        off += snprintf(buf + off, MGMT_MSG_MAX_LEN - (size_t)off,
            "%s{\"instance_name\":\"%s\",\"ethertype\":%u,"
            "\"node_type\":\"%s\",\"cpu_affinity\":%d"
            "%s%s%s}",
            i > 0 ? "," : "",
            w->instances[i].instance_name,
            w->instances[i].ethertype,
            (w->instances[i].node_type == NODE_TYPE_BACKEND) ? "backend" : "frontend",
            w->instances[i].cpu_affinity,
            w->instances[i].channels_json[0] ? ",\"channels\":" : "",
            w->instances[i].channels_json[0] ? w->instances[i].channels_json : "",
            w->instances[i].channels_json[0] ? "" : "");
    }
    off += snprintf(buf + off, MGMT_MSG_MAX_LEN - (size_t)off, "]}\n");
    mgmt_send_raw(ctx, buf, off);
    free(buf);

    LOG_INFO("Instance sync: replied with %d instances for %s",
             inst_count, node_id);
}

/* Worker 侧：收到 Manager 的同步响应，提取实例列表 */
static void mgmt_handle_instance_sync_resp(global_ctx_t *ctx, const char *msg)
{
    if (ctx->config.node.node_role != NODE_ROLE_WORKER) return;
    if (ctx->mgmt.sync_state == INSTANCE_SYNC_DONE) return;  /* 已同步 */

    int count = 0;
    mgmt_parse_int(msg, "instance_count", &count);
    if (count <= 0) {
        ctx->mgmt.sync_state = INSTANCE_SYNC_DONE;
        LOG_INFO("Instance sync: no dynamic instances to restore");
        return;
    }

    /* 提取 instances 数组 */
    const char *p = strstr(msg, "\"instances\":[");
    if (!p) return;
    p += 13;  /* 跳过 \"instances\":[ */

    /* 解析每个实例对象 */
    for (int i = 0; i < count && i < MGMT_MAX_INSTANCES_PER_WORKER; i++) {
        /* 找到下一个 '{' */
        while (*p && *p != '{') p++;
        if (!*p) break;

        /* 解析 instance_name */
        const char *ns = strstr(p, "\"instance_name\":\"");
        if (!ns) break;
        ns += 17;
        char name[65] = {0};
        const char *ne = strchr(ns, '"');
        if (!ne) break;
        size_t nl = (size_t)(ne - ns);
        if (nl >= 64) nl = 63;
        memcpy(name, ns, nl);

        /* 解析 ethertype */
        int eth = 0;
        const char *es = strstr(p, "\"ethertype\":");
        if (es) eth = (int)strtol(es + 12, NULL, 10);

        /* 解析 node_type */
        const char *ts = strstr(p, "\"node_type\":\"");
        uint8_t ntype = NODE_TYPE_FRONTEND;
        if (ts && strncmp(ts + 13, "backend", 7) == 0) ntype = NODE_TYPE_BACKEND;

        /* 解析 cpu_affinity */
        int aff = -1;
        const char *as = strstr(p, "\"cpu_affinity\":");
        if (as) aff = (int)strtol(as + 15, NULL, 10);

        LOG_INFO("Instance sync: restoring '%s' (eth=0x%04X)", name, eth);

        /* 构建 instance_config_t，调用 main.c 的 spawn 路径 */
        instance_config_t inst;
        memset(&inst, 0, sizeof(inst));
        size_t nl_capped = nl < (size_t)(MAX_LISTEN_ADDR - 1) ? nl : (size_t)(MAX_LISTEN_ADDR - 1);
        memcpy(inst.instance_name, name, nl_capped);
        inst.instance_name[nl_capped] = '\0';
        memcpy(inst.source, "dynamic", 8);
        inst.ethertype = (uint16_t)eth;
        inst.node_type = (node_type_t)ntype;
        inst.cpu_affinity = aff;

        /* 提取 channels JSON（在实例对象的 "channels" 字段中） */
        char channels_json[4096] = {0};
        const char *ch = strstr(p, "\"channels\":");
        if (ch) {
            ch += 11;
            int cdepth = 0, cstr = 0;
            const char *ce = ch;
            while (*ce) {
                if (cstr) { if (*ce == '"' && *(ce-1) != '\\') cstr = 0; }
                else { if (*ce == '"') cstr = 1; else if (*ce == '[') cdepth++; else if (*ce == ']') cdepth--; }
                ce++;
                if (cdepth == 0) break;
            }
            size_t clen = (size_t)(ce - ch);
            if (clen < 4095) { memcpy(channels_json, ch, clen); channels_json[clen] = '\0'; }
        }

        extern void master_spawn_from_sync(instance_config_t *inst);
        master_spawn_from_sync(&inst);

        /* 移动到下一个 '}' */
        while (*p && *p != '}') p++;
        if (*p == '}') p++;
    }

    ctx->mgmt.sync_state = INSTANCE_SYNC_DONE;
    ctx->mgmt.sync_retry_count = 0;
    LOG_INFO("Instance sync: complete (%d instances restored)", count);
}

void mgmt_shutdown(global_ctx_t *ctx)
{
    if (ctx->mgmt.mgmt_channel) {
        channel_destroy(ctx, ctx->mgmt.mgmt_channel);
        ctx->mgmt.mgmt_channel = NULL;
    }
    /* M9: 清零 shared_secret 防止密钥残留，explicit_bzero 确保不被编译器优化 */
    explicit_bzero(ctx->config.management.shared_secret,
                   sizeof(ctx->config.management.shared_secret));
    LOG_INFO("Management module shut down");
}
