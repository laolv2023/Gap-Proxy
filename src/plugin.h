/*
 * plugin.h — 业务功能插件框架（编译期链接）
 *
 * 设计原则：极简链表注册 + 顺序调用 + 空链零开销短路
 *
 * Hook 点:
 *   HP-4  应用数据入站: KCP重组后、write_local前，可修改/丢弃
 *   HP-7  通道生命周期: channel_create / channel_destroy
 *
 * 安全约束:
 *   - on_app_data_in 中 *len 不得超过 cap（框架强制校验，超限视为错误丢弃）
 *   - 插件不可直接修改 global_ctx_t 关键字段（由代码审计保证）
 *   - 插件崩溃（SIGSEGV/longjmp/死循环）会导致整个进程终止（单线程模型）
 */

#ifndef GAPPROXY_PLUGIN_H
#define GAPPROXY_PLUGIN_H

#include <stdint.h>
#include "types.h"

/* ── 插件返回值 ────────────────────────────────────────────────────────── */
typedef enum {
    PLUGIN_OK       =  0,   /* 继续传递，不做任何改变 */
    PLUGIN_DROP     =  1,   /* 静默丢弃当前消息/帧 */
    PLUGIN_ERROR    = -1,   /* 插件内部错误：视同 PLUGIN_OK 继续，但打 WARN 日志 */
} plugin_result_t;

/* ── 插件描述符 ───────────────────────────────────────────────────────────
 * 分配在全局/静态区，链入 plugin_chain。
 *
 * priority: 越小越先执行（0 最高优先级）
 * init:      返回 0=成功，<0=失败（中止后续 init 并回滚已初始化的插件），NULL=跳过
 * shutdown:  NULL=无需清理；按 init 反序调用（依赖反转保证）
 * init_success: 框架内部标志，插件作者勿设（init 成功时框架置 1）
 */
typedef struct plugin_s {
    const char     *name;
    int             priority;
    int             init_success;  /* 框架内部：1=init 已成功（用于回滚和 shutdown） */

    /* HP-4: 应用数据入站。data/len 可原地修改。
     *       框架强制校验 *len ∈ [0,cap]，超限视为错误丢弃。
     *       PLUGIN_ERROR 返回时强烈建议不修改 data/len（语义模糊区域）。 */
    plugin_result_t (*on_app_data_in)(struct channel_s *ch,
                                      uint8_t *data, int *len, int cap);

    /* HP-7: 通道生命周期 */
    void (*on_channel_create)(struct channel_s *ch);
    void (*on_channel_destroy)(struct channel_s *ch);

    /* 初始化/清理（NULL=无需） */
    int  (*init)(global_ctx_t *ctx);
    void (*shutdown)(global_ctx_t *ctx);

    struct plugin_s *next;
} plugin_t;

/* ── 公开 API ──────────────────────────────────────────────────────────── */

/* 注册插件（链入全局 ctx->plugin_chain，按 priority 排序，拒绝重复注册） */
void plugin_register(global_ctx_t *ctx, plugin_t *p);

/* HP-4 调用：空链时短路返回 PLUGIN_OK */
plugin_result_t plugin_invoke_app_data_in(global_ctx_t *ctx, struct channel_s *ch,
                                          uint8_t *data, int *len, int cap);
/* HP-7 调用：空链时短路（不调用任何插件） */
void plugin_invoke_channel_create(global_ctx_t *ctx, struct channel_s *ch);
void plugin_invoke_channel_destroy(global_ctx_t *ctx, struct channel_s *ch);

/* 初始化/清理所有已注册插件（init 顺序调用，shutdown 反序调用） */
int  plugin_init_all(global_ctx_t *ctx);
void plugin_shutdown_all(global_ctx_t *ctx);

#endif /* GAPPROXY_PLUGIN_H */
