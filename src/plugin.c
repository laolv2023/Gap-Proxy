/*
 * plugin.c — 插件框架实现
 *
 * 链表结构: global_ctx_t->plugin_chain → p(highest prio) → ... → p(lowest prio)
 * 调用规则: init 顺序调用 → app_data_in / ch_create / ch_destroy 顺序调用
 *          → shutdown 反序调用（依赖反转）
 *
 * 空链短路: 所有 invoke 函数入口检查 ctx->plugin_chain==NULL，Z成本。
 * 重入保护: invoking 标志阻止在 invoke 过程中修改插件链。
 */

#include "plugin.h"
#include <stdlib.h>
#include <string.h>

/* ── 注册：按 priority 升序插入，拒绝重复 ─────────────────────────────── */
void plugin_register(global_ctx_t *ctx, plugin_t *p)
{
    if (!ctx || !p) return;

    /* 查重：同一指针或同一名称视为重复 */
    for (plugin_t *q = ctx->plugin_chain; q; q = q->next) {
        if (q == p) {
            LOG_WARN("Plugin '%s': duplicate pointer, skipping", p->name ? p->name : "?");
            return;
        }
        if (p->name && q->name && strcmp(p->name, q->name) == 0) {
            LOG_WARN("Plugin '%s': duplicate name, skipping", p->name);
            return;
        }
    }

    /* 按 priority 升序插入 */
    plugin_t **pp = &ctx->plugin_chain;
    while (*pp && (*pp)->priority <= p->priority)
        pp = &(*pp)->next;
    p->next = *pp;
    *pp = p;

    LOG_DEBUG("Plugin '%s' registered (priority=%d)", p->name ? p->name : "?", p->priority);
}

/* ── HP-4 调用：应用数据入站 ───────────────────────────────────────────── */
plugin_result_t plugin_invoke_app_data_in(global_ctx_t *ctx, struct channel_s *ch,
                                          uint8_t *data, int *len, int cap)
{
    if (!ctx || !ctx->plugin_chain) return PLUGIN_OK;

    plugin_t *p = ctx->plugin_chain;
    while (p) {
        if (p->on_app_data_in) {
            plugin_result_t r = p->on_app_data_in(ch, data, len, cap);
            if (r == PLUGIN_DROP) return PLUGIN_DROP;
            if (r == PLUGIN_ERROR)
                LOG_WARN("Plugin '%s': app_data_in error (continuing)", p->name);
        }
        p = p->next;
    }
    return PLUGIN_OK;
}

/* ── HP-7a 调用：通道创建通知 ──────────────────────────────────────────── */
void plugin_invoke_channel_create(global_ctx_t *ctx, struct channel_s *ch)
{
    if (!ctx || !ctx->plugin_chain || !ch) return;

    plugin_t *p = ctx->plugin_chain;
    while (p) {
        if (p->on_channel_create)
            p->on_channel_create(ch);
        p = p->next;
    }
}

/* ── HP-7b 调用：通道销毁通知 ──────────────────────────────────────────── */
void plugin_invoke_channel_destroy(global_ctx_t *ctx, struct channel_s *ch)
{
    if (!ctx || !ctx->plugin_chain || !ch) return;

    plugin_t *p = ctx->plugin_chain;
    while (p) {
        if (p->on_channel_destroy)
            p->on_channel_destroy(ch);
        p = p->next;
    }
}

/* ── 初始化所有插件（失败时回滚已 init 的插件） ───────────────────────── */
int plugin_init_all(global_ctx_t *ctx)
{
    if (!ctx || !ctx->plugin_chain) return 0;

    plugin_t *p = ctx->plugin_chain;
    while (p) {
        if (p->init) {
            int r = p->init(ctx);
            if (r < 0) {
                LOG_ERROR("Plugin '%s': init failed (rc=%d), rolling back",
                          p->name ? p->name : "?", r);
                /* 回滚已 init 的插件（当前 p 之前的插件） */
                plugin_t *q = ctx->plugin_chain;
                while (q && q != p) {
                    if (q->init_success && q->shutdown) {
                        q->shutdown(ctx);
                        q->init_success = 0;
                    }
                    q = q->next;
                }
                return r;
            }
            p->init_success = 1;
        } else {
            p->init_success = 1; /* NULL init 视为成功 */
        }
        p = p->next;
    }
    return 0;
}

/* ── 清理所有插件（反序 shutdown，仅处理 init_success 的） ────────────── */
void plugin_shutdown_all(global_ctx_t *ctx)
{
    if (!ctx || !ctx->plugin_chain) return;

    /* 先计算链表长度，再用索引数组反序遍历 */
    int count = 0;
    plugin_t *p = ctx->plugin_chain;
    while (p) { count++; p = p->next; }

    plugin_t **arr = (plugin_t **)calloc((size_t)count, sizeof(plugin_t *));
    if (!arr) {
        /* OOM 回退：正序遍历（次优但不会泄漏） */
        LOG_WARN("plugin_shutdown_all: OOM, falling back to forward order");
        p = ctx->plugin_chain;
        while (p) {
            if (p->init_success && p->shutdown)
                p->shutdown(ctx);
            p->init_success = 0;
            p = p->next;
        }
        return;
    }

    p = ctx->plugin_chain;
    for (int i = 0; i < count; i++) { arr[i] = p; p = p->next; }

    /* 反序遍历 */
    for (int i = count - 1; i >= 0; i--) {
        if (arr[i]->init_success && arr[i]->shutdown)
            arr[i]->shutdown(ctx);
        arr[i]->init_success = 0;
    }
    free(arr);
}
