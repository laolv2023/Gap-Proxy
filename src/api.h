/*
 * api.h - HTTP API 管理接口模块
 *
 * 基于 Mongoose 库提供 REST API 端点：
 *   GET  /api/v1/status     - 系统健康状态
 *   GET  /api/v1/config     - 获取运行配置（密钥脱敏）
 *   POST /api/v1/reload     - 触发配置热重载
 *   GET  /api/v1/channels   - 列出全部通道
 *   GET  /api/v1/channels/:id - 通道详情
 *   POST /api/v1/channels   - 动态添加通道
 *   PUT  /api/v1/channels/:id - 动态修改通道
 *   DELETE /api/v1/channels/:id - 动态删除通道
 *   GET  /api/v1/stats      - 全局统计
 *   GET  /api/v1/logs       - 最近日志条目
 */

#ifndef API_H
#define API_H

#include "types.h"

/* 初始化 API 服务器（从 ctx->config.api 读取配置） */
int  api_init(global_ctx_t *ctx);

/* 非阻塞 API 事件轮询（在主循环中调用，timeout=0） */
void api_poll(global_ctx_t *ctx);

/* 停止 API 服务器并释放资源 */
void api_shutdown(global_ctx_t *ctx);
void log_shutdown(void);

/* ============================================================================
 * TEST_BUILD 测试桥接 — 暴露静态 handler 供单元测试使用
 * ============================================================================ */
#ifdef TEST_BUILD

struct mg_connection;
struct mg_http_message;

void test_api_set_ctx(global_ctx_t *ctx);
global_ctx_t *test_api_get_ctx(void);

int  test_api_check_auth(struct mg_connection *c, struct mg_http_message *hm);
int  test_api_check_rate_limit(struct mg_connection *c, struct mg_http_message *hm);
void test_api_generate_token(char *buf, size_t len);

void test_api_handle_status(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_config(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_nodes(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_node_by_id(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_node_instances(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_channels(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_channel_by_id(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_stats(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_logs(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_sessions(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_session_by_id(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_metrics(struct mg_connection *c, struct mg_http_message *hm);
void test_api_handle_config_switch(struct mg_connection *c, struct mg_http_message *hm);

#endif /* TEST_BUILD */

#endif /* API_H */
