/*
 * cli.c — gapproxy 命令行工具
 *
 * 用法:
 *   gapproxy-cli <command> [args] [--json]
 *
 * 环境变量:
 *   KCP_SERVER=host:port  (默认 localhost:8080)
 *   KCP_TOKEN=bearer       (必需)
 *
 * 子命令:
 *   status [--json]                   系统状态
 *   channels [--json]                 通道列表
 *   channel <id> [--json]             通道详情
 *   sessions [--json]                 会话列表
 *   session <id> [--json]             会话详情+KCP窗口
 *   nodes [--json]                    节点列表
 *   node <id> [--json]                节点详情
 *   logs [--follow] [n]               日志 (默认20条, -f 实时)
 *   config                            当前配置 JSON
 *   metrics                           Prometheus 指标
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <netdb.h>
#include <time.h>
#include <json-c/json.h>

/* ═══════════════════════════════════════════════════════════════
 * 配置
 * ═══════════════════════════════════════════════════════════════ */

static char g_server[256]  = "localhost:8080";
static char g_token[128]   = {0};
static char g_host[128]    = "localhost";
static int  g_port         = 8080;
static int  g_json_mode    = 0;

/* ═══════════════════════════════════════════════════════════════
 * HTTP 客户端 (RAW socket, 不依赖 libcurl)
 * ═══════════════════════════════════════════════════════════════ */

static int http_get(const char *path, char **out, size_t *out_len)
{
    /* 拒绝含 CR/LF 的路径，防止 HTTP 请求头注入 */
    if (strpbrk(path, "\r\n")) {
        fprintf(stderr, "Invalid path (contains CR/LF)\n");
        return -1;
    }
    char req[1024];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Authorization: Bearer %s\r\n"
        "Accept: application/json\r\n"
        "\r\n", path, g_host, g_token);
    if (req_len < 0 || req_len >= (int)sizeof(req)) {
        fprintf(stderr, "http_get: request too long (%d bytes)\n", req_len);
        return -1;
    }

    struct addrinfo hints = {0}, *ai;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", g_port);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_host, port_str, &hints, &ai) != 0) {
        fprintf(stderr, "DNS: %s\n", g_host); return -1;
    }

    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) { perror("socket"); freeaddrinfo(ai); return -1; }

    struct sockaddr_in addr;
    memcpy(&addr, ai->ai_addr, sizeof(addr));

    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    send(fd, req, (size_t)req_len, 0);

    size_t cap = 65536;
    char *buf = (char *)malloc(cap);
    if (!buf) { close(fd); return -1; }
    size_t total = 0;

    for (;;) {
        if (total + 4096 > cap) {
            cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) { free(buf); close(fd); return -1; }
            buf = nb;
        }
        ssize_t n = recv(fd, buf + total, cap - total - 1, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';

    /* 跳过 HTTP 头，找到 JSON 体 */
    char *body_start = strstr(buf, "\r\n\r\n");
    if (!body_start) { free(buf); return -1; }
    body_start += 4;

    size_t body_len = strlen(body_start);
    char *body = (char *)malloc(body_len + 1);
    if (!body) { free(buf); return -1; }
    memcpy(body, body_start, body_len + 1);
    free(buf);

    *out = body;
    *out_len = body_len;
    return 0;
}

static int http_post(const char *path, const char *json_body, char **out, size_t *out_len)
{
    /* 拒绝含 CR/LF 的路径，防止 HTTP 请求头注入 */
    if (strpbrk(path, "\r\n")) {
        fprintf(stderr, "Invalid path (contains CR/LF)\n");
        return -1;
    }
    char req[8192];
    int req_len = snprintf(req, sizeof(req),
        "POST %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Authorization: Bearer %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s", path, g_host, g_token, strlen(json_body), json_body);
    if (req_len < 0 || req_len >= (int)sizeof(req)) {
        fprintf(stderr, "http_post: request too long (%d bytes)\n", req_len);
        return -1;
    }

    struct addrinfo hints = {0}, *ai;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", g_port);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_host, port_str, &hints, &ai) != 0) {
        fprintf(stderr, "DNS: %s\n", g_host); return -1;
    }

    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) { perror("socket"); freeaddrinfo(ai); return -1; }

    struct sockaddr_in addr;
    memcpy(&addr, ai->ai_addr, sizeof(addr));

    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); close(fd); return -1;
    }
    send(fd, req, (size_t)req_len, 0);

    size_t cap = 65536;
    char *buf = (char *)malloc(cap);
    if (!buf) { close(fd); return -1; }
    size_t total = 0;
    for (;;) {
        if (total + 4096 > cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { free(buf); close(fd); return -1; } buf = nb; }
        ssize_t n = recv(fd, buf + total, cap - total - 1, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';
    char *body_start = strstr(buf, "\r\n\r\n");
    if (!body_start) { free(buf); return -1; }
    body_start += 4;
    size_t body_len = strlen(body_start);
    char *body = (char *)malloc(body_len + 1);
    if (!body) { free(buf); return -1; }
    memcpy(body, body_start, body_len + 1);
    free(buf);
    *out = body;
    *out_len = body_len;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * JSON 辅助
 * ═══════════════════════════════════════════════════════════════ */

static const char *js(struct json_object *o, const char *k) {
    struct json_object *v;
    if (!json_object_object_get_ex(o, k, &v)) return "-";
    return json_object_get_string(v);
}
static int64_t ji(struct json_object *o, const char *k) {
    struct json_object *v;
    if (!json_object_object_get_ex(o, k, &v)) return 0;
    return json_object_get_int64(v);
}

#define JS(o,k) js((o),(k))
#define JI(o,k) ji((o),(k))

/* ═══════════════════════════════════════════════════════════════
 * 格式化输出
 * ═══════════════════════════════════════════════════════════════ */

static void print_raw(const char *body) { printf("%s\n", body); }

/* ═══════════════════════════════════════════════════════════════
 * 子命令
 * ═══════════════════════════════════════════════════════════════ */

static void cmd_status(void)
{
    char *body; size_t len;
    if (http_get("/api/v1/status", &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }
    if (g_json_mode) { print_raw(body); free(body); return; }

    struct json_object *o = json_tokener_parse(body);
    free(body);
    if (!o) { fprintf(stderr, "JSON parse error\n"); return; }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║         gapproxy Status              ║\n");
    printf("╠══════════════════════════════════════════╣\n");
    printf("║  %-6s: %-29s ║\n", "Node",   JS(o,"node_id"));
    printf("║  %-6s: %-29s ║\n", "Role",   JS(o,"role"));
    printf("║  %-6s: %-29s ║\n", "Ver",    JS(o,"version"));
    printf("║  %-6s: %-10s Workers: %-12s ║\n",
           "Uptime", JS(o,"uptime_seconds"), JS(o,"worker_count"));
    printf("║  Active: %-8s Memory: %-12s ║\n",
           JS(o,"active_channels"), JS(o,"memory_used_bytes"));
    printf("╠══════════════════════════════════════════╣\n");

    struct json_object *nic;
    if (json_object_object_get_ex(o, "nic", &nic)) {
        printf("║ NIC  rx: %8s pkts %10s B  ║\n",
               JS(nic,"rx_packets"), JS(nic,"rx_bytes"));
        printf("║      tx: %8s pkts %10s B  ║\n",
               JS(nic,"tx_packets"), JS(nic,"tx_bytes"));
        printf("║   drop: %8s rx  %10s tx   ║\n",
               JS(nic,"rx_dropped"), JS(nic,"tx_dropped"));
    }
    printf("╚══════════════════════════════════════════╝\n");
    json_object_put(o);
}

static void cmd_channels(void)
{
    char *body; size_t len;
    if (http_get("/api/v1/channels", &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }
    if (g_json_mode) { print_raw(body); free(body); return; }

    struct json_object *arr = json_tokener_parse(body);
    free(body);
    if (!arr) { fprintf(stderr, "JSON parse error\n"); return; }

    int n = json_object_array_length(arr);
    printf("%-4s %-8s %-6s %-10s %-20s %-20s\n",
           "ID", "Mode", "Proto", "Listen", "Local", "Remote");
    printf("──── ──────── ────── ────────── ──────────────────── ────────────────────\n");
    for (int i = 0; i < n; i++) {
        struct json_object *ch = json_object_array_get_idx(arr, i);
        printf("%-4s %-8s %-6s %-10s %-20s %-20s\n",
               JS(ch,"id"), JS(ch,"mode"), JS(ch,"proto"),
               JS(ch,"listen_port"), JS(ch,"local_addr"), JS(ch,"remote_addr"));
    }
    printf("── %d channels ──\n", n);
    json_object_put(arr);
}

static void cmd_channel(const char *id)
{
    char path[128]; snprintf(path, sizeof(path), "/api/v1/channels/%s", id);
    char *body; size_t len;
    if (http_get(path, &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }
    if (g_json_mode) { print_raw(body); free(body); return; }

    struct json_object *o = json_tokener_parse(body);
    free(body);
    if (!o) { fprintf(stderr, "JSON parse error\n"); return; }

    printf("Channel %s:\n", id);
    printf("  Mode: %-10s Proto: %-6s State: %s\n",
           JS(o,"mode"), JS(o,"proto"), JS(o,"state"));
    printf("  Listen: %s:%s  Remote: %s:%s\n",
           JS(o,"listen_addr"), JS(o,"listen_port"),
           JS(o,"remote_addr"), JS(o,"remote_port"));
    printf("  Tx: %sB/%sP  Rx: %sB/%sP  Retrans: %s  Err: %s/%s\n",
           JS(o,"tx_bytes"), JS(o,"tx_packets"),
           JS(o,"rx_bytes"), JS(o,"rx_packets"),
           JS(o,"retransmits"), JS(o,"tx_errors"), JS(o,"rx_errors"));

    struct json_object *rt;
    if (json_object_object_get_ex(o, "runtime", &rt)) {
        printf("  State: %-10s RTT: %sms  Window: %s/%s/%s\n",
               JS(rt,"state"), JS(rt,"rtt_ms"),
               JS(rt,"snd_wnd"), JS(rt,"rcv_wnd"), JS(rt,"rmt_wnd"));
        printf("  snd_una=%s snd_nxt=%s rcv_nxt=%s cwnd=%s inflight=%s\n",
               JS(rt,"snd_una"), JS(rt,"snd_nxt"), JS(rt,"rcv_nxt"),
               JS(rt,"cwnd"), JS(rt,"inflight"));
    }
    json_object_put(o);
}

static void cmd_sessions(void)
{
    char *body; size_t len;
    if (http_get("/api/v1/sessions", &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }
    if (g_json_mode) { print_raw(body); free(body); return; }

    struct json_object *arr = json_tokener_parse(body);
    free(body);
    if (!arr) { fprintf(stderr, "JSON parse error\n"); return; }

    int n = json_object_array_length(arr);
    printf("%-4s %-10s %-8s %-6s %8s %8s %6s %6s\n",
           "Ch", "State", "Role", "Proto", "TxB", "RxB", "RTTms", "Retr");
    printf("──── ───────── ──────── ────── ──────── ──────── ────── ──────\n");
    for (int i = 0; i < n; i++) {
        struct json_object *s = json_object_array_get_idx(arr, i);
        printf("%-4s %-10s %-8s %-6s %8s %8s %6s %6s\n",
               JS(s,"channel_id"), JS(s,"state"), JS(s,"role"),
               JS(s,"protocol"), JS(s,"tx_bytes"), JS(s,"rx_bytes"),
               JS(s,"rtt_ms"), JS(s,"retransmits"));
    }
    printf("── %d sessions ──\n", n);
    json_object_put(arr);
}

static void cmd_session(const char *id)
{
    char path[128]; snprintf(path, sizeof(path), "/api/v1/sessions/%s", id);
    char *body; size_t len;
    if (http_get(path, &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }
    if (g_json_mode) { print_raw(body); free(body); return; }

    struct json_object *o = json_tokener_parse(body);
    free(body);
    if (!o) { fprintf(stderr, "JSON parse error\n"); return; }

    printf("Session %s:\n", id);
    printf("  Channel: %-4s  State: %-8s  Role: %-6s  Proto: %s\n",
           JS(o,"channel_id"), JS(o,"state"), JS(o,"role"), JS(o,"protocol"));
    printf("  Tx: %sB/%sP  Rx: %sB/%sP  RTT: %sms  Retrans: %s\n",
           JS(o,"tx_bytes"), JS(o,"tx_packets"),
           JS(o,"rx_bytes"), JS(o,"rx_packets"),
           JS(o,"rtt_ms"), JS(o,"retransmits"));
    printf("  KCP: snd_una=%s snd_nxt=%s rcv_nxt=%s\n",
           JS(o,"snd_una"), JS(o,"snd_nxt"), JS(o,"rcv_nxt"));
    printf("       snd_wnd=%s rcv_wnd=%s rmt_wnd=%s\n",
           JS(o,"snd_wnd"), JS(o,"rcv_wnd"), JS(o,"rmt_wnd"));
    printf("       cwnd=%s inflight=%s rx_srto=%s rx_rto=%s\n",
           JS(o,"cwnd"), JS(o,"inflight"), JS(o,"rx_srtt"), JS(o,"rx_rto"));
    printf("       last_active: %ss ago\n", JS(o,"last_active_sec"));
    json_object_put(o);
}

static void cmd_nodes(void)
{
    char *body; size_t len;
    if (http_get("/api/v1/nodes", &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }
    if (g_json_mode) { print_raw(body); free(body); return; }

    struct json_object *o = json_tokener_parse(body);
    free(body);
    if (!o) { fprintf(stderr, "JSON parse error\n"); return; }

    printf("%-20s %-10s %6s %8s\n",
           "Node ID", "State", "Delta", "LastSeen");
    printf("──────────────────── ────────── ────── ────────\n");

    struct json_object *arr;
    if (json_object_object_get_ex(o, "workers", &arr)) {
        int n = json_object_array_length(arr);
        for (int i = 0; i < n; i++) {
            struct json_object *w = json_object_array_get_idx(arr, i);
            printf("%-20s %-10s %6s %8ss\n",
                   JS(w,"node_id"), JS(w,"state"),
                   JS(w,"config_version_delta"), JS(w,"last_seen"));
        }
        printf("── %d workers ──\n", n);
    }
    json_object_put(o);
}

static void cmd_node(const char *id)
{
    char path[128]; snprintf(path, sizeof(path), "/api/v1/nodes/%s", id);
    char *body; size_t len;
    if (http_get(path, &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }
    if (g_json_mode) { print_raw(body); free(body); return; }

    struct json_object *o = json_tokener_parse(body);
    free(body);
    if (!o) { fprintf(stderr, "JSON parse error\n"); return; }

    printf("Node %s:\n", id);
    printf("  State: %-10s  Registered: %s  Last seen: %ss ago\n",
           JS(o,"state"), JS(o,"registered_at"), JS(o,"last_seen"));
    printf("  Config delta: %-6s  Health resp: %-5s  Degraded: %s\n",
           JS(o,"config_version_delta"), JS(o,"health_resp_count"),
           JS(o,"degraded_since"));

    struct json_object *arr;
    if (json_object_object_get_ex(o, "instances", &arr)) {
        int n = json_object_array_length(arr);
        printf("  Instances (%d):\n", n);
        for (int i = 0; i < n; i++) {
            struct json_object *inst = json_object_array_get_idx(arr, i);
            printf("    %-20s pid=%-6s type=%-8s eth=%-6s restarts=%s\n",
                   JS(inst,"instance_name"), JS(inst,"pid"),
                   JS(inst,"node_type"), JS(inst,"ethertype"),
                   JS(inst,"restart_count"));
        }
    }
    json_object_put(o);
}

static void cmd_logs(int n, int follow)
{
    char path[128];
    snprintf(path, sizeof(path), "/api/v1/logs");

    while (1) {
        char *body; size_t len;
        if (http_get(path, &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }

        struct json_object *arr = json_tokener_parse(body);
        free(body);
        if (!arr) { fprintf(stderr, "JSON parse error\n"); return; }

        int total = json_object_array_length(arr);
        int start = (total > n) ? total - n : 0;
        for (int i = start; i < total; i++) {
            struct json_object *e = json_object_array_get_idx(arr, i);
            const char *lvls[] = {"DBG","INF","WRN","ERR"};
            int lvl = (int)JI(e, "level");
            printf("[%s] %s  %s\n",
                   (lvl >= 0 && lvl < 4) ? lvls[lvl] : "???",
                   JS(e,"timestamp"), JS(e,"message"));
        }
        json_object_put(arr);

        if (!follow) break;
        sleep(2);
    }
}

static void cmd_metrics(void)
{
    char *body; size_t len;
    if (http_get("/api/v1/metrics", &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }
    printf("%s", body);
    free(body);
}

static void cmd_config(void)
{
    char *body; size_t len;
    if (http_get("/api/v1/config", &body, &len) < 0) { fprintf(stderr, "request failed\n"); return; }
    struct json_object *o = json_tokener_parse(body);
    free(body);
    if (!o) { fprintf(stderr, "JSON parse error\n"); return; }
    printf("%s\n", json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY));
    json_object_put(o);
}

static void cmd_spawn_batch(int argc, char **argv)
{
    const char *targets = NULL;
    const char *channels = NULL;
    const char *ethertype = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i+1 < argc) targets = argv[++i];
        else if (strcmp(argv[i], "-c") == 0 && i+1 < argc) channels = argv[++i];
        else if (strcmp(argv[i], "-e") == 0 && i+1 < argc) ethertype = argv[++i];
    }
    if (!targets) { fprintf(stderr, "Usage: spawn-batch -t \"w1,w2\" -c '[{...}]' [-e 0x88B5]\n"); return; }

    /* 构造 JSON body */
    char body[8192];
    int off = snprintf(body, sizeof(body), "{\"targets\":[");
    const char *p = targets;
    int first = 1;
    while (*p) {
        const char *start = p;
        while (*p && *p != ',') p++;
        if (!first) off += snprintf(body+off, sizeof(body)-off, ",");
        off += snprintf(body+off, sizeof(body)-off, "\"%.*s\"", (int)(p-start), start);
        if (*p == ',') p++;
        first = 0;
    }
    off += snprintf(body+off, sizeof(body)-off, "]");
    if (ethertype) off += snprintf(body+off, sizeof(body)-off, ",\"ethertype\":%s", ethertype);
    if (channels) off += snprintf(body+off, sizeof(body)-off, ",\"channels\":%s", channels);
    off += snprintf(body+off, sizeof(body)-off, "}");

    char *resp; size_t rlen;
    int ret = http_post("/api/v1/instances/spawn-batch", body, &resp, &rlen);
    if (ret < 0) { fprintf(stderr, "request failed\n"); return; }
    struct json_object *o = json_tokener_parse(resp);
    free(resp);
    if (!o) { fprintf(stderr, "JSON parse error\n"); return; }
    printf("%s\n", json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY));
    json_object_put(o);
}

/* ═══════════════════════════════════════════════════════════════
 * 主入口
 * ═══════════════════════════════════════════════════════════════ */

static void usage(void)
{
    printf("gapproxy-cli — 可观测工具\n\n"
           "环境: KCP_SERVER=host:port  KCP_TOKEN=bearer\n\n"
           "命令:\n"
           "  status                 系统状态\n"
           "  channels               通道列表\n"
           "  channel <id>           通道详情\n"
           "  sessions               会话列表\n"
           "  session <id>           会话详情 + KCP 窗口\n"
           "  nodes                  节点列表\n"
           "  node <id>              节点详情 + 实例\n"
           "  logs [-f] [n]          日志 (默认20条, -f 实时)\n"
           "  metrics                Prometheus 指标\n"
           "  config                 当前配置\n"
           "  spawn-batch -t <w1,w2> -c <channels> [-e eth]\n"
           "                         批量 SPAWN\n"
           "  --json                 原始 JSON 输出\n");
}

int main(int argc, char **argv)
{
    /* 读取配置 */
    const char *env = getenv("KCP_SERVER");
    if (env) { strncpy(g_server, env, 255); g_server[255] = '\0'; }
    env = getenv("KCP_TOKEN");
    if (env) { strncpy(g_token, env, 127); g_token[127] = '\0'; }

    /* 解析 host:port */
    char *colon = strchr(g_server, ':');
    if (colon) {
        *colon = '\0';
        strncpy(g_host, g_server, 127);
        g_host[127] = '\0';
        g_port = atoi(colon + 1);
        *colon = ':';
    }

    if (g_token[0] == 0) {
        fprintf(stderr, "Error: KCP_TOKEN not set\n");
        return 1;
    }

    if (argc < 2) { usage(); return 1; }

    const char *cmd = argv[1];
    int json_flag = (argc > 2 && strcmp(argv[argc-1], "--json") == 0);
    if (json_flag) g_json_mode = 1;

    if (strcmp(cmd, "status") == 0)        cmd_status();
    else if (strcmp(cmd, "channels") == 0) cmd_channels();
    else if (strcmp(cmd, "channel") == 0 && argc > 2) cmd_channel(argv[2]);
    else if (strcmp(cmd, "sessions") == 0) cmd_sessions();
    else if (strcmp(cmd, "session") == 0 && argc > 2) cmd_session(argv[2]);
    else if (strcmp(cmd, "nodes") == 0)    cmd_nodes();
    else if (strcmp(cmd, "node") == 0 && argc > 2) cmd_node(argv[2]);
    else if (strcmp(cmd, "logs") == 0) {
        int n = 20, follow = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--follow") == 0) follow = 1;
            else if (strcmp(argv[i], "--json") != 0) n = atoi(argv[i]);
        }
        cmd_logs(n, follow);
    }
    else if (strcmp(cmd, "metrics") == 0)  cmd_metrics();
    else if (strcmp(cmd, "config") == 0)   cmd_config();
    else if (strcmp(cmd, "spawn-batch") == 0) cmd_spawn_batch(argc-2, argv+2);
    else { usage(); return 1; }

    return 0;
}
