# Gap-Proxy (gapproxy)

## 项目简介

`gapproxy` 是一个 **Linux 用户空间二层代理隧道系统**，通过 **AF_PACKET 原始套接字**直接在数据链路层（OSI 第 2 层）收发以太网帧，完全绕过 Linux 内核 TCP/IP 协议栈。系统集成 **KCP 协议**（一种基于 UDP 的可靠传输协议）提供 ARQ 可靠传输能力，支持**透明 TCP/UDP 代理**和**多流复用**（多通道），适用于需要低延迟、高吞吐、完全旁路内核网络的特殊场景。

```
客户端 ──TCP/UDP──► Frontend 节点 ──AF_PACKET(KCP)──► Backend 节点 ──TCP/UDP──► 服务端
     透明代理          仅需 MAC/EtherType            仅需 MAC/EtherType         透明代理
```

**版本**: 1.0.0 | **语言**: C (GNU11) | **平台**: Linux (≥ 2.6.31) | **代码规模**: ~16,000 行核心 + ~40,000 行测试

---

## 核心特性

| 特性 | 说明 |
|------|------|
| 🔌 **纯链路层通信** | 基于 AF_PACKET + 自定义 EtherType，无需 IP 地址配置、无需路由表 |
| 🔄 **透明 TCP/UDP 代理** | Frontend 代理（本地监听 → 远端转发）和 Backend 代理（远端请求 → 本地服务），对应用透明 |
| 📦 **KCP 可靠 ARQ 传输** | 集成 KCP (ikcp) 协议，提供可配置的自动重传、流量控制和拥塞控制 |
| 🔀 **多流复用** | 每个通道独立 KCP 实例和 7 状态状态机（CLOSED/SYN_SENT/SYN_RCVD/ESTABLISHED/FIN_SENT/FIN_RCVD/CLOSED_ZOMBIE） |
| 🔐 **国密加密与校验** | SM4-CBC 加密 + SM3-HMAC 完整性校验，Encrypt-then-MAC 安全设计 |
| 🚀 **高性能设计** | epoll 边缘触发 I/O（EPOLLET）、TPACKET_V2 零拷贝、非阻塞套接字、KCP 背压机制 |
| 📡 **多实例部署** | Master-Worker 架构（Nginx 风格），单 Master 管理最多 64 个 Worker，支持 CPU 亲和性绑定 |
| 🔍 **BPF 内核过滤** | Berkeley Packet Filter 在内核层按 EtherType 过滤帧，减少用户态开销 |
| 🛡️ **集群管理** | Manager-Worker 远程配置推送、健康检查、远程实例调度（SPAWN/KILL） |
| 🔄 **热重载** | SIGHUP 触发配置热重载，通道增量 diff，不影响已有连接 |
| 🎛️ **通道动态管理** | SIGUSR1 CTL 信号触发 JSON 指令，支持运行时 add/del 通道；CHANNEL_CTL 可转发到 SPAWN Worker |
| 🌐 **HTTP 管理 API** | RESTful API（`/api/v1/status`、`/api/v1/instances/spawn` 等 15+ 端点），Bearer Token 认证 |
| 🔌 **插件系统** | 支持数据入站/通道生命周期 hook point，可扩展数据面处理 |
| 📊 **全面监控** | 通道级/全局级统计计数器，CLI 管理工具（`gapproxy-cli`），远程 syslog |

---

## 模块架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Gap-Proxy 架构                           │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    应用层 (Application)                          │    │
│  │            TCP/UDP 透明代理 (proxy.c 2089行)                     │    │
│  │      local_fd ◄──► recv_buf ◄──► KCP                           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                │                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                  可靠传输层 (Reliable Transport)                  │    │
│  │       KCP / ikcp: ARQ · 流量控制 · 分段重组 · 拥塞控制            │    │
│  │       kcp_wrap.c — 封装适配层（393行）                          │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                │                                         │
│  ┌──────────────────────────────────┐  ┌──────────────────────────┐     │
│  │   通道层 (Channel Layer)         │  │  安全层 (Security)       │     │
│  │   channel.c (2473行)             │  │  crypto.c — SM4-CBC+SM3  │     │
│  │   7 状态机 · SYN/ACK/FIN/RST    │  │  myproto.c — 9字节紧凑帧 │     │
│  │   心跳检测 · 超时回收           │  │  acl.c — IP ACL 匹配     │     │
│  └──────────────────────────────────┘  └──────────────────────────┘     │
│                                │                                         │
│  ┌──────────────────────────────────┐  ┌──────────────────────────┐     │
│  │  AF_PACKET 层 (af_packet.c)     │  │  管理面 (Control Plane)   │     │
│  │  TPACKET_V2 环形缓冲区          │  │  mgmt.c (2465行)          │     │
│  │  BPF 内核过滤                   │  │  Manager↔Worker JSON协议  │     │
│  │  TX/RX 零拷贝                   │  │  api.c — HTTP REST API    │     │
│  └──────────────────────────────────┘  └──────────────────────────┘     │
│                                                                          │
│  ┌──────────────────────────────────┐  ┌──────────────────────────┐     │
│  │  插件系统 (plugin.c)             │  │  CLI 工具 (cli.c)        │     │
│  │  HP-4: 数据入站                  │  │  gapproxy-cli — 独立进   │     │
│  │  HP-7: 通道生命周期              │  │  程，HTTP/JSON 交互      │     │
│  └──────────────────────────────────┘  └──────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────┘
```

### 模块清单（24 个源文件）

| 模块 | 文件 | 行数 | 职责 |
|------|------|:---:|------|
| **主程序** | `main.c` | 5,204 | 启动/信号处理/配置加载/Worker 管理/CTL 执行 |
| **通道管理** | `channel.c` / `.h` | 2,473 | 7 状态状态机、SYN/ACK/FIN/RST 握手、心跳、超时回收 |
| **Mongoose API** | `api.c` / `.h` | 2,420 | HTTP REST API 15+ 端点、Bearer Token 认证、日志服务 |
| **管理协议** | `mgmt.c` | 2,465 | Manager↔Worker JSON 协议、SPAWN/KILL/配置推送/CHANNEL_CTL |
| **透明代理** | `proxy.c` / `.h` | 2,089 | TCP/UDP 代理、epoll 事件循环、背压控制、recv_buf 管理 |
| **AF_PACKET** | `af_packet.c` / `.h` | 1,039 | 原始套接字收发、TPACKET_V2 环形缓冲区、BPF 过滤 |
| **MyProto 协议** | `myproto.c` / `.h` | 822 | 9 字节紧凑帧头、CRC-16/CRC-32、大端序列化 |
| **加密** | `crypto.c` / `.h` | 599 | SM4-CBC 加密/SM3-HMAC、`/dev/urandom` IV |
| **CLI 工具** | `cli.c` | 595 | 独立管理客户端（`gapproxy-cli`） |
| **KCP 封装** | `kcp_wrap.c` / `.h` | 393 | ikcp 创建/销毁/参数设置、发送/接收/更新 |
| **ACL** | `acl.c` / `.h` | 118 | IP ACL 匹配引擎（CIDR/范围/精确） |
| **插件** | `plugin.c` / `.h` | 154 | 数据入站 hook (HP-4)、通道生命周期 hook (HP-7) |
| **类型定义** | `types.h` | 1,852 | 全部结构体、枚举、常量、宏定义 |
| **KCP 内核** | `ikcp.c` / `.h` | 1,614 | 第三方 KCP 协议栈（skywind3000/kcp） |

---

## 快速开始

### 第 1 步：安装依赖

```bash
# Debian/Ubuntu
sudo apt-get install -y build-essential gcc make libjson-c-dev nettle-dev

# RHEL/CentOS/Fedora
sudo dnf install -y gcc make json-c-devel nettle-devel
```

### 第 2 步：编译

```bash
cd gapproxy

# Release 构建（生产环境推荐）
make

# Debug 构建（包含调试日志）
make debug

# 编译 CLI 管理工具
make cli

# 运行全量测试（1000 用例）
make test-prod
```

### 第 3 步：运行

```bash
# 两节点最小配置示例：

# 机器 A（Frontend）— frontend.json
cat > frontend.json << 'EOF'
{
    "interface": "eth0",
    "ethertype": 35013,
    "peer_mac": "BB:BB:BB:BB:BB:BB",
    "node_type": "frontend",
    "channels": [
        {"channel_id": 1, "listen_port": 8080, "remote_port": 80,
         "listen_addr": "0.0.0.0", "remote_addr": "192.168.1.100", "is_tcp": true}
    ]
}
EOF

# 机器 B（Backend）— backend.json
cat > backend.json << 'EOF'
{
    "interface": "eth0",
    "ethertype": 35013,
    "peer_mac": "AA:AA:AA:AA:AA:AA",
    "node_type": "backend",
    "channels": [
        {"channel_id": 1, "listen_port": 8080, "remote_port": 80,
         "listen_addr": "0.0.0.0", "remote_addr": "192.168.1.100", "is_tcp": true}
    ]
}
EOF

# 分别在两台机器上启动
sudo ./gapproxy frontend.json   # 机器 A
sudo ./gapproxy backend.json    # 机器 B

# 测试
curl http://<机器A_IP>:8080
```

> **注意**：需要 `root` 权限（AF_PACKET 原始套接字需要 `CAP_NET_RAW`）。两台机器必须在同一二层网络。

---

## 配置概览

完整配置文档见 [docs/CONFIG_REF.md](docs/CONFIG_REF.md) 和 [docs/CONFIG.md](docs/CONFIG.md)。

### 全局配置（`global_config_t`）

| 字段 | 类型 | 默认值 | 说明 |
|------|------|:---:|------|
| `interface` | string | — | 网络接口名（必填） |
| `ethertype` | uint16 | 35013 | 自定义以太类型 (0x88B5) |
| `peer_mac` | MAC | — | 对端 MAC 地址 |
| `node_type` | enum | `standalone` | 节点角色：`frontend` / `backend` / `standalone` |
| `worker_type` | enum | `standalone` | Worker 类型：`frontend` / `backend` |
| `master_config_path` | path | — | Master 实例配置文件路径 |
| `max_channels` | int | 256 | 最大通道数（上限 65535） |
| `perf_max_memory_mb` | int | 0 | 内存配额上限（MB），0=禁用 |
| `management` | object | — | Manager-Worker 管理通道配置（keepalive/注册/发现） |

### 通道配置（`channel_config_t`）

| 字段 | 类型 | 默认值 | 说明 |
|------|------|:---:|------|
| `channel_id` | uint32 | — | 通道 ID（必填，全局唯一） |
| `listen_port` | uint16 | 0 | 本地监听端口 |
| `remote_port` | uint16 | 0 | 远端转发端口 |
| `listen_addr` | IP | `0.0.0.0` | 本地监听地址 |
| `remote_addr` | IP | — | 远端转发地址（仅 IP，不支持主机名） |
| `is_tcp` | bool | true | true=TCP, false=UDP |
| `enabled` | int | 1 | 热重载时控制启用/禁用 |
| `encryption_mode` | enum | 0 | 加密模式：0=plain, 1=SM4-CBC+SM3 |
| `acl_allowlist` | JSON array | [] | IP ACL 白名单 |

---

## 管理 API

HTTP 管理接口默认监听 `127.0.0.1:8080`，Bearer Token 认证。

### 端点一览

| 方法 | 端点 | 说明 |
|------|------|------|
| `GET` | `/api/v1/status` | 节点状态、Worker 列表 |
| `GET` | `/api/v1/metrics` | Prometheus 格式指标 |
| `GET` | `/api/v1/nodes` | 集群节点列表 |
| `GET` | `/api/v1/channels` | 全部通道状态 |
| `GET` | `/api/v1/sessions` | 活跃会话列表 |
| `GET` | `/api/v1/config` | 当前配置查看 |
| `POST` | `/api/v1/config/push` | 配置推送（Manager→Worker） |
| `POST` | `/api/v1/config/switch` | 实例配置切换 |
| `GET` | `/api/v1/config/version` | 配置版本号 |
| `POST` | `/api/v1/instances/spawn` | 启动新 Worker 实例 |
| `POST` | `/api/v1/instances/spawn-batch` | 批量启动 Worker 实例 |
| `POST` | `/api/v1/instances/kill` | 停止 Worker 实例 |
| `POST` | `/api/v1/instances/channels` | SPAWN 实例通道管理（add/del/status） |
| `GET` | `/api/v1/stats` | 全局流量统计 |
| `GET` | `/api/v1/logs` | 获取日志输出 |
| `POST` | `/api/v1/reload` | 触发热重载 |

### CLI 客户端

```bash
# 编译 CLI
make cli

# 查看状态
./gapproxy-cli status -s localhost:8080 -t <token>

# 查看通道
./gapproxy-cli channels -s localhost:8080 -t <token>

# 启动新 Worker
./gapproxy-cli spawn -s localhost:8080 -t <token> -c worker_config.json

# 实时跟随日志
./gapproxy-cli logs -s localhost:8080 -t <token> --follow
```

---

## 管理协议

Manager 与 Worker 通过 AF_PACKET 管理通道（`channel_id=0`）交换 JSON 消息：

| 消息类型 | 方向 | 说明 |
|------|------|------|
| `NODE_REGISTER` | Worker → Manager | Worker 注册（含节点信息） |
| `NODE_REGISTER_ACK` | Manager → Worker | 注册确认（成功/拒绝/重放检测） |
| `NODE_KEEPALIVE` | Worker → Manager | Worker 心跳 |
| `NODE_KEEPALIVE_ACK` | Manager → Worker | 心跳回复 |
| `CONFIG_PUSH` | Manager → Worker | 配置下发（全局+通道） |
| `CONFIG_PUSH_ACK` | Worker → Manager | 配置确认 |
| `CONFIG_SWITCH` | Manager → Worker | 配置文件切换指令 |
| `SPAWN_INSTANCE` | Manager → Worker | 启动新 Worker 实例 |
| `SPAWN_ACK` | Worker → Manager | SPAWN 确认 |
| `KILL_INSTANCE` | Manager → Worker | 停止 Worker 实例 |
| `CHANNEL_CTL` | Manager → Worker | 通道动态管理（add/del） |
| `CHANNEL_CTL_ACK` | Worker → Manager | 通道操作确认 |
| `NODE_UNREGISTER` | Worker → Manager | Worker 注销 |

---

## 双主机部署架构

```
主机 A (Frontend)                              主机 B (Backend)
┌────────────────────────────┐                ┌────────────────────────────┐
│                            │                │                            │
│  Master                    │   AF_PACKET    │  Master                    │
│  ┌──────────────────────┐  │  (channel_id=0)│  ┌──────────────────────┐  │
│  │ Manager (配置中心)    │◄─┼───────────────┼─►│ Manager (配置中心)    │  │
│  │ - 监听 API            │  │  NODE_REGISTER │  │ - 监听 API            │  │
│  │ - 健康检查            │  │  CONFIG_PUSH   │  │ - 健康检查            │  │
│  │ - 实例调度(SPAWN/KILL)│  │  CHANNEL_CTL   │  │ - 实例调度(SPAWN/KILL)│  │
│  └──────┬───────────────┘  │                │  └──────┬───────────────┘  │
│         │                   │                │         │                   │
│  ┌──────┴───────────────┐  │                │  ┌──────┴───────────────┐  │
│  │ Worker 1 (FRONTEND)   │◄─┼────────────────┼─►│ Worker 1 (BACKEND)   │  │
│  │ frontend_channels[]   │  │                │  │ backend_channels[]   │  │
│  └──────────────────────┘  │   AF_PACKET    │  └──────────────────────┘  │
│  ┌──────────────────────┐  │  (channel_id=N)│  ┌──────────────────────┐  │
│  │ Worker 2 (FRONTEND)   │◄─┼────────────────┼─►│ Worker 2 (BACKEND)   │  │
│  │ frontend_channels[]   │  │                │  │ backend_channels[]   │  │
│  └──────────────────────┘  │                │  └──────────────────────┘  │
│           ...               │                │           ...               │
│  (最多 64 个 Worker)        │                │  (最多 64 个 Worker)        │
│                            │                │                            │
│  ┌──────────────────────┐  │                │                            │
│  │ API :8080             │  │                │                            │
│  └──────────────────────┘  │                │                            │
└────────────────────────────┘                └────────────────────────────┘
```

**关键约束**：
- 两台主机各运行一个 Master 进程
- 每个 Master 管理多个 Worker（通过 `fork()` + `exec()` 启动）
- Worker 可绑定不同 CPU 核心（`cpu_affinity` 配置）
- 管理通道（channel_id=0）为广播模型：v1.0 中所有 Worker 共享密钥
- 数据通道（channel_id≥1）按配置分配，Frontend 和 Backend 的通道 ID 需对称对应

---

## 测试

| 层级 | 命令 | 用例数 | 覆盖范围 |
|------|------|:---:|------|
| 编译检查 | `make` ↦ `-Wall -Wextra -Werror` | — | 所有源文件零警告零错误 |
| 全量回归 | `make test-prod` | 1,000 | 7 个子套件：加密/通道/KCP/配置/管理协议/API/集成 |
| 严格标志 | `-Wconversion -Wshadow -Wformat=2` | — | 定期检查 |
| 运行时检测 | `valgrind` / `-fsanitize=address,undefined` | — | 内存/UB 检测 |

### 测试套件明细

| 套件 | 用例 | 重点 |
|------|:---:|------|
| `test_production_crypto` | 200 | SM4-CBC 加解密、SM3-HMAC、MyProto 帧序列化/CRC |
| `test_production_channel` | 200 | 7 状态状态机、SYN/ACK/FIN/RST 握手、channel_create/destroy |
| `test_production_kcp` | 170 | KCP 可靠传输、ACL 匹配引擎、拥塞控制参数 |
| `test_production_config` | 170 | 配置解析/验证、SPAWN/KILL、worker_registered |
| `test_production_mgmt` | 140 | NODE_REGISTER/CONFIG_PUSH/CHANNEL_CTL JSON 消息 |
| `test_production_api` | 120 | HTTP API 端点、Token 认证、JSON 响应 |
| `test_production_integ` | 140 | 子系统集成、压力测试、回归验证 |

### 通过标准

```
make clean && make               → 零错误零警告
make test-prod × 5               → 1000/1000 全通过
-Wconversion -Wshadow -Wformat=2 → 仅第三方代码警告
valgrind --leak-check=full       → 零泄漏
```

---

## 审计历史

自 v1.0.0 发布以来，历经 **20 轮方法论审计**（E-X），累计修复 **31 项代码缺陷**：

| 轮次 | 方法 | 发现 | 代表性问题 |
|:--:|------|:---:|------|
| E-G | 控制流/数值/API 契约 | 0 | 基础质量验证全部通过 |
| H | 死代码与可达性 | 1 | switch default 分支 ch=NULL 恒真 |
| I | 不变量安全 | 1 | channel_hash_remove 失败仍 count-- |
| J | 调用链追踪 | 1 | proxy_flush_to_local 写错误静默吞没 |
| K | 构建/文档一致性 | 1 | make test-prod 退出码仅传播最后一个 |
| L | 时间/超时 | 1 | usleep 被信号打断导致假阳性超时 |
| M | 错误注入 | 2 | crypto_enabled=0 透传密文+EPOLLOUT 忽略 |
| N | JSON 解析 | 3 | json_object_get_string(NULL)→strcmp→SIGSEGV |
| O | FD 生命周期 | 1 | listen_fd close 后未置 -1 (double-close) |
| P | 插件/资源耗尽 | 3 | ikcp OOM assert→abort、EMFILE busy-poll、KCP 背压被杀 |
| Q | 字节序/测试断言 | 3 | 3 个"永真"测试断言 |
| R | Makefile/CLI | 4 | mongoose 缺依赖、HTTP CRLF 注入、栈泄露 |
| S | 符号/反模式 | 0 | 零代码缺陷 |
| T | 格式串/严格编译 | 2 | uint64→%u 截断、0xFFFFFFFF<<32 UB |
| U | errno/KCP diff | 1 | EPOLLERR 从不查 SO_ERROR |
| V | Worker/资源上限 | 1 | kill_stuck 重复 SIGKILL |
| W | 返回值审计 | 2 | 38 处关键函数返回值静默丢弃 |
| X | Valgrind/DNS | 0 | 零代码缺陷 |

完整审计方法论见 [docs/AUDIT_METHODOLOGY.md](docs/AUDIT_METHODOLOGY.md)。

---

## 文档索引

| 文档 | 说明 |
|------|------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 系统架构设计 |
| [docs/CONFIG_REF.md](docs/CONFIG_REF.md) | 完整配置参考（所有字段、默认值、类型） |
| [docs/CONFIG.md](docs/CONFIG.md) | 配置快速指南 |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | 开发指南（构建系统、代码风格、测试框架） |
| [docs/SECURITY.md](docs/SECURITY.md) | 安全文档（加密方案、密钥管理、威胁模型、已知限制） |
| [docs/TESTING.md](docs/TESTING.md) | 测试框架使用说明 |
| [docs/AUDIT_METHODOLOGY.md](docs/AUDIT_METHODOLOGY.md) | 审计方法论（20 种方法的操作指南和 SOP） |
| [docs/CLI.md](docs/CLI.md) | CLI 管理工具使用手册 |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | 术语表 |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | 故障排查指南 |
| [docs/DEPLOY.md](docs/DEPLOY.md) | 部署指南 |

---

## 许可证 & 致谢

本项目集成以下开源组件：

- [skywind3000/kcp](https://github.com/skywind3000/kcp) — KCP 可靠传输协议（BSD/MIT）
- [json-c](https://github.com/json-c/json-c) — C 语言 JSON 解析库（MIT）
- [GNU Nettle](https://www.lysator.liu.se/~nisse/nettle/) — 加密库，提供 SM3/SM4（GPLv2+）
- [Mongoose](https://github.com/cesanta/mongoose) — 嵌入式 HTTP 服务器（MIT）

---
*最后更新：2026-06-18，基于 20 轮全量审计，v1.0.0，31 项缺陷修复后。*
