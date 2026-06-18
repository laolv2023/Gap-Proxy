# Gap-Proxy

## 系统介绍

**Gap-Proxy** 是一个 Linux 用户空间二层代理隧道系统，通过 **AF_PACKET 原始套接字**直接在数据链路层（OSI L2）收发以太网帧，完全绕过 Linux 内核 TCP/IP 协议栈。系统集成 **KCP 协议**提供可靠 ARQ 传输，支持透明 TCP/UDP 代理和多流复用。

```
客户端 ──TCP/UDP──► Frontend ──AF_PACKET(KCP)──► Backend ──TCP/UDP──► 服务端
    透明代理        仅需 MAC/EtherType        仅需 MAC/EtherType      透明代理
```

### 部署模式

两台主机各运行一个 Master 进程，每个 Master 通过 `fork()` + `exec()` 管理多个不同方向（Frontend/Backend）的 Worker 实例：

```
主机 A (Frontend)                          主机 B (Backend)
┌──────────────────────┐                 ┌──────────────────────┐
│ Master                │   AF_PACKET    │ Master                │
│ ├─ Worker (frontend)  │◄──────────────►│ ├─ Worker (backend)   │
│ ├─ Worker (frontend)  │  (channel_id=N)│ ├─ Worker (backend)   │
│ └─ ... (最多 64)      │                 │ └─ ... (最多 64)      │
│ API :8080             │   AF_PACKET    │ API :8080             │
└──────────────────────┘  (channel_id=0) └──────────────────────┘
                         管理通道(JSON)
```

**版本**: 1.0.0 | **语言**: C (GNU11) | **平台**: Linux (≥ 2.6.31) | **代码**: ~16,000 行

---

## 系统特性

| 特性 | 说明 |
|------|------|
| **纯链路层通信** | 基于 AF_PACKET + 自定义 EtherType，无需 IP 地址配置、无需路由表 |
| **透明 TCP/UDP 代理** | Frontend 本地监听→KCP 隧道→Backend 转发至目标服务，对应用完全透明 |
| **KCP 可靠 ARQ 传输** | 集成 KCP 协议，自动重传、自适应流量控制、拥塞控制，比 TCP 快 30%-40% |
| **多流复用** | 每通道独立 KCP 实例 + 7 状态状态机（CLOSED→SYN_SENT→SYN_RCVD→ESTABLISHED→FIN_SENT→FIN_RCVD→CLOSED_ZOMBIE） |
| **国密加密与校验** | SM4-CBC 帧级加密 + SM3-HMAC 完整性校验，Encrypt-then-MAC 安全设计 |
| **Master-Worker 架构** | Nginx 风格多进程架构，单 Master 管理最多 64 个 Worker，支持 CPU 亲和性绑定 |
| **集群管理协议** | Manager↔Worker 间 13 种 JSON 管理消息：注册/心跳/配置推送/实例调度/通道管控 |
| **动态实例调度** | HTTP API 触发 SPAWN（启动新 Worker）/ KILL（停止 Worker），支持批量操作 |
| **通道热管理** | SIGHUP 热重载配置（增量 diff 不影响已有连接）+ SIGUSR1 信号触发 JSON CTL 指令（add/del 通道） |
| **HTTP 管理 API** | 16 个 RESTful 端点（`/api/v1/status`、`/api/v1/instances/spawn` 等），Bearer Token 认证 |
| **CLI 管理工具** | `gapproxy-cli` 独立命令行客户端，支持 status/channels/spawn/logs --follow |
| **高性能数据面** | epoll 边缘触发（EPOLLET）、TPACKET_V2 零拷贝环形缓冲区、BPF 内核过滤、KCP 背压保护 |
| **插件系统** | HP-4 数据入站 hook + HP-7 通道生命周期 hook，支持数据面自定义扩展 |
| **安全防护** | 管理消息序列号防重放、HMAC 恒时比较、Token 安全随机生成、IP ACL 白名单、管理通道独立加密密钥 |
| **全面可观测** | 通道/Worker/全局三级统计计数器、Prometheus 风格 metrics 端点、远程 syslog、Core dump 诊断 |

### 模块组成

```
Gap-Proxy 源码 (24 个文件)

  数据面                        控制面
  ┌─────────────┐            ┌─────────────┐
  │ proxy.c     │            │ mgmt.c      │ Manager↔Worker 管理协议
  │ channel.c   │ 7状态机    │ api.c       │ HTTP REST API
  │ af_packet.c │ L2 收发    │ cli.c       │ 命令行管理工具
  │ kcp_wrap.c  │ KCP 适配   │ plugin.c    │ 插件系统
  │ ikcp.c      │ KCP 内核   │ main.c      │ 入口/信号/Worker 管理
  │ myproto.c   │ 帧协议     └─────────────┘
  │ crypto.c    │ 加密
  │ acl.c       │ ACL
  └─────────────┘
```
