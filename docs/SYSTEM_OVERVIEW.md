# Gap-Proxy 系统总体说明

## 一、术语和定义

### 1.1 核心术语

| 术语 | 定义 |
|------|------|
| **Gap-Proxy** | 项目名称。一个 Linux 用户空间二层代理隧道系统。 |
| **AF_PACKET** | Linux 内核提供的原始套接字接口，允许用户态程序直接在数据链路层（L2）收发以太网帧，绕过内核 TCP/IP 协议栈。使用 `socket(AF_PACKET, SOCK_RAW, htons(ethertype))` 创建。 |
| **EtherType** | 以太网帧头中的 2 字节类型字段，用于标识上层协议。Gap-Proxy 使用自定义 EtherType（默认 `0x88B5`）区分本协议帧。 |
| **KCP** | KCP - A Fast and Reliable ARQ Protocol（skywind3000/kcp）。基于 UDP 思想的可靠传输协议，提供比 TCP 快 30%-40% 的吞吐量，通过可配置的自动重传（ARQ）、流量控制和拥塞控制实现可靠交付。 |
| **BPF** | Berkeley Packet Filter，Linux 内核的包过滤机制。Gap-Proxy 在 AF_PACKET 套接字上附加 BPF 程序，在内核层按 EtherType 过滤帧，避免无关帧进入用户态。 |
| **TPACKET_V2** | Linux AF_PACKET 的零拷贝环形缓冲区接口（`setsockopt(PACKET_RX_RING)` / `PACKET_TX_RING)`），用户态与内核态通过 `mmap` 共享内存区域传递帧描述符，消除 `recvfrom`/`sendto` 的数据拷贝开销。 |
| **SM4-CBC** | 国密 SM4 分组密码的 CBC 模式。128 位密钥 + 128 位随机 IV，16 字节分组，PKCS7 填充。用于帧负载加密。 |
| **SM3-HMAC** | 基于国密 SM3 哈希算法（256 位摘要，512 位块）的 HMAC。用于帧完整性校验和消息认证。 |
| **Encrypt-then-MAC** | 先加密后认证的安全设计模式：先用 SM4-CBC 加密明文 → 对密文计算 SM3-HMAC → 将 HMAC 追加到密文尾部。防止 padding oracle 等侧信道攻击。 |

### 1.2 MyProto 帧格式

Gap-Proxy 使用自定义 MyProto 协议封装 KCP 负载。已建立的通道（ESTABLISHED 状态）上所有数据帧均经过 KCP 封装后再由 MyProto 组帧。

**帧头（9 字节，紧凑布局，`__attribute__((packed))`）**：

```
Byte  0..3:  channel_id    (uint32_t, big-endian)  通道标识符
Byte  4:     flags         (uint8_t)                帧类型标志位
Byte  5..6:  payload_len   (uint16_t, big-endian)   负载长度（不含帧头和尾帧）
Byte  7..8:  header_crc    (uint16_t)               CRC-16/CCITT 帧头校验
```

**帧尾（4 字节，可选）**：

```
Byte  N..N+3: frame_crc32  (uint32_t, little-endian) CRC-32C 全帧校验
```

**帧总长度**：9（头） + 0..65535（负载） + 4（尾，可选）= 13..65548 字节

**标志位（flags）定义**：

| 位掩码 | 宏 | 含义 |
|:---:|------|------|
| `0x01` | `MPF_SYN` | 连接建立请求（三次握手第一步） |
| `0x02` | `MPF_ACK` | 确认帧（握手/数据传输确认） |
| `0x04` | `MPF_FIN` | 连接关闭请求（优雅断开） |
| `0x08` | `MPF_RST` | 连接重置（异常断开） |
| `0x10` | `MPF_DATA` | 数据帧（承载应用层数据） |
| `0x20` | `MPF_PING` | 心跳探测帧 |
| `0x40` | `MPF_PONG` | 心跳应答帧 |
| `0x80` | `MPF_CRYPTO` | 加密帧标记（负载已加密） |

**控制帧识别**：`flags & MPF_CTRL_MASK`（SYN/ACK/FIN/RST/PING/PONG）为非数据帧，走控制面处理；仅 `MPF_DATA` 帧将 KCP 负载递交给应用层。

### 1.3 节点角色（Node Role）

| 角色 | 值 | 定义 |
|------|:---:|------|
| `NONE` | 0 | 未配置角色，向后兼容旧版单进程独立运行模式 |
| `MANAGER` | 1 | Master 管理进程，负责配置分发、进程监管、信号转发、API 服务 |
| `WORKER` | 2 | Worker 工作进程，负责数据面处理（AF_PACKET + KCP + 透明代理） |

### 1.4 节点类型（Node Type）

| 类型 | 值 | 定义 |
|------|:---:|------|
| `FRONTEND` | 0 | 前端节点：接收客户端 TCP/UDP 连接，通过 KCP 隧道转发到后端 |
| `BACKEND` | 1 | 后端节点：接收前端转发的 KCP 流量，代理到目标服务 |

### 1.5 通道角色（Channel Role）— 内部运行时角色，不暴露于配置

通道角色由程序在运行时根据协议交互自动分配，用户配置文件中不存在此字段。

| 角色 | 值 | 分配时机 | 行为 |
|------|:---:|------|------|
| `INITIATOR` | 0 | LISTENER accept 新客户端后派生 | 发送 SYN 帧驱动三次握手 |
| `RESPONDER` | 1 | 收到对端 SYN 且本端无此通道时动态创建 | 回复 ACK 完成握手；根据本节点 `node_type` 确定本地动作：Frontend 连接远端服务，Backend 监听本地端口 |
| `LISTENER` | 2 | 程序启动时从 `config.channels[]` 创建 | 仅 bind+listen 本地端口，accept 后派生 INITIATOR，自身不参与 KCP 数据传输 |

### 1.6 通道状态机（Channel State）

```
CLOSED ──(SYN)──► SYN_SENT ──(ACK)──► ESTABLISHED ──(FIN)──► FIN_SENT
  ▲                   │                     │                    │
  │                   ▼                     ▼                    ▼
  │               SYN_RCVD               FIN_RCVD            CLOSED
  │                   │                     │                    │
  └───────────────────┴─────────────────────┴────────────────────┘
                        CLOSED_ZOMBIE (超时回收)
```

| 状态 | 定义 | 超时 | 进入条件 |
|------|------|:---:|------|
| `CLOSED` | 初始状态，通道未建立 | — | 通道创建/销毁后 |
| `SYN_SENT` | 已发送 SYN 帧，等待对端 ACK | 3s | 本地发起连接 |
| `SYN_RCVD` | 已收到 SYN 帧，已回复 ACK，等待确认 | 3s | 收到对端 SYN |
| `ESTABLISHED` | 连接已建立，可双向传输数据 | keepalive 超时 | 握手完成 |
| `FIN_SENT` | 已发送 FIN 帧，等待对端确认 | 3s | 本地主动关闭 |
| `FIN_RCVD` | 已收到 FIN 帧，已回复 ACK，等待本地关闭 | 3s | 收到对端 FIN |
| `CLOSED_ZOMBIE` | 等待超时回收的僵尸状态 | 5s | FIN/RST 交换完成 |

### 1.7 加密模式

| 模式 | 值 | 密钥长度 | IV 长度 | HMAC 长度 | 定义 |
|------|:---:|:---:|:---:|:---:|------|
| `NONE` | 0 | — | — | — | 不加密，payload 明文传输（仅可信内网） |
| `SM4_SM3` | 1 | 16 字节 | 16 字节 | 32 字节 | SM4-CBC + SM3-HMAC（生产推荐） |

### 1.8 通道标志（Channel Flags）

| 标志 | 值 | 定义 |
|------|:---:|------|
| `STATIC_LISTENER` | 0x01 | 静态监听通道：不被热重载销毁，仅在配置显式移除时删除 |
| `RELOAD_MARKED` | 0x02 | 热重载临时标记：新旧配置增量比对时标记残留通道以供清理 |
| `KCP_READ_PAUSED` | 0x04 | KCP 读取暂停：发送窗口高水位时暂停本地 socket 读取 |
| `MGMT_CHANNEL` | 0x08 | 管理通道标记：收发走 `mgmt_dispatch` 路径而非 proxy 转发 |

---

## 二、系统架构

### 2.1 分层架构

```
┌──────────────────────────────────────────────────────────┐
│                    应用层 (Application)                    │
│   TCP/UDP 透明代理 (proxy.c)                              │
│   local_fd ◄──► recv_buf ◄──► KCP                        │
├──────────────────────────────────────────────────────────┤
│                  可靠传输层 (Transport)                    │
│   KCP / ikcp: ARQ · 流量控制 · 分段重组 · 拥塞控制         │
│   kcp_wrap.c — 封装适配层                                │
├──────────────────────────────────────────────────────────┤
│                     安全层 (Security)                     │
│   crypto.c — SM4-CBC 加密 + SM3-HMAC 校验                │
│   myproto.c — 9 字节紧凑帧头 + CRC + 大端序列化            │
│   acl.c — IP ACL 匹配引擎                                │
├──────────────────────────────────────────────────────────┤
│                   通道层 (Channel)                        │
│   channel.c — 7 状态机 · SYN/ACK/FIN/RST 握手             │
│   心跳检测 · 超时回收 · 哈希表索引                         │
├──────────────────────────────────────────────────────────┤
│                  数据链路层 (Data Link)                    │
│   af_packet.c — AF_PACKET 原始套接字                     │
│   TPACKET_V2 环形缓冲区 · BPF 内核过滤 · TX/RX 零拷贝      │
└──────────────────────────────────────────────────────────┘
```

### 2.2 双主机部署架构

Gap-Proxy 采用两层管理模型：

- **进程层**：每台主机运行一个 **Master 进程**（通过 `--master` 启动），负责 `fork()` 和管理本地 Worker 子进程（Nginx 风格多进程模型）。Master 不进入数据面，仅处理进程监管信号（SIGCHLD/SIGHUP/SIGTERM/SIGUSR1）。
- **网络层**：集群中存在**唯一一个 Manager 节点**（`node_role: "manager"`），它是所在主机上某个 Worker 进程额外承担的管理职责。Manager 通过管理通道（`channel_id=0`）管理所有远程 Worker，提供 HTTP API、配置推送、健康检查、实例调度。

```
主机 A（Manager 节点，兼 Frontend）         主机 B（Worker 节点，兼 Backend）

┌────────────────────────┐               ┌────────────────────────┐
│ Master (进程监管)         │               │ Master (进程监管)         │
│                         │               │                         │
│  ┌───────────────────┐  │  AF_PACKET   │  ┌───────────────────┐  │
│  │ Worker-0 (MANAGER) │◄─┼──────────────┼─►│ Worker-0 (WORKER)  │  │
│  │ · HTTP API :8080   │  │ (channel_id=0)│ │ · 向 Manager 注册  │  │
│  │ · 集群管理中心       │  │  管理通道(JSON) │ │ · 接收配置推送      │  │
│  │ · 数据面(frontend)  │  │               │ │ · 响应健康检查      │  │
│  └───────────────────┘  │               │  │ · 数据面(backend)  │  │
│                         │               │  └───────────────────┘  │
│  ┌───────────────────┐  │  AF_PACKET   │  ┌───────────────────┐  │
│  │ Worker-1 (frontend) │◄─┼──────────────┼─►│ Worker-1 (backend) │  │
│  │ 纯数据面              │  │ (channel_id≥1)│ │ 纯数据面              │  │
│  └───────────────────┘  │  数据通道      │  └───────────────────┘  │
│  ┌───────────────────┐  │               │  ┌───────────────────┐  │
│  │ Worker-2 (frontend) │◄─┼──────────────┼─►│ Worker-2 (backend) │  │
│  └───────────────────┘  │               │  └───────────────────┘  │
│         ...              │               │         ...              │
│   (最多 64 Worker)       │               │   (最多 64 Worker)       │
└────────────────────────┘               └────────────────────────┘
```

### 2.3 通信模型

```
客户端 ──TCP/UDP──► Frontend Worker ──AF_PACKET(KCP)──► Backend Worker ──TCP/UDP──► 目标服务
   透明代理            仅需 MAC/EtherType                仅需 MAC/EtherType           透明代理
```

**核心约束**：
- 两台主机各启动一个 **Master 进程**（`--master kcp-multi.json`），负责 fork 和管理本地 Worker
- Manager 是**集群中唯一的管理中心**，由某台主机的一个 Worker 实例承担（配置 `node_role: "manager"`）
- Manager 自身也处理数据面（兼 Frontend/Backend），不是纯控制面节点
- 其他 Worker 配置 `node_role: "worker"`，启动时通过管理通道向 Manager 注册
- 管理通道 (`channel_id=0`) 由**双方各自的 Worker 持有**，复用数据面 AF_PACKET 套接字，承载 JSON 管理消息
- 远程管理操作（SPAWN/KILL/CONFIG_SWITCH）通过 **文件 + 信号中继**：Worker 接收管理消息 → 写临时文件 → 给本地 Master 发信号 → Master 执行
- 双方通道 ID 需对称对应：Frontend 的 channel_id=N 对 Backend 的 channel_id=N

### 2.4 主事件循环

```
main()
  ├── 解析命令行参数
  ├── 加载 JSON 配置文件
  ├── 验证配置一致性
  ├── 初始化子系统（加密/管理/代理/AF_PACKET）
  ├── 创建静态配置通道
  ├── 进入主循环 (master_loop / worker_main)
  │     │
  │     ├── epoll_wait(timeout=10ms)
  │     │     ├── EPOLLIN on raw_sock   → af_packet_recv → channel_process_frame
  │     │     ├── EPOLLIN on listen_fd  → proxy_accept → assign to channel
  │     │     ├── EPOLLIN on local_fd   → proxy_handle_local_read → channel_send_data
  │     │     ├── EPOLLOUT on local_fd  → proxy_handle_local_write → kcp_wrap_recv
  │     │     └── EPOLLIN on heartbeat_fd → 心跳/超时检查
  │     │
  │     ├── kcp_wrap_update(10ms)       → 驱动 KCP 定时器
  │     ├── channel_timeout_check       → 超时通道回收
  │     └── api_poll / mgmt_poll        → HTTP 请求 / 管理消息处理
  │
  └── cleanup → 销毁所有通道 → 释放资源 → 退出
```

### 2.5 信号处理

| 信号 | 处理方式 | 效果 |
|------|------|------|
| `SIGTERM` / `SIGINT` | `sigwaitinfo` 同步等待 | 优雅关闭：停止 Worker → 清理通道 → 退出 |
| `SIGHUP` | `sigwaitinfo` 同步等待 | 配置热重载：重新读取 JSON → 增量 diff 通道 |
| `SIGUSR1` | `sigwaitinfo` 同步等待 | 通道 CTL：读取 `ctl.json` → 执行 add/del 指令 |
| `SIGUSR2` | `sigwaitinfo` 同步等待 | 预留扩展 |
| `SIGURG` | `sigwaitinfo` 同步等待 | 配置切换：切换配置文件路径 |
| `SIGCHLD` | `sigwaitinfo` 同步等待 | 子进程收割：`waitpid(WNOHANG)` 循环回收僵尸 |

---

## 三、系统组件

Gap-Proxy 由以下 14 个核心模块组成，总计约 16,000 行核心 C 代码。

### 3.1 数据面组件

| 组件 | 文件 | 行数 | 职责 |
|------|------|:---:|------|
| **透明代理** | `proxy.c` | 2,089 | TCP/UDP 代理转发、epoll 事件循环（EPOLLET 边缘触发）、recv_buf 环形缓冲管理、KCP 背压控制、连接生命周期管理、`SO_ERROR` 诊断 |
| **通道管理** | `channel.c` | 2,473 | 7 状态状态机、SYN/ACK/FIN/RST 握手、两级心跳策略（全局+逐通道）、超时回收、通道哈希表、`channel_send_ctrl` / `channel_send_data` |
| **AF_PACKET** | `af_packet.c` | 1,039 | 原始套接字创建/绑定/发送/接收、TPACKET_V2 零拷贝环形缓冲区（256 帧 × 1600 字节）、BPF 内核过滤程序附加、以太网帧构造/解析 |
| **KCP 封装** | `kcp_wrap.c` | 393 | ikcp 创建/销毁、`kcp_wrap_send` / `kcp_wrap_recv` / `kcp_wrap_update` 接口、KCP 参数映射（mtu/窗口/超时） |
| **KCP 内核** | `ikcp.c` | 1,614 | 第三方 KCP 协议栈（skywind3000/kcp），ARQ 重传、滑动窗口流量控制、拥塞避免、RTO 计算 |
| **帧协议** | `myproto.c` | 822 | 9 字节紧凑帧头构建/解析、CRC-16/CCITT 头校验 + CRC-32C 尾帧、big-endian 序列化/反序列化、加密帧标记与处理、帧验证与畸形帧拒绝 |
| **加密** | `crypto.c` | 599 | SM4-CBC 加密/解密、SM3-HMAC 计算/验证、`/dev/urandom` IV 生成（`getrandom` 兜底）、恒时 HMAC 比较 |
| **ACL** | `acl.c` | 118 | IP 地址匹配引擎：CIDR（`192.168.0.0/24`）、精确 IP（`10.0.0.1`）、IP 范围（`10.0.0.1-10.0.0.255`） |

### 3.2 控制面组件

| 组件 | 文件 | 行数 | 职责 |
|------|------|:---:|------|
| **管理协议** | `mgmt.c` | 2,465 | Manager↔Worker 间 16 种 JSON 管理消息（集群唯一 Manager 集中管理）（集群唯一 Manager 集中管理）构建/解析/分发（`mgmt_dispatch`）、注册/心跳/配置推送/SPAWN/KILL/CHANNEL_CTL、消息序列号防重放、Worker 注册表维护 |
| **HTTP API** | `api.c` | 2,420 | 内嵌 Mongoose HTTP 服务器、RESTful 端点路由、Bearer Token 认证（`Authorization: Bearer <token>`）、请求校验、远程 syslog 支持 |
| **主程序** | `main.c` | 5,204 | 进程入口、信号处理（`sigwaitinfo` 同步模式）、JSON 配置加载/验证/热重载（`config_reload`）、Worker 生命周期管理（`master_handle_spawn_request` / `kill_stuck_workers`）、CTL JSON 指令执行（`ctl_execute_json`）、CPU 亲和性绑定 |
| **CLI 工具** | `cli.c` | 595 | 独立命令行管理客户端（`gapproxy-cli`）、通过 HTTP API 查询/管理集群、支持 `--follow` 日志流式输出 |
| **插件系统** | `plugin.c` | 154 | HP-4：数据入站后置 hook（`plugin_invoke_channel_data_inbound`）、HP-7：通道销毁前置 hook（`plugin_invoke_channel_destroy`） |

### 3.3 公共基础

| 组件 | 文件 | 行数 | 职责 |
|------|------|:---:|------|
| **类型定义** | `types.h` | 1,852 | 全部结构体（`channel_t`、`global_ctx_t`、`channel_config_t` 等）、枚举（状态机/角色/类型/加密）、常量（`MAX_CHANNELS`=256、`MAX_FRAME_SIZE` 等）、宏（`LOG_ERROR`/`time_now` 等）、模块 API 声明 |

### 3.4 组件交互图

```
                          ┌──────────────────┐
                          │     main.c        │
                          │  入口/信号/配置    │
                          └──┬───────┬──────┬─┘
                             │       │      │
              ┌──────────────┼───────┼──────┼──────────────┐
              ▼              ▼       │      ▼              ▼
        ┌──────────┐   ┌──────────┐  │  ┌──────────┐  ┌──────────┐
        │  mgmt.c  │   │  api.c   │  │  │ plugin.c │  │  cli.c   │
        │ 管理协议  │   │ HTTP API │  │  │ 插件系统  │  │ CLI 工具  │
        └─────┬─────┘   └──────────┘  │  └──────────┘  └──────────┘
              │ 管理通道               │
              │ (channel_id=0)         │
    ┌─────────┼────────────────────────┼─────────────────────────┐
    │         ▼                        ▼                         │
    │  ┌──────────────────────────────────────────────────┐      │
    │  │              channel.c (通道层)                    │      │
    │  │  哈希表 · 7 状态机 · 心跳 · 超时 · SYN/FIN/RST    │      │
    │  └────┬─────────────────────────┬───────────────────┘      │
    │       │ KCP 负载                │ 控制帧                    │
    │       ▼                         ▼                          │
    │  ┌──────────┐           ┌──────────────┐                   │
    │  │ proxy.c  │           │  myproto.c   │                   │
    │  │ 透明代理  │           │  帧协议/加密  │                   │
    │  └────┬─────┘           └──────┬───────┘                   │
    │       │ 数据帧                  │ 组帧/解帧                  │
    │       └──────────┬─────────────┘                          │
    │                  ▼                                         │
    │         ┌───────────────┐                                  │
    │         │  af_packet.c  │                                  │
    │         │  L2 原始套接字 │                                  │
    │         └───────┬───────┘                                  │
    │                 │ sendto/recvfrom                          │
    └─────────────────┼──────────────────────────────────────────┘
                      ▼
                 Linux 内核
              (AF_PACKET + BPF)
```

---

## 四、系统功能

### 4.1 透明代理

```
┌─────────┐   TCP    ┌────────────┐   KCP    ┌────────────┐   TCP    ┌──────────┐
│ 客户端   │─────────►│ Frontend   │─────────►│ Backend    │─────────►│ 目标服务  │
│         │◄─────────│ Worker     │◄─────────│ Worker     │◄─────────│          │
└─────────┘   TCP    └────────────┘   KCP    └────────────┘   TCP    └──────────┘
```

**数据流（上行）**：

```
客户端 → local_fd (read) → KCP (channel_send_data) → MyProto 组帧 → AF_PACKET 发送
```

**数据流（下行）**：

```
AF_PACKET 接收 → MyProto 解帧 → KCP (kcp_wrap_recv) → local_fd (write)
```

**TCP vs UDP 代理差异**：

| 维度 | TCP 代理 | UDP 代理 |
|------|------|------|
| 连接模型 | 有连接（accept/connect） | 无连接（sendto/recvfrom） |
| local_fd 生命周期 | 每次 `accept` 新连接 → 绑定到通道 | 通道创建时 `socket` 一次，复用到关闭 |
| recv_buf | 按需分配（初始 64KB，最大可到 `perf_max_memory_mb`） | 固定缓冲区 |
| 背压保护 | `KCP_READ_PAUSED` 标志暂停本地 `read` | EPOLLOUT 通知写就绪 |
| 关闭方式 | FIN 优雅断开（双向关闭） | 直接 `close` |

### 4.2 可靠传输（KCP）

#### 4.2.1 核心机制

- **自动重传（ARQ）**：KCP 为每个发出的数据段设置超时（RTO），超时未确认则重传。RTO 根据 SRTT（平滑往返时间）和 RTTVAR（往返时间方差）动态计算。
- **流量控制**：发送窗口（`snd_wnd`=128）和接收窗口（`rcv_wnd`=128）限制在途数据量。
- **拥塞控制**：自适应调整发送速率，连续超时时减小窗口。
- **快速重传**：收到 3 个以上跳过某个序列号的 ACK 时立即重传（不等待超时）。
- **背压保护**：KCP 发送窗口满时，`channel_send_data` 返回 -1 → 调用者设置 `CH_FLAG_KCP_READ_PAUSED` → 暂停本地 `read` → 等待 KCP 窗口释放后通过 EPOLLOUT 恢复。

#### 4.2.2 KCP 参数参考

| 参数 | 默认值 | 范围 | 说明 |
|------|:---:|:---:|------|
| `mtu` | 1400 | 512-1478 | KCP 最大传输单元（不含帧头） |
| `snd_wnd` | 128 | 32-1024 | 发送窗口大小（段数） |
| `rcv_wnd` | 128 | 32-1024 | 接收窗口大小（段数） |
| `nodelay` | 1 | 0-1 | 启用 nodelay 模式（降低延迟） |
| `interval` | 10 | 5-100 | KCP 内部时钟滴答（ms） |
| `resend` | 2 | 0-10 | 快速重传触发阈值（跳过 ACK 次数） |
| `nc` | 1 | 0-1 | 是否关闭拥塞控制（`1`=关闭，纯流量控制） |

**最大在途数据量**：`snd_wnd × mtu = 128 × 1400 = 179,200 字节`

#### 4.2.3 KCP 与系统时钟的关系

- KCP 通过 `kcp_wrap_update(current_ms)` 每 10ms 驱动一次定时器
- `current_ms` 来自 `time_now()`（`CLOCK_MONOTONIC`），单调递增，不受系统时间调整影响
- 主事件循环 `epoll_wait(timeout=10ms)` 与 KCP 定时器同步
- `epoll_wait` 可能因信号提前返回（EINTR）→ KCP 可能以高于 10ms 的频率更新，不影响正确性

### 4.3 加密与安全

#### 4.3.1 加密帧结构

```
明文帧:  [MyProto Header(9)] [Plaintext Payload(N)] [CRC32 Tail(4)]

加密后:  [MyProto Header(9)] [Ciphertext(N+p)] [SM3-HMAC(32)] [CRC32 Tail(4)]
                              └── SM4-CBC 加密 ──┘ └── 认证标签 ──┘
```

加密流程：
1. IV = `getrandom(16)` 从 `/dev/urandom` 获取随机数
2. `ciphertext = SM4_CBC_Encrypt(key, iv, plaintext)` → PKCS7 填充
3. `hmac = SM3_HMAC(auth_key, header || iv || ciphertext)` → 关联数据认证
4. 输出 = `iv(16) || ciphertext || hmac(32)`
5. 帧头 `flags` 置 `MPF_CRYPTO` 位

**加密开销**：16（IV） + 1~16（PKCS7 填充） + 32（HMAC）= 49~64 字节/帧

#### 4.3.2 安全机制汇总

| 机制 | 实现 | 防御 |
|------|------|------|
| 帧级加密 | 每帧独立 IV + SM4-CBC | 密钥流复用攻击 |
| Encrypt-then-MAC | 先加密，后对密文和关联数据认证 | Padding Oracle |
| 恒时 HMAC 比较 | 逐字节 XOR + 累加，不提前返回 | 时序侧信道 |
| 管理消息序列号 | 单调递增 `mgmt_seq`，拒绝 `seq ≤ last_seq` | 重放攻击 |
| API Token | `getrandom()` 安全随机生成 64 字符十六进制 | Token 猜测 |
| IP ACL | CIDR/精确/范围三种模式白名单 | 未授权 IP 访问 |
| 管理通道密钥隔离 | `mgmt_keys[]` 独立于 `data_keys[]` | 密钥交叉攻击 |
| 共享密钥空间 | `shared_secret` 统一管理，`explicit_bzero` 清零 | 密钥内存残留 |

### 4.4 集群管理

集群中存在唯一一个 Manager 节点（`node_role: "manager"`），通过管理通道（`channel_id=0`）集中管理所有远程 Worker（`node_role: "worker"`）。Manager 本身也是一个 Worker 进程，同时承担数据面和管理面职责。

#### 4.4.1 管理消息协议

管理通道（`channel_id=0`）承载 JSON 消息，通用格式：

```json
{
    "type": "NODE_REGISTER",
    "seq": 42,
    "ts": 1718700000,
    "node_id": "worker-frontend-01",
    "version": "1.0.0",
    "... 消息特定字段 ..."
}
```

**公共字段**：`type`（消息类型）、`seq`（单调递增序列号）、`ts`（Unix 时间戳）、`node_id`（节点标识符）。

#### 4.4.2 消息类型一览

管理通道（`channel_id=0`）承载以下 16 种 JSON 消息类型：

| 消息类型 | 方向 | 触发 | 关键字段 |
|----------|------|------|------|
| `NODE_REGISTER` | Worker→Manager | Worker 启动时 | `instance_config`（配置路径） |
| `NODE_REGISTER_ACK` | Manager→Worker | 注册成功后 | `status`（ok/rejected/replay） |
| `HEALTH_CHECK` | Manager→Worker | Manager 周期性健康检查 | — |
| `HEALTH_RESP` | Worker→Manager | 健康检查回复 | `uptime_seconds` |
| `CONFIG_PUSH` | Manager→Worker | API/热重载触发 | `config`（完整 JSON 对象） |
| `CONFIG_ACK` | Worker→Manager | 配置应用后 | `status`、`channels_enabled` |
| `CONFIG_SWITCH` | Manager→Worker | API 触发 | `instance_name`、`config_path` |
| `SWITCH_ACK` | Worker→Manager | 配置切换完成后 | `status`、`instance_name` |
| `SPAWN_INSTANCE` | Manager→Worker | API 触发 SPAWN | `instance_name`、`config_path`、`cpu_affinity` |
| `SPAWN_ACK` | Worker→Manager | SPAWN 完成后 | `status`、`instance_name` |
| `KILL_INSTANCE` | Manager→Worker | API 触发 KILL | `instance_name` |
| `KILL_ACK` | Worker→Manager | KILL 完成后 | `status`、`instance_name` |
| `CHANNEL_CTL` | Manager→Worker | API/CTL 信号触发 | `op`（add/del）、`channel_id`、`channel_config` |
| `CHANNEL_CTL_ACK` | Worker→Manager | 通道操作后 | `added`、`deleted`、`errors` |
| `INSTANCE_SYNC_REQ` | Worker→Manager | Worker 注册后同步 | 请求已有实例状态 |
| `INSTANCE_SYNC_RESP` | Manager→Worker | 响应同步请求 | 实例列表及状态 |

### 4.5 HTTP 管理 API

#### 4.5.1 端点一览

| 方法 | 端点 | 认证 | 功能 |
|------|------|:---:|------|
| `GET` | `/api/v1/status` | Bearer | 节点状态、Worker 列表、启动时间 |
| `GET` | `/api/v1/metrics` | Bearer | Prometheus 格式监控指标 |
| `GET` | `/api/v1/nodes` | Bearer | 集群节点列表及状态 |
| `GET` | `/api/v1/nodes/<id>/instances` | Bearer | 指定节点下的实例列表 |
| `GET` `POST` | `/api/v1/channels` | Bearer | GET 全部通道状态；POST 创建新通道 |
| `GET` | `/api/v1/channels/<id>` | Bearer | 单个通道详情 |
| `GET` | `/api/v1/sessions` | Bearer | 活跃会话列表 |
| `GET` | `/api/v1/sessions/<id>` | Bearer | 单个会话详情 |
| `GET` | `/api/v1/config` | Bearer | 当前完整配置（JSON） |
| `POST` | `/api/v1/config/switch` | Bearer | 切换实例配置文件路径 |
| `POST` | `/api/v1/instances/spawn` | Bearer | 启动新 Worker 实例（单次） |
| `POST` | `/api/v1/instances/spawn-batch` | Bearer | 批量启动 Worker 实例 |
| `POST` | `/api/v1/instances/kill` | Bearer | 停止指定 Worker 实例 |
| `POST` | `/api/v1/instances/channels` | Bearer | SPAWN 实例通道管理（add/del/status） |
| `GET` | `/api/v1/stats` | Bearer | 全局流量统计（总帧数/总字节/总错误） |
| `GET` | `/api/v1/logs` | Bearer | 获取日志输出（支持 `?lines=N`） |
| `POST` | `/api/v1/reload` | Bearer | 触发热重载（等价于 `kill -HUP`） |

#### 4.5.2 认证流程

```
Client                          Gap-Proxy API
  │                                    │
  │  GET /api/v1/status                │
  │  Authorization: Bearer <token>     │
  │ ──────────────────────────────────►│
  │                                    │ api_check_auth(token)
  │                                    │   → strcmp(token, config.api_token)
  │                                    │   → 成功：继续 │ 失败：401
  │◄────────────────────────────────── │
  │  200 {"status":"running", ...}     │
```

### 4.6 Worker 生命周期管理

Worker 生命周期分为两层：**本地**（Master 通过 fork 创建本地子进程）和**远程**（Manager 通过管理消息调度远程主机上的 Worker）。

#### 远程 SPAWN（跨主机）

```
Manager (主机A)                     Worker (主机B)                     Master (主机B)
     │                                   │                                 │
     │── SPAWN_INSTANCE (ch_id=0) ──────►│                                 │
     │                                   │ mgmt_handle_spawn_instance()    │
     │                                   │ 写临时文件 + kill(ppid, SIGUSR1)│
     │                                   │────────────────────────────────►│
     │                                   │                                 │ master_handle_spawn_request
     │                                   │                                 │ 验证 → fork() 子进程
                                        │
                                        │ fork() + exec()
                                        ▼
                                   Worker 子进程
                                        │
                                        │ NODE_REGISTER (管理消息)
                                        ▼
                                   Manager 确认注册
                                        │
                                   ┌────┴────┐
                                   │ 正常运行  │ (数据面 + 心跳周期)
                                   └────┬────┘
                                        │
          KILL_INSTANCE (管理消息)       │
Master ───────────────────────────► Worker 主进程
                                        │
                                        │ SIGTERM (等待 30s)
                                        │ SIGKILL (强制)
                                        ▼
                                   进程退出 + waitpid 非阻塞回收
```

**关键机制**：
- **SPAWN 确认超时**：Master 发送 SPAWN_INSTANCE 后轮询等待 `SPAWN_WAIT_RETRIES × SPAWN_WAIT_US`（50 × 10ms = 500ms），超时视为失败
- **KILL 分级**：先 `SIGTERM`（优雅退出）→ 30 秒后 `SIGKILL`（强制终止）→ `waitpid(WNOHANG)` 立即回收
- **崩溃重启**：Worker 异常退出后由 Master 的 `restart_worker` 逻辑自动重启（可配置次数上限）
- **CPU 亲和性**：`cpu_affinity` 配置 → `sched_setaffinity()` 绑定进程到指定核心
- **冲突检测**：启动时检测多个 Worker 绑定同一 CPU 核心，输出警告

### 4.7 配置热重载

#### 4.7.1 全量重载（SIGHUP）

```
SIGHUP → config_reload()
  ├── 加载新 JSON 配置文件
  ├── 验证配置一致性
  ├── Step 1: 标记所有现存通道为 RELOAD_MARKED
  ├── Step 2: 遍历新配置
  │     ├── 已存在且未改变 → 清除 RELOAD_MARKED（保留）
  │     ├── 不存在 → channel_create（创建）
  │     └── enabled=false → channel_destroy（销毁）
  ├── Step 3: 清理仍带 RELOAD_MARKED 的通道（已从新配置移除）
  └── Step 4: 更新全局配置参数
```

#### 4.7.2 通道级 CTL（SIGUSR1）

```
SIGUSR1 → 读取 ctl.json 文件 → ctl_execute_json()
  ├── op: "add"     → channel_create → channel_send_ctrl(SYN) → 启动握手
  ├── op: "del"     → channel_send_ctrl(FIN) → 等待关闭 → channel_destroy
  └── op: "status"  → 打印当前通道状态 JSON
```

### 4.8 可观测性

#### 4.8.1 统计计数器

**通道级**（每通道独立）：

| 计数器 | 类型 | 说明 |
|------|:---:|------|
| `tx_frames` / `rx_frames` | uint64 | 发送/接收帧总数 |
| `tx_bytes` / `rx_bytes` | uint64 | 发送/接收字节总数 |
| `tx_errors` / `rx_errors` | uint64 | 发送/接收错误次数 |
| `kcp_snd_una` / `kcp_rcv_nxt` | uint32 | KCP 发送/接收窗口前沿（实时快照） |

**Worker 级**：聚合该 Worker 所有通道的统计。

**全局级**（`global_ctx_t`）：

| 计数器 | 说明 |
|------|------|
| `channel_count` | 当前活跃通道数 |
| `channel_create_total` | 累计创建通道数 |
| `channel_destroy_total` | 累计销毁通道数 |
| `channel_create_max_per_sec` | 每秒最大创建速率（性能基准） |

#### 4.8.2 日志系统

```
LOG_ERROR  → stderr + syslog + API /logs（始终输出）
LOG_WARN   → stderr + syslog + API /logs（始终输出）
LOG_INFO   → stderr + syslog + API /logs（默认）
LOG_DEBUG  → stderr + syslog + API /logs（仅 debug 构建）
LOG_AUDIT  → stderr + syslog（安全审计事件专用）
```

**远程 syslog**：通过 `log_syslog_remote` 配置 UDP syslog 服务器地址（`host:port`），日志实时发送。

#### 4.8.3 Prometheus 端点

`GET /api/v1/metrics` 返回 Prometheus 格式指标：

```
# HELP gap_proxy_channels_active Number of active channels
# TYPE gap_proxy_channels_active gauge
gap_proxy_channels_active 42
# HELP gap_proxy_frames_total Total frames processed
# TYPE gap_proxy_frames_total counter
gap_proxy_frames_total{channel="1",direction="tx"} 1024000
```

---

## 五、应用场景

### 5.1 跨隔离网络透明代理

**场景**：两个安全域之间不允许 IP 层通信（无路由、无 IP 地址），但物理上在同一二层网络。

**方案**：两台主机各部署 Gap-Proxy，通过自定义 EtherType 在数据链路层直接通信，应用层完全无感知。

```
安全域 A                      同一二层网络                    安全域 B
┌────────────┐                                            ┌────────────┐
│ 客户端      │──TCP──► Frontend ──AF_PACKET──► Backend ──TCP──► 数据库   │
│            │                  (L2 隧道)                   │            │
└────────────┘                                            └────────────┘
         无 IP 路由可达                                       无 IP 路由可达
```

**配置要点**：双方配置对端 MAC、相同 EtherType、通道 ID 对称。

### 5.2 高性能代理隧道

**场景**：需要比传统 VPN/IPSec/GRE 更低延迟、更高吞吐的代理隧道。

**对比**：

| 维度 | 传统 VPN (IPSec) | Gap-Proxy |
|------|:---:|:---:|
| 协议层 | L3 (IP) | L2 (Ethernet) |
| 内核旁路 | 否（内核 IPsec 栈） | 是（AF_PACKET 零拷贝） |
| 传输协议 | ESP/AH（固定参数） | KCP（窗口/延迟/重传全可调） |
| 加密 | AES-GCM（硬件加速） | SM4-CBC + SM3-HMAC（软件） |
| 延迟 | ~1ms+（内核协议栈开销） | ~0.3ms（KCP nodelay 模式） |
| 适用场景 | 通用站点互联 | 低延迟数据面定制场景 |

### 5.3 多流复用的代理网关

**场景**：一台前端机器需要代理多种不同后端服务，每个服务需要独立的加密密钥和带宽控制。

**方案**：利用 Gap-Proxy 的多通道机制，每个通道独立 KCP 实例 + 独立密钥 + 独立窗口参数。

```
客户端端口 8080 ──► 通道 1 (key_A, wnd=128) ──► 后端服务 A
客户端端口 9090 ──► 通道 2 (key_B, wnd=256) ──► 后端服务 B（高吞吐）
客户端端口 3306 ──► 通道 3 (key_C, wnd=64)  ──► 数据库 C（低延迟）
```

### 5.4 集群多实例负载分担

**场景**：单机代理吞吐量不够，需要多进程并行处理，每个进程绑定不同 CPU 核心。

**方案**：Master-Worker 架构，启动多个 Worker 实例，每个绑定独立 CPU 核心，通过管理 API 动态扩缩容。

```
Master ──► Worker 1 (CPU 0) ──► 通道 1-50
       ├──► Worker 2 (CPU 1) ──► 通道 51-100
       ├──► Worker 3 (CPU 2) ──► 通道 101-150
       └──► Worker 4 (CPU 3) ──► 通道 151-200
```

**容量估算**：4 Worker × 50 通道 × 179KB KCP 窗口 = ~35MB 内存 + ~240 FD

### 5.5 远程配置管理与自动化运维

**场景**：大量代理节点的配置需要集中管理，根据流量动态调整通道参数。

```
运维平台 ──HTTP API──► Manager ──CONFIG_PUSH──► Worker 1
                                     ├──────────► Worker 2
                                     └──────────► Worker N
```

**运维命令示例**：

```bash
# 查看集群状态
gapproxy-cli status -s manager:8080 -t "$TOKEN"

# 推送新配置
gapproxy-cli config-push -s manager:8080 -t "$TOKEN" -n worker-frontend-01 -f new_config.json

# 按需扩容
gapproxy-cli spawn -s manager:8080 -t "$TOKEN" -f worker_config.json

# 实时监控
gapproxy-cli logs -s manager:8080 -t "$TOKEN" --follow

# 通道动态增删
gapproxy-cli channel-add -s manager:8080 -t "$TOKEN" -w worker-01 \
  '{"channel_id":99,"listen_port":9999,"remote_port":80,"remote_addr":"10.0.0.1","is_tcp":true}'
```

---

*最后更新：2026-06-18*
