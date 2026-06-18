# Gap-Proxy 系统总体说明

## 一、术语和定义

| 术语 | 定义 |
|------|------|
| **Gap-Proxy** | 项目名称。一个 Linux 用户空间二层代理隧道系统。 |
| **AF_PACKET** | Linux 内核提供的原始套接字接口，允许用户态程序直接在数据链路层（L2）收发以太网帧，绕过内核 TCP/IP 协议栈。 |
| **EtherType** | 以太网帧头中的 2 字节类型字段，用于标识上层协议。Gap-Proxy 使用自定义 EtherType（默认 `0x88B5`）区分本协议帧。 |
| **KCP** | 一种基于 UDP 的可靠传输协议（KCP - A Fast and Reliable ARQ Protocol），提供比 TCP 快 30%-40% 的吞吐量，通过可配置的自动重传和流量控制实现可靠交付。 |
| **BPF** | Berkeley Packet Filter，Linux 内核的包过滤机制。Gap-Proxy 使用 BPF 在内核层按 EtherType 过滤帧，减少用户态处理开销。 |
| **TPACKET_V2** | Linux AF_PACKET 的零拷贝环形缓冲区接口，用户态与内核态通过共享内存区域传递帧描述符，避免数据拷贝。 |
| **SM4-CBC** | 国密 SM4 分组密码的 CBC 模式（128 位密钥），用于帧负载加密。 |
| **SM3-HMAC** | 基于国密 SM3 哈希算法的 HMAC（256 位摘要），用于帧完整性校验和身份认证。 |
| **Encrypt-then-MAC** | 先加密后认证的安全设计模式：先用 SM4-CBC 加密明文，再对密文计算 SM3-HMAC，防止 padding oracle 等侧信道攻击。 |

### 节点角色（Node Role）

| 角色 | 值 | 定义 |
|------|:---:|------|
| `NONE` | 0 | 未配置角色，向后兼容旧版单进程独立运行模式 |
| `MANAGER` | 1 | Master 管理进程，负责配置分发、进程监管、信号转发、API 服务 |
| `WORKER` | 2 | Worker 工作进程，负责数据面处理（AF_PACKET + KCP + 透明代理） |

### 节点类型（Node Type）

| 类型 | 值 | 定义 |
|------|:---:|------|
| `FRONTEND` | 0 | 前端节点，接收客户端 TCP/UDP 连接，通过 KCP 隧道转发到后端节点 |
| `BACKEND` | 1 | 后端节点，接收前端转发的 KCP 隧道数据，代理到目标服务 |

### 通道角色（Channel Role）

| 角色 | 值 | 定义 |
|------|:---:|------|
| `INITIATOR` | 0 | 主动发起方，发送 SYN 帧驱动三次握手 |
| `RESPONDER` | 1 | 被动响应方，收到 SYN 后回复 ACK 完成握手 |
| `LISTENER` | 2 | 纯监听方，仅监听本地端口，由对端 SYN 触发握手 |

### 通道状态（Channel State）

```
CLOSED ──(SYN)──► SYN_SENT ──(ACK)──► ESTABLISHED ──(FIN)──► FIN_SENT
  ▲                   │                     │                    │
  │                   ▼                     ▼                    ▼
  │               SYN_RCVD               FIN_RCVD            CLOSED
  │                   │                     │                    │
  └───────────────────┴─────────────────────┴────────────────────┘
                        CLOSED_ZOMBIE (超时回收)
```

| 状态 | 定义 |
|------|------|
| `CLOSED` | 初始状态，通道未建立 |
| `SYN_SENT` | 已发送 SYN 帧，等待对端 ACK |
| `SYN_RCVD` | 已收到 SYN 帧，已回复 ACK，等待确认 |
| `ESTABLISHED` | 连接已建立，可双向传输数据 |
| `FIN_SENT` | 已发送 FIN 帧，等待对端确认关闭 |
| `FIN_RCVD` | 已收到 FIN 帧，已回复 ACK，等待本地关闭 |
| `CLOSED_ZOMBIE` | 等待超时回收的僵尸状态 |

### 加密模式

| 模式 | 值 | 定义 |
|------|:---:|------|
| `NONE` | 0 | 不加密，payload 明文传输（仅可信内网） |
| `SM4_SM3` | 1 | SM4-CBC 加密 + SM3-HMAC 完整性校验（生产推荐） |

### 通道标志（Channel Flags）

| 标志 | 值 | 定义 |
|------|:---:|------|
| `STATIC_LISTENER` | 0x01 | 静态监听通道，不被热重载销毁 |
| `RELOAD_MARKED` | 0x02 | 热重载临时标记，增量比对后清理 |
| `KCP_READ_PAUSED` | 0x04 | KCP 发送窗口高水位，暂停本地读取 |
| `MGMT_CHANNEL` | 0x08 | 管理通道标记，收发走 mgmt_dispatch |

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

```
主机 A (Frontend)                          主机 B (Backend)

┌──────────────────────┐                 ┌──────────────────────┐
│ Master (Manager)      │                 │ Master (Manager)      │
│ ┌──────────────────┐  │   AF_PACKET    │ ┌──────────────────┐  │
│ │ HTTP API :8080   │  │  (channel_id=0)│ │ HTTP API :8080   │  │
│ │ 16 个 REST 端点   │  │  管理通道(JSON) │ │ 16 个 REST 端点   │  │
│ └──────────────────┘  │                 │ └──────────────────┘  │
│         │              │                 │         │              │
│ ┌───────┴───────────┐  │                 │ ┌───────┴───────────┐  │
│ │ Worker 1 (frontend)│◄─┼─────────────────┼─►│ Worker 1 (backend) │  │
│ │ channel_id: 1..N   │  │  AF_PACKET     │ │ channel_id: 1..N   │  │
│ └───────────────────┘  │  (channel_id≥1) │ └───────────────────┘  │
│ ┌───────────────────┐  │   数据通道      │ ┌───────────────────┐  │
│ │ Worker 2 (frontend)│◄─┼─────────────────┼─►│ Worker 2 (backend) │  │
│ └───────────────────┘  │                 │ └───────────────────┘  │
│         ...             │                 │         ...             │
│   (最多 64 Worker)      │                 │   (最多 64 Worker)      │
└──────────────────────┘                 └──────────────────────┘
```

**通信模型**：

```
客户端 ──TCP/UDP──► Frontend Worker ──AF_PACKET(KCP)──► Backend Worker ──TCP/UDP──► 目标服务
   透明代理            仅需 MAC/EtherType                仅需 MAC/EtherType           透明代理
```

**约定**：
- 两台主机各运行一个 Master 进程
- 管理通道（channel_id=0）在 AF_PACKET 上承载 JSON 消息，由 Manager 直接收发
- 数据通道（channel_id≥1）分别由 Frontend Worker 和 Backend Worker 按配置分配到具体进程
- Worker 由 Master 通过 `fork()` + `exec()` 启动，可配置 CPU 亲和性绑定

---

## 三、系统组件

Gap-Proxy 由以下 14 个核心模块组成：

### 3.1 数据面组件

| 组件 | 文件 | 职责 |
|------|------|------|
| **透明代理** | `proxy.c` | TCP/UDP 代理转发、epoll 事件循环、recv_buf 管理、KCP 背压控制、连接生命周期管理 |
| **通道管理** | `channel.c` | 7 状态状态机、SYN/ACK/FIN/RST 握手、心跳检测、超时回收、通道哈希表 |
| **AF_PACKET** | `af_packet.c` | 原始套接字收发、TPACKET_V2 零拷贝环形缓冲区、BPF 内核过滤、以太网帧构造/解析 |
| **KCP 封装** | `kcp_wrap.c` | ikcp 创建/销毁/参数设置、发送/接收/更新接口、窗口/超时配置映射 |
| **KCP 内核** | `ikcp.c` | 第三方 KCP 协议栈（skywind3000/kcp），ARQ 重传、流量控制、拥塞控制 |
| **帧协议** | `myproto.c` | 9 字节紧凑帧头构建/解析、CRC-16 头校验 + CRC-32 尾帧、大端序列化/反序列化、加密帧处理 |
| **加密** | `crypto.c` | SM4-CBC 加密/SM3-HMAC 校验、`/dev/urandom` IV 生成、恒时 HMAC 比较 |
| **ACL** | `acl.c` | IP 地址匹配引擎（CIDR/精确/范围三种模式） |

### 3.2 控制面组件

| 组件 | 文件 | 职责 |
|------|------|------|
| **管理协议** | `mgmt.c` | Manager↔Worker 间 13 种 JSON 管理消息的构建/解析/处理：注册、心跳、配置推送、实例调度、通道管控 |
| **HTTP API** | `api.c` | 内嵌 Mongoose HTTP 服务器，16 个 RESTful 端点，Bearer Token 认证，远程 syslog |
| **主程序** | `main.c` | 进程入口、信号处理（SIGHUP/SIGTERM/SIGUSR1/SIGCHLD）、配置加载/验证/热重载、Worker 生命周期管理、CTL JSON 指令执行 |
| **CLI 工具** | `cli.c` | 独立命令行管理客户端（`gapproxy-cli`），通过 HTTP API 查询/管理集群 |
| **插件系统** | `plugin.c` | 数据入站后置 hook（HP-4）、通道销毁前置 hook（HP-7） |

### 3.3 公共基础

| 组件 | 文件 | 职责 |
|------|------|------|
| **类型定义** | `types.h` | 全部结构体、枚举、常量、宏定义，约 1,800 行，是整个项目的数据结构基石 |

---

## 四、系统功能

### 4.1 透明代理

```
┌─────────┐   TCP    ┌────────────┐   KCP    ┌────────────┐   TCP    ┌──────────┐
│ 客户端   │─────────►│ Frontend   │─────────►│ Backend    │─────────►│ 目标服务  │
│         │◄─────────│ Worker     │◄─────────│ Worker     │◄─────────│          │
└─────────┘   TCP    └────────────┘   KCP    └────────────┘   TCP    └──────────┘
```

- **Frontend Worker**：监听本地 TCP/UDP 端口 → 接收客户端连接 → 通过 KCP 隧道封装转发到 Backend
- **Backend Worker**：接收 KCP 隧道数据 → 解封装 → 连接到目标服务 → 双向转发

### 4.2 可靠传输（KCP）

- **自动重传（ARQ）**：未确认数据段超时后自动重传
- **流量控制**：发送/接收窗口限制在途数据量
- **拥塞控制**：自适应调整发送速率，避免网络拥塞
- **背压保护**：KCP 发送窗口满时自动暂停本地 socket 读取，防止内存暴涨

### 4.3 加密与安全

- **帧级加密**：每个 MyProto 帧独立加密，IV 从 `/dev/urandom` 随机生成
- **Encrypt-then-MAC**：先 SM4-CBC 加密明文，再对密文计算 SM3-HMAC
- **管理通道保护**：管理通道可使用独立密钥，与数据通道隔离
- **防重放**：管理消息包含单调递增序列号，拒绝低序列号消息
- **Token 安全**：API Token 使用 `getrandom()` 系统调用安全随机生成
- **HMAC 恒时比较**：防止时序侧信道攻击
- **IP ACL**：支持 CIDR/精确 IP/范围三种匹配模式

### 4.4 集群管理

**管理通道（channel_id=0）**承载以下 13 种 JSON 消息类型：

| 消息类型 | 方向 | 功能 |
|----------|------|------|
| `NODE_REGISTER` | Worker→Manager | Worker 注册（含节点 ID、版本、角色） |
| `NODE_REGISTER_ACK` | Manager→Worker | 注册确认（成功/拒绝/重放检测） |
| `NODE_KEEPALIVE` | Worker→Manager | Worker 心跳 |
| `NODE_KEEPALIVE_ACK` | Manager→Worker | 心跳回复 |
| `CONFIG_PUSH` | Manager→Worker | 配置下发（全局 + 通道配置） |
| `CONFIG_PUSH_ACK` | Worker→Manager | 配置确认 |
| `CONFIG_SWITCH` | Manager→Worker | 配置文件路径切换指令 |
| `SPAWN_INSTANCE` | Manager→Worker | 启动新 Worker 实例 |
| `SPAWN_ACK` | Worker→Manager | SPAWN 结果确认 |
| `KILL_INSTANCE` | Manager→Worker | 停止 Worker 实例 |
| `CHANNEL_CTL` | Manager→Worker | 通道动态管理（add/del/list） |
| `CHANNEL_CTL_ACK` | Worker→Manager | 通道操作确认 |
| `NODE_UNREGISTER` | Worker→Manager | Worker 注销 |

### 4.5 HTTP 管理 API

系统提供 16 个 RESTful API 端点：

| 方法 | 端点 | 功能 |
|------|------|------|
| `GET` | `/api/v1/status` | 节点状态、Worker 列表 |
| `GET` | `/api/v1/metrics` | Prometheus 格式监控指标 |
| `GET` | `/api/v1/nodes` | 集群节点列表 |
| `GET` | `/api/v1/channels` | 全部通道状态 |
| `GET` | `/api/v1/sessions` | 活跃会话列表 |
| `GET` | `/api/v1/config` | 当前配置查看 |
| `POST` | `/api/v1/config/push` | 配置推送 |
| `POST` | `/api/v1/config/switch` | 实例配置切换 |
| `GET` | `/api/v1/config/version` | 配置版本号 |
| `POST` | `/api/v1/instances/spawn` | 启动新 Worker |
| `POST` | `/api/v1/instances/spawn-batch` | 批量启动 Worker |
| `POST` | `/api/v1/instances/kill` | 停止 Worker |
| `POST` | `/api/v1/instances/channels` | SPAWN 实例通道管理 |
| `GET` | `/api/v1/stats` | 全局流量统计 |
| `GET` | `/api/v1/logs` | 获取日志输出 |
| `POST` | `/api/v1/reload` | 触发热重载 |

### 4.6 Worker 生命周期管理

```
          SPAWN_INSTANCE
Master ─────────────────► Worker (主进程)
                              │
                              │ fork() + exec()
                              ▼
                         Worker 子进程
                              │
                              │ NODE_REGISTER
                              ▼
                         Manager 确认注册
                              │
                         ┌────┴────┐
                         │ 正常运行 │ (数据面 + 心跳)
                         └────┬────┘
                              │
          KILL_INSTANCE       │
Master ─────────────────► Worker 主进程
                              │
                              │ SIGTERM → SIGKILL
                              ▼
                         进程退出 + 回收
```

- **SPAWN**：通过 HTTP API 或管理消息触发，在目标主机上 `fork()` + `exec()` 新 Worker 实例
- **KILL**：向指定 Worker 发送 `SIGTERM`，超时后 `SIGKILL`，非阻塞回收
- **重启保护**：Worker 异常退出后由 Master 自动重启（可配置次数限制）
- **CPU 亲和性**：每个 Worker 可绑定到指定 CPU 核心，避免缓存颠簸

### 4.7 配置热重载

- **SIGHUP 信号**触发全量配置重载
- 通道增量 diff：仅关闭移除的通道、仅创建新增的通道，已有连接不受影响
- 通过 `CH_FLAG_RELOAD_MARKED` 标志位实现新旧配置比对
- **SIGUSR1 CTL 信号**触发 JSON 指令，支持运行时 add/del 通道
- `CONFIG_SWITCH` 管理消息支持配置文件路径热切换

### 4.8 可观测性

- **通道级统计**：每通道独立计数器（tx_frames/rx_frames/tx_bytes/rx_bytes/tx_errors 等）
- **Worker 级统计**：聚合该 Worker 所有通道的统计
- **全局统计**：channel_count、通道创建/销毁速率
- **Prometheus 端点**：`/api/v1/metrics` 输出 Prometheus 格式指标
- **CLI 工具**：`gapproxy-cli status/channels/stats/logs` 查询实时状态
- **远程 syslog**：可配置远程 syslog 服务器，支持 UDP 传输

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

### 5.2 高性能代理隧道

**场景**：需要比传统 VPN/IPSec/GRE 更低延迟、更高吞吐的代理隧道。

**方案**：利用 AF_PACKET 零拷贝 + KCP 协议，绕过内核 TCP/IP 协议栈，实现接近线速的转发性能。

| 对比维度 | 传统 VPN (IPSec) | Gap-Proxy |
|----------|:---:|:---:|
| 协议层 | L3 (IP) | L2 (Ethernet) |
| 内核旁路 | 否 | 是（AF_PACKET 零拷贝） |
| 传输协议 | ESP/AH | KCP（可调参数） |
| 加密 | 内置 | SM4-CBC + SM3-HMAC |
| 延迟 | ~1ms+ | ~0.3ms（KCP 参数优化后） |

### 5.3 多流复用的代理网关

**场景**：一台前端机器需要代理多种不同后端服务，每个服务需要独立的加密密钥和带宽控制。

**方案**：利用 Gap-Proxy 的多通道机制，每个通道独立 KCP 实例 + 独立密钥 + 独立窗口参数。

```
客户端端口 8080 ──► 通道 1 (key_A) ──► 后端服务 A
客户端端口 9090 ──► 通道 2 (key_B) ──► 后端服务 B
客户端端口 3306 ──► 通道 3 (key_C) ──► 数据库 C
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

### 5.5 远程配置管理与自动化运维

**场景**：大量代理节点的配置需要集中管理，根据流量动态调整通道参数。

**方案**：Manager-Worker 协议支持从中心 Manager 向所有 Worker 推送配置更新，通过 HTTP API 批量操作。

```
运维平台 ──HTTP API──► Manager ──CONFIG_PUSH──► Worker 1
                                     ├──────────► Worker 2
                                     └──────────► Worker N
```
