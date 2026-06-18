/*
 * types.h - Gap-Proxy 公共类型定义
 *
 * 本头文件是整个项目的数据结构基石，定义了所有模块共享的：
 *   - 协议常量、帧格式、魔数与标志位
 *   - 枚举类型（通道状态机、角色、节点类型、加密模式等）
 *   - 协议头结构体（9 字节紧凑帧头）
 *   - 配置结构体（通道级、全局级、多实例 master-worker 级）
 *   - 运行时核心结构体（channel_t、global_ctx_t）
 *   - 防御机制常量（MAC 学习确认、DoS 速率限制、断路器、内存配额、自诊断、应急缓冲池）
 *   - 加密常量（SM4-CBC / SM3-HMAC）、统计计数器、日志宏、工具宏
 *
 * 设计原则：
 *   - 所有结构体采用紧凑布局，减少内存占用，避免缓存行伪共享
 *   - 以 channel_id（32 位无符号整数）为全局标识，支持最多 65536 个并发通道
 *   - 动态通道 ID 分配采用 listener_base[] / listener_next[] 分区机制，避免不同 listener 间冲突
 *   - 热重载通过 CH_FLAG_RELOAD_MARKED 标志位实现增量更新，不中断现有连接
 *   - 时间戳统一使用 CLOCK_MONOTONIC 单调时钟，不受 NTP / systemd-timesyncd 调拨干扰
 *   - 所有外部可见的模块接口在本文件末尾声明，方便各 .c 文件包含
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>

/* ============================================================================
 * 常量定义
 * ============================================================================ */

/* ───────────────────────────────────────────────────────────────────────────
 * MyProto 协议概述
 *
 * MyProto 是一个轻量级二层隧道协议，运行在 AF_PACKET 原始套接字之上，
 * 在以太网帧中直接承载多路复用的 KCP 可靠传输通道。
 *
 * 协议栈层次（自上而下）：
 *   应用数据 (TCP/UDP payload)
 *     → KCP (可靠传输、流量控制、ARQ 自动重传)
 *       → MyProto (多路复用/解复用、通道生命周期管理、加密)
 *         → AF_PACKET (原始以太网帧收发，完全绕过内核协议栈)
 *
 * 帧结构（从外到内，自以太网帧开始）：
 *   [Ethernet Header 14B] [MyProto Header 9B] [Optional: SM4-IV 16B]
 *     [Payload (KCP segment)] [Optional: SM3-HMAC 32B]
 *
 * 帧分类：
 *   - 控制帧（SYN / ACK / FIN / RST / PING / PONG）：
 *     仅包含 9 字节 MyProto 帧头，无 payload，用于通道握手、关闭、保活。
 *   - 数据帧（MPF_DATA）：
 *     包含 MyProto 帧头 + KCP 段（可选择 SM4-CBC 加密 + SM3-HMAC 完整性校验）。
 * ─────────────────────────────────────────────────────────────────────────── */

/* ── MyProto 协议常量 ───────────────────────────────────────────────────────
 * 这些常量定义了 MyProto 协议的边界值，任何不符合的帧将被静默丢弃。
 *   MYPROTO_MAGIC:    魔数 0x4D50（ASCII 'MP'），用于在以太网帧 payload 中快速识别 MyProto 帧
 *   MYPROTO_VERSION:  协议版本号，当前为 1，预留未来协议升级的兼容性判断
 *   MYPROTO_HDR_SIZE: 协议头固定大小 9 字节，是帧路由的最小解析单元
 *   MYPROTO_ETHERTYPE: 自定义 EtherType 0x88B5，用于 BPF 过滤器和内核旁路识别
 * ─────────────────────────────────────────────────────────────────────────── */
#define MYPROTO_MAGIC           0x4D50      /* 魔数 'MP'：用于在以太网帧 payload 起始处识别 MyProto 帧 */
#define MYPROTO_VERSION         0x01        /* 协议版本号：接收端可据此判断对端协议兼容性 */
#define MYPROTO_HDR_SIZE        9           /* MyProto 帧头固定大小（字节）：channel_id(4B) + flags(1B) + payload_len(2B) + header_crc(2B) */
#define MYPROTO_ETHERTYPE       0x88B5      /* 自定义 EtherType 值：AF_PACKET bind 与 BPF 过滤器均使用此值 */

/* ── 帧标志位（Flags）定义 ──────────────────────────────────────────────────
 * 每个 MyProto 帧的 flags 字段为 1 字节（8 位，位于帧头偏移 4 处），定义如下：
 *
 *   Bit 7 (0x80): 保留位，当前未使用，必须为 0
 *   Bit 6 (0x40): MPF_CRYPTO  — 加密标志。置位表示 payload 经 SM4-CBC 加密，尾部附 SM3-HMAC
 *   Bit 5 (0x20): MPF_PONG   — 心跳响应帧（PONG），响应对端 PING 请求
 *   Bit 4 (0x10): MPF_PING   — 心跳探测帧（PING），用于检测对端存活状态
 *   Bit 3 (0x08): MPF_RST    — 强制复位帧（RST），立即终止通道，不经过优雅关闭流程
 *   Bit 2 (0x04): MPF_FIN    — 通道关闭请求帧（FIN），发起 TCP 式四次挥手
 *   Bit 1 (0x02): MPF_ACK    — 确认帧（ACK），响应 SYN 或 FIN，完成握手/挥手
 *   Bit 0 (0x01): MPF_SYN    — 通道建立请求帧（SYN），发起三次握手
 *
 *   特殊值：flags == 0x00 (MPF_DATA) 表示纯数据帧，无控制语义
 *   MPF_CTRL_MASK (0x3F) 掩码覆盖所有控制位（bit0~bit5），用于快速判断帧类型
 * ─────────────────────────────────────────────────────────────────────────── */
#define MPF_DATA                0x00        /* 数据帧标志：flags 低 6 位全 0，表示无控制语义 */
#define MPF_SYN                 0x01        /* SYN 标志：通道建立请求，发起三次握手第一步 */
#define MPF_ACK                 0x02        /* ACK 标志：确认响应，用于 SYN-ACK 和 FIN-ACK */
#define MPF_FIN                 0x04        /* FIN 标志：通道关闭请求，发起四次挥手 */
#define MPF_RST                 0x08        /* RST 标志：强制复位，立即关闭通道，不等待对端确认 */
#define MPF_PING                0x10        /* PING 标志：心跳探测请求，定期发送以检测对端存活 */
#define MPF_PONG                0x20        /* PONG 标志：心跳探测响应，收到 PING 后立即回复 */
#define MPF_CRYPTO              0x40        /* CRYPTO 标志：payload 经 SM4-CBC 加密且含 SM3-HMAC 尾部 */
#define MPF_CTRL_MASK           0x3F        /* 控制帧掩码：bit0~bit5 全 1，用于 IS_CTRL_FRAME 宏快速判断 */

/* ── 帧类型判断宏 ───────────────────────────────────────────────────────────
 * IS_CTRL_FRAME(flags):   若 flags 中任意控制位（SYN/ACK/FIN/RST/PING/PONG）置位则返回真
 * IS_DATA_FRAME(flags):   若 flags 中所有控制位均为 0 则返回真（即纯数据帧）
 * IS_CRYPTO_FRAME(flags): 若 flags 中 MPF_CRYPTO 位为 1 则返回真，表示 payload 已加密
 * ─────────────────────────────────────────────────────────────────────────── */
#define IS_CTRL_FRAME(flags)    ((flags) & MPF_CTRL_MASK)
#define IS_DATA_FRAME(flags)    (((flags) & MPF_CTRL_MASK) == 0)
#define IS_CRYPTO_FRAME(flags)  ((flags) & MPF_CRYPTO)

/* ── 以太网帧常量 ───────────────────────────────────────────────────────────
 * ETH_HDR_SIZE:       标准以太网头部大小 14 字节（DST_MAC(6) + SRC_MAC(6) + EtherType(2)）
 *                     注意：不含 IEEE 802.1Q VLAN 标签（+4 字节），当前不支持 VLAN 环境
 * ETH_MTU:            标准以太网 MTU 为 1500 字节，即链路层 payload 上限
 * ETH_MAX_PAYLOAD:    最大以太网载荷，与 ETH_MTU 相同（包含 MyProto 帧头 + KCP 段 + 加密开销）
 * MAX_FRAME_SIZE:     最大帧缓冲区大小 1550 字节（ETH_MTU + 加密开销 64B 的安全余量）
 * ETH_MAC_ADDR_LEN:   MAC 地址固定为 6 字节（48 位 IEEE OUI + NIC specific）
 * ─────────────────────────────────────────────────────────────────────────── */
#define ETH_HDR_SIZE            14          /* 以太网帧头大小（字节）：DST_MAC(6) + SRC_MAC(6) + EtherType(2) */
#define ETH_MTU                 1500        /* 标准以太网最大传输单元（字节） */
#define ETH_MAX_PAYLOAD         1500        /* 最大以太网 payload（字节），等于 ETH_MTU */
#define MAX_FRAME_SIZE          1600        /* 最大帧缓冲区（字节）：≥ ETH_MTU(1500) + CRYPTO_OVERHEAD(64) */
#define ETH_MAC_ADDR_LEN        6           /* MAC 地址长度（字节）：IEEE 802 标准 48 位地址 */

/* 编译时断言：确保 ETH_MAX_PAYLOAD 能安全转换为 int 类型（受限于 kcp_wrap_input 接口签名）。
 * 若未来引入 jumbo frame（MTU > 32767），需同步修改 kcp_wrap_input 参数类型为 size_t。 */
_Static_assert(ETH_MAX_PAYLOAD <= INT_MAX,
               "ETH_MAX_PAYLOAD exceeds INT_MAX; update kcp_wrap_input signature");

/* ── KCP 参数 ───────────────────────────────────────────────────────────────
 * KCP 是 MyProto 底层使用的可靠传输协议，以下常量控制其行为：
 *
 * KCP_MTU_CONSERVATIVE (1400): 保守 MTU，适用于不确定链路 MTU 或存在额外封装的环境
 * KCP_MTU_PERFORMANCE  (1478): 高性能 MTU，ETH_MTU(1500) - 以太网头(14) - MyProto头(9) + 1 字节余量
 * KCP_MSS_CONSERVATIVE (1376): 保守 MSS = KCP_MTU_CONSERVATIVE - KCP 开销(24)
 * KCP_MSS_PERFORMANCE  (1454): 高性能 MSS = KCP_MTU_PERFORMANCE - KCP 开销(24)
 * KCP_SEND_WINDOW (1024): 发送窗口大小（KCP 段数），越大吞吐越高但内存越多
 * KCP_RECV_WINDOW (1024): 接收窗口大小（KCP 段数），需 >= 发送窗口以避免对端等待
 * KCP_NODELAY  (1):   启用 nodelay 模式，禁用 KCP 内部的 Nagle 式小包合并算法
 * KCP_INTERVAL (10):   KCP 内部时钟 tick 间隔（毫秒），ikcp_update 调用频率的基础
 * KCP_RESEND   (2):    快速重传阈值：收到 ≥2 次重复 ACK 时立即重传（不等超时）
 * KCP_NC       (1):    禁用 KCP 内置拥塞控制（No Congestion），流量控制完全由应用层管理
 * KCP_UPDATE_INTERVAL (10): 主循环调用 ikcp_update 的间隔（毫秒），应与 KCP_INTERVAL 保持一致
 * ─────────────────────────────────────────────────────────────────────────── */
#define KCP_MTU_CONSERVATIVE    1400        /* 保守 KCP MTU（字节）：适用于不确定网络环境 */
#define KCP_MTU_PERFORMANCE     1478        /* 高性能 KCP MTU（字节）：ETH_MTU - ETH_HDR - MyProto_HDR + 1 */
#define KCP_MSS_CONSERVATIVE    1376        /* 保守 KCP MSS（字节）：KCP_MTU_CONSERVATIVE - KCP 内部开销(24) */
#define KCP_MSS_PERFORMANCE     1454        /* 高性能 KCP MSS（字节）：KCP_MTU_PERFORMANCE - KCP 内部开销(24) */
#define KCP_SEND_WINDOW         1024        /* KCP 发送窗口（段数）：控制未确认段的发送上限 */
#define KCP_RECV_WINDOW         1024        /* KCP 接收窗口（段数）：控制接收缓冲区的段数上限 */
#define KCP_NODELAY             1           /* 启用 nodelay 模式：禁用 KCP 小包合并，降低延迟 */
#define KCP_INTERVAL            10          /* KCP 内部时钟 tick 间隔（毫秒）：影响超时计算精度 */
#define KCP_RESEND              2           /* 快速重传阈值：重复 ACK 次数达到此值立即重传 */
#define KCP_NC                  1           /* 禁用 KCP 拥塞控制：不启用慢启动和拥塞避免算法 */
#define KCP_UPDATE_INTERVAL     10          /* ikcp_update 调用间隔（毫秒）：主循环轮询周期 */

/* ── 性能调优默认值 ─────────────────────────────────────────────────────────
 * 这些参数控制 AF_PACKET 套接字缓冲、发送重试策略、本地 TCP 缓冲、
 * KCP 流控水位线以及每轮处理上限，直接影响系统吞吐量与延迟。
 *
 * perf_af_packet_sndbuf / rcvbuf (16 MiB):
 *   设置 AF_PACKET 原始套接字的 SO_SNDBUF / SO_RCVBUF，减少内核丢包。
 *   对于 10 Gbps 链路建议 ≥ 16 MiB，1 Gbps 链路 4 MiB 即可。
 *
 * perf_af_packet_send_retry_max (8):
 *   当 sendto() 返回 EAGAIN（内核发送队列满）时的最大重试次数。
 *   每次重试间隔 perf_af_packet_send_wait_ms (1 ms)，总计最多等待 8 ms。
 *
 * perf_proxy_tcp_sockbuf (4 MiB):
 *   本地 TCP 套接字的 SO_SNDBUF / SO_RCVBUF，用于 frontend↔backend 间的代理转发。
 *
 * perf_proxy_recv_buf_max (16 MiB):
 *   本地 socket 写端阻塞时，KCP→socket 方向待发送数据的缓冲上限。
 *   达到上限后暂停 KCP 读取（背压机制），防止无限制内存增长。
 *
 * perf_kcp_read_pause_waitsnd (KCP_SEND_WINDOW × 4):
 *   KCP waitsnd（等待发送的段数）超过此高水位时暂停从 local_fd 读取。
 *   防止本地应用写入速度远超网络发送速度导致 KCP 发送队列无限膨胀。
 *
 * perf_kcp_read_resume_waitsnd (KCP_SEND_WINDOW × 2):
 *   当 waitsnd 降至低水位以下时恢复从 local_fd 读取，形成滞回控制。
 *
 * perf_max_frames_per_cycle (8192):
 *   主循环每轮最多从 AF_PACKET 套接字处理的帧数，防止单轮占用 CPU 过久。
 * ─────────────────────────────────────────────────────────────────────────── */
#define PERF_AF_PACKET_SNDBUF           (16 * 1024 * 1024) /* AF_PACKET 套接字发送缓冲区大小（字节） */
#define PERF_AF_PACKET_RCVBUF           (16 * 1024 * 1024) /* AF_PACKET 套接字接收缓冲区大小（字节） */
#define PERF_AF_PACKET_SEND_RETRY_MAX   8                  /* sendto() EAGAIN 最大重试次数 */
#define PERF_AF_PACKET_SEND_WAIT_MS     1                  /* sendto() 重试间隔（毫秒） */
#define PERF_PROXY_TCP_SOCKBUF          (4 * 1024 * 1024)  /* 本地代理 TCP 套接字缓冲区大小（字节） */
#define PERF_PROXY_RECV_BUF_MAX         (16 * 1024 * 1024) /* 本地 socket 写阻塞时待发送缓冲上限（字节） */
#define PERF_KCP_READ_PAUSE_WAITSND     (KCP_SEND_WINDOW * 4) /* KCP 读暂停高水位（waitsnd 段数） */
#define PERF_KCP_READ_RESUME_WAITSND    (KCP_SEND_WINDOW * 2) /* KCP 读恢复低水位（waitsnd 段数） */
#define PERF_KCP_IMMEDIATE_FLUSH        1                  /* KCP 入队后是否立即调用 ikcp_flush：1=立即，0=延迟 */
#define PERF_MAX_FRAMES_PER_CYCLE       8192               /* 主循环每轮最多处理 AF_PACKET 帧数（防止 CPU 独占） */

/* ── 通道（Channel）常量 ────────────────────────────────────────────────────
 * MAX_CHANNELS (65536):
 *   最大通道数配置上限。channel_id 为 uint32_t，但实际可并发通道数受此常量限制。
 *   主要用于数组大小声明（如 channels[]、listener_base[]、cb_open[]）。
 *
 * CHANNEL_HASH_SIZE_DEFAULT (1024):
 *   哈希表默认桶数。使用链地址法解决冲突，负载因子 > 2 时考虑扩容。
 *
 * CHANNEL_RECV_BUF_SIZE (8192):
 *   每个通道的 KCP→socket 待发送缓冲区的初始容量（字节），按需扩容至 CHANNEL_RECV_BUF_MAX。
 *
 * KCP_APP_RECV_BUF_SIZE (64 KiB):
 *   KCP 单条应用消息（ikcp_recv 返回的一个完整上层消息）的接收缓冲区大小。
 *
 * CHANNEL_ID_STATIC_MIN (1):
 *   静态通道 ID 从 1 开始分配，0 保留用于管理通道。
 *
 * HEARTBEAT_CH_ID (0xFFFFFFFF):
 *   全局心跳通道 ID，与普通数据通道无冲突（普通通道 ID ≤ 65535）。
 * ─────────────────────────────────────────────────────────────────────────── */
#define MAX_CHANNELS            65536       /* 最大通道数：channel_id 数组和查找表的容量上限 */
#define SPAWN_MAX_CHANNELS      256         /* 单实例 SPAWN 最大通道数（栈安全上限） */
#define CHANNEL_HASH_SIZE_DEFAULT 1024      /* 通道哈希表默认桶数：使用链地址法解决哈希冲突 */
#define CHANNEL_RECV_BUF_SIZE   8192        /* 通道接收缓冲区初始容量（字节）：按需动态扩容 */
#define CHANNEL_RECV_BUF_MAX    PERF_PROXY_RECV_BUF_MAX /* 通道接收缓冲区最大容量（兼容旧代码别名） */
#define KCP_APP_RECV_BUF_SIZE   (64 * 1024) /* KCP 应用层单消息接收缓冲区大小（字节） */
#define CHANNEL_ID_STATIC_MIN   1           /* 静态通道 ID 最小值：0 保留给管理通道 */
#define HEARTBEAT_CH_ID         0xFFFFFFFF  /* 全局心跳通道 ID：不与任何普通数据通道冲突 */

/* ── 超时与心跳 ─────────────────────────────────────────────────────────────
 * HEARTBEAT_INTERVAL (10 秒):
 *   全局心跳帧（PING）的发送间隔。每个周期检查 last_global_heartbeat，
 *   若超过此间隔则通过专用心跳通道发送 PING 帧。
 *
 * HEARTBEAT_TIMEOUT (60 秒):
 *   对端心跳超时阈值。若在此时间内未收到对端任何心跳响应（PONG），
 *   视为链路中断，触发全局重连或告警。
 *
 * CHANNEL_IDLE_TIMEOUT (300 秒 / 5 分钟):
 *   单通道空闲超时。若某个通道在 5 分钟内无任何数据收发，自动关闭。
 *   适用于 frontend 上客户端异常断开但未发送 FIN 的场景。
 *
 * CHANNEL_GRACEFUL_TIMEOUT (30 秒):
 *   优雅关闭超时。发送 FIN 后等待对端 FIN-ACK 的最大时间。
 *   超时后强制进入 CLOSED 状态，回收通道资源。
 * ─────────────────────────────────────────────────────────────────────────── */
#define HEARTBEAT_INTERVAL      10          /* 心跳 PING 发送间隔（秒）：定期检测链路存活状态 */
#define HEARTBEAT_TIMEOUT       60          /* 心跳超时（秒）：对端无 PONG 响应的最大容忍时间 */
#define CHANNEL_IDLE_TIMEOUT    300         /* 通道空闲超时（秒）：无数据收发自动关闭，释放资源 */
#define CHANNEL_GRACEFUL_TIMEOUT 30         /* 优雅关闭超时（秒）：等待对端 FIN-ACK 的最大时间 */

/* ── MAC 学习防御常量 ───────────────────────────────────────────────────────
 * 在点到点 AF_PACKET 链路中，对端 MAC 地址通常固定。但攻击者可能伪造
 * 不同源 MAC 的以太网帧，试图劫持或干扰通信。MAC 学习防御机制如下：
 *
 *   1. 当收到来自"未知 MAC"的有效 MyProto 帧时，不立即接受，而是记录为候选 MAC
 *   2. 在 PEER_MAC_CONFIRM_WINDOW (500 ms) 时间窗口内，
 *      同一候选 MAC 必须被至少 PEER_MAC_CONFIRM_MIN (3) 个有效帧确认
 *   3. 确认后更新 g_ctx->peer_mac，后续仅接受来自该 MAC 的帧
 *   4. 若窗口内未达到最小确认数，候选 MAC 被丢弃，计数器重置
 *
 * 此机制有效防御 ARP 欺骗和 MAC 泛洪攻击，同时允许合法的对端网卡更换。
 * ─────────────────────────────────────────────────────────────────────────── */
#define PEER_MAC_CONFIRM_MIN      3         /* MAC 确认最小帧数：候选 MAC 需在窗口内被 ≥3 帧确认 */
#define PEER_MAC_CONFIRM_WINDOW   500       /* MAC 确认时间窗口（毫秒）：超时未达阈值则重置候选 */

/* ── 未知帧速率限制（DoS 防御）─────────────────────────────────────────────
 * 当收到 channel_id 无效（无对应通道）的 MyProto 帧时，每帧消耗 1 个 token。
 * 每秒最多允许 UNKNOWN_FRAME_MAX_PER_SEC 个未知帧通过。
 * token 桶容量 = 速率上限，每秒补充一次。
 * 超过速率的帧被静默丢弃并计入 diag_rx_unknown_dropped 计数器。
 * 此机制防御攻击者向随机 channel_id 发送大量垃圾帧消耗 CPU。
 * ─────────────────────────────────────────────────────────────────────────── */
#define UNKNOWN_FRAME_MAX_PER_SEC 100       /* 未知通道帧速率上限（帧/秒）：token bucket 算法 */

/* ── 断路器（Circuit Breaker）常量 ──────────────────────────────────────────
 * 每个通道独立维护一个断路器状态机，防止故障通道反复重连消耗资源。
 *
 * 状态迁移：
 *   CLOSED（正常）→ 连续 CB_MAX_FAILURES(5) 次失败 → OPEN（拒绝连接）
 *   OPEN → 等待 CB_HALF_OPEN_DELAY(30s) → HALF_OPEN（允许探测）
 *   HALF_OPEN → 每隔 CB_PROBE_INTERVAL(5s) 发送一次探测
 *   HALF_OPEN → 探测成功 → CLOSED（恢复正常）
 *   HALF_OPEN → 探测失败 → OPEN（重新计时）
 *
 * 断路器数组 cb_open[MAX_CHANNELS] 存储每个通道的断路器状态（0=CLOSED, 1=OPEN）。
 * ─────────────────────────────────────────────────────────────────────────── */
#define CB_MAX_FAILURES           5         /* 断路器触发阈值：连续失败次数达到此值进入 OPEN 状态 */
#define CB_HALF_OPEN_DELAY       30         /* OPEN 到 HALF_OPEN 冷却时间（秒）：防止立即重试 */
#define CB_PROBE_INTERVAL         5         /* HALF_OPEN 状态探测间隔（秒）：测试对端是否恢复 */

/* ── 全局内存配额 ───────────────────────────────────────────────────────────
 * PERF_MAX_MEMORY_MB_DEFAULT (2048 MB = 2 GiB):
 *   进程级内存使用上限。通过 global_memory_used 字段跟踪当前堆分配近似值。
 *   达到上限后：拒绝新建通道、暂停接收缓冲区扩容、触发 OOM 优雅降级。
 *   设置为 0 表示不限制（仅用于调试环境）。
 * ─────────────────────────────────────────────────────────────────────────── */
#define PERF_MAX_MEMORY_MB_DEFAULT 2048     /* 默认全局内存上限（MiB）：达到后触发 OOM 降级流程 */

/* ── 自诊断常量 ─────────────────────────────────────────────────────────────
 * 运行时自诊断模块定期输出系统健康状态，便于运维监控和问题定位。
 *
 * DIAG_INTERVAL_SEC (300 秒 = 5 分钟):
 *   自诊断输出间隔。每次输出包括：通道数、内存使用、丢包率、加密错误累计等。
 *
 * DIAG_CRYPTO_ERROR_THRESH (50):
 *   加密错误累计告警阈值。若在诊断周期内加密/解密错误累计超过此值，
 *   输出 WARN 级别日志，提示可能存在密钥不匹配或数据篡改。
 * ─────────────────────────────────────────────────────────────────────────── */
#define DIAG_INTERVAL_SEC         300        /* 自诊断输出间隔（秒）：定期输出系统健康快照 */
#define DIAG_CRYPTO_ERROR_THRESH  50         /* 加密错误累计告警阈值：超过后输出 WARN 日志 */

/* ── OOM 优雅降级：应急缓冲池 ───────────────────────────────────────────────
 * EMERGENCY_POOL_SIZE (8192 字节):
 *   进程启动时预分配的静态缓冲区，位于 global_ctx_t 的 emergency_pool[] 字段。
 *   当全局内存配额耗尽（global_memory_used >= perf_max_memory_mb）时，
 *   正常的 malloc 被阻塞，但关键控制帧（RST/Terminate）仍需发送以通知对端。
 *   此时从应急缓冲池中分配临时内存，确保控制面不受数据面 OOM 影响。
 *   emergency_pool_used 标志防止池被重复消费，需进程重启恢复。
 * ─────────────────────────────────────────────────────────────────────────── */
#define EMERGENCY_POOL_SIZE       8192       /* 应急缓冲池大小（字节）：OOM 时用于关键控制帧发送 */

/* ── 加密常量 ───────────────────────────────────────────────────────────────
 * SM4 是中国国家密码管理局发布的对称分组密码算法（GB/T 32907-2016）。
 * SM3 是中国国家密码管理局发布的密码杂凑算法（GB/T 32905-2016）。
 *
 * 加密方案：SM4-CBC + SM3-HMAC（Encrypt-then-MAC）
 *   - SM4 密钥长度：128 位（16 字节），分组大小 128 位
 *   - SM4-CBC 需要 16 字节随机初始化向量（IV），每帧独立生成
 *   - SM3-HMAC 输出 32 字节（256 位），对 ciphertext 计算 MAC
 *   - 帧格式：[SM4-IV 16B] [SM4-CBC Ciphertext] [SM3-HMAC 32B]
 *   - CRYPTO_OVERHEAD = IV(16) + PKCS7 填充(max 16) + HMAC(32) = 64 字节最大值
 * ─────────────────────────────────────────────────────────────────────────── */
#define SM4_KEY_SIZE            16          /* SM4 密钥长度（字节）：128 位对称密钥 */
#define SM4_IV_SIZE             16          /* SM4-CBC 初始化向量长度（字节）：每帧随机生成 */
#define SM3_HMAC_SIZE           32          /* SM3-HMAC 输出长度（字节）：256 位完整性校验值 */
#define SM4_IV_LEN             SM4_IV_SIZE
#define SM3_HMAC_LEN           SM3_HMAC_SIZE
/* CRYPTO_OVERHEAD = IV(16) + PKCS7_padding_max(16) + HMAC(32) = 64。
 * 宏体中两个 SM4_IV_SIZE 含义不同：第一个为实际 SM4-CBC IV，第二个为
 * PKCS7 填充块大小上限（与 SM4 块大小相等，复用 SM4_IV_SIZE 常量）。 */
#define CRYPTO_OVERHEAD         (SM4_IV_SIZE + SM4_IV_SIZE + SM3_HMAC_SIZE)

/* ── CRC32 ──────────────────────────────────────────────────────────────────
 * CRC32_SIZE (4 字节):
 *   可选的 CRC32 校验值，附加在 MyProto payload 尾部（加密之前）。
 *   用于快速检测传输过程中的比特错误，在解密前即可丢弃损坏帧，
 *   避免无效解密消耗 CPU。可通过 crc_enabled 配置项启用/禁用。
 * ─────────────────────────────────────────────────────────────────────────── */
#define CRC32_SIZE              4           /* CRC32 校验值大小（字节） */

/* ── AF_PACKET 常量 ─────────────────────────────────────────────────────────
 * AF_PACKET_FRAME_SIZE (1600):
 *   从 AF_PACKET 套接字读取的帧缓冲区大小，需 ≥ ETH_MTU(1500) + 安全余量。
 *
 * BPF_FILTER_MAX (256):
 *   BPF（Berkeley Packet Filter）过滤器程序的最大长度（指令数）。
 *   用于内核态按 EtherType + channel_id 过滤帧，减少用户态无效拷贝。
 * ─────────────────────────────────────────────────────────────────────────── */
#define AF_PACKET_FRAME_SIZE    1600        /* AF_PACKET recvfrom 缓冲区大小（字节） */
#define BPF_FILTER_MAX          256         /* BPF 过滤器最大指令数 */

/* ── 代理常量 ───────────────────────────────────────────────────────────────
 * MAX_LISTEN_ADDR / MAX_REMOTE_ADDR (64):
 *   监听地址和远端地址字符串的最大长度，支持 IPv4 点分十进制和域名。
 *   IPv6 地址（最长 45 字符）也在此范围内。
 *
 * MAX_INTERFACE_NAME (32):
 *   网卡接口名称最大长度（Linux IFNAMSIZ = 16，此处预留更大空间）。
 *
 * MAX_CONFIG_PATH / MAX_PID_PATH (256):
 *   配置文件路径和 PID 文件路径的最大长度，支持绝对路径。
 *
 * DEFAULT_LISTEN_ADDR "127.0.0.1":
 *   默认监听地址为本地回环，仅接受本地客户端连接。生产环境建议改为 0.0.0.0。
 * ─────────────────────────────────────────────────────────────────────────── */
#define MAX_LISTEN_ADDR         64          /* 监听地址字符串最大长度（字节） */
#define MAX_REMOTE_ADDR         64          /* 远端地址字符串最大长度（字节） */
#define MAX_INTERFACE_NAME      32          /* 网卡接口名称最大长度（字节） */
#define MAX_CONFIG_PATH         256         /* 配置文件路径最大长度（字节） */
#define MAX_PID_PATH            256         /* PID 文件路径最大长度（字节） */
#define DEFAULT_LISTEN_ADDR     "127.0.0.1" /* 默认监听地址：仅本机回环，生产环境建议 0.0.0.0 */

/* ============================================================================
 * 枚举类型
 * ============================================================================ */

/* ── 通道状态机（channel_state_t）───────────────────────────────────────────
 * 仿 TCP 状态机的简化版本，用于 MyProto 通道的完整生命周期管理。
 *
 * 状态迁移图（详细）：
 *
 *                       ┌──────────────────────────────────────────────┐
 *                       │                                              │
 *                       ▼                                              │
 *   CLOSED ──(发送SYN)──▶ SYN_SENT ──(收到ACK)──▶ ESTABLISHED         │
 *      │                      │                        │               │
 *      │                  (收到SYN,                    │               │
 *      │                   发送ACK)                    │               │
 *      │                      ▼                        │               │
 *      └────────────── SYN_RCVD ──(收到ACK)────────────┘               │
 *                             │                                        │
 *   ESTABLISHED ──(主动关闭,发送FIN)──▶ FIN_SENT                       │
 *        │                                  │                          │
 *   (收到FIN,                            (收到ACK)                     │
 *    发送ACK)                                │                          │
 *        │                                   ▼                          │
 *        ▼                             等待对端FIN ◀───────────────────┘
 *   FIN_RCVD ◀──(收到FIN,发送ACK)────────┘
 *        │
 *   (超时/主动关闭)
 *        ▼
 *   TIME_WAIT ──(2MSL 超时)──▶ CLOSED
 *
 * 状态说明：
 *   CHANNEL_CLOSED (0):      初始状态或已完全关闭，不占用任何资源（KCP 未创建）
 *   CHANNEL_SYN_SENT (1):    已发送 SYN，等待对端 SYN-ACK，使用指数退避重传
 *   CHANNEL_SYN_RCVD (2):    收到对端 SYN 并已回复 ACK，等待对端确认 ACK
 *   CHANNEL_ESTABLISHED (3): 三次握手完成，双向数据通信中，KCP 保证可靠传输
 *   CHANNEL_FIN_SENT (4):    主动发送 FIN，等待对端 FIN-ACK，仍可接收对端数据
 *   CHANNEL_FIN_RCVD (5):    收到对端 FIN，已回复 ACK，等待本地应用关闭
 *   CHANNEL_TIME_WAIT (6):   等待 2MSL（最大段生存时间 × 2），防止延迟帧干扰后续新连接
 *
 * 设计要点：
 *   - SYN_SENT / SYN_RCVD：握手中使用指数退避重传 SYN/ACK，初始间隔 200ms，最大 6.4s
 *   - ESTABLISHED：正常通信状态，KCP 负责可靠传输和流控
 *   - FIN_SENT / FIN_RCVD：TCP 式四次挥手，允许对端完成剩余数据发送
 *   - TIME_WAIT：2MSL 等待（约 60 秒），确保网络中所有延迟帧均已消亡
 * ─────────────────────────────────────────────────────────────────────────── */
typedef enum {
    CHANNEL_CLOSED      = 0,    /* 关闭状态：初始状态或已完全关闭，KCP 实例已释放 */
    CHANNEL_SYN_SENT    = 1,    /* SYN 已发送：等待对端 SYN-ACK 响应，指数退避重传 */
    CHANNEL_SYN_RCVD    = 2,    /* SYN 已接收：已回复 ACK，等待对端确认完成握手 */
    CHANNEL_ESTABLISHED = 3,    /* 已建立连接：三次握手完成，双向 KCP 数据通信中 */
    CHANNEL_FIN_SENT    = 4,    /* FIN 已发送：主动关闭方等待对端 FIN，仍可接收数据 */
    CHANNEL_FIN_RCVD    = 5,    /* FIN 已接收：被动关闭方等待本地应用完成数据发送 */
    CHANNEL_TIME_WAIT   = 6     /* 时间等待：2MSL 等待期，防止残余延迟帧干扰新连接 */
} channel_state_t;

/* ── 通道角色（channel_role_t）──────────────────────────────────────────────
 * 每个通道在握手和通信过程中扮演一种角色，决定其在协议交互中的行为。
 *
 * CHANNEL_ROLE_INITIATOR (0) — 主动发起方：
 *   由 frontend LISTENER accept 新客户端连接后创建，或由 backend 主动向
 *   frontend 发起连接时创建。负责发送 SYN 帧启动三次握手。
 *
 * CHANNEL_ROLE_RESPONDER (1) — 被动响应方：
 *   收到对端 SYN 帧后自动创建，回复 SYN-ACK，完成握手后进入 ESTABLISHED。
 *   通常运行在 backend 节点上。
 *
 * CHANNEL_ROLE_LISTENER (2) — 纯监听方：
 *   仅 bind + listen 本地端口，不主动发送 SYN。用于 frontend 节点的服务端口
 *   监听通道。它本身不参与 KCP 数据传输，仅为每个 accept 的新客户端连接
 *   派生 INITIATOR 子通道（通过 listener_next[] 分配动态 channel_id）。
 * ─────────────────────────────────────────────────────────────────────────── */
typedef enum {
    CHANNEL_ROLE_INITIATOR = 0, /* 主动发起方：发送 SYN，驱动三次握手流程 */
    CHANNEL_ROLE_RESPONDER = 1, /* 被动响应方：收到 SYN 后回复 ACK，完成握手 */
    CHANNEL_ROLE_LISTENER  = 2  /* 纯监听方：仅 accept 本地连接，为每个客户端派生 INITIATOR 子通道 */
} channel_role_t;

/* ── 通道标志位（channel flags）─────────────────────────────────────────────
 * 这些标志位存储在 channel_t.flags 字段中，控制通道的特殊行为。
 *
 * CH_FLAG_STATIC_LISTENER (0x01):
 *   标记该通道为静态 listener（由配置文件定义），不会被 destroy 销毁。
 *   热重载时通过此标志识别持久通道，与动态子通道区分。
 *
 * CH_FLAG_RELOAD_MARKED (0x02):
 *   热重载过程中的临时标记。reload 流程：
 *     1) 给所有现有通道打上此标记
 *     2) 遍历新配置，匹配成功的通道清除标记
 *     3) 仍有标记的通道 = 旧配置中存在但新配置中已删除 → 触发关闭
 *
 * CH_FLAG_KCP_READ_PAUSED (0x04):
 *   KCP 发送队列高水位标志。当 KCP waitsnd 超过暂停水位时置位，
 *   暂停从 local_fd 读取数据。降至恢复水位后清除。
 *
 * CH_FLAG_MGMT_CHANNEL (0x08):
 *   管理通道标志。标记该通道为 master-worker 间管理通道，
 *   数据走 mgmt_dispatch 而非普通 proxy 转发路径。
 * ─────────────────────────────────────────────────────────────────────────── */
#define CH_FLAG_STATIC_LISTENER 0x01        /* 静态 listener 通道：不被 destroy 销毁，热重载时识别持久通道 */
#define CH_FLAG_RELOAD_MARKED   0x02        /* 热重载临时标记：用于增量比对新旧配置，标记残留通道以关闭 */
#define CH_FLAG_KCP_READ_PAUSED 0x04        /* KCP 读取暂停标志：发送队列高水位，暂停本地 socket 读取 */
#define CH_FLAG_MGMT_CHANNEL    0x08        /* 管理通道标志：收发走 mgmt_dispatch 路径而非 proxy 转发 */

/* ── 节点角色常量 ───────────────────────────────────────────────────────────
 * 在 Master-Worker 多进程架构下，每个进程具有一个节点角色：
 *
 * NODE_ROLE_NONE (0):    未配置角色（向后兼容旧版单进程模式）
 * NODE_ROLE_MANAGER (1): Master 管理进程，负责配置分发、进程监管、信号转发
 * NODE_ROLE_WORKER (2):  Worker 工作进程，负责数据面（AF_PACKET + KCP + 代理）
 * ─────────────────────────────────────────────────────────────────────────── */
/* 注意：NODE_ROLE_* 为 #define 宏（值 0/1/2），与 node_type_t 枚举
 * (NODE_TYPE_FRONTEND=0, NODE_TYPE_BACKEND=1) 数值重叠但语义完全独立。
 * NODE_ROLE 用于 Master-Worker 多进程角色区分，NODE_TYPE 用于代理节点
 * 拓扑定位（前端/后端），两者不可混用。 */
#define NODE_ROLE_NONE      0   /* 未配置角色：向后兼容旧版单进程独立运行模式 */
#define NODE_ROLE_MANAGER   1   /* Manager 角色：Master 进程，配置管理与进程监管 */
#define NODE_ROLE_WORKER    2   /* Worker 角色：Worker 进程，数据面处理 */

/* ── 管理模块常量 ───────────────────────────────────────────────────────────
 * MGMT_MAX_WORKERS (64):
 *   单个 Manager 可管理的最大 Worker 数量，与 MAX_INSTANCES 保持同步。
 *
 * Worker 状态：
 *   MGMT_WORKER_STATE_JOINING  (0): Worker 已连接但尚未完成注册握手
 *   MGMT_WORKER_STATE_ACTIVE   (1): Worker 已注册，正常运行中
 *   MGMT_WORKER_STATE_DEGRADED (2): Worker 心跳超时，标记为降级但仍保留状态
 * ─────────────────────────────────────────────────────────────────────────── */
/* 注意：MGMT_MAX_WORKERS 与 MAX_INSTANCES (见 master_config_t 定义处，当前值 64)
 * 必须保持相同数值，两者分别控制 Manager 侧 Worker 容量和 Master 侧实例数组
 * 大小。编译期无 static_assert 约束，修改任一方必须同步更新另一方。 */
#define MGMT_MAX_WORKERS        64          /* 最大 Worker 数量：Manager 可同时管理的 Worker 上限 */
#define MGMT_WORKER_STATE_JOINING   0       /* Worker 加入中：已连接但未完成注册握手 */
#define MGMT_WORKER_STATE_ACTIVE    1       /* Worker 活跃：已注册，正常运行中 */
#define MGMT_WORKER_STATE_DEGRADED  2       /* Worker 降级：心跳超时，功能受限但未移除 */

/* ── 批次操作 pending 跟踪 ──────────────────────────────────────────────────
 * pending_op_t: Manager 侧跟踪异步批次操作（如 batch SPAWN）的状态。
 *
 * PENDING_OP_MAX (8): 最大并发 pending 操作数。批量 SPAWN 为低频操作，
 * 使用固定长度数组 + 线性扫描空闲槽位，避免动态分配。
 *
 * PENDING_OP_TARGET_MAX (16): 单次操作最大目标 Worker 数。
 *
 * PENDING_TIMEOUT (5): 默认等待 ACK 超时（秒）。
 * ─────────────────────────────────────────────────────────────────────────── */
#define PENDING_OP_MAX          8
#define PENDING_OP_TARGET_MAX   16
#define PENDING_TIMEOUT_SEC     5

typedef enum {
    PENDING_SPAWN_BATCH = 0,  /* 批量 SPAWN_INSTANCE 操作 */
} pending_op_type_t;

typedef struct {
    int     worker_id;       /* 目标 Worker 的 workers[] 索引 */
    int     send_seq;        /* SPAWN_INSTANCE 消息的 seq (用于 ACK 匹配) */
    uint8_t acked  : 1;     /* 已收到 ACK */
    uint8_t success: 1;     /* ACK 状态: 1=成功, 0=失败 */
} pending_target_t;

typedef struct {
    int             op_id;          /* 操作 ID (pending_ops[] 槽位索引) */
    pending_op_type_t type;         /* PENDING_SPAWN_BATCH */
    pending_target_t targets[PENDING_OP_TARGET_MAX];
    int             n_targets;      /* 目标总数 */
    int             n_done;         /* 已收到 ACK 数量 */
    int             n_success;      /* 成功 ACK 数量 */
    time_t          deadline;       /* 超时时刻 (= time(NULL) + PENDING_TIMEOUT_SEC) */
    uint8_t         active  : 1;   /* 1=活跃, 0=空闲槽位 */
    char            channels_json[4096]; /* 用于回退的 channels 配置 */
} pending_op_t;

/* ── 远程实例调度文件路径 ──────────────────────────────────────────────────
 * Master 进程通过 JSON 文件与外部调度器（如 systemd、supervisor、编排系统）
 * 进行进程间通信，实现实例的启停和配置切换。
 *
 * SPAWN_REQUEST / RESPONSE:  创建新 Worker 实例的请求/响应文件
 * KILL_REQUEST / RESPONSE:   终止指定 Worker 实例的请求/响应文件
 * SWITCH_CONFIG_REQUEST / RESPONSE: 切换实例配置文件的请求/响应文件
 *
 * SPAWN_WAIT_RETRIES (50):   等待新 Worker 启动的最大轮询次数
 * SPAWN_WAIT_US (10000):     每次轮询间隔 10 ms，总计最多等待 500 ms
 * ─────────────────────────────────────────────────────────────────────────── */
#define SPAWN_REQUEST_FILE      "/tmp/kcp-spawn.json"             /* 创建实例请求文件路径 */
#define SPAWN_RESPONSE_FILE     "/tmp/kcp-spawn-resp.json"        /* 创建实例响应文件路径 */
#define KILL_REQUEST_FILE       "/tmp/kcp-kill.json"              /* 终止实例请求文件路径 */
#define KILL_RESPONSE_FILE      "/tmp/kcp-kill-resp.json"         /* 终止实例响应文件路径 */
#define SWITCH_CONFIG_REQUEST_FILE "/tmp/kcp-switch-config.json"  /* 切换配置请求文件路径 */
#define SWITCH_CONFIG_RESPONSE_FILE "/tmp/kcp-switch-config-resp.json" /* 切换配置响应文件路径 */
#define CHANNEL_CTL_FILE     "/tmp/kcp-channel-ctl.json"    /* 通道控制转发（M→child） */
#define CHANNEL_CTL_RESPONSE_FILE \
    "/tmp/kcp-channel-ctl-resp.json"          /* 通道控制转发响应（预留，暂未使用）*/
#define SPAWN_WAIT_RETRIES      50      /* 等待 Worker 启动最大轮询次数：每 10ms 一次 */
#define SPAWN_WAIT_US           10000   /* 每次轮询间隔（微秒）：10ms */

/* ── API / 日志 / 限流常量 ──────────────────────────────────────────────────
 * LOG_BUF_SIZE (1000):
 *   API 审计日志环形缓冲区容量，存储最近的日志条目。
 *
 * LOG_ENTRY_MAX_LEN (256):
 *   单条审计日志消息的最大长度（字节），超出部分截断。
 *
 * RATE_LIMIT_MAX_IPS (256):
 *   API 速率限制器可跟踪的最大独立 IP 数量，使用 LRU 式淘汰。
 * ─────────────────────────────────────────────────────────────────────────── */
#define LOG_BUF_SIZE            1000        /* API 审计日志环形缓冲区容量（条数） */
#define LOG_ENTRY_MAX_LEN       256         /* 单条审计日志消息最大长度（字节） */
#define RATE_LIMIT_MAX_IPS      256         /* API 速率限制最大跟踪 IP 数量 */

/* ── 代理节点类型（node_type_t）─────────────────────────────────────────────
 * 决定节点在网络拓扑中的位置和数据转发方向：
 *
 * NODE_TYPE_FRONTEND (0) — 前端节点：
 *   - 部署在客户端侧（靠近用户）
 *   - 在本地 bind 端口，接受客户端 TCP/UDP 连接
 *   - 将客户端数据通过 Gap-Proxy 隧道转发到 backend
 *   - 每个客户端连接对应一个动态 INITIATOR 通道
 *   - 角色以 LISTENER + INITIATOR 为主
 *
 * NODE_TYPE_BACKEND (1) — 后端节点：
 *   - 部署在服务端侧（靠近真实服务）
 *   - 接收 frontend 隧道数据，转发到本地实际服务端口
 *   - 角色以 RESPONDER 为主（被动接受 frontend 的连接）
 *   - 一个 backend 可同时服务多个 frontend 的对等连接
 *
 * 典型部署拓扑：
 *   客户端 ──TCP──▶ [FRONTEND] ──AF_PACKET(KCP)──▶ [BACKEND] ──TCP──▶ 真实服务
 * ─────────────────────────────────────────────────────────────────────────── */
typedef enum {
    NODE_TYPE_FRONTEND  = 0,    /* 前端节点：面向客户端，接收 TCP/UDP 连接并隧道转发 */
    NODE_TYPE_BACKEND   = 1     /* 后端节点：面向真实服务，将隧道数据解封后本地转发 */
} node_type_t;

/* ── 加密模式（crypto_mode_t）───────────────────────────────────────────────
 * CRYPTO_MODE_NONE (0):    不加密，payload 以明文传输（仅用于可信内网环境）
 * CRYPTO_MODE_SM4_SM3 (1): SM4-CBC 加密 + SM3-HMAC 完整性校验（推荐生产环境）
 * ─────────────────────────────────────────────────────────────────────────── */
typedef enum {
    CRYPTO_MODE_NONE    = 0,    /* 无加密模式：payload 明文传输，无完整性保护 */
    CRYPTO_MODE_SM4_SM3 = 1     /* SM4-SM3 模式：SM4-CBC 加密 + SM3-HMAC 完整性校验 */
} crypto_mode_t;

/* ============================================================================
 * 协议头结构体
 * ============================================================================ */

/* ── MyProto 帧头格式（myproto_hdr_t，9 字节紧凑布局）───────────────────────
 *
 * 字节布局（网络字节序，大端）：
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         channel_id                            |  4 字节
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    flags      |           payload_len         |  header_crc  |  1B + 2B + 2B
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 字段详细说明：
 *   channel_id  (4 字节, uint32_t):
 *     全局唯一的通道标识符，取值范围 [0, 65535]。
 *     用于多路复用/解复用：发送端填入目标通道 ID，接收端根据此字段查找对应 channel_t。
 *     也作为通道哈希表的查找键。
 *
 *   flags       (1 字节, uint8_t):
 *     帧标志位，按位编码（参见 MPF_* 常量定义）。
 *     bit7 保留，bit6 = CRYPTO，bit5 = PONG，bit4 = PING，
 *     bit3 = RST，bit2 = FIN，bit1 = ACK，bit0 = SYN。
 *
 *   payload_len (2 字节, uint16_t):
 *     MyProto 帧头之后的 payload 长度（字节），不含帧头本身。
 *     对于控制帧（SYN/ACK/FIN/RST/PING/PONG），此字段为 0。
 *     对于数据帧，为 KCP 段长度（可能含加密开销和 CRC）。
 *     最大值受 ETH_MAX_PAYLOAD - MYPROTO_HDR_SIZE 限制。
 *
 *   header_crc  (2 字节, uint16_t):
 *     帧头 CRC16 校验值（CCITT 多项式 0x1021），覆盖前 7 字节（channel_id + flags + payload_len）。
 *     用于检测帧头比特错误，防止 channel_id 损坏导致帧被路由到错误通道。
 *     注意：这仅保护帧头，payload 的完整性由 KCP 重传机制或 SM3-HMAC 保证。
 *
 * 设计理由：
 *   - 9 字节极小开销（对比 TCP 头 20 字节、UDP 头 8 字节），适合低延迟高吞吐场景
 *   - __attribute__((packed)) 强制紧凑布局，消除编译器填充，确保跨平台二进制一致
 *   - header_crc 保护关键路由信息（channel_id），避免帧头单比特错误导致静默投递错误
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint32_t channel_id;   /* 通道标识符（网络字节序）：唯一标识一个逻辑通道，也用作哈希表键 */
    uint8_t  flags;        /* 帧标志位：按位编码的控制帧类型和加密标记（参见 MPF_* 定义） */
    uint16_t payload_len;  /* 负载长度（字节，网络字节序）：帧头之后 payload 的字节数 */
    uint16_t header_crc;   /* 帧头 CRC16 校验：覆盖 channel_id + flags + payload_len（7 字节） */
} myproto_hdr_t;

/* 编译时断言：确保 myproto_hdr_t 在跨平台、跨编译器场景下始终为 9 字节 */
_Static_assert(sizeof(myproto_hdr_t) == 9, "myproto_hdr_t must be 9 bytes");

/* ============================================================================
 * 配置结构体
 * ============================================================================ */

/* ── 客户端访问控制 (channel_acl_t) ─────────────────────────────────────────
 * 每个 listener 通道可配置客户端 IP/端口白名单，实现细粒度访问控制。
 *
 * ACL 条目类型：
 *   acl_ip_type_t:
 *     ACL_IP_SINGLE (1): 单个 IP 地址精确匹配
 *     ACL_IP_CIDR   (2): CIDR 子网匹配（如 192.168.0.0/24）
 *     ACL_IP_RANGE  (3): IP 地址范围匹配（起始 IP ~ 结束 IP）
 *
 *   acl_port_type_t:
 *     ACL_PORT_SINGLE (1): 单个端口精确匹配
 *     ACL_PORT_RANGE  (2): 端口范围匹配（起始端口 ~ 结束端口）
 *
 * 匹配逻辑：IP 规则和端口规则均为 OR 关系（匹配任一条即放行）。
 * 若 ACL 启用但无任何规则，默认放行所有连接（白名单模式：规则存在时匹配规则）。
 * 若 ACL 未启用（enabled=0），所有连接均放行。
 * ─────────────────────────────────────────────────────────────────────────── */
#define MAX_ACL_IPS    16                    /* 每个 listener 最大 IP 白名单条目数 */
#define MAX_ACL_PORTS  8                     /* 每个 listener 最大端口白名单条目数 */

typedef enum {
    ACL_IP_SINGLE = 1,    /* 单 IP 匹配：addr 字段为精确 IP 地址 */
    ACL_IP_CIDR   = 2,    /* CIDR 子网匹配：addr 为网络地址，mask_or_end 为子网掩码 */
    ACL_IP_RANGE  = 3     /* IP 范围匹配：addr 为起始 IP，mask_or_end 为结束 IP */
} acl_ip_type_t;

typedef enum {
    ACL_PORT_SINGLE = 1,  /* 单端口匹配：port_start 为精确端口号，port_end 等于 port_start */
    ACL_PORT_RANGE  = 2   /* 端口范围匹配：port_start 为起始端口，port_end 为结束端口 */
} acl_port_type_t;

typedef struct {
    uint8_t  type;           /* acl_ip_type_t：ACL_IP_SINGLE / ACL_IP_CIDR / ACL_IP_RANGE */
    uint32_t addr;           /* 网络字节序：起始 IP 地址（SINGLE / CIDR / RANGE 均使用此字段） */
    uint32_t mask_or_end;    /* CIDR 模式：网络字节序子网掩码；RANGE 模式：网络字节序结束 IP */
} acl_ip_entry_t;

typedef struct {
    uint8_t  type;           /* acl_port_type_t：ACL_PORT_SINGLE / ACL_PORT_RANGE */
    uint16_t port_start;     /* 起始端口号（主机字节序） */
    uint16_t port_end;       /* 结束端口号（主机字节序），SINGLE 模式下等于 port_start */
} acl_port_entry_t;

typedef struct {
    uint8_t          enabled;     /* 是否启用 ACL：0=不启用（全放行），1=启用白名单模式 */
    uint8_t          ip_count;    /* IP 白名单有效条目数：范围为 [0, MAX_ACL_IPS] */
    acl_ip_entry_t   ips[MAX_ACL_IPS];     /* IP 白名单条目数组 */
    uint8_t          port_count;  /* 端口白名单有效条目数：范围为 [0, MAX_ACL_PORTS] */
    acl_port_entry_t ports[MAX_ACL_PORTS]; /* 端口白名单条目数组 */
} channel_acl_t;

/* ── 单通道配置（channel_config_t）──────────────────────────────────────────
 * 每个 channel_config_t 描述一条转发规则，将本地监听端点映射到远端目标端点。
 *
 * 字段说明：
 *   channel_id:
 *     全局唯一通道标识。静态配置的通道使用固定 ID（≥ CHANNEL_ID_STATIC_MIN）。
 *     动态通道由 listener_next[] 分区机制分配 ID。
 *
 *   listen_addr / listen_port:
 *     frontend 节点上接受客户端连接的本地地址和端口。
 *     backend 节点上通常不使用此字段（除非需要反向连接）。
 *
 *   remote_addr / remote_port:
 *     backend 节点上转发到的真实服务地址和端口。
 *     frontend 节点上通常不使用此字段。
 *
 *   source_port:
 *     backend 节点连接远端服务时绑定的源端口。0 表示由内核随机分配。
 *     用于某些需要固定源端口的场景（如防火墙规则匹配）。
 *
 *   is_tcp:
 *     1 = TCP 代理模式（创建 TCP socket），0 = UDP 代理模式（创建 UDP socket）。
 *     影响本地 socket 创建方式和数据读取语义。
 *
 *   enabled:
 *     0 = 跳过此配置条目（热重载时可动态禁用某条规则）。
 *     仅影响静态通道，不影响已建立的动态子通道。
 *
 *   max_sessions:
 *     此端口允许的最大并发会话（子通道）数。0 表示使用默认值 1。
 *     frontend 上每 accept 一个新客户端连接即创建一个 session 子通道。
 *     达到上限后新连接被拒绝（TCP RST 或 UDP ICMP Port Unreachable）。
 *
 *   client_acl:
 *     客户端 IP/端口访问控制白名单。仅 enabled=1 时生效。
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint32_t    channel_id;                 /* 通道全局唯一标识：静态 ID ≥ 1，动态 ID 由分区机制分配 */
    uint16_t    listen_port;                /* 本地监听端口（主机字节序）：frontend 接受客户端连接的端口 */
    uint16_t    remote_port;                /* 远端目标端口（主机字节序）：backend 转发到的真实服务端口 */
    uint16_t    source_port;                /* backend 连接远端时绑定的源端口（主机字节序），0=内核随机分配 */
    char        listen_addr[MAX_LISTEN_ADDR];  /* 本地监听地址字符串：如 "127.0.0.1" 或 "0.0.0.0" */
    char        remote_addr[MAX_REMOTE_ADDR];  /* 远端目标地址字符串：如 "192.168.1.100" */
    uint8_t     is_tcp;                     /* 传输层协议类型：1=TCP 代理，0=UDP 代理 */
    uint8_t     enabled;                    /* 启用标志：0=禁用（跳过此规则），1=启用 */
    uint16_t    max_sessions;               /* 最大并发会话数：0=默认值 1，超限后拒绝新客户端连接 */
    channel_acl_t client_acl;               /* 客户端 IP/端口访问控制白名单 */
} channel_config_t;

/* ── 节点配置（node_config_t）───────────────────────────────────────────────
 * 标识进程在 Master-Worker 架构中的身份。
 *
 * node_id:   节点唯一标识字符串（最长 64 字符），用于管理通道中的身份认证
 * node_role: 节点角色（NODE_ROLE_MANAGER / NODE_ROLE_WORKER / NODE_ROLE_NONE）
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    char    node_id[65];           /* 节点标识符（字符串，最多 64 字符）：管理通道身份认证凭据 */
    uint8_t node_role;            /* 节点角色：NODE_ROLE_NONE / NODE_ROLE_MANAGER / NODE_ROLE_WORKER */
} node_config_t;

/* ── 管理通道配置（mgmt_config_t）───────────────────────────────────────────
 * Master-Worker 管理通道的详细参数，控制 Worker 注册、心跳保活和重连策略。
 *
 * enabled:            是否启用管理通道（0=独立模式，1=Master-Worker 模式）
 * channel_id:         管理通道使用的 channel_id（通常为 0，与数据通道隔离）
 * manager_port:       Manager 侧监听端口（Manager 在本地 bind 此端口等待 Worker 连接）
 * listen_port:        Worker 侧监听端口（Worker 在本地 bind 此端口接收 Manager 指令）
 * keepalive_interval: 管理通道心跳间隔（秒），Worker 定期发送健康检查帧
 * keepalive_timeout:  管理通道心跳超时（秒），Manager 超时未收到心跳则标记 Worker DEGRADED
 * reconnect_interval: Worker 断开后重连间隔（秒），使用指数退避，上限为此值的 8 倍
 * shared_secret:      预共享密钥（最长 64 字符），用于 HMAC-SHA256 管理消息认证。
 *                     空字符串表示不启用认证（仅用于可信内网测试环境）。
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t     enabled;               /* 管理通道启用标志：0=独立模式，1=Master-Worker 模式 */
    uint16_t    channel_id;            /* 管理通道 ID：通常为 0，与数据通道 ID 空间隔离 */
    uint16_t    manager_port;          /* Manager 侧监听端口（主机字节序）：等待 Worker 连接 */
    uint16_t    listen_port;           /* Worker 侧监听端口（主机字节序）：接收 Manager 指令 */
    int         keepalive_interval;    /* 管理心跳发送间隔（秒）：Worker 定期向 Manager 报告存活 */
    int         keepalive_timeout;     /* 管理心跳超时（秒）：Manager 超时未收到心跳则标记降级 */
    int         reconnect_interval;    /* Worker 重连间隔（秒）：断开后重连的基础间隔，指数退避 */
    char        shared_secret[65];     /* 预共享密钥（字符串，最多 64 字符）：HMAC-SHA256 认证凭据 */
} mgmt_config_t;

/* ── 管理模块 Worker 跟踪结构体（mgmt_worker_t）─────────────────────────────
 * Manager 进程为每个已连接的 Worker 维护此结构体，用于状态监控和配置分发。
 *
 * node_id:           Worker 节点标识，与 node_config_t.node_id 对应
 * state:             Worker 当前状态（JOINING / ACTIVE / DEGRADED）
 * channel_id:        与此 Worker 通信的管理通道 ID
 * registered_at:     Worker 完成注册的时间戳
 * last_seen:         最后一次收到 Worker 消息的时间戳（用于超时检测）
 * degraded_since:    Worker 进入 DEGRADED 状态的时间戳，0 表示未降级
 * health_resp_count: 连续收到的健康检查响应计数（用于从 DEGRADED 恢复为 ACTIVE）
 * last_seq:          最后收到的管理消息序列号（用于检测消息丢失和重放攻击）
 * config_version:    Worker 当前使用的配置版本号（uint64_t 防回绕），
 *                    Manager 据此判断是否需要推送新配置
 * ─────────────────────────────────────────────────────────────────────────── */

/* ── Worker 实例追踪类型 ── */
#define MGMT_MAX_INSTANCES_PER_WORKER 128

typedef struct {
    char     instance_name[65];
    uint16_t ethertype;
    uint8_t  node_type;
    int      cpu_affinity;
    char     channels_json[4096];   /* SPAWN时的通道配置JSON，重启恢复用 */
    /* ── 可观测运行时字段 ── */
    pid_t    pid;                   /* 实例进程 PID，0=未启动或已退出 */
    uint32_t spawned_at;            /* 实例创建时间（CLOCK_MONOTONIC 秒） */
    uint32_t restart_count;         /* 实例崩溃重启次数 */
} mgmt_worker_instance_t;

typedef enum {
    INSTANCE_SYNC_IDLE     = 0,
    INSTANCE_SYNC_PENDING  = 1,
    INSTANCE_SYNC_RETRYING = 2,
    INSTANCE_SYNC_DONE     = 3
} instance_sync_state_t;

typedef struct {
    char        node_id[65];            /* Worker 节点标识字符串 */
    uint8_t     state;                  /* Worker 状态：MGMT_WORKER_STATE_JOINING / ACTIVE / DEGRADED */
    uint32_t    channel_id;             /* 与此 Worker 通信的管理通道 ID */
    time_t      registered_at;          /* 注册完成时间戳（Unix 时间），注意32位系统上 year2038 */
    time_t      last_seen;              /* 最后一次收到消息的时间戳 */
    time_t      degraded_since;         /* 进入 DEGRADED 状态的时间戳，0=未降级 */
    int         health_resp_count;      /* 连续健康检查响应计数：用于从 DEGRADED 恢复 ACTIVE */
    uint64_t    last_seq;               /* 最后收到的管理消息序列号（防消息重放） */
    uint64_t    config_version;         /* Worker 当前配置版本号（uint64_t 防止整数回绕） */

    /* ── 动态实例追踪（Manager 侧） ── */
    mgmt_worker_instance_t instances[MGMT_MAX_INSTANCES_PER_WORKER];
    int                     instance_count;
} mgmt_worker_t;

/* ── 管理模块运行时状态（mgmt_state_t）──────────────────────────────────────
 * 管理模块的全局运行时状态，嵌入在 global_ctx_t 中。
 *
 * workers[]:        已连接的 Worker 跟踪数组，最大 MGMT_MAX_WORKERS 个
 * worker_count:     当前活跃 Worker 数量（JOINING + ACTIVE + DEGRADED）
 * mgmt_seq:         全局管理消息序列号（uint64_t 防回绕），每条管理消息递增
 * config_version:   当前全局配置版本号（uint64_t 防回绕），配置变更时递增
 * worker_registered: Worker 侧标志：0=未确认注册，1=已收到 Manager 注册 ACK
 * mgmt_channel:     指向管理通道 channel_t 的指针（channel_id=0 的预留通道）
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    mgmt_worker_t   workers[MGMT_MAX_WORKERS]; /* Worker 跟踪数组：存储每个 Worker 的运行状态 */
    int             worker_count;              /* 当前活跃 Worker 数量 */
    uint64_t        mgmt_seq;                  /* 管理消息序列号（uint64_t 防止回绕） */
    uint64_t        config_version;            /* 当前全局配置版本号（uint64_t 防止回绕） */
    uint32_t        worker_registered;         /* Worker 注册确认标志：0=未确认，1=已获 ACK */
    struct channel_s *mgmt_channel;            /* 管理通道指针（channel_id=0） */
    pending_op_t    pending_ops[PENDING_OP_MAX]; /* 批次操作跟踪（Manager 侧） */
    uint64_t        applied_config_version;    /* Worker 侧：已应用的 CONFIG_PUSH 版本 */

    /* ── 动态实例同步（Worker 侧） ── */
    uint32_t        sync_state;                /* instance_sync_state_t */
    time_t          sync_last_attempt;
    int             sync_retry_count;
    /* ── 配置文件持久化 ── */
    char            config_path[MAX_CONFIG_PATH]; /* Manager 配置文件路径 */
    /*
     * 警告：workers[] 数组使 sizeof(mgmt_state_t) ≈ 32 MB，禁止栈上分配。
     * 所有分配必须通过 global_ctx_t（calloc 分配），详见 mgmt_init()。
     */
} mgmt_state_t;

/* ── API 审计日志条目（log_entry_t）─────────────────────────────────────────
 * API 服务器将每个管理操作记录为一条审计日志，存储在环形缓冲区中。
 *
 * timestamp: 操作发生时间（Unix 时间戳）
 * level:     日志级别（0=INFO, 1=WARN, 2=ERROR, 3=AUDIT）
 * message:   日志消息文本（最长 LOG_ENTRY_MAX_LEN 字节，超出截断）
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    time_t      timestamp;                    /* 日志时间戳（Unix 时间） */
    uint32_t    channel_id;                   /* 通道ID：0=全局日志, >0=某通道日志 */
    int         level;                        /* 日志级别：0=INFO, 1=WARN, 2=ERROR, 3=AUDIT */
    char        message[LOG_ENTRY_MAX_LEN];   /* 日志消息内容（最长 255 字节 + null） */
} log_entry_t;

/* ── API 速率限制条目（rate_limit_entry_t）─────────────────────────────────
 * 基于滑动窗口的 IP 级别速率限制，防止 API 暴力破解和 DoS 攻击。
 *
 * ip:           客户端 IP 地址字符串
 * count:        当前窗口内的请求计数
 * window_start: 当前窗口起始时间戳
 *
 * 算法：当 count 超过 api_rate_limit 且 time_now - window_start < api_rate_limit_window
 *       时，拒绝该 IP 的后续请求。窗口过期后自动重置。
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    char        ip[64];             /* 客户端 IP 地址字符串（支持 IPv4 和 IPv6） */
    int         count;              /* 当前时间窗口内的请求计数 */
    time_t      window_start;       /* 当前速率限制窗口的起始时间戳 */
} rate_limit_entry_t;

/* ── 加密配置（encryption_config_t）─────────────────────────────────────────
 * SM4 密钥配置，以十六进制字符串形式存储，兼容外部配置管理系统的 crypto.h 接口。
 *
 * enabled: 是否启用加密（0=明文传输，1=SM4-CBC + SM3-HMAC）
 * sm4_key: SM4 密钥的十六进制字符串表示（32 字符 = 128 位 + null 终止符）
 *          示例："0123456789ABCDEFFEDCBA9876543210"
 * ─────────────────────────────────────────────────────────────────────────── */
#define SM4_KEY_HEX_LEN     32        /* SM4 密钥十六进制字符串长度：128 位 = 32 个十六进制字符 */
#define SM4_KEY_BIN_LEN     16        /* SM4 密钥二进制长度（字节）：128 位 = 16 字节 */

typedef struct {
    uint8_t     enabled;              /* 加密启用标志：0=明文传输，1=SM4-CBC + SM3-HMAC */
    char        sm4_key[SM4_KEY_HEX_LEN + 1]; /* SM4 密钥（十六进制字符串，32 字符 + null 终止符） */
} encryption_config_t;

/* ── 全局配置（global_config_t）─────────────────────────────────────────────
 * global_config_t 是所有模块配置的聚合体，由配置文件解析后填充。
 * 在 Master-Worker 架构中，此结构体同时作为 shared 默认值和 worker 实例配置的基类。
 *
 * 字段分组说明：
 *
 * [网卡配置]
 *   interface:   绑定的物理网卡名称（如 "eth0", "enp1s0"），用于 AF_PACKET bind
 *   ethertype:   自定义 EtherType 值（默认 0x88B5），多实例时每个实例必须不同
 *   local_mac:   本地网卡 MAC 地址（6 字节二进制），从网卡自动获取或手动配置
 *   peer_mac:    对端网卡 MAC 地址（6 字节二进制），可配置或通过 MAC 学习自动获取
 *
 * [KCP 参数]
 *   kcp_mtu:         KCP 最大传输单元（字节），通常 1400（保守）或 1478（高性能）
 *   kcp_send_window: KCP 发送窗口大小（段数），默认 1024
 *   kcp_recv_window: KCP 接收窗口大小（段数），默认 1024
 *   kcp_nodelay:     nodelay 模式（0/1），默认 1 启用
 *   kcp_interval:    KCP 内部时钟间隔（毫秒），默认 10
 *   kcp_resend:      快速重传阈值（重复 ACK 数），默认 2
 *   kcp_nc:          是否禁用 KCP 拥塞控制（0/1），默认 1 禁用
 *
 * [性能调优]
 *   perf_af_packet_sndbuf:       AF_PACKET SO_SNDBUF 大小（字节）
 *   perf_af_packet_rcvbuf:       AF_PACKET SO_RCVBUF 大小（字节）
 *   perf_af_packet_send_retry_max: EAGAIN 最大重试次数
 *   perf_af_packet_send_wait_ms:   每次重试等待时间（毫秒）
 *   perf_proxy_tcp_sockbuf:      本地 TCP socket 缓冲区大小（字节）
 *   perf_proxy_recv_buf_max:     接收缓冲上限（字节），触发背压
 *   perf_kcp_read_pause_waitsnd:  KCP 读暂停高水位（waitsnd 段数）
 *   perf_kcp_read_resume_waitsnd: KCP 读恢复低水位（waitsnd 段数）
 *   perf_kcp_immediate_flush:     KCP send 后是否立即 flush（0/1）
 *   perf_max_frames_per_cycle:    每轮最多处理 AF_PACKET 帧数
 *   perf_max_memory_mb:           全局内存配额上限（MiB），0=不限制
 *   perf_max_peer_per_channel:    每通道最大对等体数，0=不限制
 *
 * [代理配置]
 *   node_type:   节点类型（NODE_TYPE_FRONTEND / NODE_TYPE_BACKEND）
 *   node:        管理节点身份配置（node_id + node_role）
 *   management:  管理通道详细参数
 *   max_channels: 最大通道数（≤ MAX_CHANNELS）
 *
 * [API 配置]
 *   api_enabled:           是否启用 HTTP API 管理接口
 *   api_listen_addr:       API 服务器监听地址
 *   api_listen_port:       API 服务器监听端口
 *   api_auth_token:        API Bearer Token 认证凭据
 *   api_rate_limit:        API 每秒最大请求数
 *   api_rate_limit_window: API 速率统计窗口（秒）
 *   heartbeat_interval:    全局心跳发送间隔（秒）
 *   heartbeat_timeout:     全局心跳超时阈值（秒）
 *
 * [加密与 CRC]
 *   encryption:   加密子配置（enabled + sm4_key）
 *   crc_enabled:  是否启用 CRC32 校验（0=禁用，1=启用）
 *
 * [NIC MTU]
 *   auto_set_nic_mtu: 是否自动设置网卡 MTU（0=否，1=是）
 *   nic_mtu:          目标网卡 MTU 值
 *   auto_kcp_mtu:     是否从 nic_mtu 自动计算 kcp_mtu（kcp_mtu = nic_mtu - 开销）
 *
 * [多实例与进程管理]
 *   pid_file:      PID 文件完整路径
 *   instance_name: 实例名称（用于日志标识和多实例区分）
 *
 * [通道列表]
 *   channels[]:    通道配置数组（静态通道列表）
 *   channel_count: 实际通道配置条目数
 *
 * [统计]
 *   stats_enabled: 是否启用统计收集和输出
 *
 * [Watchdog 心跳]
 *   heartbeat_fd: 心跳 pipe 写端文件描述符（worker → master）。
 *                 -1 表示 standalone 模式（无 master 监管）。
 *                 Master 通过 fork 将此 fd 传递给 worker。
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* ── 网卡配置 ── */
    char        interface[MAX_INTERFACE_NAME];  /* 网卡名称（如 "eth0", "enp1s0"）：AF_PACKET bind 目标 */
    uint16_t    ethertype;                      /* 自定义 EtherType：多实例隔离的关键参数 */
    uint8_t     local_mac[ETH_MAC_ADDR_LEN];    /* 本地 MAC 地址（6 字节二进制）：以太网帧源地址 */
    uint8_t     peer_mac[ETH_MAC_ADDR_LEN];     /* 对端 MAC 地址（6 字节二进制）：以太网帧目的地址 */

    /* ── KCP 参数 ── */
    int         kcp_mtu;                /* KCP 最大传输单元（字节） */
    int         kcp_send_window;        /* KCP 发送窗口大小（段数）：未确认段上限 */
    int         kcp_recv_window;        /* KCP 接收窗口大小（段数）：接收缓冲段上限 */
    int         kcp_nodelay;            /* nodelay 模式：1=启用（低延迟），0=禁用（低带宽消耗） */
    int         kcp_interval;           /* KCP 内部时钟 tick 间隔（毫秒） */
    int         kcp_resend;             /* 快速重传阈值：重复 ACK 次数达到此值立即重传 */
    int         kcp_nc;                 /* 拥塞控制开关：1=禁用 KCP 内置拥塞控制，0=启用 */

    /* ── 性能调优配置 ── */
    int         perf_af_packet_sndbuf;          /* AF_PACKET SO_SNDBUF 大小（字节） */
    int         perf_af_packet_rcvbuf;          /* AF_PACKET SO_RCVBUF 大小（字节） */
    int         perf_af_packet_send_retry_max;  /* sendto() EAGAIN 最大重试次数 */
    int         perf_af_packet_send_wait_ms;    /* sendto() 每次重试等待时间（毫秒） */
    int         perf_proxy_tcp_sockbuf;         /* 本地 TCP 代理 socket 缓冲区大小（字节） */
    int         perf_proxy_recv_buf_max;        /* 接收缓冲上限（字节）：触发 KCP 读暂停背压 */
    int         perf_kcp_read_pause_waitsnd;    /* KCP 读暂停高水位（waitsnd 段数） */
    int         perf_kcp_read_resume_waitsnd;   /* KCP 读恢复低水位（waitsnd 段数） */
    int         perf_kcp_immediate_flush;       /* KCP send 后立即 flush：1=立即，0=批量 */
    int         perf_max_frames_per_cycle;      /* 主循环每轮最多处理 AF_PACKET 帧数 */
    int         perf_max_memory_mb;             /* 全局内存配额上限（MiB）：0=不限制 */
    int         perf_max_peer_per_channel;      /* 每通道最大对等体数：0=不限制 */

    /* ── 代理配置 ── */
    node_type_t node_type;            /* 代理节点类型：NODE_TYPE_FRONTEND / NODE_TYPE_BACKEND */
    node_config_t node;               /* 管理节点身份：node_id + node_role */
    mgmt_config_t management;         /* 管理通道详细参数配置 */
    int          max_channels;          /* 最大并发通道数（≤ MAX_CHANNELS），校验时拒绝 ≤0 */

    /* ── API 配置 ── */
    uint8_t     api_enabled;            /* API 服务器启用标志：0=禁用，1=启用 */
    char        api_listen_addr[32];    /* API 服务器监听地址（如 "127.0.0.1"） */
    uint16_t    api_listen_port;        /* API 服务器监听端口 */
    char        api_auth_token[65];     /* API 认证令牌（Bearer Token，最长 64 字符） */
    int         api_rate_limit;         /* API 每秒最大请求数（令牌桶算法） */
    int         api_rate_limit_window;  /* API 速率统计窗口大小（秒） */

    /* ── 日志配置 ── */
    char        log_file[256];          /* 本地日志文件路径（空=禁用文件输出） */
    uint8_t     log_syslog;             /* syslog 输出：0=禁用，1=启用 */
    char        log_syslog_facility[32]; /* syslog facility: "daemon"/"local0"-"local7" */
    char        log_syslog_remote[64];   /* 远程 syslog 服务器: "host" 或 "host:port"（空=禁用） */
    uint8_t     log_session_close;       /* 会话关闭日志：0=禁用，1=启用 */
    int          heartbeat_interval;    /* 全局心跳 PING 发送间隔（秒） */
    int          heartbeat_timeout;     /* 全局心跳超时阈值（秒）：对端无响应则视为断连 */

    /* ── 加密配置 ── */
    encryption_config_t encryption;       /* 加密子配置：enabled + sm4_key 十六进制字符串 */

    /* ── CRC 配置 ── */
    uint8_t     crc_enabled;            /* CRC32 启用标志：0=禁用，1=对 payload 附加 CRC32 校验 */

    /* ── NIC MTU 配置 ── */
    uint8_t     auto_set_nic_mtu;       /* 自动设置网卡 MTU：0=不自动设置，1=启动时设置 nic_mtu */
    int         nic_mtu;                /* 目标网卡 MTU 值（auto_set_nic_mtu=1 时生效） */
    uint8_t     auto_kcp_mtu;           /* 自动计算 KCP MTU：0=否，1=根据 nic_mtu 自动计算 kcp_mtu */

    /* ── 多实例配置 ── */
    char        pid_file[MAX_PID_PATH]; /* PID 文件完整路径（如 "/var/run/kcp.pid"） */
    char        instance_name[MAX_LISTEN_ADDR]; /* 实例名称（用于日志标识和多实例区分） */

    /* ── 通道列表 ── */
    /*
     * 警告：此数组使 sizeof(global_config_t) ≈ 22 MB，禁止栈上分配。
     * 所有分配必须通过 calloc() / malloc()，详见 create_global_config()。
     */
    channel_config_t channels[MAX_CHANNELS]; /* 通道配置数组：每项一条转发规则 */
    int              channel_count;          /* 实际通道配置条目数 */

    /* ── 统计 ── */
    uint8_t     stats_enabled;          /* 统计收集启用标志：0=禁用，1=收集并定期输出统计信息 */

    /* ── Watchdog 心跳 ── */
    int         heartbeat_fd;           /* 心跳 pipe 写端 fd（worker→master）：-1=standalone 模式无 watchdog */
} global_config_t;

/* ============================================================================
 * 运行时结构体
 * ============================================================================ */

/* ── 通道统计计数器（channel_stats_t）───────────────────────────────────────
 * 每个通道独立维护的统计计数器，用于性能监控和故障诊断。
 *
 * tx_frames / tx_bytes:  发送的 MyProto 帧总数和字节总数（含帧头和加密开销）
 * rx_frames / rx_bytes:  接收的 MyProto 帧总数和字节总数
 * retransmits:           KCP 重传次数（通过 ikcp_waitsnd 变化间接统计）
 * tx_errors:             发送错误数（sendto 失败次数）
 * rx_errors:             接收错误数（recvfrom 失败或帧格式错误）
 * crc_errors:            CRC32 校验失败次数
 * crypto_errors:         加密/解密失败次数（密钥不匹配、HMAC 验证失败、数据篡改）
 *
 * 所有计数器为 uint64_t，在通道生命周期内单调递增，不会溢出。
 * 可通过 API 接口查询或定期输出到自诊断日志。
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t    tx_frames;              /* 已发送 MyProto 帧总数 */
    uint64_t    tx_bytes;               /* 已发送字节总数（含帧头和加密开销） */
    uint64_t    rx_frames;              /* 已接收 MyProto 帧总数 */
    uint64_t    rx_bytes;               /* 已接收字节总数（含帧头和加密开销） */
    uint64_t    retransmits;            /* KCP 重传总次数 */
    uint64_t    tx_errors;              /* 发送错误总数（sendto 失败） */
    uint64_t    rx_errors;              /* 接收错误总数（recvfrom 失败或帧格式错误） */
    uint64_t    rx_dropped;             /* 插件丢弃帧数（HP-4 PLUGIN_DROP） */
    uint64_t    crc_errors;             /* CRC32 校验失败总数 */
    uint64_t    crypto_errors;          /* 加密/解密失败总数（HMAC 验证失败等） */
} channel_stats_t;

/* ── 网卡统计（nic_stats_t）─────────────────────────────────── */
typedef struct {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint64_t rx_errors;
    uint64_t tx_errors;
} nic_stats_t;

/* ── 通道结构体（channel_t）─────────────────────────────────────────────────
 * channel_t 是整个系统的核心运行时数据结构，代表一条 MyProto 逻辑通道。
 * 每条通道封装了：协议状态、KCP 传输实例、网络套接字、缓冲区、时间戳与统计。
 *
 * 生命周期：
 *   1. 静态通道创建：从 config.channels[] 初始化，flags 含 CH_FLAG_STATIC_LISTENER
 *   2. 动态通道创建：LISTENER accept 新客户端或收到 SYN 时动态创建
 *   3. 通道销毁：状态回到 CLOSED 后从哈希表移除，释放 KCP 实例和缓冲区内存
 *
 * 字段分组详解：
 *
 * [标识字段]
 *   channel_id:    全局唯一通道标识（uint32_t），也用作哈希表查找键
 *   state:         通道状态机当前状态（channel_state_t 七状态之一）
 *   role:          通道角色（INITIATOR / RESPONDER / LISTENER）
 *   flags:         标志位掩码（CH_FLAG_STATIC_LISTENER / RELOAD_MARKED / KCP_READ_PAUSED / MGMT_CHANNEL）
 *   listener_idx:  指向父 listener 在 config.channels[] 中的索引。
 *                  对于动态子通道，通过此字段获取父 listener 的端口/地址/ACL 配置。
 *                  对于 LISTENER 角色自身，指向自己的配置索引。
 *
 * [KCP 实例]
 *   kcp:           指向 IKCPCB（KCP 控制块）的指针，通道从 SYN_SENT/SYN_RCVD 状态时创建，
 *                  在 CLOSED 状态时释放。NULL 表示 KCP 尚未创建或已销毁。
 *
 * [网络层]
 *   raw_sock:      每通道独立的 AF_PACKET 原始套接字。
 *                  使用独立 raw_sock 而非共享全局 raw_sock 的原因：
 *                  - 每通道可绑定不同的 BPF 过滤器（按 channel_id 过滤）
 *                  - 避免全局锁竞争，提升多通道并发发送性能
 *                  - 独立的 SO_SNDBUF / SO_RCVBUF 隔离
 *   ifindex:       网卡接口索引（通过 ioctl(SIOCGIFINDEX) 获取），用于 bind
 *   peer_mac:      对端 MAC 地址（6 字节），用于构造以太网帧的目的地址
 *   local_mac:     本地 MAC 地址（6 字节），用于构造以太网帧的源地址
 *   ethertype:     此通道使用的 EtherType 值（通常与全局配置一致）
 *
 * [本地套接字]
 *   listen_fd:     仅 LISTENER 角色使用，是 bind + listen 后的监听套接字。
 *                  负责 accept 新的客户端 TCP 连接。
 *   local_fd:      INITIATOR / RESPONDER 角色使用，是 accept 返回的已连接
 *                  套接字（或主动 connect 创建的套接字）。
 *                  数据流向：local_fd ←(read/write)→ KCP → AF_PACKET → 对端
 *   listen_addr:   本地监听地址字符串
 *   listen_port:   本地监听端口（主机字节序）
 *   remote_addr:   远端目标地址字符串（backend 转发目标）
 *   remote_port:   远端目标端口（主机字节序）
 *   source_port:   backend 连接远端时绑定的源端口（0=内核随机）
 *   is_tcp:        TCP(1) 或 UDP(0) 代理模式标志
 *
 * [时间戳]
 *   last_active:    最后一次数据收发的时间戳（CLOCK_MONOTONIC 秒），用于空闲超时检测
 *   last_peer_seen: 最后一次收到对端有效帧的时间戳，用于心跳超时检测
 *   created_at:     通道创建时间戳
 *   syn_sent_at:    SYN 帧发送时间戳，用于 SYN 重传的指数退避计算
 *
 * [缓冲区]
 *   recv_buf:       指向 KCP→socket 方向待发送数据的缓冲区（按需堆分配）。
 *                   当本地 socket 写阻塞时（EAGAIN），KCP 接收的数据暂存在此。
 *                   recv_buf_len 达到 recv_buf_cap 时触发背压（paused=1）。
 *   recv_buf_len:   缓冲区中有效数据的长度（字节）
 *   recv_buf_cap:   缓冲区的当前容量（字节），初始 CHANNEL_RECV_BUF_SIZE，可扩容至 CHANNEL_RECV_BUF_MAX
 *
 * [流控]
 *   paused:         背压标志：1=本地 socket 写阻塞，暂停从 KCP 读取数据。
 *                   恢复条件：recv_buf 被成功写入 socket 后 len 下降。
 *
 * [重传与连接]
 *   syn_retry_count: SYN 重传计数，用于指数退避（1s, 2s, 4s, ... 最大 64s）
 *   fin_retry_count: FIN 重传计数
 *   connect_pending: 异步 TCP connect 进行中标志：1=等待 EPOLLOUT 确认连接完成
 *
 * [统计]
 *   stats:          通道级别统计计数器（channel_stats_t）
 *
 * [链表]
 *   hash_next:      指向哈希冲突链中下一个节点的指针（链地址法），NULL 表示链尾
 * ─────────────────────────────────────────────────────────────────────────── */
struct IKCPCB;  /* KCP 控制块前向声明（定义在 ikcp.h） */

typedef struct channel_s {
    /* ── 标识 ── */
    uint32_t        channel_id;         /* 通道全局唯一标识符：用作哈希表键和协议帧路由 */
    channel_state_t state;              /* 通道状态机当前状态：七状态之一（CLOSED→...→ESTABLISHED→...→CLOSED） */
    channel_role_t  role;               /* 通道角色：INITIATOR / RESPONDER / LISTENER */
    uint32_t        flags;              /* 标志位掩码：CH_FLAG_STATIC_LISTENER / RELOAD_MARKED / KCP_READ_PAUSED / MGMT_CHANNEL */
    uint16_t        listener_idx;       /* 父 listener 在 config.channels[] 中的索引 */

    /* ── KCP 实例 ── */
    struct IKCPCB  *kcp;                /* KCP 控制块指针：通道握手完成后创建，关闭时释放。NULL=未创建 */

    /* ── 网络层 ── */
    int             raw_sock;           /* 每通道独立的 AF_PACKET 原始套接字 fd */
    int             ifindex;            /* 网卡接口索引（用于 bind） */
    uint8_t         peer_mac[ETH_MAC_ADDR_LEN];   /* 对端 MAC 地址（6 字节二进制） */
    uint8_t         local_mac[ETH_MAC_ADDR_LEN];  /* 本地 MAC 地址（6 字节二进制） */
    uint16_t        ethertype;          /* 此通道使用的 EtherType 值 */

    /* ── 本地套接字 ──
     * listen_fd: 仅 LISTENER 角色使用，bind+listen 后的监听套接字，用于 accept 新客户端
     * local_fd:  INITIATOR/RESPONDER 使用，已连接套接字（accept 返回或主动 connect），
     *            数据在 local_fd 与 KCP 之间双向流动
     */
    int             local_fd;           /* 已连接套接字 fd：与本地应用/服务通信的数据端点 */
    int             listen_fd;          /* 监听套接字 fd：仅 LISTENER 角色有效，等待客户端连接 */
    uint16_t        listen_port;        /* 本地监听端口（主机字节序） */
    uint16_t        remote_port;        /* 远端目标端口（主机字节序） */
    uint16_t        source_port;        /* 连接远端时绑定的源端口（主机字节序），0=内核随机分配 */
    char            listen_addr[MAX_LISTEN_ADDR];  /* 本地监听地址字符串 */
    char            remote_addr[MAX_REMOTE_ADDR];  /* 远端目标地址字符串 */
    uint8_t         is_tcp;             /* 传输协议标志：1=TCP 代理模式，0=UDP 代理模式 */

    /* ── 时间戳 ── */
    uint32_t        last_active;        /* 最后数据收发时间（CLOCK_MONOTONIC 秒）：用于空闲超时检测 */
    uint32_t        last_peer_seen;     /* 最后收到对端有效帧的时间：用于心跳超时检测 */
    uint32_t        created_at;         /* 通道创建时间戳（CLOCK_MONOTONIC 秒） */
    uint32_t        syn_sent_at;        /* SYN 帧发送时间戳：用于重传的指数退避计算 */
    uint32_t        fin_rcvd_at;        /* FIN_RCVD 状态进入时间戳：最小 2s 后才允许 → TIME_WAIT */
    uint32_t        last_ack_sent;      /* 上次发送 ACK 的时间戳：per-channel 防抖（1s 内不重发 ACK） */

    /* ── 缓冲区 ── */
    uint8_t        *recv_buf;           /* KCP→socket 方向待发送数据缓冲区指针（按需堆分配） */
    int             recv_buf_len;       /* 缓冲区中有效数据的长度（字节） */
    int             recv_buf_cap;       /* 缓冲区的当前容量（字节），可动态扩容 */

    /* ── 流控 ── */
    int             paused;             /* 背压标志：1=本地 socket 写阻塞，暂停从 KCP 读取数据 */

    /* ── 重传与连接 ── */
    uint8_t         syn_retry_count;    /* SYN 帧重传计数：用于指数退避（1s→2s→4s→...→64s） */
    uint8_t         fin_retry_count;    /* FIN 帧重传计数 */
    uint8_t         connect_pending;    /* 异步 TCP connect 进行中：1=等待 EPOLLOUT 确认连接完成 */

    /* ── 统计 ── */
    channel_stats_t stats;              /* 通道级别统计计数器 */

    /* ── 哈希表链表 ── */
    struct channel_s *hash_next;        /* 哈希冲突链中下一个节点指针：NULL 表示链尾 */
} channel_t;

/* ── 全局上下文（global_ctx_t）──────────────────────────────────────────────
 * global_ctx_t 是系统的单例全局状态，持有所有运行时资源和状态。
 * 整个进程生命周期内只有一个实例（通过全局指针 g_ctx 访问）。
 *
 * 字段分组详解：
 *
 * [AF_PACKET 网络层]
 *   raw_sock:          全局 AF_PACKET 原始套接字（用于接收所有帧的主套接字）
 *   ifindex:           网卡接口索引
 *   local_mac:         本地 MAC 地址（从网卡获取或配置指定）
 *   peer_mac:          对端 MAC 地址（最终确认的 MAC，经 MAC 学习防御验证）
 *   peer_mac_learned:  对端 MAC 是否通过自动学习获得（1=自动学习，0=手动配置）
 *   peer_mac_confirm_count:    MAC 学习确认计数器（候选 MAC 已出现的有效帧数）
 *   peer_mac_confirm_mac:      等待确认的候选 MAC 地址（6 字节）
 *   peer_mac_confirm_ts:       候选 MAC 首次出现的时间戳（用于 500ms 窗口判断）
 *   ethertype:         全局 EtherType 值
 *
 * [OOM 优雅降级：应急缓冲池]
 *   emergency_pool[8192]:  预分配的静态缓冲区，OOM 时用于发送关键控制帧（如 RST）
 *   emergency_pool_used:   应急池已被消费的标志（1=已消费，需重启进程恢复）
 *
 * [配置]
 *   config:  全局配置结构体（global_config_t），从配置文件解析
 *
 * [通道管理]
 *   channel_hash:       通道哈希表（堆分配，大小为 channel_hash_size）
 *                       使用链地址法（channel_t.hash_next）解决冲突
 *   channel_hash_size:  哈希表的桶数（通常为质数以减少冲突）
 *   channel_count:      当前活跃通道总数
 *
 * [epoll 事件循环]
 *   epoll_fd:   epoll 实例的文件描述符，统一管理所有通道的 I/O 事件
 *
 * [运行状态]
 *   running:          运行标志（volatile sig_atomic_t），SIGTERM/SIGINT 将其置 0
 *   reload_requested: 配置重载请求标志（SIGHUP 触发），主循环检测后执行热重载
 *   ctl_requested:    通道控制请求标志（SIGUSR1 触发），用于增量通道操作
 *                     与 reload_requested 的区别：ctl_requested 不重新读取完整配置文件，
 *                     而是读取控制命令执行增量操作（如动态添加/删除单个通道）
 *   start_time:       进程启动时间戳（CLOCK_MONOTONIC 秒）
 *   config_path:      当前配置文件的完整路径（用于 SIGHUP 热重载）
 *   listener_base[]:  每个 listener 的动态 ID 池起始偏移（分区机制核心）
 *                     计算公式：listener_base[i] = i * 分区大小
 *   listener_next[]:  每个 listener 的下一个可用动态 ID（相对 listener_base 的偏移）
 *                     分配新 ID：id = listener_base[idx] + listener_next[idx]++
 *   last_global_heartbeat:  上次发送全局心跳 PING 的时间戳
 *
 * [统计]
 *   last_stats_time:  上次输出统计信息的时间戳
 *
 * [速率限制 — 通道创建（防 SYN flood）]
 *   使用 token bucket 算法限制动态通道的创建速率：
 *   channel_create_timestamp:  上次 token 补充时刻（kcp_wrap_clock 毫秒）
 *   channel_create_tokens:     当前可用 token 数
 *   channel_create_max_per_sec: 每秒最大创建数（tokens/s），0=不限制
 *
 * [速率限制 — 未知帧（DoS 防御）]
 *   使用 token bucket 算法限制未知 channel_id 帧的处理速率：
 *   unknown_frame_tokens:  当前可用 token 数
 *   unknown_frame_ts:      上次 token 补充时间（毫秒）
 *   每收到一个未知帧消耗 1 token，token 不足则静默丢弃并计 diag 计数器
 *
 * [全局内存跟踪]
 *   global_memory_used:  当前进程堆分配近似值（字节）。
 *                        与 perf_max_memory_mb 比较，超限触发 OOM 降级。
 *
 * [通道断路器]
 *   cb_open[]:  每个 channel_id 的断路器状态数组：0=CLOSED（正常），1=OPEN（拒绝连接）
 *
 * [运行时自诊断]
 *   diag_rx_unknown_dropped: 未知通道帧的累计丢弃数（自诊断周期内）
 *   diag_last_diag_ts:       上次输出自诊断信息的时间戳
 *
 * [通道管理 API（Unix Domain Socket）]
 *   ctl_sock_fd:    Unix socket 文件描述符（-1=未启用），监听本地管理命令
 *   ctl_sock_path:  Unix socket 文件路径
 *
 * [管理模块状态]
 *   mgmt:        管理模块运行时状态（worker 跟踪、序列号、配置版本号等）
 *   master_pid:  父 Master 进程的 PID（worker 进程用于向 master 发送信号）
 *
 * [Watchdog 心跳]
 *   heartbeat_fd:        心跳 pipe 写端 fd（worker 向 master 发送心跳字节）
 *   last_heartbeat_sent: 上次发送心跳的时间戳
 *
 * [API 模块状态（Mongoose HTTP 服务器）]
 *   mg_mgr:          Mongoose 事件管理器指针
 *   api_listener:    Mongoose HTTP 监听器指针
 *   api_auth_header: HTTP Authorization 请求头期望值（预计算，避免每次拼接）
 *
 * [API 审计日志]
 *   log_buffer[]:    环形缓冲区（大小 LOG_BUF_SIZE），存储最近的审计日志
 *   log_buffer_head: 环形缓冲区写入位置索引
 *   log_buffer_count: 当前缓冲区中有效日志条目数
 *
 * [API 速率限制]
 *   rate_limits[]:   客户端 IP 速率限制条目数组（最大 RATE_LIMIT_MAX_IPS 个）
 *   rate_limit_count: 当前跟踪的独立 IP 数量
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* ── AF_PACKET 网络层 ── */
    int             raw_sock;           /* 全局 AF_PACKET 原始套接字 fd：用于接收所有帧 */
    int             ifindex;            /* 网卡接口索引（ioctl SIOCGIFINDEX 获取） */
    uint8_t         local_mac[ETH_MAC_ADDR_LEN];   /* 本地 MAC 地址（6 字节二进制） */
    uint8_t         peer_mac[ETH_MAC_ADDR_LEN];    /* 对端 MAC 地址（经 MAC 学习防御验证的最终地址） */
    uint8_t         peer_mac_learned;   /* 对端 MAC 学习标志：1=自动学习获得，0=手动配置指定 */
    uint8_t         peer_mac_confirm_count; /* MAC 学习确认计数器：候选 MAC 出现的有效帧数 */
    uint8_t         peer_mac_confirm_mac[ETH_MAC_ADDR_LEN]; /* 等待确认的候选 MAC 地址 */
    uint32_t        peer_mac_confirm_ts;   /* 候选 MAC 首次出现的时间戳（kcp_wrap_clock 毫秒） */
    uint16_t        ethertype;          /* 全局 EtherType 值 */

    /* ── OOM 优雅降级：预分配应急缓冲池 ── */
    uint8_t         emergency_pool[EMERGENCY_POOL_SIZE]; /* 预分配 8192 字节应急缓冲区 */
    int             emergency_pool_used;  /* 应急池已消费标志：1=已分配（需重启恢复），0=可用 */

    /* ── 配置 ── */
    global_config_t config;             /* 全局配置结构体：所有模块的配置参数聚合 */

    /* ── 通道管理 ── */
    channel_t     **channel_hash;                /* 通道哈希表（堆分配指针数组，链地址法解决冲突） */
    uint32_t        channel_hash_size;           /* 哈希表桶数（通常为质数） */
    int             channel_count;               /* 当前活跃通道总数 */

    /* ── epoll 事件循环 ── */
    int             epoll_fd;           /* epoll 实例 fd：统一管理所有通道 I/O 事件 */

    /* ── 运行状态 ── */
    volatile sig_atomic_t running;          /* 运行标志：0=正在退出主循环，1=正常运行 */
    volatile sig_atomic_t reload_requested; /* 配置重载请求（SIGHUP）：触发完整配置文件重新加载 */
    volatile sig_atomic_t ctl_requested;    /* 通道控制请求（SIGUSR1）：触发增量通道操作 */
    uint32_t        start_time;             /* 进程启动时间戳（CLOCK_MONOTONIC 秒） */
    char            config_path[MAX_CONFIG_PATH]; /* 当前配置文件完整路径（用于 SIGHUP 热重载） */
    uint32_t        listener_base[MAX_CHANNELS];  /* 每个 listener 的动态 ID 池起始偏移（分区机制） */
    uint32_t        listener_next[MAX_CHANNELS];  /* 每个 listener 的下一个可用动态 ID（相对偏移） */
    uint32_t        last_global_heartbeat;  /* 上次发送全局心跳 PING 的时间戳 */

    /* ── 速率限制：PONG 响应（token bucket，10/s） ── */
    uint32_t        pong_tokens;            /* PONG token bucket 当前 token 数 */
    uint32_t        pong_ts;                /* 上次 token 补充时间（秒） */

    /* ── 统计 ── */
    uint32_t        last_stats_time;    /* 上次输出统计信息的时间戳 */

    /* ── 速率限制：通道创建（token bucket 防 SYN flood） ── */
    uint32_t        channel_create_timestamp;  /* 上次 token 补充时间（kcp_wrap_clock 毫秒） */
    uint32_t        channel_create_tokens;     /* 当前可用 token 数量 */
    uint32_t        channel_create_max_per_sec; /* 每秒最大通道创建数（tokens/s），0=不限制 */

    /* ── 速率限制：未知帧处理（token bucket 防 DoS） ── */
    uint32_t        unknown_frame_tokens;     /* 未知帧 token bucket 当前 token 数 */
    uint32_t        unknown_frame_ts;         /* 上次 token 补充时间（毫秒） */

    /* ── 全局内存跟踪 ── */
    size_t          global_memory_used;       /* 当前进程堆分配近似值（字节）：监控内存使用 */

    /* ── NIC 统计（可观测性） ── */
    nic_stats_t     nic;            /* 当前网卡统计快照 */
    nic_stats_t     nic_prev;       /* 上次统计快照（用于速率计算） */
    uint32_t        nic_last_poll;  /* 上次 NIC 统计采集时间（CLOCK_MONOTONIC 毫秒） */

    /* ── 通道断路器 ── */
    uint8_t         cb_open[MAX_CHANNELS];          /* 断路器状态数组：0=CLOSED（正常），1=OPEN（拒绝） */

    /* ── 运行时自诊断 ── */
    uint64_t        diag_rx_unknown_dropped;  /* 未知通道帧累计丢弃数（自诊断周期内） */
    uint32_t        diag_last_diag_ts;        /* 上次输出自诊断信息的时间戳 */

    /* ── 通道管理 API（Unix Domain Socket） ── */
    int             ctl_sock_fd;        /* Unix socket fd：监听本地管理命令，-1=未启用 */
    char            ctl_sock_path[MAX_CONFIG_PATH]; /* Unix socket 文件路径 */

    /* ── 管理模块状态 ── */
    mgmt_state_t    mgmt;                     /* 管理模块运行时状态 */
    pid_t           master_pid;               /* 父 Master 进程 PID：worker 用于向 master 发送信号 */

    /* ── Watchdog 心跳 ── */
    int             heartbeat_fd;             /* 心跳 pipe 写端 fd（worker→master）：写入 1 字节表示存活 */
    uint32_t        last_heartbeat_sent;      /* 上次发送心跳的时间戳（CLOCK_MONOTONIC 秒） */

    /* ── API 模块状态（Mongoose HTTP 服务器） ── */
    void           *mg_mgr;                   /* Mongoose 事件管理器指针 */
    void           *api_listener;             /* Mongoose HTTP 监听器指针 */
    char            api_auth_header[80];       /* HTTP Authorization 请求头期望值（预计算字符串） */

    /* ── API 审计日志 ── */
    log_entry_t     log_buffer[LOG_BUF_SIZE];  /* 审计日志环形缓冲区 */
    int             log_buffer_head;           /* 环形缓冲区写入位置索引 */
    int             log_buffer_count;          /* 缓冲区中有效日志条目数 */

    /* ── API 速率限制 ── */
    rate_limit_entry_t  rate_limits[RATE_LIMIT_MAX_IPS]; /* 客户端 IP 速率限制条目数组 */
    int                 rate_limit_count;                 /* 当前跟踪的独立 IP 数量 */

    /* ── 业务插件链 ── */
    struct plugin_s    *plugin_chain;      /* 插件链表头（按 priority 升序），NULL=无插件 */

} global_ctx_t;

/* ============================================================================
 * Master-Worker 多实例架构类型（Nginx 风格进程模型）
 *
 * 架构概述：
 *   Master 进程：唯一的管理进程，负责：
 *     - 解析配置文件（master_config_t），提取 shared 默认值和 instance 列表
 *     - fork 出所有 Worker 子进程
 *     - 通过信号（SIGHUP/SIGTERM/SIGUSR1）管理 Worker 生命周期
 *     - Watchdog 心跳监控，自动重启崩溃或失联的 Worker
 *     - 优雅 reload：fork 新 Worker → 等待旧 Worker 排干 → SIGTERM 旧 Worker
 *
 *   Worker 进程：数据面处理进程，负责：
 *     - AF_PACKET 原始套接字收发
 *     - KCP 可靠传输协议处理
 *     - 本地 TCP/UDP 代理转发
 *     - 使用现有的 global_ctx_t 和 channel_t 数据结构
 *
 * 实例间隔离方式：
 *   - 进程隔离：每个 Worker 是独立进程，独立地址空间、epoll、KCP 实例
 *   - EtherType 隔离：每个实例使用不同的 EtherType，BPF 过滤器精确匹配
 *   - 端口隔离：每个实例独立的 listen_port，无端口冲突
 *   - CPU 亲和性：可选将 Worker 绑定到指定 CPU 核心，避免 L1/L2 cache 竞争
 *
 * 配置文件结构（多实例模式）：
 *   {
 *     "shared": { ... global_config_t 默认值 ... },
 *     "instances": [
 *       { "instance_name": "worker-1", "ethertype": 0x88B5, ... },
 *       { "instance_name": "worker-2", "ethertype": 0x88B6, ... }
 *     ]
 *   }
 *
 * 单个实例的 instance_config_t 中的字段会覆盖 shared 默认值。
 * ============================================================================ */

#define MAX_INSTANCES          64          /* 最大实例数：与 MGMT_MAX_WORKERS 保持一致 */
#define WORKER_GRACEFUL_TIMEOUT  30        /* Worker 优雅退出最大等待时间（秒）：超时后 SIGKILL */

/* ── Watchdog 常量 ──────────────────────────────────────────────────────────
 * Master 进程的 Watchdog 子系统监控每个 Worker 的存活状态，自动重启异常 Worker。
 *
 * WATCHDOG_MAX_RESTARTS (5):
 *   在 WATCHDOG_RESTART_WINDOW (60s) 时间窗口内允许的最大重启次数。
 *   超过此阈值后不再自动重启，需人工介入（防止无限重启循环）。
 *
 * WATCHDOG_RESTART_DELAY (1s):
 *   每次重启之间的最小间隔，防止 fork 风暴耗尽系统 PID。
 *
 * WATCHDOG_HEARTBEAT_INTERVAL (2s):
 *   Worker 通过 pipe 向 Master 发送心跳的间隔。轻量级操作，每个 Worker
 *   每 2 秒向 pipe 写入 1 字节。
 *
 * WATCHDOG_HEARTBEAT_TIMEOUT (10s):
 *   Master 等待心跳的最大时间。超过此值未收到心跳视为 Worker 可能卡死。
 *
 * WATCHDOG_HEARTBEAT_MAX_MISS (3):
 *   连续丢失心跳的最大次数。丢失 ≥3 次后 Master 发送 SIGKILL 并触发重启。
 *   实际触发时间 = HEARTBEAT_INTERVAL × MAX_MISS = 2s × 3 = 至少 6 秒。
 *
 * WATCHDOG_STARTUP_GRACE (4s):
 *   新 Worker 启动后的宽容期。在此时间内不进行心跳超时检查，
 *   避免 Worker 初始化耗时（加载配置、打开套接字、KCP 初始化等）导致误判。
 * ─────────────────────────────────────────────────────────────────────────── */
#define WATCHDOG_MAX_RESTARTS       5   /* 重启窗口内最大重启次数：防止无限重启循环 */
#define WATCHDOG_RESTART_WINDOW    60   /* 重启计数窗口（秒）：超时后重置重启计数 */
#define WATCHDOG_RESTART_DELAY      1   /* 最小重启间隔（秒）：防止 fork 风暴 */
#define WATCHDOG_HEARTBEAT_INTERVAL 2   /* Worker 心跳发送间隔（秒）：向 pipe 写 1 字节 */
#define WATCHDOG_HEARTBEAT_TIMEOUT 10   /* Master 心跳等待超时（秒）：超时未收到视为 Worker 失联 */
#define WATCHDOG_HEARTBEAT_MAX_MISS 3   /* 最大连续丢失心跳次数：≥3 次后 kill Worker */
#define WATCHDOG_STARTUP_GRACE      4   /* 新 Worker 启动宽容期（秒）：避免初始化耗时导致误判 */

/* ── Worker 状态枚举（worker_state_t）───────────────────────────────────────
 * WORKER_STARTING (0):        刚刚 fork，尚未通过心跳或管理通道确认存活
 * WORKER_RUNNING (1):         正常运行中，定期发送心跳
 * WORKER_EXITING (2):         收到 SIGTERM，正在优雅排水（完成现有连接后退出）
 * WORKER_DEAD (3):            已退出（被 waitpid 回收），等待 Master 清理状态
 * WORKER_RESTART_PENDING (4): 等待延迟后自动重启（Watchdog 触发）
 * ─────────────────────────────────────────────────────────────────────────── */
typedef enum {
    WORKER_STARTING        = 0,   /* 启动中：刚 fork，尚未确认存活 */
    WORKER_RUNNING         = 1,   /* 运行中：正常处理数据面，定期发心跳 */
    WORKER_EXITING         = 2,   /* 退出中：收到 SIGTERM，优雅排水中 */
    WORKER_DEAD            = 3,   /* 已终止：等待 Master 通过 waitpid 回收 */
    WORKER_RESTART_PENDING = 4    /* 等待重启：延迟后由 Watchdog 自动重启 */
} worker_state_t;

/* ── 实例差异化配置（instance_config_t）─────────────────────────────────────
 * 每个 Worker 实例可覆盖 shared 默认值中的特定字段。
 * 覆盖规则：
 *   - 数值型字段：值为 0 / -1 / 特殊值表示使用 shared 默认值
 *   - 字符串字段：空字符串表示使用 shared 默认值
 *   - 布尔型字段（int8_t）：-1 表示使用 shared 默认值，0=显式禁用，1=显式启用
 *
 * 字段说明：
 *   instance_name:   实例名称（必填，用于日志和管理标识）
 *   ethertype:       自定义 EtherType（必填，实例间必须互不相同以实现帧隔离）
 *   pid_file:        PID 文件路径（可选，覆盖 shared 默认值）
 *   cpu_affinity:    CPU 核心绑定（-1=不绑定，≥0=绑定到指定核心）
 *
 *   以下为可选覆盖字段（含义与 global_config_t 中对应字段一致）：
 *   node_type, heartbeat_interval, heartbeat_timeout, crc_enabled
 *
 *   channels / channel_count / channel_capacity:
 *     此实例专属的通道配置列表（堆分配，master_config_load 负责内存管理）
 *
 *   encryption_enabled / sm4_key:
 *     加密覆盖（独立于 shared 的加密配置）
 *
 *   KCP / performance 覆盖：
 *     kcp_mtu, auto_kcp_mtu, kcp_send_window, kcp_recv_window,
 *     kcp_nodelay, kcp_interval, kcp_resend, kcp_nc
 *
 *   peer_mac_str / local_mac_str:
 *     MAC 地址覆盖（字符串格式 "xx:xx:xx:xx:xx:xx"），空字符串使用 shared
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    char        instance_name[MAX_LISTEN_ADDR];  /* 实例名称（必填）：用于日志、管理和 PID 文件命名 */
    char        source[16];                      /* 实例来源："static"(配置文件) / "dynamic"(SPAWN) */
    char        node_id[65];                     /* 管理节点 ID（可选）：覆盖 shared.node.node_id */
    uint16_t    ethertype;                       /* 自定义 EtherType（必填）：实例间必须互不相同 */
    char        pid_file[MAX_PID_PATH];          /* PID 文件路径（可选）：覆盖 shared 默认值 */
    int         cpu_affinity;                    /* CPU 核心亲和性绑定：-1=不绑定，≥0=目标核心编号 */

    /* 以下字段为可选覆盖。值为 0 / NODE_TYPE_FRONTEND / 空字符串 / -1 表示使用 shared 默认值 */
    node_type_t node_type;                /* 节点类型覆盖（NODE_TYPE_FRONTEND / NODE_TYPE_BACKEND） */
    int         heartbeat_interval;       /* 心跳间隔覆盖（秒） */
    int         heartbeat_timeout;        /* 心跳超时覆盖（秒） */
    int8_t      crc_enabled;            /* CRC32 覆盖：-1=使用 shared，0=禁用，1=启用 */

    /* 此实例专属的通道配置（堆分配，master_config_load 负责分配和释放） */
    channel_config_t *channels;          /* 通道配置数组（堆分配） */
    int               channel_count;     /* 有效通道配置条目数 */
    int               channel_capacity;  /* 通道数组的分配容量（≥ channel_count） */

    /* 加密覆盖（空 sm4_key 字符串表示使用 shared 默认加密配置） */
    int8_t      encryption_enabled;     /* 加密覆盖：-1=使用 shared，0=禁用，1=启用 */
    char        sm4_key[SM4_KEY_HEX_LEN + 1]; /* SM4 密钥覆盖（十六进制字符串） */

    /* KCP / 性能参数覆盖（-1 表示使用 shared 默认值） */
    int         kcp_mtu;                /* KCP MTU 覆盖 */
    int8_t      auto_kcp_mtu;           /* 自动 KCP MTU 覆盖：-1=使用 shared，0=off，1=on */
    int         kcp_send_window;        /* KCP 发送窗口覆盖 */
    int         kcp_recv_window;        /* KCP 接收窗口覆盖 */
    int         kcp_nodelay;            /* KCP nodelay 覆盖 */
    int         kcp_interval;           /* KCP interval 覆盖 */
    int         kcp_resend;             /* KCP resend 覆盖 */
    int         kcp_nc;                 /* KCP nc 覆盖 */

    /* MAC 地址覆盖（空字符串表示使用 shared 默认 MAC） */
    char        peer_mac_str[18];       /* 对端 MAC 地址覆盖（字符串 "xx:xx:xx:xx:xx:xx"） */
    char        local_mac_str[18];      /* 本地 MAC 地址覆盖（字符串 "xx:xx:xx:xx:xx:xx"） */
} instance_config_t;

/* ── Worker 进程运行时信息（worker_info_t）──────────────────────────────────
 * Master 进程为每个已 fork 的 Worker 维护此结构体，用于进程监管和 Watchdog。
 *
 * 字段说明：
 *   pid:                子进程 PID
 *   instance_index:     指向 master_config.instances[] 的索引
 *   state:              当前 Worker 状态（WORKER_STARTING / RUNNING / EXITING / DEAD / RESTART_PENDING）
 *   started_at:         启动时间戳（CLOCK_MONOTONIC 秒）
 *   exit_signal_sent_at: 发送 SIGTERM 的时间戳（用于超时后 SIGKILL）
 *
 *   [Watchdog 自动重启]
 *   restart_count:  当前重启窗口内已重启次数（用于 WATCHDOG_MAX_RESTARTS 判断）
 *   last_restart_at: 上次重启的时间戳（用于窗口重置判断）
 *   restart_at:      计划重启的时间戳（RESTART_PENDING 状态下的延迟重启）
 *   exit_code:       上次退出码（正值=正常退出码，负值=被信号杀死，如 -9 表示 SIGKILL）
 *
 *   [Watchdog 心跳监控]
 *   heartbeat_fd:     pipe 的 Master 端读 fd（-1=未启用 watchdog）
 *   last_heartbeat:   上次收到心跳的时间戳
 *   heartbeat_missed: 连续丢失心跳次数（用于 WATCHDOG_HEARTBEAT_MAX_MISS 判断）
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    pid_t           pid;                /* 子进程 PID */
    int             instance_index;     /* 指向 master_config.instances[] 的索引 */
    worker_state_t  state;              /* Worker 当前状态：STARTING / RUNNING / EXITING / DEAD / RESTART_PENDING */
    uint32_t        started_at;         /* 启动时间戳（CLOCK_MONOTONIC 秒） */
    uint32_t        exit_signal_sent_at; /* 发送 SIGTERM 的时间戳：用于超时后升级为 SIGKILL */

    /* ── Watchdog 自动重启 ── */
    int             restart_count;      /* 当前重启窗口内已重启次数 */
    uint32_t        last_restart_at;    /* 上次重启的时间戳：用于窗口重置判断 */
    uint32_t        restart_at;         /* 计划重启时间戳（RESTART_PENDING 状态的延迟触发时间） */
    int             exit_code;          /* 上次退出码：正值=exit() 参数，负值=终止信号编号 */

    /* ── Watchdog 心跳监控 ── */
    int             heartbeat_fd;       /* 心跳 pipe 的 Master 端读 fd：-1=未启用 watchdog */
    uint32_t        last_heartbeat;     /* 上次收到心跳的时间戳（CLOCK_MONOTONIC 秒） */
    int             heartbeat_missed;   /* 连续丢失心跳次数：≥ WATCHDOG_HEARTBEAT_MAX_MISS 则 kill */
} worker_info_t;

/* ── Master 全局配置（master_config_t）──────────────────────────────────────
 * Master 进程的顶级配置结构体，管理 shared 默认值、实例列表和 Worker 监管状态。
 *
 * shared:
 *   所有实例的 baseline 默认配置（global_config_t）。
 *   实例可通过 instance_config_t 中的非默认值覆盖特定字段。
 *
 * instances[] / instance_count:
 *   实例差异化配置列表。每个实例至少需提供 instance_name 和 ethertype。
 *
 * workers[] / worker_count:
 *   Worker 进程运行时监管数组。与 instances[] 按 instance_index 对应。
 *
 * pid_file:
 *   Master 进程自身的 PID 文件路径。
 *
 * daemonize:
 *   是否以守护进程模式运行（0=前台运行，1=后台 daemon 模式）。
 *   守护进程化包括：fork+setsid、重定向 stdin/stdout/stderr 到 /dev/null、
 *   写入 PID 文件等标准 daemon 流程。
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* 共享默认值（所有实例的 baseline 配置） */
    global_config_t shared;

    /* 实例差异化配置列表 */
    instance_config_t instances[MAX_INSTANCES];
    int               instance_count;

    /* Worker 进程运行时监管数组 */
    worker_info_t workers[MAX_INSTANCES];
    int           worker_count;

    /* Master 进程自身配置 */
    char pid_file[MAX_PID_PATH];        /* Master 进程 PID 文件完整路径 */
    int  daemonize;                     /* 守护进程化标志：0=前台运行，1=后台 daemon */
} master_config_t;

/* ============================================================================
 * 工具宏
 * ============================================================================ */

/* ── MIN / MAX ──────────────────────────────────────────────────────────────
 * 类型安全的最小值/最大值宏（使用 GNU 表达式扩展，避免多次求值副作用）。
 * ─────────────────────────────────────────────────────────────────────────── */
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* ── ARRAY_SIZE ─────────────────────────────────────────────────────────────
 * 编译时计算静态数组的元素个数。
 * 注意：不能用于指针（会得到错误结果），仅用于栈分配或全局静态数组。
 * ─────────────────────────────────────────────────────────────────────────── */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* ── 单调时钟时间戳辅助 ────────────────────────────────────────────────────
 *
 * time_now():
 *   返回 CLOCK_MONOTONIC 的秒级时间戳（uint32_t）。
 *
 *   为什么使用 CLOCK_MONOTONIC 而非 time(NULL)？
 *     - time() 返回系统实时钟（CLOCK_REALTIME），受 NTP 校时和
 *       systemd-timesyncd 时钟调拨影响，可能出现时间跳变（向前或向后）
 *     - 时间跳变会导致：心跳超时集中误触发、会话空闲超时错误断开、
 *       断路器冷却时间计算错误等严重问题
 *     - CLOCK_MONOTONIC 以系统启动时间为基点单调递增，不受 NTP 影响
 *     - uint32_t 秒级时间戳：2^32 秒 ≈ 136 年才会回绕，远超服务生命周期
 *     - 兼容性：需要 POSIX.1-2001，Linux 2.6+ / glibc 2.4+（均已满足）
 *
 * time_elapsed(t):
 *   计算从时间戳 t 到当前时间的经过秒数。
 *   安全处理时间戳回绕（尽管在 uint32_t 下 136 年内不会发生）。
 *   若 t > 当前时间（理论上不会发生），返回 0。
 * ─────────────────────────────────────────────────────────────────────────── */
__attribute__((unused))
static inline uint32_t time_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)ts.tv_sec;
}
#define time_elapsed(t)     ({ uint32_t __n = time_now(); (__n < (t)) ? (uint32_t)0 : (__n - (t)); })

/* ============================================================================
 * 模块接口声明
 * ============================================================================ */

/* ── 管理模块接口（mgmt_*）──────────────────────────────────────────────────
 * mgmt_init:            初始化管理模块（创建管理通道、启动注册流程）
 * mgmt_dispatch:        处理管理通道收到的消息（配置分发、健康检查响应等）
 * mgmt_push_config_to_all: 将当前配置推送给所有已注册的 Worker
 * mgmt_periodic:        定期任务（心跳检查、超时检测、状态清理）
 * mgmt_shutdown:        关闭管理模块，释放资源
 * config_apply_from_mgmt: 解析并应用来自管理通道的 JSON 配置
 * mgmt_send_instance_command: 向指定 Worker 发送管理命令
 * ─────────────────────────────────────────────────────────────────────────── */
int  mgmt_init(global_ctx_t *ctx);
void mgmt_dispatch(struct channel_s *ch, uint8_t *data, int len);
void mgmt_push_config_to_all(global_ctx_t *ctx, const char *target_node_id);
void mgmt_periodic(global_ctx_t *ctx);
void mgmt_shutdown(global_ctx_t *ctx);
int  config_apply_from_mgmt(global_ctx_t *ctx, const char *config_json);
int  mgmt_send_instance_command(global_ctx_t *ctx, const char *type,
                                const char *target_node_id,
                                const char *payload_json);
int  mgmt_send_channel_ctl(global_ctx_t *ctx, const char *target_node_id,
                           const char *ctl_json);

/* ── API 模块接口（api_*）───────────────────────────────────────────────────
 * api_init:     初始化 HTTP API 服务器（Mongoose 绑定端口、设置路由）
 * api_poll:     轮询 Mongoose 事件循环（在主循环中每次迭代调用）
 * api_shutdown: 停止 API 服务器，释放 Mongoose 资源
 * ─────────────────────────────────────────────────────────────────────────── */
int  api_init(global_ctx_t *ctx);
void api_poll(global_ctx_t *ctx);
void api_shutdown(global_ctx_t *ctx);

/* ── 全局上下文指针 ────────────────────────────────────────────────────────
 * g_ctx 指向进程唯一的 global_ctx_t 实例。
 * 在 main() 中分配（栈或静态区），初始化后赋值，所有模块通过此指针访问全局状态。
 * ─────────────────────────────────────────────────────────────────────────── */
extern global_ctx_t *volatile g_ctx;

/* ── 日志宏 ────────────────────────────────────────────────────────────────
 * 五级日志系统，全部输出到 stderr（适合 systemd journal 采集和容器日志）。
 *
 * 日志级别从低到高：
 *   LOG_DEBUG: 调试信息。
 *     仅在编译时定义了 DEBUG 宏（-DDEBUG）的情况下生效。
 *     用于开发阶段追踪详细数据流、状态变化、KCP 内部状态等。
 *     生产环境编译时自动剔除，零运行时开销。
 *
 *   LOG_INFO: 正常运行信息。
 *     记录关键生命周期事件：连接建立/关闭、配置加载、Worker 启动/退出、
 *     心跳恢复等。用于运维监控和问题回溯。
 *
 *   LOG_WARN: 警告信息。
 *     记录异常但非致命的事件：重传超限、接近资源上限、CRC 校验失败率升高、
 *     断路器触发、对端响应延迟等。需关注但不需要立即处理。
 *
 *   LOG_ERROR: 错误信息。
 *     记录需要立即处理的错误：系统调用失败、连接失败、加密解密错误、
 *     内存分配失败等。通常伴随降级或重试逻辑。
 *
 *   LOG_AUDIT: 安全审计事件。
 *     记录所有管理操作和安全相关事件：API 认证失败、配置变更来源、
 *     管理命令执行、Worker 注册/注销等。用于安全审计和合规追溯。
 *
 * 设计理由：
 *   - fprintf(stderr) 而非 syslog()：简化依赖，方便容器化部署，
 *     systemd/journald 可直接捕获 stderr 输出
 *   - 日志级别通过编译宏控制：DEBUG 在 release build 中完全剔除
 *   - 统一格式 "[LEVEL] message\n"：便于 grep 过滤和日志平台解析
 *   - 使用 ##__VA_ARGS__（GNU 扩展）：支持可变参数的 fmt 字符串
 * ─────────────────────────────────────────────────────────────────────────── */
#ifdef DEBUG
#define LOG_DEBUG(fmt, ...)   log_output(LOG_LVL_DEBUG, fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...)   do { } while (0)
#endif

#define LOG_INFO(fmt, ...)    log_output(LOG_LVL_INFO,  fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)    log_output(LOG_LVL_WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   log_output(LOG_LVL_ERROR, fmt, ##__VA_ARGS__)
#define LOG_AUDIT(fmt, ...)   log_output(LOG_LVL_AUDIT, fmt, ##__VA_ARGS__)

/* 日志级别常量（供 log_output 使用） */
#define LOG_LVL_DEBUG 0
#define LOG_LVL_INFO  1
#define LOG_LVL_WARN  2
#define LOG_LVL_ERROR 3
#define LOG_LVL_AUDIT 4

/* log_output — 统一日志输出：stderr + 本地文件 + syslog */
void log_output(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* log_init   — 初始化日志子系统（打开文件 + openlog） */
void log_init(global_ctx_t *ctx);

#endif /* TYPES_H */
