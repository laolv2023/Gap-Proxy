/*
 * af_packet.c - AF_PACKET 原始套接字实现
 *
 * 在数据链路层直接收发以太网帧，绕过 TCP/IP 协议栈。
 * 支持 BPF 过滤器、MAC 地址发现、NIC MTU 管理以及冲突检测。
 *
 * 所有函数在错误路径上均通过 LOG_ERROR 记录 errno，
 * 并返回适当的错误码。缓冲区操作均包含溢出保护。
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                   AF_PACKET 原始套接字 API 使用说明                        ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                          ║
 * ║   AF_PACKET 允许用户态程序绕过内核 TCP/IP 协议栈，直接在数据链路层        ║
 * ║   收发以太网帧。关键系统调用和创建步骤：                                   ║
 * ║                                                                          ║
 * ║   1. socket(AF_PACKET, SOCK_RAW, htons(ethertype))                       ║
 * ║      创建指定 EtherType 的原始套接字                                      ║
 * ║      ethertype 参数同时作为绑定过滤条件                                   ║
 * ║                                                                          ║
 * ║   2. setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V2)                  ║
 * ║      升级到 TPACKET_V2 以获得更高的吞吐量                                 ║
 * ║      失败时自动回退到 TPACKET_V1                                          ║
 * ║                                                                          ║
 * ║   3. setsockopt(SOL_SOCKET, SO_SNDBUF / SO_RCVBUF)                       ║
 * ║      扩大套接字缓冲区 (256KB发送 / 512KB接收)                              ║
 * ║                                                                          ║
 * ║   4. bind(sock, &sockaddr_ll, sizeof(sll))                               ║
 * ║      绑定到指定网卡接口 (sll_ifindex = 接口索引)                          ║
 * ║                                                                          ║
 * ║   5. fcntl(sock, F_SETFL, O_NONBLOCK)                                    ║
 * ║      设置为非阻塞模式，配合 epoll 使用                                    ║
 * ║                                                                          ║
 * ║   6. setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog)                 ║
 * ║      安装 BPF 过滤器，内核级过滤仅接收匹配 EtherType 的帧                 ║
 * ║      大幅减少不必要的用户态/内核态切换                                     ║
 * ║                                                                          ║
 * ║   【发送流程】                                                            ║
 * ║   构造以太网帧: [dst_mac(6) | src_mac(6) | ethertype(2) | payload(N)]    ║
 * ║   sendto(sock, frame, len, 0, &sockaddr_ll, sizeof(sll))                 ║
 * ║                                                                          ║
 * ║   【接收流程】                                                            ║
 * ║   recvfrom(sock, buf, size, 0, &sockaddr_ll, &sll_len)                   ║
 * ║   解析: dst_mac = buf[0..5], src_mac = buf[6..11], ethertype = buf[12..13]║
 * ║   负载: buf[14..recvd-1]                                                  ║
 * ║                                                                          ║
 * ║   【BPF 过滤器字节码说明】                                                ║
 * ║   指令0: ldh [12]        — 从偏移12加载16位 (EtherType字段)              ║
 * ║   指令1: jeq #V, 0, 1   — 等于ethertype则继续，否则跳转到reject          ║
 * ║   指令2: ret #0          — 拒绝（返回0字节）                              ║
 * ║   指令3: ret #0xFFFFFFFF — 接受（返回全部）                               ║
 * ║                                                                          ║
 * ║   【辅助功能】                                                            ║
 * ║   - af_packet_get_mac():   SIOCGIFHWADDR ioctl 获取 MAC 地址            ║
 * ║   - af_packet_get_ifindex(): SIOCGIFINDEX ioctl 获取接口索引            ║
 * ║   - af_packet_set_mtu():   SIOCSIFMTU ioctl 设置 MTU                   ║
 * ║   - af_packet_get_mtu():   SIOCGIFMTU ioctl 获取 MTU                   ║
 * ║   - af_packet_detect_conflict(): 解析 /proc/net/packet 检测冲突         ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

#include "af_packet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* ============================================================================
 * 内部常量
 * ============================================================================ */

/* /proc/net/packet 行最大长度 */
#define PROC_NET_PACKET_LINE_MAX 512

/* 单次发送/接收帧硬上限（以太网头 + 有效载荷 + VLAN + 安全余量） */
#define AF_PKT_MAX_FRAME         (ETH_HDR_SIZE + ETH_MAX_PAYLOAD + 128)

static int g_af_packet_sndbuf = PERF_AF_PACKET_SNDBUF;
static int g_af_packet_rcvbuf = PERF_AF_PACKET_RCVBUF;
static int g_af_packet_send_retry_max = PERF_AF_PACKET_SEND_RETRY_MAX;
static int g_af_packet_send_wait_ms = PERF_AF_PACKET_SEND_WAIT_MS;

/* ============================================================================
 * 内部辅助函数
 * ============================================================================ */

/*
 * 尝试将套接字缓冲区大小设置为期望值。
 * 失败时仅记录警告，因为内核可能限制缓冲区大小。
 */
static void af_packet_set_sockbuf(int sock, int optname, int desired)
{
    int val = desired;

    if (setsockopt(sock, SOL_SOCKET, optname, &val, sizeof(val)) < 0) {
        int saved_errno = errno;
        LOG_ERROR("af_packet: setsockopt(%s, %d) failed (non-fatal): %s",
                  (optname == SO_SNDBUF) ? "SO_SNDBUF" : "SO_RCVBUF",
                  desired, strerror(saved_errno));
    }
}

void af_packet_configure(int sndbuf, int rcvbuf,
                         int retry_max, int retry_wait_ms)
{
    g_af_packet_sndbuf = (sndbuf > 0) ? sndbuf : PERF_AF_PACKET_SNDBUF;
    g_af_packet_rcvbuf = (rcvbuf > 0) ? rcvbuf : PERF_AF_PACKET_RCVBUF;
    g_af_packet_send_retry_max =
        (retry_max >= 0) ? retry_max : PERF_AF_PACKET_SEND_RETRY_MAX;
    g_af_packet_send_wait_ms =
        (retry_wait_ms >= 0) ? retry_wait_ms : PERF_AF_PACKET_SEND_WAIT_MS;
}

/*
 * 安全的字符串截断复制（始终以 NUL 结尾）。
 */
static size_t safe_strncpy(char *dst, const char *src, size_t dstsize)
{
    size_t i;

    if (!dst || !src || dstsize == 0) {
        return 0;
    }

    for (i = 0; i < dstsize - 1 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';

    return i;
}

static int af_packet_send_busy_errno(int err)
{
    return err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS;
}

/* ============================================================================
 * af_packet_create — 创建并配置 AF_PACKET 原始套接字
 *
 * 这是 AF_PACKET 模块的核心初始化函数，创建可直接收发以太网帧的原始套接字。
 *
 * 创建流程 (每一步都可能失败，失败跳转到 fail 标签清理):
 *
 *   1. 参数校验
 *      - if_name / ifindex 非空
 *      - 网卡名长度 ≤ IFNAMSIZ (16 字节)
 *
 *   2. socket(AF_PACKET, SOCK_RAW, ethertype)
 *      创建 AF_PACKET 类型的原始套接字，绑定指定 EtherType。
 *      ethertype 参数必须为网络字节序 (big-endian)，调用方使用 htons() 转换。
 *      内核根据 ethertype 过滤接收到的帧，仅转发匹配 EtherType 的帧到用户态。
 *
 *   3. setsockopt(PACKET_VERSION, TPACKET_V2)
 *      尝试升级到 TPACKET_V2 以获得更高吞吐量。
 *      失败时自动回退到 TPACKET_V1 (非致命错误)，继续执行。
 *      TPACKET_V2 在内存映射 (mmap) 模式下优势明显，
 *      但普通 sendto/recvfrom 模式也有一定性能改善。
 *
 *   4. setsockopt(SO_SNDBUF / SO_RCVBUF)
 *      扩大套接字缓冲区: 默认发送 256KB / 接收 512KB。
 *      内核可能限制实际大小，失败仅记录警告。
 *
 *   5. af_packet_get_ifindex(sock, if_name)
 *      通过 SIOCGIFINDEX ioctl 获取网卡接口索引 (如 eth0 → 2)。
 *
 *   6. bind(sock, &sockaddr_ll)
 *      将套接字绑定到指定网卡接口。
 *      sockaddr_ll 结构指定: sll_family=AF_PACKET, sll_protocol=ethertype,
 *      sll_ifindex=接口索引。
 *
 *   7. fcntl(F_SETFL, O_NONBLOCK)
 *      设置为非阻塞模式，配合 epoll 使用。
 *      非阻塞模式下 sendto/recvfrom 在缓冲区满/空时返回 EAGAIN，
 *      而不是阻塞整个进程。
 *
 * 返回值: 成功返回套接字 fd (≥0), 失败返回 -1 (fd 已在 fail 标签中 close)。
 *         成功时通过 ifindex 输出参数返回接口索引。
 *
 * 注意: ethertype 参数必须是网络字节序 (big-endian)，
 *       调用方应使用 htons() 转换。内核 API 要求网络字节序的协议号。
 * ============================================================================ */
int af_packet_create(const char *if_name, uint16_t ethertype, int *ifindex)
{
    int              sock = -1;
    int              idx  = -1;
    struct sockaddr_ll sll;
    int              flags;
    int              version;

    /* --- 参数校验 --- */
    if (!if_name || !ifindex) {
        LOG_ERROR("af_packet_create: null argument (if_name=%p ifindex=%p)",
                  (const void *)if_name, (const void *)ifindex);
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_create: interface name too long: \"%s\"", if_name);
        errno = EINVAL;
        return -1;
    }

    /* --- 创建 AF_PACKET 原始套接字 --- */
    sock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, ethertype);
    if (sock < 0) {
        if (errno == EPERM) {
            LOG_ERROR("af_packet_create: socket(AF_PACKET, SOCK_RAW) "
                      "requires CAP_NET_RAW or root (EPERM)");
        }
        LOG_ERROR("af_packet_create: socket(AF_PACKET, SOCK_RAW, 0x%04X) "
                  "failed: %s", ethertype, strerror(errno));
        return -1;
    }

    /* --- 设置 TPACKET_V2 以获得更高性能 --- */
    version = TPACKET_V2;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION,
                   &version, sizeof(version)) < 0) {
        /* 非致命：回退至 TPACKET_V1 */
        LOG_ERROR("af_packet_create: PACKET_VERSION(TPACKET_V2) failed "
                  "(non-fatal, falling back to V1): %s", strerror(errno));
    }

    /* --- 扩大套接字缓冲区 --- */
    af_packet_set_sockbuf(sock, SO_SNDBUF, g_af_packet_sndbuf);
    af_packet_set_sockbuf(sock, SO_RCVBUF, g_af_packet_rcvbuf);

    /* --- 获取网卡接口索引 --- */
    idx = af_packet_get_ifindex(sock, if_name);
    if (idx < 0) {
        LOG_ERROR("af_packet_create: af_packet_get_ifindex(%s) failed", if_name);
        goto fail;
    }

    /* --- 绑定到网卡接口 --- */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = ethertype;
    sll.sll_ifindex  = idx;

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_ERROR("af_packet_create: bind(%s, ifindex=%d) failed: %s",
                  if_name, idx, strerror(errno));
        goto fail;
    }

    /* --- 设置为非阻塞模式 --- */
    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        LOG_ERROR("af_packet_create: fcntl(F_GETFL) failed: %s",
                  strerror(errno));
        goto fail;
    }

    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERROR("af_packet_create: fcntl(F_SETFL, O_NONBLOCK) failed: %s",
                  strerror(errno));
        goto fail;
    }

    *ifindex = idx;
    return sock;

fail:
    if (sock >= 0) {
        close(sock);
    }
    return -1;
}

/* ============================================================================
 * af_packet_set_bpf — 安装 BPF (Berkeley Packet Filter) 过滤器
 *
 * BPF 在内核层面过滤帧，大幅减少不必要的用户态/内核态切换。
 * 过滤器在内核协议栈接收帧后、传递给用户态之前执行。
 *
 * BPF 字节码 (4 条指令) 解析:
 *
 *   指令 0: BPF_LD | BPF_H | BPF_ABS, 12
 *     ldh [12] — 从帧偏移 12 处加载 16 位半字 (EtherType 字段)
 *     以太网帧布局: dst_mac(6) + src_mac(6) = 12 字节，偏移 12 是 EtherType
 *
 *   指令 1: BPF_JMP | BPF_JEQ | BPF_K, ntohs(ethertype), 1, 0
 *     jeq #V, 1, 0 — 如果 A == ethertype 则跳到下一条指令 (偏移+1)，
 *     否则跳过一条指令 (偏移+0 即下一条 → reject)
 *     注意: ldh 使用 be16_to_cpu 转换，因此比较值必须用 ntohs 转为主机字节序
 *
 *   指令 2: BPF_RET | BPF_K, 0
 *     ret #0 — 拒绝帧 (返回 0 字节，内核丢弃该帧)
 *
 *   指令 3: BPF_RET | BPF_K, 0xFFFFFFFF
 *     ret #0xFFFFFFFF — 接受帧 (返回完整帧内容给用户态)
 *
 * 执行流程:
 *   若 EtherType == 期望值 → 指令 1 跳转到指令 3 → accept
 *   若 EtherType != 期望值 → 指令 1 顺序执行指令 2 → reject
 *
 * 错误恢复: 若 SO_ATTACH_FILTER 失败 (如已有过滤器占用)，
 *   先尝试 SO_DETACH_FILTER 分离旧过滤器，再重新附加。
 *   这在热重载场景中很重要 (同一进程可能多次设置过滤规则)。
 *
 * @param sock      AF_PACKET 套接字 fd
 * @param ethertype 期望的 EtherType (网络字节序)
 * @return          0=成功, -1=失败
 * ============================================================================ */
int af_packet_set_bpf(int sock, uint16_t ethertype)
{
    struct sock_filter bpf_code[] = {
        /* 000 */ BPF_STMT(BPF_LD  | BPF_H   | BPF_ABS, 12),
        /* 001 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                           ntohs(ethertype), 1, 0),
        /* 002 */ BPF_STMT(BPF_RET | BPF_K, 0),
        /* 003 */ BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF),
    };

    struct sock_fprog bpf_prog;
    socklen_t         opt_len;
    int               ret;
    int               saved_errno;

    if (sock < 0) {
        LOG_ERROR("af_packet_set_bpf: invalid socket fd %d", sock);
        errno = EBADF;
        return -1;
    }

    bpf_prog.len    = sizeof(bpf_code) / sizeof(bpf_code[0]);
    bpf_prog.filter = bpf_code;

    if (bpf_prog.len > BPF_FILTER_MAX) {
        LOG_ERROR("af_packet_set_bpf: BPF program too long (%u instructions)",
                  bpf_prog.len);
        errno = EINVAL;
        return -1;
    }

    ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                     &bpf_prog, sizeof(bpf_prog));
    if (ret < 0) {
        saved_errno = errno;
        LOG_ERROR("af_packet_set_bpf: SO_ATTACH_FILTER failed "
                  "(ethertype=0x%04X): %s", ethertype, strerror(saved_errno));

        /*
         * 如果已存在过滤器，则先尝试分离再重新附加。
         * EEXIST 或已附加状态在不同内核版本中可能表现不同。
         */
        opt_len = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER,
                       NULL, opt_len) == 0) {
            ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                             &bpf_prog, sizeof(bpf_prog));
            if (ret < 0) {
                saved_errno = errno;
                LOG_ERROR("af_packet_set_bpf: SO_ATTACH_FILTER retry "
                          "failed: %s", strerror(saved_errno));
                errno = saved_errno;
                return -1;
            }
            /* 重新附加成功 */
            return 0;
        }

        errno = saved_errno;
        return -1;
    }

    return 0;
}

/* ============================================================================
 * af_packet_send — 构造并发送以太网帧
 *
 * 帧构造流程 (直接在栈上拼接):
 *
 *   1. 参数校验: sock≥0, MAC 指针非空, payload_len≤ETH_MAX_PAYLOAD,
 *      ifindex>0, frame_len≤AF_PKT_MAX_FRAME
 *
 *   2. 帧布局 (frame_buf):
 *      [0..5]    目标 MAC 地址 (dst_mac, 6 字节)
 *      [6..11]   源   MAC 地址 (src_mac, 6 字节)
 *      [12]      EtherType 高字节 (host_ethertype >> 8)
 *      [13]      EtherType 低字节 (host_ethertype & 0xFF)
 *                注意: ethertype 参数是网络字节序，需 ntohs 转 host 序后
 *                再手动大端编码写回 frame_buf[12..13]
 *      [14..]    负载数据 (payload, payload_len 字节)
 *
 *   3. 目标地址 (sockaddr_ll):
 *      sll_family   = AF_PACKET
 *      sll_protocol = ethertype (网络字节序)
 *      sll_ifindex  = ifindex (网卡接口索引)
 *      sll_halen    = ETH_ALEN (6)
 *      sll_addr     = dst_mac (目标物理地址)
 *
 *   4. 发送重试机制 (应对瞬时背压):
 *      AF_PACKET 非阻塞模式下，sendto 可能因发送缓冲区满返回
 *      EAGAIN / EWOULDBLOCK / ENOBUFS。直接返回会导致 KCP 帧丢失，
 *      上层 TCP 将看到大量重传。
 *
 *      重试策略:
 *        for attempt = 0..g_af_packet_send_retry_max:
 *          sendto() → 成功则 break
 *          → 非 busy 错误 (如 EINVAL): 立即返回 -1
 *          → busy 错误 (EAGAIN/EWOULDBLOCK/ENOBUFS):
 *             若 attempt == max → 返回 -1 (重试耗尽)
 *             否则 poll(POLLOUT, g_af_packet_send_wait_ms) 等待可写
 *
 *      参数可调: g_af_packet_send_retry_max (最大重试次数),
 *               g_af_packet_send_wait_ms (每次等待毫秒数)
 *
 *   5. 部分发送检查: (size_t)sent != frame_len → 返回 -1
 *      以太网帧必须完整发送，部分帧接收端无法解析。
 *
 * ethertype 为网络字节序 (big-endian)
 * ============================================================================ */

ssize_t af_packet_send(int sock, int ifindex,
                       const uint8_t dst_mac[ETH_MAC_ADDR_LEN],
                       const uint8_t src_mac[ETH_MAC_ADDR_LEN],
                       uint16_t ethertype,
                       const uint8_t *payload, size_t payload_len)
{
    uint8_t            frame_buf[AF_PKT_MAX_FRAME];
    size_t             frame_len;
    struct sockaddr_ll sll;
    ssize_t            sent = -1;
    int                saved_errno;

    /* --- 参数校验 --- */
    if (sock < 0) {
        LOG_ERROR("af_packet_send: invalid socket fd %d", sock);
        errno = EBADF;
        return -1;
    }

    if (!dst_mac || !src_mac) {
        LOG_ERROR("af_packet_send: null MAC address pointer");
        errno = EINVAL;
        return -1;
    }

    if (!payload && payload_len > 0) {
        LOG_ERROR("af_packet_send: null payload with non-zero length %zu",
                  payload_len);
        errno = EINVAL;
        return -1;
    }

    if (payload_len > ETH_MAX_PAYLOAD) {
        LOG_ERROR("af_packet_send: payload length %zu exceeds ETH_MAX_PAYLOAD %d",
                  payload_len, ETH_MAX_PAYLOAD);
        errno = EMSGSIZE;
        return -1;
    }

    if (ifindex <= 0) {
        LOG_ERROR("af_packet_send: invalid ifindex %d", ifindex);
        errno = EINVAL;
        return -1;
    }

    /* --- 构造以太网帧 --- */
    frame_len = ETH_HDR_SIZE + payload_len;

    if (frame_len > sizeof(frame_buf)) {
        LOG_ERROR("af_packet_send: frame too large (%zu > %zu)",
                  frame_len, sizeof(frame_buf));
        errno = EMSGSIZE;
        return -1;
    }

    /* 以太网头部：目标 MAC + 源 MAC + EtherType */
    memcpy(frame_buf, dst_mac, ETH_MAC_ADDR_LEN);
    memcpy(frame_buf + ETH_MAC_ADDR_LEN, src_mac, ETH_MAC_ADDR_LEN);
    /* ethertype 为网络字节序 (big-endian), 转为 host 序后再手动编码 */
    {
        uint16_t host_ethertype = ntohs(ethertype);
        frame_buf[12] = (uint8_t)((host_ethertype >> 8) & 0xFF);
        frame_buf[13] = (uint8_t)(host_ethertype & 0xFF);
    }

    /* 负载 */
    if (payload && payload_len > 0) {
        memcpy(frame_buf + ETH_HDR_SIZE, payload, payload_len);
    }

    /* --- 构造目标地址 --- */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = ethertype;
    sll.sll_ifindex  = ifindex;
    sll.sll_hatype   = ARPHRD_ETHER; /* 1 = 以太网 */
    sll.sll_pkttype  = 0;
    sll.sll_halen    = ETH_ALEN;
    /* sll_addr 在 struct sockaddr_ll 中定义为 8 字节，ETH_ALEN (MAC 地址) 为 6 字节；
     * 此处仅拷贝 6 字节，其余 2 字节已由上方 memset(&sll, 0, ...) 归零。
     * 这是有意为之：内核通过 sll_halen=6 确定有效地址长度，尾部填充字节无影响。 */
    memcpy(sll.sll_addr, dst_mac, ETH_ALEN);

    /* --- 发送 ---
     * KCP output 回调无法回滚已经 flush 的段。非阻塞 AF_PACKET 在发送缓冲
     * 暂满时如果直接返回，会导致 KCP 帧实际丢失，上层 TCP 看到大量重传。
     * 因此对 EAGAIN/EWOULDBLOCK/ENOBUFS 做短等待重试，把瞬时背压
     * 尽量吸收在发送层。
     *
     * ENOBUFS 常见于网卡/驱动发送队列短时打满，语义上同样是
     * 暂时不可发送，而不是永久协议错误。
     */
    for (int attempt = 0; attempt <= g_af_packet_send_retry_max; attempt++) {
        sent = sendto(sock, frame_buf, frame_len, 0,
                      (const struct sockaddr *)&sll, sizeof(sll));
        if (sent >= 0) {
            break;
        }

        saved_errno = errno;
        if (!af_packet_send_busy_errno(saved_errno)) {
            LOG_ERROR("af_packet_send: sendto failed (ifindex=%d, len=%zu): %s",
                      ifindex, frame_len, strerror(saved_errno));
            errno = saved_errno;
            return -1;
        }

        if (attempt == g_af_packet_send_retry_max) {
            LOG_DEBUG("af_packet_send: send buffer still full after retry "
                      "(ifindex=%d, len=%zu)", ifindex, frame_len);
            errno = saved_errno;
            return -1;
        }

        {
            struct pollfd pfd;

            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = sock;
            pfd.events = POLLOUT;

            int poll_ret = poll(&pfd, 1, g_af_packet_send_wait_ms);
            saved_errno = errno;
            if (poll_ret < 0 && saved_errno != EINTR) {
                LOG_ERROR("af_packet_send: poll(POLLOUT) failed "
                          "(ifindex=%d): %s", ifindex, strerror(saved_errno));
                errno = saved_errno;
                return -1;
            }
            /* 检查 revents：若 fd 进入错误状态则放弃重试 */
            if (poll_ret > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
                LOG_ERROR("af_packet_send: poll(POLLOUT) revents error 0x%x "
                          "(ifindex=%d)", (unsigned)pfd.revents, ifindex);
                errno = EIO;
                return -1;
            }
        }
    }

    if ((size_t)sent != frame_len) {
        LOG_ERROR("af_packet_send: partial send (%zd of %zu bytes)", sent, frame_len);
        /* 部分发送视为错误 */
        errno = EIO;
        return -1;
    }

    return sent;
}

/* ============================================================================
 * af_packet_recv — 接收并解析以太网帧
 *
 * 接收流程:
 *
 *   1. 参数校验: sock≥0, buf 非空, 输出指针非空
 *
 *   2. recvfrom(sock, recv_buf, ..., &sockaddr_ll, &sll_len)
 *      从 AF_PACKET 套接字接收原始以太网帧。
 *      AF_PACKET 返回的数据包含完整的以太网帧 (14 字节头 + 负载)。
 *      内核已根据 BPF 过滤器和 EtherType 做了预过滤。
 *
 *   3. 帧长度验证:
 *      - recvd < ETH_HDR_SIZE (14): 帧太短，返回 -1
 *      - recvd > sizeof(recv_buf): 帧超出内部缓冲区，返回 -1
 *
 *   4. 以太网头解析:
 *      dst_mac   = recv_buf[0..5]    (目标 MAC，6 字节)
 *      src_mac   = recv_buf[6..11]   (源 MAC，6 字节)
 *      ethertype = recv_buf[12]<<8 | recv_buf[13]  (EtherType，网络字节序)
 *
 *   5. 负载提取:
 *      payload_len = recvd - ETH_HDR_SIZE
 *      若 payload_len > buf_size (调用者缓冲区太小): 返回 -1
 *      否则 memcpy 负载到 buf[0..payload_len-1]
 *
 *   6. 错误处理:
 *      EAGAIN/EWOULDBLOCK: 非阻塞模式下无数据可读，静默返回 -1
 *      其他错误: LOG_ERROR 并返回 -1
 *
 * 返回值: 成功返回负载长度 (>0), 失败返回 -1
 * ============================================================================ */

ssize_t af_packet_recv(int sock, uint8_t *buf, size_t buf_size,
                       uint8_t src_mac[ETH_MAC_ADDR_LEN],
                       uint8_t dst_mac[ETH_MAC_ADDR_LEN],
                       uint16_t *ethertype)
{
    uint8_t            recv_buf[AF_PKT_MAX_FRAME]; /* 栈上 ~1642B；调用链已控递归深度 */
    struct sockaddr_ll sll;
    socklen_t          sll_len;
    ssize_t            recvd;
    size_t             payload_len;
    int                saved_errno;

    /* --- 参数校验 --- */
    if (sock < 0) {
        LOG_ERROR("af_packet_recv: invalid socket fd %d", sock);
        errno = EBADF;
        return -1;
    }

    if (!buf || buf_size == 0) {
        LOG_ERROR("af_packet_recv: null or zero-size buffer");
        errno = EINVAL;
        return -1;
    }

    if (!src_mac || !dst_mac || !ethertype) {
        LOG_ERROR("af_packet_recv: null output pointer");
        errno = EINVAL;
        return -1;
    }

    /* --- 接收原始帧 --- */
    memset(&sll, 0, sizeof(sll));
    sll_len = sizeof(sll);

    recvd = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                     (struct sockaddr *)&sll, &sll_len);
    if (recvd < 0) {
        saved_errno = errno;
        if (saved_errno != EAGAIN && saved_errno != EWOULDBLOCK) {
            LOG_ERROR("af_packet_recv: recvfrom failed: %s", strerror(saved_errno));
        }
        errno = saved_errno;
        return -1;
    }

    /* --- 验证帧长度 --- */
    if ((size_t)recvd < ETH_HDR_SIZE) {
        LOG_ERROR("af_packet_recv: received frame too short (%zd bytes, "
                  "minimum %d)", recvd, ETH_HDR_SIZE);
        errno = EINVAL;
        return -1;
    }

    if ((size_t)recvd > sizeof(recv_buf)) {
        LOG_ERROR("af_packet_recv: received frame exceeds buffer "
                  "(%zd > %zu)", recvd, sizeof(recv_buf));
        errno = EMSGSIZE;
        return -1;
    }

    /* --- 解析以太网头部 --- */
    memcpy(dst_mac, recv_buf, ETH_MAC_ADDR_LEN);
    memcpy(src_mac, recv_buf + ETH_MAC_ADDR_LEN, ETH_MAC_ADDR_LEN);
    *ethertype = ((uint16_t)recv_buf[12] << 8) | (uint16_t)recv_buf[13];

    payload_len = (size_t)recvd - ETH_HDR_SIZE;

    /* --- 将负载复制到调用者缓冲区 --- */
    if (payload_len > buf_size) {
        LOG_ERROR("af_packet_recv: payload length %zu exceeds caller buffer %zu",
                  payload_len, buf_size);
        errno = EMSGSIZE;
        return -1;
    }

    if (payload_len > 0) {
        memcpy(buf, recv_buf + ETH_HDR_SIZE, payload_len);
    }

    return (ssize_t)payload_len;
}

/* ============================================================================
 * af_packet_get_mac
 * ============================================================================ */

int af_packet_get_mac(int sock, const char *if_name, uint8_t mac[ETH_MAC_ADDR_LEN])
{
    struct ifreq ifr;
    int          ret;
    int          saved_errno;

    if (!if_name || !mac) {
        LOG_ERROR("af_packet_get_mac: null argument");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_get_mac: interface name too long: \"%s\"", if_name);
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    safe_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

    if (sock >= 0) {
        ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
    } else {
        /* 调用者未提供有效套接字，则尝试使用临时套接字 */
        int tmp_sock;

        tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_sock < 0) {
            LOG_ERROR("af_packet_get_mac: cannot create temp socket: %s",
                      strerror(errno));
            return -1;
        }
        ret = ioctl(tmp_sock, SIOCGIFHWADDR, &ifr);
        saved_errno = errno;
        close(tmp_sock);
        errno = saved_errno;
    }

    if (ret < 0) {
        LOG_ERROR("af_packet_get_mac: SIOCGIFHWADDR(%s) failed: %s",
                  if_name, strerror(errno));
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_MAC_ADDR_LEN);
    return 0;
}

/* ============================================================================
 * af_packet_get_ifindex
 * ============================================================================ */

int af_packet_get_ifindex(int sock, const char *if_name)
{
    struct ifreq ifr;
    int          ret;
    int          saved_errno;

    if (!if_name) {
        LOG_ERROR("af_packet_get_ifindex: null if_name");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_get_ifindex: interface name too long: \"%s\"",
                  if_name);
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    safe_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

    if (sock >= 0) {
        ret = ioctl(sock, SIOCGIFINDEX, &ifr);
    } else {
        int tmp_sock;

        tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_sock < 0) {
            LOG_ERROR("af_packet_get_ifindex: cannot create temp socket: %s",
                      strerror(errno));
            return -1;
        }
        ret = ioctl(tmp_sock, SIOCGIFINDEX, &ifr);
        saved_errno = errno;
        close(tmp_sock);
        errno = saved_errno;
    }

    if (ret < 0) {
        LOG_ERROR("af_packet_get_ifindex: SIOCGIFINDEX(%s) failed: %s",
                  if_name, strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

/* ============================================================================
 * af_packet_set_mtu
 * ============================================================================ */

int af_packet_set_mtu(int sock, const char *if_name, int mtu)
{
    struct ifreq ifr;
    int          ret;
    int          saved_errno;

    if (!if_name) {
        LOG_ERROR("af_packet_set_mtu: null if_name");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_set_mtu: interface name too long: \"%s\"", if_name);
        errno = EINVAL;
        return -1;
    }

    if (mtu <= 0 || mtu > 65535) {
        LOG_ERROR("af_packet_set_mtu: invalid MTU value %d", mtu);
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    safe_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
    ifr.ifr_mtu = mtu;

    if (sock >= 0) {
        ret = ioctl(sock, SIOCSIFMTU, &ifr);
    } else {
        int tmp_sock;

        tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_sock < 0) {
            LOG_ERROR("af_packet_set_mtu: cannot create temp socket: %s",
                      strerror(errno));
            return -1;
        }
        ret = ioctl(tmp_sock, SIOCSIFMTU, &ifr);
        saved_errno = errno;
        close(tmp_sock);
        errno = saved_errno;
    }

    if (ret < 0) {
        LOG_ERROR("af_packet_set_mtu: SIOCSIFMTU(%s, %d) failed: %s",
                  if_name, mtu, strerror(errno));
        return -1;
    }

    return 0;
}

/* ============================================================================
 * af_packet_get_mtu
 * ============================================================================ */

int af_packet_get_mtu(int sock, const char *if_name)
{
    struct ifreq ifr;
    int          ret;
    int          saved_errno;

    if (!if_name) {
        LOG_ERROR("af_packet_get_mtu: null if_name");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_get_mtu: interface name too long: \"%s\"", if_name);
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    safe_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

    if (sock >= 0) {
        ret = ioctl(sock, SIOCGIFMTU, &ifr);
    } else {
        int tmp_sock;

        tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_sock < 0) {
            LOG_ERROR("af_packet_get_mtu: cannot create temp socket: %s",
                      strerror(errno));
            return -1;
        }
        ret = ioctl(tmp_sock, SIOCGIFMTU, &ifr);
        saved_errno = errno;
        close(tmp_sock);
        errno = saved_errno;
    }

    if (ret < 0) {
        LOG_ERROR("af_packet_get_mtu: SIOCGIFMTU(%s) failed: %s",
                  if_name, strerror(errno));
        return -1;
    }

    return ifr.ifr_mtu;
}

/* ============================================================================
 * af_packet_detect_conflict
 *
 * ============================================================================ */

int af_packet_detect_conflict(const char *if_name, uint16_t ethertype)
{
    FILE *fp;
    char  line[PROC_NET_PACKET_LINE_MAX];
    int   found_conflict = 0;

    if (!if_name) {
        LOG_ERROR("af_packet_detect_conflict: null if_name");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_detect_conflict: interface name too long: \"%s\"",
                  if_name);
        errno = EINVAL;
        return -1;
    }

    fp = fopen("/proc/net/packet", "r");
    if (!fp) {
        LOG_ERROR("af_packet_detect_conflict: cannot open "
                  "/proc/net/packet: %s", strerror(errno));
        return -1;
    }

    /*
     * /proc/net/packet 格式（Linux 4.x+ 典型输出）：
     *
     *   sk       RefCnt Type Proto  Iface R Rmem   User   Inode
     *   ffff...  2      1    88b5   eth0  1 0      0      0     0
     *
     * 字段说明（空格/制表符分隔）：
     *   - Proto: 十六进制 EtherType（主机字节序？实际上是网络字节序的十六进制表示）
     *
     * 解析策略：
     *   1. 跳过标题行（以 "sk" 开头）
     *   2. 对每一行，提取 Proto（第 4 列）和 Iface（第 5 列）
     *   3. 比较 Iface 和 Proto
     */

    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        char          *token;
        char          *saveptr;
        int            col;
        int            match_iface;
        unsigned long  proto_val;

        /* 跳过标题行 */
        if (line[0] == 's' && line[1] == 'k') {
            continue;
        }

        /*
         * 使用 strtok_r 安全解析列。
         * 列索引（0-based）：
         *   0:sk  1:RefCnt  2:Type  3:Proto  4:Iface  5:R 6:Rmem ...
         */
        col = 0;
        match_iface = 0;
        proto_val   = 0;

        token = strtok_r(line, " \t\n", &saveptr);
        while (token != NULL) {
            if (col == 3) {
                /* Proto 字段 - 十六进制 */
                char *endptr;
                proto_val = strtoul(token, &endptr, 16);
                if (*endptr != '\0' && *endptr != ' ' && *endptr != '\t') {
                    /* 解析失败，跳过此行 */
                    proto_val = 0;
                    break;
                }
            } else if (col == 4) {
                /* Iface 字段 */
                if (strcmp(token, if_name) == 0) {
                    match_iface = 1;
                }
            }

            token = strtok_r(NULL, " \t\n", &saveptr);
            col++;
        }

        /*
         * 检查冲突：同一网卡接口上存在匹配的 EtherType 的套接字。
         *
         * 注意：/proc/net/packet 中的 Proto 字段为十六进制网络字节序。
         * 直接比较十六进制值即可。
         */
        if (match_iface && proto_val == ethertype) {
            found_conflict = 1;
            break;
        }
    }

    fclose(fp);

    if (found_conflict) {
        LOG_ERROR("af_packet_detect_conflict: conflict detected on %s "
                  "(ethertype=0x%04X)", if_name, ethertype);
        return 1;
    }

    return 0;
}

/* ============================================================================
 * af_packet_close
 * ============================================================================ */

void af_packet_close(int sock)
{
    if (sock >= 0) {
        /*
         * 在关闭之前分离 BPF 过滤器（尽力而为）。
         * 虽然 close 会自动清理，但显式分离可以避免残留状态。
         */
        setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);

        if (close(sock) < 0) {
            LOG_ERROR("af_packet_close: close(%d) failed: %s",
                      sock, strerror(errno));
        }
    }
}
