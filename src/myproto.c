/*
 * myproto.c - MyProto 私有链路层协议模块实现
 *
 * 实现协议头的封装/解析、帧验证、CRC32 校验以及 SM4/SM3 加密存根。
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                      MyProto 帧格式（字节布局）                           ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                          ║
 * ║   ┌─ 以太网头（14 字节，由 af_packet 层添加/剥离） ─┐                    ║
 * ║   │ dst_mac(6) │ src_mac(6) │ EtherType(2)          │                    ║
 * ║   └─────────────────────────────────────────────────┘                    ║
 * ║                                                                          ║
 * ║   ┌─ MyProto 协议头（9 字节，本模块处理） ────────────────────────┐        ║
 * ║   │ channel_id(4) │ flags(1) │ payload_len(2) │ header_crc(2)    │        ║
 * ║   │  通道标识符    │ 标志位   │ 负载长度       │ 头部 CRC         │        ║
 * ║   └────────────────────────────────────────────────────────────────┘    ║
 * ║                                                                          ║
 * ║   ┌─ 负载区域（变长，payload_len 字节） ────────────────────────┐        ║
 * ║   │                                                             │        ║
 * ║   │  【明文模式】: raw_data                                     │        ║
 * ║   │  【加密模式】: IV(16B) ∥ SM4-CBC密文(N×16B) ∥ SM3-HMAC(32B)│        ║
 * ║   │                                                             │        ║
 * ║   └─────────────────────────────────────────────────────────────┘        ║
 * ║                                                                          ║
 * ║   ┌─ CRC32 尾部（可选，4 字节小端序） ─┐                                 ║
 * ║   │ crc32(4) — 覆盖 [MyProto头 + 负载] │                                 ║
 * ║   └────────────────────────────────────┘                                 ║
 * ║                                                                          ║
 * ║   【完整帧结构总结】                                                      ║
 * ║   Eth(14) + MyProtoHdr(9) + Payload(N) + [CRC32(4)]                      ║
 * ║   最小帧: 14 + 9 = 23 字节                                               ║
 * ║   最大帧: 14 + 9 + 1500 + 4 = 1527 字节                                  ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "types.h"
#include "myproto.h"
#include "crypto.h"

/* 测试场景弱符号：正式程序中 api.c 的强符号覆盖此 no-op fallback */
void __attribute__((weak))
log_output(int level, const char *fmt, ...)
{
    (void)level; (void)fmt;
}

/* ============================================================================
 * 内部常量
 * ============================================================================ */

/* 帧最小长度：MyProto 协议头（以太网头由 af_packet 层处理） */
#define MYPROTO_MIN_FRAME_SIZE  (MYPROTO_HDR_SIZE)

/* H3: 编译期断言 MAX_FRAME_SIZE 不小于 ETH_MAX_PAYLOAD, 防止栈溢出 */
_Static_assert(MAX_FRAME_SIZE >= ETH_MAX_PAYLOAD,
               "MAX_FRAME_SIZE must be >= ETH_MAX_PAYLOAD to prevent stack overflow");

/* ============================================================================
 * CRC-16/CCITT（帧头完整性校验）
 *
 * 算法参数:
 *   多项式:   0x1021 (x^16 + x^12 + x^5 + 1)
 *   初始值:   0x0000
 *   输入反射: 否 (MSB first)
 *   输出反射: 否
 *   XOR-out:  无 (0x0000)
 *
 * 计算方式:
 *   for each byte:
 *     crc ^= (byte << 8)  — 字节与 CRC 高 8 位异或
 *     for 8 bits:
 *       if crc & 0x8000: crc = (crc << 1) ^ 0x1021
 *       else:            crc = (crc << 1)
 *
 * 覆盖范围: MyProto 帧头前 7 字节 (channel_id(4) + flags(1) + payload_len(2))
 *           即线格式中 header_crc 字段之前的所有字段。
 *
 * 用途: 检测传输过程中帧头比特错误。CRC-16 可检测所有单比特、双比特错误
 *       以及所有长度 ≤ 16 的突发错误，漏检率约为 1/65536。
 *
 * 注意: 这是非加密完整性校验，不防篡改。帧的防篡改由 SM3-HMAC 提供。
 * ============================================================================ */
static uint16_t crc16_ccitt(const uint8_t *data, size_t len)
{
    uint16_t crc = 0x0000;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

/* ============================================================================
 * CRC32 实现 (帧尾完整性校验)
 *
 * 算法: CRC-32/ISO-HDLC (与 Ethernet FCS、gzip、PNG 一致)
 *
 * 参数:
 *   多项式:   0x04C11DB7 (标准 CRC-32)
 *   反射形式: 0xEDB88320 (查表优化用反射多项式)
 *   初始值:   0xFFFFFFFF
 *   输入反射: 是 (每个字节 LSB first)
 *   输出反射: 是
 *   XOR-out:  0xFFFFFFFF
 *
 * 实现方式:
 *   使用 256 条目查找表加速，避免逐位计算。
 *   查表公式: crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
 *
 * 线程安全:
 *   使用 pthread_once 确保查找表只初始化一次。
 *   crc32_table_init() 在线程安全的单次调用中生成查找表，
 *   后续所有线程共享同一份只读查找表。
 *
 * 惰性初始化:
 *   查找表在首次调用 myproto_crc32() 时生成，而非程序启动时。
 *   若程序从未使用 CRC32 功能，查找表不会占用内存。
 *
 * ═ 覆盖范围 ═
 *   CRC32 覆盖 [MyProto头(9B) + 负载(N B)] 全部数据，
 *   即整个 MyProto 帧 (不含以太网头)。
 *
 * ═ 用途 ═
 *   可选的数据完整性校验。与 CRC-16 header_crc 的区别:
 *     - header_crc (CRC-16): 仅覆盖帧头，必选校验
 *     - frame_crc (CRC-32): 覆盖帧头+负载，可选 (通过 crc_enabled 控制)
 * ============================================================================ */
static void crc32_generate_table(uint32_t table[256])
{
    int i, j;

    for (i = 0; i < 256; i++) {
        uint32_t crc = (uint32_t)i;
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
}

/*
 * 获取 CRC32 查找表（惰性初始化，使用 pthread_once 确保线程安全）。
 */
static pthread_once_t crc32_table_once = PTHREAD_ONCE_INIT;
static uint32_t crc32_table[256];

static void crc32_table_init(void)
{
    crc32_generate_table(crc32_table);
}

static const uint32_t *crc32_get_table(void)
{
    pthread_once(&crc32_table_once, crc32_table_init);
    return crc32_table;
}

/*
 * myproto_crc32 — 计算数据的 CRC32 校验值 (查表法)
 *
 * 使用标准 CRC-32/ISO-HDLC 多项式 (0xEDB88320 反射形式)。
 * 初始值 0xFFFFFFFF，最终异或 0xFFFFFFFF。
 *
 * 查表法公式: crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
 *
 * 逐字节处理，每个字节:
 *   crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8)
 *
 * 这是 CRC-32 最常用的实现 (与 Ethernet / gzip / PNG 一致)。
 * 查找表通过 pthread_once 惰性初始化，线程安全。
 */
uint32_t myproto_crc32(const uint8_t *data, size_t len)
{
    const uint32_t *table = crc32_get_table();
    uint32_t crc = 0xFFFFFFFF;
    size_t i;

    for (i = 0; i < len; i++) {
        crc = (crc >> 8) ^ table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============================================================================
 * 公开 API 实现
 * ============================================================================ */

/*
 * myproto_validate_hdr — 验证 MyProto 帧头合法性
 *
 * 输入: 已解析的 myproto_hdr_t 结构体 (由 myproto_parse_frame 填充)
 *
 * 检查项:
 *   1. hdr 非空 (空指针防御)
 *
 *   2. channel_id 范围检查:
 *      - channel_id ∈ [0, MAX_CHANNELS]: 静态预分配的通道 ID，直接放行
 *      - channel_id == HEARTBEAT_CH_ID: 心跳专用通道 ID，特殊放行
 *      - channel_id > MAX_CHANNELS: 动态分配的通道 ID (多会话模式)，
 *        允许通过，由上层 channel.c 的路由逻辑处理。
 *        仅记录 LOG_DEBUG 日志，不返回错误。
 *
 *   3. payload_len 上限检查:
 *      - payload_len ≤ ETH_MAX_PAYLOAD (1500 字节)
 *      - 超出则返回 -1，防止接收端缓冲区溢出
 *
 * 返回值: 0=合法, -1=非法 (payload_len 超限)
 *         注意: channel_id 超出 MAX_CHANNELS 不算错误，仅动态通道。
 */
int myproto_validate_hdr(const myproto_hdr_t *hdr)
{
    if (!hdr) {
        LOG_ERROR("myproto_validate_hdr: null header pointer");
        return -1;
    }

    if (hdr->channel_id > MAX_CHANNELS && hdr->channel_id != HEARTBEAT_CH_ID) {
        LOG_DEBUG("myproto_validate_hdr: channel_id %u exceeds MAX_CHANNELS (%u), "
                  "may be dynamic channel",
                  (unsigned int)hdr->channel_id, MAX_CHANNELS);
        /* 动态 channel_id 允许通过，不返回 -1 */
    }

    /* R4-H1: 硬上限检查 — 防止任意32位channel_id通过。
     * MAX_CHANNELS * 16 = 1048576，为动态通道留出充足余量。 */
    if (hdr->channel_id > 1048576 && hdr->channel_id != HEARTBEAT_CH_ID) {
        LOG_WARN("myproto_validate_hdr: channel_id %u exceeds hard limit 1048576",
                  (unsigned int)hdr->channel_id);
        return -1;
    }

    if (hdr->payload_len > ETH_MAX_PAYLOAD) {
        LOG_ERROR("myproto_validate_hdr: payload_len %u exceeds ETH_MAX_PAYLOAD (%u)",
                  hdr->payload_len, ETH_MAX_PAYLOAD);
        return -1;
    }

    return 0;
}

/*
 * myproto_build_frame — 构造完整的 MyProto 帧 (通用帧构建函数)
 *
 * 这是 MyProto 协议的帧序列化核心。myproto_build_data_frame 和
 * myproto_build_ctrl_frame 最终都通过本函数完成帧头写入+负载复制。
 *
 * 缓冲区布局 (MyProto 层视角，不含以太网头，以太网头由 af_packet 层添加):
 *   [0..3]    channel_id  (4 字节，大端序，htonl 转换)
 *   [4]       flags       (1 字节，直接赋值)
 *   [5..6]    payload_len (2 字节，大端序，htons 转换)
 *   [7..8]    header_crc  (2 字节，CRC-16/CCITT over 前 7 字节线格式)
 *   [9..]     负载数据    (payload_len 字节，原样复制)
 *   [若 crc_enabled] CRC32 (4 字节小端序，通过 myproto_append_crc 追加)
 *
 * 帧头构造细节:
 *   1. channel_id → htonl() → 写入 buf[0..3] (网络字节序: 大端)
 *   2. flags      → 直接写入 buf[4] (单字节，无字节序)
 *   3. payload_len → htons() → 写入 buf[5..6] (网络字节序: 大端)
 *   4. header_crc  → crc16_ccitt(buf[0..6]) → 写入 buf[7..8]
 *      (CRC-16 覆盖前 7 字节，包含 channel_id + flags + payload_len)
 *
 * 自重叠优化:
 *   负载可能已由 crypto_encrypt_frame 写入 buf+MYPROTO_HDR_SIZE (加密路径)。
 *   若 payload == buf + MYPROTO_HDR_SIZE (原地数据)，跳过 memcpy 避免
 *   自重叠拷贝。非加密路径下 payload 指向独立数据区，执行 memcpy。
 *
 * CRC 追加:
 *   若 crc_enabled: 调用 myproto_append_crc() 在帧末尾追加 CRC32。
 *   否则返回 total_len = MYPROTO_HDR_SIZE + payload_len。
 *
 * 成功返回实际帧长度 (含 CRC 则为 total_len+4)，失败返回 -1。
 */
ssize_t myproto_build_frame(uint8_t *buf, size_t buf_size,
                            const myproto_hdr_t *hdr,
                            const uint8_t *payload, size_t payload_len,
                            int crc_enabled)
{
    size_t total_len;

    if (!buf) {
        LOG_ERROR("myproto_build_frame: null buffer");
        return -1;
    }
    if (!hdr) {
        LOG_ERROR("myproto_build_frame: null header pointer");
        return -1;
    }
    if (payload_len > 0 && !payload) {
        LOG_ERROR("myproto_build_frame: null payload with non-zero length %zu",
                  payload_len);
        return -1;
    }

    if (buf_size < MYPROTO_HDR_SIZE) {
        LOG_ERROR("myproto_build_frame: buffer too small (have %zu, need %u)",
                  buf_size, MYPROTO_HDR_SIZE);
        return -1;
    }
    if (payload_len > buf_size - MYPROTO_HDR_SIZE) {
        LOG_ERROR("myproto_build_frame: buffer too small "
                  "(need %zu, have %zu)", MYPROTO_HDR_SIZE + payload_len, buf_size);
        return -1;
    }

    total_len = MYPROTO_HDR_SIZE + payload_len;

    /* 写入 MyProto 协议头（大端序） */
    {
        uint32_t net_channel  = htonl(hdr->channel_id);
        uint16_t net_payload  = htons(hdr->payload_len);
        uint16_t header_crc;

        memcpy(buf,     &net_channel,  4);
        buf[4] = hdr->flags;
        memcpy(buf + 5, &net_payload,  2);

        /* CRC-16/CCITT over first 7 header bytes (wire format) */
        header_crc = crc16_ccitt(buf, 7);
        memcpy(buf + 7, &header_crc,   2);
    }

    /* 复制负载数据（若 payload 已位于 buf+MYPROTO_HDR_SIZE 则跳过，
     * 避免自重叠 memcpy — 加密路径下数据已由 crypto 模块原地写入） */
    if (payload_len > 0 && payload != buf + MYPROTO_HDR_SIZE) {
        memcpy(buf + MYPROTO_HDR_SIZE, payload, payload_len);
    }

    /* 如果启用 CRC，附加 CRC32 到帧末尾 */
    if (crc_enabled) {
        ssize_t ret = myproto_append_crc(buf, total_len, buf_size);
        if (ret < 0) {
            return -1;
        }
        return ret;
    }

    return (ssize_t)total_len;
}

/*
 * myproto_parse_frame — 解析 MyProto 帧 (反序列化)
 *
 * 从原始字节流中提取 MyProto 协议头，验证合法性，输出负载指针和长度。
 * 输入数据从 MyProto 协议头开始 (以太网头已由 af_packet 层剥离)。
 *
 * 解析流程:
 *   1. 空指针检查 (data, hdr, payload, payload_len 全部非空)
 *   2. 最小长度检查: data_len ≥ MYPROTO_HDR_SIZE (9 字节)
 *   3. 协议头反序列化 (大端序 → 主机序):
 *        channel_id  = ntohl(data[0..3])
 *        flags       = data[4]
 *        payload_len = ntohs(data[5..6])
 *        wire_crc    = data[7..8] (原样读取)
 *   4. CRC-16 帧头完整性校验:
 *        computed = crc16_ccitt(data[0..6])
 *        若 computed != wire_crc → 返回 -1 (帧头损坏)
 *   5. 协议头合法性校验: myproto_validate_hdr()
 *        channel_id 范围 + payload_len 上限
 *   6. 负载边界检查: payload_len ≤ 实际可用数据长度
 *        (data_len - MYPROTO_MIN_FRAME_SIZE)
 *   7. 设置输出:
 *        *payload     = data + MYPROTO_HDR_SIZE (负载起始地址)
 *        *payload_len = hdr->payload_len          (负载长度)
 *
 * 成功返回 0，失败返回 -1。
 */
int myproto_parse_frame(const uint8_t *data, size_t data_len,
                        myproto_hdr_t *hdr,
                        const uint8_t **payload, size_t *payload_len)
{
    if (!data) {
        LOG_ERROR("myproto_parse_frame: null data pointer");
        return -1;
    }
    if (!hdr) {
        LOG_ERROR("myproto_parse_frame: null header output pointer");
        return -1;
    }
    if (!payload) {
        LOG_ERROR("myproto_parse_frame: null payload output pointer");
        return -1;
    }
    if (!payload_len) {
        LOG_ERROR("myproto_parse_frame: null payload_len output pointer");
        return -1;
    }

    if (data_len < MYPROTO_MIN_FRAME_SIZE) {
        LOG_ERROR("myproto_parse_frame: data too short "
                  "(%zu bytes, minimum %u)", data_len, MYPROTO_MIN_FRAME_SIZE);
        return -1;
    }

    /* 从以太网头之后读取 MyProto 协议头（大端序） */
    {
        uint32_t net_channel;
        uint16_t net_payload;
        uint16_t wire_crc;

        memcpy(&net_channel, data,     4);
        hdr->flags       = data[4];
        memcpy(&net_payload, data + 5, 2);
        memcpy(&wire_crc,   data + 7, 2);

        hdr->channel_id  = ntohl(net_channel);
        hdr->payload_len = ntohs(net_payload);

        /* CRC-16/CCITT 帧头完整性校验 */
        {
            uint16_t computed = crc16_ccitt(data, 7);
            if (computed != wire_crc) {
                LOG_ERROR("myproto_parse_frame: header CRC mismatch (ch=%u)",
                          hdr->channel_id);
                return -1;
            }
            hdr->header_crc = wire_crc;
        }
    }

    /* 验证协议头 */
    if (myproto_validate_hdr(hdr) != 0) {
        return -1;
    }

    /* 检查 payload_len 是否在可用数据范围内 */
    {
        size_t available = data_len - MYPROTO_MIN_FRAME_SIZE;
        if (hdr->payload_len > available) {
            LOG_ERROR("myproto_parse_frame: declared payload_len %u exceeds "
                      "available bytes %zu", hdr->payload_len, available);
            return -1;
        }
    }

    /* 设置输出指针 */
    *payload = data + MYPROTO_HDR_SIZE;
    *payload_len = hdr->payload_len;

    return 0;
}

/*
 * myproto_build_ctrl_frame — 构造控制帧 (无负载的纯协议头帧)
 *
 * 控制帧定义: 帧头指定 flags 中包含至少一个控制标志位 (MPF_CTRL_MASK)，
 * payload_len 固定为 0，无负载数据。
 *
 * 控制帧类型 (通过 flags 区分):
 *   MPF_SYN  — 连接建立请求 (SYN)
 *   MPF_FIN  — 连接关闭请求 (FIN)
 *   MPF_RST  — 连接重置 (RST)
 *   MPF_ACK  — 确认 (ACK)
 *
 * 约束:
 *   - flags 必须包含至少一个 MPF_CTRL_MASK 位 (SYN/FIN/RST/ACK 之一)，
 *     否则视为调用错误返回 -1
 *   - 控制帧不附加 CRC32 (crc_enabled 参数被忽略，内部恒传 0)
 *     理由: 控制帧长度固定 (9 字节)，CRC-16 header_crc 已提供头部校验，
 *           无负载无需额外的 CRC32
 *   - crc_enabled 参数保留仅用于接口统一，
 *     与 myproto_build_data_frame 保持相同的函数签名风格
 *
 * 与 myproto_build_data_frame 的区别:
 *   - 控制帧: payload_len=0, 无加密, 无 CRC32
 *   - 数据帧: 可能含负载, 可能加密 (MPF_CRYPTO), 可能附加 CRC32
 */
ssize_t myproto_build_ctrl_frame(uint8_t *buf, size_t buf_size,
                                 uint32_t channel_id, uint8_t flags,
                                 int crc_enabled)
{
    myproto_hdr_t hdr;

    if (!buf) {
        LOG_ERROR("myproto_build_ctrl_frame: null buffer");
        return -1;
    }

    if (buf_size < MYPROTO_MIN_FRAME_SIZE) {
        LOG_ERROR("myproto_build_ctrl_frame: buffer too small "
                  "(need %u, have %zu)", MYPROTO_MIN_FRAME_SIZE, buf_size);
        return -1;
    }

    (void)crc_enabled; /* 控制帧不使用 CRC，保留参数以供接口统一 */

    /* 验证 flags 中至少包含一个控制标志 */
    if ((flags & MPF_CTRL_MASK) == 0) {
        LOG_ERROR("myproto_build_ctrl_frame: no control flag set in flags=0x%02X",
                  flags);
        return -1;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id  = channel_id;
    hdr.flags       = flags;
    hdr.payload_len = 0;

    return myproto_build_frame(buf, buf_size, &hdr, NULL, 0, 0);
}

/*
 * myproto_build_data_frame — 构造数据帧 (可能加密)
 *
 * 数据帧是 MyProto 协议传输用户数据的核心载体。
 *
 * 两条路径:
 *
 *   【加密路径】(flags & MPF_CRYPTO):
 *     1. 预检查缓冲区容量: buf_size 需容纳 MYPROTO_HDR_SIZE + CRYPTO_OVERHEAD
 *        CRYPTO_OVERHEAD = IV(16) + PKCS7_pad(≤16) + HMAC(32) ≈ 64 字节
 *     2. 调用 crypto_encrypt_frame():
 *        data → buf + MYPROTO_HDR_SIZE (原地加密，输出写入帧头的后续空间)
 *        加密输出线格式: IV(16) | SM4-CBC密文 | SM3-HMAC(32)
 *     3. wire_payload_len = 加密后总长度 (IV+密文+HMAC)
 *     4. 构建协议头: payload_len = wire_payload_len, flags 含 MPF_CRYPTO
 *     5. 调用 myproto_build_frame(..., buf+MYPROTO_HDR_SIZE, wire_payload_len)
 *        负载已在 buf 内原地就位 (payload == buf+MYPROTO_HDR_SIZE)，
 *        myproto_build_frame 检测到自重叠后跳过 memcpy
 *
 *   【非加密路径】:
 *     1. wire_payload_len = data_len (原始数据原样传输)
 *     2. 构建协议头: payload_len = data_len, flags 不含 MPF_CRYPTO
 *     3. 调用 myproto_build_frame(..., data, data_len)
 *        data 指向独立数据区，myproto_build_frame 通过 memcpy 复制
 *
 * 线格式总结:
 *   加密帧:   Eth(14) + MyProtoHdr(9) + IV(16) + 密文(N) + HMAC(32) [+ CRC32(4)]
 *   明文帧:   Eth(14) + MyProtoHdr(9) + Payload(N)                [+ CRC32(4)]
 *
 * 加密由 crypto 模块 (SM4-CBC + SM3-HMAC via Nettle) 处理。
 */
ssize_t myproto_build_data_frame(uint8_t *buf, size_t buf_size,
                                 uint32_t channel_id, uint8_t flags,
                                 const uint8_t *data, size_t data_len,
                                 int crc_enabled)
{
    myproto_hdr_t hdr;
    size_t wire_payload_len;
    size_t total_len;

    if (!buf) {
        LOG_ERROR("myproto_build_data_frame: null buffer");
        return -1;
    }
    if (data_len > 0 && !data) {
        LOG_ERROR("myproto_build_data_frame: null data with non-zero length %zu",
                  data_len);
        return -1;
    }

    /* 加密路径：先将加密输出写入 buf+MYPROTO_HDR_SIZE，再构建帧头 */
    if (flags & MPF_CRYPTO) {
        /* Pre-check buffer capacity: crypto may add up to CRYPTO_OVERHEAD bytes */
        int max_crypto_len;
        /* KCP data_len is bounded by KCP MTU (~1400), and CRYPTO_OVERHEAD=64;
         * ETH_MAX_PAYLOAD=1500 < INT_MAX, so (int)data_len + CRYPTO_OVERHEAD
         * never exceeds INT_MAX. See _Static_assert below. */
        _Static_assert(ETH_MAX_PAYLOAD + CRYPTO_OVERHEAD <= INT_MAX,
                       "data_len + CRYPTO_OVERHEAD must fit in int");
        max_crypto_len = (int)data_len + CRYPTO_OVERHEAD;
        if (MYPROTO_HDR_SIZE + (size_t)max_crypto_len > buf_size) {
            LOG_ERROR("myproto_build_data_frame: buffer too small for crypto "
                      "(need at least %zu, have %zu)",
                      MYPROTO_HDR_SIZE + (size_t)max_crypto_len, buf_size);
            return -1;
        }
        /* Pre-compute wire payload length for AEAD: pkcs7 guarantees
         * ct_len = ((data_len / 16) + 1) * 16, so:
         * payload_len = SM4_IV_LEN(16) + ct_len + SM3_HMAC_LEN(32) */
        int ct_est = ((int)data_len / SM4_IV_LEN + 1) * SM4_IV_LEN;
        uint16_t est_payload_len = (uint16_t)(SM4_IV_LEN + ct_est + SM3_HMAC_LEN);
        /* Now safe to write */
        int crypto_len = crypto_encrypt_frame(data, (int)data_len,
                                               buf + MYPROTO_HDR_SIZE,
                                               (int)(buf_size - MYPROTO_HDR_SIZE),
                                               channel_id, flags,
                                               est_payload_len);
        if (crypto_len < 0) {
            LOG_ERROR("crypto_encrypt_frame failed");
            return -1;
        }
        wire_payload_len = (size_t)crypto_len;
    } else {
        wire_payload_len = data_len;
    }

    total_len = MYPROTO_HDR_SIZE + wire_payload_len;
    if (total_len > buf_size) {
        LOG_ERROR("myproto_build_data_frame: buffer too small "
                  "(need %zu, have %zu)", total_len, buf_size);
        return -1;
    }

    if (wire_payload_len > ETH_MAX_PAYLOAD) {
        LOG_ERROR("myproto_build_data_frame: wire payload %zu exceeds "
                  "ETH_MAX_PAYLOAD %u", wire_payload_len, ETH_MAX_PAYLOAD);
        return -1;
    }

    /* 构建协议头 */
    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id  = channel_id;
    hdr.flags       = flags;
    hdr.payload_len = (uint16_t)wire_payload_len;

    /*
     * 加密路径下，加密数据已由 crypto_encrypt_frame 写入 buf+MYPROTO_HDR_SIZE；
     * 非加密路径下，原始数据还在 data 中。
     * 使用 myproto_build_frame 统一写入头 + 负载。
     */
    if (flags & MPF_CRYPTO) {
        return myproto_build_frame(buf, buf_size, &hdr,
                                    buf + MYPROTO_HDR_SIZE, wire_payload_len,
                                    crc_enabled);
    } else {
        return myproto_build_frame(buf, buf_size, &hdr, data, data_len,
                                    crc_enabled);
    }
}

/*
 * myproto_process_data_frame — 处理接收到的数据帧 (解密 + HMAC 验证)
 *
 * 这是接收端处理加密帧的核心函数。myproto_parse_frame 完成帧头解析后，
 * 由 channel_process_frame 调用本函数对负载进行解密和认证。
 *
 * 处理流程:
 *   1. 若未启用加密 (flags 不含 MPF_CRYPTO): 直接返回 0，负载保持原样
 *
 *   2. 加密帧处理:
 *      a. 调用 crypto_decrypt_frame(payload, *payload_len, decrypted_buf, ...)
 *         解密并进行 SM3-HMAC 验证 (Encrypt-then-MAC)
 *         crypto_decrypt_frame 内部:
 *           → 先验证 HMAC (常量时间比较)
 *           → HMAC 通过后才执行 SM4-CBC 解密 + PKCS7 去填充
 *      b. 解密成功: 检查 decrypted_len ≤ *payload_len (防止缓冲区溢出)
 *      c. memmove 将解密后的明文移回 payload 区域 (原地替换密文)
 *      d. 更新 *payload_len = decrypted_len (解密后长度变短)
 *
 *   3. 解密/HMAC 失败: 返回 -1，帧被丢弃
 *
 * 安全设计:
 *   - HMAC 先验证后解密，防止 padding oracle 攻击
 *   - 常量时间 MAC 比较，防止 timing side-channel
 *   - 使用 memmove 而非 memcpy，支持原地解密 (decrypted_buf → payload)
 *   - HMAC 覆盖 channel_id/flags/payload_len 关联数据，防止跨通道重放 (R4-C2)
 *
 * 加密由 crypto 模块 (SM4-CBC + SM3-HMAC via Nettle) 处理。
 */
int myproto_process_data_frame(myproto_hdr_t *hdr,
                               uint8_t *payload, size_t *payload_len)
{
    size_t decrypted_len;
    uint8_t decrypted_buf[MAX_FRAME_SIZE];
    int ret;

    if (!hdr) {
        LOG_ERROR("myproto_process_data_frame: null header pointer");
        return -1;
    }
    if (!payload) {
        LOG_ERROR("myproto_process_data_frame: null payload pointer");
        return -1;
    }
    if (!payload_len) {
        LOG_ERROR("myproto_process_data_frame: null payload_len pointer");
        return -1;
    }

    /* 非加密帧：无需处理，直接返回成功 */
    if (!(hdr->flags & MPF_CRYPTO)) {
        return 0;
    }

    /* 拒绝加密帧：crypto 未启用时不透传密文 */
    if (!crypto_is_enabled()) {
        LOG_ERROR("myproto_process_data_frame: crypto frame received but crypto disabled");
        return -1;
    }

    /* 加密帧处理：调用 crypto 模块解密，传入关联数据用于 AEAD */
    ret = crypto_decrypt_frame(payload, (int)*payload_len,
                                decrypted_buf, sizeof(decrypted_buf),
                                hdr->channel_id, hdr->flags,
                                hdr->payload_len);
    if (ret < 0) {
        LOG_ERROR("crypto_decrypt_frame failed (HMAC/auth error)");
        return -1;
    }
    decrypted_len = (size_t)ret;

    /* 检查解密后长度不超过原始密文缓冲区 */
    if (decrypted_len > *payload_len) {
        LOG_ERROR("myproto_process_data_frame: decrypted length %zu exceeds "
                  "payload buffer %zu", decrypted_len, *payload_len);
        return -1;
    }

    /* 将解密后的明文移回 payload 区域 */
    memmove(payload, decrypted_buf, decrypted_len);
    *payload_len = decrypted_len;

    return 0;
}

/*
 * myproto_append_crc — 附加 CRC32 到帧末尾
 *
 * 计算 buf[0..frame_len-1] 的 CRC32 (ISO-HDLC 标准多项式)，
 * 以 4 字节小端序 (little-endian) 附加到 frame_len 偏移处。
 *
 * 为什么要小端序? CRC32 在 Ethernet FCS 中是小端序存储，
 * 保持一致性便于调试和与其他工具互通。
 *
 * 输出格式: [原始帧数据(N)] [CRC32 byte0(LSB) | byte1 | byte2 | byte3(MSB)]
 *
 * 返回值: 附加 CRC 后的帧总长度 (frame_len + 4)，失败返回 -1
 */
ssize_t myproto_append_crc(uint8_t *buf, size_t frame_len, size_t buf_size)
{
    uint32_t crc;

    if (!buf) {
        LOG_ERROR("myproto_append_crc: null buffer");
        return -1;
    }

    if (buf_size < CRC32_SIZE) {
        LOG_ERROR("myproto_append_crc: buffer too small (have %zu, need %u)",
                  buf_size, CRC32_SIZE);
        return -1;
    }
    if (frame_len > buf_size - CRC32_SIZE) {
        LOG_ERROR("myproto_append_crc: buffer overflow "
                  "(frame_len=%zu + CRC=%u > buf_size=%zu)",
                  frame_len, CRC32_SIZE, buf_size);
        return -1;
    }

    if (frame_len == 0) {
        LOG_ERROR("myproto_append_crc: zero frame length");
        return -1;
    }

    crc = myproto_crc32(buf, frame_len);

    /* 以小端序写入 CRC32 */
    buf[frame_len]     = (uint8_t)(crc & 0xFF);
    buf[frame_len + 1] = (uint8_t)((crc >> 8) & 0xFF);
    buf[frame_len + 2] = (uint8_t)((crc >> 16) & 0xFF);
    buf[frame_len + 3] = (uint8_t)((crc >> 24) & 0xFF);

    return (ssize_t)(frame_len + CRC32_SIZE);
}

/*
 * myproto_verify_crc — 验证帧末尾的 CRC32
 *
 * 解析流程:
 *   1. 最小长度检查: frame_len ≥ CRC32_SIZE (4 字节)
 *   2. 数据长度: data_len = frame_len - CRC32_SIZE
 *   3. 计算数据部分的 CRC32: computed = myproto_crc32(buf, data_len)
 *   4. 读取存储的 CRC32: stored = buf[data_len..data_len+3] (小端序)
 *   5. 比较 computed vs stored:
 *        - 相等: 返回 data_len (校验通过的数据长度)
 *        - 不等: 返回 -1 (CRC 不匹配，帧被丢弃)
 *
 * 覆盖范围: buf[0..data_len-1] = [MyProto头 + 负载]
 * CRC 字段本身不参与计算。
 *
 * 校验通过返回数据长度（不含 CRC），失败返回 -1。
 */
ssize_t myproto_verify_crc(const uint8_t *buf, size_t frame_len)
{
    uint32_t computed_crc;
    uint32_t stored_crc;
    size_t data_len;

    if (!buf) {
        LOG_ERROR("myproto_verify_crc: null buffer");
        return -1;
    }

    if (frame_len < CRC32_SIZE) {
        LOG_ERROR("myproto_verify_crc: frame too short for CRC "
                  "(%zu bytes, minimum %u)", frame_len, CRC32_SIZE);
        return -1;
    }

    data_len = frame_len - CRC32_SIZE;

    /* 计算数据部分的 CRC32 */
    computed_crc = myproto_crc32(buf, data_len);

    /* 读取存储的 CRC32（小端序） */
    stored_crc = (uint32_t)buf[data_len]
               | ((uint32_t)buf[data_len + 1] << 8)
               | ((uint32_t)buf[data_len + 2] << 16)
               | ((uint32_t)buf[data_len + 3] << 24);

    if (computed_crc != stored_crc) {
        LOG_ERROR("myproto_verify_crc: CRC mismatch "
                  "(computed=0x%08X, stored=0x%08X)",
                  computed_crc, stored_crc);
        return -1;
    }

    return (ssize_t)data_len;
}
