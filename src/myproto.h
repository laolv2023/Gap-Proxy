/*
 * myproto.h - MyProto 私有链路层协议模块
 *
 * 负责 MyProto 协议头的封装/解析、帧验证、CRC32 校验以及 SM4/SM3 加密接口。
 */

#ifndef MYPROTO_H
#define MYPROTO_H

#include "types.h"

/* ============================================================================
 * 帧类型判断内联函数
 * ============================================================================ */

/* 判断是否为控制帧（SYN/ACK/FIN/RST/PING/PONG 任一标志置位） */
static inline int myproto_is_ctrl_frame(uint8_t flags) {
    return (flags & MPF_CTRL_MASK) != 0;
}

/* 判断是否为数据帧（无控制标志，可能有加密标志） */
static inline int myproto_is_data_frame(uint8_t flags) {
    return (flags & MPF_CTRL_MASK) == 0;
}

/* 判断是否为加密帧 */
static inline int myproto_is_crypto_frame(uint8_t flags) {
    return (flags & MPF_CRYPTO) != 0;
}

/* ============================================================================
 * 函数声明
 * ============================================================================ */

/*
 * 验证 MyProto 帧头合法性
 * @param hdr 指向协议头的指针
 * @return    合法返回 0，非法返回 -1
 */
int myproto_validate_hdr(const myproto_hdr_t *hdr);

/*
 * 构造完整的 MyProto 帧（仅包含协议头 + 负载，不含以太网头）
 * 以太网头由 af_packet 层负责添加
 *
 * @param buf        输出缓冲区
 * @param buf_size   缓冲区大小
 * @param hdr        协议头结构体
 * @param payload    负载数据
 * @param payload_len 负载长度
 * @param crc_enabled 若为非零，自动附加 CRC32 到帧末尾
 * @return           成功返回完整帧长度（含 CRC），失败返回 -1
 */
ssize_t myproto_build_frame(uint8_t *buf, size_t buf_size,
                            const myproto_hdr_t *hdr,
                            const uint8_t *payload, size_t payload_len,
                            int crc_enabled);

/*
 * 解析 MyProto 帧
 * @param data       接收到的原始数据
 * @param data_len   数据长度
 * @param hdr        输出：解析出的协议头
 * @param payload    输出：负载数据指针（指向 data 内的位置）
 * @param payload_len 输出：负载长度
 * @return           成功返回 0，失败返回 -1
 */
int myproto_parse_frame(const uint8_t *data, size_t data_len,
                        myproto_hdr_t *hdr,
                        const uint8_t **payload, size_t *payload_len);

/*
 * 构造控制帧（SYN/ACK/FIN/RST/PING/PONG）
 * @param buf        输出缓冲区
 * @param buf_size   缓冲区大小
 * @param channel_id 通道 ID
 * @param flags      标志位（MPF_SYN 等）
 * @param crc_enabled 预留参数，控制帧不使用 CRC（内部恒传 0）
 * @return           成功返回帧总长度，失败返回 -1
 */
ssize_t myproto_build_ctrl_frame(uint8_t *buf, size_t buf_size,
                                 uint32_t channel_id, uint8_t flags,
                                 int crc_enabled);

/*
 * 构造数据帧（可能加密）
 * @param buf        输出缓冲区
 * @param buf_size   缓冲区大小
 * @param channel_id 通道 ID
 * @param flags      标志位（0 或 MPF_CRYPTO）
 * @param data       数据负载
 * @param data_len   数据长度
 * @param crc_enabled 若为非零，自动附加 CRC32 到帧末尾
 * @return           成功返回帧总长度（含 CRC），失败返回 -1
 */
ssize_t myproto_build_data_frame(uint8_t *buf, size_t buf_size,
                                 uint32_t channel_id, uint8_t flags,
                                 const uint8_t *data, size_t data_len,
                                 int crc_enabled);

/*
 * 处理接收到的数据帧（解密、验证 HMAC）
 * @param hdr        协议头
 * @param payload    负载指针（原地修改）
 * @param payload_len 负载长度指针（解密后更新）
 * @return           成功返回 0，失败返回 -1
 */
int myproto_process_data_frame(myproto_hdr_t *hdr,
                               uint8_t *payload, size_t *payload_len);

/*
 * 计算 CRC32 校验值
 * @param data    数据指针
 * @param len     数据长度
 * @return        CRC32 校验值
 */
uint32_t myproto_crc32(const uint8_t *data, size_t len);

/*
 * 附加 CRC32 到帧末尾
 * @param buf      帧缓冲区
 * @param frame_len 当前帧长度
 * @param buf_size  缓冲区总大小
 * @return          附加 CRC 后的帧长度，失败返回 -1
 */
ssize_t myproto_append_crc(uint8_t *buf, size_t frame_len, size_t buf_size);

/*
 * 验证帧末尾的 CRC32
 * @param buf      帧缓冲区
 * @param frame_len 帧长度（含 CRC）
 * @return          校验通过返回数据长度（不含 CRC），失败返回 -1
 */
ssize_t myproto_verify_crc(const uint8_t *buf, size_t frame_len);

#endif /* MYPROTO_H */
