/**
 * @file    crypto.h
 * @brief   国密加密模块 — SM4-CBC 对称加密 + SM3-HMAC 消息认证
 *
 * 本模块提供帧级别的加密/解密和完整性保护。
 * 加密算法组合: SM4-CBC (128-bit 分组密码, 国密 GB/T 32907)
 *               + SM3-HMAC (256-bit 哈希消息认证码, 国密 GB/T 32905)
 *               + PKCS7 填充 (对齐到 16 字节块)
 *               + 随机 IV (/dev/urandom, 每帧独立)
 * 底层依赖: GNU Nettle 加密库 (libnettle)。
 *
 * ═══════════════ 加密帧格式 ═══════════════
 *
 *   ┌───────┬──────────────────────┬────────────────┐
 *   │  IV   │  SM4-CBC Ciphertext  │  SM3-HMAC      │
 *   │ 16 B  │  (PKCS7 padded, N)   │  32 B          │
 *   └───────┴──────────────────────┴────────────────┘
 *
 * 字段说明:
 *   IV (16 字节):      随机初始化向量，每帧独立生成，以明文传输。
 *                      CBC 模式下 IV 只需不可预测，不需要保密。
 *   Ciphertext (N 字节): SM4-CBC 加密后的密文，含 PKCS7 填充。
 *                       N 始终为 16 的倍数 (PKCS7 填充保证)。
 *                       PKCS7 规则: 若明文长度 mod 16 = 0，追加 16 字节 0x10；
 *                       否则追加 (16-r) 字节的 (16-r)。
 *   HMAC (32 字节):     SM3-HMAC 消息认证码，覆盖 AD || IV || Ciphertext，
 *                       AD = channel_id(4B BE) | flags(1B) | payload_len(2B BE)。
 *                       AD 不传输，由双方从帧头各自重建。
 *                       关联数据认证防止跨通道重放 (R4-C2)。
 *
 * 解密时首先验证 HMAC (认证标签)，失败则拒绝帧；
 * HMAC 通过后才进行 SM4-CBC 解密和 PKCS7 去填充。
 * 这是 Encrypt-then-MAC 设计: 先验签后解密，可最早发现篡改并拒绝无效数据，
 * 避免对篡改密文进行无意义的解密运算。
 *
 * ═══════════════ 安全设计要点 ═══════════════
 *
 *   1. IV 随机性:
 *      每帧从 /dev/urandom 读取 16 字节独立 IV，杜绝固定 IV 或
 *      计数器 IV 的重放攻击。相同明文在不同帧中产生完全不同的密文。
 *   2. 密钥分离:
 *      SM4 加密/解密使用独立的内部轮密钥上下文 (g_enc_ctx / g_dec_ctx)。
 *      SM4 加密轮密钥与解密轮密钥不同，分别由 sm4_set_encrypt_key 和
 *      sm4_set_decrypt_key 独立设置，避免密钥调度上的混淆。
 *   3. HMAC 密钥派生:
 *      HMAC 密钥从 SM4 密钥派生 (HMAC-SM3("KCP-HMAC", key))，
 *      即固定标签 "KCP-HMAC" 作为 HMAC key，SM4 原始密钥作为 data。
 *      这确保即使 SM4 密钥暴露，HMAC 密钥也需单独破解，满足密钥分离原则。
 *      类似于 HKDF-extract 的简化版本。
 *   4. Encrypt-then-MAC (先加密后 MAC):
 *      HMAC 在解密前验证，防止 padding oracle 攻击和密文篡改攻击。
 *      无效帧在解密前被丢弃，节省 CPU 且消除侧信道泄漏路径。
 *      常量时间 HMAC 比较 (逐字节 XOR-OR 累加，无短路退出) 防止 timing leak。
 *   5. 关联数据认证 (R4-C2 AEAD):
 *      HMAC 输入扩展为 AD || IV || Ciphertext，其中
 *      AD = channel_id(4B BE) | flags(1B) | payload_len(2B BE)。
 *      防止攻击者将加密帧从一个通道重放到另一个通道。
 *      即使 SM4-CBC+HMAC 非标准 AEAD，手动关联数据绑定实现等效保护。
 *   6. 临时密钥擦除:
 *      crypto_init() 结束后 memset 清零 key_bin 栈内存，
 *      并插入编译器 barrier (__asm__ volatile) 防止优化掉擦除操作。
 *      crypto_cleanup() 同样擦除所有密钥上下文。
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include "types.h"

/* ═══════════════════════════════════════════
 * 生命周期管理
 * ═══════════════════════════════════════════ */

/**
 * @brief 初始化加密模块 (crypto_init)
 *
 * 生命周期: 程序启动时调用一次，在创建任何通道之前完成。
 *
 * 初始化流程:
 *   1. 检查 cfg->enabled，若为 false 则直接返回 0 (无需初始化)
 *   2. hex 密钥解析: 将 32 字符 hex 字符串逐两字节解析为 16 字节 binary key
 *      (sscanf("%2x") 循环)，并校验恰好 32 字符 (第 33 字符必须为 '\0')
 *   3. SM4 密钥调度: 分别调用 sm4_set_encrypt_key / sm4_set_decrypt_key
 *      填充全局加解密上下文，两者轮密钥不同必须分别设置
 *   4. HMAC 密钥派生: 以固定 8 字节标签 "KCP-HMAC" 为 HMAC key，
 *      对 SM4 原始密钥做 HMAC-SM3 运算，输出 32 字节 HMAC 工作密钥存入 g_hmac_key
 *   5. /dev/urandom 预打开: open() 获取文件描述符 g_urandom_fd，
 *      后续每帧加密可复用此 fd 读取 IV，避免频繁 open/close 开销
 *   6. 密钥擦除: memset 清零栈上的 key_bin，__asm__ barrier 防止编译器优化
 *
 * @param cfg  加密配置指针 (enabled + sm4_key hex 字符串)
 * @return     0=成功 (或加密未启用), -1=hex 解析错误/密钥长度错误/urandom 不可用
 */
int  crypto_init(const encryption_config_t *cfg);

/** @brief 清理加密模块
 *
 * 清零 SM4 加密/解密上下文和 HMAC 密钥 (memset 擦除敏感数据)，
 * 将 crypto_enabled 标志重置为 0。
 */
void crypto_cleanup(void);

/** @brief 查询加密是否已启用
 *
 * @return  1=已启用, 0=未启用 (明文模式)
 */
int  crypto_is_enabled(void);

/* ═══════════════════════════════════════════
 * 帧级加解密 API
 * ═══════════════════════════════════════════ */

/** @brief 帧级加密: 明文 → [IV | SM4-CBC密文 | SM3-HMAC]
 *
 * 加密流程 (crypto_encrypt_frame):
 *   1. 若加密未启用，直接 memcpy 明文到输出 (明文透传模式)
 *   2. 容量估算: 最坏情况下总长度 = IV(16) + (明文+16) + HMAC(32)
 *      即明文 + CRYPTO_OVERHEAD 字节，超出 out_cap 则返回 -1
 *   3. 从 /dev/urandom (预打开的 g_urandom_fd) 读取 16 字节随机 IV，
 *      最多重试 3 次以应对 EINTR 等异常
 *   4. 将 IV 写入输出缓冲区头部 [0..15]
 *   5. PKCS7 填充明文到 16 字节对齐 → SM4-CBC 加密 (使用 g_enc_ctx)
 *      密文紧接 IV 之后写入 [16..]
 *   6. SM3-HMAC 计算，覆盖 [AD(7) | IV | 密文] 全部数据，追加到帧末尾
 *      AD = channel_id(4B 网络序) | flags(1B) | payload_len(2B 网络序)
 *      将关联数据纳入 HMAC 可防止跨通道重放攻击 (R4-C2)。
 *   7. 返回完整帧总长度: IV(16) + 密文(N) + HMAC(32)
 *
 * 每帧使用独立随机 IV，即使相同明文重复发送也产生不同的密文。
 * IV 以明文传输是安全的: CBC 模式下 IV 只需不可预测，不需保密。
 *
 * @param in       明文数据指针
 * @param in_len   明文长度 (0~KCP_MTU_CONSERVATIVE, 约 1400 字节)
 * @param out      [out] 加密后缓冲区 (至少 IV+HDR+max_ct+HMAC 字节)
 * @param out_cap  out 缓冲区容量 (bytes)
 * @param channel_id  通道标识符 (网络序)，纳入 HMAC 关联数据
 * @param flags       帧标志位，纳入 HMAC 关联数据
 * @param payload_len 加密后线格式负载长度 (网络序，=IV+CT+HMAC)，纳入 HMAC
 * @return         >0=加密后总长度, -1=buffer 不足/IV 读取失败/加密错误
 */
int  crypto_encrypt_frame(const uint8_t *in, int in_len,
                          uint8_t *out, int out_cap,
                          uint32_t channel_id, uint8_t flags,
                          uint16_t payload_len);

/** @brief 帧级解密: [IV | SM4-CBC密文 | SM3-HMAC] → 明文
 *
 * 解密流程 (crypto_decrypt_frame, Encrypt-then-MAC 顺序):
 *   1. 若加密未启用，直接 memcpy 到输出 (明文透传模式)
 *   2. 边界检查: in_len ≥ IV(16)+HMAC(32)=48, ct_len > 0 且 16 对齐
 *      ct_len = in_len - IV - HMAC，必须为 SM4 块大小 16 的整数倍
 *   3. 【先验 MAC】提取 IV (前 16 字节)，计算期望 HMAC over
 *      [AD(channel_id+flags+payload_len) | IV | 密文]
 *      与帧末尾的 HMAC 进行常量时间比较 (逐字节 XOR-OR，无短路退出)
 *      → HMAC 不匹配则立即返回 -1，不执行解密
 *   4. 【后解密】SM4-CBC 解密 (使用 g_dec_ctx) → PKCS7 去填充 + 格式校验:
 *      pad 值 ∈ [1,16]; 末尾 pad 字节全部等于 pad 值
 *      → 去填充失败返回 -1
 *   5. ct_len > out_cap 检查 (审计修复 R7: 防止解密后缓冲区溢出)
 *   6. 返回解密后明文长度 (≤ ct_len)
 *
 * Encrypt-then-MAC 的安全性:
 *   - 攻击者无法通过修改密文观察解密结果 (padding oracle 防御)
 *   - HMAC 不匹配的帧在解密前被丢弃，节省 CPU 消除侧信道
 *   - 常量时间 MAC 比较防止 timing leak (审计修复 S2)
 *   - 关联数据 (channel_id/flags/payload_len) 纳入 HMAC，防止跨通道重放 (R4-C2)
 *
 * @param in           加密帧数据 (完整线格式)
 * @param in_len       加密帧总长度
 * @param out          [out] 解密后明文缓冲区
 * @param out_cap      out 缓冲区容量
 * @param channel_id   通道标识符 (网络序)，来自帧头，纳入 HMAC AD
 * @param flags        帧标志位，来自帧头，纳入 HMAC AD
 * @param payload_len  负载长度 (网络序，来自帧头)，纳入 HMAC AD
 * @return             >0=明文字节数, -1=HMAC/格式/缓冲区错误
 */
int  crypto_decrypt_frame(const uint8_t *in, int in_len,
                          uint8_t *out, int out_cap,
                          uint32_t channel_id, uint8_t flags,
                          uint16_t payload_len);

/** @brief 计算 SM3-HMAC 认证标签（用于管理消息认证）
 *
 * @param data      待认证数据
 * @param data_len  数据长度
 * @param mac_out   [out] 32 字节 HMAC 输出
 * @return          0=成功, -1=加密模块未初始化
 */
int  crypto_hmac_sign(const uint8_t *data, int data_len, uint8_t mac_out[32]);

#endif /* CRYPTO_H */
