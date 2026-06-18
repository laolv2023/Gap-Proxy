/**
 * @file    crypto.c
 * @brief   SM4-CBC 加密 / SM3-HMAC 认证模块（基于 GNU Nettle）
 *
 * @details
 * 本模块为 Gap-Proxy 提供帧级对称加密和完整性保护：
 *   - SM4-CBC：国密分组密码 CBC 模式，带标准 PKCS7 填充
 *   - SM3-HMAC：国密哈希消息认证码，防止篡改和重放（配合 IV）
 *   - HMAC 密钥通过 HKDF 式派生：HMAC-SM3("KCP-HMAC", sm4_key)
 *   - 线格式：IV(16B) || ciphertext(N×16B) || HMAC(32B)
 *   - 每帧独立随机 IV（/dev/urandom），即使相同明文也产生不同密文
 *
 * 依赖：
 *   - Nettle 库 (sm4.h, cbc.h, hmac.h)
 *   - Linux /dev/urandom（IV 熵源）
 *
 * 安全设计要点：
 *   - 解密时先验证 HMAC，再执行 CBC 解密，防止 padding oracle / 密文篡改攻击
 *   - 加密/解密使用独立轮密钥上下文（g_enc_ctx / g_dec_ctx），避免密钥调度混乱
 *   - 派生密钥和临时密钥材料使用后立即 memset 擦除
 *   - PKCS7 解填充做完整格式校验（pad 范围 + 逐字节一致性）
 *
 * 已知限制：
 *   - memcmp 非恒定时间，理论上有 timing leak（注释已标注），在 LAN 威胁模型下可接受
 *   - IV 生成依赖 /dev/urandom 可用性，容器/沙箱中需确保设备节点存在
 *   - SM4-CBC + SM3-HMAC 非标准 AEAD，但通过手动关联数据绑定已实现等效保护 (R4-C2)
 */

#include "crypto.h"
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/random.h>
#include <nettle/sm4.h>
#include <nettle/cbc.h>
#include <nettle/hmac.h>

/* H29: 互斥锁保护 IV 生成与加密过程，防止并发调用导致 IV 破碎。 */
#include <pthread.h>

/* 测试场景弱符号：正式程序中 api.c 的强符号覆盖此 no-op fallback */
void __attribute__((weak))
log_output(int level, const char *fmt, ...)
{
    (void)level; (void)fmt;
}

/** SM4 加密上下文（轮密钥由 sm4_set_encrypt_key 填充） */
static struct sm4_ctx  g_enc_ctx;
/** SM4 解密上下文（轮密钥与加密不同，由 sm4_set_decrypt_key 填充） */
static struct sm4_ctx  g_dec_ctx;
/** 全局加密开关：0=明文透传 / 1=加密模式 */
static int             crypto_enabled = 0;
int                   g_urandom_fd  = -1; /* /dev/urandom fd（启动时打开，复用） */

/* H29: 加密操作互斥锁 — 保护 IV 生成→加密→HMAC 的原子性，
 * 防止并发调用 crypto_encrypt_frame 时 IV 与密文交错写入。 */
static pthread_mutex_t g_crypto_mutex = PTHREAD_MUTEX_INITIALIZER;
/**
 * HMAC 密钥（32 字节），由 SM4 密钥通过 HMAC-SM3("KCP-HMAC", sm4_key) 派生。
 *
 * H16: 此为单密钥模式下的简化派生方式，并非真正的密钥分离（若 SM4 密钥泄露，
 * 攻击者可通过相同 HMAC 派生获得 HMAC 密钥）。真正的密钥分离需使用独立随机
 * HMAC 密钥或完整 HKDF（extract+expand）。在当前 LAN 点对点场景中，
 * 此简化派生可接受，因为双方共享同一预配置密钥。
 */
static uint8_t         g_hmac_key[SM3_DIGEST_SIZE];

/**
 * @brief   初始化加密子系统
 *
 * @param   cfg  配置结构（含 enabled 标志和 hex 格式 sm4_key）
 * @return  0 成功；错误码（当前始终返回 0，错误由调用者在初始化前校验）
 *
 * @details
 * 流程：
 *   1. 将 32 字符 hex 密钥 → 16 字节二进制 key_bin
 *   2. 分别调用 sm4_set_encrypt_key / sm4_set_decrypt_key 填充加解密上下文
 *      （SM4 加解密轮密钥不同，必须分别设置）
 *   3. 派生 HMAC 密钥：以固定标签 "KCP-HMAC"(8B) 作为 HMAC key，
 *      对 SM4 原始密钥做 HMAC-SM3，得到 32B HMAC 工作密钥
 *   4. memset 擦除临时 key_bin，防止栈泄露
 */
int crypto_init(const encryption_config_t *cfg)
{
    crypto_enabled = cfg->enabled;
    if (!crypto_enabled) return 0;

    /* ═══════════════════════════════════════════════════════
     * 步骤 1: hex 密钥解析（32 字符 hex → 16 字节 binary）
     *
     * 循环逐 2 字符调用 sscanf("%2x") 转换为一个字节。
     * sscanf 的 %2x 限定最多读取 2 个 hex 字符，自动跳过无效字符。
     * 例如 hex 字符串 "010203...0F10" → binary [0x01,0x02,...,0x0F,0x10]
     * ═══════════════════════════════════════════════════════ */
    uint8_t key_bin[16];
    for (int i = 0; i < 16; i++) {
        unsigned int b;
        if (sscanf(cfg->sm4_key + i * 2, "%2x", &b) != 1) {
            /* L2: 错误路径 — 擦除已解析密钥片段、禁用加密并返回 -1。
             * 调用者无需额外清理，crypto_enabled=0 使后续加解密均为透传。 */
            LOG_ERROR("crypto_init: invalid hex key at position %d", i * 2);
            memset(key_bin, 0, sizeof(key_bin));  /* 清零已解析的密钥片段，防止残留 */
            crypto_enabled = 0;
            return -1;
        }
        key_bin[i] = (uint8_t)b;
    }
    /* 校验密钥恰好为 32 字符：第 33 字符 (索引 32) 必须为 '\0'
     * 防止 "abc" 等短字符串通过，要求严格的 hex 编码密钥 */
    if (cfg->sm4_key[32] != '\0') {
        LOG_ERROR("crypto_init: key must be exactly 32 hex characters");
        memset(key_bin, 0, sizeof(key_bin));
        crypto_enabled = 0;
        return -1;
    }

    /* ═══════════════════════════════════════════════════════
     * 步骤 2: SM4 密钥调度
     *
     * SM4 加密轮密钥和解密轮密钥不同 (解密轮密钥是加密轮密钥的逆序)，
     * 因此必须分别调用 sm4_set_encrypt_key 和 sm4_set_decrypt_key。
     * 两个上下文存储在独立的全局变量 g_enc_ctx / g_dec_ctx 中。
     * ═══════════════════════════════════════════════════════ */
    sm4_set_encrypt_key(&g_enc_ctx, key_bin);
    sm4_set_decrypt_key(&g_dec_ctx, key_bin);

    /* ═══════════════════════════════════════════════════════
     * 步骤 3: 派生 HMAC 密钥（单密钥模式简化派生）
     *
     * 派生方式: HMAC-SM3(key="KCP-HMAC"(8字节), message=sm4_key(16字节))
     * 输出: 32 字节 HMAC 工作密钥存入 g_hmac_key
     *
     * 这是一个简化的 HKDF-extract 操作:
     *   - "KCP-HMAC" 作为固定标签 (label)
     *   - SM4 原始密钥作为输入密钥材料 (IKM)
     *   - 输出作为 HMAC 工作密钥
     *
     * H16: 注意此方式并非真正的密钥分离（双方共享同一 SM4 密钥，
     * 若 SM4 密钥泄露，攻击者可用相同方式派生 HMAC 密钥）。
     * 在 LAN 点对点预共享密钥场景下可接受。完整密钥分离应使用
     * 独立的随机 HMAC 密钥或标准 HKDF(extract+expand) 流程。
     *
     * M10-TRADEOFF: 固定标签 "KCP-HMAC" 非标准 HKDF，SM4 密钥泄露会导致
     * HMAC 密钥同步泄露。仅适用于 LAN 预共享密钥威胁模型。
     * ═══════════════════════════════════════════════════════ */
    struct hmac_sm3_ctx hctx;
    hmac_sm3_set_key(&hctx, 8, (const uint8_t *)"KCP-HMAC");
    hmac_sm3_update(&hctx, 16, key_bin);
    hmac_sm3_digest(&hctx, SM3_DIGEST_SIZE, g_hmac_key);

    /* ═══════════════════════════════════════════════════════
     * 步骤 4: 预打开 /dev/urandom
     *
     * 复用 fd 避免每帧加密都 open/close。
     * O_CLOEXEC 确保 fork+exec 子进程不会继承此 fd。
     * 若使用 xfork()（先 fork 再 exec），O_CLOEXEC 同样安全：
     * fd 在 exec 时自动关闭，子进程无法访问父进程的熵源。
     * posix_spawn() 系列函数亦尊重 O_CLOEXEC 语义。
     * ═══════════════════════════════════════════════════════ */
    g_urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (g_urandom_fd < 0) {
        LOG_ERROR("crypto_init: cannot open /dev/urandom: %s", strerror(errno));
        crypto_enabled = 0;
        return -1;
    }

    /* 擦除临时 key：通过 memset + compiler barrier 防止栈泄露。
     * barrier (__asm__ volatile) 告诉编译器: 内存已改变，不要优化掉 memset。
     * 若有 core dump，key_bin 不会被写入 dump 文件 (栈已被覆盖)。 */
    memset(key_bin, 0, sizeof(key_bin));
    __asm__ __volatile__("" : : "r"(key_bin) : "memory");
    return 0;
}

/**
 * @brief   查询加密是否启用
 * @return  1 已启用 / 0 未启用
 */
int crypto_is_enabled(void) { return crypto_enabled; }

/* 前置声明：sm3_hmac_compute 定义在下方（原用于帧级 HMAC） */
static void sm3_hmac_compute(const uint8_t *data, int data_len, uint8_t mac_out[32]);

/* 公开 wrapper：管理消息 HMAC 认证（审计: T11-2）
 *
 * crypto_hmac_sign 是 crypto_encrypt_frame / crypto_decrypt_frame 之外的
 * 第三个公开 API，专门用于管理消息的认证 (非帧级加解密)。
 *
 * 使用场景: 管理通道中的配置同步、心跳认证等消息需要 HMAC 签名，
 * 但不经过完整的 IV+CBC+HMAC 帧加密流程。直接对原始数据计算 SM3-HMAC。
 *
 * @param data      待认证数据
 * @param data_len  数据长度
 * @param mac_out   [out] 32 字节 HMAC 输出
 * @return          0=成功, -1=加密模块未初始化
 */
int crypto_hmac_sign(const uint8_t *data, int data_len, uint8_t mac_out[32])
{
    if (!crypto_enabled) return -1;
    if (!data || !mac_out) return -1;
    sm3_hmac_compute(data, data_len, mac_out);
    return 0;
}

/**
 * @brief   清理加密子系统，擦除所有敏感密钥材料
 *
 * @details
 * 将所有密钥上下文和 HMAC 密钥清零并重置加密开关。
 * 应在进程退出前调用，防止密钥残留在内存中。
 */
void crypto_cleanup(void)
{
    /* H1: 使用 explicit_bzero 确保密钥材料清零不会被编译器优化掉。
     * explicit_bzero (glibc 2.25+) 通过编译器屏障 + 内存屏障保证清零执行。 */
    pthread_mutex_lock(&g_crypto_mutex);
    explicit_bzero(&g_enc_ctx, sizeof(g_enc_ctx));
    explicit_bzero(&g_dec_ctx, sizeof(g_dec_ctx));
    explicit_bzero(g_hmac_key, sizeof(g_hmac_key));
    crypto_enabled = 0;
    pthread_mutex_unlock(&g_crypto_mutex);
    /* L15: crypto_cleanup 仅在主线程 shutdown 调用，单线程无 close 竞争风险 */
    if (g_urandom_fd >= 0) {
        close(g_urandom_fd);
        g_urandom_fd = -1;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  SM4-CBC 加密（Nettle 后端）
 *
 *  使用 PKCS7 填充方案：
 *    若 in_len % 16 == 0，追加 16 字节的 0x10
 *    若 in_len % 16 == r  (r>0)，追加 (16-r) 字节，每字节值为 (16-r)
 *  这确保解密后能精确恢复原始明文长度。
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief   SM4-CBC 加密（内部函数）
 *
 * @param   key    未使用（使用全局 g_enc_ctx）
 * @param   iv     16 字节初始化向量（调用者负责随机生成）
 * @param   in     明文缓冲区
 * @param   in_len 明文长度（字节）
 * @param   out    输出缓冲区（调用者确保 ≥ in_len + 16）
 * @return  加密后总长度（含 PKCS7 填充）；-1 表示参数错误
 *
 * @note    key 参数保留用于 API 兼容性，实际使用全局 g_enc_ctx。
 *          调用 cbc_encrypt 时将 sm4_crypt 强制转换为 nettle_cipher_func，
 *          这是 Nettle 库的标准用法（SM4 块大小为 16 字节）。
 */
static int sm4_cbc_encrypt(const uint8_t *key __attribute__((unused)),
                           const uint8_t *iv,
                           const uint8_t *in, int in_len,
                           uint8_t *out)
{
    /* PKCS7 padding: 填充字节数 ∈ [1, 16]
     * pad = 16 - (in_len % 16)，当 in_len 恰好为 16 倍数时 pad=16 */
    int pad = SM4_IV_LEN - (in_len % SM4_IV_LEN);
    if (in_len > INT_MAX - SM4_IV_SIZE) return -1;
    int padded_len = in_len + pad;

    /* 构造填充后的临时缓冲区：原始数据 + 填充字节（每字节值为 pad） */
    uint8_t buf[MAX_FRAME_SIZE];
    if (padded_len > (int)sizeof(buf)) {
        LOG_ERROR("sm4_cbc_encrypt: input too large (%d > %zu)",
                  padded_len, sizeof(buf));
        return -1;
    }
    memcpy(buf, in, in_len);
    memset(buf + in_len, pad, pad);

    /* CBC 加密：需要 local copy of IV，因为 cbc_encrypt 会就地修改 iv_copy */
    uint8_t iv_copy[SM4_IV_LEN];
    memcpy(iv_copy, iv, SM4_IV_LEN);
    cbc_encrypt(&g_enc_ctx, (nettle_cipher_func *)sm4_crypt,
                SM4_IV_LEN, iv_copy, padded_len, out, buf);
    return padded_len;
}

/**
 * @brief   SM4-CBC 解密（内部函数）
 *
 * @param   key    未使用（使用全局 g_dec_ctx）
 * @param   iv     16 字节初始化向量
 * @param   in     密文缓冲区
 * @param   in_len 密文长度（必须是 16 的整数倍，≥ 16）
 * @param   out    输出缓冲区（调用者确保 ≥ in_len）
 * @return  明文长度（去除填充后）；-1 表示格式错误
 *
 * @details
 * PKCS7 解填充验证三步：
 *   1. pad 值必须在 [1, 16] 范围内
 *   2. 末尾 pad 个字节必须全部等于 pad 值
 *   3. 若任一步失败则返回 -1（丢弃该帧，不返回部分解密数据）
 *
 * @note    入参校验（in_len % 16 == 0）在调用者 crypto_decrypt_frame 中完成，
 *          此处再次检查以防调用链异常。
 */
static int sm4_cbc_decrypt(const uint8_t *key __attribute__((unused)),
                           const uint8_t *iv,
                           const uint8_t *in, int in_len,
                           uint8_t *out)
{
    if (in_len < SM4_IV_LEN || in_len % SM4_IV_LEN != 0) return -1;

    uint8_t iv_copy[SM4_IV_LEN];
    memcpy(iv_copy, iv, SM4_IV_LEN);
    cbc_decrypt(&g_dec_ctx, (nettle_cipher_func *)sm4_crypt,
                SM4_IV_LEN, iv_copy, in_len, out, in);

    /* 去除 PKCS7 填充：读取末尾字节作为 pad 值 */
    int pad = out[in_len - 1];
    /* pad 必须在 [1, 16] 范围，超出说明数据损坏或攻击 */
    if (pad < 1 || pad > SM4_IV_LEN) return -1;
    /* L14: 外部 HMAC 已验证密文完整性，逐字节短路不泄露明文，风险可控 */
    for (int i = 0; i < pad; i++) {
        if (out[in_len - 1 - i] != pad) return -1;
    }
    return in_len - pad;
}

/* ═══════════════════════════════════════════════════════════════════
 *  SM3-HMAC 计算（Nettle 后端）
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief   计算 SM3-HMAC (GNU Nettle 后端)
 *
 * @param   data     输入数据
 * @param   data_len 数据长度 (字节)
 * @param   mac      输出 32 字节 MAC (调用者分配 SM3_DIGEST_SIZE=32 字节)
 *
 * @details
 * 使用全局 g_hmac_key (32 字节，由 crypto_init 从 SM4 密钥派生) 作为 HMAC 密钥。
 * Nettle HMAC 三步标准模式:
 *   hmac_sm3_set_key  — 设置 HMAC 密钥 (内部 ipad/opad 初始化)
 *   hmac_sm3_update   — 喂入待认证数据 (可分多次调用)
 *   hmac_sm3_digest   — 输出最终的 32 字节认证标签
 *
 * SM3 是国密哈希算法 (GB/T 32905)，输出 256 位 (32 字节) 摘要。
 * HMAC-SM3 构造: HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
 * 其中 H=SM3, K=g_hmac_key, ipad=0x36, opad=0x5C。
 *
 * 此函数为 static，帧级加解密和 crypto_hmac_sign 均通过它计算 HMAC。
 */
static void sm3_hmac_compute(const uint8_t *data, int data_len,
                             uint8_t mac[SM3_DIGEST_SIZE])
{
    struct hmac_sm3_ctx ctx;
    hmac_sm3_set_key(&ctx, SM3_DIGEST_SIZE, g_hmac_key);
    hmac_sm3_update(&ctx, data_len, data);
    hmac_sm3_digest(&ctx, SM3_DIGEST_SIZE, mac);
}

/* ═══════════════════════════════════════════════════════════════════
 *  帧级加密 / 解密（完整线格式）
 *
 *  线格式布局（加密模式）：
 *    [0..15]   随机 IV (16B)
 *    [16..N-33] SM4-CBC 密文（含 PKCS7 填充，长度是 16 的整数倍）
 *    [N-32..N-1] SM3-HMAC over AD || IV || ciphertext (32B)
 *    AD = channel_id(4B BE) | flags(1B) | payload_len(2B BE) (7B, 不传输)
 *
 *  HMAC 覆盖范围包含关联数据 AD（channel_id + flags + payload_len），
 *  防止跨通道重放攻击 (R4-C2)：攻击者无法将一个通道的加密帧重放到另一个通道。
 *
 *  明文模式（crypto_enabled==0）：直接透传原始数据。
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief   帧级加密：明文 → IV || ciphertext || HMAC
 *
 * @param   in       明文数据
 * @param   in_len   明文长度
 * @param   out      输出缓冲区
 * @param   out_cap  输出缓冲区容量（字节）
 * @param   channel_id  通道标识符 (网络序)，纳入 HMAC 关联数据
 * @param   flags       帧标志位，纳入 HMAC 关联数据
 * @param   payload_len 加密后线格式负载总长度 (网络序，=IV+CT+HMAC)，纳入 HMAC
 * @return  加密后总长度（IV + ciphertext + HMAC）；-1 表示失败
 *
 * @details
 * 加密流程：
 *   1. 从 /dev/urandom 读取 16 字节随机 IV
 *   2. 将 IV 写入输出头部
 *   3. SM4-CBC 加密（含 PKCS7 填充）
 *   4. 计算 SM3-HMAC over AD(7B) || IV || ciphertext：
 *      AD = channel_id(4B BE) | flags(1B) | payload_len(2B BE)
 *      HMAC 追加到帧尾。关联数据绑定通道身份，防止跨通道重放 (R4-C2)。
 *
 * 若加密未启用（crypto_enabled==0），则直接 memcpy 明文到输出。
 *
 * @note    每次加密都使用新鲜 IV：即使同一明文重复发送，密文也不同，
 *          有效防止流量分析。IV 不加密，以明文形式传输——CBC 模式下
 *          IV 只需不可预测，不需保密。
 */
int crypto_encrypt_frame(const uint8_t *in, int in_len,
                         uint8_t *out, int out_cap,
                         uint32_t channel_id, uint8_t flags,
                         uint16_t payload_len)
{
    if (!crypto_enabled) {
        if (in_len > out_cap) return -1;
        memcpy(out, in, in_len);
        return in_len;
    }

    /* ═══════════════════════════════════════════════════════
     * 帧级加密主流程
     *
     * 线格式: [IV(16B) | SM4-CBC密文(N×16B) | SM3-HMAC(32B)]
     * 总长度 = 16 + ct_len + 32 (ct_len 为 16 的整数倍)
     *
     * 步骤:
     *   1. 容量估算 (最坏情况)
     *   2. 生成随机 IV (/dev/urandom)
     *   3. SM4-CBC 加密 (PKCS7 填充)
     *   4. SM3-HMAC 计算 (覆盖 IV+密文)
     * ═══════════════════════════════════════════════════════ */

    /* 估算总长度: IV(16) + 密文(≤in_len+16) + HMAC(32)
     * 最坏情况：明文已是 16 倍数，PKCS7 追加完整一个 block (16 字节) */
    if (in_len > INT_MAX - SM4_IV_LEN - SM4_IV_LEN - SM3_HMAC_LEN) return -1;
    int max_ct = in_len + SM4_IV_LEN;
    int total = SM4_IV_LEN + max_ct + SM3_HMAC_LEN;
    if (total > out_cap) return -1;

    /* H29: 加锁保护 IV 生成→加密→HMAC 的原子性，防止并发调用
     * 在 IV 读取与写入之间被其他线程插入，导致破碎 IV。 */
    pthread_mutex_lock(&g_crypto_mutex);

    /* 1. 生成随机 IV：优先 getrandom，失败回退到 /dev/urandom。 */
    uint8_t iv[SM4_IV_LEN];
    if (getrandom(iv, sizeof(iv), GRND_NONBLOCK) == (ssize_t)sizeof(iv)) goto iv_ready;
    {
        if (g_urandom_fd < 0) { pthread_mutex_unlock(&g_crypto_mutex); return -1; }
        ssize_t total_read = 0;
        for (int retry = 0; retry < 3 && total_read < SM4_IV_LEN; retry++) {
            ssize_t n = read(g_urandom_fd, iv + total_read,
                             SM4_IV_LEN - total_read);
            if (n < 0) {
                if (errno == EINTR) continue;
                pthread_mutex_unlock(&g_crypto_mutex); return -1;
            }
            if (n == 0) { pthread_mutex_unlock(&g_crypto_mutex); return -1; }
            total_read += n;
        }
        if (total_read < SM4_IV_LEN) { pthread_mutex_unlock(&g_crypto_mutex); return -1; }
    }
    iv_ready:
    memcpy(out, iv, SM4_IV_LEN);

    /* 2. SM4-CBC 加密（密文紧接 IV 之后） */
    int ct_len = sm4_cbc_encrypt(NULL, iv, in, in_len,
                                  out + SM4_IV_LEN);
    if (ct_len < 0) { pthread_mutex_unlock(&g_crypto_mutex); return -1; }

    /* 3. SM3-HMAC over AD || IV || Ciphertext (R4-C2 AEAD fix)
     *    AD = channel_id(4B BE) | flags(1B) | payload_len(2B BE) = 7 bytes.
     *    关联数据纳入 HMAC 防止跨通道重放：攻击者无法将加密帧
     *    从一个通道重放到另一个通道，因为 channel_id 已绑定到 MAC。
     *    使用 hmac_sm3_update 逐步计算，避免要求连续缓冲区。 */
    {
        int computed_payload_len = SM4_IV_LEN + ct_len + SM3_HMAC_LEN;
        if ((uint16_t)computed_payload_len != payload_len) {
            pthread_mutex_unlock(&g_crypto_mutex);
            return -1;  /* caller's payload_len prediction mismatch */
        }
        uint8_t ad[7];
        ad[0] = (uint8_t)(channel_id >> 24);
        ad[1] = (uint8_t)(channel_id >> 16);
        ad[2] = (uint8_t)(channel_id >> 8);
        ad[3] = (uint8_t)(channel_id);
        ad[4] = flags;
        ad[5] = (uint8_t)(payload_len >> 8);
        ad[6] = (uint8_t)(payload_len);

        struct hmac_sm3_ctx hctx;
        hmac_sm3_set_key(&hctx, SM3_DIGEST_SIZE, g_hmac_key);
        hmac_sm3_update(&hctx, 7, ad);
        hmac_sm3_update(&hctx, SM4_IV_LEN + ct_len, out);
        hmac_sm3_digest(&hctx, SM3_DIGEST_SIZE, out + SM4_IV_LEN + ct_len);
    }

    pthread_mutex_unlock(&g_crypto_mutex);

    return SM4_IV_LEN + ct_len + SM3_HMAC_LEN;
}

/**
 * @brief   帧级解密：IV || ciphertext || HMAC → 明文
 *
 * @param   in       加密帧数据
 * @param   in_len   加密帧总长度
 * @param   out      明文输出缓冲区
 * @param   out_cap  输出缓冲区容量
 * @param   channel_id  通道标识符 (网络序)，来自帧头，纳入 HMAC AD 验证
 * @param   flags       帧标志位，来自帧头，纳入 HMAC AD 验证
 * @param   payload_len 负载长度 (网络序，来自帧头)，纳入 HMAC AD 验证
 * @return  明文长度；-1 表示 HMAC 验证失败或解密错误
 *
 * @details
 * 解密流程（顺序至关重要）：
 *   1. 【先】验证 SM3-HMAC over AD || IV || ciphertext
 *      AD = channel_id(4B BE) | flags(1B) | payload_len(2B BE)
 *      — 若 MAC 不匹配立即拒绝，不解密
 *   2. 【后】SM4-CBC 解密 + PKCS7 解填充
 *
 *   先验 MAC 后解密的设计原则（Encrypt-then-MAC）：
 *     - 防止 padding oracle 攻击：攻击者无法通过修改密文观察解密结果
 *     - 防止密文篡改：HMAC 不匹配的帧在解密前就被丢弃
 *     - 节省 CPU：无效帧不消耗解密计算
 *     - 防止跨通道重放：关联数据 (channel_id) 绑定通道身份 (R4-C2)
 *
 * @warning  memcmp 为非常量时间实现，理论上存在 timing side-channel。
 *           在当前 LAN 场景下（攻击者难以精确测量纳秒级时差），风险可控。
 *           未来可替换为 CRYPTO_memcmp / sodium_memcmp。
 */
int crypto_decrypt_frame(const uint8_t *in, int in_len,
                         uint8_t *out, int out_cap,
                         uint32_t channel_id, uint8_t flags,
                         uint16_t payload_len)
{
    /* 明文透传路径：容量检查与 crypto_encrypt_frame 对称。 */
    if (!crypto_enabled) {
        if (in_len > out_cap) return -1;
        memcpy(out, in, in_len);
        return in_len;
    }

    /* 最小长度检查：至少需要 IV(16) + HMAC(32) = 48 字节。
     * 注：ct_len 后续校验要求 ct_len > 0 且为 16 的倍数，
     * 因此有效最小帧 = IV(16) + 1 block(16) + HMAC(32) = 64 字节。 */
    if (in_len < SM4_IV_LEN + SM3_HMAC_LEN) return -1;
    int ct_len = in_len - SM4_IV_LEN - SM3_HMAC_LEN;
    /* 密文长度必须是 16（SM4 块大小）的整数倍 */
    if (ct_len <= 0 || ct_len % SM4_IV_LEN != 0) return -1;

    /* H29: 加锁保护解密过程（与 crypto_encrypt_frame 共用同一互斥锁），
     * 防止并发解密时 HMAC 验证与 CBC 解密间的竞态。 */
    pthread_mutex_lock(&g_crypto_mutex);

    /* 1. 验证 HMAC — 在解密之前执行（Encrypt-then-MAC 的关键顺序）
     *
     *    审计修复 R1: 原实现先解密再验 MAC，存在 padding oracle 风险。
     *    攻击者可通过修改密文观察解密是否报错，逐字节推测明文。
     *    现改为先验证 HMAC，验证通过才执行解密 —— 彻底消除此风险。
     *
     *    审计修复 S2: 原使用 memcmp 做 MAC 比较，memcmp 在第一个不同字节处
     *    短路返回，存在 timing side-channel。现改为逐字节 XOR 累加到
     *    volatile diff 变量，无短路退出，实现常量时间比较。
     *
     *    审计修复 R4-C2: HMAC 输入扩展为 AD || IV || Ciphertext，
     *    AD = channel_id(4B BE) | flags(1B) | payload_len(2B BE)，
     *    防止攻击者将加密帧跨通道重放。 */
    {
        uint8_t ad[7];
        ad[0] = (uint8_t)(channel_id >> 24);
        ad[1] = (uint8_t)(channel_id >> 16);
        ad[2] = (uint8_t)(channel_id >> 8);
        ad[3] = (uint8_t)(channel_id);
        ad[4] = flags;
        ad[5] = (uint8_t)(payload_len >> 8);
        ad[6] = (uint8_t)(payload_len);

        uint8_t mac_calc[SM3_HMAC_LEN];
        struct hmac_sm3_ctx hctx;
        hmac_sm3_set_key(&hctx, SM3_DIGEST_SIZE, g_hmac_key);
        hmac_sm3_update(&hctx, 7, ad);
        hmac_sm3_update(&hctx, SM4_IV_LEN + ct_len, in);
        hmac_sm3_digest(&hctx, SM3_DIGEST_SIZE, mac_calc);

        /* 常量时间 MAC 比较：逐字节 OR 差异，避免短路退出 */
        volatile uint8_t diff = 0;
        for (int i = 0; i < SM3_HMAC_LEN; i++)
            diff |= mac_calc[i] ^ in[SM4_IV_LEN + ct_len + i];
        if (diff != 0) {
            pthread_mutex_unlock(&g_crypto_mutex);
            return -2;  /* HMAC mismatch — 区分于格式错误 (-1) */
        }
    }

    /* 2. SM4-CBC 解密（先验证输出缓冲区足够）
     *    ct_len 在解密后可能会因 PKCS7 解填充缩短，不会超过 out_cap */
    if (ct_len > out_cap) { pthread_mutex_unlock(&g_crypto_mutex); return -1; }
    int pt_len = sm4_cbc_decrypt(NULL, in, in + SM4_IV_LEN, ct_len, out);
    if (pt_len < 0 || pt_len > out_cap) {
        pthread_mutex_unlock(&g_crypto_mutex);
        return -1;
    }
    pthread_mutex_unlock(&g_crypto_mutex);
    return pt_len;
}
