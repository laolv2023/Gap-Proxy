#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "acl.h"

/* ── IP 匹配（所有值均为网络字节序）── */

static int acl_ip_match(uint32_t client_ip, const acl_ip_entry_t *entry)
{
    switch (entry->type) {
    case ACL_IP_SINGLE:
        return (client_ip == entry->addr);

    case ACL_IP_CIDR:
        return ((client_ip & entry->mask_or_end) ==
                (entry->addr & entry->mask_or_end));

    case ACL_IP_RANGE:
        /* 网络字节序（大端）: 直接 uint32 比较与 IP 前缀序等价 */
        return (client_ip >= entry->addr &&
                client_ip <= entry->mask_or_end);

    default:
        return 0;
    }
}

/* ── 端口匹配 ── */

static int acl_port_match(uint16_t client_port, const acl_port_entry_t *entry)
{
    switch (entry->type) {
    case ACL_PORT_SINGLE:
        return (client_port == entry->port_start);
    case ACL_PORT_RANGE:
        /* M6: port_end 是包含上界（闭区间 [port_start, port_end]），
         * 因此使用 <= 比较。配置解析时保证 port_start <= port_end。 */
        return (client_port >= entry->port_start &&
                client_port <= entry->port_end);
    default:
        return 0;
    }
}

/* ── 总匹配 ── */

int acl_check(const channel_acl_t *acl,
              uint32_t client_ip, uint16_t client_port)
{
    if (!acl || !acl->enabled) return 1;

    /* M13: ACL 启用但规则为空 → 默认拒绝，防止未授权访问 */
    if (acl->ip_count == 0 && acl->port_count == 0) {
        LOG_WARN("ACL enabled but no rules defined: default-deny (all connections rejected)");
        return 0;
    }

    /* IP 白名单（OR 逻辑）：ip_count == 0 → 跳过 */
    if (acl->ip_count > 0) {
        int ok = 0;
        for (int i = 0; i < acl->ip_count; i++) {
            if (acl_ip_match(client_ip, &acl->ips[i])) {
                ok = 1;
                break;
            }
        }
        if (!ok) return 0;
    }

    /* 端口白名单（OR 逻辑）：port_count == 0 → 跳过 */
    if (acl->port_count > 0) {
        int ok = 0;
        for (int i = 0; i < acl->port_count; i++) {
            if (acl_port_match(client_port, &acl->ports[i])) {
                ok = 1;
                break;
            }
        }
        if (!ok) return 0;
    }

    return 1;
}

/* ── 地址提取 ── */

int extract_ip_port(const struct sockaddr_storage *ss,
                    uint32_t *ip_out, uint16_t *port_out)
{
    if (!ss || !ip_out || !port_out) return 0;

    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)ss;
        *ip_out   = in->sin_addr.s_addr;         /* 网络字节序 */
        *port_out = ntohs(in->sin_port);
        return 1;
    }

    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss;

        /* IPv4-mapped IPv6: ::ffff:a.b.c.d */
        static const uint8_t v4mapped[12] = {
            0,0,0,0,0,0,0,0,0,0,0xFF,0xFF
        };
        if (memcmp(in6->sin6_addr.s6_addr, v4mapped, 12) == 0) {
            memcpy(ip_out, in6->sin6_addr.s6_addr + 12, 4);
        } else {
            /* 纯 IPv6: 对只含 IPv4 规则的 ACL 返回不匹配 */
            LOG_DEBUG("ACL: pure IPv6 address rejected (IPv4-only rules)");
            return 0;
        }
        *port_out = ntohs(in6->sin6_port);
        return 1;
    }

    return 0;
}
