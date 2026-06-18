#ifndef ACL_H
#define ACL_H

#include <stdint.h>
#include <sys/socket.h>
#include "types.h"

/* acl_check: 检查客户端 IP/端口是否通过 ACL
 * @param acl         通道 ACL 配置（不可为 NULL）
 * @param client_ip   客户端 IP，网络字节序
 * @param client_port 客户端端口，主机字节序
 * @return 1=允许通过, 0=拒绝
 */
int acl_check(const channel_acl_t *acl,
              uint32_t client_ip, uint16_t client_port);

/* extract_ip_port: 从 sockaddr_storage 中提取 IP 和端口
 * 支持 AF_INET 和 IPv4-mapped AF_INET6。
 * @param ss       sockaddr_storage 指针
 * @param ip_out   输出: 网络字节序 IP
 * @param port_out 输出: 主机字节序端口
 * @return 1=成功, 0=不支持/失败
 */
int extract_ip_port(const struct sockaddr_storage *ss,
                    uint32_t *ip_out, uint16_t *port_out);

#endif /* ACL_H */
