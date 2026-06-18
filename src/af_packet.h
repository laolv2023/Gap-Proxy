/*
 * af_packet.h - AF_PACKET 原始套接字模块
 *
 * 负责在数据链路层直接收发以太网帧，绕过 TCP/IP 协议栈。
 * 支持 BPF 过滤器、MAC 地址发现和 NIC MTU 管理。
 */

#ifndef AF_PACKET_H
#define AF_PACKET_H

#include "types.h"
#include <net/if.h>

/* ============================================================================
 * 函数声明
 * ============================================================================ */

/*
 * 配置 AF_PACKET 性能参数
 * @param sndbuf        SO_SNDBUF，<=0 使用默认值
 * @param rcvbuf        SO_RCVBUF，<=0 使用默认值
 * @param retry_max     EAGAIN/EWOULDBLOCK/ENOBUFS 最大重试次数，<0 使用默认值
 * @param retry_wait_ms 每次重试 poll 等待毫秒数，<0 使用默认值
 */
void af_packet_configure(int sndbuf, int rcvbuf,
                         int retry_max, int retry_wait_ms);

/*
 * 创建 AF_PACKET 原始套接字
 * @param if_name   网卡接口名称（如 "eth0"）
 * @param ethertype 自定义 EtherType（网络字节序）
 * @param ifindex   输出：网卡接口索引
 * @return          成功返回套接字 fd，失败返回 -1
 */
int af_packet_create(const char *if_name, uint16_t ethertype, int *ifindex);

/*
 * 设置 BPF 过滤器，仅接收指定 EtherType 的帧
 * @param sock      AF_PACKET 套接字
 * @param ethertype 过滤的 EtherType（网络字节序）
 * @return          成功返回 0，失败返回 -1
 */
int af_packet_set_bpf(int sock, uint16_t ethertype);

/*
 * 发送以太网帧
 * @param sock    AF_PACKET 套接字
 * @param ifindex 网卡接口索引
 * @param dst_mac 目标 MAC 地址（6 字节）
 * @param src_mac 源 MAC 地址（6 字节）
 * @param ethertype EtherType（网络字节序）
 * @param payload 负载数据
 * @param payload_len 负载长度
 * @return        成功返回发送字节数（含以太网头），失败返回 -1
 */
ssize_t af_packet_send(int sock, int ifindex,
                       const uint8_t dst_mac[ETH_MAC_ADDR_LEN],
                       const uint8_t src_mac[ETH_MAC_ADDR_LEN],
                       uint16_t ethertype,
                       const uint8_t *payload, size_t payload_len);

/*
 * 接收以太网帧（阻塞或非阻塞取决于套接字设置）
 * @param sock       AF_PACKET 套接字
 * @param buf        接收缓冲区
 * @param buf_size   缓冲区大小
 * @param src_mac    输出：源 MAC 地址
 * @param dst_mac    输出：目标 MAC 地址
 * @param ethertype  输出：EtherType
 * @return           成功返回负载长度，失败返回 -1
 */
ssize_t af_packet_recv(int sock, uint8_t *buf, size_t buf_size,
                       uint8_t src_mac[ETH_MAC_ADDR_LEN],
                       uint8_t dst_mac[ETH_MAC_ADDR_LEN],
                       uint16_t *ethertype);

/*
 * 获取网卡 MAC 地址
 * @param sock    AF_PACKET 套接字
 * @param if_name 网卡接口名称
 * @param mac     输出：MAC 地址（6 字节）
 * @return        成功返回 0，失败返回 -1
 */
int af_packet_get_mac(int sock, const char *if_name, uint8_t mac[ETH_MAC_ADDR_LEN]);

/*
 * 获取网卡接口索引
 * @param sock    AF_PACKET 套接字（可传 -1，使用 ioctl 时可为任意套接字）
 * @param if_name 网卡接口名称
 * @return        成功返回接口索引，失败返回 -1
 */
int af_packet_get_ifindex(int sock, const char *if_name);

/*
 * 设置网卡 MTU
 * @param sock    AF_PACKET 套接字
 * @param if_name 网卡接口名称
 * @param mtu     目标 MTU
 * @return        成功返回 0，失败返回 -1
 */
int af_packet_set_mtu(int sock, const char *if_name, int mtu);

/*
 * 获取网卡 MTU
 * @param sock    AF_PACKET 套接字
 * @param if_name 网卡接口名称
 * @return        成功返回 MTU 值，失败返回 -1
 */
int af_packet_get_mtu(int sock, const char *if_name);

/*
 * 检测 AF_PACKET 冲突（检查 /proc/net/packet 中是否有相同 EtherType）
 * @param if_name   网卡接口名称
 * @param ethertype EtherType
 * @return          0 表示无冲突，1 表示有冲突，-1 表示检测失败
 */
int af_packet_detect_conflict(const char *if_name, uint16_t ethertype);

/*
 * 关闭 AF_PACKET 套接字
 * @param sock 要关闭的套接字
 */
void af_packet_close(int sock);

#endif /* AF_PACKET_H */
