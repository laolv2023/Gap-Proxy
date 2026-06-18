//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
//
// 【中文说明】
// KCP 协议头文件 — 定义 KCP 控制块结构体和所有公开 API。
// 本文件被 kcp_wrap.h 包含，通过 kcp_wrap_* 封装函数间接使用。
//
// 【核心类型】
//   ikcpcb    — KCP 控制块 (KCP Control Block)，管理连接状态
//   IKCPSEG   — KCP 数据段 (Segment)，内部传输基本单元
//   IQUEUEHEAD — 双向循环链表节点，用于队列管理
//
// 【KCP 段结构 (wire format)】
//   ┌────────┬─────┬─────┬─────┬──────┬──────┬──────┬──────┬──────────┐
//   │ conv(4)│cmd(1)│frg(1)│wnd(2)│ts(4) │sn(4) │una(4)│len(4)│data(len) │
//   └────────┴─────┴─────┴─────┴──────┴──────┴──────┴──────┴──────────┘
//   总共 24 字节协议头 (IKCP_OVERHEAD) + 负载数据
//   所有多字节字段使用小端序 (Little-Endian)
//
//=====================================================================
#ifndef _IKCP_H_
#define _IKCP_H_

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>


//=====================================================================
// 32位整数定义 (32-bit Integer Definition)
// 跨平台兼容: Windows / Linux / macOS / BSD
//=====================================================================
#ifndef __INTEGER_32_BITS__
#define __INTEGER_32_BITS__
#if defined(_WIN64) || defined(WIN64) || defined(__amd64__) || \
	defined(__x86_64) || defined(__x86_64__) || defined(_M_IA64) || \
	defined(_M_AMD64)
	typedef unsigned int ISTDUINT32;
	typedef int ISTDINT32;
#elif defined(_WIN32) || defined(WIN32) || defined(__i386__) || \
	defined(__i386) || defined(_M_X86)
	typedef unsigned long ISTDUINT32;
	typedef long ISTDINT32;
#elif defined(__MACOS__)
	typedef UInt32 ISTDUINT32;
	typedef SInt32 ISTDINT32;
#elif defined(__APPLE__) && defined(__MACH__)
	#include <sys/types.h>
	typedef u_int32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#elif defined(__BEOS__)
	#include <sys/inttypes.h>
	typedef u_int32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#elif (defined(_MSC_VER) || defined(__BORLANDC__)) && (!defined(__MSDOS__))
	typedef unsigned __int32 ISTDUINT32;
	typedef __int32 ISTDINT32;
#elif defined(__GNUC__)
	#include <stdint.h>
	typedef uint32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#else 
	typedef unsigned long ISTDUINT32; 
	typedef long ISTDINT32;
#endif
#endif


//=====================================================================
// 整数类型定义 (Integer Type Definitions)
//   IINT8/IUINT8:  8位  有符号/无符号整数
//   IINT16/IUINT16: 16位 有符号/无符号整数
//   IINT32/IUINT32: 32位 有符号/无符号整数
//   IINT64/IUINT64: 64位 有符号/无符号整数
//=====================================================================
#ifndef __IINT8_DEFINED
#define __IINT8_DEFINED
typedef char IINT8;
#endif

#ifndef __IUINT8_DEFINED
#define __IUINT8_DEFINED
typedef unsigned char IUINT8;
#endif

#ifndef __IUINT16_DEFINED
#define __IUINT16_DEFINED
typedef unsigned short IUINT16;
#endif

#ifndef __IINT16_DEFINED
#define __IINT16_DEFINED
typedef short IINT16;
#endif

#ifndef __IINT32_DEFINED
#define __IINT32_DEFINED
typedef ISTDINT32 IINT32;
#endif

#ifndef __IUINT32_DEFINED
#define __IUINT32_DEFINED
typedef ISTDUINT32 IUINT32;
#endif

#ifndef __IINT64_DEFINED
#define __IINT64_DEFINED
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef __int64 IINT64;
#else
typedef long long IINT64;
#endif
#endif

#ifndef __IUINT64_DEFINED
#define __IUINT64_DEFINED
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef unsigned __int64 IUINT64;
#else
typedef unsigned long long IUINT64;
#endif
#endif

#ifndef INLINE
#if defined(__GNUC__)

#if (__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1))
#define INLINE         __inline__ __attribute__((always_inline))
#else
#define INLINE         __inline__
#endif

#elif (defined(_MSC_VER) || defined(__BORLANDC__) || defined(__WATCOMC__))
#define INLINE __inline
#else
#define INLINE 
#endif
#endif

#if (!defined(__cplusplus)) && (!defined(inline))
#define inline INLINE
#endif


//=====================================================================
// 双向循环链表队列定义 (QUEUE DEFINITION)
//
// IQUEUEHEAD: 链表头/节点，包含 next/prev 指针
// 基于 Linux 内核链表风格实现，通过宏 ICONTAINEROF 从节点指针
// 反推包含它的结构体指针。
//
// 核心宏:
//   IQUEUE_INIT(ptr)     — 初始化链表节点 (自环)
//   IQUEUE_ADD(node,head) — 头部插入
//   IQUEUE_ADD_TAIL       — 尾部插入
//   IQUEUE_DEL(entry)     — 删除节点
//   IQUEUE_ENTRY(ptr,type,member) — 从节点指针获取容器结构体
//=====================================================================
#ifndef __IQUEUE_DEF__
#define __IQUEUE_DEF__

struct IQUEUEHEAD {
	struct IQUEUEHEAD *next, *prev;
};

typedef struct IQUEUEHEAD iqueue_head;


//---------------------------------------------------------------------
// queue init                                                         
//---------------------------------------------------------------------
#define IQUEUE_HEAD_INIT(name) { &(name), &(name) }
#define IQUEUE_HEAD(name) \
	struct IQUEUEHEAD name = IQUEUE_HEAD_INIT(name)

#define IQUEUE_INIT(ptr) ( \
	(ptr)->next = (ptr), (ptr)->prev = (ptr))

#define IOFFSETOF(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define ICONTAINEROF(ptr, type, member) ( \
		(type*)( ((char*)((type*)ptr)) - IOFFSETOF(type, member)) )

#define IQUEUE_ENTRY(ptr, type, member) ICONTAINEROF(ptr, type, member)


//---------------------------------------------------------------------
// queue operation                     
//---------------------------------------------------------------------
#define IQUEUE_ADD(node, head) ( \
	(node)->prev = (head), (node)->next = (head)->next, \
	(head)->next->prev = (node), (head)->next = (node))

#define IQUEUE_ADD_TAIL(node, head) ( \
	(node)->prev = (head)->prev, (node)->next = (head), \
	(head)->prev->next = (node), (head)->prev = (node))

#define IQUEUE_DEL_BETWEEN(p, n) ((n)->prev = (p), (p)->next = (n))

#define IQUEUE_DEL(entry) (\
	(entry)->next->prev = (entry)->prev, \
	(entry)->prev->next = (entry)->next, \
	(entry)->next = 0, (entry)->prev = 0)

#define IQUEUE_DEL_INIT(entry) do { \
	IQUEUE_DEL(entry); IQUEUE_INIT(entry); } while (0)

#define IQUEUE_IS_EMPTY(entry) ((entry) == (entry)->next)

#define iqueue_init		IQUEUE_INIT
#define iqueue_entry	IQUEUE_ENTRY
#define iqueue_add		IQUEUE_ADD
#define iqueue_add_tail	IQUEUE_ADD_TAIL
#define iqueue_del		IQUEUE_DEL
#define iqueue_del_init	IQUEUE_DEL_INIT
#define iqueue_is_empty IQUEUE_IS_EMPTY

#define IQUEUE_FOREACH(iterator, head, TYPE, MEMBER) \
	for ((iterator) = iqueue_entry((head)->next, TYPE, MEMBER); \
		&((iterator)->MEMBER) != (head); \
		(iterator) = iqueue_entry((iterator)->MEMBER.next, TYPE, MEMBER))

#define iqueue_foreach(iterator, head, TYPE, MEMBER) \
	IQUEUE_FOREACH(iterator, head, TYPE, MEMBER)

#define iqueue_foreach_entry(pos, head) \
	for( (pos) = (head)->next; (pos) != (head) ; (pos) = (pos)->next )
	

#define __iqueue_splice(list, head) do {	\
		iqueue_head *first = (list)->next, *last = (list)->prev; \
		iqueue_head *at = (head)->next; \
		(first)->prev = (head), (head)->next = (first);		\
		(last)->next = (at), (at)->prev = (last); }	while (0)

#define iqueue_splice(list, head) do { \
	if (!iqueue_is_empty(list)) __iqueue_splice(list, head); } while (0)

#define iqueue_splice_init(list, head) do {	\
	iqueue_splice(list, head);	iqueue_init(list); } while (0)


#ifdef _MSC_VER
#pragma warning(disable:4311)
#pragma warning(disable:4312)
#pragma warning(disable:4996)
#endif

#endif


//---------------------------------------------------------------------
// BYTE ORDER & ALIGNMENT
//---------------------------------------------------------------------
#ifndef IWORDS_BIG_ENDIAN
    #ifdef _BIG_ENDIAN_
        #if _BIG_ENDIAN_
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #if defined(__hppa__) || \
            defined(__m68k__) || defined(mc68000) || defined(_M_M68K) || \
            (defined(__MIPS__) && defined(__MIPSEB__)) || \
            defined(__ppc__) || defined(__POWERPC__) || defined(_M_PPC) || \
            defined(__sparc__) || defined(__powerpc__) || \
            defined(__mc68000__) || defined(__s390x__) || defined(__s390__) || \
            defined(__ARM_BIG_ENDIAN)
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #define IWORDS_BIG_ENDIAN  0
    #endif
#endif

#ifndef IWORDS_MUST_ALIGN
	#if defined(__i386__) || defined(__i386) || defined(_i386_)
		#define IWORDS_MUST_ALIGN 0
	#elif defined(_M_IX86) || defined(_X86_) || defined(__x86_64__)
		#define IWORDS_MUST_ALIGN 0
	#elif defined(__amd64) || defined(__amd64__)
		#define IWORDS_MUST_ALIGN 0
	#else
		#define IWORDS_MUST_ALIGN 1
	#endif
#endif


//=====================================================================
// Predefine struct
//=====================================================================
struct IKCPCB;
typedef struct IKCPCB ikcpcb;


//=====================================================================
// KCP 数据段结构体 (SEGMENT)
//
// node:     链表节点 (IQUEUEHEAD)，用于挂载到队列
// conv:     会话 ID
// cmd:      命令类型 (PUSH/ACK/WASK/WINS)
// frg:      分片序号 (0=最后一个分片)
// wnd:      窗口大小 (对端可接收的窗口)
// ts:       时间戳 (发送时的时间)
// sn:       序列号 (递增)
// una:      未确认序列号 (对端期望的下一个序列号)
// len:      数据长度
// resendts: 下次重传时间戳
// rto:      重传超时 (RTO)
// fastack:  快速确认计数 (用于触发快速重传)
// xmit:     已传输次数
// data[1]:  柔性数组成员，实际数据存储在此
//=====================================================================
struct IKCPSEG
{
	struct IQUEUEHEAD node;
	IUINT32 conv;
	IUINT32 cmd;
	IUINT32 frg;
	IUINT32 wnd;
	IUINT32 ts;
	IUINT32 sn;
	IUINT32 una;
	IUINT32 len;
	IUINT32 resendts;
	IUINT32 rto;
	IUINT32 fastack;
	IUINT32 xmit;
	char data[1];
};


//---------------------------------------------------------------------
// IKCPOPS - 可插拔拥塞控制操作 (Pluggable Congestion Control)
//
// 通过函数指针表实现可替换的拥塞控制算法。
// 回调包括:
//   init/release:  生命周期管理
//   on_ack:        收到 ACK 时调用
//   on_fast_retransmit: 快速重传时调用
//   on_timeout:    超时时调用
//   on_tick:       每个周期调用
//   on_app_limited: 应用限速时调用
//   on_rtt:        RTT 更新时调用
//   on_pkt_sent/on_pkt_acked: 数据包发送/确认回调
//---------------------------------------------------------------------
struct IKCPOPS
{
	const char *name;
	int (*init)(ikcpcb *kcp);
	void (*release)(ikcpcb *kcp);
	void (*on_ack)(ikcpcb *kcp, IUINT32 acked_segs, IUINT32 acked_bytes,
			IUINT32 prior_in_flight);
	void (*on_fast_retransmit)(ikcpcb *kcp, IUINT32 fast_retrans,
				IUINT32 inflight, IUINT32 prior_cwnd);
	void (*on_timeout)(ikcpcb *kcp, IUINT32 prior_cwnd);
	void (*on_tick)(ikcpcb *kcp);
	void (*on_app_limited)(ikcpcb *kcp, IUINT32 inflight);
	void (*on_rtt)(ikcpcb *kcp, IINT32 rtt);
	void (*on_pkt_sent)(ikcpcb *kcp, IUINT32 sn, IUINT32 ts,
				IUINT32 len, IUINT32 inflight, IUINT32 xmit);
	void (*on_pkt_acked)(ikcpcb *kcp, IUINT32 sn, IUINT32 ts,
				IUINT32 len, IINT32 rtt, IUINT32 xmit);
	IUINT32 (*get_info)(ikcpcb *kcp, void *buf, IUINT32 bufsize);
	IUINT32 (*pacing_rate)(ikcpcb *kcp);
};


//---------------------------------------------------------------------
// IKCPCB - KCP 控制块 (KCP Control Block)
//
// 核心状态变量:
//   conv:      会话 ID
//   mtu/mss:   最大传输单元 / 最大分段大小
//   state:     连接状态 (0=正常, -1=死链)
//   snd_una:   发送未确认 (最早的未确认序列号)
//   snd_nxt:   下一个发送序列号
//   rcv_nxt:   下一个期望接收序列号
//   snd_wnd/rcv_wnd/rmt_wnd/cwnd: 发送/接收/远端/拥塞窗口
//   rx_rttval/rx_srtt/rx_rto/rx_minrto: RTT 相关变量
//
// 队列:
//   snd_queue: 发送队列 (应用层已入队，待发送)
//   rcv_queue: 接收队列 (已完整接收，待应用层读取)
//   snd_buf:   发送缓冲区 (已发送，等待确认)
//   rcv_buf:   接收缓冲区 (已接收，等待重组)
//
// 回调:
//   output:  输出回调 (KCP → 网络层)
//   writelog: 日志回调 (可选)
//---------------------------------------------------------------------
struct IKCPCB
{
	IUINT32 conv, mtu, mss, state;
	IUINT32 snd_una, snd_nxt, rcv_nxt;
	IUINT32 ts_recent, ts_lastack, ssthresh;
	IINT32 rx_rttval, rx_srtt, rx_rto, rx_minrto;
	IUINT32 snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe;
	IUINT32 current, interval, ts_flush, xmit;
	IUINT32 nrcv_buf, nsnd_buf;
	IUINT32 nrcv_que, nsnd_que;
	IUINT32 nodelay, updated;
	IUINT32 ts_probe, probe_wait;
	IUINT32 dead_link, incr;
	struct IQUEUEHEAD snd_queue;
	struct IQUEUEHEAD rcv_queue;
	struct IQUEUEHEAD snd_buf;
	struct IQUEUEHEAD rcv_buf;
	IUINT32 *acklist;
	IUINT32 ackcount;
	IUINT32 ackblock;
	IUINT32 ackedlen;
	void *user;
	char *buffer;
	int fastresend;
	int fastlimit;
	int nocwnd, stream;
	const struct IKCPOPS *ccops;
	void *congest;
	int logmask;
	int (*output)(const char *buf, int len, struct IKCPCB *kcp, void *user);
	void (*writelog)(const char *log, struct IKCPCB *kcp, void *user);
};


#define IKCP_LOG_OUTPUT			1
#define IKCP_LOG_INPUT			2
#define IKCP_LOG_SEND			4
#define IKCP_LOG_RECV			8
#define IKCP_LOG_IN_DATA		16
#define IKCP_LOG_IN_ACK			32
#define IKCP_LOG_IN_PROBE		64
#define IKCP_LOG_IN_WINS		128
#define IKCP_LOG_OUT_DATA		256
#define IKCP_LOG_OUT_ACK		512
#define IKCP_LOG_OUT_PROBE		1024
#define IKCP_LOG_OUT_WINS		2048

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------
// KCP 公开 API 接口 (Public Interface)
//---------------------------------------------------------------------

/* 创建 KCP 实例: conv=会话ID, user=用户数据指针 (本项目中为 channel_t) */
ikcpcb* ikcp_create(IUINT32 conv, void *user);

/* 销毁 KCP 实例，释放所有资源 */
void ikcp_release(ikcpcb *kcp);

/* 设置输出回调: KCP 需要发送数据时调用此回调 */
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len, 
	ikcpcb *kcp, void *user));

/* 从 KCP 接收数据 (KCP→应用层): 返回字节数, <0 表示无可用数据 (EAGAIN) */
int ikcp_recv(ikcpcb *kcp, char *buffer, int len);

/* 发送数据到 KCP (应用层→KCP): 返回字节数, <0 表示错误 */
int ikcp_send(ikcpcb *kcp, const char *buffer, int len);

/* 更新 KCP 状态机: 每 10ms-100ms 调用一次, current=当前毫秒时间戳 */
void ikcp_update(ikcpcb *kcp, IUINT32 current);

/* 计算下次调用 ikcp_update 的时间: 返回应调用的毫秒时间戳 */
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current);

/* 输入收到的原始数据段 (网络层→KCP) */
int ikcp_input(ikcpcb *kcp, const char *data, long size);

/* 刷新待发送数据: 将 snd_queue/buf 中的数据通过 output 回调发送 */
void ikcp_flush(ikcpcb *kcp);

/* 查看接收队列中下一条完整消息的大小 */
int ikcp_peeksize(const ikcpcb *kcp);

/* 设置 MTU: 默认 1400, 范围 [50, 65535] */
int ikcp_setmtu(ikcpcb *kcp, int mtu);

/* 设置发送/接收窗口大小: sndwnd/rcvwnd > 0 有效 */
int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd);

/* 获取等待发送的段数 (nsnd_buf + nsnd_que) */
int ikcp_waitsnd(const ikcpcb *kcp);

/* 配置 nodelay 模式:
 *   nodelay:  0=普通 / 1=nodelay (更快, 更高带宽占用)
 *   interval: 内部更新间隔 ms, 默认 100, 范围 [10, 5000]
 *   resend:   快速重传阈值, 0=禁用, 默认 0
 *   nc:       0=启用拥塞控制 / 1=禁用拥塞控制
 *   最快配置: ikcp_nodelay(kcp, 1, 20, 2, 1) */
int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc);

/* 安装可插拔拥塞控制算法: ops=NULL 恢复内置算法 */
int ikcp_setcc(ikcpcb *kcp, const struct IKCPOPS *ops);

/* 写日志: mask=日志级别掩码组合 */
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...);

/* 设置自定义内存分配器 */
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*));

/* 从原始数据包读取会话 ID (conv) */
IUINT32 ikcp_getconv(const void *ptr);


#ifdef __cplusplus
}
#endif

#endif


