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
// KCP 是一个快速可靠的 ARQ (自动重传请求) 协议，使用不同于 TCP 的拥塞控制算法。
// 它以比 TCP 更高的带宽为代价，换取 30%-40% 的平均延迟降低。
// 本文件被 kcp_wrap.c 封装，通过 kcp_wrap_create/send/recv/update 等函数调用。
//
// 【核心概念】
//   - conv:   会话 ID，本项目中对应 channel_id
//   - seg:    数据段 (segment)，KCP 内部传输单元
//   - snd_queue / rcv_queue: 发送/接收队列
//   - snd_buf / rcv_buf:     发送/接收缓冲区（窗口）
//   - IKCP_CMD_PUSH: 数据推送命令 (81)
//   - IKCP_CMD_ACK:  确认命令 (82)
//   - IKCP_CMD_WASK: 窗口探测请求 (83)
//   - IKCP_CMD_WINS: 窗口大小通知 (84)
//
// 【关键函数索引】
//   ikcp_create()  — 创建 KCP 实例
//   ikcp_release() — 销毁 KCP 实例
//   ikcp_send()    — 发送数据（应用层 → KCP）
//   ikcp_recv()    — 接收数据（KCP → 应用层）
//   ikcp_input()   — 输入数据段（网络层 → KCP）
//   ikcp_update()  — 更新状态机（驱动定时器、重传）
//   ikcp_flush()   — 刷新待发送数据到 output 回调
//   ikcp_nodelay() — 配置 nodelay 模式参数
//   ikcp_wndsize() — 设置窗口大小
//   ikcp_setmtu()  — 设置 MTU
//
//=====================================================================
#include "ikcp.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#define IKCP_FASTACK_CONSERVE

//=====================================================================
// KCP 协议常量 (Protocol Constants)
//=====================================================================
const IUINT32 IKCP_RTO_NDL = 30;		// nodelay 模式最小 RTO (毫秒)
const IUINT32 IKCP_RTO_MIN = 100;		// 普通模式最小 RTO (毫秒)
const IUINT32 IKCP_RTO_DEF = 200;       // 默认 RTO (毫秒)
const IUINT32 IKCP_RTO_MAX = 60000;     // 最大 RTO (毫秒)
const IUINT32 IKCP_CMD_PUSH = 81;		// 命令: 推送数据
const IUINT32 IKCP_CMD_ACK  = 82;		// 命令: 确认
const IUINT32 IKCP_CMD_WASK = 83;		// 命令: 窗口探测 (询问对端窗口大小)
const IUINT32 IKCP_CMD_WINS = 84;		// 命令: 窗口通知 (告知本端窗口大小)
const IUINT32 IKCP_ASK_SEND = 1;		// 需要发送 WASK 探测
const IUINT32 IKCP_ASK_TELL = 2;		// 需要发送 WINS 通知
const IUINT32 IKCP_WND_SND = 32;        // 默认发送窗口大小
const IUINT32 IKCP_WND_RCV = 128;       // 默认接收窗口大小 (必须 >= 最大分片数)
const IUINT32 IKCP_MTU_DEF = 1400;      // 默认 MTU
const IUINT32 IKCP_ACK_FAST	= 3;        // 快速确认阈值 (收到此数量的重复ACK触发快速重传)
const IUINT32 IKCP_INTERVAL	= 100;      // 默认内部更新间隔 (毫秒)
const IUINT32 IKCP_OVERHEAD = 24;       // KCP 协议头开销 (字节)
const IUINT32 IKCP_DEADLINK = 20;       // 死链检测: 连续无响应更新次数阈值
const IUINT32 IKCP_THRESH_INIT = 2;     // 慢启动阈值初始值
const IUINT32 IKCP_THRESH_MIN = 2;      // 慢启动阈值最小值
const IUINT32 IKCP_PROBE_INIT = 5000;	// 窗口探测初始间隔 (毫秒, 5秒)
const IUINT32 IKCP_PROBE_LIMIT = 120000;// 窗口探测最大间隔 (毫秒, 120秒)
const IUINT32 IKCP_FASTACK_LIMIT = 5;   // 快速确认触发次数上限


//---------------------------------------------------------------------
// 编解码函数 (encode / decode)
// 所有多字节整数使用小端序 (Little-Endian / LSB first)
//---------------------------------------------------------------------

/* encode 8 bits unsigned int */
static inline char *ikcp_encode8u(char *p, unsigned char c)
{
	*(unsigned char*)p++ = c;
	return p;
}

/* decode 8 bits unsigned int */
static inline const char *ikcp_decode8u(const char *p, unsigned char *c)
{
	*c = *(unsigned char*)p++;
	return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *ikcp_encode16u(char *p, unsigned short w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (w & 255);
	*(unsigned char*)(p + 1) = (w >> 8);
#else
	memcpy(p, &w, 2);
#endif
	p += 2;
	return p;
}

/* decode 16 bits unsigned int (lsb) */
static inline const char *ikcp_decode16u(const char *p, unsigned short *w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*w = *(const unsigned char*)(p + 1);
	*w = *(const unsigned char*)(p + 0) + (*w << 8);
#else
	memcpy(w, p, 2);
#endif
	p += 2;
	return p;
}

/* encode 32 bits unsigned int (lsb) */
static inline char *ikcp_encode32u(char *p, IUINT32 l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (unsigned char)((l >>  0) & 0xff);
	*(unsigned char*)(p + 1) = (unsigned char)((l >>  8) & 0xff);
	*(unsigned char*)(p + 2) = (unsigned char)((l >> 16) & 0xff);
	*(unsigned char*)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
	memcpy(p, &l, 4);
#endif
	p += 4;
	return p;
}

/* decode 32 bits unsigned int (lsb) */
static inline const char *ikcp_decode32u(const char *p, IUINT32 *l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else 
	memcpy(l, p, 4);
#endif
	p += 4;
	return p;
}

static inline IUINT32 _imin_(IUINT32 a, IUINT32 b) {
	return a <= b ? a : b;
}

static inline IUINT32 _imax_(IUINT32 a, IUINT32 b) {
	return a >= b ? a : b;
}

static inline IUINT32 _ibound_(IUINT32 lower, IUINT32 middle, IUINT32 upper) 
{
	return _imin_(_imax_(lower, middle), upper);
}

static inline long _itimediff(IUINT32 later, IUINT32 earlier) 
{
	return ((IINT32)(later - earlier));
}

//---------------------------------------------------------------------
// 数据段管理 (segment management)
// 数据段 (IKCPSEG) 是 KCP 内部传输的基本单元
//---------------------------------------------------------------------
typedef struct IKCPSEG IKCPSEG;

static void* (*ikcp_malloc_hook)(size_t) = NULL;
static void (*ikcp_free_hook)(void *) = NULL;

// internal malloc
static void* ikcp_malloc(size_t size) {
	if (ikcp_malloc_hook) 
		return ikcp_malloc_hook(size);
	return malloc(size);
}

// internal free
static void ikcp_free(void *ptr) {
	if (ikcp_free_hook) {
		ikcp_free_hook(ptr);
	}	else {
		free(ptr);
	}
}

// redefine allocator
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*))
{
	ikcp_malloc_hook = new_malloc;
	ikcp_free_hook = new_free;
}

// allocate a new kcp segment
static IKCPSEG* ikcp_segment_new(ikcpcb *kcp, int size)
{
	(void)kcp;
	return (IKCPSEG*)ikcp_malloc(sizeof(IKCPSEG) + size);
}

// delete a segment
static void ikcp_segment_delete(ikcpcb *kcp, IKCPSEG *seg)
{
	(void)kcp;
	ikcp_free(seg);
}

// write log
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...)
{
	char buffer[1024];
	va_list argptr;
	if ((mask & kcp->logmask) == 0 || kcp->writelog == 0) return;
	va_start(argptr, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, argptr);
	/* L17: vsnprintf >=1024 时截断，日志非关键路径，截断可接受 */
	va_end(argptr);
	kcp->writelog(buffer, kcp, kcp->user);
}

// check log mask
static int ikcp_canlog(const ikcpcb *kcp, int mask)
{
	if ((mask & kcp->logmask) == 0 || kcp->writelog == NULL) return 0;
	return 1;
}

// output segment
static int ikcp_output(ikcpcb *kcp, const void *data, int size)
{
	assert(kcp);
	assert(kcp->output);
	if (ikcp_canlog(kcp, IKCP_LOG_OUTPUT)) {
		ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size);
	}
	if (size == 0) return 0;
	return kcp->output((const char*)data, size, kcp, kcp->user);
}

// output queue
void ikcp_qprint(const char *name, const struct IQUEUEHEAD *head)
{
	(void)name;
	(void)head;
#if 0
	const struct IQUEUEHEAD *p;
	printf("<%s>: [", name);
	for (p = head->next; p != head; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		printf("(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
		if (p->next != head) printf(",");
	}
	printf("]\n");
#endif
}


//---------------------------------------------------------------------
// ikcp_create - 创建 KCP 实例
//
// 参数:
//   conv: 会话 ID (本项目中对应 channel_id)
//   user: 用户数据指针 (本项目中指向 channel_t)
//
// 返回值:
//   成功返回 KCP 控制块指针，失败返回 NULL (内存不足)
//
// 流程:
//   1. 分配 ikcpcb 结构体内存并清零
//   2. 初始化所有队列 (snd_queue, rcv_queue, snd_buf, rcv_buf)
//   3. 设置默认参数: MTU=1400, MSS=MTU-OVERHEAD
//   4. 初始化定时器和状态变量
//---------------------------------------------------------------------
ikcpcb* ikcp_create(IUINT32 conv, void *user)
{
	ikcpcb *kcp = (ikcpcb*)ikcp_malloc(sizeof(struct IKCPCB));
	if (kcp == NULL) return NULL;
	kcp->conv = conv;
	kcp->user = user;
	kcp->snd_una = 0;
	kcp->snd_nxt = 0;
	kcp->rcv_nxt = 0;
	kcp->ts_recent = 0;
	kcp->ts_lastack = 0;
	kcp->ts_probe = 0;
	kcp->probe_wait = 0;
	kcp->snd_wnd = IKCP_WND_SND;
	kcp->rcv_wnd = IKCP_WND_RCV;
	kcp->rmt_wnd = IKCP_WND_RCV;
	kcp->cwnd = 0;
	kcp->incr = 0;
	kcp->probe = 0;
	kcp->mtu = IKCP_MTU_DEF;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	kcp->stream = 0;

	kcp->buffer = (char*)ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
	if (kcp->buffer == NULL) {
		ikcp_free(kcp);
		return NULL;
	}

	iqueue_init(&kcp->snd_queue);
	iqueue_init(&kcp->rcv_queue);
	iqueue_init(&kcp->snd_buf);
	iqueue_init(&kcp->rcv_buf);
	kcp->nrcv_buf = 0;
	kcp->nsnd_buf = 0;
	kcp->nrcv_que = 0;
	kcp->nsnd_que = 0;
	kcp->state = 0;
	kcp->acklist = NULL;
	kcp->ackblock = 0;
	kcp->ackcount = 0;
	kcp->ackedlen = 0;
	kcp->rx_srtt = 0;
	kcp->rx_rttval = 0;
	kcp->rx_rto = IKCP_RTO_DEF;
	kcp->rx_minrto = IKCP_RTO_MIN;
	kcp->current = 0;
	kcp->interval = IKCP_INTERVAL;
	kcp->ts_flush = IKCP_INTERVAL;
	kcp->nodelay = 0;
	kcp->updated = 0;
	kcp->logmask = 0;
	kcp->ssthresh = IKCP_THRESH_INIT;
	kcp->fastresend = 0;
	kcp->fastlimit = IKCP_FASTACK_LIMIT;
	kcp->nocwnd = 0;
	kcp->xmit = 0;
	kcp->dead_link = IKCP_DEADLINK;
	kcp->output = NULL;
	kcp->ccops = NULL;
	kcp->congest = NULL;
	kcp->writelog = NULL;

	return kcp;
}


//---------------------------------------------------------------------
// ikcp_release - 销毁 KCP 实例，释放所有资源
//
// 流程:
//   1. 释放拥塞控制回调 (ccops)
//   2. 逐个释放所有队列中的数据段:
//      snd_buf (发送缓冲区) → rcv_buf (接收缓冲区)
//      → snd_queue (发送队列) → rcv_queue (接收队列)
//   3. 释放 KCP 控制块自身内存
//---------------------------------------------------------------------
void ikcp_release(ikcpcb *kcp)
{
	IKCPSEG *seg;
	assert(kcp);
	if (kcp) {
		if (kcp->ccops && kcp->ccops->release) {
			kcp->ccops->release(kcp);
		}
		while (!iqueue_is_empty(&kcp->snd_buf)) {
			seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_buf)) {
			seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->snd_queue)) {
			seg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_queue)) {
			seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		if (kcp->buffer) {
			ikcp_free(kcp->buffer);
		}
		if (kcp->acklist) {
			ikcp_free(kcp->acklist);
		}

		kcp->nrcv_buf = 0;
		kcp->nsnd_buf = 0;
		kcp->nrcv_que = 0;
		kcp->nsnd_que = 0;
		kcp->ackcount = 0;
		kcp->buffer = NULL;
		kcp->acklist = NULL;
		ikcp_free(kcp);
	}
}


//---------------------------------------------------------------------
// set output callback, which will be invoked by kcp
//---------------------------------------------------------------------
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len,
	ikcpcb *kcp, void *user))
{
	kcp->output = output;
}


//---------------------------------------------------------------------
// ikcp_recv - 从 KCP 接收数据（KCP → 应用层）
//
// 参数:
//   buffer: 接收缓冲区
//   len:    缓冲区大小
//
// 返回值:
//   >0:  成功接收的字节数
//   -1:  无完整消息可读 (EAGAIN 语义)
//   -2:  peek 长度异常
//   -3:  缓冲区不足 (peeksize > len)
//
// 流程:
//   1. 计算下一条完整消息的长度 (ikcp_peeksize)
//   2. 如果缓冲区足够大，从 rcv_queue 中取出数据段并拷贝
//   3. 返回实际拷贝的字节数
//---------------------------------------------------------------------
int ikcp_recv(ikcpcb *kcp, char *buffer, int len)
{
	struct IQUEUEHEAD *p;
	int ispeek = (len < 0)? 1 : 0;
	int peeksize;
	int recover = 0;
	IKCPSEG *seg;
	if (!kcp) return -1;

	if (iqueue_is_empty(&kcp->rcv_queue))
		return -1;

	if (len < 0) len = -len;

	peeksize = ikcp_peeksize(kcp);

	if (peeksize < 0) 
		return -2;

	if (peeksize > len) 
		return -3;

	if (kcp->nrcv_que >= kcp->rcv_wnd)
		recover = 1;

	// merge fragment
	for (len = 0, p = kcp->rcv_queue.next; p != &kcp->rcv_queue; ) {
		int fragment;
		seg = iqueue_entry(p, IKCPSEG, node);
		p = p->next;

		if (buffer) {
			memcpy(buffer, seg->data, seg->len);
			buffer += seg->len;
		}

		len += seg->len;
		fragment = seg->frg;

		if (ikcp_canlog(kcp, IKCP_LOG_RECV)) {
			ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn);
		}

		if (ispeek == 0) {
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
			kcp->nrcv_que--;
		}

		if (fragment == 0) 
			break;
	}

	assert(len == peeksize);

	// move available data from rcv_buf -> rcv_queue
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

	// fast recover
	if (kcp->nrcv_que < kcp->rcv_wnd && recover) {
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		kcp->probe |= IKCP_ASK_TELL;
	}

	return len;
}


//---------------------------------------------------------------------
// peek data size
//---------------------------------------------------------------------
int ikcp_peeksize(const ikcpcb *kcp)
{
	struct IQUEUEHEAD *p;
	IKCPSEG *seg;
	int length = 0;

	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue)) return -1;

	seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
	if (seg->frg == 0) return seg->len;

	if (kcp->nrcv_que < seg->frg + 1) return -1;

	for (p = kcp->rcv_queue.next; p != &kcp->rcv_queue; p = p->next) {
		seg = iqueue_entry(p, IKCPSEG, node);
		length += seg->len;
		if (seg->frg == 0) break;
	}

	return length;
}


//---------------------------------------------------------------------
// ikcp_send - 发送数据到 KCP（应用层 → KCP）
//
// 参数:
//   buffer: 待发送数据
//   len:    数据长度
//
// 返回值:
//   0:  成功入队
//   -1: 参数错误
//   -2: 内存分配失败
//
// 流程:
//   1. 将数据按 MSS 分片
//   2. 每个分片封装为 IKCPSEG 数据段，加入 snd_queue
//   3. 分片数必须 < IKCP_WND_RCV (128)，否则返回 -2
//---------------------------------------------------------------------
int ikcp_send(ikcpcb *kcp, const char *buffer, int len)
{
	IKCPSEG *seg;
	int count, i;
	int sent = 0;

	if (!kcp) return -1;
	assert(kcp->mss > 0);
	if (len < 0) return -1;

	// append to previous segment in streaming mode (if possible)
	if (kcp->stream != 0) {
		if (!iqueue_is_empty(&kcp->snd_queue)) {
			IKCPSEG *old = iqueue_entry(kcp->snd_queue.prev, IKCPSEG, node);
			if (old->len < kcp->mss) {
				int capacity = kcp->mss - old->len;
				int extend = (len < capacity)? len : capacity;
				seg = ikcp_segment_new(kcp, old->len + extend);
				assert(seg);
				if (seg == NULL) {
					return -2;
				}
				iqueue_add_tail(&seg->node, &kcp->snd_queue);
				memcpy(seg->data, old->data, old->len);
				if (buffer) {
					memcpy(seg->data + old->len, buffer, extend);
					buffer += extend;
				}
				seg->len = old->len + extend;
				seg->frg = 0;
				len -= extend;
				iqueue_del_init(&old->node);
				ikcp_segment_delete(kcp, old);
				sent = extend;
			}
		}
		if (len <= 0) {
			return sent;
		}
	}

	if (len <= (int)kcp->mss) count = 1;
	else count = (len + kcp->mss - 1) / kcp->mss;

	if (count >= (int)IKCP_WND_RCV) {
		if (kcp->stream != 0 && sent > 0) 
			return sent;
		return -2;
	}

	if (count == 0) count = 1;

	// fragment
	for (i = 0; i < count; i++) {
		int size = len > (int)kcp->mss ? (int)kcp->mss : len;
		seg = ikcp_segment_new(kcp, size);
		if (seg == NULL) {
			return -2;
		}
		if (buffer && len > 0) {
			memcpy(seg->data, buffer, size);
		}
		seg->len = size;
		seg->frg = (kcp->stream == 0)? (count - i - 1) : 0;
		iqueue_init(&seg->node);
		iqueue_add_tail(&seg->node, &kcp->snd_queue);
		kcp->nsnd_que++;
		if (buffer) {
			buffer += size;
		}
		len -= size;
		sent += size;
	}

	return sent;
}


//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
static void ikcp_update_ack(ikcpcb *kcp, IINT32 rtt)
{
	IINT32 rto = 0;
	if (kcp->rx_srtt == 0) {
		kcp->rx_srtt = rtt;
		kcp->rx_rttval = rtt / 2;
	}	else {
		long delta = rtt - kcp->rx_srtt;
		if (delta < 0) delta = -delta;
		kcp->rx_rttval = (3 * kcp->rx_rttval + delta) / 4;
		kcp->rx_srtt = (7 * kcp->rx_srtt + rtt) / 8;
		if (kcp->rx_srtt < 1) kcp->rx_srtt = 1;
	}
	rto = kcp->rx_srtt + _imax_(kcp->interval, 4 * kcp->rx_rttval);
	kcp->rx_rto = _ibound_(kcp->rx_minrto, rto, IKCP_RTO_MAX);
	if (kcp->ccops && kcp->ccops->on_rtt) {
		kcp->ccops->on_rtt(kcp, rtt);
	}
}

static void ikcp_shrink_buf(ikcpcb *kcp)
{
	struct IQUEUEHEAD *p = kcp->snd_buf.next;
	if (p != &kcp->snd_buf) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		kcp->snd_una = seg->sn;
	}	else {
		kcp->snd_una = kcp->snd_nxt;
	}
}

static void ikcp_parse_ack(ikcpcb *kcp, IUINT32 sn)
{
	struct IQUEUEHEAD *p, *next;
	IINT32 pkt_rtt;

	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (sn == seg->sn) {
			kcp->ackedlen += seg->len;
			if (kcp->ccops && kcp->ccops->on_pkt_acked) {
				pkt_rtt = -1;
				if (_itimediff(kcp->current, seg->ts) >= 0) {
					pkt_rtt = _itimediff(kcp->current, seg->ts);
				}
				kcp->ccops->on_pkt_acked(kcp, seg->sn, seg->ts,
						seg->len, pkt_rtt, seg->xmit);
			}
			iqueue_del(p);
			ikcp_segment_delete(kcp, seg);
			kcp->nsnd_buf--;
			break;
		}
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
	}
}

static void ikcp_parse_una(ikcpcb *kcp, IUINT32 una)
{
	struct IQUEUEHEAD *p, *next;
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (_itimediff(una, seg->sn) > 0) {
			kcp->ackedlen += seg->len;
			if (kcp->ccops && kcp->ccops->on_pkt_acked) {
				kcp->ccops->on_pkt_acked(kcp, seg->sn, seg->ts,
						seg->len, -1, seg->xmit);
			}
			iqueue_del(p);
			ikcp_segment_delete(kcp, seg);
			kcp->nsnd_buf--;
		}	else {
			break;
		}
	}
}

static void ikcp_parse_fastack(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	struct IQUEUEHEAD *p, *next;

	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
		else if (sn != seg->sn) {
		#ifndef IKCP_FASTACK_CONSERVE
			seg->fastack++;
		#else
			if (_itimediff(ts, seg->ts) >= 0)
				seg->fastack++;
		#endif
		}
	}
}


//---------------------------------------------------------------------
// ack append
//---------------------------------------------------------------------
static void ikcp_ack_push(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	IUINT32 newsize = kcp->ackcount + 1;
	IUINT32 *ptr;

	if (newsize > kcp->ackblock) {
		IUINT32 *acklist;
		IUINT32 newblock;

		for (newblock = 8; newblock < newsize; newblock <<= 1);
		acklist = (IUINT32*)ikcp_malloc(newblock * sizeof(IUINT32) * 2);

		if (acklist == NULL) {
			fprintf(stderr, "[ERROR] ikcp_ack_push: malloc(%lu) failed, dropping ack\n",
			        (unsigned long)(newblock * sizeof(IUINT32) * 2));
			return;
		}

		if (kcp->acklist != NULL) {
			IUINT32 x;
			for (x = 0; x < kcp->ackcount; x++) {
				acklist[x * 2 + 0] = kcp->acklist[x * 2 + 0];
				acklist[x * 2 + 1] = kcp->acklist[x * 2 + 1];
			}
			ikcp_free(kcp->acklist);
		}

		kcp->acklist = acklist;
		kcp->ackblock = newblock;
	}

	ptr = &kcp->acklist[kcp->ackcount * 2];
	ptr[0] = sn;
	ptr[1] = ts;
	kcp->ackcount++;
}

static void ikcp_ack_get(const ikcpcb *kcp, int p, IUINT32 *sn, IUINT32 *ts)
{
	if (sn) sn[0] = kcp->acklist[p * 2 + 0];
	if (ts) ts[0] = kcp->acklist[p * 2 + 1];
}


//---------------------------------------------------------------------
// parse data
//---------------------------------------------------------------------
void ikcp_parse_data(ikcpcb *kcp, IKCPSEG *newseg)
{
	struct IQUEUEHEAD *p, *prev;
	IUINT32 sn = newseg->sn;
	int repeat = 0;
	
	if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 ||
		_itimediff(sn, kcp->rcv_nxt) < 0) {
		ikcp_segment_delete(kcp, newseg);
		return;
	}

	for (p = kcp->rcv_buf.prev; p != &kcp->rcv_buf; p = prev) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		prev = p->prev;
		if (seg->sn == sn) {
			repeat = 1;
			break;
		}
		if (_itimediff(sn, seg->sn) > 0) {
			break;
		}
	}

	if (repeat == 0) {
		iqueue_init(&newseg->node);
		iqueue_add(&newseg->node, p);
		kcp->nrcv_buf++;
	}	else {
		ikcp_segment_delete(kcp, newseg);
	}

#if 0
	ikcp_qprint("rcvbuf", &kcp->rcv_buf);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

	// move available data from rcv_buf -> rcv_queue
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

#if 0
	ikcp_qprint("queue", &kcp->rcv_queue);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

#if 1
//	printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
//	printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
#endif
}


//---------------------------------------------------------------------
// ikcp_input - 输入收到的数据段（网络层 → KCP）
//
// 参数:
//   data: 收到的原始 KCP 数据段
//   size: 数据段长度
//
// 返回值:
//   0:  成功处理
//   <0: 错误 (格式错误或校验失败)
//
// 流程:
//   1. 解析 KCP 协议头 (conv, cmd, frg, wnd, ts, sn, una, len)
//   2. 根据命令类型分发:
//      IKCP_CMD_ACK: 处理确认，更新 snd_una，从 snd_buf 移除已确认段
//      IKCP_CMD_PUSH: 将数据段放入 rcv_buf，检查完整性
//      IKCP_CMD_WASK: 回复 WINS (窗口探测)
//      IKCP_CMD_WINS: 更新对端窗口大小 (rmt_wnd)
//   3. 将完整连续的数据段从 rcv_buf 移动到 rcv_queue
//---------------------------------------------------------------------
int ikcp_input(ikcpcb *kcp, const char *data, long size)
{
	if (!kcp) return -1;
	IUINT32 prev_una = kcp->snd_una;
	IUINT32 prev_nsnd_buf = kcp->nsnd_buf;
	IUINT32 acked_segs, prior_in_flight;
	IUINT32 maxack = 0, latest_ts = 0;
	int flag = 0;

	kcp->ackedlen = 0;

	if (ikcp_canlog(kcp, IKCP_LOG_INPUT)) {
		ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);
	}

	if (data == NULL || size < (long)IKCP_OVERHEAD) return -1;

	while (1) {
		IUINT32 ts, sn, len, una, conv;
		IUINT16 wnd;
		IUINT8 cmd, frg;
		IKCPSEG *seg;

		if (size < (int)IKCP_OVERHEAD) break;

		data = ikcp_decode32u(data, &conv);
		if (conv != kcp->conv) return -1;

		data = ikcp_decode8u(data, &cmd);
		data = ikcp_decode8u(data, &frg);
		data = ikcp_decode16u(data, &wnd);
		data = ikcp_decode32u(data, &ts);
		data = ikcp_decode32u(data, &sn);
		data = ikcp_decode32u(data, &una);
		data = ikcp_decode32u(data, &len);

		size -= IKCP_OVERHEAD;

		if ((long)size < (long)len || (int)len < 0) return -2;
		if (len > (IUINT32)kcp->mtu * 128) return -2; /* C2: 拒绝超大payload, 以IKCP_WND_RCV为上限 */

		if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS) 
			return -3;

		kcp->rmt_wnd = wnd;
		ikcp_parse_una(kcp, una);
		ikcp_shrink_buf(kcp);

		if (cmd == IKCP_CMD_ACK) {
			if (_itimediff(kcp->current, ts) >= 0) {
				ikcp_update_ack(kcp, _itimediff(kcp->current, ts));
			}
			ikcp_parse_ack(kcp, sn);
			ikcp_shrink_buf(kcp);
			if (flag == 0) {
				flag = 1;
				maxack = sn;
				latest_ts = ts;
			}	else {
				if (_itimediff(sn, maxack) > 0) {
				#ifndef IKCP_FASTACK_CONSERVE
					maxack = sn;
					latest_ts = ts;
				#else
					if (_itimediff(ts, latest_ts) > 0) {
						maxack = sn;
						latest_ts = ts;
					}
				#endif
				}
			}
			if (ikcp_canlog(kcp, IKCP_LOG_IN_ACK)) {
				ikcp_log(kcp, IKCP_LOG_IN_ACK, 
					"input ack: sn=%lu rtt=%ld rto=%ld", (unsigned long)sn, 
					(long)_itimediff(kcp->current, ts),
					(long)kcp->rx_rto);
			}
		}
		else if (cmd == IKCP_CMD_PUSH) {
			if (ikcp_canlog(kcp, IKCP_LOG_IN_DATA)) {
				ikcp_log(kcp, IKCP_LOG_IN_DATA, 
					"input psh: sn=%lu ts=%lu", (unsigned long)sn, (unsigned long)ts);
			}
			if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0) {
				ikcp_ack_push(kcp, sn, ts);
				if (_itimediff(sn, kcp->rcv_nxt) >= 0) {
					seg = ikcp_segment_new(kcp, len);
				if (!seg) return -1;  /* OOM: 拒绝此输入 */
					seg->conv = conv;
					seg->cmd = cmd;
					seg->frg = frg;
					seg->wnd = wnd;
					seg->ts = ts;
					seg->sn = sn;
					seg->una = una;
					seg->len = len;

					if (len > 0) {
						memcpy(seg->data, data, len);
					}

					ikcp_parse_data(kcp, seg);
				}
			}
		}
		else if (cmd == IKCP_CMD_WASK) {
			// ready to send back IKCP_CMD_WINS in ikcp_flush
			// tell remote my window size
			kcp->probe |= IKCP_ASK_TELL;
			if (ikcp_canlog(kcp, IKCP_LOG_IN_PROBE)) {
				ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
			}
		}
		else if (cmd == IKCP_CMD_WINS) {
			// do nothing
			if (ikcp_canlog(kcp, IKCP_LOG_IN_WINS)) {
				ikcp_log(kcp, IKCP_LOG_IN_WINS,
					"input wins: %lu", (unsigned long)(wnd));
			}
		}
		else {
			return -3;
		}

		data += len;
		size -= len;
	}

	if (flag != 0) {
		ikcp_parse_fastack(kcp, maxack, latest_ts);
	}

	if (_itimediff(kcp->snd_una, prev_una) > 0) {
		acked_segs = kcp->snd_una - prev_una;
		prior_in_flight = prev_nsnd_buf;
		if (kcp->ccops && kcp->ccops->on_ack) {
			kcp->ccops->on_ack(kcp, acked_segs, kcp->ackedlen, 
					prior_in_flight);
		}
		else {
			if (kcp->cwnd < kcp->rmt_wnd) {
				IUINT32 mss = kcp->mss;
				if (kcp->cwnd < kcp->ssthresh) {
					kcp->cwnd++;
					kcp->incr += mss;
				}	else {
					if (kcp->incr < mss) kcp->incr = mss;
					kcp->incr += (mss * mss) / kcp->incr + (mss / 16);
					if ((kcp->cwnd + 1) * mss <= kcp->incr) {
					#if 1
						kcp->cwnd = (kcp->incr + mss - 1) / ((mss > 0)? mss : 1);
					#else
						kcp->cwnd++;
					#endif
					}
				}
				if (kcp->cwnd > kcp->rmt_wnd) {
					kcp->cwnd = kcp->rmt_wnd;
					kcp->incr = kcp->rmt_wnd * mss;
				}
			}
		}
	}

	return 0;
}


//---------------------------------------------------------------------
// ikcp_encode_seg
//---------------------------------------------------------------------
static char *ikcp_encode_seg(char *ptr, const IKCPSEG *seg)
{
	ptr = ikcp_encode32u(ptr, seg->conv);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->cmd);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->frg);
	ptr = ikcp_encode16u(ptr, (IUINT16)seg->wnd);
	ptr = ikcp_encode32u(ptr, seg->ts);
	ptr = ikcp_encode32u(ptr, seg->sn);
	ptr = ikcp_encode32u(ptr, seg->una);
	ptr = ikcp_encode32u(ptr, seg->len);
	return ptr;
}

static int ikcp_wnd_unused(const ikcpcb *kcp)
{
	if (kcp->nrcv_que < kcp->rcv_wnd) {
		return kcp->rcv_wnd - kcp->nrcv_que;
	}
	return 0;
}


//---------------------------------------------------------------------
// ikcp_flush - 刷新待发送数据到 output 回调
//
// 将 snd_queue 中的数据段移动到 snd_buf，将 snd_buf 中待发送的数据
// 通过 kcp->output 回调发送到网络层。
//
// 关键逻辑:
//   1. 从 snd_queue 取数据段 → 设置 sn/ts/una → 移入 snd_buf
//   2. 从 snd_buf 取数据段 → 编码为 KCP 段 → 调用 output 回调
//   3. 拥塞控制: cwnd = min(snd_wnd, rmt_wnd)，超过则暂停发送
//   4. 快速重传: 当收到 fastlimit 个以上 ACK 时触发重传
//   5. 超时重传: 当 RTO 超时时触发重传
//   6. 窗口探测: 当 rmt_wnd=0 时定期发送探测包
//---------------------------------------------------------------------
void ikcp_flush(ikcpcb *kcp)
{
	if (!kcp) return;
	IUINT32 current = kcp->current;
	char *buffer = kcp->buffer;
	char *ptr = buffer;
	int count, size, i;
	IUINT32 resent, cwnd;
	IUINT32 rtomin;
	IUINT32 prior_cwnd;
	IUINT32 eff_cwnd, cur_inflight;
	IINT32 pacing_budget = -1;
	struct IQUEUEHEAD *p;
	int change = 0;
	int lost = 0;
	IKCPSEG seg;

	// 'ikcp_update' hasn't been called yet. 
	if (kcp->updated == 0) return;

	if (kcp->ccops && kcp->ccops->on_tick) {
		kcp->ccops->on_tick(kcp);
	}

	if (kcp->ccops && kcp->ccops->pacing_rate) {
		pacing_budget = (IINT32)kcp->ccops->pacing_rate(kcp);
	}

	prior_cwnd = kcp->cwnd;

	seg.conv = kcp->conv;
	seg.cmd = IKCP_CMD_ACK;
	seg.frg = 0;
	seg.wnd = ikcp_wnd_unused(kcp);
	seg.una = kcp->rcv_nxt;
	seg.len = 0;
	seg.sn = 0;
	seg.ts = 0;

	// flush acknowledges
	count = kcp->ackcount;
	for (i = 0; i < count; i++) {
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ikcp_ack_get(kcp, i, &seg.sn, &seg.ts);
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	kcp->ackcount = 0;

	// probe window size (if remote window size equals zero)
	if (kcp->rmt_wnd == 0) {
		if (kcp->probe_wait == 0) {
			kcp->probe_wait = IKCP_PROBE_INIT;
			kcp->ts_probe = kcp->current + kcp->probe_wait;
		}	
		else {
			if (_itimediff(kcp->current, kcp->ts_probe) >= 0) {
				if (kcp->probe_wait < IKCP_PROBE_INIT) 
					kcp->probe_wait = IKCP_PROBE_INIT;
				kcp->probe_wait += kcp->probe_wait / 2;
				if (kcp->probe_wait > IKCP_PROBE_LIMIT)
					kcp->probe_wait = IKCP_PROBE_LIMIT;
				kcp->ts_probe = kcp->current + kcp->probe_wait;
				kcp->probe |= IKCP_ASK_SEND;
			}
		}
	}	else {
		kcp->ts_probe = 0;
		kcp->probe_wait = 0;
	}

	// flush window probing commands
	if (kcp->probe & IKCP_ASK_SEND) {
		seg.cmd = IKCP_CMD_WASK;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	// flush window probing commands
	if (kcp->probe & IKCP_ASK_TELL) {
		seg.cmd = IKCP_CMD_WINS;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	kcp->probe = 0;

	// calculate window size
	cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
	if (kcp->ccops != NULL || kcp->nocwnd == 0) cwnd = _imin_(kcp->cwnd, cwnd);

	// move data from snd_queue to snd_buf
	while (_itimediff(kcp->snd_nxt, kcp->snd_una + cwnd) < 0) {
		IKCPSEG *newseg;
		if (iqueue_is_empty(&kcp->snd_queue)) break;

		newseg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);

		iqueue_del(&newseg->node);
		iqueue_add_tail(&newseg->node, &kcp->snd_buf);
		kcp->nsnd_que--;
		kcp->nsnd_buf++;

		newseg->conv = kcp->conv;
		newseg->cmd = IKCP_CMD_PUSH;
		newseg->wnd = seg.wnd;
		newseg->ts = current;
		newseg->sn = kcp->snd_nxt++;
		newseg->una = kcp->rcv_nxt;
		newseg->resendts = current;
		newseg->rto = kcp->rx_rto;
		newseg->fastack = 0;
		newseg->xmit = 0;
	}

	// check on_app_limited
	if (kcp->ccops && kcp->ccops->on_app_limited) {
		if (iqueue_is_empty(&kcp->snd_queue)) {
			eff_cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
			eff_cwnd = _imin_(kcp->cwnd, eff_cwnd);
			cur_inflight = kcp->nsnd_buf;
			if (cur_inflight < eff_cwnd) {
				kcp->ccops->on_app_limited(kcp, cur_inflight);
			}
		}
	}

	// calculate resent
	resent = (kcp->fastresend > 0)? (IUINT32)kcp->fastresend : 0xffffffff;
	rtomin = (kcp->nodelay == 0)? (kcp->rx_rto >> 3) : 0;

	// flush data segments
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		IKCPSEG *segment = iqueue_entry(p, IKCPSEG, node);
		int needsend = 0;
		if (segment->xmit == 0) {
			needsend = 1;
			segment->xmit++;
			segment->rto = kcp->rx_rto;
			segment->resendts = current + segment->rto + rtomin;
		}
		else if (_itimediff(current, segment->resendts) >= 0) {
			needsend = 1;
			segment->xmit++;
			kcp->xmit++;
			if (kcp->nodelay == 0) {
				segment->rto += _imax_(segment->rto, (IUINT32)kcp->rx_rto);
			}	else {
				IINT32 step = (kcp->nodelay < 2)? 
					((IINT32)(segment->rto)) : kcp->rx_rto;
				segment->rto += step / 2;
			}
			segment->resendts = current + segment->rto;
			lost = 1;
		}
		else if (segment->fastack >= resent) {
			if ((int)segment->xmit <= kcp->fastlimit || 
				kcp->fastlimit <= 0) {
				needsend = 1;
				segment->xmit++;
				segment->fastack = 0;
				segment->resendts = current + segment->rto;
				change++;
			}
		}

		if (needsend) {
			int need;
			segment->ts = current;
			segment->wnd = seg.wnd;
			segment->una = kcp->rcv_nxt;

			if (pacing_budget >= 0 && pacing_budget < (IINT32)segment->len) {
				break;
			}

			if (kcp->ccops && kcp->ccops->on_pkt_sent) {
				kcp->ccops->on_pkt_sent(kcp, segment->sn, current,
						segment->len, kcp->nsnd_buf, segment->xmit);
			}

			size = (int)(ptr - buffer);
			need = IKCP_OVERHEAD + segment->len;

			if (size + need > (int)kcp->mtu) {
				ikcp_output(kcp, buffer, size);
				ptr = buffer;
			}

			ptr = ikcp_encode_seg(ptr, segment);

			if (segment->len > 0) {
				memcpy(ptr, segment->data, segment->len);
				ptr += segment->len;
			}

			if (pacing_budget >= 0) {
				pacing_budget -= (IINT32)segment->len;
			}

			if (segment->xmit >= kcp->dead_link) {
				kcp->state = (IUINT32)-1;
			}
		}
	}

	// flash remaining segments
	size = (int)(ptr - buffer);
	if (size > 0) {
		ikcp_output(kcp, buffer, size);
	}

	// update ssthresh
	if (change) {
		if (kcp->ccops && kcp->ccops->on_fast_retransmit) {
			kcp->ccops->on_fast_retransmit(kcp, (IUINT32)change, 
					kcp->nsnd_buf, prior_cwnd);
		}
		else {
			IUINT32 inflight = kcp->snd_nxt - kcp->snd_una;
			kcp->ssthresh = inflight / 2;
			if (kcp->ssthresh < IKCP_THRESH_MIN)
				kcp->ssthresh = IKCP_THRESH_MIN;
			kcp->cwnd = kcp->ssthresh + resent;
			kcp->incr = kcp->cwnd * kcp->mss;
		}
	}

	if (lost) {
		if (kcp->ccops && kcp->ccops->on_timeout) {
			kcp->ccops->on_timeout(kcp, prior_cwnd);
		}
		else {
			kcp->ssthresh = prior_cwnd / 2;
			if (kcp->ssthresh < IKCP_THRESH_MIN)
				kcp->ssthresh = IKCP_THRESH_MIN;
			kcp->cwnd = 1;
			kcp->incr = kcp->mss;
		}
	}

	if (kcp->cwnd < 1) {
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}

	/* H4: cwnd=0 时死链检测盲区补丁 — 扫描 snd_buf 中未发送的超时段 */
	{
		struct IQUEUEHEAD *q;
		for (q = kcp->snd_buf.next; q != &kcp->snd_buf; q = q->next) {
			IKCPSEG *seg = iqueue_entry(q, IKCPSEG, node);
			if (seg->xmit > 0 && seg->xmit >= kcp->dead_link) {
				kcp->state = (IUINT32)-1;
				break;
			}
		}
	}
}


//---------------------------------------------------------------------
// ikcp_update - 更新 KCP 状态机（驱动定时器）
//
// 参数:
//   current: 当前时间戳 (毫秒, 单调递增)
//
// 调用频率:
//   建议每 10ms-100ms 调用一次，本项目每 10ms 调用一次
//
// 流程:
//   1. 计算距上次更新的时间差 (slap)
//   2. 检查是否需要发送窗口探测 (IKCP_CMD_WASK)
//   3. 更新重传定时器 (rx_rto)
//   4. 检查死链: 如果超过 IKCP_DEADLINK 次无响应，标记 state=-1
//   5. 调用 ikcp_flush() 发送待处理数据
//---------------------------------------------------------------------
void ikcp_update(ikcpcb *kcp, IUINT32 current)
{
	if (!kcp) return;
	IINT32 slap;

	kcp->current = current;

	if (kcp->updated == 0) {
		kcp->updated = 1;
		kcp->ts_flush = kcp->current;
	}

	slap = _itimediff(kcp->current, kcp->ts_flush);

	if (slap >= 10000 || slap < -10000) {
		kcp->ts_flush = kcp->current;
		slap = 0;
	}

	if (slap >= 0) {
		kcp->ts_flush += kcp->interval;
		if (_itimediff(kcp->current, kcp->ts_flush) >= 0) {
			kcp->ts_flush = kcp->current + kcp->interval;
		}
		ikcp_flush(kcp);
	}
}


//---------------------------------------------------------------------
// Determines when you should invoke ikcp_update next:
// returns the timestamp (in milliseconds) at which you should call
// ikcp_update, assuming no ikcp_input/_send calls occur in between.
// You can call ikcp_update at that time instead of calling it repeatedly.
// Important for reducing unnecessary ikcp_update invocations. Use it to
// schedule ikcp_update (e.g., implementing an epoll-like mechanism,
// or optimizing ikcp_update when handling massive kcp connections).
//---------------------------------------------------------------------
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current)
{
	IUINT32 ts_flush = kcp->ts_flush;
	IINT32 tm_flush = 0x7fffffff;
	IINT32 tm_packet = 0x7fffffff;
	IUINT32 minimal = 0;
	struct IQUEUEHEAD *p;

	if (kcp->updated == 0) {
		return current;
	}

	if (_itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000) {
		ts_flush = current;
	}

	if (_itimediff(current, ts_flush) >= 0) {
		return current;
	}

	tm_flush = _itimediff(ts_flush, current);

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		IINT32 diff = _itimediff(seg->resendts, current);
		if (diff <= 0) {
			return current;
		}
		if (diff < tm_packet) tm_packet = diff;
	}

	minimal = (IUINT32)(tm_packet < tm_flush ? tm_packet : tm_flush);
	if (minimal >= kcp->interval) minimal = kcp->interval;

	return current + minimal;
}



//---------------------------------------------------------------------
// ikcp_setmtu - 设置 KCP 最大传输单元 (MTU)
//
// 参数:
//   mtu: 新的 MTU 值 (50 ~ 65535, 必须 >= IKCP_OVERHEAD)
//
// 流程:
//   1. 检查 mtu 合法性 (不能小于 IKCP_OVERHEAD=24)
//   2. 分配新的内部缓冲区 (大小为 (mtu+OVERHEAD)*3)
//   3. 更新 mss = mtu - IKCP_OVERHEAD
//---------------------------------------------------------------------
int ikcp_setmtu(ikcpcb *kcp, int mtu)
{
	char *buffer;
	if (mtu < 50 || mtu < (int)IKCP_OVERHEAD) 
		return -1;
	/* C17: 添加上界检查，防止 (mtu+IKCP_OVERHEAD)*3 整数溢出。
	 * 16000 远大于实际使用场景 (≤1500)，足够安全。 */
	if (mtu > 16000)
		return -1;
	buffer = (char*)ikcp_malloc((mtu + IKCP_OVERHEAD) * 3);
	if (buffer == NULL) 
		return -2;
	kcp->mtu = mtu;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	ikcp_free(kcp->buffer);
	kcp->buffer = buffer;
	return 0;
}

int ikcp_interval(ikcpcb *kcp, int interval)
{
	if (interval > 5000) interval = 5000;
	else if (interval < 10) interval = 10;
	kcp->interval = interval;
	return 0;
}

//---------------------------------------------------------------------
// ikcp_nodelay - 配置 KCP nodelay 模式参数
//
// 参数:
//   nodelay:  0=普通模式 / 1=nodelay模式 (更低的RTO)
//   interval: 内部更新间隔 (ms), 范围 [10, 5000]
//   resend:   快速重传阈值 (收到此数量的重复ACK触发快速重传)
//   nc:       是否禁用拥塞控制 (0=启用 / 1=禁用)
//
// nodelay=1 时 RTO 最小值从 100ms 降至 30ms (IKCP_RTO_NDL)
//---------------------------------------------------------------------
int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc)
{
	if (nodelay >= 0) {
		kcp->nodelay = nodelay;
		if (nodelay) {
			kcp->rx_minrto = IKCP_RTO_NDL;	
		}	
		else {
			kcp->rx_minrto = IKCP_RTO_MIN;
		}
	}
	if (interval >= 0) {
		if (interval > 5000) interval = 5000;
		else if (interval < 10) interval = 10;
		kcp->interval = interval;
	}
	if (resend >= 0) {
		kcp->fastresend = resend;
	} else {
		/* H19: 负数 resend 参数不应静默忽略。设为默认值
		 * resend=0 (禁用快速重传), nc=0 (启用拥塞控制)。 */
		kcp->fastresend = 0;
	}
	if (nc >= 0) {
		kcp->nocwnd = nc;
	} else {
		kcp->nocwnd = 0;
	}
	return 0;
}


//---------------------------------------------------------------------
// ikcp_wndsize - 设置 KCP 发送/接收窗口大小
//
// 参数:
//   sndwnd: 发送窗口大小 (>0 有效)
//   rcvwnd: 接收窗口大小 (>0 有效, 自动调整为 >= IKCP_WND_RCV=128)
//---------------------------------------------------------------------
int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd)
{
	if (kcp) {
		/* H18: 添加上界检查，防止超大窗口（如 2^31）导致死循环或 OOM。
		 * 32768 远大于实际使用场景，安全无副作用。 */
		if (sndwnd > 0) {
			if (sndwnd > 32768) sndwnd = 32768;
			kcp->snd_wnd = sndwnd;
		}
		if (rcvwnd > 0) {   // must >= max fragment size
			if (rcvwnd > 32768) rcvwnd = 32768;
			kcp->rcv_wnd = _imax_(rcvwnd, IKCP_WND_RCV);
		}
	}
	return 0;
}

//---------------------------------------------------------------------
// ikcp_waitsnd - 获取 KCP 等待发送的字节数
//
// 返回值: nsnd_buf (发送缓冲区中的段数) + nsnd_que (发送队列中的段数)
// 用于判断是否需要继续调用 ikcp_update 来刷新数据
//---------------------------------------------------------------------
int ikcp_waitsnd(const ikcpcb *kcp)
{
	return kcp->nsnd_buf + kcp->nsnd_que;
}


// read conv
IUINT32 ikcp_getconv(const void *ptr)
{
	IUINT32 conv;
	ikcp_decode32u((const char*)ptr, &conv);
	return conv;
}


//---------------------------------------------------------------------
// install congestion control
//---------------------------------------------------------------------
int ikcp_setcc(ikcpcb *kcp, const struct IKCPOPS *ops)
{
	assert(kcp);
	if (kcp->ccops && kcp->ccops->release) {
		kcp->ccops->release(kcp);
	}
	kcp->congest = NULL;
	kcp->ccops = ops;
	if (ops) {
		if (ops->init) {
			if (ops->init(kcp) < 0) {
				kcp->ccops = NULL;
				kcp->congest = NULL;
				if (kcp->cwnd < 1) kcp->cwnd = 1;
				kcp->incr = kcp->cwnd * kcp->mss;
				return -1;
			}
		}
	}
	else {
		if (kcp->cwnd < 1) kcp->cwnd = 1;
		kcp->incr = kcp->cwnd * kcp->mss;
		if (kcp->incr < kcp->mss) kcp->incr = kcp->mss;
	}
	return 0;
}



