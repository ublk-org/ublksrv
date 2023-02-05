// SPDX-License-Identifier: GPL-2.0
#ifndef UBLK_QCOW2_COMMON_H_
#define UBLK_QCOW2_COMMON_H_

#include "ublksrv_tgt.h"

#define qcow2_assert(x)  ublk_assert(x)

#ifdef DEBUG
#define QCOW2_DEBUG  DEBUG
#else
#undef QCOW2_DEBUG
#endif

#define UBLK_DBG_QCOW2_FLUSH   (1U << 16)
#define UBLK_DBG_QCOW2_META_L2  (1U << 17)
#define UBLK_DBG_QCOW2_META_L1  (1U << 18)
#define UBLK_DBG_QCOW2_META_RB  (1U << 19)
#define UBLK_DBG_QCOW2_IO_WAITER  (1U << 20)
#define UBLK_DBG_QCOW2_ALLOCATOR  (1U << 21)

#define UBLK_DBG_QCOW2_META (UBLK_DBG_QCOW2_META_L2 | UBLK_DBG_QCOW2_META_RB)

enum QCOW2_PARA {
#ifdef DEBUG_QCOW2_META_STRESS
	REFCOUNT_BLK_MAX_CACHE_BYTES = 8U << 10,
#else
	REFCOUNT_BLK_MAX_CACHE_BYTES = 256U << 10,
#endif
	REFCOUNT_BLK_SLICE_BITS = 12,
	REFCOUNT_BLK_SLICE_BYTES = 1U << REFCOUNT_BLK_SLICE_BITS,

#ifdef DEBUG_QCOW2_META_STRESS
	L2_TABLE_MAX_CACHE_BYTES = 1U << 13,
#else
	L2_TABLE_MAX_CACHE_BYTES = 1U << 20,
#endif
	L2_TABLE_SLICE_BITS = 12,
	L2_TABLE_SLICE_BYTES = 1U << L2_TABLE_SLICE_BITS,

#ifdef DEBUG_QCOW2_META_STRESS
	META_MAX_TAGS = 1,
#else
	META_MAX_TAGS = 16,
#endif
	//at most 500ms delay if not any slice is running of
	//lru cache, otherwise the flush is started immediately
	MAX_META_FLUSH_DELAY_MS = 500,
};

#define qcow2_log ublk_log

//be careful
//#DEBUG_QCOW2_META_OBJ, still required for some meta debug

#ifdef QCOW2_DEBUG
static inline void alloc_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    ublk_dbg(UBLK_DBG_QCOW2_ALLOCATOR, fmt, ap);
}

static inline void flush_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    ublk_dbg(UBLK_DBG_QCOW2_FLUSH, fmt, ap);
}

static inline void qcow2_io_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    ublk_dbg(UBLK_DBG_IO, fmt, ap);
}

#else
#define alloc_log(...)  do {}while(0)
#define flush_log(...)  do {}while(0)
#define qcow2_io_log(...)  do {}while(0)
#endif

/*
 * 00 ~ 11: tag
 * 12 ~ 23: qid
 * 24 ~ 31: type_id, 0 ~ 254: meta, 255: data,
 * 	so which meta data can be looked up via this type_id in each io
 */
class qcow2_io_ctx_t {
public:
	u32 data;

	u32 get_tag() const {
		return data & 0xfff;
	}

	u32 get_qid() const {
		return (data >> 12) & 0xfff;
	}

	u32 get_type() const {
		return (data >> 24) & 0xff;
	}

	void set_type(u8 type) {
		data &= 0x00ffffff;
		data |= type << 24;
	}

	qcow2_io_ctx_t() {
		data = 255U << 24;
	}
	qcow2_io_ctx_t(u32 val) {
		data = val;
	}
	qcow2_io_ctx_t(u32 tag, u32 qid) {
		data = (qid << 12) | tag;
	}
	qcow2_io_ctx_t(u32 tag, u32 qid, u8 type) {
		data = (type << 24) | (qid << 12) | tag;
	}
	qcow2_io_ctx_t operator=(const u32 val) {
		return qcow2_io_ctx_t(val);
	}
};


//L1 max size is 32MB which can have 4M entries, so at most 22 bits
//needed, so define QCOW2_TAG_BITS as 10, so the upper 22 bits can
//hold entry index.
#define	QCOW2_TAG_BITS	10
#define	QCOW2_MAX_QUEUE_DEPTH	(1U<<10)

class IOWaiters {
private:
	//io waiters for this meta data, once this meta is updated,
	//call resume() on each io in io_waiters, so before io ctx
	//is waiting, it has to be added to io_waiters.
	//
	//Support to wait on single entry update, and the entry index
	//is stored in bit 31~12, tag is stored in bit 11~0. All one
	//entry index means that waitting on whole meta data.
	//
	std::unordered_set<unsigned int> io_waiters;

	void __mapping_meta_add_waiter(unsigned tag, unsigned entry_idx) {
		unsigned val;

		qcow2_assert(!(tag & ~(QCOW2_MAX_QUEUE_DEPTH - 1)));
		qcow2_assert(!(entry_idx & ~((1U << (32 - QCOW2_TAG_BITS)) - 1)));

		val = tag | (entry_idx << QCOW2_TAG_BITS);
		io_waiters.insert(val);
	}
	void __mapping_meta_wakeup_all(const struct ublksrv_queue *q,
			unsigned my_tag, unsigned entry_idx, bool all);
public:
	IOWaiters();
	void add_waiter(unsigned tag);
	void add_waiter_idx(unsigned tag, unsigned entry_idx);
	void wakeup_all(const struct ublksrv_queue *q, unsigned my_tag);
	void wakeup_all_idx(const struct ublksrv_queue *q,
			unsigned my_tag, unsigned entry_idx);
};

#endif
