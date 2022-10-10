// SPDX-License-Identifier: GPL-2.0
#ifndef UBLK_QCOW2_H_
#define UBLK_QCOW2_H_

#include <string>
#include <iostream>
#include <valarray>
#include <unordered_set>
#include <unordered_map>
#include <bits/stdc++.h>
#include <exception>
#include <chrono>
#include "qcow2_format.h"
#include "ublksrv_priv.h"
#include "lrucache.hpp"
#include "ublksrv_tgt.h"

#define qcow2_assert(x)  do { \
	if (!(x)) {	\
		syslog(LOG_ERR, "%s %d: assert!\n", __func__, __LINE__); \
		assert(x);	\
	}	\
} while (0)

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

static inline void qcow2_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(LOG_INFO, fmt, ap);
}

#ifdef DEBUG_QCOW2_META_OBJ
#define meta_log  qcow2_log
#else
#define meta_log(...)  do {}while(0)
#endif

#ifdef DEBUG_QCOW2_ALLOCATOR
#define alloc_log  qcow2_log
#else
#define alloc_log(...)  do {}while(0)
#endif

#ifdef DEBUG_QCOW2_META_FLUSH
#define flush_log  qcow2_log
#else
#define flush_log(...)  do {}while(0)
#endif

#ifdef DEBUG_QCOW2_IO
#define qcow2_io_log  qcow2_log
#else
#define qcow2_io_log(...)  do {}while(0)
#endif

class Qcow2State;
class Qcow2Header;

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

/*
 * Class design:
 * 1) copy constructor / operator assign overloading / 
 *
 * 2) one friend function for dumping object
 *
 *
 * Loading meta:
 *
 *
 * Flushing meta:
 */
class Qcow2Meta {
protected:
#ifdef DEBUG_QCOW2_META_OBJ
	const char *id;
#endif
	Qcow2Header	&header;
	void *addr;	//buffer address
	u64   offset;	//offset in host image
	u32   buf_sz;	//buffer size
	u32   data_len; //current data length in the buffer, valid iff update is
			//true

#define QCOW2_META_DIRTY    (1U << 0)
#define QCOW2_META_UPDATE   (1U << 1)

//l1 & refcount table is top meta, set in constructor, should only
//be used for flush meta
#define QCOW2_META_TOP       (1U << 2)

//the meta slice is being flushed to image
#define QCOW2_META_FLUSHING  (1U << 3)

#define QCOW2_META_PREP_FLUSH (1U << 4)

//set for L1/L2 meta
#define QCOW2_META_MAPPING   (1U << 5)

//evicted from lru cache, and may be in loading or flushing, and will
//be freed after loading or flushing is done.
//
//But can't be re-dirtied any more, so slice marked as EVICTED is readonly
#define QCOW2_META_EVICTED   (1U << 7)
	u32	flags;

	int	refcnt;
public:
	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
			u32 len);
	Qcow2Meta(Qcow2Header &h, u64 off, u32 buf_sz, const char *, u32 f);
	virtual ~Qcow2Meta();
	void zero_buf();
	virtual void show(const char *f = "", int line = 0);

#ifdef DEBUG_QCOW2_META_OBJ
	const char *get_id() {
		return id;
	}
#endif
	void set_evicted() {
		flags |= QCOW2_META_EVICTED;
	}
	bool get_evicted() {
		return flags & QCOW2_META_EVICTED;
	}

	void set_dirty(unsigned int idx, bool val) {
		if (val)
			flags |= QCOW2_META_DIRTY;
		else
			flags &= ~QCOW2_META_DIRTY;
	}

	bool get_dirty(unsigned int idx) const {
		return flags & QCOW2_META_DIRTY;
	}

	u64 get_offset() const {
		return offset;
	}

	u64 get_buf_size() const {
		return buf_sz;
	}

	u32 get_data_len() const {
		return data_len;
	}
	bool get_update() const {
		return !!(flags & QCOW2_META_UPDATE);
	}
	void set_update(bool val) {
		if (val)
			flags |= QCOW2_META_UPDATE;
		else
			flags &= ~QCOW2_META_UPDATE;
	}

	bool is_top_meta() const
	{
		return !!(flags & QCOW2_META_TOP);
	}

	bool is_mapping_meta() const
	{
		return !!(flags & QCOW2_META_MAPPING);
	}

	bool is_flushing() const {
		return !!(flags & QCOW2_META_FLUSHING);
	}

	unsigned get_flags() const {
		return flags;
	}

	int read_ref() const {
		return refcnt;
	}

	bool get_prep_flush() const {
		return !!(flags & QCOW2_META_PREP_FLUSH);
	}

	void set_prep_flush(bool val)
	{
		if (val)
			flags |= QCOW2_META_PREP_FLUSH;
		else
			flags &= ~QCOW2_META_PREP_FLUSH;
	}
};

#define  QCOW2_EXT_MAGIC_END 0
#define  QCOW2_EXT_MAGIC_BACKING_FORMAT 0xe2792aca
#define  QCOW2_EXT_MAGIC_FEATURE_TABLE 0x6803f857
#define  QCOW2_EXT_MAGIC_CRYPTO_HEADER 0x0537be77
#define  QCOW2_EXT_MAGIC_BITMAPS 0x23852875
#define  QCOW2_EXT_MAGIC_DATA_FILE 0x44415441

class Qcow2HeaderExt {
private:
	u64 offset;
public:
	u32 type;
	u32 len;

	Qcow2HeaderExt(char *addr, u64 off): offset(off)
	{
		u32 *buf = (u32 *)(addr + offset);
		type = be32_to_cpu(buf[0]);

		buf = (u32 *)(addr + offset + 4);
		len = be32_to_cpu(buf[0]);
	}

	virtual void dump() const
	{
		syslog(LOG_INFO,"%s: type %x len %d\n",
				typeid(*this).name(), type, len);
	}
};

class Qcow2HeaderExtString : public Qcow2HeaderExt {
public:
	std::string str;

	Qcow2HeaderExtString(char *addr, u64 offset):
		Qcow2HeaderExt(addr, offset), str((char *)addr, 0, len)
	{
	}

	virtual void dump() const
	{
		syslog(LOG_INFO,"%s: type %x len %d string %s\n",
				typeid(*this).name(), type, len, str.c_str());
	}
};

class Qcow2HeaderExtFeatureNameTable : public Qcow2HeaderExt {
public:
	struct feature_entry {
		char feature_type;
		char bit_num;
		char feature_name[46];
	};
	typedef std::valarray<feature_entry> ArrayFeature;
	ArrayFeature __a;

	Qcow2HeaderExtFeatureNameTable(char *addr, u64 offset);
	~Qcow2HeaderExtFeatureNameTable() {};
	void dump() const;
};

class Qcow2HeaderExtBitmaps : public Qcow2HeaderExt {
public:
	u32  nr_bitmap;
	u64  bitmap_directory_size;
	u64  bitmap_directory_offset;
	Qcow2HeaderExtBitmaps(char *addr, u64 offset):
		Qcow2HeaderExt(addr, offset)
	{
		nr_bitmap = be32_to_cpu(*(u32 *)(addr + offset + 8));
		bitmap_directory_size = be64_to_cpu(*(u64 *)(addr +
					offset + 12));
		bitmap_directory_offset = be64_to_cpu(*(u64 *)(addr +
					offset + 20));
	}
	virtual void dump() const
	{
		syslog(LOG_INFO,"%s: type %x len %d nr_bitmap %d bitmap_dir(offset %lx sz %lu)\n",
				typeid(*this).name(), type, len,
				nr_bitmap, bitmap_directory_offset,
				bitmap_directory_size);
	}
};

class Qcow2HeaderExtEncHeader : public Qcow2HeaderExt {
public:
	u64  enc_offset;
	u64  enc_len;
	Qcow2HeaderExtEncHeader(char *addr, u64 offset):
		Qcow2HeaderExt(addr, offset)
	{
		enc_offset = be64_to_cpu(*(u64 *)(addr +
					offset + 8));
		enc_len = be64_to_cpu(*(u64 *)(addr +
					offset + 16));
	}
	virtual void dump() const
	{
		syslog(LOG_INFO,"%s: type %x len %d enc(offset %llx sz %lu)\n",
				typeid(*this).name(), type, len,
				enc_offset, enc_len);
	}
};

#define __INLINE_SET_GET(type, prop, v2_val)			\
type get_##prop() const						\
{								\
	if (offsetof(QCowHeader, prop) >= 72 && version == 2)	\
		return v2_val;					\
	switch(sizeof(type)) {					\
	case 8:							\
		return be64_to_cpu(((QCowHeader*)addr)->prop);	\
	case 4:							\
		return be32_to_cpu(((QCowHeader*)addr)->prop);	\
	case 2:							\
		return be16_to_cpu(((QCowHeader*)addr)->prop);	\
	case 1:							\
		return ((QCowHeader*)addr)->prop;		\
	}							\
}								\
void set_##prop(type v)						\
{								\
	QCowHeader *h = (QCowHeader *)addr;			\
	if (offsetof(QCowHeader, prop) >= 72 && version == 2)	\
		return;						\
	switch(sizeof(type)) {					\
	case 8:							\
		h->prop = cpu_to_be64(v);			\
		break;						\
	case 4:							\
		h->prop = cpu_to_be32(v);			\
		break;						\
	case 2:							\
		h->prop = cpu_to_be16(v);			\
		break;						\
	case 1:							\
		h->prop = v;					\
		break;						\
	}							\
	Qcow2Meta::set_dirty(-1, true);				\
}

#define INLINE_SET_GET(type, prop) __INLINE_SET_GET(type, prop, 0)

class Qcow2Header: public Qcow2Meta {
private:
	int populate();
	Qcow2HeaderExtString		*backingfile_format_name;
	Qcow2HeaderExtString		*ext_data_file_name;
	Qcow2HeaderExtFeatureNameTable	*feature_name_table;
	Qcow2HeaderExtBitmaps		*bitmaps;
	Qcow2HeaderExtEncHeader		*enc_header_pointer;
public:
	const u32 magic;
	const u32 version;
	const u32 cluster_bits;
	const u32 refcount_order;

	//this way looks ugly, but just for retrieve qs in destructor of
	//Qcow2SliceMeta
	Qcow2State &qs;

	Qcow2Header(Qcow2State &qs);
	virtual ~Qcow2Header();
	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
			u32 len);
	void dump_ext() const;

	INLINE_SET_GET(u32, magic);
	INLINE_SET_GET(u32, version);
	INLINE_SET_GET(u64, backing_file_offset);
	INLINE_SET_GET(u32, backing_file_size);
	INLINE_SET_GET(u32, cluster_bits);
	INLINE_SET_GET(u64, size);
	INLINE_SET_GET(u32, crypt_method);
	INLINE_SET_GET(u32, l1_size);
	INLINE_SET_GET(u64, l1_table_offset);
	INLINE_SET_GET(u64, refcount_table_offset);
	INLINE_SET_GET(u32, refcount_table_clusters);
	INLINE_SET_GET(u32, nb_snapshots);
	INLINE_SET_GET(u64, snapshots_offset);
	__INLINE_SET_GET(u64, incompatible_features, 0);
	__INLINE_SET_GET(u64, compatible_features, 0);
	__INLINE_SET_GET(u64, autoclear_features, 0);
	__INLINE_SET_GET(u32, refcount_order, 4);
	__INLINE_SET_GET(u32, header_length, 72);
	__INLINE_SET_GET(u8, compression_type, 0);

	friend std::ostream & operator<<(std::ostream &os, const Qcow2Header &h);

	bool is_extended_l2_entries() {
		return get_incompatible_features() & 0x8;
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
	void __mapping_meta_wakeup_all(struct ublksrv_queue *q,
			unsigned my_tag, unsigned entry_idx, bool all);
public:
	IOWaiters();
	void add_waiter(unsigned tag);
	void add_waiter_idx(unsigned tag, unsigned entry_idx);
	void wakeup_all(struct ublksrv_queue *q, unsigned my_tag);
	void wakeup_all_idx(struct ublksrv_queue *q,
			unsigned my_tag, unsigned entry_idx);
};

class Qcow2MappingMeta: public Qcow2Meta {
private:
	IOWaiters io_waiters;
protected:
	u32 entry_bits_order;
	s32 next_free_idx;	//cache the next free idx

	//deprecate now
	bool entry_val_is_dirty(u64 val) {
		qcow2_assert(false);
		return true;
	}

	int __flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
		u64 off, u32 len, bool run_fsync = false);
	int clear_dirty_entries(Qcow2State &qs,
		const qcow2_io_ctx_t &ioc, u64 off, u32 len);
public:
	Qcow2MappingMeta(Qcow2State &qs, u64 off, u32 buf_sz,
			const char *cls_name, u32 f);
	s32 get_nr_entries() {
		return (buf_sz << 3) >> entry_bits_order;
	}
	s32 get_next_free_idx() {
		return next_free_idx;
	}
	void set_next_free_idx(s32 idx) {
		if (idx < get_nr_entries())
			next_free_idx = idx;
	}

	void add_waiter(unsigned tag) {
		io_waiters.add_waiter(tag);
	}

	void add_waiter_idx(unsigned tag, unsigned entry_idx) {
		io_waiters.add_waiter_idx(tag, entry_idx);
	}

	void wakeup_all(struct ublksrv_queue *q, unsigned my_tag) {
		io_waiters.wakeup_all(q, my_tag);
	}

	void wakeup_all_idx(struct ublksrv_queue *q,
			unsigned my_tag, unsigned entry_idx) {
		io_waiters.wakeup_all_idx(q, my_tag, entry_idx);
	}

	virtual u64  get_entry(u32 idx) = 0;
	virtual void set_entry(u32 idx, u64 val) = 0;
	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
			u32 len) = 0;

	//both load() and flush() should be async, and done() needs to be called
	//after both load() and flush() meta IO are done.
	virtual void io_done(Qcow2State &qs, struct ublksrv_queue *q,
			struct io_uring_cqe *cqe);
};

class Qcow2TopTable: public Qcow2MappingMeta {
private:
	u32 flush_blk_idx;

protected:
	u32 min_bs_bits;
	std::vector <bool> dirty;
public:
	Qcow2TopTable(Qcow2State &qs, u64 off, u32 buf_sz,
			const char *cls_name, u32 f);

	bool is_flushing(u32 idx) {
		if (Qcow2Meta::is_flushing() && idx == flush_blk_idx)
			return true;
		return false;
	}

	bool get_blk_dirty(u32 idx)
	{
		return dirty[idx];
	}

	void set_blk_dirty(u32 idx, bool val)
	{
		dirty[idx] = val;
	}

	u32 dirty_blks() {
		u32 total = 0;

		for (int i = 0; i < dirty.size(); i++)
			if (dirty[i])
				total += 1;
		return total;
	}

	u32 dirty_blk_size() {
		return dirty.size();
	}

	int get_1st_dirty_blk() {
		for (int i = 0; i < dirty.size(); i++)
			if (dirty[i])
				return i;
		return -1;
	}

	void set_flush_blk_idx(u32 idx)
	{
		flush_blk_idx = idx;
	}

	u32 get_flush_blk_idx()
	{
		return flush_blk_idx;
	}

	u64 single_entry_order() const
	{
		if (is_mapping_meta())
			return (2 * header.cluster_bits - 3);
		return 2 * header.cluster_bits + 3 - header.refcount_order;
	}

	bool prep_flush(const qcow2_io_ctx_t &ioc, u32 blk_idx);
	void unprep_flush(u32 blk_idx);

	virtual void io_done(Qcow2State &qs, struct ublksrv_queue *q,
			struct io_uring_cqe *);
	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off, u32 len);
	bool has_dirty_slices(Qcow2State &qs, int idx);
};

//allocating detection needs to review!!!
class Qcow2L1Table: public Qcow2TopTable {
public:
	u32  offset_to_idx(u64 virt_offset) {
		u32 cluster_bits = header.cluster_bits;
		bool has_extended_l2_entries = header.is_extended_l2_entries();
		u32 idx = (virt_offset >> cluster_bits) >>
			(cluster_bits - 3 - !!has_extended_l2_entries);

		return idx;
	}

	u64  get_entry_fast(u32 idx) {
		u64 val = be64_to_cpu(((const u64 *)addr)[idx]);

		return val;
	}

	void set_entry_fast(u32 idx, u64 val) {
		unsigned i = idx >> (min_bs_bits - 3);

		((u64 *)addr)[idx] = cpu_to_be64(val);
		set_dirty(idx, true);

		qcow2_assert(i < dirty.size());
		dirty[i] = true;
	}

	bool entry_allocated(u64 entry) {
		return entry != 0;
	}

	bool entry_is_dirty(u32 idx) {
		return entry_val_is_dirty(get_entry(idx));
	}

	Qcow2L1Table(Qcow2State &qs);
	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
	virtual u64  get_entry(u32 idx);
	virtual void set_entry(u32 idx, u64 val);
	void dump();
};

class Qcow2RefcountTable: public Qcow2TopTable {
public:
	u32  offset_to_idx(u64 virt_offset) {
		u32 cluster_bits = header.cluster_bits;
		u32 idx = (virt_offset >> cluster_bits) >>
			(cluster_bits + 3 - header.refcount_order);

		return idx;
	}
	void set_entry_fast(u32 idx, u64 val) {
		unsigned i = idx >> (min_bs_bits - 3);

		((u64 *)addr)[idx] = cpu_to_be64(val);
		set_dirty(idx, true);

		qcow2_assert(i < dirty.size());
		dirty[i] = true;
	}
	u64  get_entry_fast(u32 idx) {
		return be64_to_cpu(((u64 *)addr)[idx]);
	}
	bool entry_is_dirty(u32 idx) {
		return entry_val_is_dirty(get_entry(idx));
	}

	Qcow2RefcountTable(Qcow2State &qs);
	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
	virtual u64  get_entry(u32 idx);
	virtual void set_entry(u32 idx, u64 val);
	void dump();
};

class Qcow2SliceMeta: public Qcow2MappingMeta {
protected:
	bool prep_flush(const qcow2_io_ctx_t &ioc);
	void unprep_flush();
#ifdef DEBUG_QCOW2_META_VALIDATE
	void *validate_addr;
#endif
public:
	unsigned int parent_idx; //parent's this entry points to us

	Qcow2SliceMeta(Qcow2State &qs, u64 off, u32 buf_sz,
			const char *cls_name, u32 p_idx, u32 f);
	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
			u32 len) = 0;
	virtual void dump() = 0;
	virtual ~Qcow2SliceMeta();
	virtual void get_dirty_range(u64 *start, u64 *end) = 0;

	//both load() and flush() should be async, and done() needs to be called
	//after both load() and flush() meta IO are done.
	virtual void io_done(Qcow2State &qs, struct ublksrv_queue *q,
			struct io_uring_cqe *cqe);
	int zero_my_cluster(Qcow2State &qs, const qcow2_io_ctx_t &ioc);

	u64 get_offset() const {
		return offset;
	}

	void get_ref() {
		qcow2_assert(refcnt > 0);
		refcnt += 1;
	}

	void put_ref() {
		qcow2_assert(refcnt > 0);
		if (--refcnt == 0)
			delete this;
	}
#ifdef DEBUG_QCOW2_META_VALIDATE
	void io_done_validate(Qcow2State &qs, struct ublksrv_queue *q,
			struct io_uring_cqe *cqe);
#else
	void io_done_validate(Qcow2State &qs, struct ublksrv_queue *q,
			struct io_uring_cqe *cqe) {}
#endif
};

class Qcow2RefcountBlock: public Qcow2SliceMeta {
private:
	virtual void wait_clusters(Qcow2State &qs, const qcow2_io_ctx_t &ioc);
public:
	unsigned dirty_start_idx;
	u64  get_entry_fast(u32 idx) {
		switch (header.refcount_order) {
		case 0:
		return (((const u8 *)addr)[idx / 8] >> (idx % 8)) & 0x1;

		case 1:
		return (((const u8 *)addr)[idx / 4] >> (2 * (idx % 4))) & 0x3;

		case 2:
		return (((const u8 *)addr)[idx / 2] >> (4 * (idx % 2))) & 0xf;

		case 3:
		return ((const u8 *)addr)[idx];

		case 4:
		return be16_to_cpu(((const u16 *)addr)[idx]);

		case 5:
		return be32_to_cpu(((const u32 *)addr)[idx]);

		case 6:
		return be64_to_cpu(((const u64 *)addr)[idx]);
		}
		return 0;
	}

	void set_entry_fast(u32 idx, u64 val) {
		switch (header.refcount_order) {
		case 0:
			qcow2_assert(!(val >> 1));
			((u8 *)addr)[idx / 8] &= ~(0x1 << (idx % 8));
			((u8 *)addr)[idx / 8] |= val << (idx % 8);
			break;
		case 1:
			qcow2_assert(!(val >> 2));
			((u8 *)addr)[idx / 4] &= ~(0x3 << (2 * (idx % 4)));
			((u8 *)addr)[idx / 4] |= val << (2 * (idx % 4));
			break;
		case 2:
			qcow2_assert(!(val >> 4));
			((u8 *)addr)[idx / 2] &= ~(0xf << (4 * (idx % 2)));
			((u8 *)addr)[idx / 2] |= val << (4 * (idx % 2));
			break;
		case 3:
			qcow2_assert(!(val >> 8));
			((u8 *)addr)[idx] = val;
			break;
		case 4:
			qcow2_assert(!(val >> 16));
			((u16 *)addr)[idx] = cpu_to_be16(val);
			break;
		case 5:
			qcow2_assert(!(val >> 32));
			((u32 *)addr)[idx] = cpu_to_be32(val);
			break;
		case 6:
			((u64 *)addr)[idx] = cpu_to_be64(val);
			break;
		}
		set_dirty(idx, true);
		if (dirty_start_idx == ((unsigned)-1))
			dirty_start_idx = idx;
	}

	u32 entries_order() {
		return header.cluster_bits + 3 - header.refcount_order;
	}

	u64 virt_offset()
	{
		const u64 single_entry_order = entries_order() +
			header.cluster_bits;
		u32 slice_idx = (offset & ((1U << header.cluster_bits) - 1)) >>
			QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS;
		u32 slice_virt_bits = header.cluster_bits + 3 - header.refcount_order +
		QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS;

		return ((u64)parent_idx << single_entry_order) + ((u64)slice_idx <<
				slice_virt_bits);
	}

	bool entry_is_dirty(u32 idx) {
		return idx >= dirty_start_idx;
	}

	Qcow2RefcountBlock(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
	virtual ~Qcow2RefcountBlock();
	virtual u64  get_entry(u32 idx);
	virtual void set_entry(u32 idx, u64 val);
	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
			u32 len);
	virtual void dump();
	virtual void get_dirty_range(u64 *start, u64 *end);
};

//allocating detection needs to review!!!
class Qcow2L2Table: public Qcow2SliceMeta {
private:
	//the two is valid only iff this slice is dirty
	u64 dirty_start, dirty_end;
	virtual void wait_clusters(Qcow2State &qs, const qcow2_io_ctx_t &ioc);
public:
	u64  get_entry_fast(u32 idx) {
		u64 val = be64_to_cpu(((const u64 *)addr)[idx]);

		return val;
	}

	u64  get_extended_entry(u32 idx) {
		return 0;
	}

	void set_entry_fast(u32 idx, u64 val) {
		((u64 *)addr)[idx] = cpu_to_be64(val);
		set_dirty(idx, true);
	}

	bool entry_allocated(u64 entry) {
		return entry != 0;
	}

	u64 virt_offset()
	{
		u64 base = ((u64)parent_idx) << (header.cluster_bits - 3 +
				header.cluster_bits);
		u64 clusters = (get_offset() &
				((1ULL << header.cluster_bits) - 1)) >> 3;

		return base + (clusters << header.cluster_bits);
	}
	bool entry_is_dirty(u32 idx) {
		return entry_val_is_dirty(get_entry(idx));
	}

	Qcow2L2Table(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
	virtual ~Qcow2L2Table();
	virtual u64  get_entry(u32 idx);
	virtual void set_entry(u32 idx, u64 val);
	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
			u32 len);
	virtual void dump();
	virtual void get_dirty_range(u64 *start, u64 *end);
	//virtual int flush(Qcow2State &qs, qcow2_io_ctx_t ioc, bool auto_free = false);
	virtual void io_done(Qcow2State &qs, struct ublksrv_queue *q,
			struct io_uring_cqe *cqe);
#ifdef DEBUG_QCOW2_META_VALIDATE
	void check(Qcow2State &qs, const char *func, int line);
	void check_duplicated_clusters(Qcow2State &qs, int tag,
			const char *func, int line);
#else
	void check(Qcow2State &qs, const char *func, int line) {}
	void check_duplicated_clusters(Qcow2State &qs, int tag,
			const char *func, int line) {}
#endif
};

/*
 * Design overview
 *
 * 1) code reuse:
 *    - such as code can be reused as one libqcow2
 *
 *    - internal implementation maximize reusing design & code	
 *
 * 2) io isolation: io handling code often depends on os or platform or
 * user choice, so io handling isolation is considered from the beginning;
 * but focus on aio style
 * 
 * 3) completely aio: for read/write io and meta
 */

/* MQ support:
 *
 * 1) how to share meta data among queues?  meta data has to be protected for
 * support MQ
 *
 * 2) we can start from SQ support.
 */

/*
 * Buffer management and cache design:
 *
 * 1) fixed amount of buffer is pre-allocated & shared for all l2 cache slice,
 * refcount blk, just like qcow2
 *
 * 2) fixed buffer is pre-allocated for header, l1, refcount table and other
 * kind of meta, but the buffer is dedicated
 *
 * Cache design(L2 table cache, refcount block cache):
 *
 * 1) why can't support for l1/refcount table
 *
 */

class MetaIoException: public std::exception
{
public:
	const char * what() { return "MetaIO exception"; }
};

class MetaUpdateException: public std::exception
{
public:
	const char * what() { return "MetaEntry update exception"; }
};

template <class T>
class slice_cache {
private:
	u8 slice_size_bits, cluster_size_bits, slice_virt_size_bits;

	cache::lru_cache<u64, T *> slices;
	std::unordered_map<u64, T *> evicted_slices;

	int __figure_group_for_flush(Qcow2State &qs);
	int figure_group_from_dirty_list(Qcow2State &qs);
public:
	unsigned get_nr_slices() {
		return 1U << (cluster_size_bits - slice_size_bits);
	}

	u64 get_slice_virt_size_bits() {
		return slice_virt_size_bits;
	}

	u64 get_slice_size_bits() {
		return slice_size_bits;
	}

	unsigned get_slices_size() {
		return slices.size();
	}

	unsigned get_evicted_slices_size() {
		return evicted_slices.size();
	}

	unsigned get_slice_idx(u64 virt_offset) {
		u32 nr_slices = 1ULL << (cluster_size_bits - slice_size_bits);
		const u64 virt_size = ((u64)nr_slices) << slice_virt_size_bits;
		u64 virt_base = virt_offset & ~(virt_size - 1);

		return (virt_offset - virt_base) >> slice_virt_size_bits;
	}

	T *find_slice(u64 key, bool use_evicted_cache) {
		T *t = slices.get(key);

		if (t)
			return t;

		if (use_evicted_cache) {
			auto it = evicted_slices.find(key);

			if (it != evicted_slices.end())
				return it->second;
		}
		return nullptr;
	}

	void remove_slice_from_evicted_list(T *t) {
		auto it = evicted_slices.find(t->virt_offset());

		if (it != evicted_slices.end())
			evicted_slices.erase(it);
	}

	//called in running flush contex
	bool has_evicted_dirty_slices()
	{
		if (evicted_slices.empty())
			return false;

		for (auto it = evicted_slices.cbegin(); it !=
				evicted_slices.cend(); ++it) {
			if (it->second->get_dirty(-1))
				return true;
		}
		return false;
	}

	slice_cache(u8 slice_bits, u8 cluster_bits, u8 slice_virt_bits,
			u32 max_size);

	//only called from meta flushing code path
	T *__find_slice(u64 key, bool use_evicted_cache);
	T *alloc_slice(Qcow2State& qs, const qcow2_io_ctx_t &ioc,
		u64 virt_offset, u64 host_offset, u32 parent_idx);
	void add_slice_to_evicted_list(u64 virt_offset, T *l2);
	void dump(Qcow2State &qs);
	int figure_group_for_flush(Qcow2State &qs);
};

/* todo: remove caches in destructor */
class Qcow2ClusterMapping {
private:
	Qcow2State &state;
	slice_cache <Qcow2L2Table> cache;

	u32 l2_entries_order, cluster_bits;

	//l1/l2 entry alloc state
	//
	//added before allocating one l1/l2 entry, and freed after
	//the allocation is done
	//
	//For l1, the key is (1ULL << 63) | offset & ~((1ULL << (cluster_bits + l2 entries bits)) - 1)
	//
	//for l2, the key is offset & ~((1ULL << cluster_bits) - 1)
	std::unordered_map<u64, u32> entry_alloc;
	u32 max_alloc_entries;

	u64 l2_slice_virt_size() {
		return 1ULL << (cluster_bits + L2_TABLE_SLICE_BITS - 3);
	}

	u64 l2_slice_key(u64 virt_offset) {
		return ((virt_offset) & ~(l2_slice_virt_size() - 1));
	}

	u32 __entry_get_alloc_state(u64 key) {
		auto it = entry_alloc.find(key);

		if (it != entry_alloc.end())
			return it->second;
		return -1;
	}

	bool __entry_is_allocating(u64 key) {
		u32 state = __entry_get_alloc_state(key);

		return state != -1;
	}

	void __entry_mark_allocating(u64 key, u32 owner) {
		auto it = entry_alloc.find(key);
		u32 sz;

		qcow2_assert(it == entry_alloc.end());

		entry_alloc[key] = owner;

		sz = entry_alloc.size();
		if (sz > max_alloc_entries)
			max_alloc_entries = sz;
	}

	void __entry_mark_allocated(u64 key) {
		auto it = entry_alloc.find(key);

		qcow2_assert(it != entry_alloc.end());

		entry_alloc.erase(it);
	}

	u64 l1_entry_alloc_key(u64 offset) {
		return (offset & ~((1ULL << (cluster_bits +
					     l2_entries_order)) - 1)) |
				(1ULL << 63);
	}

	u64 l2_entry_alloc_key(u64 offset) {
		u64 key = (offset & ~((1ULL << cluster_bits) - 1));

		qcow2_assert(!(key & (1ULL << 63)));
		return key;
	}

	u64 entry_alloc_key(u64 offset, bool l1) {
		if (l1)
			return l1_entry_alloc_key(offset);
		return l2_entry_alloc_key(offset);
	}

	bool entry_is_allocating(u64 offset, bool l1) {
		u64 key = entry_alloc_key(offset, l1);

		return __entry_is_allocating(key);
	}

	u32 entry_get_alloc_owner(u64 offset, bool l1) {
		u64 key = entry_alloc_key(offset, l1);
		u32 state = __entry_get_alloc_state(key);

		qcow2_assert(state != -1);
		return state;
	}

	void entry_mark_allocating(u64 offset, u32 owner, bool l1) {
		u64 key = entry_alloc_key(offset, l1);

		__entry_mark_allocating(key, owner);
	}

	void entry_mark_allocated(u64 offset, bool l1) {
		u64 key = entry_alloc_key(offset, l1);

		__entry_mark_allocated(key);
	}

	Qcow2L2Table *create_and_add_l2(const qcow2_io_ctx_t &ioc, u64 offset);
	Qcow2L2Table *load_l2_slice(const qcow2_io_ctx_t &ioc, u64 offset,
			u64 l1_entry);
	int build_mapping(const qcow2_io_ctx_t &ioc,
		u64 virt_offset, Qcow2L2Table *l2, u32 idx_in_slice,
		u64 *l2_entry);
	u64 __map_cluster(const qcow2_io_ctx_t &ioc,
		Qcow2L2Table *l2, u64 offset, bool create_l2);
	Qcow2L2Table *create_l2_map(const qcow2_io_ctx_t &ioc, u64 offset,
			bool create_l2);
public:
	// refcount table shouldn't be so big
	Qcow2ClusterMapping(Qcow2State &qs);

	//the main logic for mapping cluster
	//create l2 and setup the mapping if 'create_l2' is true & l2 isn't
	//present for this 'offset'
	u64 map_cluster(const qcow2_io_ctx_t &ioc, u64 offset, bool create_l2);
	int figure_group_from_l1_table();

	Qcow2L2Table* __find_slice(u64 key, bool use_dirty=true);

	u64 l1_idx(u64 offset) {
		return offset >> (cluster_bits + l2_entries_order);
	}

	u64 l2_idx(u64 offset) {
		return (offset >> cluster_bits) &
			((1ULL << l2_entries_order) - 1);
	}

	bool has_evicted_dirty_slices()
	{
		return cache.has_evicted_dirty_slices();
	}

	void remove_slice_from_evicted_list(Qcow2L2Table *t) {
		cache.remove_slice_from_evicted_list(t);
	}

	void dump_meta();
};

enum QCOW2_CLUSTER_USE {
	L2_TABLE = 0,
	REFCOUNT_BLK = 1,
	DATA = 2,
};

/*
 * Think about lifetime issue. Is it possible that one state is removed
 * but it is being used somewhere?
 *
 * So far the simple rule is that the state can only be removed after
 * its state becomes QCOW2_ALLOC_ZEROED.
 *
 * So except for being absolute safety, don't call get_cluster_state()
 * directly.
 */
class Qcow2ClusterState {
#define QCOW2_ALLOC_STARTED	0	//cluster allocated in ram
#define QCOW2_ALLOC_ZEROING	1	//IO for zeroing this cluster is submitted
#define QCOW2_ALLOC_ZEROED	2	//cluster zeroed
#define QCOW2_ALLOC_DONE	3	//mapping setup
private:
	u8 state;
	u8 purpose;
	IOWaiters io_waiters;

public:
	Qcow2ClusterState() {
		state = QCOW2_ALLOC_STARTED;
	}

	Qcow2ClusterState(u8 s, u8 p) {
		state = s;
		purpose = p;
	}

	//called after the cluster is allocated from ram
	u8 get_state() {
		return state;
	}

	void set_state(u8 s) {
		state = s;
	}

	u8 get_purpose() {
		return purpose;
	}

	void add_waiter(unsigned tag) {
		io_waiters.add_waiter(tag);
	}

	void wakeup_all(struct ublksrv_queue *q, unsigned my_tag) {
		io_waiters.wakeup_all(q, my_tag);
	}
};

/* todo: remove caches in destructor */
class Qcow2ClusterAllocator {
private:
	Qcow2State &state;
	s32 slice_idx;
	u8  table_entry_virt_size_bits;
	u64 alloc_cnt;
	slice_cache <Qcow2RefcountBlock> cache;

	u32 refcount_block_entries();
	void allocate_refcount_blk(const qcow2_io_ctx_t &ioc, s32 idx);

public:
	//key is cluster start offset, val is its allocate status
	std::unordered_map<u64, Qcow2ClusterState *> alloc_state;
	u32 max_alloc_states;
	u64 max_physical_size;

	// refcount table shouldn't be so big
	Qcow2ClusterAllocator(Qcow2State &qs);

	//called after refcount table is loaded
	void setup();
	u64 allocate_cluster(const qcow2_io_ctx_t &ioc);
	u64 refcount_blk_key(const Qcow2RefcountBlock *rb);
	void dump_meta();
	int figure_group_from_refcount_table();

	Qcow2RefcountBlock* __find_slice(u64 key);

	bool has_evicted_dirty_slices()
	{
		return cache.has_evicted_dirty_slices();
	}

	void remove_slice_from_evicted_list(Qcow2RefcountBlock *t) {
		cache.remove_slice_from_evicted_list(t);
	}

	/* the following helpers are for implementing soft update */

	//don't refer to one state after one cycle of coroutine wait &
	//wakeup, and caller has to check if the return value
	Qcow2ClusterState *get_cluster_state(u64 cluster_offset) {
		auto it = alloc_state.find(cluster_offset);

		if (it == alloc_state.end())
			return nullptr;

		return it->second;
	}

	//the zeroing io may return -EAGAIN, then we need to
	//reset its state for re-issuing zeroing IO
	bool alloc_cluster_reset(u64 cluster_offset) {
		auto it = alloc_state.find(cluster_offset);

		if (it == alloc_state.end())
			return false;

		//maybe the cluster has been zeroed, so double check
		if (it->second->get_state() < QCOW2_ALLOC_ZEROED) {
			it->second->set_state(QCOW2_ALLOC_STARTED);
			return true;
		}
		return false;
	}

	//called after the cluster is allocated from ram
	void alloc_cluster_started(const qcow2_io_ctx_t &ioc,
			u64 cluster_offset, u8 purpose);

	//check if the allocated cluster is zeroed
	bool alloc_cluster_is_zeroed(u64 cluster_offset) {
		Qcow2ClusterState * cs = get_cluster_state(cluster_offset);

		return cs == nullptr || cs->get_state() >= QCOW2_ALLOC_ZEROED;
	}

	//called after IO for zeroing this cluster is started
	void alloc_cluster_zeroing(const qcow2_io_ctx_t &ioc, u64 cluster_offset);

	//called after the cluster is zeroed
	void alloc_cluster_zeroed(struct ublksrv_queue *q,
			int tag, u64 cluster_offset);

	//called after the cluster is zeroed and associated mapping is updated
	void alloc_cluster_done(const qcow2_io_ctx_t &ioc, u64 cluster_offset);

	//called after the cluster is zeroed and associated mapping is updated
	void alloc_cluster_add_waiter(const qcow2_io_ctx_t &ioc,
			u64 cluster_offset);
};

class Qcow2Image {
private:
	std::string	fpath;
public:
	int fd;
	Qcow2Image(const char *path);
	~Qcow2Image();
};

enum qcow2_meta_flush {
	IDLE,
	PREP_WRITE_SLICES, //all slices are added to list for flush
	ZERO_MY_CLUSTER,
	WAIT,	//valid only for mapping table, wait for refcount table flushing done
	WRITE_SLICES,
	WRITE_TOP,
	DONE,
};

class MetaFlushingState {
private:
	// for flushing slices depended by current parent_idx, and for
	// handling state of WRITE_SLICE
	//
	//any slices depended by current parent_idx are added to this list,
	//and it is removed after the flushing is done
	//
	//once the list becomes empty, the state is switched to
	//WRITE_TOP.
	std::vector <Qcow2SliceMeta *> slices_to_flush;
	std::vector <Qcow2SliceMeta *> slices_in_flight;
	unsigned state;
	int parent_blk_idx;
	int parent_entry_idx;
	bool mapping;

	void del_meta_from_list(std::vector <Qcow2SliceMeta *> &v,
		const Qcow2SliceMeta *t);

	void __prep_write_slice(Qcow2State &qs, struct ublksrv_queue *q);

	void __zero_my_cluster(Qcow2State &qs, struct ublksrv_queue *q);
	co_io_job __zero_my_cluster_co(Qcow2State &qs,
		struct ublksrv_queue *q, struct ublk_io *io, int tag,
		Qcow2SliceMeta *m);

	void __write_slices(Qcow2State &qs, struct ublksrv_queue *q);
	co_io_job __write_slice_co(Qcow2State &qs,
		struct ublksrv_queue *q, Qcow2SliceMeta *m,
		struct ublk_io *io, int tag);

	void __write_top(Qcow2State &qs, struct ublksrv_queue *q);
	co_io_job  __write_top_co(Qcow2State &qs, struct ublksrv_queue *q,
			struct ublk_io *io, int tag);

	void __done(Qcow2State &qs, struct ublksrv_queue *q);
	bool __need_flush(int queued);
	void mark_no_update();
public:
	Qcow2TopTable &top;
	unsigned slice_dirtied;
	std::chrono::system_clock::time_point last_flush;

	unsigned get_state() const {
		return state;
	}
	void set_state(u32 s) {
		ublksrv_log(LOG_INFO, "%s: map %d slice_dirtied %u parent_blk_idx %d"
				" parent_entry_idx %d %d->%d to_flush %d in_flight %d\n",
				__func__, mapping, slice_dirtied,
				parent_blk_idx, parent_entry_idx, state,
				s, slices_to_flush.size(),
				slices_in_flight.size());
		state = s;
	}

	MetaFlushingState(Qcow2TopTable &t, bool is_mapping);
	void slice_is_done(const Qcow2SliceMeta*);
	void add_slice_to_flush(Qcow2SliceMeta *m);
	void run_flush(Qcow2State &qs, struct ublksrv_queue *q,
			int top_blk_idx);
	bool need_flush(Qcow2State &qs, int *top_idx, unsigned queued);
	void dump(const char *func, int line) const;
	int calc_refcount_dirty_blk_range(Qcow2State& qs,
			int *refcnt_blk_start, int *refcnt_blk_end);
};

/*
 * For any kind of meta flushing, one tag or io slot is required,
 * so start the meta flushing class with meta tag allocator.
 *
 * Meta data updating is never forground task, so if running out
 * of tags, let's wait until one tag is released.
 */
class Qcow2MetaFlushing {
private:
	std::vector <bool> tags;

	int refcnt_blk_start;
	int refcnt_blk_end;

	bool handle_mapping_dependency_start_end(Qcow2State *qs,
			struct ublksrv_queue *q);
	void handle_mapping_dependency(Qcow2State *qs,
			struct ublksrv_queue *q);
public:
	Qcow2State &state;

	MetaFlushingState mapping_stat;
	MetaFlushingState refcount_stat;

	void inc_dirtied_slice(bool mapping) {
		if (mapping)
			mapping_stat.slice_dirtied += 1;
		else
			refcount_stat.slice_dirtied += 1;
	}

	void dec_dirtied_slice(bool mapping) {
		if (mapping)
			mapping_stat.slice_dirtied -= 1;
		else
			refcount_stat.slice_dirtied -= 1;
	}

	Qcow2MetaFlushing(Qcow2State &qs);
	void dump();
	int alloc_tag(struct ublksrv_queue *q);
	void free_tag(struct ublksrv_queue *q, int tag);
	void run_flush(struct ublksrv_queue *q, int queued);
};

class Qcow2State {
private:
	std::vector <Qcow2SliceMeta *> freed_slices;
public:
	unsigned min_bs_bits;
	struct meta_mapping {
		int nr;
		std::vector <Qcow2MappingMeta *> meta;
	};
	typedef std::valarray<struct meta_mapping> MetaArray;

	const struct ublksrv_dev *dev;
	Qcow2Image img;
	Qcow2Header header;

	/* must be declared after header */
	Qcow2L1Table l1_table;

	/* must be declared after header */
	Qcow2RefcountTable refcount_table;

	Qcow2ClusterAllocator cluster_allocator;
	Qcow2ClusterMapping cluster_map;

	// map meta io object with one per-queue unique ID, which is set
	// in sqe->user_data, so we can retrieve the meta io object by
	// cqe->user_data after the io is done.
	MetaArray meta_io_map;

	Qcow2MetaFlushing meta_flushing;

#ifdef DEBUG_QCOW2_META_VALIDATE
	std::unordered_map<u64, u64> cluster_use;
	std::unordered_map<u64, u64> cluster_validate_map;
#endif

	Qcow2State(const char *img_path, const struct ublksrv_dev *dev);
	virtual ~Qcow2State();

	virtual	u32 get_l1_table_max_size();
	virtual	u64 get_l1_table_offset();

	virtual	u32 get_refcount_table_max_size();
	virtual	u32 get_refcount_table_act_size();
	virtual	u64 get_refcount_table_offset();

	Qcow2MappingMeta *get_meta_io(u32 qid, u32 pos) {
		return meta_io_map[qid].meta[pos];
	}

	void del_meta_io(u32 qid, u32 pos) {
		meta_io_map[qid].meta[pos] = nullptr;
		meta_io_map[qid].nr--;

		if (!meta_io_map[qid].nr)
			meta_io_map[qid].meta.clear();
	}

	u64 get_dev_size() {
		return dev->tgt.dev_size;
	}

	unsigned get_min_flush_unit_bits(){
		return min_bs_bits;
	}

	void add_slice_to_free_list(Qcow2SliceMeta *m) {
		freed_slices.push_back(m);
	}

	void kill_slices(struct ublksrv_queue *q);
	u32 add_meta_io(u32 qid, Qcow2MappingMeta *m);
	void dump_meta();

#ifdef DEBUG_QCOW2_META_VALIDATE
	void validate_cluster_use(u64 host_off, u64 virt_off, u32 use);
	bool validate_cluster_map(u64 host_off, u64 virt_off);
#else
	void validate_cluster_use(u64 host_off, u64 virt_off, u32 use) {}
	bool validate_cluster_map(u64 host_off, u64 virt_off) { return true;}
#endif
};

static inline Qcow2State *dev_to_qcow2state(const struct ublksrv_dev *dev)
{
	return (Qcow2State *)dev->target_data;
}

Qcow2State *make_qcow2state(const char *file, struct ublksrv_dev *dev);

class Qcow2StatePlain : public Qcow2State {
public:
	Qcow2StatePlain(const char *img_path, const struct ublksrv_dev *dev):
		Qcow2State(img_path, dev) {}
};

class Qcow2StateSnapshot : public Qcow2State {
public:
	Qcow2StateSnapshot(const char *img_path, const struct ublksrv_dev *dev):
		Qcow2State(img_path, dev) {}
};

class Qcow2StateExternalDataFile : public Qcow2State {
public:
	Qcow2StateExternalDataFile(const char *img_path, const struct ublksrv_dev *dev):
		Qcow2State(img_path, dev) {}
};

static inline int qcow2_meta_io_done(struct ublksrv_queue *q,
		struct io_uring_cqe *cqe)
{
	if (!cqe)
		return -EAGAIN;

	int op = user_data_to_op(cqe->user_data);
	int tag = user_data_to_tag(cqe->user_data);
	u32 tgt_data = user_data_to_tgt_data(cqe->user_data);

	/* plain IO's tgt_data is zero */
	if (tgt_data == 0) {
		syslog(LOG_ERR, "%s target data is zero for meta io(tag %d op %u %llx)\n",
				__func__, tag, op, cqe->user_data);
		return -EAGAIN;
	}

	Qcow2State *qs = dev_to_qcow2state(q->dev);
	/* retrieve meta data from target data part of cqe->user_data */
	Qcow2MappingMeta *meta = qs->get_meta_io(q->q_id, tgt_data - 1);

	if (cqe->res < 0)
		syslog(LOG_ERR, "%s: tag %d op %d tgt_data %d meta %p userdata %d\n",
			__func__, tag, user_data_to_op(cqe->user_data),
			tgt_data, meta, cqe->res);
	meta->io_done(*qs, q, cqe);

	return -EAGAIN;
}

#endif
