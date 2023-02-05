// SPDX-License-Identifier: GPL-2.0
#ifndef UBLK_QCOW2_META_H_
#define UBLK_QCOW2_META_H_

#include "qcow2_common.h"

class Qcow2State;
class Qcow2Header;

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

//only used for .reset()
#define QCOW2_META_DONT_ALLOC_BUF   (1U << 6)

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

	virtual ~Qcow2HeaderExt() {}

	virtual void dump() const
	{
		qcow2_log("%s: type %x len %d\n",
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
		qcow2_log("%s: type %x len %d string %s\n",
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
		qcow2_log("%s: type %x len %d nr_bitmap %d bitmap_dir(offset %lx sz %lu)\n",
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
		qcow2_log("%s: type %x len %d enc(offset %" PRIx64 " sz %" PRIu64 ")\n",
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

	void wakeup_all(const struct ublksrv_queue *q, unsigned my_tag) {
		io_waiters.wakeup_all(q, my_tag);
	}

	void wakeup_all_idx(const struct ublksrv_queue *q,
			unsigned my_tag, unsigned entry_idx) {
		io_waiters.wakeup_all_idx(q, my_tag, entry_idx);
	}

	virtual u64  get_entry(u32 idx) = 0;
	virtual void set_entry(u32 idx, u64 val) = 0;
	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
			u32 len) = 0;

	//both load() and flush() should be async, and done() needs to be called
	//after both load() and flush() meta IO are done.
	virtual void io_done(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *cqe);
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

	virtual void io_done(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *);
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
	virtual void wait_clusters(Qcow2State &qs, const qcow2_io_ctx_t &ioc);
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
	virtual void io_done(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *cqe);
	int zero_my_cluster(Qcow2State &qs, const qcow2_io_ctx_t &ioc);

	void reclaim_me();

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
			reclaim_me();
	}

	//In theory, virt_offset() should be implemented as virtual function.
	//However, it is actually one helper for fast path, so move it to
	//parent class, and use base flag to return the proper return value.
	u64 virt_offset() {
		if (is_mapping_meta()) {
			u64 base = ((u64)parent_idx) << (header.cluster_bits -
					3 + header.cluster_bits);
			u64 clusters = (get_offset() &
				((1ULL << header.cluster_bits) - 1)) >> 3;

			return base + (clusters << header.cluster_bits);
		}

		const u64 single_entry_order = 2 * header.cluster_bits +
			3 - header.refcount_order;
		u32 slice_idx = (get_offset() & ((1U << header.cluster_bits) - 1)) >>
			QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS;
		u32 slice_virt_bits = header.cluster_bits + 3 -
			header.refcount_order + QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS;

		return ((u64)parent_idx << single_entry_order) +
			((u64)slice_idx << slice_virt_bits);
	}
#ifdef DEBUG_QCOW2_META_VALIDATE
	void io_done_validate(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *cqe);
#else
	void io_done_validate(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *cqe) {}
#endif
};

class Qcow2RefcountBlock: public Qcow2SliceMeta {
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

	bool entry_is_dirty(u32 idx) {
		return idx >= dirty_start_idx;
	}

	Qcow2RefcountBlock(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
	void reset(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
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

	bool entry_is_dirty(u32 idx) {
		return entry_val_is_dirty(get_entry(idx));
	}

	Qcow2L2Table(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
	void reset(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
	virtual ~Qcow2L2Table();
	virtual u64  get_entry(u32 idx);
	virtual void set_entry(u32 idx, u64 val);
	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
			u32 len);
	virtual void dump();
	virtual void get_dirty_range(u64 *start, u64 *end);
	//virtual int flush(Qcow2State &qs, qcow2_io_ctx_t ioc, bool auto_free = false);
	virtual void io_done(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *cqe);
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

#endif
