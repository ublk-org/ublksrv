// SPDX-License-Identifier: GPL-2.0
#include <cassert>

#include "qcow2.h"
#include "ublksrv_tgt.h"


// refcnt is for slice only, and initialize it as two, one is for submission
// side, another is for free side. This way guarantees that the returned slice
// from alloc_slice is always valid
Qcow2Meta::Qcow2Meta(Qcow2Header &h, u64 off, u32 sz, const char *name, u32 f):
	header(h), offset(off), buf_sz(sz), flags(f), refcnt(2)
{
	//used for implementing slice's ->reset() only
	if (f & QCOW2_META_DONT_ALLOC_BUF)
		return;

	if (posix_memalign((void **)&addr, getpagesize(), sz))
		ublk_err( "allocate memory %d bytes failed, %s\n",
				sz, name);
#ifdef DEBUG_QCOW2_META_OBJ
	id = name;
	qcow2_log("%s: constructed, obj %p, buf size %d off %lx flags %x\n",
			name, this, sz, off, flags);
#endif
}

void Qcow2Meta::show(const char *func, int line)
{
#ifdef DEBUG_QCOW2_META_OBJ
	qcow2_log("%s:%d id %s obj %p flags %x off %lx ref %d\n",
			func, line, id, this, flags, offset, refcnt);
#else
	qcow2_log("%s:%d obj %p flags %x off %lx ref %d\n",
			func, line, this, flags, offset, refcnt);
#endif
}

Qcow2Meta::~Qcow2Meta()
{
#ifdef DEBUG_QCOW2_META_OBJ
	qcow2_log("%s: destructed, obj %p flags %x off %lx ref %d\n",
			id, this, flags, offset, refcnt);
#endif
	if (flags & QCOW2_META_DONT_ALLOC_BUF)
		return;

	if (!is_top_meta() && (get_dirty(-1) || is_flushing() ||
				(!get_update() && !get_evicted()))) {
		qcow2_log("BUG %s: obj %p flags %x off %lx\n",
				__func__, this, flags, offset);
		qcow2_assert(0);
	}
	free(addr);
}

int Qcow2Meta::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync)
{
	int fd;

	if (addr == NULL)
		return -EINVAL;
	if (len > buf_sz) {
		ublk_err( "%s %s: load too much %d(%d) \n",
				__func__, typeid(*this).name(), len, buf_sz);
		return -EINVAL;
	}
	if (!sync)
		return -EOPNOTSUPP;

	//qcow2_log("%s: read %s offset %llx len %lu  \n", __func__,
	//		typeid(*this).name(), offset, len);
	fd = qs.img.fd;
	lseek(fd, offset, SEEK_SET);
	data_len = read(fd, addr, len);
	if (data_len != len)
		qcow2_log("%s: read %u(%u)\n", __func__, len, data_len);
	if (data_len > 0)
		flags |= QCOW2_META_UPDATE;
	return data_len;
}

int Qcow2Meta::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
		u32 len)
{
	int fd = qs.img.fd;
	int ret;

	if (!(flags & QCOW2_META_DIRTY))
		return 0;

	if (!(flags & QCOW2_META_UPDATE))
		ublk_err( "%s %s: buf isn't update\n", __func__,
				typeid(*this).name());

	//qcow2_log("%s: write %s offset %llx len %lu  \n", __func__,
	//		typeid(*this).name(), offset, buf_sz);
	lseek(fd, off, SEEK_SET);
	ret = write(fd, addr, len);
	if (len != ret)
		qcow2_log("%s: write %u(%u)\n", __func__, len, ret);
	if (ret > 0)
		flags &= ~QCOW2_META_DIRTY;

	return len;
}

void Qcow2Meta::zero_buf() {
	memset((void *)addr, 0, buf_sz);
}

// Base class is constructed first, then follows member class/objects,
// and member classes are done in the order of their declaration,
// so here __a can be setup correctly.
Qcow2HeaderExtFeatureNameTable::Qcow2HeaderExtFeatureNameTable(
		char *addr, u64 offset): Qcow2HeaderExt(addr, offset),
	__a(len / sizeof(struct feature_entry))
{
	unsigned off = offset;

	for (int i = 0; i < __a.size(); i++) {
		__a[i].feature_type = *(addr + off + 8);
		__a[i].bit_num = *(addr + off + 9);
		strncpy(__a[i].feature_name, addr + off + 10, 46);
		off += 48;
	}
}

void Qcow2HeaderExtFeatureNameTable::dump() const
{
	Qcow2HeaderExt::dump();

	for (int i = 0; i < __a.size(); i++)
		qcow2_log("\t %d: type %x bit_num %u name %s\n",
			i, __a[i].feature_type, __a[i].bit_num,
			__a[i].feature_name);
}

Qcow2Header::Qcow2Header(Qcow2State &state): Qcow2Meta(*this, 0, 4096,
	typeid(this).name(), 0), magic(0), version(0), cluster_bits(0),
	refcount_order(0), qs(state)
{
	backingfile_format_name = NULL;
	feature_name_table = NULL;
	enc_header_pointer = NULL;
	bitmaps = NULL;
	ext_data_file_name = NULL;

	load(state, 0, buf_sz, true);
}

int Qcow2Header::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
			u32 len)
{
	return Qcow2Meta::flush(qs, ioc, off, len);
}

Qcow2Header::~Qcow2Header()
{
	delete	backingfile_format_name;
	delete	feature_name_table;
	delete	enc_header_pointer;
	delete	bitmaps;
	delete	ext_data_file_name;
}

void Qcow2Header::dump_ext() const
{
	if (backingfile_format_name)
		backingfile_format_name->dump();

	if (ext_data_file_name)
		ext_data_file_name->dump();

	if (feature_name_table)
		feature_name_table->dump();

	if (bitmaps)
		bitmaps->dump();

	if (enc_header_pointer)
		enc_header_pointer->dump();
}

/*
 * populate header extensions
 *
 * The header may take more than 4k, which should be decided by
 * backing_file_offset & backing_file_size __or__ populate
 * header extensions.
 */
int Qcow2Header::populate()
{
	char *buf = (char *)addr;
	u64 start = (get_header_length() + 7) & ~0x7ULL;
	u32 *p_magic =  const_cast<u32 *> (&magic);
	u32 *p_version =  const_cast<u32 *> (&version);
	u32 *p_cluster_bits = const_cast<u32 *> (&cluster_bits);
	u32 *p_refcount_order = const_cast<u32 *> (&refcount_order);

	*p_magic = get_magic();
	*p_version = get_version();
	*p_cluster_bits = get_cluster_bits();
	*p_refcount_order = get_refcount_order();

	if (version == 2)
		goto exit;

	//todo: populate extensions
	while (true) {
		Qcow2HeaderExt ext(buf, start);

		switch (ext.type) {
		case QCOW2_EXT_MAGIC_END:
			goto exit;
		case QCOW2_EXT_MAGIC_BACKING_FORMAT:
			this->backingfile_format_name =
				new Qcow2HeaderExtString(buf, start);
			break;
		case QCOW2_EXT_MAGIC_FEATURE_TABLE:
			this->feature_name_table =
				new Qcow2HeaderExtFeatureNameTable(
						buf, start);
			break;
		case QCOW2_EXT_MAGIC_CRYPTO_HEADER:
			this->enc_header_pointer =
				new Qcow2HeaderExtEncHeader(buf, start);
			break;
		case QCOW2_EXT_MAGIC_BITMAPS:
			this->bitmaps =
				new Qcow2HeaderExtBitmaps(buf, start);
			break;
		case QCOW2_EXT_MAGIC_DATA_FILE:
			this->ext_data_file_name =
				new Qcow2HeaderExtString(buf, start);
			break;
		};
		start += 8 + (ext.len + 7) & ~0x7ULL;
	}
 exit:
	return 0;
}

int Qcow2Header::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync)
{
	int ret;

	ret = Qcow2Meta::load(qs, ioc, len, sync);
	if (ret <= 0)
		goto fail;

	ret = populate();
	return ret;
 fail:
	ublk_err( "%s: load failed %d", __func__, ret);
	return ret;
}

std::ostream & operator<<(std::ostream &os, const Qcow2Header &h)
{
	char buf[256];

	sprintf(buf, "magic: %x", h.magic);
	std::cout << std::string(buf) << std::endl;
	qcow2_log("%s", buf);

	sprintf(buf, "version: %x\n", h.version);
	std::cout << std::string(buf) << std::endl;
	qcow2_log("%s", buf);

	sprintf(buf, "cluster_bits: %x\n", h.cluster_bits);
	std::cout << std::string(buf) << std::endl;
	qcow2_log("%s", buf);

	sprintf(buf, "refcount_order: %x\n", h.refcount_order);
	std::cout << std::string(buf) << std::endl;
	qcow2_log("%s", buf);

	return os;
}

Qcow2MappingMeta::Qcow2MappingMeta(Qcow2State &qs, u64 off, u32 buf_sz,
		const char *cls_name, u32 f):
	Qcow2Meta(qs.header, off, buf_sz, cls_name, f)
{
	//default each entry is 64bits(8bytes) except for:
	// extended l2 entry is 128bit, refcount blk has refcount_order
	entry_bits_order = 6;
	next_free_idx = -1;
}

/*
 * __flush() is just one worker, state check/update is done before calling
 * __flush()
 */
int Qcow2MappingMeta::__flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
		u64 off, u32 len, bool run_fsync)
{
	int fd = qs.img.fd;
	u32 qid = ioc.get_qid();
	u32 tag = ioc.get_tag();
	const struct ublksrv_queue *q = ublksrv_get_queue(qs.dev, qid);
	struct io_uring_sqe *sqe, *sqe2;
	unsigned mio_id;

	qcow2_assert(flags & QCOW2_META_DIRTY);

	if (!(flags & QCOW2_META_UPDATE))
		ublk_err( "%s %s: buf isn't update\n", __func__,
				typeid(*this).name());

	if (off < offset || off >= offset + buf_sz) {
		ublk_err( "%s %s: offset %" PRIx64 " is wrong\n", __func__,
				typeid(*this).name(), offset);
		return -EINVAL;
	}

	if (len > offset + buf_sz - off) {
		ublk_err( "%s %s: len %x is wrong\n", __func__,
				typeid(*this).name(), len);
		return -EINVAL;
	}

	sqe = io_uring_get_sqe(q->ring_ptr);
	if (!sqe) {
		ublk_err( "%s %s: not get sqe allocated",
				__func__, typeid(*this).name());
		return -ENOMEM;
	}

	if (run_fsync) {
		sqe2 = io_uring_get_sqe(q->ring_ptr);
		if (!sqe2) {
			ublk_err( "%s %s: not get sqe2 allocated",
				__func__, typeid(*this).name());
			return -ENOMEM;
		}
		io_uring_prep_fsync(sqe2, fd, IORING_FSYNC_DATASYNC);
		sqe2->user_data = build_user_data(0xffff, IORING_OP_FSYNC, 0, 1);
		sqe2->flags |= IOSQE_IO_LINK;
	}

	mio_id = qs.add_meta_io(qid, this);

	io_uring_prep_write(sqe, fd, (void *)((u64)addr + (off - offset)),
			len, off);
	sqe->user_data = build_user_data(tag, IORING_OP_WRITE, mio_id + 1, 1);
	ublk_dbg(UBLK_DBG_QCOW2_META, "%s %s: flushing %p tag %d off %lx sz %d flags %x refcnt %d\n",
			__func__, typeid(*this).name(), this, tag, off,
			len, flags, read_ref());
	return 1;
}

void Qcow2MappingMeta::io_done(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *cqe)
{
	u32 tag = user_data_to_tag(cqe->user_data);
	u32 meta_id = user_data_to_tgt_data(cqe->user_data) - 1;
	u32 op = user_data_to_op(cqe->user_data);

	qs.del_meta_io(q->q_id, meta_id);

	//zero my cluster needn't to wakeup events on me
	if (op != IORING_OP_FALLOCATE)
		wakeup_all(q, tag);
}

Qcow2TopTable::Qcow2TopTable(Qcow2State &qs, u64 off, u32 buf_sz,
		const char *cls_name, u32 f):
	Qcow2MappingMeta(qs, off, buf_sz, cls_name, f),
	min_bs_bits(qs.min_bs_bits),
	dirty(qs.get_l1_table_max_size() >> qs.min_bs_bits)
{
	ublk_dbg(UBLK_DBG_QCOW2_META_L1, "%s: %s dirty size %zd %u/%u\n",
			__func__,
			cls_name, dirty.size(),
		qs.get_l1_table_max_size(),qs.min_bs_bits);
	for (int i = 0; i < dirty.size(); i++)
		dirty[i] = false;
}

bool Qcow2TopTable::prep_flush(const qcow2_io_ctx_t &ioc, u32 blk_idx)
{
	if (!(flags & QCOW2_META_DIRTY))
		return false;

	//so far, just allow one in-progress unit for l1/refcount table
	if (flags & QCOW2_META_FLUSHING)
		return false;

	flags |= QCOW2_META_FLUSHING;
	return true;
}

void Qcow2TopTable::unprep_flush(u32 blk_idx) {
	flags &= ~QCOW2_META_FLUSHING;
}

void Qcow2TopTable::io_done(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *cqe)
{
	u32 op = user_data_to_op(cqe->user_data);

	//only for write l1 or refcount table
	qcow2_assert(op == IORING_OP_WRITE);

	unprep_flush(get_flush_blk_idx());

	if (cqe->res < 0)
		return;

	set_blk_dirty(get_flush_blk_idx(), false);

	Qcow2MappingMeta::io_done(qs, q, cqe);
}

int Qcow2TopTable::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
		u64 off, u32 len)
{
	int blk_idx = (off - offset) >> min_bs_bits;
	int ret;

	qcow2_assert(len == 512 && blk_idx < dirty.size());

	if (!prep_flush(ioc, blk_idx))
		return 0;

	if (!get_blk_dirty(blk_idx)) {
		ret = 0;
		goto exit;
	}

	set_flush_blk_idx(blk_idx);

	//need to run fsync before writting l1/refcount table, so
	//that write order between top and l2/refcount blk is respected
	ret = Qcow2MappingMeta::__flush(qs, ioc, off, len, true);
exit:
	if (ret <= 0)
		unprep_flush(blk_idx);
	return ret;
}

bool Qcow2TopTable::has_dirty_slices(Qcow2State &qs, int idx)
{
	u64 entry = get_entry(idx);
	u64 start, end, step, offset;

	if (!entry)
		return false;

	if (is_mapping_meta())
		step = 1ULL << (QCOW2_PARA::L2_TABLE_SLICE_BITS - 3 +
				qs.header.cluster_bits);
	else
		step = 1ULL << (QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS - 3 +
				qs.header.cluster_bits);

	start = ((u64)idx) << single_entry_order();
	end = start + (1ULL << single_entry_order());
	for (offset = start; offset < end; offset += step) {
		Qcow2SliceMeta *t;

		if (is_mapping_meta())
			t = qs.cluster_map.__find_slice(offset);
		else
			t = qs.cluster_allocator.__find_slice(offset);

		if (t && t->get_dirty(-1))
			return true;
	}

	return false;
}

Qcow2L1Table::Qcow2L1Table(Qcow2State &qs): Qcow2TopTable(qs,
		qs.get_l1_table_offset(), qs.get_l1_table_max_size(),
		typeid(*this).name(), QCOW2_META_TOP | QCOW2_META_MAPPING)
{
}

int Qcow2L1Table::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync)
{
	int ret;

	ret = Qcow2Meta::load(qs, ioc, len, sync);
	if (ret < 0)
		ublk_err( "%s %s: load failed %d", __func__,
				typeid(*this).name(), ret);
	return ret;
}

void Qcow2L1Table::dump()
{
	qcow2_log("%s %s: sizeof %zd\n", __func__, typeid(*this).name(),
			sizeof(*this));
	for (int i = 0; i < header.get_l1_size(); i++)
		qcow2_log("%d: %lx\n", i, get_entry(i));
}

u64  Qcow2L1Table::get_entry(u32 idx) {
	return get_entry_fast(idx);
}

void Qcow2L1Table::set_entry(u32 idx, u64 val) {
	set_entry_fast(idx, val);
}

Qcow2RefcountTable::Qcow2RefcountTable(Qcow2State &qs):
	Qcow2TopTable(qs, qs.get_refcount_table_offset(),
		qs.get_refcount_table_max_size(),
		typeid(*this).name(), QCOW2_META_TOP)
{
}

int Qcow2RefcountTable::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
		u32 len, bool sync)
{
	int ret;

	ret = Qcow2Meta::load(qs, ioc, len, sync);
	if (ret < 0)
		ublk_err( "%s %s: load failed %d", __func__,
				typeid(*this).name(), ret);
	return ret;
}

u64  Qcow2RefcountTable::get_entry(u32 idx) {
	return get_entry_fast(idx);
}

void Qcow2RefcountTable::set_entry(u32 idx, u64 val) {
	set_entry_fast(idx, val);
}

void Qcow2RefcountTable::dump()
{
	qcow2_log("%s %s: sizeof %zd\n", __func__, typeid(*this).name(),
			sizeof(*this));
	for (int i = 0; i < data_len / 8; i++) {
		u64 entry = get_entry(i);

		if (entry != 0)
			qcow2_log("%d: %lx\n", i, entry);
	}
}

Qcow2SliceMeta::Qcow2SliceMeta(Qcow2State &qs, u64 off, u32 buf_sz,
		const char *cls_name, u32 p_idx, u32 f):
	Qcow2MappingMeta(qs, off, buf_sz, cls_name, f),
	parent_idx(p_idx)
{
#ifdef QCOW2_CACHE_DEBUG
        qcow2_log("slice meta %llx/%p/%d allocated\n", off, addr, buf_sz);
#endif
#ifdef DEBUG_QCOW2_META_VALIDATE
	if (posix_memalign((void **)&validate_addr, getpagesize(), buf_sz))
		ublk_err( "%s: allocate validate memory %d bytes failed\n",
				__func__, buf_sz);
#endif
}

Qcow2SliceMeta::~Qcow2SliceMeta() {
#ifdef DEBUG_QCOW2_META_VALIDATE
	free(validate_addr);
#endif
}

bool Qcow2SliceMeta::prep_flush(const qcow2_io_ctx_t &ioc)
{
	if (!(flags & QCOW2_META_DIRTY))
		return false;

	if (flags & QCOW2_META_FLUSHING) {
		add_waiter(ioc.get_tag());
		throw MetaUpdateException();
	}
	flags |= QCOW2_META_FLUSHING;
	return true;
}

void Qcow2SliceMeta::unprep_flush() {
	flags &= ~QCOW2_META_FLUSHING;
}

int Qcow2SliceMeta::zero_my_cluster(Qcow2State &qs,
		const qcow2_io_ctx_t &ioc)
{
	u64 cluster_off = offset & ~((1ULL << qs.header.cluster_bits) - 1);
	Qcow2ClusterState *s = qs.cluster_allocator.get_cluster_state(
			 cluster_off);
	u32 qid = ioc.get_qid();
	u32 tag = ioc.get_tag();
	const struct ublksrv_queue *q = ublksrv_get_queue(qs.dev, qid);
	int fd = q->dev->tgt.fds[1];
	struct io_uring_sqe *sqe;
	int mode = FALLOC_FL_ZERO_RANGE;
	unsigned mio_id;

	if (s == nullptr)
		return 0;

	if (s->get_state() >= QCOW2_ALLOC_ZEROED)
		return 0;

	if (s->get_state() == QCOW2_ALLOC_ZEROING) {
		s->add_waiter(ioc.get_tag());
		throw MetaUpdateException();
	}

	sqe = io_uring_get_sqe(q->ring_ptr);
	if (!sqe) {
		ublk_err("%s: tag %d offset %" PRIu64 "op %d, no sqe for zeroing\n",
			__func__, tag, offset, IORING_OP_FALLOCATE);
		return -ENOMEM;
	}

	get_ref();

	mio_id = qs.add_meta_io(qid, this);
	s->set_state(QCOW2_ALLOC_ZEROING);
	io_uring_prep_fallocate(sqe, fd, mode, cluster_off,
			(1ULL << qs.header.cluster_bits));
	sqe->user_data = build_user_data(tag,
			IORING_OP_FALLOCATE, mio_id + 1, 1);
	ublk_dbg(UBLK_DBG_QCOW2_META, "%s %s: zeroing %p tag %d off %lx sz %d flags %x ref %d\n",
			__func__, typeid(*this).name(), this, tag, cluster_off,
			(1ULL << qs.header.cluster_bits), flags, refcnt);
	return 1;
}

int Qcow2SliceMeta::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
		u32 len, bool sync)
{
	int ret = -EINVAL;
	u32 qid = ioc.get_qid();
	u32 tag = ioc.get_tag();
	const struct ublksrv_queue *q = ublksrv_get_queue(qs.dev, qid);
	struct io_uring_sqe *sqe;
	int mio_id;

	if (sync) {
		ublk_err( "%s %s: we only support async load",
				__func__, typeid(*this).name());
		return -EINVAL;
	}

	if (flags & QCOW2_META_UPDATE) {
		ublk_err( "%s %s: we are update, need to load?",
				__func__, typeid(*this).name());
		return -EINVAL;
	}

	sqe = io_uring_get_sqe(q->ring_ptr);
	if (!sqe) {
		ublk_err( "%s %s: not get sqe allocated",
				__func__, typeid(*this).name());
		return ret;
	}

	get_ref();

	mio_id = qs.add_meta_io(qid, this);

	io_uring_prep_read(sqe, 1, (void *)addr, buf_sz, offset);
	sqe->flags = IOSQE_FIXED_FILE;
	/* meta io id starts from one and zero is reserved for plain ublk io */
	sqe->user_data = build_user_data(tag, IORING_OP_READ, mio_id + 1, 1);

	ublk_dbg(UBLK_DBG_QCOW2_META, "%s: queue io op %d(%llx %x %llx)"
				" (qid %d tag %u, cmd_op %u target: %d tgt_data %d)\n",
			__func__, sqe->opcode, sqe->off, sqe->len, sqe->addr,
			q->q_id, tag, sqe->opcode, 1, mio_id + 1);
	ublk_dbg(UBLK_DBG_QCOW2_META, "%s %s: loading %p tag %d off %lx sz %d flags %x ref %d\n",
			__func__, typeid(*this).name(), this, tag,
			offset, buf_sz, flags, refcnt);

	return 0;
}

#ifdef DEBUG_QCOW2_META_VALIDATE
void Qcow2SliceMeta::io_done_validate(Qcow2State &qs, const struct ublksrv_queue *q,
			struct io_uring_cqe *cqe)
{
	u32 tag = user_data_to_tag(cqe->user_data);
	u32 meta_id = user_data_to_tgt_data(cqe->user_data) - 1;
	u32 op = user_data_to_op(cqe->user_data);
	u64 cluster_off = offset & ~((1ULL << qs.header.cluster_bits) - 1);
	bool res;

	//for write, buffer data has been saved to validate_addr before
	//submitting the WRITE io
	if (op != IORING_OP_WRITE) {
		lseek(qs.img.fd, offset, SEEK_SET);
		read(qs.img.fd, validate_addr, buf_sz);
	}

	if (op == IORING_OP_FALLOCATE) {
		for (int i = 0; i < buf_sz; i++) {
			char *buf = (char *)validate_addr;

			qcow2_assert(buf[i] == 0);
		}
	} else if (op == IORING_OP_WRITE || op == IORING_OP_READ) {
		unsigned long *buf = (unsigned long *)addr;
		unsigned long *buf2 = (unsigned long *)validate_addr;

		res = bcmp(addr, validate_addr, buf_sz);

		if (res == 0)
			return;

		for (int i = 0; i < buf_sz / 8; i++) {
			if (buf[i] != buf2[i]) {
				qcow2_log("%s: not same in %d %lx %lx\n",
					__func__, i, buf[i], buf2[i]);
				qcow2_log("%s: tag %d, tgt_data %d op %d meta (%p %x %lx %d) res %d\n",
					__func__, tag, meta_id, op, this,
					get_flags(), get_offset(),
					refcnt, cqe->res);
			}
		}
		qcow2_assert(0);
	}
}
#endif

/* called for both load() and flush() */
void Qcow2SliceMeta::io_done(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *cqe)
{
	u32 tag = user_data_to_tag(cqe->user_data);
	u32 meta_id = user_data_to_tgt_data(cqe->user_data) - 1;
	u32 op = user_data_to_op(cqe->user_data);
	u64 cluster_off = offset & ~((1ULL << qs.header.cluster_bits) - 1);

	if (cqe->res < 0) {
		qcow2_log("%s: failure: tag %d, tgt_data %d op %d meta (%p %x %lx %d) res %d\n",
			__func__, tag, meta_id, op, this,
			get_flags(), get_offset(), refcnt, cqe->res);
		//zeroing the cluster for holding me is done
		if (op == IORING_OP_FALLOCATE) {
			if (qs.cluster_allocator.
			    alloc_cluster_reset(cluster_off))
				goto exit;
		} else if (op == IORING_OP_WRITE) {
			unprep_flush();
			goto exit;
		} else
			goto exit;
	}

	io_done_validate(qs, q, cqe);

	if (op == IORING_OP_READ)
		set_update(true);
	else if (op == IORING_OP_WRITE) {
		unprep_flush();
		qs.meta_flushing.dec_dirtied_slice(is_mapping_meta());
		set_dirty(-1, false);
		set_prep_flush(false);
	} else if (op == IORING_OP_FALLOCATE)
		qs.cluster_allocator.alloc_cluster_zeroed(q, tag, cluster_off);
	else
		ublk_err( "%s: unknown op: tag %d op %d meta_id %d res %d\n",
			__func__, tag, op, meta_id, cqe->res);

	ublk_dbg(UBLK_DBG_QCOW2_META, "%s: tag %d, tgt_data %d op %d meta (%p %x %lx %d) res %d\n",
			__func__, tag, meta_id, op, this,
			get_flags(), get_offset(), refcnt, cqe->res);

	//wake up waiters
	Qcow2MappingMeta::io_done(qs, q, cqe);

	//if it is evicted, now it is ready to free it
	if ((op == IORING_OP_WRITE) && cqe->res >= 0 && get_evicted())
		qs.add_slice_to_free_list(this);

exit:
	//drop the reference grabbed in either load() or flush()
	put_ref();
	return;
}

void Qcow2SliceMeta::wait_clusters(Qcow2State &qs,
		const qcow2_io_ctx_t &ioc)
{
	for (int i = 0; i < get_nr_entries(); i++) {
		u64 entry = get_entry(i);

		if (entry) {
			u64 cluster_off;

			//mapping meta means this is one l2 table, otherwise
			//it is one refcount block table
			if (is_mapping_meta())
				cluster_off = entry & L1E_OFFSET_MASK;
			else
				cluster_off = virt_offset() + (u64)i << qs.header.cluster_bits;

			 Qcow2ClusterState *s = qs.cluster_allocator.
				 get_cluster_state(cluster_off);

			if (s == nullptr)
				continue;

			if (s->get_state() < QCOW2_ALLOC_ZEROED) {
				s->add_waiter(ioc.get_tag());
				throw MetaUpdateException();
			}
		}
	}
}

void Qcow2SliceMeta::reclaim_me()
{
	unsigned queues = header.qs.dev_info->nr_hw_queues;

	ublk_dbg(UBLK_DBG_QCOW2_META, "%s: %p off %llx flags %x\n", __func__,
			this, get_offset(), flags);

	header.qs.remove_slice_from_evicted_list(this);

	ublk_dbg(UBLK_DBG_QCOW2_META, "%s: %p off %llx\n", __func__, this, get_offset());

	//Tell the whole world, I am leaving
	for (int i = 0; i < queues; i++) {
		const struct ublksrv_queue *q = ublksrv_get_queue(header.qs.dev, i);

		wakeup_all(q, -1);
	}
	header.qs.reclaim_slice(this);
}

Qcow2RefcountBlock::Qcow2RefcountBlock(Qcow2State &qs, u64 off, u32 p_idx, u32 f):
	Qcow2SliceMeta(qs, off, QCOW2_PARA::REFCOUNT_BLK_SLICE_BYTES,
			typeid(*this).name(), p_idx, f),
	dirty_start_idx((unsigned)-1)
{
	entry_bits_order = qs.header.refcount_order;
	ublk_dbg(UBLK_DBG_QCOW2_META_RB, "rb meta %p %llx -> %llx \n", this, virt_offset(), off);
}


void Qcow2RefcountBlock::reset(Qcow2State &qs, u64 off, u32 p_idx, u32 f)
{
	Qcow2RefcountBlock tmp(qs, off, p_idx, f | QCOW2_META_DONT_ALLOC_BUF);

	qcow2_assert(refcnt == 0);

	offset = tmp.get_offset();
	flags  = tmp.get_flags() & ~QCOW2_META_DONT_ALLOC_BUF;
	refcnt = tmp.read_ref();

	ublk_dbg(UBLK_DBG_QCOW2_META_RB, "%s: %p refcnt %d flags %x offset %lx \n",
			__func__, this, refcnt, flags, offset);

	next_free_idx = tmp.get_next_free_idx();

	parent_idx = tmp.parent_idx;

	dirty_start_idx = tmp.dirty_start_idx;
}

u64  Qcow2RefcountBlock::get_entry(u32 idx) {
	return get_entry_fast(idx);
}

void Qcow2RefcountBlock::set_entry(u32 idx, u64 val) {
	set_entry_fast(idx, val);

	if (is_flushing() || !get_update()) {
		qcow2_log("BUG %s: obj %p flags %x off %lx\n",
				__func__, this, flags, offset);
		qcow2_assert(0);
	}
}

int Qcow2RefcountBlock::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
		u64 off, u32 len)
{
	int ret;

	//wait_clusters(qs, ioc);

	if (!prep_flush(ioc))
		return 0;

	//flush can't be started unless the above two are done
	//
	//the ref is released in io_done()
	get_ref();
#ifdef DEBUG_QCOW2_META_VALIDATE
	memcpy(validate_addr, addr, buf_sz);
#endif
	ret = Qcow2MappingMeta::__flush(qs, ioc, off, len);
	if (ret <= 0) {
		unprep_flush();
		put_ref();
	}
	return ret;
}

Qcow2RefcountBlock::~Qcow2RefcountBlock()
{
}

void Qcow2RefcountBlock::get_dirty_range(u64 *start, u64 *end)
{
	*start = 1;
	*end = 0;
}

void Qcow2RefcountBlock::dump()
{
	unsigned cnt = 0;
	int f = -1, l;
	for (int i = 0; i < get_nr_entries(); i++) {
		u64 entry = get_entry(i);

		if (entry != 0) {
			if (f == -1)
				f = i;
			l = i;
			cnt++; //qcow2_log("%d: %lx\n", i, entry);
		}
	}

	if (!cnt)
		return;

	qcow2_log("%s %s: buf_sz %u offset %" PRIx64 " sizeof %zd entries %u parent_idx %u virt_off %" PRIx64 " flags %x\n",
			__func__, typeid(*this).name(), buf_sz, offset, sizeof(*this),
			cnt, parent_idx, virt_offset(),
			flags);
	qcow2_log("\t [%d] = %" PRIx64 "/%" PRIx64 " [%d] = %" PRIx64 "/%" PRIx64 "\n",
			f, get_entry(f),
			virt_offset() + (f << header.cluster_bits),
			l, get_entry(l),
			virt_offset() + (l << header.cluster_bits));
}

Qcow2L2Table::Qcow2L2Table(Qcow2State &qs, u64 off, u32 p_idx, u32 f):
	Qcow2SliceMeta(qs, off, QCOW2_PARA::L2_TABLE_SLICE_BYTES,
		typeid(*this).name(), p_idx, f | QCOW2_META_MAPPING)
{
	if (header.is_extended_l2_entries())
		entry_bits_order <<= 1;
	dirty_start = (u64)-1;
	dirty_end = 0;
        ublk_dbg(UBLK_DBG_QCOW2_META_L2, "l2 meta %p %llx -> %llx \n", this, virt_offset(), off);
}

void Qcow2L2Table::reset(Qcow2State &qs, u64 off, u32 p_idx, u32 f)
{
	Qcow2L2Table tmp(qs, off, p_idx, f | QCOW2_META_DONT_ALLOC_BUF);

	qcow2_assert(refcnt == 0);

	offset = tmp.get_offset();
	flags = tmp.get_flags() & ~QCOW2_META_DONT_ALLOC_BUF;
	refcnt = tmp.read_ref();

	ublk_dbg(UBLK_DBG_QCOW2_META_L2, "%s: %p refcnt %d flags %x offset %lx \n",
			__func__, this, refcnt, flags, offset);

	next_free_idx = tmp.get_next_free_idx();

	parent_idx = tmp.parent_idx;

	tmp.get_dirty_range(&dirty_start, &dirty_end);
}

Qcow2L2Table::~Qcow2L2Table()
{
}

void Qcow2L2Table::io_done(Qcow2State &qs, const struct ublksrv_queue *q,
			const struct io_uring_cqe *cqe)
{
	get_ref();
	Qcow2SliceMeta::io_done(qs, q, cqe);
	check(qs, __func__, __LINE__);
	put_ref();
}

u64  Qcow2L2Table::get_entry(u32 idx) {
	return get_entry_fast(idx);
}

void Qcow2L2Table::get_dirty_range(u64 *start, u64 *end)
{
	*start = dirty_start;
	*end = dirty_end;
}

void Qcow2L2Table::set_entry(u32 idx, u64 val) {
	set_entry_fast(idx, val);

	if (is_flushing() || !get_update()) {
		qcow2_log("BUG %s: obj %p flags %x off %lx\n",
				__func__, this, flags, offset);
		qcow2_assert(0);
	}

	val &= L2E_OFFSET_MASK;

	qcow2_assert(!(val & ((1ULL << header.cluster_bits) - 1)));

	if (val < dirty_start)
		dirty_start = val;
	if (val > dirty_end)
		dirty_end = val;
}

int Qcow2L2Table::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
		u64 off, u32 len)
{
	int ret;

	wait_clusters(qs, ioc);

	if (!prep_flush(ioc))
		return 0;

	//flush can't be started unless the above two are done
	//
	//the ref is released in io_done()
	get_ref();
#ifdef DEBUG_QCOW2_META_VALIDATE
	memcpy(validate_addr, addr, buf_sz);
	check_duplicated_clusters(qs, ioc.get_tag(), __func__, __LINE__);
#endif
	ret = Qcow2MappingMeta::__flush(qs, ioc, off, len);
	if (ret <= 0) {
		unprep_flush();
		put_ref();
	}
	return ret;
}

void Qcow2L2Table::dump()
{
	unsigned cnt = 0;
	int f = -1, l;

	for (int i = 0; i < get_nr_entries(); i++) {
		u64 entry = get_entry(i);

		if (entry != 0) {
			if (f == -1)
				f = i;
			l = i;
			cnt++; //qcow2_log("%d: %lx\n", i, entry);
		}
	}

	if (!cnt)
		return;

	qcow2_log("%s %s: buf_sz %u offset %" PRIx64 " sizeof %zd entries %u parent_idx %u virt_off %" PRIx64 " flags %x\n",
			__func__, typeid(*this).name(), buf_sz, offset, sizeof(*this),
			cnt, parent_idx, virt_offset(), flags);
	qcow2_log("\t [%d] = %" PRIx64 "[%u] = %" PRIx64 "\n", f,
			get_entry(f), l, get_entry(l));
}

#ifdef DEBUG_QCOW2_META_VALIDATE
void Qcow2L2Table::check(Qcow2State &qs, const char *func, int line)
{
	int i, cnt = 0;
	bool bad = false;

	if (!get_update())
		return;

	//don't check evicted obj, which can't be used by anyone
	if (get_evicted())
		return;

	for (i = 0; i < get_nr_entries(); i++) {
		u64 entry = get_entry(i) & ((1ULL << 63) - 1);

		if (entry == 0)
			continue;

		cnt++;

		if (entry + (1ULL << qs.header.cluster_bits) >
				qs.cluster_allocator.max_physical_size) {
			qcow2_log("%s %d: entry %llx(parent idx %d, idx %d) offset %llx is too big\n",
					func, line, entry, parent_idx, i,
					get_offset());
			bad = true;
		}

		if (entry & ((1ULL << qs.header.cluster_bits) - 1)) {
			qcow2_log("%s: entry %llx(parent idx %d, idx %d) offset %llx isn't aligned\n",
					func, line, entry, parent_idx, i,
					get_offset());
			bad = true;
		}
	}

	if (bad) {
		qcow2_log("%s %s: %p buf_sz %u offset %llx sizeof %d parent_idx %u virt_off %llx flags %x refcnt %d\n",
				__func__, typeid(*this).name(), this, buf_sz, offset, sizeof(*this),
				parent_idx, virt_offset(), flags, read_ref());
		qcow2_log("\t total entries %d\n", cnt);
		assert(0);
	}
}

void Qcow2L2Table::check_duplicated_clusters(Qcow2State &qs, int tag,
		const char *func, int line)
{
	for (int i = 0; i < get_nr_entries(); i++) {
		u64 entry = get_entry(i);

		if (entry != 0) {
			u64 host_off = entry & ((1ULL << 63) - 1);
			u64 virt_off = virt_offset() + (((u64)i) <<
				qs.header.cluster_bits);

			if (qs.validate_cluster_map(host_off, virt_off))
				continue;
			qcow2_log("BUG %s %d: tag %d obj %p flags %x off %lx virt_off "
					"%lx(#%d) parent_idx %d\n",
				func, line, tag, this, flags, offset,
				virt_offset(), i, parent_idx);
			qcow2_assert(0);
		}
	}
}
#endif
