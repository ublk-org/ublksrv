// SPDX-License-Identifier: GPL-2.0
#include "qcow2.h"

MetaFlushingState::MetaFlushingState(Qcow2TopTable &t, bool is_mapping):
	mapping(is_mapping), top(t)
{
	state = qcow2_meta_flush::IDLE;
	slice_dirtied = 0;
	parent_blk_idx = -1;
	last_flush = std::chrono::system_clock::now();
}

void MetaFlushingState::del_meta_from_list(std::vector <Qcow2SliceMeta *> &v,
		const Qcow2SliceMeta *t)
{
	auto it = find(v.cbegin(), v.cend(), t);

	qcow2_assert(it != v.cend());
	v.erase(it);
}

void MetaFlushingState::slice_is_done(const Qcow2SliceMeta *t)
{
	del_meta_from_list(slices_in_flight, t);

	qcow2_assert(state == WRITE_SLICES);

	if (slices_in_flight.empty() && slices_to_flush.empty()) {
		if (++parent_entry_idx >= (512/8))
			set_state(qcow2_meta_flush::WRITE_TOP);
		else
			//handle next entry in this block of top table
			set_state(qcow2_meta_flush::PREP_WRITE_SLICES);
	}
}

void MetaFlushingState::add_slice_to_flush(Qcow2SliceMeta *m)
{
	qcow2_assert(state == PREP_WRITE_SLICES);
	qcow2_assert(m->get_dirty(-1));

	auto it = find(slices_to_flush.cbegin(), slices_to_flush.cend(), m);
	qcow2_assert(it == slices_to_flush.cend());

	auto it1 = find(slices_in_flight.cbegin(), slices_in_flight.cend(), m);
	qcow2_assert(it1 == slices_in_flight.cend());

	slices_to_flush.push_back(m);
}

co_io_job MetaFlushingState::__write_slice_co(Qcow2State &qs,
		const struct ublksrv_queue *q, Qcow2SliceMeta *m,
		struct ublk_io_tgt *io, int tag)
{
	int ret;
	qcow2_io_ctx_t ioc(tag, q->q_id);
	bool wait;

	slices_in_flight.push_back(m);
again:
	try {
		ret = m->flush(qs, ioc, m->get_offset(), m->get_buf_size());
		wait = false;
	} catch (MetaUpdateException &meta_update_error) {
		wait = true;
	}

	if (wait) {
		co_await__suspend_always(tag);
		goto again;
	}

	if (ret < 0) {
		ublk_err( "%s: zero my cluster failed %d\n",
				__func__, ret);
		goto exit;
	}

	if (ret > 0) {
		const struct io_uring_cqe *cqe;
		bool done = false;
		int io_ret = 0;

		co_await__suspend_always(tag);

		cqe = io->tgt_io_cqe;
		done = (cqe && cqe->res != -EAGAIN);
		if (done)
			io_ret = cqe->res;
		ret = qcow2_meta_io_done(q, cqe);
		if (!done && ret == -EAGAIN)
			goto again;

		//here we can't retry since the slice may be
		//dirtied just after io_done()
		if (!done) {
			if (ret < 0)
				goto exit;
		} else {
			if (io_ret < 0)
				goto exit;
			ret = io_ret;
		}
	}
exit:
	if (m->get_prep_flush()) {
		m->set_prep_flush(false);
		m->wakeup_all(q, tag);
	}
	qs.meta_flushing.free_tag(q, tag);
	if (ret >= 0)
		slice_is_done(m);
	else
		del_meta_from_list(slices_in_flight, m);
	m->put_ref();
}

void MetaFlushingState::__write_slices(Qcow2State &qs,
		const struct ublksrv_queue *q)
{
	std::vector<Qcow2SliceMeta *> &v1 = slices_to_flush;
	std::vector<Qcow2SliceMeta *>::const_iterator it = v1.cbegin();

	flush_log("%s: mapping %d to_flush %d, in_flight %d\n",
			__func__, mapping, v1.size(), slices_in_flight.size());

	if (v1.empty())
		return;

	while (it != v1.cend()) {
		int tag;
		struct ublk_io_tgt *io;
		Qcow2SliceMeta *m;

		tag = qs.meta_flushing.alloc_tag(q);
		if (tag == -1)
			return;
		m = *it;
		it = v1.erase(it);
		m->get_ref();
		io = ublk_get_io_tgt_data(q, tag);
		io->co = __write_slice_co(qs, q, m, io, tag);
	}
}

//todo: run fsync before flushing top table, and global fsync should be
//fine, given top table seldom becomes dirty
co_io_job MetaFlushingState::__write_top_co(Qcow2State &qs,
		const struct ublksrv_queue *q, struct ublk_io_tgt *io, int tag)
{
	int ret;
	qcow2_io_ctx_t ioc(tag, q->q_id);
	bool wait;

again:
	try {
		ret = top.flush(qs, ioc,
				top.get_offset() + parent_blk_idx * 512, 512);
		wait = false;
	} catch (MetaUpdateException &meta_update_error) {
		wait = true;
	}

	if (wait) {
		co_await__suspend_always(tag);
		goto again;
	}

	if (ret < 0) {
		ublk_err( "%s: zero my cluster failed %d\n",
				__func__, ret);
		goto exit;
	}

	if (ret > 0) {
		const struct io_uring_cqe *cqe;

		co_await__suspend_always(tag);

		cqe = io->tgt_io_cqe;
		ret = qcow2_meta_io_done(q, cqe);
		if (ret == -EAGAIN)
			goto again;
		if (ret < 0)
			goto exit;
	}
exit:
	qs.meta_flushing.free_tag(q, tag);

	if (!top.get_blk_dirty(parent_blk_idx))
		set_state(qcow2_meta_flush::DONE);
}

void MetaFlushingState::__write_top(Qcow2State &qs,
		const struct ublksrv_queue *q)
{
	int tag;
	struct ublk_io_tgt *io;

	if (top.is_flushing(parent_blk_idx))
		return;

	tag = qs.meta_flushing.alloc_tag(q);
	if (tag == -1)
		return;

	io = ublk_get_io_tgt_data(q, tag);
	io->co = __write_top_co(qs, q, io, tag);
}

void MetaFlushingState::__done(Qcow2State &qs, const struct ublksrv_queue *q)
{
	set_state(qcow2_meta_flush::IDLE);
	last_flush = std::chrono::system_clock::now();
}

void MetaFlushingState::mark_no_update()
{
	auto it = slices_to_flush.begin();

	for (; it != slices_to_flush.end(); it++)
		(*it)->set_prep_flush(true);
}

void MetaFlushingState::__prep_write_slice(Qcow2State &qs,
		const struct ublksrv_queue *q)
{
	u64 entry;
	u64 idx = -1;
	u64 start, end, offset, step;

	do {
		qcow2_assert(parent_entry_idx >= 0 && parent_entry_idx < (512/8));

		idx = (parent_blk_idx * 512 / 8) + parent_entry_idx;

		qcow2_assert(idx >= 0 && idx < top.get_nr_entries());

		entry = top.get_entry(idx);
		if (entry && top.has_dirty_slices(qs, idx))
			break;

		if (++parent_entry_idx == (512/8)) {
			parent_entry_idx = 0;
			set_state(qcow2_meta_flush::WRITE_TOP);
			return;
		}
	} while (true);

	if (mapping)
		step = 1ULL << (QCOW2_PARA::L2_TABLE_SLICE_BITS - 3 +
				qs.header.cluster_bits);
	else
		step = 1ULL << (QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS - 3 +
				qs.header.cluster_bits);

	start = idx << top.single_entry_order();
	end = start + (1ULL << top.single_entry_order());
	for (offset = start; offset < end; offset += step) {
		Qcow2SliceMeta *t;

		if (mapping)
			t = qs.cluster_map.__find_slice(offset);
		else
			t = qs.cluster_allocator.__find_slice(offset);

		if (t && t->get_dirty(-1)) {
			qcow2_assert(!t->is_flushing());
			add_slice_to_flush(t);
		}
	}

	if (slices_to_flush.size() > 0)
		set_state(qcow2_meta_flush::ZERO_MY_CLUSTER);
	else
		set_state(qcow2_meta_flush::WRITE_TOP);
}

co_io_job MetaFlushingState::__zero_my_cluster_co(Qcow2State &qs,
		const struct ublksrv_queue *q, struct ublk_io_tgt *io, int tag,
		Qcow2SliceMeta *m)

{
	int ret;
	qcow2_io_ctx_t ioc(tag, q->q_id);
	u64 cluster_off = m->get_offset() &
		~((1ULL << qs.header.cluster_bits) - 1);
	bool wait;

again:
	try {
		ret = m->zero_my_cluster(qs, ioc);
		wait = false;
	} catch (MetaUpdateException &meta_update_error) {
		wait = true;
	}

	if (wait) {
		co_await__suspend_always(tag);
		goto again;
	}

	if (ret < 0) {
		ublk_err( "%s: zero my cluster failed %d\n",
				__func__, ret);
		goto exit;
	}

	if (ret > 0) {
		const struct io_uring_cqe *cqe;

		co_await__suspend_always(tag);

		cqe = io->tgt_io_cqe;
		ret = qcow2_meta_io_done(q, cqe);
		if (ret == -EAGAIN)
			goto again;
		if (ret < 0)
			goto exit;
	}
exit:
	qs.meta_flushing.free_tag(q, tag);
	if (qs.cluster_allocator.alloc_cluster_is_zeroed(cluster_off)) {
		//for mapping table, wait until the associated refcount
		//tables are flushed out
		if (mapping) {
			mark_no_update();
			set_state(qcow2_meta_flush::WAIT);
		} else
			set_state(qcow2_meta_flush::WRITE_SLICES);
	}
	m->put_ref();
}


void MetaFlushingState::__zero_my_cluster(Qcow2State &qs,
		const struct ublksrv_queue *q)
{
	int tag;
	struct ublk_io_tgt *io;
	Qcow2SliceMeta *m = slices_to_flush[0];
	u64 cluster_off = m->get_offset() &
		~((1ULL << qs.header.cluster_bits) - 1);
	Qcow2ClusterState *s =
		qs.cluster_allocator.get_cluster_state(cluster_off);

	if (s != nullptr && s->get_state() == QCOW2_ALLOC_ZEROING)
		return;

	tag = qs.meta_flushing.alloc_tag(q);
	if (tag == -1)
		return;

	m->get_ref();
	io = ublk_get_io_tgt_data(q, tag);
	io->co = __zero_my_cluster_co(qs, q, io, tag, m);
}

void MetaFlushingState::run_flush(Qcow2State &qs,
		const struct ublksrv_queue *q, int top_blk_idx)
{
	if (state == qcow2_meta_flush::IDLE) {
		if (top_blk_idx >= 0 && top_blk_idx < top.dirty_blk_size()) {
			parent_blk_idx = top_blk_idx;
			parent_entry_idx = 0;
			set_state(qcow2_meta_flush::PREP_WRITE_SLICES);
		}
	}
again:
	if (state == qcow2_meta_flush::PREP_WRITE_SLICES)
		__prep_write_slice(qs, q);

	if (state == qcow2_meta_flush::ZERO_MY_CLUSTER)
		__zero_my_cluster(qs, q);

	if (state == qcow2_meta_flush::WAIT) {
		qcow2_assert(mapping);
		return;
	}

	if (state == qcow2_meta_flush::WRITE_SLICES)
		__write_slices(qs, q);

	if (state == qcow2_meta_flush::WRITE_TOP)
		__write_top(qs, q);

	if (state == qcow2_meta_flush::DONE)
		__done(qs, q);

	if (state == qcow2_meta_flush::PREP_WRITE_SLICES)
		goto again;
}

void MetaFlushingState::dump(const char *func, int line) const {
	qcow2_log("%s %d: mapping %d state %d blk_idx %d entry_idx %d list size(%ld %ld)"
			" dirty slices %u, top table dirty blocks %u\n",
			func, line, mapping, state,
			parent_blk_idx, parent_entry_idx,
			slices_to_flush.size(),
			slices_in_flight.size(),
			slice_dirtied, top.dirty_blks());
}

bool MetaFlushingState::__need_flush(int queued)
{
	bool need_flush = slice_dirtied > 0;

	if (!need_flush)
		need_flush = top.dirty_blks() > 0;

	if (!need_flush)
		return false;

	if (queued) {
		auto diff = std::chrono::system_clock::now() - last_flush;
		std::chrono::milliseconds ms = std::chrono::duration_cast<
			std::chrono::milliseconds>(diff);

		//timeout, so flush now
		if (ms.count() > MAX_META_FLUSH_DELAY_MS)
			return true;
		else
			return false;
	}

	/* queue is idle, so have to flush immediately */
	return true;
}

bool MetaFlushingState::need_flush(Qcow2State &qs, int *top_idx,
		unsigned queued)
{
	bool need_flush = get_state() > qcow2_meta_flush::IDLE;
	int idx = -1;

	if (!need_flush) {
		if (mapping)
			need_flush = qs.cluster_map.
				has_evicted_dirty_slices();
		else
			need_flush = qs.cluster_allocator.
				has_evicted_dirty_slices();

		//only flush refcount tables actively if there
		//are evicted dirty refcount slices
		if (!need_flush)
			need_flush = __need_flush(queued);
	}

	if (need_flush && get_state() == qcow2_meta_flush::IDLE) {
		if (mapping)
			idx = qs.cluster_map.figure_group_from_l1_table();
		else
			idx = qs.cluster_allocator.figure_group_from_refcount_table();

		//idx is more accurate than slice_dirtied
		//FIXME: make slice_dirtied more accurate
		if (idx == -1) {
			need_flush = false;
			slice_dirtied = 0;
		}
	}

	*top_idx = idx;
	return need_flush;
}

//calculate the 1st index of refcount table, in which the to-be-flushed
//l2's entries depend on
int MetaFlushingState::calc_refcount_dirty_blk_range(Qcow2State& qs,
			int *refcnt_blk_start, int *refcnt_blk_end)
{
	u64 s = (u64)-1;
	u64 e = 0;
	u64 l2_offset = 0;
	int start_idx, end_idx;

	qcow2_assert(mapping);

	for (auto it = slices_to_flush.begin(); it != slices_to_flush.end();
			it++) {
		u64 ts, te;

		qcow2_assert((*it)->get_dirty(-1));

		(*it)->get_dirty_range(&ts, &te);

		if (!l2_offset)
			l2_offset = (*it)->get_offset() & ~((1ULL <<
					qs.header.cluster_bits) - 1);

		if (ts > te)
			continue;
		if (ts < s)
			s = ts;
		if (te > e)
			e = te;
	}

	if (s > e)
		return -EINVAL;

	//this l2 should be considered too
	if (l2_offset && l2_offset < s)
		s = l2_offset;

	start_idx = qs.refcount_table.offset_to_idx(s);
	*refcnt_blk_start = start_idx >> (qs.get_min_flush_unit_bits() - 3);

	end_idx = qs.refcount_table.offset_to_idx(e);
	*refcnt_blk_end = end_idx >> (qs.get_min_flush_unit_bits() - 3);
	*refcnt_blk_end += 1;

	flush_log("%s: %lx-%lx idx (%d %d) blk idx(%d %d)\n", __func__, s, e,
			start_idx, end_idx, *refcnt_blk_start, *refcnt_blk_end);

	if (*refcnt_blk_start == *refcnt_blk_end)
		*refcnt_blk_end = *refcnt_blk_start + 1;

	if (*refcnt_blk_start >= *refcnt_blk_end)
		qcow2_log("%s: %lx-%lx bad idx %d %d\n", __func__, s, e,
				*refcnt_blk_start, *refcnt_blk_end);

	qcow2_assert(*refcnt_blk_start < *refcnt_blk_end);

	return 0;
}

Qcow2MetaFlushing::Qcow2MetaFlushing(Qcow2State &qs):
	tags(QCOW2_PARA::META_MAX_TAGS),
	refcnt_blk_start(-1),
	refcnt_blk_end(-1),
	state(qs),
	mapping_stat(qs.l1_table, true),
	refcount_stat(qs.refcount_table, false)
{
	for (int i = 0; i < tags.size(); i++)
		tags[i] = true;
}

int Qcow2MetaFlushing::alloc_tag(const struct ublksrv_queue *q) {
	for (size_t i = 0; i < tags.size(); i++) {
		if (tags[i]) {
			tags[i] = false;
			return i + q->q_depth;
		}
	}
	return -1;
}

void Qcow2MetaFlushing::free_tag(const struct ublksrv_queue *q, int tag) {
	int depth = q->q_depth;

	qcow2_assert(tag >= depth && tag < depth + tags.size());
	tags[tag - depth] = true;
}

void Qcow2MetaFlushing::dump()
{
	ublk_err( "meta flushing: mapping: dirty slices %u, l1 dirty blocks %u\n",
			mapping_stat.slice_dirtied,
			state.l1_table.dirty_blks());
	ublk_err( "meta flushing: refcount: dirty slices %u, refcount table dirty blocks %u\n",
			refcount_stat.slice_dirtied,
			state.refcount_table.dirty_blks());
}

bool Qcow2MetaFlushing::handle_mapping_dependency_start_end(Qcow2State *qs,
		const struct ublksrv_queue *q)
{
	if (refcount_stat.get_state() == qcow2_meta_flush::IDLE &&
			(refcnt_blk_start == refcnt_blk_end)) {
		int ret;

		//current flushing refcnt is done
		if (refcnt_blk_start >= 0) {
			mapping_stat.set_state(
					qcow2_meta_flush::WRITE_SLICES);
			refcnt_blk_start = refcnt_blk_end = -1;
			mapping_stat.run_flush(state, q, -1);

			return true;
		} else { //current flushing is just started
			ret = mapping_stat.calc_refcount_dirty_blk_range(
					*qs, &refcnt_blk_start, &refcnt_blk_end);

			if (ret < 0) {
				mapping_stat.set_state(
					qcow2_meta_flush::WRITE_SLICES);
				mapping_stat.run_flush(state, q, -1);
				return true;
			}
		}
	}

	return false;
}

void Qcow2MetaFlushing::handle_mapping_dependency(Qcow2State *qs,
		const struct ublksrv_queue *q)
{
	qcow2_assert(mapping_stat.get_state() == qcow2_meta_flush::WAIT);

	if (!handle_mapping_dependency_start_end(qs, q)) {

		refcount_stat.run_flush(state, q, refcnt_blk_start);

		while (refcount_stat.get_state() == qcow2_meta_flush::IDLE &&
				(++refcnt_blk_start < refcnt_blk_end))
			refcount_stat.run_flush(state, q, refcnt_blk_start);
		handle_mapping_dependency_start_end(qs, q);
	}

	if (mapping_stat.get_state() != qcow2_meta_flush::WAIT)
		mapping_stat.run_flush(state, q, -1);
}

bool Qcow2MetaFlushing::is_flushing()
{
	return mapping_stat.get_state() != qcow2_meta_flush::IDLE ||
			refcount_stat.get_state() != qcow2_meta_flush::IDLE;
}

void Qcow2MetaFlushing::run_flush(const struct ublksrv_queue *q, int queued)
{
	Qcow2State *qs = queue_to_qcow2state(q);
	bool need_flush;
	int map_idx = -1;
	int refcnt_idx = -1;

	need_flush = mapping_stat.need_flush(*qs, &map_idx, queued);
	need_flush |= refcount_stat.need_flush(*qs, &refcnt_idx, queued);

	if (need_flush)
		flush_log("%s: enter flush: state %d/%d top blk idx %d/%d queued %d, refcnt blks(%d %d)\n",
			__func__, mapping_stat.get_state(),
			refcount_stat.get_state(), map_idx, refcnt_idx,
			queued, refcnt_blk_start, refcnt_blk_end);

	//refcount tables flushing is always triggered by flushing mapping
	//tables
	if (need_flush)
		mapping_stat.run_flush(state, q, map_idx);

	if (mapping_stat.get_state() == qcow2_meta_flush::WAIT)
		handle_mapping_dependency(qs, q);

	if (need_flush)
		flush_log("%s: exit flush: state %d/%d queued %d refcnt blks(%d %d) has dirty slice %d\n",
			__func__, mapping_stat.get_state(),
			refcount_stat.get_state(), queued,
			refcnt_blk_start, refcnt_blk_end,
			qs->has_dirty_slice());
}
