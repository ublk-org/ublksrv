// SPDX-License-Identifier: GPL-2.0
#include "qcow2.h"

Qcow2Image:: Qcow2Image(const char *path): fpath(path) {
	fd = open(path, O_RDWR | O_DIRECT);
	if (fd < 0)
		syslog(LOG_ERR, "%s: backing file %s can't be opened %d\n",
				__func__, path, fd);
}

Qcow2Image:: ~Qcow2Image() {
	if (fd >= 0)
		close(fd);
}

Qcow2State:: Qcow2State(const char *path, const struct ublksrv_dev *d):
	min_bs_bits(9), dev(d), img(path), header(*this), l1_table(*this),
	refcount_table(*this), cluster_allocator(*this),
	meta_io_map(d->ctrl_dev->dev_info.nr_hw_queues),
	cluster_map(*this), meta_flushing(*this)
{
	u64 l1_bytes = get_l1_table_max_size();
	u64 ref_table_bytes = get_refcount_table_act_size();

	l1_table.load(*this, 0, l1_bytes, true);
	//l1_table.dump();

	refcount_table.load(*this, 0, ref_table_bytes, true);
	//refcount_table.dump();

	cluster_allocator.setup();
}

Qcow2State:: ~Qcow2State() {
}

u32 Qcow2State::get_l1_table_max_size()
{
	u32 l2_entry_size = 8;
	u64 l2_size, res;

	l2_entry_size = header.is_extended_l2_entries() ? 16 : 8;

	l2_size = ((1 << header.cluster_bits) / l2_entry_size) <<
		header.cluster_bits;
	res = (header.get_size() + l2_size - 1) / l2_size;
	res *= 8;

	//qcow2_log("%s: cls bit %d, l2 entry size %d, l2_size %d, l1 tbl size %d\n",
	//		__func__, header.cluster_bits, l2_entry_size, l2_size, res);
	if (res < QCOW_MAX_L1_SIZE)
		return round_up(res, 1UL << min_bs_bits);
	return  QCOW_MAX_L1_SIZE;
}

u32 Qcow2State::get_refcount_table_max_size()
{
	u64 blk_size, res;

	blk_size = 1ULL << (2 * header.cluster_bits + 3 - header.refcount_order);
	res = (header.get_size() + blk_size - 1) / blk_size;
	res *= 8;

	//qcow2_log("%s: cls bit %d, refcount_order %d, blk_size %llu, ref tbl size %d\n",
	//		__func__, header.cluster_bits, header.refcount_order, blk_size, res);
	if (res < QCOW_MAX_REFTABLE_SIZE)
		return round_up(res, 1UL << min_bs_bits);
	return  QCOW_MAX_REFTABLE_SIZE;
}

u32 Qcow2State::get_refcount_table_act_size()
{
	u64 ref_table_bytes = header.get_refcount_table_clusters() <<
		header.cluster_bits;

	if (ref_table_bytes > get_refcount_table_max_size())
		ref_table_bytes = get_refcount_table_max_size();

	return round_up(ref_table_bytes, 1UL << min_bs_bits);
}

u64  Qcow2State::get_l1_table_offset()
{
	return header.get_l1_table_offset();
}

u64 Qcow2State::get_refcount_table_offset()
{
	return header.get_refcount_table_offset();
}

u32 Qcow2State::add_meta_io(u32 qid, Qcow2MappingMeta *m)
{
	struct meta_mapping *map = &meta_io_map[qid];
	std::vector <Qcow2MappingMeta *> &v = map->meta;
	int i;

	for (i = 0; i < v.size(); i++)
		if (v[i] == nullptr)
			break;
	if (i < v.size()) {
		v[i] = m;
	} else {
		v.push_back(m);
		i = v.size() - 1;
	}

	map->nr += 1;

	return i;
}

void Qcow2State::dump_meta()
{
	cluster_allocator.dump_meta();
	cluster_map.dump_meta();
	meta_flushing.dump();
}

//todo: allocate from slices from reclaim_slices
void Qcow2State::kill_slices(struct ublksrv_queue *q)
{
	std::vector<Qcow2SliceMeta *> tmp(move(freed_slices));

	if (tmp.empty())
		return;

	qcow2_assert(!tmp.empty() && freed_slices.empty());

	//can't free new added slice from ->wakeup_all()
	for (auto it = tmp.cbegin(); it != tmp.cend(); ++it) {
		auto m = *it;

		m->put_ref();
	}
}

#ifdef DEBUG_QCOW2_META_VALIDATE
void Qcow2State::validate_cluster_use(u64 host_off, u64 virt_off, u32 use) {
	auto it = cluster_use.find(host_off);

	if (it == cluster_use.end())
		cluster_use[host_off] = ((u64)use << 56) | virt_off;
	else {
		qcow2_log("%s: duplicated cluster assignment host off "
				"%llx, virt_off %llx use %d, old entry %llx\n",
				__func__, host_off, virt_off, use,
				it->second);
		qcow2_assert(0);
	}
}

// call it for each entry before flushing the slice
bool Qcow2State::validate_cluster_map(u64 host_off, u64 virt_off) {
	auto it = cluster_validate_map.find(host_off);

	if (it == cluster_validate_map.end()) {
		cluster_validate_map[host_off] = virt_off;
		return true;
	}

	if (virt_off == it->second)
		return true;

	qcow2_log("%s: duplicated cluster assignment host off "
			"%llx, virt_off %llx old virt_offset %llx\n",
			__func__, host_off, virt_off, it->second);
	return false;
}
#endif

/* Make any kind of Qcow2State, so far only support the plain one */
Qcow2State *make_qcow2state(const char *file, struct ublksrv_dev *dev)
{
	return new Qcow2StatePlain(file, dev);
}

template <class T>
slice_cache<T>::slice_cache(u8 slice_bits, u8 cluster_bits, u8 slice_virt_bits,
		u32 max_size): slices(max_size >> slice_bits), evicted_slices({}),
	slice_size_bits(slice_bits),
	cluster_size_bits(cluster_bits),
	slice_virt_size_bits(slice_virt_bits)
{
}

template <class T>
T *slice_cache<T>::__find_slice(u64 key, bool use_evicted_cache) {
	T *t = slices.__get(key);

	if (t)
		return t;

	if (use_evicted_cache) {
		auto it = evicted_slices.find(key);

		if (it != evicted_slices.end())
			return it->second;
	}
	return nullptr;
}

template <class T>
T *slice_cache<T>::alloc_slice(Qcow2State &state, const qcow2_io_ctx_t &ioc,
		u64 virt_offset, u64 host_offset, u32 parent_idx)
{
	T *t;
	u32 flags;
	bool zero_buf;

	qcow2_assert(__find_slice(virt_offset, true) == nullptr);
	qcow2_assert(!(virt_offset & ((1ULL << cluster_size_bits) - 1)));

	if (!state.cluster_allocator.alloc_cluster_is_zeroed(host_offset &
				~((1ULL << cluster_size_bits) - 1))) {
		flags = QCOW2_META_UPDATE | QCOW2_META_DIRTY;
		zero_buf = true;
	} else {
		flags = 0;
		zero_buf = false;
	}

	t = new T(state, host_offset, parent_idx, flags);
	if (t->get_dirty(-1))
		state.meta_flushing.inc_dirtied_slice(t->is_mapping_meta());

	if (zero_buf)
		t->zero_buf();

	T *old = slices.put(virt_offset, t);
	if (old) {
#ifdef DEBUG_QCOW2_META_OBJ
		qcow2_assert(__find_slice(old->virt_offset(), true)
				== nullptr);
#endif
		//loading or flushing may be in-progress, that is allowed.
		//and we guarantee that the slice isn't released until
		//the loading or flushing is done
		old->set_evicted();
		add_slice_to_evicted_list(old->virt_offset(), old);

		//can't free one dirty slice, but one clean slice can't
		//be dirtied after it is evicted, so safe to move clean
		//slice into free list for release
		if (!old->get_dirty(-1))
			state.add_slice_to_free_list(old);
		old->put_ref();

#ifdef DEBUG_QCOW2_META_OBJ
		meta_log("%s: %s evicted from tag %d, obj %p flags %x offset %lx ref %d\n",
				__func__, old->get_id(), ioc.get_tag(), old,
				old->get_flags(), old->get_offset(),
				old->read_ref());
#endif
	}

	if (virt_offset != t->virt_offset()) {
		syslog(LOG_ERR, "%s %d: %s %llx/%llx parent_idx %d host_off %llx flags %x\n",
			__func__, __LINE__, typeid(*t).name(),
			virt_offset, t->virt_offset(), parent_idx,
			host_offset, flags);
		qcow2_assert(virt_offset == t->virt_offset());
	}

	return t;
}

template <class T>
void slice_cache<T>::add_slice_to_evicted_list(u64 virt_offset, T *t)
{
	auto it = evicted_slices.find(virt_offset);

	qcow2_assert(virt_offset == t->virt_offset());

	if (it == evicted_slices.end())
		evicted_slices[virt_offset] = t;
	else {
#if 1
		auto m = it->second;
		qcow2_log("%s: add duplicated cache virt_offset %llx, remove old entry(%p %lx/%lx %x %d)\n",
				__func__, virt_offset, m, m->virt_offset(),
				m->get_offset(), m->get_flags(), m->read_ref());
		it->second->show(__func__, __LINE__);
		qcow2_assert(0);
#endif

		//this slice has been in handled in prep_flushing,
		//so it is fine to remove it from freed list now
		evicted_slices.erase(it);
		evicted_slices[virt_offset] = t;
	}
}

template <class T>
void slice_cache<T>::dump(Qcow2State &qs) {
	unsigned long long start;
	unsigned long long end = qs.get_dev_size();

	syslog(LOG_INFO, "cache size %u, dirty cache size %u\n",
			slices.size(), evicted_slices.size());
	for (start = 0; start <= end;
			start += (1ULL << slice_virt_size_bits)) {
		T *t = __find_slice(start, true);

		if (t)
			t->dump();
	}
}

template <class T>
int slice_cache<T>::figure_group_from_dirty_list(Qcow2State &qs) {
	std::unordered_map<u32, int> cnt;
	int val = -1;
	int idx = -1;

	for (auto it = evicted_slices.cbegin(); it != evicted_slices.cend(); ++it) {
		u32 key = (it->second->parent_idx * 8) / 512;
		auto it1 = cnt.find(key);

		if (it1 == cnt.end())
			cnt[key] = 0;
		else
			cnt[key] += 1;
	}

	for (auto it = cnt.cbegin(); it != cnt.cend(); ++it) {
		if (it->second > val) {
			idx = it->first;
			val = it->second;
		}
	}

	flush_log("%s: dirty list: idx %d cnt %u\n", __func__, idx, val);

	qcow2_assert(idx != -1);
	return idx;
}

template <class T>
int slice_cache<T>::__figure_group_for_flush(Qcow2State &qs)
{
	unsigned long long start;
	unsigned long long end = qs.get_dev_size();
	std::unordered_map<u32, int> cnt;
	int val = -1;
	int idx = -1;

	//todo: use lrucache iterator to cut the loop time
	for (start = 0; start <= end;
			start += (1ULL << slice_virt_size_bits)) {
		T *t = slices.__get(start);

		if (t != nullptr && t->get_dirty(-1) && !t->is_flushing()) {
			u32 key = (t->parent_idx * 8) / 512;
			auto it1 = cnt.find(key);

			if (it1 == cnt.end())
				cnt[key] = 0;
			else
				cnt[key] += 1;
		}
	}

	if (cnt.size() == 0)
		return -1;

	for (auto it = cnt.cbegin(); it != cnt.cend(); ++it) {
		if (it->second > val) {
			idx = it->first;
			val = it->second;
		}
	}
	qcow2_assert(idx != -1);
	flush_log("%s: lru list: idx %d cnt %u\n", __func__, idx, val);
	return idx;
}

template <class T>
int slice_cache<T>::figure_group_for_flush(Qcow2State &qs)
{
	if (evicted_slices.size() > 0)
		return figure_group_from_dirty_list(qs);

	return __figure_group_for_flush(qs);
}

// refcount table shouldn't be so big
Qcow2ClusterAllocator::Qcow2ClusterAllocator(Qcow2State &qs): state(qs),
	cache(REFCOUNT_BLK_SLICE_BITS, qs.header.cluster_bits,
		qs.header.cluster_bits + 3 - qs.header.refcount_order +
		QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS,
		QCOW2_PARA::REFCOUNT_BLK_MAX_CACHE_BYTES),
	alloc_state({})
{
	max_alloc_states = 0;
};

Qcow2RefcountBlock* Qcow2ClusterAllocator::__find_slice(u64 key)
{
	return cache.__find_slice(key, true);
}

int Qcow2ClusterAllocator::figure_group_from_refcount_table()
{
	int ret = cache.figure_group_for_flush(state);

	if (ret == -1)
		return state.refcount_table.get_1st_dirty_blk();
	return ret;
}

void Qcow2ClusterAllocator::alloc_cluster_started(const qcow2_io_ctx_t &ioc,
		u64 cluster_offset, u8 purpose)
{
	auto it = alloc_state.find(cluster_offset);
	u32 sz;

	qcow2_assert(it == alloc_state.end());

	alloc_state[cluster_offset] = new Qcow2ClusterState(
			QCOW2_ALLOC_STARTED, purpose);

	sz = alloc_state.size();

	if (sz > max_alloc_states)
		max_alloc_states = sz;

	alloc_log("%s: offset %lx state %d purpose %d\n",
			__func__, cluster_offset,
			QCOW2_ALLOC_STARTED, purpose);
}

void Qcow2ClusterAllocator::alloc_cluster_zeroing(const qcow2_io_ctx_t &ioc,
		u64 cluster_offset)
{
	auto it = alloc_state.find(cluster_offset);

	qcow2_assert(it != alloc_state.end());

	it->second->set_state(QCOW2_ALLOC_ZEROING);

	alloc_log("%s: offset %lx state %d purpose %d\n", __func__,
			cluster_offset, it->second->get_state(),
			it->second->get_purpose());
}

void Qcow2ClusterAllocator::alloc_cluster_zeroed(struct ublksrv_queue *q,
		int tag, u64 cluster_offset)
{
	auto it = alloc_state.find(cluster_offset);

	if (it == alloc_state.end())
		syslog(LOG_ERR, "%s: offset %lx\n", __func__, cluster_offset);
	qcow2_assert(it != alloc_state.end());

	it->second->set_state(QCOW2_ALLOC_ZEROED);
	alloc_log("%s: offset %lx state %d purpose %d\n", __func__,
			cluster_offset, it->second->get_state(),
			it->second->get_purpose());

	it->second->wakeup_all(q, tag);

	/* safe to remove it now */
	delete it->second;
	alloc_state.erase(it);
}

//called after mapping is setup for this cluster
void Qcow2ClusterAllocator::alloc_cluster_done(const qcow2_io_ctx_t &ioc,
		u64 cluster_offset)
{
	auto it = alloc_state.find(cluster_offset);

	qcow2_assert(it != alloc_state.end());

	delete it->second;

	alloc_state.erase(it);
}

void Qcow2ClusterAllocator::dump_meta() {

	qcow2_log("cluster allocator %s: total allocates %lld clusters, bytes %lld KB, max states %u/%u\n",
			__func__, alloc_cnt, (alloc_cnt <<
			state.header.cluster_bits) >> 10,
			max_alloc_states, alloc_state.size());
	state.refcount_table.dump();
	cache.dump(state);
}

void Qcow2ClusterAllocator::setup() {
	long i = 0;

	for (i = (state.refcount_table.get_data_len() / 8) - 1; i >= 0; i--)
		if (state.refcount_table.get_entry(i) != 0)
			break;
	/*
	 * most of times this entry has slot available yet, otherwise
	 * allocate_cluster() will move to next refcount block cache
	 */
	state.refcount_table.set_next_free_idx(i);

	table_entry_virt_size_bits = 2 * state.header.cluster_bits + 3 -
		state.header.refcount_order;
	slice_idx = 0;
	alloc_cnt = 0;

	//just one estimation, for runtime check only
	max_physical_size = ((u64)(i + 1)) << table_entry_virt_size_bits;
}

void Qcow2ClusterAllocator::allocate_refcount_blk(const qcow2_io_ctx_t &ioc,
		s32 idx)
{
	Qcow2RefcountBlock *rb;
	u64 virt_offset = (u64)idx << table_entry_virt_size_bits;
	u64 host_offset = virt_offset;

	if (state.refcount_table.is_flushing(idx)) {
		state.refcount_table.add_waiter(ioc.get_tag());
		throw MetaUpdateException();
	}

	max_physical_size = ((u64)(idx + 1)) << table_entry_virt_size_bits;
	state.refcount_table.set_next_free_idx(idx);
	qcow2_assert(!state.refcount_table.get_entry(idx));
	state.refcount_table.set_entry(idx, host_offset);

	//track the new allocated cluster
	alloc_cluster_started(ioc, host_offset,
			QCOW2_CLUSTER_USE::REFCOUNT_BLK);
	state.validate_cluster_use(host_offset, virt_offset,
			QCOW2_CLUSTER_USE::REFCOUNT_BLK);

	rb = cache.alloc_slice(state, ioc, virt_offset, host_offset, idx);
	qcow2_assert(rb != nullptr);
	qcow2_assert(rb->get_update() && !rb->get_evicted() &&
			!rb->is_flushing());

	//the first cluster is for this refcount block
	rb->set_entry(0, 1);
	rb->set_next_free_idx(1);
}

u64 Qcow2ClusterAllocator::allocate_cluster(const qcow2_io_ctx_t &ioc)
{
	Qcow2RefcountBlock *rb;
	s32 free_idx;
	u64 virt_offset, host_offset;

again:
	free_idx = state.refcount_table.get_next_free_idx();
	virt_offset = ((u64)free_idx << table_entry_virt_size_bits) +
		((u64)slice_idx << cache.get_slice_virt_size_bits());
	rb = cache.find_slice(virt_offset, true);
	if (rb == nullptr)
		goto alloc_refcount_blk;
	qcow2_assert(rb->read_ref() > 0);

check_new:
	/* the cache has been allocated & being loaded */
	if (!rb->get_update()) {
		rb->add_waiter(ioc.get_tag());
		throw MetaUpdateException();
	}

	//if we are being flushed, can't touch the in-ram table,
	//so wait until the flushing is done
	if (rb->is_flushing() || rb->get_evicted()) {
		rb->add_waiter(ioc.get_tag());
		throw MetaUpdateException();
	}

#ifdef QCOW2_CACHE_DEBUG
	qcow2_log("%s: hit: next free %d entries %d virt_off %llx slice_idx %d\n",
			__func__, rb->get_next_free_idx(), rb->get_nr_entries(),
			virt_offset, slice_idx);
#endif
	//todo: cache the last free entry
	for (int i = rb->get_next_free_idx(); i < rb->get_nr_entries(); i++) {
		if (i < 0)
			continue;
		//qcow2_log("\t entry[%d]=%llx\n", i, rb->get_entry(i));
		if (rb->get_entry_fast(i) == 0) {
			u64 res = virt_offset + (((u64)i) <<
					state.header.cluster_bits);

			if (!rb->get_dirty(-1))
				state.meta_flushing.inc_dirtied_slice(false);
			qcow2_assert(rb->get_update() && !rb->is_flushing() &&
				!rb->get_evicted());
			rb->set_entry(i, 1);
			rb->set_next_free_idx(i + 1);

			alloc_cnt++;
			return res;
		}
	}

	if (++slice_idx < cache.get_nr_slices())
		goto again;

	// this current cache is full, so move to next one.
	//
	// Here it is different with l2 table's cache which is sliced, but
	// refcount blk cache size is always equal to one cluster
	qcow2_assert(free_idx < state.refcount_table.get_nr_entries());
	allocate_refcount_blk(ioc, free_idx + 1);
	slice_idx = 0;
	goto again;

alloc_refcount_blk:
	//start is host offset of refcount block object
	host_offset = state.refcount_table.get_entry(free_idx) +
			    + (u64(slice_idx) << cache.get_slice_size_bits());

	rb = cache.alloc_slice(state, ioc, virt_offset, host_offset, free_idx);

	/* the cluster may be allocated just in ram, no need to load */
	if (rb->get_update())
		goto check_new;

	rb->load(state, ioc, QCOW2_PARA::REFCOUNT_BLK_SLICE_BYTES, false);

	//add our tag into io_waiters, so once we get updated,
	//the current io context will be resumed when handling cqe
	//
	//we have to call it explicitly here for both io contexts
	//which starts to load meta and wait for in-flight meta
	rb->add_waiter(ioc.get_tag());

	//->handle_io_async() has to handle this exception
	throw MetaIoException();

	return 0;
}

// refcount table shouldn't be so big
Qcow2ClusterMapping::Qcow2ClusterMapping(Qcow2State &qs): state(qs),
	cache(QCOW2_PARA::L2_TABLE_SLICE_BITS,
		qs.header.cluster_bits,
		qs.header.cluster_bits + L2_TABLE_SLICE_BITS - 3,
		QCOW2_PARA::L2_TABLE_MAX_CACHE_BYTES),
	cluster_bits(state.header.cluster_bits),
	l2_entries_order(state.header.cluster_bits - 3),
	max_alloc_entries(0)
{
}

Qcow2L2Table* Qcow2ClusterMapping::__find_slice(u64 key, bool use_dirty)
{
	return cache.__find_slice(key, use_dirty);
}

int Qcow2ClusterMapping::figure_group_from_l1_table()
{
	int ret = cache.figure_group_for_flush(state);

	if (ret == -1)
		return state.l1_table.get_1st_dirty_blk();
	return ret;
}

Qcow2L2Table *Qcow2ClusterMapping::create_and_add_l2(const qcow2_io_ctx_t &ioc,
		u64 offset)
{
	const unsigned idx = l1_idx(offset);
	int ret;
	u64 l1_entry = state.l1_table.get_entry(idx);
	u64 l2_cluster = -1;
	struct ublksrv_queue *q = ublksrv_get_queue(state.dev, ioc.get_qid());
	Qcow2L2Table *l2 = nullptr;

	qcow2_assert(!state.l1_table.entry_allocated(l1_entry));

	//in case of being flushed, we can't update in-ram meta, so
	//exit and wait for flush completion
	if (state.l1_table.is_flushing(idx)) {
		state.l1_table.add_waiter(ioc.get_tag());
		throw MetaUpdateException();
	}

	//if someone is allocating cluster for this entry, wait until
	//the entry becomes valid or failed
	if (entry_is_allocating(offset, true)) {
		u32 owner = entry_get_alloc_owner(offset, true);

		if (owner != ioc.get_tag()) {
			state.l1_table.add_waiter_idx(ioc.get_tag(), idx);
			throw MetaUpdateException();
		}
	} else {
		//store owner into the entry for marking we are allocating, so
		//others can't allocate for this entry any more, and others
		//just need to wait until the allocation is done
		entry_mark_allocating(offset, ioc.get_tag(), true);
	}

	l2_cluster = state.cluster_allocator.allocate_cluster(ioc);
	if (l2_cluster == -1) {
		state.l1_table.set_entry(idx, 0);
	} else {
		unsigned long s_idx = cache.get_slice_idx(l2_slice_key(offset));
		u64 host_offset = l2_cluster +
			(s_idx << cache.get_slice_size_bits());

		state.cluster_allocator.alloc_cluster_started(ioc,
				l2_cluster, QCOW2_CLUSTER_USE::L2_TABLE);
		state.validate_cluster_use(l2_cluster, l2_slice_key(offset),
				QCOW2_CLUSTER_USE::L2_TABLE);
		//allocate l2 cache
		l2 = cache.alloc_slice(state, ioc, l2_slice_key(offset),
				host_offset, idx);
		l2->get_ref();
		qcow2_assert(l2->get_update());

		l2_cluster |= 1ULL << 63;
		state.l1_table.set_entry(idx, l2_cluster);
	}

	entry_mark_allocated(offset, true);
	state.l1_table.wakeup_all_idx(q, ioc.get_tag(), idx);

	return l2;
}

Qcow2L2Table *Qcow2ClusterMapping::load_l2_slice(const qcow2_io_ctx_t &ioc, u64 offset,
		u64 l1_entry)
{
	const u64 slice_offset = (l2_idx(offset) << 3) &
		~(QCOW2_PARA::L2_TABLE_SLICE_BYTES - 1);
	u64 start = (l1_entry & ((1ULL << 63) - 1)) + slice_offset;
	Qcow2L2Table *l2;

	l2 = cache.alloc_slice(state, ioc, l2_slice_key(offset), start,
			l1_idx(offset));
	//start may point to one new allocated cluster
	if (l2->get_update()) {
		l2->get_ref();
		return l2;
	}

	ublksrv_log(LOG_INFO, "cache: alloc: key %llx val %p, update %d\n",
			start, l2, l2->get_update());
	l2->load(state, ioc, QCOW2_PARA::L2_TABLE_SLICE_BYTES, false);
	l2->add_waiter(ioc.get_tag());
	throw MetaIoException();

	return l2;
}

//return l2 slice object with holding one extra reference
Qcow2L2Table *Qcow2ClusterMapping::create_l2_map(const qcow2_io_ctx_t &ioc,
		u64 offset, bool create_l2)
{
	u64 l1_entry = state.l1_table.get_entry_fast(l1_idx(offset));
	Qcow2L2Table *l2 = nullptr;

	if (state.l1_table.entry_allocated(l1_entry))
		return load_l2_slice(ioc, offset, l1_entry);

	if (create_l2) {
		// l2 table isn't allocated yet, so create one and add it here
		l2 = create_and_add_l2(ioc, offset);
		if (!l2)
			syslog(LOG_ERR, "%s: tag %d: allocate l2 failed for %llx\n",
				__func__, ioc.get_tag(), offset);
	}
	return l2;
}

//virt_offset's l2 table doesn't include this entry yet, so allocate
//one cluster and install the mapping
int Qcow2ClusterMapping::build_mapping(const qcow2_io_ctx_t &ioc,
		u64 virt_offset, Qcow2L2Table *l2, u32 idx_in_slice,
		u64 *l2_entry)
{
	struct ublksrv_queue *q = ublksrv_get_queue(state.dev, ioc.get_qid());
	u64 data_cluster = -1;
	int ret;

	qcow2_assert(l2->get_update());

	//in case of being flushed, we can't update in-ram meta, so
	//exit and wait for flush completion
	//
	//If this slice is marked as PREP_FLUSH, the dependent refcount
	//block tables are being flushed, so delay this slice update
	//until our flushing is done
	if (l2->is_flushing() || l2->get_evicted() || l2->get_prep_flush()) {
		l2->add_waiter(ioc.get_tag());
		throw MetaUpdateException();
	}

	qcow2_assert(l2->read_ref() > 0);

	if (entry_is_allocating(virt_offset, false)) {
		u32 owner = entry_get_alloc_owner(virt_offset, false);

		if (owner != ioc.get_tag()) {
			l2->add_waiter_idx(ioc.get_tag(), idx_in_slice);
			throw MetaUpdateException();
		}
	} else {
		entry_mark_allocating(virt_offset, ioc.get_tag(), false);
	}

	data_cluster = state.cluster_allocator.allocate_cluster(ioc);
	qcow2_assert(l2->get_update() && !l2->is_flushing() &&
			!l2->get_evicted());
	if (data_cluster == -1) {
		l2->set_entry(idx_in_slice, 0);
		ret = -ENOSPC;
	} else {
		state.cluster_allocator.alloc_cluster_started(ioc,
				data_cluster, QCOW2_CLUSTER_USE::DATA);
		state.validate_cluster_use(data_cluster, virt_offset,
				QCOW2_CLUSTER_USE::DATA);
		data_cluster |= 1ULL << 63;
		*l2_entry = data_cluster;
		if (!l2->get_dirty(-1))
			state.meta_flushing.inc_dirtied_slice(true);
		l2->set_entry(idx_in_slice, data_cluster);
		ret = 0;
	}

	l2->check(state, __func__, __LINE__);

	entry_mark_allocated(virt_offset, false);
	l2->wakeup_all_idx(q, ioc.get_tag(), idx_in_slice);
	return ret;
}

//we get one extra reference of l2 when calling this function.
u64 Qcow2ClusterMapping::__map_cluster(const qcow2_io_ctx_t &ioc,
		Qcow2L2Table *l2, u64 offset, bool create_l2)
{
	const u32 idx_in_slice = ((l2_idx(offset) << 3) &
			(QCOW2_PARA::L2_TABLE_SLICE_BYTES - 1)) >> 3;
	u64 l2_entry;
	int ret;
	u64 host_offset;

	qcow2_assert(l2->read_ref() > 0);
	l2->check(state, __func__, __LINE__);

	/* the cache is being loaded */
	if (!l2->get_update()) {
		l2->add_waiter(ioc.get_tag());
		throw MetaUpdateException();
	}

	l2_entry = l2->get_entry_fast(idx_in_slice);
	if (l2->entry_allocated(l2_entry))
		goto exit;

	if (!create_l2)
		return 0;

	ret = build_mapping(ioc, offset, l2, idx_in_slice, &l2_entry);
	if (ret) {
		qcow2_log("%s %d: tag %d build l2 mapping failed %d\n",
				__func__, __LINE__, ioc.get_tag(), ret);
		return 0;
	}
exit:
	qcow2_assert(l2->entry_allocated(l2_entry));
	return l2_entry & ((1ULL << 63) - 1);
}


//any caller has to catch both MetaIoException and MetaUpdateException
u64 Qcow2ClusterMapping::map_cluster(const qcow2_io_ctx_t &ioc, u64 offset,
		bool create_l2)
{
	Qcow2L2Table *l2 = cache.find_slice(l2_slice_key(offset), true);
	u64 off_in_cls = offset & ((1ULL << cluster_bits) - 1);
	u64 host_off = 0;

	offset = offset & ~((1ULL << cluster_bits) - 1);

	// l2 could be freed when wakeup() is called, so refcount
	// has to be grabbed
	if (l2) {
		l2->get_ref();
	} else {
		try {
			l2 = create_l2_map(ioc, offset, create_l2);
		} catch (MetaIoException &meta_error) {
			throw MetaIoException();
		} catch (MetaUpdateException &meta_update_error) {
			throw MetaUpdateException();
		}
	}

	if (l2 == nullptr)
		return 0;

	try {
		host_off = __map_cluster(ioc, l2, offset, create_l2);
	} catch (MetaIoException &meta_error) {
		l2->put_ref();
		throw MetaIoException();
	} catch (MetaUpdateException &meta_update_error) {
		l2->put_ref();
		throw MetaUpdateException();
	}

	l2->put_ref();
	return host_off + off_in_cls;
}

void Qcow2ClusterMapping::dump_meta()
{
	qcow2_log("cluster mapping%s: max_alloc_entries %u/%u\n", __func__,
			max_alloc_entries, entry_alloc.size());
	state.l1_table.dump();
	cache.dump(state);
}

MetaFlushingState::MetaFlushingState(Qcow2TopTable &t, bool is_mapping):
	top(t), mapping(is_mapping)
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
		struct ublksrv_queue *q, Qcow2SliceMeta *m,
		struct ublk_io *io, int tag)
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
		co_io_job_submit_and_wait(tag);
		goto again;
	}

	if (ret < 0) {
		syslog(LOG_ERR, "%s: zero my cluster failed %d\n",
				__func__, ret);
		goto exit;
	}

	if (ret > 0) {
		struct io_uring_cqe *cqe;
		bool done = false;
		int io_ret = 0;

		co_io_job_submit_and_wait(tag);

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
		struct ublksrv_queue *q)
{
	std::vector<Qcow2SliceMeta *> &v1 = slices_to_flush;
	std::vector<Qcow2SliceMeta *>::const_iterator it = v1.cbegin();

	flush_log("%s: mapping %d to_flush %d, in_flight %d\n",
			__func__, mapping, v1.size(), slices_in_flight.size());

	if (v1.empty())
		return;

	while (it != v1.cend()) {
		int ret, tag;
		struct ublk_io_tgt *io;
		Qcow2SliceMeta *m;

		tag = qs.meta_flushing.alloc_tag(q);
		if (tag == -1)
			return;
		io = (struct ublk_io_tgt *)&q->ios[tag];
		m = *it;
		it = v1.erase(it);
		m->get_ref();
		io->co = __write_slice_co(qs, q, m, (struct ublk_io *)io, tag);
	}
}

//todo: run fsync before flushing top table, and global fsync should be
//fine, given top table seldom becomes dirty
co_io_job MetaFlushingState::__write_top_co(Qcow2State &qs,
		struct ublksrv_queue *q, struct ublk_io *io, int tag)
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
		co_io_job_submit_and_wait(tag);
		goto again;
	}

	if (ret < 0) {
		syslog(LOG_ERR, "%s: zero my cluster failed %d\n",
				__func__, ret);
		goto exit;
	}

	if (ret > 0) {
		struct io_uring_cqe *cqe;

		co_io_job_submit_and_wait(tag);

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
		struct ublksrv_queue *q)
{
	int ret, tag;
	struct ublk_io_tgt *io;

	if (top.is_flushing(parent_blk_idx))
		return;

	tag = qs.meta_flushing.alloc_tag(q);
	if (tag == -1)
		return;

	io = (struct ublk_io_tgt *)&q->ios[tag];
	io->co = __write_top_co(qs, q, (struct ublk_io *)io, tag);
}

void MetaFlushingState::__done(Qcow2State &qs, struct ublksrv_queue *q)
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
		struct ublksrv_queue *q)
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
		struct ublksrv_queue *q, struct ublk_io *io, int tag,
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
		co_io_job_submit_and_wait(tag);
		goto again;
	}

	if (ret < 0) {
		syslog(LOG_ERR, "%s: zero my cluster failed %d\n",
				__func__, ret);
		goto exit;
	}

	if (ret > 0) {
		struct io_uring_cqe *cqe;

		co_io_job_submit_and_wait(tag);

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
		struct ublksrv_queue *q)
{
	int ret, tag;
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
	io = (struct ublk_io_tgt *)&q->ios[tag];
	io->co = __zero_my_cluster_co(qs, q, (struct ublk_io *)io, tag, m);
}

void MetaFlushingState::run_flush(Qcow2State &qs,
		struct ublksrv_queue *q, int top_blk_idx)
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
	qcow2_log("%s %d: mapping %d state %d blk_idx %d entry_idx %d list size(%d %d)"
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

Qcow2MetaFlushing::Qcow2MetaFlushing(Qcow2State &qs): state(qs),
	tags(QCOW2_PARA::META_MAX_TAGS), mapping_stat(qs.l1_table, true),
	refcount_stat(qs.refcount_table, false),
	refcnt_blk_start(-1),
	refcnt_blk_end(-1)
{
	for (int i = 0; i < tags.size(); i++)
		tags[i] = true;
}

int Qcow2MetaFlushing::alloc_tag(struct ublksrv_queue *q) {
	for (size_t i = 0; i < tags.size(); i++) {
		if (tags[i]) {
			tags[i] = false;
			return i + q->q_depth;
		}
	}
	return -1;
}

void Qcow2MetaFlushing::free_tag(struct ublksrv_queue *q, int tag) {
	int depth = q->q_depth;

	qcow2_assert(tag >= depth && tag < depth + tags.size());
	tags[tag - depth] = true;
}

void Qcow2MetaFlushing::dump()
{
	syslog(LOG_ERR, "meta flushing: mapping: dirty slices %u, l1 dirty blocks %u\n",
			mapping_stat.slice_dirtied,
			state.l1_table.dirty_blks());
	syslog(LOG_ERR, "meta flushing: refcount: dirty slices %u, refcount table dirty blocks %u\n",
			refcount_stat.slice_dirtied,
			state.refcount_table.dirty_blks());
}

bool Qcow2MetaFlushing::handle_mapping_dependency_start_end(Qcow2State *qs,
		struct ublksrv_queue *q)
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
		struct ublksrv_queue *q)
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

void Qcow2MetaFlushing::run_flush(struct ublksrv_queue *q, int queued)
{
	Qcow2State *qs = dev_to_qcow2state(q->dev);
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
		flush_log("%s: exit flush: state %d/%d queued %d refcnt blks(%d %d)\n",
			__func__, mapping_stat.get_state(),
			refcount_stat.get_state(), queued,
			refcnt_blk_start, refcnt_blk_end);
}
