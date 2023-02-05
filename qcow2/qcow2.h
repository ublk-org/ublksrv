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
#include <deque>
#include "lrucache.hpp"
#include "qcow2_format.h"
#include "qcow2_meta.h"

class Qcow2State;
class Qcow2Header;

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

	std::deque<T *> reclaimed_slices;

	int __figure_group_for_flush(Qcow2State &qs);
	int figure_group_from_dirty_list(Qcow2State &qs);
public:
	void add_slice_to_reclaim_list(T *t) {
		reclaimed_slices.push_back(t);
	}

	T *pick_slice_from_reclaim_list() {
		if (reclaimed_slices.empty())
			return nullptr;
		auto t = reclaimed_slices.front();
		reclaimed_slices.pop_front();

		return t;
	}

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
	bool has_dirty_slice(Qcow2State &qs);
	void shrink(Qcow2State &qs);
};

/* todo: remove caches in destructor */
class Qcow2ClusterMapping {
private:
	Qcow2State &state;
	slice_cache <Qcow2L2Table> cache;

	friend class Qcow2State;

	u32 cluster_bits, l2_entries_order;

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

	void wakeup_all(const struct ublksrv_queue *q, unsigned my_tag) {
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

	friend class Qcow2State;

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
	void alloc_cluster_zeroed(const struct ublksrv_queue *q,
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

	void __prep_write_slice(Qcow2State &qs, const struct ublksrv_queue *q);

	void __zero_my_cluster(Qcow2State &qs, const struct ublksrv_queue *q);
	co_io_job __zero_my_cluster_co(Qcow2State &qs,
		const struct ublksrv_queue *q, struct ublk_io_tgt *io, int tag,
		Qcow2SliceMeta *m);

	void __write_slices(Qcow2State &qs, const struct ublksrv_queue *q);
	co_io_job __write_slice_co(Qcow2State &qs,
		const struct ublksrv_queue *q, Qcow2SliceMeta *m,
		struct ublk_io_tgt *io, int tag);

	void __write_top(Qcow2State &qs, const struct ublksrv_queue *q);
	co_io_job  __write_top_co(Qcow2State &qs, const struct ublksrv_queue *q,
			struct ublk_io_tgt *io, int tag);

	void __done(Qcow2State &qs, const struct ublksrv_queue *q);
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
		ublk_dbg(UBLK_DBG_QCOW2_FLUSH, "%s: map %d slice_dirtied %u parent_blk_idx %d"
				" parent_entry_idx %d %d->%d to_flush %zd in_flight %zd\n",
				__func__, mapping, slice_dirtied,
				parent_blk_idx, parent_entry_idx, state,
				s, slices_to_flush.size(),
				slices_in_flight.size());
		state = s;
	}

	MetaFlushingState(Qcow2TopTable &t, bool is_mapping);
	void slice_is_done(const Qcow2SliceMeta*);
	void add_slice_to_flush(Qcow2SliceMeta *m);
	void run_flush(Qcow2State &qs, const struct ublksrv_queue *q,
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
			const struct ublksrv_queue *q);
	void handle_mapping_dependency(Qcow2State *qs,
			const struct ublksrv_queue *q);
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
	int alloc_tag(const struct ublksrv_queue *q);
	void free_tag(const struct ublksrv_queue *q, int tag);
	void run_flush(const struct ublksrv_queue *q, int queued);
	bool is_flushing();
};

class Qcow2State {
private:
	std::vector <Qcow2SliceMeta *> freed_slices;
public:
	const struct ublksrv_ctrl_dev_info *dev_info;
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

	void kill_slices(const struct ublksrv_queue *q);
	u32 add_meta_io(u32 qid, Qcow2MappingMeta *m);
	void dump_meta();
	void reclaim_slice(Qcow2SliceMeta *m);
	void remove_slice_from_evicted_list(Qcow2SliceMeta *m);
	bool has_dirty_slice();
	u32 get_l2_slices_count();
	void shrink_cache();

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
	return (Qcow2State *)dev->tgt.tgt_data;
}

static inline Qcow2State *queue_to_qcow2state(const struct ublksrv_queue *q)
{
	return (Qcow2State *)q->private_data;
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

static inline int qcow2_meta_io_done(const struct ublksrv_queue *q,
		const struct io_uring_cqe *cqe)
{
	if (!cqe)
		return -EAGAIN;

	int op = user_data_to_op(cqe->user_data);
	int tag = user_data_to_tag(cqe->user_data);
	u32 tgt_data = user_data_to_tgt_data(cqe->user_data);

	/* plain IO's tgt_data is zero */
	if (tgt_data == 0) {
		ublk_err( "%s target data is zero for meta io(tag %d op %u %llx)\n",
				__func__, tag, op, cqe->user_data);
		return -EAGAIN;
	}

	Qcow2State *qs = queue_to_qcow2state(q);
	/* retrieve meta data from target data part of cqe->user_data */
	Qcow2MappingMeta *meta = qs->get_meta_io(q->q_id, tgt_data - 1);

	if (cqe->res < 0)
		ublk_err( "%s: tag %d op %d tgt_data %d meta %p userdata %d\n",
			__func__, tag, user_data_to_op(cqe->user_data),
			tgt_data, meta, cqe->res);
	meta->io_done(*qs, q, cqe);

	return -EAGAIN;
}

#endif
