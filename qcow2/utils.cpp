// SPDX-License-Identifier: GPL-2.0
#include <cassert>

#include "qcow2.h"
#include "ublksrv_tgt.h"

IOWaiters::IOWaiters(): io_waiters({})
{
}

void IOWaiters::add_waiter(unsigned tag) {
	__mapping_meta_add_waiter(tag, 0x3fffff);
}

/* The caller is waiting on the specified entry update */
void IOWaiters::add_waiter_idx(unsigned tag, unsigned entry_idx) {
	__mapping_meta_add_waiter(tag, entry_idx);
}

/*
 * For wakeup other IOs waiting for this meta.
 *
 * qcow2_tgt_io_done() will wakeup for current IO, that isn't covered
 * by here.
 */
void IOWaiters::__mapping_meta_wakeup_all(const struct ublksrv_queue *q,
		unsigned my_tag, unsigned entry_idx, bool all) {
	std::unordered_set<unsigned> tags(move(io_waiters));
	std::unordered_set<unsigned>::const_iterator it = tags.cbegin();

	ublk_dbg(UBLK_DBG_QCOW2_IO_WAITER, "%s: %d %p my tag %d enter\n",
			__func__, __LINE__, this, my_tag);
	while (it != tags.cend()) {
		unsigned t = *it;
		unsigned tag = t & (QCOW2_MAX_QUEUE_DEPTH - 1);
		unsigned idx = t >> QCOW2_TAG_BITS;

		/* can't wakeup me */
		if (tag == my_tag) {
			it = tags.erase(it);
			continue;
		}

		ublk_dbg(UBLK_DBG_QCOW2_IO_WAITER, "%s: %d my tag %d tag %d idx %x\n",
				__func__, __LINE__, my_tag, tag, idx);
		if (all || idx == entry_idx) {
			struct ublk_io_tgt *__io =
				ublk_get_io_tgt_data(q, tag);

			it = tags.erase(it);
			__io->tgt_io_cqe = NULL;

			try {
				((struct ublk_io_tgt *)__io)->co.resume();
			} catch (MetaIoException &meta_error) {
				io_waiters.merge(tags);
				throw MetaIoException();
			} catch (MetaUpdateException &meta_update_error) {
				io_waiters.merge(tags);
				throw MetaUpdateException();
			}
		} else {
			it++;
		}
		ublk_dbg(UBLK_DBG_QCOW2_IO_WAITER, "%s: %d %p my tag %d tag %d idx %x\n",
				__func__, __LINE__, this, my_tag, tag, idx);
	}
	io_waiters.merge(tags);
	ublk_dbg(UBLK_DBG_QCOW2_IO_WAITER, "%s: %d %p my tag %d exit\n",
			__func__, __LINE__, this, my_tag);
}

void IOWaiters::wakeup_all(const struct ublksrv_queue *q, unsigned my_tag) {
	__mapping_meta_wakeup_all(q, my_tag, 0x3fffff, true);
}

void IOWaiters::wakeup_all_idx(const struct ublksrv_queue *q, unsigned my_tag,
		unsigned entry_idx) {
	__mapping_meta_wakeup_all(q, my_tag, entry_idx, false);
}
