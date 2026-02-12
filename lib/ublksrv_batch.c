// SPDX-License-Identifier: MIT or LGPL-2.1-only

/*
 * UBLK_F_BATCH_IO support for libublksrv
 *
 * Implements batch-based operations instead of per-tag FETCH/COMMIT_AND_FETCH:
 * - UBLK_U_IO_PREP_IO_CMDS: One-time prep with buffer info
 * - UBLK_U_IO_FETCH_IO_CMDS: Multishot fetch returning 2-byte tags
 * - UBLK_U_IO_COMMIT_IO_CMDS: Batch commit of completed IOs
 */

#include <config.h>
#include <sys/mman.h>

#include "ublksrv_priv.h"

/* Compatibility definitions for older liburing versions */
#ifndef IORING_URING_CMD_MULTISHOT
#define IORING_URING_CMD_MULTISHOT	(1U << 1)
#endif

#ifndef IOU_PBUF_RING_INC
#define IOU_PBUF_RING_INC	(1U << 1)
#endif

/* Calculate element size based on device flags (8 or 16 bytes) */
static unsigned char ublk_batch_elem_buf_size(const struct _ublksrv_queue *q)
{
	/* Zero-copy, user-copy, and auto-buf-reg only need 8 bytes */
	if (q->state & (UBLKSRV_ZERO_COPY | UBLKSRV_USER_COPY | UBLKSRV_AUTO_ZC))
		return 8;

	/* Need extra 8 bytes for buffer address */
	return 16;
}

/* Calculate commit buffer size (page-aligned) */
static unsigned int ublk_batch_commit_buf_size(const struct _ublksrv_queue *q)
{
	unsigned elem_size = ublk_batch_elem_buf_size(q);
	unsigned int total = elem_size * q->q_depth;
	unsigned int page_sz = getpagesize();

	return round_up(total, page_sz);
}

/* Build user_data for batch commands */
static inline __u64 build_batch_user_data(unsigned short buf_idx, unsigned op,
					  unsigned short nr_elem)
{
	/* Encode: tag=buf_idx, op=cmd_op, tgt_data=nr_elem (full 16 bits) */
	return build_user_data(buf_idx, op, nr_elem, 0);
}

static inline unsigned short batch_user_data_to_nr_elem(__u64 user_data)
{
	return user_data_to_tgt_data(user_data);
}

/* Allocate batch IO buffers for a queue */
int ublksrv_batch_alloc_bufs(struct _ublksrv_queue *q)
{
	struct ublksrv_queue_batch *b = &q->batch;
	unsigned int page_sz = getpagesize();
	unsigned int fetch_buf_size;
	void *buf;
	int i, ret;

	b->commit_buf_elem_size = ublk_batch_elem_buf_size(q);
	b->commit_buf_size = ublk_batch_commit_buf_size(q);

	/* Allocate commit buffer memory */
	ret = posix_memalign(&buf, page_sz,
			     b->commit_buf_size * UBLK_BATCH_NR_COMMIT_BUFS);
	if (ret || !buf)
		return -ENOMEM;

	b->commit_buf_mem = buf;

	/* Lock commit buffer pages for fast access */
	if (mlock(b->commit_buf_mem,
		  b->commit_buf_size * UBLK_BATCH_NR_COMMIT_BUFS))
		ublk_err("%s: can't lock commit buffer: %s\n", __func__,
			strerror(errno));

	/* Setup commit buffer state */
	for (i = 0; i < UBLK_BATCH_NR_COMMIT_BUFS; i++) {
		b->commit_bufs[i].buf = (char *)buf + i * b->commit_buf_size;
		b->commit_bufs[i].done = 0;
		b->commit_bufs[i].count = b->commit_buf_size / b->commit_buf_elem_size;
	}

	/* Allocate fetch buffers (page-aligned) */
	fetch_buf_size = round_up(q->q_depth * 2, page_sz);
	for (i = 0; i < UBLK_BATCH_NR_FETCH_BUFS; i++) {
		b->fetch_bufs[i].fetch_buf_size = fetch_buf_size;

		ret = posix_memalign((void **)&b->fetch_bufs[i].fetch_buf,
				     page_sz, fetch_buf_size);
		if (ret || !b->fetch_bufs[i].fetch_buf)
			goto fail_fetch;

		/* Lock fetch buffer pages for fast fetching */
		if (mlock(b->fetch_bufs[i].fetch_buf, fetch_buf_size))
			ublk_err("%s: can't lock fetch buffer: %s\n", __func__,
				strerror(errno));

		/* Setup buffer ring for multishot fetch */
		b->fetch_bufs[i].br = io_uring_setup_buf_ring(&q->ring, 1,
				i, IOU_PBUF_RING_INC, &ret);
		if (!b->fetch_bufs[i].br) {
			ublk_err("%s: qid %d buffer ring %d setup failed: %d (%s)\n",
				__func__, q->q_id, i, ret, strerror(-ret));
			free(b->fetch_bufs[i].fetch_buf);
			goto fail_fetch;
		}
		ublk_dbg(UBLK_DBG_QUEUE, "%s: qid %d buffer ring %d setup ok\n",
			__func__, q->q_id, i);
		b->fetch_bufs[i].fetch_buf_off = 0;
	}

	/* Determine batch command flags */
	b->cmd_flags = 0;
	if (ublksrv_queue_use_buf(q))
		b->cmd_flags |= UBLK_BATCH_F_HAS_BUF_ADDR;

	b->cur_commit_buf = 0;
	b->prep_done = 0;

	ublk_dbg(UBLK_DBG_QUEUE, "%s: q%d elem_size=%u buf_size=%u flags=%x\n",
		__func__, q->q_id, b->commit_buf_elem_size,
		b->commit_buf_size, b->cmd_flags);

	return 0;

fail_fetch:
	while (--i >= 0) {
		io_uring_free_buf_ring(&q->ring, b->fetch_bufs[i].br, 1, i);
		munlock(b->fetch_bufs[i].fetch_buf, b->fetch_bufs[i].fetch_buf_size);
		free(b->fetch_bufs[i].fetch_buf);
	}
	munlock(b->commit_buf_mem,
		b->commit_buf_size * UBLK_BATCH_NR_COMMIT_BUFS);
	free(b->commit_buf_mem);
	b->commit_buf_mem = NULL;
	return -ENOMEM;
}

/* Free batch IO buffers */
void ublksrv_batch_free_bufs(struct _ublksrv_queue *q)
{
	struct ublksrv_queue_batch *b = &q->batch;
	int i;

	for (i = 0; i < UBLK_BATCH_NR_FETCH_BUFS; i++) {
		if (b->fetch_bufs[i].br) {
			io_uring_free_buf_ring(&q->ring, b->fetch_bufs[i].br, 1, i);
			b->fetch_bufs[i].br = NULL;
		}
		if (b->fetch_bufs[i].fetch_buf) {
			munlock(b->fetch_bufs[i].fetch_buf,
				b->fetch_bufs[i].fetch_buf_size);
			free(b->fetch_bufs[i].fetch_buf);
			b->fetch_bufs[i].fetch_buf = NULL;
		}
	}

	if (b->commit_buf_mem) {
		munlock(b->commit_buf_mem,
			b->commit_buf_size * UBLK_BATCH_NR_COMMIT_BUFS);
		free(b->commit_buf_mem);
		b->commit_buf_mem = NULL;
	}
}

/*
 * Common helper for issuing PREP or COMMIT batch commands.
 * Returns the allocated SQE, or NULL on failure.
 */
static struct io_uring_sqe *ublksrv_batch_io_cmd(struct _ublksrv_queue *q,
						 unsigned int cmd_op,
						 void *buf,
						 unsigned short buf_idx,
						 unsigned short nr_elem)
{
	struct ublksrv_queue_batch *b = &q->batch;
	struct io_uring_sqe *sqe;
	struct ublk_batch_io *cmd;

	sqe = ublksrv_alloc_sqe(&q->ring);
	if (!sqe)
		return NULL;

	cmd = (struct ublk_batch_io *)ublksrv_get_sqe_cmd(sqe);

	ublksrv_set_sqe_cmd_op(sqe, cmd_op);
	sqe->fd = 0;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->flags = IOSQE_FIXED_FILE;
	sqe->addr = (__u64)buf;
	sqe->len = b->commit_buf_elem_size * nr_elem;

	cmd->q_id = q->q_id;
	cmd->flags = b->cmd_flags;
	cmd->nr_elem = nr_elem;
	cmd->elem_bytes = b->commit_buf_elem_size;
	cmd->reserved = 0;
	cmd->reserved2 = 0;

	io_uring_sqe_set_data64(sqe, build_batch_user_data(buf_idx,
		_IOC_NR(cmd_op), nr_elem));

	q->cmd_inflight++;

	return sqe;
}

/* Issue UBLK_U_IO_PREP_IO_CMDS - one-time setup */
static int ublksrv_batch_queue_prep_io_cmds(struct _ublksrv_queue *q)
{
	struct ublksrv_queue_batch *b = &q->batch;
	struct batch_commit_buf *cb = &b->commit_bufs[0];
	unsigned short nr_elem = q->q_depth;
	int i;

	/* Fill prep buffer with all tags and buffer info */
	for (i = 0; i < nr_elem; i++) {
		struct ublk_batch_elem *elem = (struct ublk_batch_elem *)
			((char *)cb->buf + i * b->commit_buf_elem_size);

		elem->tag = i;
		elem->result = 0;

		if (q->state & UBLKSRV_AUTO_ZC)
			elem->buf_index = i;
		else if (ublksrv_queue_use_buf(q))
			elem->buf_addr = (__u64)q->ios[i].buf_addr;
	}

	if (!ublksrv_batch_io_cmd(q, UBLK_U_IO_PREP_IO_CMDS, cb->buf, 0, nr_elem)) {
		ublk_err("%s: run out of sqe qid %d\n", __func__, q->q_id);
		return -1;
	}

	ublk_dbg(UBLK_DBG_IO_CMD, "%s: qid %d nr_elem %u elem_bytes %u\n",
		__func__, q->q_id, nr_elem, b->commit_buf_elem_size);

	return 0;
}

/* Issue UBLK_U_IO_FETCH_IO_CMDS (multishot) */
static void ublksrv_batch_queue_fetch(struct _ublksrv_queue *q, int buf_idx)
{
	struct batch_fetch_buf *fb = &q->batch.fetch_bufs[buf_idx];
	struct io_uring_sqe *sqe;
	struct ublk_batch_io *cmd;
	unsigned short nr_elem = fb->fetch_buf_size / 2;

	/* Add buffer to the buffer ring */
	io_uring_buf_ring_add(fb->br, fb->fetch_buf, fb->fetch_buf_size, 0, 0, 0);
	io_uring_buf_ring_advance(fb->br, 1);

	sqe = ublksrv_alloc_sqe(&q->ring);
	if (!sqe) {
		ublk_err("%s: run out of sqe qid %d\n", __func__, q->q_id);
		return;
	}

	cmd = (struct ublk_batch_io *)ublksrv_get_sqe_cmd(sqe);

	ublksrv_set_sqe_cmd_op(sqe, UBLK_U_IO_FETCH_IO_CMDS);
	sqe->fd = 0;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->flags = IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
	sqe->rw_flags = IORING_URING_CMD_MULTISHOT;
	sqe->buf_group = buf_idx;

	cmd->q_id = q->q_id;
	cmd->flags = 0;
	cmd->nr_elem = nr_elem;
	cmd->elem_bytes = 2;  /* Each tag is 2 bytes */
	cmd->reserved = 0;
	cmd->reserved2 = 0;

	io_uring_sqe_set_data64(sqe, build_batch_user_data(buf_idx,
		_IOC_NR(UBLK_U_IO_FETCH_IO_CMDS), nr_elem));

	q->cmd_inflight++;
	fb->fetch_buf_off = 0;

	ublk_dbg(UBLK_DBG_IO_CMD, "%s: qid %d buf_idx %d nr_elem %u\n",
		__func__, q->q_id, buf_idx, nr_elem);
}

/* Issue initial batch fetch commands */
void ublksrv_batch_start_fetch(struct _ublksrv_queue *q)
{
	int i;

	/* Issue one-time prep command */
	ublksrv_batch_queue_prep_io_cmds(q);

	/* Issue multishot fetch commands (double-buffering) */
	for (i = 0; i < UBLK_BATCH_NR_FETCH_BUFS; i++)
		ublksrv_batch_queue_fetch(q, i);

	q->batch.prep_done = 1;
}

/* Submit commit command and swap to other buffer */
void ublksrv_batch_submit_commit(struct _ublksrv_queue *q)
{
	struct ublksrv_queue_batch *b = &q->batch;
	struct batch_commit_buf *cb = &b->commit_bufs[b->cur_commit_buf];
	unsigned short nr_elem = cb->done;

	/* Nothing to commit */
	if (nr_elem == 0)
		return;

	if (!ublksrv_batch_io_cmd(q, UBLK_U_IO_COMMIT_IO_CMDS, cb->buf,
				  b->cur_commit_buf, nr_elem)) {
		ublk_err("%s: run out of sqe qid %d\n", __func__, q->q_id);
		return;
	}

	ublk_dbg(UBLK_DBG_IO_CMD, "%s: qid %d buf %d nr_elem %u\n",
		__func__, q->q_id, b->cur_commit_buf, nr_elem);

	/* Swap to the other buffer */
	b->cur_commit_buf = 1 - b->cur_commit_buf;
	b->commit_bufs[b->cur_commit_buf].done = 0;
}

/* Handle fetch CQE - call handle_io_async for each tag */
static void ublksrv_batch_handle_fetch_cqe(struct _ublksrv_queue *q,
					   struct io_uring_cqe *cqe)
{
	unsigned short buf_idx = user_data_to_tag(cqe->user_data);
	struct batch_fetch_buf *fb = &q->batch.fetch_bufs[buf_idx];
	unsigned start = fb->fetch_buf_off;
	unsigned end = start + cqe->res;
	unsigned i;

	if (cqe->res < 0) {
		if (cqe->res != -ENOBUFS)
			ublk_err("%s: qid %d fetch failed: %d\n",
				__func__, q->q_id, cqe->res);
		return;
	}

	/* Process each 2-byte tag in the buffer */
	for (i = start; i < end; i += 2) {
		unsigned short tag = *(unsigned short *)
			((char *)fb->fetch_buf + i);

		if (tag >= q->q_depth) {
			ublk_err("%s: qid %d invalid tag %u\n",
				__func__, q->q_id, tag);
			continue;
		}

		q->tgt_ops->handle_io_async(local_to_tq(q), &q->ios[tag].data);
	}

	fb->fetch_buf_off = end;

	ublk_dbg(UBLK_DBG_IO_CMD, "%s: qid %d buf %d processed %u tags\n",
		__func__, q->q_id, buf_idx, (end - start) / 2);
}

/* Handle prep/commit CQE completion */
static void ublksrv_batch_handle_commit_cqe(struct _ublksrv_queue *q,
					    struct io_uring_cqe *cqe,
					    unsigned op)
{
	struct ublksrv_queue_batch *b = &q->batch;
	unsigned short buf_idx = user_data_to_tag(cqe->user_data);

	if (op == _IOC_NR(UBLK_U_IO_PREP_IO_CMDS)) {
		if (cqe->res != 0)
			ublk_err("%s: qid %d prep failed: %d\n",
				__func__, q->q_id, cqe->res);
		/* Prep buffer (commit_bufs[0]) is no longer needed for prep */
	} else if (op == _IOC_NR(UBLK_U_IO_COMMIT_IO_CMDS)) {
		unsigned short nr_elem = batch_user_data_to_nr_elem(cqe->user_data);
		unsigned expected = b->commit_buf_elem_size * nr_elem;

		if (cqe->res != (int)expected && cqe->res >= 0) {
			ublk_err("%s: qid %d commit partial: %d/%u\n",
				__func__, q->q_id, cqe->res, expected);
		} else if (cqe->res < 0) {
			ublk_err("%s: qid %d commit failed: %d\n",
				__func__, q->q_id, cqe->res);
		}

		ublk_dbg(UBLK_DBG_IO_CMD, "%s: qid %d buf %d commit done\n",
			__func__, q->q_id, buf_idx);
	}
}

/*
 * Handle batch IO CQE - returns true if handled, false to fall through
 * to normal (non-batch) CQE handling.
 */
bool ublksrv_batch_handle_cqe(struct _ublksrv_queue *q,
			      struct io_uring_cqe *cqe,
			      unsigned cmd_op)
{
	switch (cmd_op) {
	case _IOC_NR(UBLK_U_IO_FETCH_IO_CMDS):
		/*
		 * For multishot FETCH, only decrement cmd_inflight when
		 * the multishot actually ends (no MORE flag or error).
		 * While multishot is active, each CQE doesn't consume
		 * the command - it stays in flight.
		 */
		if (cqe->res < 0 && cqe->res != -ENOBUFS) {
			/* Error - multishot ended */
			q->cmd_inflight--;
			q->state |= UBLKSRV_QUEUE_STOPPING;
		} else {
			ublksrv_batch_handle_fetch_cqe(q, cqe);

			/* Rearm multishot if it stopped */
			if (!(cqe->flags & IORING_CQE_F_MORE) ||
			    cqe->res == -ENOBUFS) {
				unsigned short buf_idx = user_data_to_tag(cqe->user_data);
				q->cmd_inflight--;
				ublksrv_batch_queue_fetch(q, buf_idx);
			}
			/* If MORE flag is set, multishot still active - don't decrement */
		}
		return true;

	case _IOC_NR(UBLK_U_IO_PREP_IO_CMDS):
	case _IOC_NR(UBLK_U_IO_COMMIT_IO_CMDS):
		q->cmd_inflight--;
		ublksrv_batch_handle_commit_cqe(q, cqe, cmd_op);
		return true;
	}

	/* Not a batch command - fall through to normal handling */
	return false;
}
