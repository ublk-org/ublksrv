// SPDX-License-Identifier: GPL-2.0

#include <config.h>
#include <new>
#include <vector>
#include "ublksrv_tgt.h"
#include "ublksrv_tgt_endian.h"
#include "cliserv.h"
#include "nbd.h"

//#define NBD_DEBUG_HANDSHAKE 1
//#define NBD_DEBUG_IO 1
//#define NBD_DEBUG_CQE 1

#ifdef NBD_DEBUG_IO
#define NBD_IO_DBG  ublk_err
#else
#define NBD_IO_DBG(...)
#endif

#ifdef NBD_DEBUG_HANDSHAKE
#define NBD_HS_DBG  ublk_err
#else
#define NBD_HS_DBG(...)
#endif

#define nbd_err	ublk_err

#define NBD_MAX_NAME	512

#define NBD_OP_READ_REPLY  0x81

struct nbd_tgt_data {
	bool unix_sock;
	bool use_send_zc;
};

#ifndef HAVE_LIBURING_SEND_ZC
#define io_uring_prep_sendmsg_zc io_uring_prep_sendmsg
#define IORING_CQE_F_NOTIF (1U << 3)
#endif

struct nbd_queue_data {
	unsigned short in_flight_ios;		/* total ios awaiting NBD reply */

	unsigned short recv_started:1;		/* recv coroutine is running */
	unsigned short use_send_zc:1;		/* sendmsg_zc instead of sendmsg */
	unsigned short use_unix_sock:1;		/* AF_UNIX backend vs TCP */
	unsigned short need_handle_recv:1;	/* recv CQE saved, resume in bg */
	unsigned short chain_submitted:1;	/* link chain handed to kernel; */
						/* false again once last CQE in. */

	unsigned int chained_send_ios;		/* sends still in current chain */

	/*
	 * Staging queue for ios that arrived while the previous link chain
	 * was still in flight (chain_submitted=true). nbd_handle_send_bg()
	 * flushes the whole vector as one fresh chain once that clears.
	 */
	std::vector <const struct ublk_io_data *> next_chain;

	struct io_uring_sqe *last_send_sqe;	/* tail of the in-build chain */
	struct nbd_reply reply;			/* recv buffer for one reply */
	struct io_uring_cqe recv_cqe;		/* deferred recv CQE */
};

struct nbd_io_data {
	unsigned int cmd_cookie;
	unsigned int done;	//for handling partial recv
};

static inline struct nbd_queue_data *
nbd_get_queue_data(const struct ublksrv_queue *q)
{
	return (struct nbd_queue_data *)q->private_data;
}

static inline struct nbd_io_data *
io_tgt_to_nbd_data(const struct ublk_io_tgt *io)
{
	return (struct nbd_io_data *)(io + 1);
}

static int req_to_nbd_cmd_type(const struct ublksrv_io_desc *iod)
{
	switch (ublksrv_get_op(iod)) {
	case UBLK_IO_OP_DISCARD:
		return NBD_CMD_TRIM;
	case UBLK_IO_OP_FLUSH:
		return NBD_CMD_FLUSH;
	case UBLK_IO_OP_WRITE:
		return NBD_CMD_WRITE;
	case UBLK_IO_OP_READ:
		return NBD_CMD_READ;
	default:
		return -1;
	}
}

/*
 * The recv side of the NBD connection is driven by a single shared slot,
 * not by any per-IO tag. We reserve one extra tag at q->q_depth via
 * tgt->extra_ios = 1 in nbd_setup_tgt(); that slot's ublk_io_data is what
 * carries the recv coroutine and the deferred recv CQE. All four sites
 * that need to refer to "the recv slot" should go through this helper.
 */
static inline unsigned nbd_recv_tag(const struct ublksrv_queue *q)
{
	return q->q_depth;
}

static inline bool is_recv_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	return data->tag == nbd_recv_tag(q);
}

#define NBD_COOKIE_BITS 32
static inline u64 nbd_cmd_handle(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct nbd_io_data *nbd_data)
{
	u64 cookie = nbd_data->cmd_cookie;

	return (cookie << NBD_COOKIE_BITS) | ublk_unique_tag(q->q_id, data->tag);
}

static inline u32 nbd_handle_to_cookie(u64 handle)
{
	return (u32)(handle >> NBD_COOKIE_BITS);
}

static inline u32 nbd_handle_to_tag(u64 handle)
{
	return (u32)handle;
}

static inline void __nbd_build_req(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct nbd_io_data *nbd_data,
		u32 type, struct nbd_request *req)
{
	u32 nbd_cmd_flags = 0;
	u64 handle;

	if (data->iod->op_flags & UBLK_IO_F_FUA)
		nbd_cmd_flags |= NBD_CMD_FLAG_FUA;

	req->type = htonl(type | nbd_cmd_flags);

	if (type != NBD_CMD_FLUSH) {
		req->from = cpu_to_be64((u64)data->iod->start_sector << 9);
		req->len = htonl(data->iod->nr_sectors << 9);
	}

	handle = nbd_cmd_handle(q, data, nbd_data);
	memcpy(req->handle, &handle, sizeof(handle));
}

/*
 * Send-chain helpers
 * ------------------
 * All sendmsg sqes on the socket are hard-linked (IOSQE_IO_LINK) so their
 * bytes never interleave on the wire. These helpers are the only places that
 * mutate the chain bookkeeping (chained_send_ios, chain_submitted,
 * last_send_sqe); keeping them together makes the state machine in
 * nbd_handle_io_bg() easier to follow. See the big comment above
 * nbd_handle_send_bg() for the full flow.
 */

/* The current chain is busy iff it has been submitted to the kernel */
static inline bool nbd_send_chain_busy(const struct nbd_queue_data *q_data)
{
	return q_data->chained_send_ios > 0 && q_data->chain_submitted;
}

/* Record a freshly queued sendmsg sqe as the new tail of the in-build chain */
static inline void nbd_chain_append_send(struct nbd_queue_data *q_data,
		struct io_uring_sqe *sqe)
{
	q_data->last_send_sqe = sqe;
	q_data->chained_send_ios += 1;
}

/* A send CQE arrived; the chain has fully drained once the last one is in */
static inline void nbd_chain_on_send_done(struct nbd_queue_data *q_data)
{
	ublk_assert(q_data->chained_send_ios);
	if (--q_data->chained_send_ios == 0)
		q_data->chain_submitted = false;
}

/* Close the in-build chain by unlinking its tail before it is submitted */
static inline void nbd_chain_finalize(struct nbd_queue_data *q_data)
{
	if (q_data->last_send_sqe) {
		q_data->last_send_sqe->flags &= ~IOSQE_IO_LINK;
		q_data->last_send_sqe = NULL;
	}
}

/*
 * handle_io_background() is the last callback before io_uring_enter(), so any
 * sqes still chained here are about to be handed to the kernel.
 */
static inline void nbd_chain_mark_submitted(struct nbd_queue_data *q_data)
{
	if (q_data->chained_send_ios > 0)
		q_data->chain_submitted = true;
}

static int nbd_queue_req(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct msghdr *msg)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	const struct ublksrv_io_desc *iod = data->iod;
	unsigned ublk_op = ublksrv_get_op(iod);
	unsigned msg_flags = MSG_NOSIGNAL;
	struct io_uring_sqe *sqe[1];

	ublk_queue_alloc_sqes(q, sqe, 1);
	if (!sqe[0]) {
		nbd_err("%s: get sqe failed, tag %d op %d\n",
				__func__, data->tag, ublk_op);
		return -ENOMEM;
	}

	/*
	 * Always set WAITALL, so io_uring will handle retry in case of
	 * short send, see below link:
	 *
	 * https://lore.kernel.org/io-uring/b8011ec8-8d43-9b9b-4dcc-53b6cb272354@samba.org/
	 *
	 * note: It was added for recv* in 5.18 and send* in 5.19.
	 */
	msg_flags |= MSG_WAITALL;

	if (q_data->use_send_zc)
		io_uring_prep_sendmsg_zc(sqe[0], q->q_id + 1, msg, msg_flags);
	else
		io_uring_prep_sendmsg(sqe[0], q->q_id + 1, msg, msg_flags);

	/*
	 * The encoded nr_sectors should only be used for validating write req
	 * when its cqe is completed, since iod data isn't available at that time
	 * because request can be reused.
	 */
	sqe[0]->user_data = build_user_data(data->tag, ublk_op, ublk_op ==
			UBLK_IO_OP_WRITE ? data->iod->nr_sectors : 0, 1);
	io_uring_sqe_set_flags(sqe[0], /*IOSQE_CQE_SKIP_SUCCESS |*/
			IOSQE_FIXED_FILE | IOSQE_IO_LINK);
	nbd_chain_append_send(q_data, sqe[0]);

	NBD_IO_DBG("%s: queue io op %d(%llu %x %llx) ios(%u %u)"
			" (qid %d tag %u, cmd_op %u target: %d, user_data %llx)\n",
		__func__, ublk_op, data->iod->start_sector,
		data->iod->nr_sectors, sqe[0]->addr,
		q_data->in_flight_ios, q_data->chained_send_ios,
		q->q_id, data->tag, ublk_op, 1, sqe[0]->user_data);

	return 1;
}

static co_io_job __nbd_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, struct ublk_io_tgt *io)
{
	int ret = -EIO;
	struct nbd_request req = {.magic = htonl(NBD_REQUEST_MAGIC),};
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	struct nbd_io_data *nbd_data = io_tgt_to_nbd_data(io);
	int type = req_to_nbd_cmd_type(data->iod);
	unsigned op = ublksrv_get_op(data->iod);
	struct iovec iov[2] = {
		[0] = {
			.iov_base = (void *)&req,
			.iov_len = sizeof(req),
		},
		[1] = {
			.iov_base = (void *)data->iod->addr,
			.iov_len = data->iod->nr_sectors << 9,
		},
	};
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = (op == UBLK_IO_OP_WRITE) ? 2UL : 1UL,
	};

	if (type == -1)
		goto fail;

	nbd_data->cmd_cookie += 1;

	__nbd_build_req(q, data, nbd_data, type, &req);
	q_data->in_flight_ios += 1;

	nbd_data->done = 0;

again:
	ret = nbd_queue_req(q, data, &msg);
	if (ret < 0)
		goto fail;

	co_await__suspend_always(data->tag);
	if (io->tgt_io_cqe->res == -EAGAIN)
		goto again;
	ret = io->tgt_io_cqe->res;
fail:
	if (ret < 0)
		nbd_err("%s: err %d\n", __func__, ret);
	else
		ret += nbd_data->done;
	ublksrv_complete_io(q, data->tag, ret);
	q_data->in_flight_ios -= 1;
	NBD_IO_DBG("%s: tag %d res %d\n", __func__, data->tag, ret);

	co_return;
}

static int nbd_handle_recv_reply(const struct ublksrv_queue *q,
		struct nbd_io_data *recv_nbd_data,
		const struct io_uring_cqe *cqe,
		const struct ublk_io_data **io_data)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	const struct ublk_io_data *data;
	struct ublk_io_tgt *io;
	struct nbd_io_data *io_nbd_data;
	u64 handle;
	int tag, hwq;
	unsigned ublk_op;

	if (cqe->res < 0) {
		nbd_err("%s %d: reply cqe %d\n", __func__,
				__LINE__, cqe->res);
		return cqe->res;
	}
	if (cqe->res == 0 && !recv_nbd_data->done) {
		nbd_err("%s %d: zero reply cqe %d %llx\n", __func__,
				__LINE__, cqe->res, cqe->user_data);
	}

	if (ntohl(q_data->reply.magic) != NBD_REPLY_MAGIC) {
		nbd_err("%s %d: reply bad magic %x res %d\n",
				__func__, __LINE__,
				ntohl(q_data->reply.magic), cqe->res);
		return -EPROTO;
	}

	if (cqe->res + recv_nbd_data->done != sizeof(struct nbd_reply)) {
		nbd_err("%s %d: bad reply cqe %d %llx, done %u\n",
				__func__, __LINE__,
				cqe->res, cqe->user_data,
				recv_nbd_data->done);
	}
	ublk_assert(cqe->res + recv_nbd_data->done == sizeof(struct nbd_reply));

	memcpy(&handle, q_data->reply.handle, sizeof(handle));
	tag = nbd_handle_to_tag(handle);
	hwq = ublk_unique_tag_to_hwq(tag);
	tag = ublk_unique_tag_to_tag(tag);

	if (tag >= q->q_depth) {
		nbd_err("%s %d: tag is too big %d\n", __func__,
				__LINE__, tag);
		return -EINVAL;
	}

	if (hwq != q->q_id) {
		nbd_err("%s %d: hwq is too big %d\n", __func__,
				__LINE__, hwq);
		return -EINVAL;
	}

	data = ublksrv_queue_get_io_data(q, tag);
	io = __ublk_get_io_tgt_data(data);
	io_nbd_data = io_tgt_to_nbd_data(io);
	if (io_nbd_data->cmd_cookie != nbd_handle_to_cookie(handle)) {
		nbd_err("%s %d: cookie not match tag %d: %x %lx\n",
				__func__, __LINE__, data->tag,
				io_nbd_data->cmd_cookie, handle);
		return -EINVAL;
	}

	ublk_op = ublksrv_get_op(data->iod);
	if (ublk_op == UBLK_IO_OP_READ) {
		*io_data = data;
		return 1;
	}

	{
		int err = ntohl(q_data->reply.error);
		struct io_uring_cqe fake_cqe;

		NBD_IO_DBG("%s: got write reply, tag %d res %d\n",
					__func__, data->tag, err);

		if (err)
			fake_cqe.res = -EIO;
		else if (ublk_op == UBLK_IO_OP_WRITE)
			fake_cqe.res = data->iod->nr_sectors << 9;
		else
			fake_cqe.res = 0;

		io->tgt_io_cqe = &fake_cqe;
		io->co.resume();
		return 0;
	}
}

static void __nbd_resume_read_req(const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe, unsigned done)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	struct nbd_io_data *nbd_data = io_tgt_to_nbd_data(io);

	nbd_data->done = done;
	io->tgt_io_cqe = cqe;
	io->co.resume();
}

/* recv completion drives the whole IO flow */
static inline int nbd_start_recv(const struct ublksrv_queue *q,
		struct nbd_io_data *nbd_data, void *buf, int len,
		bool reply, unsigned done)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	unsigned int op = reply ? NBD_OP_READ_REPLY : UBLK_IO_OP_READ;
	unsigned int tag = nbd_recv_tag(q);
	struct io_uring_sqe *sqe[1];

	ublk_queue_alloc_sqes(q, sqe, 1);
	if (!sqe[0]) {
		nbd_err("%s: get sqe failed, len %d reply %d done %d\n",
				__func__, len, reply, done);
		return -ENOMEM;
	}

	nbd_data->done = done;
	io_uring_prep_recv(sqe[0], q->q_id + 1, (char *)buf + done, len - done, MSG_WAITALL);
	io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE);

	/* bit63 marks us as tgt io */
	sqe[0]->user_data = build_user_data(tag, op, 0, 1);

	ublk_assert(q_data->in_flight_ios);
	NBD_IO_DBG("%s: q_inflight %d queue recv %s"
				"(qid %d tag %u, target: %d, user_data %llx)\n",
			__func__, q_data->in_flight_ios, reply ? "reply" : "io",
			q->q_id, tag, 1, sqe[0]->user_data);
	return 0;
}

/*
 * Submit recv worker for reading nbd reply or read io data
 *
 * return value:
 *
 * 0 : queued via io_uring
 * len : data read already, must be same with len
 * < 0 : failure
 */
static int nbd_do_recv(const struct ublksrv_queue *q,
		struct nbd_io_data *nbd_data, int fd,
		void *buf, unsigned len)
{
	unsigned msg_flags = MSG_DONTWAIT | MSG_WAITALL;
	int i = 0;
	unsigned done = 0;
	const int loops = len < 512 ? 16 : 32;
	int ret;

	while (i++ < loops && done < len) {
		ret = recv(fd, (char *)buf + done, len - done, msg_flags);
		if (ret > 0)
			done += ret;

		if (!done)
			break;
	}
	if (done == len)
		return done;

	NBD_IO_DBG("%s: sync(non-blocking) recv %d(%s)/%d/%u\n",
			__func__, ret, strerror(errno), done, len);
	ret = nbd_start_recv(q, nbd_data, buf, len, len < 512, done);

	return ret;
}

/*
 * Every request will be responded with one reply, and we complete the
 * request after the reply is received.
 *
 * Read request is a bit special, since the data returned are received
 * with the reply together, so we have to handle read IO data here.
 */
static co_io_job __nbd_handle_recv(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, struct ublk_io_tgt *io)
{
	struct nbd_io_data *nbd_data = io_tgt_to_nbd_data(io);
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	int fd = q->dev->tgt.fds[q->q_id + 1];
	/*
	 * io_uring_cqe ends in a flexible array member, so it can't live by
	 * value in this coroutine's frame; back it with a plain buffer and
	 * use it through a pointer instead.
	 */
	u64 cqe_buf[2] = {0};
	struct io_uring_cqe *fake_cqe = (struct io_uring_cqe *)cqe_buf;

	q_data->recv_started = 1;

	while (q_data->in_flight_ios > 0) {
		const struct ublk_io_data *io_data = NULL;
		int ret;

		/*
		 * Receive one reply header. nbd_do_recv() either drains it
		 * in-line (returns the full length), queues a recv sqe and
		 * returns 0 (we suspend until its CQE), or fails. When drained
		 * in-line we drive handling with a zero-res fake CQE; otherwise
		 * the real recv CQE carries the byte count. A -EAGAIN CQE just
		 * means "retry the recv".
		 */
		do {
			ret = nbd_do_recv(q, nbd_data, fd, &q_data->reply,
					sizeof(q_data->reply));
			if (ret == sizeof(q_data->reply)) {
				nbd_data->done = ret;
				fake_cqe->res = 0;
				io->tgt_io_cqe = fake_cqe;
				break;
			}
			if (ret < 0)
				goto out;
			co_await__suspend_always(data->tag);
		} while (io->tgt_io_cqe->res == -EAGAIN);

		ret = nbd_handle_recv_reply(q, nbd_data, io->tgt_io_cqe, &io_data);
		if (ret < 0)
			break;
		if (!ret)	/* non-read reply already completed its io */
			continue;

		/* read reply: receive the payload into the io buffer */
		ublk_assert(io_data != NULL);
		unsigned int len = io_data->iod->nr_sectors << 9;

		do {
			ret = nbd_do_recv(q, nbd_data, fd,
					(void *)io_data->iod->addr, len);
			if (ret == (int)len) {
				nbd_data->done = ret;
				fake_cqe->res = 0;
				io->tgt_io_cqe = fake_cqe;
				break;
			}
			if (ret < 0)
				goto out;
			co_await__suspend_always(data->tag);
		} while (io->tgt_io_cqe->res == -EAGAIN);

		__nbd_resume_read_req(io_data, io->tgt_io_cqe, nbd_data->done);
	}
out:
	q_data->recv_started = 0;
	co_return;
}

static int nbd_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);

	/*
	 * Put the io in the queue and submit them after
	 * the current chain becomes idle.
	 */
	if (nbd_send_chain_busy(q_data))
		q_data->next_chain.push_back(data);
	else
		io->co = __nbd_handle_io_async(q, data, io);

	return 0;
}

/*
 * Don't touch @data because the pointed ublk io request may have been
 * completed before this send cqe is handled. And ublk io request completion
 * is triggered by reply received from nbd server.
 */
static void nbd_send_req_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	unsigned ublk_op = user_data_to_op(cqe->user_data);
	int tag = user_data_to_tag(cqe->user_data);
	unsigned int nr_sects = user_data_to_tgt_data(cqe->user_data);
	unsigned total;

	/* nothing to do for send_zc notification */
	if (cqe->flags & IORING_CQE_F_NOTIF)
		return;

	nbd_chain_on_send_done(q_data);

	/*
	 * In case of failure, how to tell recv work to handle the
	 * request? So far just warn it, maybe nbd server will
	 * send one err reply.
	 */
	if (cqe->res < 0)
		nbd_err("%s: tag %d cqe fail %d %llx\n",
				__func__, tag, cqe->res, cqe->user_data);

	/*
	 * We have set MSG_WAITALL, so short send shouldn't be possible,
	 * but just warn in case of io_uring regression
	 */
	if (ublk_op == UBLK_IO_OP_WRITE)
		total = sizeof(nbd_request) + (nr_sects << 9);
	else
		total = sizeof(nbd_request);
	if (cqe->res < (int)total)
		nbd_err("%s: short send/receive tag %d op %d %llx, len %u written %u cqe flags %x\n",
				__func__, tag, ublk_op, cqe->user_data,
				total, cqe->res, cqe->flags);
}

static void nbd_tgt_io_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	int tag = user_data_to_tag(cqe->user_data);

	ublk_assert(tag == data->tag);
#if NBD_DEBUG_CQE == 1
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	nbd_err("%s: tag %d queue(ios %u %u) cqe(res %d flags %x user data %llx)\n",
			__func__, tag,
			q_data->in_flight_ios, q_data->chained_send_ios,
			cqe->res, cqe->flags, cqe->user_data);
#endif

	/* both reply and read io is done in recv io coroutine */
	if (is_recv_io(q, data)) {
		struct nbd_queue_data *q_data = nbd_get_queue_data(q);

		/*
		 * Delay recv data handling into nbd_handle_io_bg(), so
		 * any recv sqe won't cut in the send sqe chain.
		 *
		 * So far, recv is strictly serialized, so saving
		 * this single cqe works; in the future, if
		 * recv becomes batched, here has to be fixed
		 */
		q_data->recv_cqe = *cqe;
		q_data->need_handle_recv = 1;
		return;
	}

	nbd_send_req_done(q, data, cqe);
}

/*
 * Send/recv chain state machine
 * =============================
 *
 * Every NBD I/O is a request -> reply pair on a single TCP socket. To keep
 * requests strictly in-order on the wire we chain their sendmsg sqes with
 * IOSQE_IO_LINK, so the kernel only starts the next send once the previous
 * one has fully drained. The recv side uses one shared extra slot (tag ==
 * q->q_depth) that consumes replies plus any read data; it MUST NOT share
 * the link chain with sends or it would block sends behind unrelated
 * recvs and break NBD's in-order delivery guarantee.
 *
 *   new io arrives
 *         |
 *         v
 *   nbd_send_chain_busy()? --yes--> push into next_chain (staged)
 *         | no
 *         v
 *   __nbd_handle_io_async coroutine builds & queues a sendmsg sqe
 *   with IOSQE_IO_LINK; nbd_chain_append_send() records it as the chain
 *   tail and bumps chained_send_ios
 *         |
 *   nbd_handle_io_bg() runs last, just before io_uring_enter:
 *       - nbd_chain_mark_submitted() sets chain_submitted
 *       - then queues the recv sqe       (recv stays out of the chain)
 *         |
 *   send CQE -> nbd_send_req_done -> nbd_chain_on_send_done():
 *               chained_send_ios--; clears chain_submitted at 0
 *               (chain has fully drained)
 *         |
 *   nbd_handle_send_bg() calls nbd_chain_finalize() to strip the
 *   trailing IOSQE_IO_LINK, then flushes anything staged into
 *   next_chain while the previous chain was busy.
 *
 * The five fields in struct nbd_queue_data plus next_chain encode this
 * machine; all of them are mutated only through the nbd_chain_* helpers
 * defined above, and nbd_send_chain_busy() is the single predicate that
 * decides whether a new io runs inline or is staged.
 */
static void nbd_handle_send_bg(const struct ublksrv_queue *q,
		struct nbd_queue_data *q_data)
{
	if (!nbd_send_chain_busy(q_data)) {
		std::vector<const struct ublk_io_data *> &ios =
			q_data->next_chain;

		for (auto it = ios.cbegin(); it != ios.cend(); ++it) {
			auto data = *it;
			struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

			ublk_assert(data->tag < q->q_depth);
			io->co = __nbd_handle_io_async(q, data, io);
		}

		ios.clear();
	}
	nbd_chain_finalize(q_data);
}

static void nbd_handle_recv_bg(const struct ublksrv_queue *q,
		struct nbd_queue_data *q_data)
{
	if (q_data->in_flight_ios && !q_data->recv_started) {
		const struct ublk_io_data *data =
			ublksrv_queue_get_io_data(q, nbd_recv_tag(q));
		struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

		ublk_assert(data->tag == nbd_recv_tag(q));

		io->co = __nbd_handle_recv(q, data, io);
	}

	/* reply or read io data is comming */
	if (q_data->need_handle_recv) {
		const struct ublk_io_data *data =
			ublksrv_queue_get_io_data(q, nbd_recv_tag(q));
		struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

		ublk_assert(data->tag == nbd_recv_tag(q));

		io->tgt_io_cqe = &q_data->recv_cqe;
		io->co.resume();
		q_data->need_handle_recv = 0;
	}
}

/*
 * The initial send request batch should be in same send sqe batch, before
 * this batch isn't done, all new send requests are staggered into next_chain
 * which will be flushed after the current chain is completed.
 *
 * Also recv work is always started after send requests are queued, because
 * the recv sqe may cut the send sqe chain, and the ublk io cmd sqe may cut
 * the send sqe chain too.
 *
 * This is why nbd_handle_recv_bg() always follows nbd_handle_send_bg().
 */
static void nbd_handle_io_bg(const struct ublksrv_queue *q, int nr_queued_io)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);

	NBD_IO_DBG("%s: pending ios %d/%d chain_submitted %d next_chain %ld recv(%d) sqes %u\n",
				__func__, q_data->in_flight_ios,
				q_data->chained_send_ios,
				q_data->chain_submitted,
				q_data->next_chain.size(),
				q_data->recv_started,
				nr_queued_io);

	nbd_handle_send_bg(q, q_data);

	/*
	 * recv SQE can't cut in send SQE chain, so it has to be
	 * moved here after the send SQE chain is built
	 *
	 * Also queuing ublk io command may allocate sqe too.
	 */
	nbd_handle_recv_bg(q, q_data);

	/*
	 * io can be completed in recv work since we do sync recv, so
	 * io could be completed before the send seq's cqe is returned.
	 *
	 * When this happens, queue more requests.
	 */
	if (!q_data->in_flight_ios) {
		if (!q_data->next_chain.empty())
			nbd_handle_send_bg(q, q_data);
	}

	if (!q_data->recv_started && !nbd_send_chain_busy(q_data) &&
			!q_data->next_chain.empty())
		nbd_err("%s: hang risk: pending ios %d/%d\n",
				__func__, q_data->in_flight_ios,
				q_data->chained_send_ios);

	/*
	 * This chain is going to be submitted to kernel because
	 * ->handle_io_background() is the last thing before calling
	 * io_uring_enter()
	 */
	nbd_chain_mark_submitted(q_data);
}

static int nbd_init_queue(const struct ublksrv_queue *q,
		void **queue_data_ptr)
{
	/*
	 * nbd_queue_data holds a std::vector (next_chain). Allocate via
	 * new so the vector's ctor runs; calloc would skip it and rely on
	 * the empty-vector layout happening to be all-zero-compatible.
	 * Value-init ({}) zeroes the POD bit-fields like calloc did.
	 */
	struct nbd_queue_data *data = new (std::nothrow) nbd_queue_data{};
	struct nbd_tgt_data *ddata = (struct nbd_tgt_data*)q->dev->tgt.tgt_data;

	if (!data)
		return -ENOMEM;

	data->use_send_zc = ddata->unix_sock ? false : ddata->use_send_zc;
	data->use_unix_sock = ddata->unix_sock;

	*queue_data_ptr = (void *)data;
	return 0;
}

static void nbd_deinit_queue(const struct ublksrv_queue *q)
{
	struct nbd_queue_data *data = nbd_get_queue_data(q);

	delete data;
}

static void nbd_deinit_tgt(const struct ublksrv_dev *dev)
{
	const struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	int i;

	free(tgt->tgt_data);

	for (i = 0; i < info->nr_hw_queues; i++) {
		int fd = tgt->fds[i + 1];

		shutdown(fd, SHUT_RDWR);
		close(fd);
	}
}

static int nbd_setup_tgt(struct ublksrv_dev *dev, int type,
		uint16_t *flags)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(cdev);
	int i;
	struct nbd_tgt_data *data;

	if (!tgt->tgt_data)
		tgt->tgt_data = calloc(sizeof(struct nbd_tgt_data), 1);
	if (!tgt->tgt_data)
		return -ENOMEM;
	data = (struct nbd_tgt_data *)tgt->tgt_data;

	const char *port;
	uint16_t needed_flags = 0;
	uint32_t cflags = NBD_FLAG_C_FIXED_NEWSTYLE;

	char host_name[NBD_MAX_NAME] = {0};
	char exp_name[NBD_MAX_NAME] = {0};
	char unix_path[NBD_MAX_NAME] = {0};
	char port_buf[NBD_MAX_NAME] = {0};
	u64 size64 = 0;
	bool can_opt_go = true;

	/* todo: support tls */
	char *certfile = NULL;
	char *keyfile = NULL;
	char *cacertfile = NULL;
	char *tlshostname = NULL;
	bool tls = false;

	unsigned long send_zc = 0;


	if (info->flags & UBLK_F_USER_COPY)
		return -EINVAL;

	ublk_json_read_target_str_info(cdev, "host", host_name);
	ublk_json_read_target_str_info(cdev, "unix", unix_path);
	ublk_json_read_target_str_info(cdev, "export_name", exp_name);
	ublk_json_read_target_str_info(cdev, "port", port_buf);
	ublk_json_read_target_ulong_info(cdev, "send_zc", &send_zc);

	port = strlen(port_buf) > 0 ? port_buf : NBD_DEFAULT_PORT;

	NBD_HS_DBG("%s: host %s port %s unix %s exp_name %s send_zc: %lu\n",
			__func__, host_name, port, unix_path, exp_name, send_zc);
	for (i = 0; i < info->nr_hw_queues; i++) {
		int sock;
		unsigned int opts = 0;

		if (strlen(unix_path))
			sock = openunix(unix_path);
		else
			sock = opennet(host_name, port, false);

		if (sock >= 0)
			negotiate(&sock, &size64, flags, exp_name,
					needed_flags, cflags, opts, certfile,
					keyfile, cacertfile, tlshostname, tls,
					can_opt_go);
		else {
			ublk_err("%s: open socket failed %d\n", __func__, sock);
			return sock;
		}

		tgt->fds[i + 1] = sock;
		NBD_HS_DBG("%s:qid %d %s-%s size %luMB flags %x sock %d\n",
				__func__, i, host_name, port,
				size64 >> 20, *flags, sock);
	}

	tgt->dev_size = size64;

	/*
	 * one extra slot for receiving reply & read io, so
	 * the preferred queue depth should be 127 or 255,
	 * then half of SQ memory consumption can be saved
	 * especially we use IORING_SETUP_SQE128
	 */
	tgt->tgt_ring_depth = info->queue_depth + 1;
	tgt->nr_fds = info->nr_hw_queues;
	tgt->extra_ios = 1;	//one extra slot for receiving nbd reply
	data->unix_sock = strlen(unix_path) > 0;
	data->use_send_zc = !!send_zc;

	tgt->io_data_size = sizeof(struct ublk_io_tgt) +
		sizeof(struct nbd_io_data);

	ublksrv_dev_set_cq_depth(dev, 2 * tgt->tgt_ring_depth);

	if (info->flags & (UBLK_F_SUPPORT_ZERO_COPY | UBLK_F_AUTO_BUF_REG))
		return -EINVAL;
	return 0;
}

static void nbd_parse_flags(struct ublk_params *p, uint16_t flags, uint32_t bs)
{
	__u32 attrs = 0;

	NBD_HS_DBG("%s: negotiated flags %x\n", __func__, flags);

	if (flags & NBD_FLAG_READ_ONLY)
		attrs |= UBLK_ATTR_READ_ONLY;
	if (flags & NBD_FLAG_SEND_FLUSH) {
		if (flags & NBD_FLAG_SEND_FUA)
			attrs |= UBLK_ATTR_FUA;
		else
			attrs |= UBLK_ATTR_VOLATILE_CACHE;
	}

	p->basic.attrs |= attrs;

	if (flags & NBD_FLAG_SEND_TRIM) {
		p->discard.discard_granularity = bs;
		p->discard.max_discard_sectors = UINT_MAX >> 9;
		p->discard.max_discard_segments	= 1;
		p->types |= UBLK_PARAM_TYPE_DISCARD;
        }
}

static int nbd_recover_tgt(struct ublksrv_dev *dev, int type)
{
	uint16_t flags = 0;

	return nbd_setup_tgt(dev, type, &flags);
}

static int nbd_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	int send_zc = 0;
	int read_only = 0;
	static const struct option nbd_longopts[] = {
		{ "host",	required_argument, 0, 0},
		{ "unix",	required_argument, 0, 0},
		{ "export_name",	required_argument, 0, 0},
		{ "port",	required_argument, 0, 0},
		{ "send_zc",  0,  &send_zc, 1},
		{ "read_only",  0,  &read_only, 1},
		{ NULL }
	};
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	struct ublksrv_tgt_base_json tgt_json = { 0 };
	int opt;
	int option_index = 0;
	unsigned char bs_shift = 9;
	const char *host_name = NULL;
	const char *unix_path = NULL;
	const char *exp_name = NULL;
	const char *port = NULL;
	uint16_t flags = 0;
	int ret;
	unsigned int attrs = UBLK_ATTR_VOLATILE_CACHE;

	if (ublksrv_is_recovering(cdev))
		return nbd_recover_tgt(dev, 0);

	if (read_only)
		attrs |= UBLK_ATTR_READ_ONLY;

	strcpy(tgt_json.name, "nbd");

	while ((opt = getopt_long(argc, argv, "-:f:",
				  nbd_longopts, &option_index)) != -1) {
		if (opt < 0)
			break;
		if (opt > 0)
			continue;

		if (!strcmp(nbd_longopts[option_index].name, "host"))
		      host_name = optarg;
		if (!strcmp(nbd_longopts[option_index].name, "unix"))
		      unix_path = optarg;
		if (!strcmp(nbd_longopts[option_index].name, "export_name"))
			exp_name = optarg;
		if (!strcmp(nbd_longopts[option_index].name, "port"))
			port = optarg;
	}

#ifndef HAVE_LIBURING_SEND_ZC
	if (send_zc)
		return -EINVAL;
#endif

	ublk_json_write_dev_info(cdev);
	ublk_json_write_tgt_str(cdev, "host", host_name);
	ublk_json_write_tgt_str(cdev, "unix", unix_path);
	ublk_json_write_tgt_str(cdev, "export_name", exp_name);
	ublk_json_write_tgt_str(cdev, "port", port);
	ublk_json_write_tgt_long(cdev, "send_zc", send_zc);

	ret = nbd_setup_tgt(dev, type, &flags);
	if (ret)
		return ret;

	tgt_json.dev_size = tgt->dev_size;
	ublk_json_write_target_base(cdev, &tgt_json);

	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.attrs = attrs,
			.logical_bs_shift	= bs_shift,
			.physical_bs_shift	= 12,
			.io_opt_shift		= 12,
			.io_min_shift		= bs_shift,
			.max_sectors		= info->max_io_buf_bytes >> 9,
			.dev_sectors		= tgt->dev_size >> 9,
		},
	};

	nbd_parse_flags(&p, flags, 1U << bs_shift);
	ublk_json_write_params(cdev, &p);

	return 0;
}

static void nbd_cmd_usage()
{
	printf("\t--host=$HOST [--port=$PORT] | --unix=$UNIX_PATH\n");
}

static const struct ublksrv_tgt_type  nbd_tgt_type = {
	.handle_io_async = nbd_handle_io_async,
	.tgt_io_done = nbd_tgt_io_done,
	.handle_io_background = nbd_handle_io_bg,
	.usage_for_add = nbd_cmd_usage,
	.init_tgt = nbd_init_tgt,
	.deinit_tgt = nbd_deinit_tgt,
	.name	=  "nbd",
	.init_queue = nbd_init_queue,
	.deinit_queue = nbd_deinit_queue,
};

int main(int argc, char *argv[])
{
	return ublksrv_main(&nbd_tgt_type, argc, argv);
}
