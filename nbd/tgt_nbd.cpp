// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>
#include <vector>
#include "ublksrv_tgt.h"
#include "ublksrv_tgt_endian.h"
#include "cliserv.h"
#include "nbd.h"

//#define NBD_DEBUG_HANDSHAKE 1
//#define NBD_DEBUG_IO 1
//#define NBD_DEBUG_CQE 1

#ifdef NBD_DEBUG_IO
#define NBD_IO_DBG(...) syslog(LOG_ERR, __VA_ARGS__)
#else
#define NBD_IO_DBG(...)
#endif

#ifdef NBD_DEBUG_HANDSHAKE
#define NBD_HS_DBG(...) syslog(LOG_ERR, __VA_ARGS__)
#else
#define NBD_HS_DBG(...)
#endif

#define nbd_err(...) syslog(LOG_ERR, __VA_ARGS__)

#define NBD_MAX_NAME	512

#define NBD_OP_READ_REQ  0x80
#define NBD_OP_READ_REPLY  0x81

#define NBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, name, val) do { \
	int ret;						\
	if (val)						\
		ret = ublksrv_json_write_target_str_info(jbuf,	\
				jbuf_size, name, val);		\
	else							\
		ret = 0;					\
	if (ret < 0)						\
		jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);	\
	else							\
		break;						\
} while (1)

#define NBD_WRITE_TGT_LONG(dev, jbuf, jbuf_size, name, val) do { \
	int ret = ublksrv_json_write_target_ulong_info(jbuf, jbuf_size, \
			name, val);					\
	if (ret < 0)							\
		jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);	\
	else							\
		break;						\
} while (1)

struct nbd_tgt_data {
	bool unix_sock;
	bool use_send_zc;
};

struct nbd_queue_data {
	unsigned short recv_started;
	unsigned short in_flight_ios;
	unsigned short in_flight_write_ios;

	unsigned short use_send_zc:1;
	unsigned short use_unix_sock:1;
	unsigned short need_recv:1;
	unsigned short need_handle_recv:1;
	unsigned short send_sqe_chain_busy:1;

	unsigned int chained_send_ios;

	/*
	 * When the current chain is busy, staggering send ios
	 * into this queue(next_chain). After the current chain
	 * is consumed, submit all send ios in 'next_chain' as
	 * one whole batch.
	 */
	std::vector <const struct ublk_io_data *> next_chain;

	const struct io_uring_cqe *recv_cqe;
	struct io_uring_sqe *last_send_sqe;
	struct nbd_reply reply;
};

struct nbd_io_data {
	unsigned int cmd_cookie;
};

static int nbd_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data);

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

static void nbd_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery,
		uint16_t *flags)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	int jbuf_size;
	char *jbuf = ublksrv_tgt_return_json_buf(dev, &jbuf_size);
	int i;
	struct nbd_tgt_data *data = (struct nbd_tgt_data *)dev->tgt.tgt_data;

	const char *port = NBD_DEFAULT_PORT;
	uint16_t needed_flags = 0;
	uint32_t cflags = NBD_FLAG_C_FIXED_NEWSTYLE;

	char host_name[NBD_MAX_NAME] = {0};
	char exp_name[NBD_MAX_NAME] = {0};
	char unix_path[NBD_MAX_NAME] = {0};
	u64 size64 = 0;
	bool can_opt_go = true;

	/* todo: support tls */
	char *certfile = NULL;
	char *keyfile = NULL;
	char *cacertfile = NULL;
	char *tlshostname = NULL;
	bool tls = false;

	long send_zc = 0;

	ublk_assert(jbuf);
	ublk_assert(type == UBLKSRV_TGT_TYPE_NBD);
	ublk_assert(!recovery || info->state == UBLK_S_DEV_QUIESCED);

	ublksrv_json_read_target_str_info(jbuf, NBD_MAX_NAME, "host",
			host_name);
	ublksrv_json_read_target_str_info(jbuf, NBD_MAX_NAME, "unix",
			unix_path);
	ublksrv_json_read_target_str_info(jbuf, NBD_MAX_NAME, "export_name",
			exp_name);
	ublksrv_json_read_target_ulong_info(jbuf, "send_zc", &send_zc);

	NBD_HS_DBG("%s: host %s unix %s exp_name %s send_zc\n", __func__,
			host_name, unix_path, exp_name, send_zc);
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

		tgt->fds[i + 1] = sock;
		NBD_HS_DBG("%s:qid %d %s-%s size %luMB flags %x sock %d\n",
				__func__, i, host_name, port,
				size64 >> 20, *flags, sock);
	}

	tgt->dev_size = size64;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = info->nr_hw_queues;
	tgt->extra_ios = 1;	//one extra slot for receiving nbd reply
	data->unix_sock = strlen(unix_path) > 0 ? true : false;
	data->use_send_zc = !!send_zc;

	tgt->io_data_size = sizeof(struct ublk_io_tgt) +
		sizeof(struct nbd_io_data);
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

static int nbd_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	int send_zc = 0;
	int read_only = 0;
	static const struct option nbd_longopts[] = {
		{ "host",	required_argument, 0, 0},
		{ "unix",	required_argument, 0, 0},
		{ "export_name",	required_argument, 0, 0},
		{ "send_zc",  0,  &send_zc, 1},
		{ "read_only",  0,  &read_only, 1},
		{ NULL }
	};
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	int jbuf_size;
	char *jbuf = ublksrv_tgt_return_json_buf(dev, &jbuf_size);
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	int ret;
	int opt;
	int option_index = 0;
	unsigned char bs_shift = 9;
	const char *host_name = NULL;
	const char *unix_path = NULL;
	const char *exp_name = NULL;
	uint16_t flags = 0;

	strcpy(tgt_json.name, "nbd");

	if (type != UBLKSRV_TGT_TYPE_NBD)
		return -1;

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
	}

	ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, jbuf_size);
	NBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "host", host_name);
	NBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "unix", unix_path);
	NBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "export_name", exp_name);
	NBD_WRITE_TGT_LONG(dev, jbuf, jbuf_size, "send_zc", send_zc);

	tgt->tgt_data = calloc(sizeof(struct nbd_tgt_data), 1);

	nbd_setup_tgt(dev, type, false, &flags);

	tgt_json.dev_size = tgt->dev_size;
	ublksrv_json_write_target_base_info(jbuf, jbuf_size, &tgt_json);

	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.attrs = read_only ? UBLK_ATTR_READ_ONLY : 0U,
			.logical_bs_shift	= bs_shift,
			.physical_bs_shift	= 12,
			.io_opt_shift		= 12,
			.io_min_shift		= bs_shift,
			.max_sectors		= info->max_io_buf_bytes >> 9,
			.dev_sectors		= tgt->dev_size >> 9,
		},
	};

	nbd_parse_flags(&p, flags, 1U << bs_shift);

	do {
		ret = ublksrv_json_write_params(&p, jbuf, jbuf_size);
		if (ret < 0)
			jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	} while (ret < 0);

	return 0;
}

static int nbd_recovery_tgt(struct ublksrv_dev *dev, int type)
{
	uint16_t flags = 0;

	nbd_setup_tgt(dev, type, true, &flags);

	return 0;
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

static inline bool is_recv_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	return data->tag >= q->q_depth;
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

/* recv completion drives the whole IO flow */
static inline int nbd_start_recv(const struct ublksrv_queue *q,
		void *buf, int len, int tag, bool reply)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	struct io_uring_sqe *sqe = io_uring_get_sqe(q->ring_ptr);
	unsigned int op = reply ? NBD_OP_READ_REPLY : UBLK_IO_OP_READ;

	if (!sqe)
		return -ENOMEM;

	io_uring_prep_recv(sqe, q->q_id + 1, buf, len, MSG_WAITALL);
	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);

	/* bit63 marks us as tgt io */
	sqe->user_data = build_user_data(tag, op, 0, 1);

	ublk_assert(q_data->in_flight_ios);
	NBD_IO_DBG("%s: q_inflight %d queue recv %s"
				"(qid %d tag %u, target: %d, user_data %llx)\n",
			__func__, q_data->in_flight_ios, reply ? "reply" : "io",
			q->q_id, tag, 1, sqe->user_data);

	return 0;
}

static void nbd_recv_reply(const struct ublksrv_queue *q)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	const struct ublk_io_data *data;

	if (!q_data->in_flight_ios)
		return;

	if (q_data->recv_started)
		return;

	q_data->recv_started = 1;

	data = ublksrv_queue_get_io_data(q, q->q_depth);

	ublk_assert(data->tag == q->q_depth);
	nbd_handle_io_async(q, data);
}

static int nbd_queue_req(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct nbd_request *req, const struct msghdr *msg)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	const struct ublksrv_io_desc *iod = data->iod;
	struct io_uring_sqe *sqe = io_uring_get_sqe(q->ring_ptr);
	unsigned ublk_op = ublksrv_get_op(iod);
	unsigned msg_flags = MSG_NOSIGNAL;

	if (!sqe)
		return 0;

	/*
	 * Always set WAITALL, so io_uring will handle retry in case of
	 * short send, see below link:
	 *
	 * https://lore.kernel.org/io-uring/b8011ec8-8d43-9b9b-4dcc-53b6cb272354@samba.org/
	 *
	 * note: It was added for recv* in 5.18 and send* in 5.19.
	 */
	msg_flags |= MSG_WAITALL;

	if (ublk_op != UBLK_IO_OP_WRITE) {
		if (q_data->use_send_zc)
			io_uring_prep_send_zc(sqe, q->q_id + 1, req,
					sizeof(*req), msg_flags, 0);
		else
			io_uring_prep_send(sqe, q->q_id + 1, req,
					sizeof(*req), msg_flags);
	} else {
		q_data->in_flight_write_ios++;
		if (q_data->use_send_zc)
			io_uring_prep_sendmsg_zc(sqe, q->q_id + 1, msg,
				msg_flags);
		else
			io_uring_prep_sendmsg(sqe, q->q_id + 1, msg,
				msg_flags);
	}

	if (ublk_op == UBLK_IO_OP_READ)
		ublk_op = NBD_OP_READ_REQ;
	sqe->user_data = build_user_data(data->tag, ublk_op, 0, 1);
	io_uring_sqe_set_flags(sqe, /*IOSQE_CQE_SKIP_SUCCESS |*/
			IOSQE_FIXED_FILE | IOSQE_IO_LINK);
	q_data->last_send_sqe = sqe;

	NBD_IO_DBG("%s: queue io op %d(%llu %x %llx) ios(%u %u)"
			" (qid %d tag %u, cmd_op %u target: %d, user_data %llx)\n",
		__func__, ublk_op, data->iod->start_sector,
		data->iod->nr_sectors, sqe->addr,
		q_data->in_flight_ios, q_data->chained_send_ios,
		q->q_id, data->tag, ublk_op, 1, sqe->user_data);

	return 1;
}

static co_io_job __nbd_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, struct ublk_io_tgt *io)
{
	int ret = -EIO;
	struct nbd_request *req = NULL;
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	struct nbd_io_data *nbd_data = io_tgt_to_nbd_data(io);
	int type = req_to_nbd_cmd_type(data->iod);
	struct iovec iov[2] = {
		[0] = {
			.iov_base = (void *)req,
			.iov_len = sizeof(*req),
		},
		[1] = {
			.iov_base = (void *)data->iod->addr,
			.iov_len = data->iod->nr_sectors << 9,
		},
	};
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = 2,
	};

	posix_memalign((void **)&req, 32, sizeof(*req));
	if (!req)
		goto fail;
	req->magic = htonl(NBD_REQUEST_MAGIC);
	iov[0].iov_base = (void *)req;

	if (type == -1)
		goto fail;

	nbd_data->cmd_cookie += 1;

	__nbd_build_req(q, data, nbd_data, type, req);
	q_data->in_flight_ios += 1;
	q_data->chained_send_ios += 1;

again:
	ret = nbd_queue_req(q, data, req, &msg);
	if (!ret)
		ret = -ENOMEM;
	if (ret < 0)
		goto fail;

	co_await__suspend_always(data->tag);
	if (io->tgt_io_cqe->res == -EAGAIN)
		goto again;
	ret = io->tgt_io_cqe->res;
fail:
	if (ret < 0)
		nbd_err("%s: err %d\n", __func__, ret);
	ublksrv_complete_io(q, data->tag, ret);
	q_data->in_flight_ios -= 1;
	free(req);
	if (ublksrv_get_op(data->iod) == UBLK_IO_OP_WRITE)
		q_data->in_flight_write_ios--;
	NBD_IO_DBG("%s: tag %d res %d\n", __func__, data->tag, ret);

	co_return;
}

static int nbd_handle_recv_reply(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, struct ublk_io_tgt *io,
		const struct io_uring_cqe *cqe,
		const struct ublk_io_data **io_data)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	struct nbd_io_data *nbd_data;
	u64 handle;
	int tag, hwq;
	unsigned ublk_op;
	int ret = -EINVAL;

	if (cqe->res < 0) {
		nbd_err("%s %d: reply cqe %d\n", __func__,
				__LINE__, cqe->res);
		ret = cqe->res;
		goto fail;
	} else if (cqe->res == 0) {
		//return 0;
		nbd_err("%s %d: zero reply cqe %d %llx\n", __func__,
				__LINE__, cqe->res, cqe->user_data);
	}

	if (ntohl(q_data->reply.magic) != NBD_REPLY_MAGIC) {
		nbd_err("%s %d: reply bad magic %x res %d\n",
				__func__, __LINE__,
				ntohl(q_data->reply.magic), cqe->res);
		ret = -EPROTO;
		goto fail;
	}

	ublk_assert(cqe->res == sizeof(struct nbd_reply));

	memcpy(&handle, q_data->reply.handle, sizeof(handle));
	tag = nbd_handle_to_tag(handle);
	hwq = ublk_unique_tag_to_hwq(tag);
	tag = ublk_unique_tag_to_tag(tag);

	if (tag >= q->q_depth) {
		nbd_err("%s %d: tag is too big %d\n", __func__,
				__LINE__, tag);
		goto fail;
	}

	if (hwq != q->q_id) {
		nbd_err("%s %d: hwq is too big %d\n", __func__,
				__LINE__, hwq);
		goto fail;
	}

	data = ublksrv_queue_get_io_data(q, tag);
	io = __ublk_get_io_tgt_data(data);
	nbd_data = io_tgt_to_nbd_data(io);
	if (nbd_data->cmd_cookie != nbd_handle_to_cookie(handle)) {
		nbd_err("%s %d: cookie not match tag %d: %x %lx\n",
				__func__, __LINE__, data->tag,
				nbd_data->cmd_cookie, handle);
		goto fail;
	}

	ublk_op = ublksrv_get_op(data->iod);
	if (ublk_op == UBLK_IO_OP_READ) {
		*io_data = data;
		return 1;
	} else {
		int err = ntohl(q_data->reply.error);
		struct io_uring_cqe fake_cqe;

		NBD_IO_DBG("%s: got write reply, tag %d res %d\n",
					__func__, data->tag, err);

		if (err) {
			fake_cqe.res = -EIO;
		} else {
			if (ublk_op == UBLK_IO_OP_WRITE)
				fake_cqe.res = data->iod->nr_sectors << 9;
			else
				fake_cqe.res = 0;
		}

		io->tgt_io_cqe = &fake_cqe;
		io->co.resume();
		return 0;
	}
fail:
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
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);

	while (q_data->in_flight_ios > 0) {
		const struct ublk_io_data *io_data = NULL;
		int ret;
read_reply:
		ret = nbd_start_recv(q, &q_data->reply, sizeof(q_data->reply),
				q->q_depth, true);
		if (ret)
			break;

		co_await__suspend_always(data->tag);
		if (io->tgt_io_cqe->res == -EAGAIN)
			goto read_reply;

		ret = nbd_handle_recv_reply(q, data, io, io->tgt_io_cqe, &io_data);
		if (ret < 0)
			break;
		if (!ret)
			continue;
read_io:
		ublk_assert(io_data != NULL);
		ret = nbd_start_recv(q, (void *)io_data->iod->addr,
			io_data->iod->nr_sectors << 9, data->tag, false);
		if (ret)
			break;

		/* still wait on recv coroutine context */
		co_await__suspend_always(data->tag);

		ret = io->tgt_io_cqe->res;
		if (ret == -EAGAIN)
			goto read_io;

		struct ublk_io_tgt *io_io = __ublk_get_io_tgt_data(io_data);
		io_io->tgt_io_cqe = io->tgt_io_cqe;
		io_io->co.resume();
	}
	q_data->recv_started = 0;
	co_return;
}

static int nbd_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);

	if (data->tag < q->q_depth) {
		/*
		 * Put the io in the queue and submit them after
		 * the current chain becomes idle.
		 */
		if (q_data->send_sqe_chain_busy)
			q_data->next_chain.push_back(data);
		else
			io->co = __nbd_handle_io_async(q, data, io);
	} else {
		q_data->need_recv = 1;
	}

	return 0;
}

static void nbd_send_req_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);
	unsigned ublk_op = ublksrv_get_op(data->iod);
	unsigned total;

	/* nothing to do for send_zc notification */
	if (cqe->flags & IORING_CQE_F_NOTIF)
		return;

	ublk_assert(q_data->chained_send_ios);
	q_data->chained_send_ios--;

	/*
	 * In case of failure, how to tell recv work to handle the
	 * request? So far just warn it, maybe nbd server will
	 * send one err reply.
	 */
	if (cqe->res < 0)
		nbd_err("%s: tag %d cqe fail %d %llx\n",
				__func__, data->tag, cqe->res, cqe->user_data);

	/*
	 * We have set MSG_WAITALL, so short send shouldn't be possible,
	 * but just warn in case of io_uring regression
	 */
	if (ublk_op == UBLK_IO_OP_WRITE)
		total = sizeof(nbd_request) + (data->iod->nr_sectors << 9);
	else
		total = sizeof(nbd_request);
	if (cqe->res < total)
		nbd_err("%s: short send/receive tag %d op %d %llx, len %u written %u cqe flags %x\n",
				__func__, data->tag, ublk_op, cqe->user_data,
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
		q_data->recv_cqe = cqe;
		q_data->need_handle_recv = 1;
		return;
	}

	nbd_send_req_done(q, data, cqe);
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

static void nbd_usage_for_add(void)
{
	printf("           nbd: --host=$HOST [--port=$PORT] | --unix=$UNIX_PATH\n");
}

static int nbd_init_queue(const struct ublksrv_queue *q,
		void **queue_data_ptr)
{
	struct nbd_queue_data *data =
		(struct nbd_queue_data *)calloc(sizeof(*data), 1);
	struct nbd_tgt_data *ddata = (struct nbd_tgt_data*)q->dev->tgt.tgt_data;

	if (!data)
		return -ENOMEM;

	data->next_chain.clear();
	data->use_send_zc = ddata->unix_sock ? false : ddata->use_send_zc;
	data->use_unix_sock = ddata->unix_sock;
	data->recv_started = 0;
	//nbd_err("%s send zc %d\n", __func__, data->use_send_zc);

	*queue_data_ptr = (void *)data;
	return 0;
}

static void nbd_deinit_queue(const struct ublksrv_queue *q)
{
	struct nbd_queue_data *data = nbd_get_queue_data(q);

	free(data);
}

static void nbd_handle_send_bg(const struct ublksrv_queue *q,
		struct nbd_queue_data *q_data)
{
	if (q_data->chained_send_ios && !q_data->send_sqe_chain_busy)
		q_data->send_sqe_chain_busy = 1;

	if (q_data->send_sqe_chain_busy && !q_data->chained_send_ios)
		q_data->send_sqe_chain_busy = 0;

	if (q_data->last_send_sqe) {
		q_data->last_send_sqe->flags &= ~IOSQE_IO_LINK;
		q_data->last_send_sqe = NULL;
	}

	if (!q_data->send_sqe_chain_busy) {
		std::vector<const struct ublk_io_data *> &ios =
			q_data->next_chain;

		for (auto it = ios.cbegin(); it != ios.cend(); ++it) {
			auto data = *it;
			struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

			ublk_assert(data->tag < q->q_depth);
			io->co = __nbd_handle_io_async(q, data, io);
		}

		ios.clear();

		if (q_data->chained_send_ios && !q_data->send_sqe_chain_busy)
			q_data->send_sqe_chain_busy = 1;
	}
}

static void nbd_handle_recv_bg(const struct ublksrv_queue *q,
		struct nbd_queue_data *q_data)
{
	if (q_data->in_flight_ios) {
		const struct ublk_io_data *data =
			ublksrv_queue_get_io_data(q, q->q_depth);
		struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

		ublk_assert(data->tag == q->q_depth);

		nbd_recv_reply(q);

		if (q_data->need_recv) {
			io->co = __nbd_handle_recv(q, data, io);
			q_data->need_recv = 0;
		}

		if (q_data->need_handle_recv) {
			io->tgt_io_cqe = q_data->recv_cqe;
			io->co.resume();
			q_data->need_handle_recv = 0;
		}
	}
}

static void nbd_handle_io_bg(const struct ublksrv_queue *q, int nr_queued_io)
{
	struct nbd_queue_data *q_data = nbd_get_queue_data(q);

	NBD_IO_DBG("%s: pending ios %d/%d queued sqes %u\n",
				__func__, q_data->in_flight_ios,
				q_data->chained_send_ios, nr_queued_io);

	nbd_handle_send_bg(q, q_data);

	/*
	 * recv SQE can't cut in send SQE chain, so it has to be
	 * moved here after the send SQE chain is built
	 */
	nbd_handle_recv_bg(q, q_data);
}

struct ublksrv_tgt_type  nbd_tgt_type = {
	.handle_io_async = nbd_handle_io_async,
	.tgt_io_done = nbd_tgt_io_done,
	.handle_io_background = nbd_handle_io_bg,
	.usage_for_add	=  nbd_usage_for_add,
	.init_tgt = nbd_init_tgt,
	.deinit_tgt = nbd_deinit_tgt,
	.type	= UBLKSRV_TGT_TYPE_NBD,
	.name	=  "nbd",
	.recovery_tgt = nbd_recovery_tgt,
	.init_queue = nbd_init_queue,
	.deinit_queue = nbd_deinit_queue,
};

static void tgt_nbd_init() __attribute__((constructor));

static void tgt_nbd_init(void)
{
	ublksrv_register_tgt_type(&nbd_tgt_type);
}

