// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include "ublksrv_aio.h"
#include "ublksrv_tgt.h"

static struct ublksrv_aio_ctx *aio_ctx = NULL;
static pthread_t io_thread;

static bool loop_is_sync_io(struct ublksrv_queue *q,
		const struct ublk_io *io, int tag)
{
	const struct ublksrv_io_desc *iod = ublksrv_get_iod(q, tag);
	unsigned ublk_op = ublksrv_get_op(iod);

	switch (ublk_op) {
	case UBLK_IO_OP_FLUSH:
	case UBLK_IO_OP_WRITE_ZEROES:
	case UBLK_IO_OP_DISCARD:
		return true;
	}

	return false;
}

static int loop_sync_io_submitter(struct ublksrv_aio_ctx *ctx,
		struct ublksrv_aio *req)
{
	const struct ublksrv_io_desc *iod = &req->io;
	unsigned ublk_op = ublksrv_get_op(iod);
	void *buf = (void *)iod->addr;
	unsigned len = iod->nr_sectors << 9;
	unsigned long long offset = iod->start_sector << 9;
	int mode = FALLOC_FL_KEEP_SIZE;
	int ret;

	switch (ublk_op) {
	case UBLK_IO_OP_FLUSH:
		ret = fdatasync(req->fd);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
		mode |= FALLOC_FL_ZERO_RANGE;
	case UBLK_IO_OP_DISCARD:
		mode |= FALLOC_FL_PUNCH_HOLE;
		ret = fallocate(req->fd, mode, offset, len);
		break;
	case UBLK_IO_OP_READ:
	case UBLK_IO_OP_WRITE:
	default:
		ublksrv_log(LOG_ERR, "%s: wrong op %d, fd %d, id %x\n",
				__func__, ublk_op, req->fd, req->id);
		return -EINVAL;
	}
	ublksrv_log(LOG_INFO, "%s: op %d, fd %d, id %x, off %llx len %u res %d %s\n",
			__func__, ublk_op, req->fd, req->id, offset, len, ret,
			strerror(errno));
exit:
	req->res = ret;
	return 1;
}

#define EPOLL_NR_EVENTS 1
static void *loop_sync_io_handler_fn(void *data)
{
	struct ublksrv_aio_ctx *ctx = (struct ublksrv_aio_ctx *)data;

	unsigned dev_id = ctx->dev->ctrl_dev->dev_info.dev_id;
	struct epoll_event events[EPOLL_NR_EVENTS];
	int epoll_fd = epoll_create(EPOLL_NR_EVENTS);
	struct epoll_event read_event;
	int ret;

	if (epoll_fd < 0) {
	        fprintf(stderr, "ublk dev %d create epoll fd failed\n", dev_id);
	        return NULL;
	}

	ublksrv_log(LOG_INFO, "ublk dev %d aio context(sync io submitter) started tid %d\n",
			dev_id, gettid());

	read_event.events = EPOLLIN;
	read_event.data.fd = ctx->efd;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->efd, &read_event);

	while (!ublksrv_aio_ctx_dead(ctx)) {
		struct aio_list list;

		aio_list_init(&list);

		ublksrv_aio_submit_worker(ctx, loop_sync_io_submitter, &list);

		ublksrv_aio_complete_worker(ctx, &list);

		epoll_wait(epoll_fd, events, EPOLL_NR_EVENTS, -1);
	}

	return NULL;
}

static const char *loop_tgt_backfile(struct ublksrv_tgt_info *tgt)
{
	return (const char *)tgt->tgt_data;
}

static bool backing_supports_discard(char *name)
{
	int fd;
	char buf[512];
	int len;

	len = snprintf(buf, 512, "/sys/block/%s/queue/discard_max_hw_bytes",
			basename(name));
	buf[len] = 0;
	fd = open(buf, O_RDONLY);
	if (fd > 0) {
		char val[128];
		int ret = pread(fd, val, 128, 0);
		unsigned long long bytes = 0;

		close(fd);
		if (ret > 0)
			bytes = strtol(val, NULL, 10);

		if (bytes > 0)
			return true;
	}
	return false;
}

static int loop_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
		*argv[])
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info  *info = &dev->ctrl_dev->dev_info;
	static const struct option lo_longopts[] = {
		{ "file",		1,	NULL, 'f' },
		{ NULL }
	};
	unsigned long long bytes;
	struct stat st;
	int fd, opt;
	char *file = NULL;
	int jbuf_size, ret;
	char *jbuf;
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD,
		.basic = {
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift	= 12,
			.io_min_shift	= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
		},

		.discard = {
			.max_discard_sectors	= UINT_MAX >> 9,
			.max_discard_segments	= 1,
		},
	};
	bool can_discard = false;

	strcpy(tgt_json.name, "loop");

	if (type != UBLKSRV_TGT_TYPE_LOOP)
		return -1;

	while ((opt = getopt_long(argc, argv, "-:f:",
				  lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			file = strdup(optarg);
			break;
		}
	}

	if (!file)
		return -1;

	fd = open(file, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "__func__, backing file %s can't be opened\n",
				__func__, file);
		return -2;
	}

	if (fstat(fd, &st) < 0)
		return -2;

	if (S_ISBLK(st.st_mode)) {
		unsigned int bs, pbs;

		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
			return -1;
		if (ioctl(fd, BLKSSZGET, &bs) != 0)
			return -1;
		if (ioctl(fd, BLKPBSZGET, &pbs) != 0)
			return -1;
		p.basic.logical_bs_shift = ilog2(bs);
		p.basic.physical_bs_shift = ilog2(pbs);
		can_discard = backing_supports_discard(file);
	} else if (S_ISREG(st.st_mode)) {
		bytes = st.st_size;
		can_discard = true;
		p.basic.logical_bs_shift = ilog2(st.st_blksize);
		p.basic.physical_bs_shift = ilog2(st.st_blksize);
	} else {
		bytes = 0;
	}

	/*
	 * in case of buffered io, use common bs/pbs so that all FS
	 * image can be supported
	 */
	if (fcntl(fd, F_SETFL, O_DIRECT)) {
		p.basic.logical_bs_shift = 9;
		p.basic.physical_bs_shift = 12;
	}

	tgt->tgt_data = strdup(file);
	tgt_json.dev_size = tgt->dev_size = bytes;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 1;
	tgt->fds[1] = fd;
	p.basic.dev_sectors = bytes >> 9;

	if (st.st_blksize && can_discard)
		p.discard.discard_granularity = st.st_blksize;
	else
		p.types &= ~UBLK_PARAM_TYPE_DISCARD;

	jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	ublksrv_json_write_dev_info(dev->ctrl_dev, jbuf, jbuf_size);
	ublksrv_json_write_target_base_info(jbuf, jbuf_size, &tgt_json);
	do {
		ret = ublksrv_json_write_target_str_info(jbuf, jbuf_size,
				"backing_file", file);
		if (ret < 0)
			jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	} while (ret < 0);

	do {
		ret = ublksrv_json_write_params(&p, jbuf, jbuf_size);
		if (ret < 0)
			jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	} while (ret < 0);

	aio_ctx = ublksrv_aio_ctx_init(dev, 0);
	if (!aio_ctx) {
		fprintf(stderr, "dev %d call ublk_aio_ctx_init failed\n",
				dev->ctrl_dev->dev_info.dev_id);
		return -ENOMEM;
	}

	if (pthread_create(&io_thread, NULL, loop_sync_io_handler_fn,
				aio_ctx)) {
		ublksrv_aio_ctx_deinit(aio_ctx);
		aio_ctx = NULL;
	}

	return 0;
}

static void loop_usage_for_add(void)
{
	printf("           loop: -f backing_file\n");
}

static int loop_queue_tgt_io(struct ublksrv_queue *q, struct ublk_io *io,
		int tag)
{
	const struct ublksrv_io_desc *iod = ublksrv_get_iod(q, tag);
	unsigned io_op = ublksrv_convert_cmd_op(iod);
	struct io_uring_sqe *sqe = io_uring_get_sqe(&q->ring);

	if (!sqe)
		return 0;

	io_uring_prep_rw(io_op, sqe, 1, (void *)iod->addr, iod->nr_sectors << 9,
			iod->start_sector << 9);
	sqe->flags = IOSQE_FIXED_FILE;
	/* bit63 marks us as tgt io */
	sqe->user_data = build_user_data(tag, io_op, 0, 1);

	q->tgt_io_inflight += 1;

	ublksrv_log(LOG_INFO, "%s: tag %d ublk io %x %llx %u\n", __func__, tag,
			iod->op_flags, iod->start_sector, iod->nr_sectors << 9);
	ublksrv_log(LOG_INFO, "%s: queue io op %d(%llu %llx %llx)"
				" (qid %d tag %u, cmd_op %u target: %d, user_data %llx) iof %x\n",
			__func__, io_op, sqe->off, sqe->len, sqe->addr,
			q->q_id, tag, io_op, 1, sqe->user_data, io->flags);

	return 1;
}

static co_io_job __loop_handle_io_async(struct ublksrv_queue *q,
		struct ublk_io *io, int tag)
{
	struct io_uring_cqe *cqe;
	int ret;

	io->queued_tgt_io = 0;
 again:
	ret = loop_queue_tgt_io(q, io, tag);
	if (ret) {
		if (io->queued_tgt_io)
			ublksrv_log(LOG_INFO, "bad queued_tgt_io %d\n",
					io->queued_tgt_io);
		io->queued_tgt_io += 1;

		co_io_job_submit_and_wait();
		io->queued_tgt_io -= 1;

		cqe = io->tgt_io_cqe;
		if (cqe->res == -EAGAIN)
			goto again;

		ublksrv_complete_io(q, tag, cqe->res);
	} else {
		ublksrv_log(LOG_INFO, "no sqe %d\n", tag);
	}
}

static int loop_handle_io_async(struct ublksrv_queue *q, int tag)
{
	struct ublk_io_tgt *io = (struct ublk_io_tgt *)&q->ios[tag];
	bool sync = loop_is_sync_io(q, (struct ublk_io *)io, tag);
	struct ublksrv_aio *req;

	if (!sync) {
		io->co = __loop_handle_io_async(q, (struct ublk_io *)io, tag);
		return 0;
	}

	req = ublksrv_aio_alloc_req(aio_ctx, 0);
	req->io = *ublksrv_get_iod(q, tag);
	req->fd = q->dev->tgt.fds[1];
	req->id = ublksrv_aio_pid_tag(q->q_id, tag);
	ublksrv_aio_submit_req(aio_ctx, q, req);
	return 0;
}

static void loop_tgt_io_done(struct ublksrv_queue *q, struct io_uring_cqe *cqe)
{
	int tag = user_data_to_tag(cqe->user_data);
	struct ublk_io *io = &q->ios[tag];

	if (!io->queued_tgt_io)
		syslog(LOG_WARNING, "%s: wrong queued_tgt_io: res %d qid %u tag %u, cmd_op %u\n",
			__func__, cqe->res, q->q_id,
			user_data_to_tag(cqe->user_data),
			user_data_to_op(cqe->user_data));
	io->tgt_io_cqe = cqe;
	((struct ublk_io_tgt *)io)->co.resume();
}

static void loop_deinit_tgt(struct ublksrv_dev *dev)
{
	ublksrv_aio_ctx_shutdown(aio_ctx);
	pthread_join(io_thread, NULL);
	ublksrv_aio_ctx_deinit(aio_ctx);

	fsync(dev->tgt.fds[1]);
	close(dev->tgt.fds[1]);

	free(dev->tgt.tgt_data);
}

static void loop_handle_event(struct ublksrv_queue *q)
{
	ublksrv_aio_handle_event(aio_ctx, q);
}

struct ublksrv_tgt_type  loop_tgt_type = {
	.type	= UBLKSRV_TGT_TYPE_LOOP,
	.name	=  "loop",
	.init_tgt = loop_init_tgt,
	.handle_io_async = loop_handle_io_async,
	.tgt_io_done = loop_tgt_io_done,
	.handle_event = loop_handle_event,
	.usage_for_add	=  loop_usage_for_add,
	.deinit_tgt	=  loop_deinit_tgt,
};

static void tgt_loop_init() __attribute__((constructor));

static void tgt_loop_init(void)
{
	ublksrv_register_tgt_type(&loop_tgt_type);
}
