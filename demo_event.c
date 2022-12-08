// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sched.h>
#include <pthread.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <error.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "ublksrv.h"
#include "ublksrv_utils.h"
#include "ublksrv_aio.h"

#define UBLKSRV_TGT_TYPE_DEMO  0

static bool use_aio = 0;
static int backing_fd = -1;

static struct ublksrv_aio_ctx *aio_ctx = NULL;
static pthread_t io_thread;
struct demo_queue_info {
	const struct ublksrv_dev *dev;
	const struct ublksrv_queue *q;
	int qid;

	pthread_t thread;
};

static struct ublksrv_ctrl_dev *this_ctrl_dev;
static const struct ublksrv_dev *this_dev;

static pthread_mutex_t jbuf_lock;
static char jbuf[4096];

static void sig_handler(int sig)
{
	const struct ublksrv_queue *q = ublksrv_get_queue(this_dev, 0);
	unsigned state = ublksrv_queue_state(q);

	fprintf(stderr, "got signal %d, stopping %d\n", sig,
			state & UBLKSRV_QUEUE_STOPPING);
	ublksrv_ctrl_stop_dev(this_ctrl_dev);
}

static void queue_fallocate_async(struct io_uring_sqe *sqe,
		struct ublksrv_aio *req)
{
	__u16 ublk_op = ublksrv_get_op(&req->io);
	__u32 flags = ublksrv_get_flags(&req->io);
	__u32 mode = FALLOC_FL_KEEP_SIZE;

	/* follow logic of linux kernel loop */
	if (ublk_op == UBLK_IO_OP_DISCARD) {
		mode |= FALLOC_FL_PUNCH_HOLE;
	} else if (ublk_op == UBLK_IO_OP_WRITE_ZEROES) {
		if (flags & UBLK_IO_F_NOUNMAP)
			mode |= FALLOC_FL_ZERO_RANGE;
		else
			mode |= FALLOC_FL_PUNCH_HOLE;
	} else {
		mode |= FALLOC_FL_ZERO_RANGE;
	}
	io_uring_prep_fallocate(sqe, req->fd, mode, req->io.start_sector << 9,
			req->io.nr_sectors << 9);
}

int async_io_submitter(struct ublksrv_aio_ctx *ctx,
		struct ublksrv_aio *req)
{
	struct io_uring *ring = (struct io_uring*)
		ublksrv_aio_get_ctx_data(ctx);
	const struct ublksrv_io_desc *iod = &req->io;
	unsigned op = ublksrv_get_op(iod);
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "%s: uring run out of sqe\n", __func__);
		return -ENOMEM;
	}

	if (op == -1 || req->fd < 0) {
		fprintf(stderr, "%s: wrong op %d, fd %d, id %x\n", __func__, op,
				req->fd, req->id);
		return -EINVAL;
	}

	io_uring_sqe_set_data(sqe, req);
	switch (op) {
	case UBLK_IO_OP_DISCARD:
	case UBLK_IO_OP_WRITE_ZEROES:
		queue_fallocate_async(sqe, req);
		break;
	case UBLK_IO_OP_FLUSH:
		io_uring_prep_fsync(sqe, req->fd, IORING_FSYNC_DATASYNC);
		break;
	case UBLK_IO_OP_READ:
		io_uring_prep_read(sqe, req->fd, (void *)iod->addr,
				iod->nr_sectors << 9, iod->start_sector << 9);
		break;
	case UBLK_IO_OP_WRITE:
		io_uring_prep_write(sqe, req->fd, (void *)iod->addr,
				iod->nr_sectors << 9, iod->start_sector << 9);
		break;
	default:
		fprintf(stderr, "%s: wrong op %d, fd %d, id %x\n", __func__,
				op, req->fd, req->id);
		return -EINVAL;
	}

	return 0;
}

int sync_io_submitter(struct ublksrv_aio_ctx *ctx,
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
	case UBLK_IO_OP_READ:
		ret = pread(req->fd, buf, len, offset);
		break;
	case UBLK_IO_OP_WRITE:
		ret = pwrite(req->fd, buf, len, offset);
		break;
	case UBLK_IO_OP_FLUSH:
		ret = fdatasync(req->fd);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
		mode |= FALLOC_FL_ZERO_RANGE;
	case UBLK_IO_OP_DISCARD:
		ret = fallocate(req->fd, mode, offset, len);
		break;
	default:
		fprintf(stderr, "%s: wrong op %d, fd %d, id %x\n", __func__,
				ublk_op, req->fd, req->id);
		return -EINVAL;
	}

	req->res = ret;
	return 1;
}

static int io_submit_worker(struct ublksrv_aio_ctx *ctx,
		struct ublksrv_aio *req)
{
	/* simulate null target */
	if (req->fd < 0)
		req->res = req->io.nr_sectors << 9;
	else
		return sync_io_submitter(ctx, req);

	return 1;
}

static int queue_event(struct ublksrv_aio_ctx *ctx)
{
	struct io_uring *ring = (struct io_uring *)
		ublksrv_aio_get_ctx_data(ctx);
	struct io_uring_sqe *sqe;
	int ctx_efd = ublksrv_aio_get_efd(ctx);

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "%s: uring run out of sqe\n", __func__);
		return -1;
	}

	io_uring_prep_poll_add(sqe, ctx_efd, POLLIN);
	io_uring_sqe_set_data64(sqe, 0);

	return 0;
}

static int reap_uring(struct ublksrv_aio_ctx *ctx, struct aio_list *list, int
		*got_efd)
{
	struct io_uring *r = (struct io_uring *)ublksrv_aio_get_ctx_data(ctx);
	struct io_uring_cqe *cqe;
	unsigned head;
	int count = 0;

	io_uring_for_each_cqe(r, head, cqe) {
		if (cqe->user_data) {
			struct ublksrv_aio *req = (struct ublksrv_aio *)
				cqe->user_data;

			if (cqe->res == -EAGAIN)
				async_io_submitter(ctx, req);
			else {
				req->res = cqe->res;
				aio_list_add(list, req);
			}
		} else {
			if (cqe->res < 0)
				fprintf(stderr, "eventfd result %d\n",
						cqe->res);
			*got_efd = 1;
		}
	        count += 1;
	}
	io_uring_cq_advance(r, count);

	return count;
}

static void *demo_event_uring_io_handler_fn(void *data)
{
	struct ublksrv_aio_ctx *ctx = (struct ublksrv_aio_ctx *)data;
	const struct ublksrv_dev *dev = ublksrv_aio_get_dev(ctx);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	unsigned dev_id = info->dev_id;
	struct io_uring ring;
	unsigned qd;
	int ret;
	int ctx_efd = ublksrv_aio_get_efd(ctx);

	qd = info->queue_depth * info->nr_hw_queues * 2;

	io_uring_queue_init(qd, &ring, 0);
	ret = io_uring_register_eventfd(&ring, ctx_efd);
	if (ret) {
		fprintf(stdout, "ublk dev %d fails to register eventfd\n",
			dev_id);
		return NULL;
	}

	ublksrv_aio_set_ctx_data(ctx, (void *)&ring);

	fprintf(stdout, "ublk dev %d aio(io_uring submitter) context started tid %d\n",
			dev_id, ublksrv_gettid());

	queue_event(ctx);
	io_uring_submit_and_wait(&ring, 0);

	while (!ublksrv_aio_ctx_dead(ctx)) {
		struct aio_list compl;
		int got_efd = 0;

		aio_list_init(&compl);
		ublksrv_aio_submit_worker(ctx, async_io_submitter, &compl);

		reap_uring(ctx, &compl, &got_efd);
		ublksrv_aio_complete_worker(ctx, &compl);

		if (got_efd)
			queue_event(ctx);
		io_uring_submit_and_wait(&ring, 1);
	}

	return NULL;
}

#define EPOLL_NR_EVENTS 1
static void *demo_event_real_io_handler_fn(void *data)
{
	struct ublksrv_aio_ctx *ctx = (struct ublksrv_aio_ctx *)data;
	const struct ublksrv_dev *dev = ublksrv_aio_get_dev(ctx);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));

	unsigned dev_id = info->dev_id;
	struct epoll_event events[EPOLL_NR_EVENTS];
	int epoll_fd = epoll_create(EPOLL_NR_EVENTS);
	struct epoll_event read_event;
	int ctx_efd = ublksrv_aio_get_efd(ctx);

	if (epoll_fd < 0) {
	        fprintf(stderr, "ublk dev %d create epoll fd failed\n", dev_id);
	        return NULL;
	}

	fprintf(stdout, "ublk dev %d aio context(sync io submitter) started tid %d\n",
			dev_id, ublksrv_gettid());

	read_event.events = EPOLLIN;
	read_event.data.fd = ctx_efd;
	(void)epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx_efd, &read_event);

	while (!ublksrv_aio_ctx_dead(ctx)) {
		struct aio_list compl;

		aio_list_init(&compl);

		ublksrv_aio_submit_worker(ctx, io_submit_worker, &compl);

		ublksrv_aio_complete_worker(ctx, &compl);

		epoll_wait(epoll_fd, events, EPOLL_NR_EVENTS, -1);
	}

	return NULL;
}

/*
 * io handler for each ublkdev's queue
 *
 * Just for showing how to build ublksrv target's io handling, so callers
 * can apply these APIs in their own thread context for making one ublk
 * block device.
 */
static void *demo_event_io_handler_fn(void *data)
{
	struct demo_queue_info *info = (struct demo_queue_info *)data;
	const struct ublksrv_dev *dev = info->dev;
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	unsigned dev_id = dinfo->dev_id;
	unsigned short q_id = info->qid;
	const struct ublksrv_queue *q;

	pthread_mutex_lock(&jbuf_lock);
	ublksrv_json_write_queue_info(ublksrv_get_ctrl_dev(dev), jbuf, sizeof jbuf,
			q_id, ublksrv_gettid());
	pthread_mutex_unlock(&jbuf_lock);

	q = ublksrv_queue_init(dev, q_id, info);
	if (!q) {
		fprintf(stderr, "ublk dev %d queue %d init queue failed\n",
				dinfo->dev_id, q_id);
		return NULL;
	}
	info->q = q;

	fprintf(stdout, "tid %d: ublk dev %d queue %d started\n", ublksrv_gettid(),
			dev_id, q->q_id);
	do {
		if (ublksrv_process_io(q) < 0)
			break;
	} while (1);

	fprintf(stdout, "ublk dev %d queue %d exited\n", dev_id, q->q_id);
	ublksrv_queue_deinit(q);
	return NULL;
}

static void demo_event_set_parameters(struct ublksrv_ctrl_dev *cdev,
		const struct ublksrv_dev *dev)
 {
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift		= 12,
			.io_min_shift		= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
			.dev_sectors		= dev->tgt.dev_size >> 9,
		},
	};
	int ret;

	pthread_mutex_lock(&jbuf_lock);
	ublksrv_json_write_params(&p, jbuf, sizeof jbuf);
	pthread_mutex_unlock(&jbuf_lock);

	ret = ublksrv_ctrl_set_params(cdev, &p);
	if (ret)
		fprintf(stderr, "dev %d set basic parameter failed %d\n",
				info->dev_id, ret);
}


static int demo_event_io_handler(struct ublksrv_ctrl_dev *ctrl_dev)
{
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ctrl_dev);
	int dev_id = dinfo->dev_id;
	int ret, i;
	const struct ublksrv_dev *dev;
	struct demo_queue_info *info_array;
	void *thread_ret;

	info_array = (struct demo_queue_info *)
		calloc(sizeof(struct demo_queue_info), dinfo->nr_hw_queues);
	if (!info_array)
		return -ENOMEM;

	dev = ublksrv_dev_init(ctrl_dev);
	if (!dev) {
		free(info_array);
		return -ENOMEM;
	}
	this_dev = dev;


	aio_ctx = ublksrv_aio_ctx_init(dev, 0);
	if (!aio_ctx) {
		fprintf(stderr, "dev %d call ublk_aio_ctx_init failed\n", dev_id);
		ret = -ENOMEM;
		goto fail;
	}

	if (!use_aio)
		pthread_create(&io_thread, NULL, demo_event_real_io_handler_fn,
				aio_ctx);
	else
		pthread_create(&io_thread, NULL, demo_event_uring_io_handler_fn,
				aio_ctx);
	for (i = 0; i < dinfo->nr_hw_queues; i++) {
		info_array[i].dev = dev;
		info_array[i].qid = i;

		pthread_create(&info_array[i].thread, NULL,
				demo_event_io_handler_fn,
				&info_array[i]);
	}

	demo_event_set_parameters(ctrl_dev, dev);

	/* everything is fine now, start us */
	ret = ublksrv_ctrl_start_dev(ctrl_dev, getpid());
	if (ret < 0)
		goto fail;

	ublksrv_ctrl_get_info(ctrl_dev);
	ublksrv_ctrl_dump(ctrl_dev, jbuf);

	/* wait until we are terminated */
	for (i = 0; i < dinfo->nr_hw_queues; i++) {
		pthread_join(info_array[i].thread, &thread_ret);
	}
	ublksrv_aio_ctx_shutdown(aio_ctx);
	pthread_join(io_thread, &thread_ret);
	ublksrv_aio_ctx_deinit(aio_ctx);

fail:
	ublksrv_dev_deinit(dev);

	free(info_array);

	return ret;
}

static int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev)
{
	if (ublksrv_ctrl_get_affinity(ctrl_dev) < 0)
		return -1;

	return demo_event_io_handler(ctrl_dev);
}

static int demo_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	struct stat st;

	strcpy(tgt_json.name, "demo_event");

	if (type != UBLKSRV_TGT_TYPE_DEMO)
		return -1;

	if (backing_fd > 0) {
		unsigned long long bytes;

		fstat(backing_fd, &st);
		if (S_ISBLK(st.st_mode)) {
			if (ioctl(backing_fd, BLKGETSIZE64, &bytes) != 0)
				return -1;
		} else if (S_ISREG(st.st_mode)) {
			bytes = st.st_size;
		} else {
			bytes = 0;
		}

		tgt->dev_size = bytes;
	} else {
		tgt->dev_size = 250UL * 1024 * 1024 * 1024;
	}

	tgt_json.dev_size = tgt->dev_size;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;

	ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, sizeof jbuf);
	ublksrv_json_write_target_base_info(jbuf, sizeof jbuf, &tgt_json);

	return 0;
}

static int demo_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublksrv_aio *req = ublksrv_aio_alloc_req(aio_ctx, 0);

	req->io = *data->iod;
	req->fd = backing_fd;
	req->id = ublksrv_aio_pid_tag(q->q_id, data->tag);
	ublksrv_aio_submit_req(aio_ctx, q, req);

	return 0;
}

static void demo_handle_event(const struct ublksrv_queue *q)
{
	ublksrv_aio_handle_event(aio_ctx, q);
}

static const struct ublksrv_tgt_type demo_event_tgt_type = {
	.type	= UBLKSRV_TGT_TYPE_DEMO,
	.name	=  "demo_event",
	.init_tgt = demo_init_tgt,
	.handle_io_async = demo_handle_io_async,
	.handle_event = demo_handle_event,
};

int main(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "need_get_data",	1,	NULL, 'g' },
		{ "backing_file",	1,	NULL, 'f' },
		{ "use_aio",		1,	NULL, 'a' },
		{ NULL }
	};
	struct ublksrv_dev_data data = {
		.dev_id = -1,
		.max_io_buf_bytes = DEF_BUF_SIZE,
		.nr_hw_queues = DEF_NR_HW_QUEUES,
		.queue_depth = DEF_QD,
		.tgt_type = "demo_event",
		.tgt_ops = &demo_event_tgt_type,
		.flags = 0,
	};
	struct ublksrv_ctrl_dev *dev;
	int ret, opt;

	while ((opt = getopt_long(argc, argv, "f:ga",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'g':
			data.flags |= UBLK_F_NEED_GET_DATA;
			break;
		case 'f':
			backing_fd = open(optarg, O_RDWR | O_DIRECT);
			if (backing_fd < 0)
				backing_fd = -1;
			break;
		case 'a':
			use_aio = true;
			break;
		}
	}

	if (backing_fd < 0)
		use_aio = false;

	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		error(EXIT_FAILURE, errno, "signal");
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		error(EXIT_FAILURE, errno, "signal");

	pthread_mutex_init(&jbuf_lock, NULL);

	data.ublksrv_flags = UBLKSRV_F_NEED_EVENTFD;
	dev = ublksrv_ctrl_init(&data);
	if (!dev)
		error(EXIT_FAILURE, ENODEV, "ublksrv_ctrl_init");
	/* ugly, but signal handler needs this_dev */
	this_ctrl_dev = dev;

	ret = ublksrv_ctrl_add_dev(dev);
	if (ret < 0) {
		error(0, -ret, "can't add dev %d", data.dev_id);
		goto fail;
	}

	ret = ublksrv_start_daemon(dev);
	if (ret < 0) {
		error(0, -ret, "can't start daemon");
		goto fail_del_dev;
	}

	ublksrv_ctrl_del_dev(dev);
	ublksrv_ctrl_deinit(dev);
	exit(EXIT_SUCCESS);

 fail_del_dev:
	ublksrv_ctrl_del_dev(dev);
 fail:
	ublksrv_ctrl_deinit(dev);

	exit(EXIT_FAILURE);
}
