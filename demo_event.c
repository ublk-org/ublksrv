// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <sys/epoll.h>
#include <errno.h>
#include <error.h>

#include "ublksrv.h"
#include "ublksrv_aio.h"

#define UBLKSRV_TGT_TYPE_DEMO  0


static struct ublksrv_aio_ctx *aio_ctx = NULL;
static pthread_t io_thread;
struct demo_queue_info {
	struct ublksrv_dev *dev;
	struct ublksrv_queue *q;
	int qid;

	pthread_t thread;
};

static struct ublksrv_ctrl_dev *this_ctrl_dev;
static struct ublksrv_dev *this_dev;

static pthread_mutex_t jbuf_lock;
static char jbuf[4096];

static void sig_handler(int sig)
{
	struct ublksrv_queue *q = this_dev->__queues[0];
	fprintf(stderr, "got signal %d, stopping %d, %d %d\n", sig,
			q->stopping, q->cmd_inflight, q->tgt_io_inflight);
	ublksrv_ctrl_stop_dev(this_ctrl_dev);
}

static int io_submit_worker(struct ublksrv_aio_ctx *ctx,
		struct ublksrv_aio *req)
{
	req->res = req->io.nr_sectors << 9;

	return 1;
}

#define EPOLL_NR_EVENTS 1
static void *demo_event_real_io_handler_fn(void *data)
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

	fprintf(stdout, "ublk dev %d aio context started tid %d\n", dev_id,
			gettid());

	read_event.events = EPOLLIN;
	read_event.data.fd = ctx->efd;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->efd, &read_event);

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
	struct ublksrv_dev *dev = info->dev;
	unsigned dev_id = dev->ctrl_dev->dev_info.dev_id;
	unsigned short q_id = info->qid;
	struct ublksrv_queue *q;
	unsigned long long ev_data = 1;

	pthread_mutex_lock(&jbuf_lock);
	ublksrv_json_write_queue_info(dev->ctrl_dev, jbuf, sizeof jbuf,
			q_id, gettid());
	pthread_mutex_unlock(&jbuf_lock);

	q = ublksrv_queue_init(dev, q_id, info);
	if (!q) {
		fprintf(stderr, "ublk dev %d queue %d init queue failed\n",
				dev->ctrl_dev->dev_info.dev_id, q_id);
		return NULL;
	}
	info->q = q;

	fprintf(stdout, "tid %d: ublk dev %d queue %d started\n", q->tid,
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
	struct ublksrv_ctrl_dev_info *info = &cdev->dev_info;
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
	int dev_id = ctrl_dev->dev_info.dev_id;
	int ret, i;
	char buf[32];
	struct ublksrv_dev *dev;
	struct demo_queue_info *info_array;
	void *thread_ret;
	struct ublksrv_ctrl_dev_info *dinfo = &ctrl_dev->dev_info;

	info_array = (struct demo_queue_info *)
		calloc(sizeof(struct demo_queue_info), dinfo->nr_hw_queues);

	dev = ublksrv_dev_init(ctrl_dev);
	if (!dev)
		return -ENOMEM;
	this_dev = dev;


	aio_ctx = ublksrv_aio_ctx_init(dev, 0);
	if (!aio_ctx) {
		fprintf(stderr, "dev %d call ublk_aio_ctx_init failed\n", dev_id);
		return -ENOMEM;
	}

	pthread_create(&io_thread, NULL, demo_event_real_io_handler_fn,
			aio_ctx);
	for (i = 0; i < dinfo->nr_hw_queues; i++) {
		int j;
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
		int j;
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
	int cnt = 0, daemon_pid;
	int ret;

	if (ublksrv_ctrl_get_affinity(ctrl_dev) < 0)
		return -1;

	return demo_event_io_handler(ctrl_dev);
}

static int demo_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	const struct ublksrv_ctrl_dev_info  *info = &dev->ctrl_dev->dev_info;
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	strcpy(tgt_json.name, "null_event");

	if (type != UBLKSRV_TGT_TYPE_DEMO)
		return -1;

	tgt_json.dev_size = tgt->dev_size = 250UL * 1024 * 1024 * 1024;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;

	ublksrv_json_write_dev_info(dev->ctrl_dev, jbuf, sizeof jbuf);
	ublksrv_json_write_target_base_info(jbuf, sizeof jbuf, &tgt_json);

	return 0;
}

static int demo_handle_io_async(struct ublksrv_queue *q, int tag)
{
	const struct ublksrv_io_desc *iod = ublksrv_get_iod(q, tag);
	struct ublksrv_aio *req = ublksrv_aio_alloc_req(aio_ctx, 0);

	req->io = *iod;
	req->fd = -1;
	req->id = ublksrv_aio_pid_tag(q->q_id, tag);
	ublksrv_aio_submit_req(aio_ctx, q, req);

	return 0;
}

static void demo_handle_event(struct ublksrv_queue *q)
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
	char *type = NULL;
	int ret, opt;

	while ((opt = getopt_long(argc, argv, ":g",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'g':
			data.flags |= UBLK_F_NEED_GET_DATA;
			break;
		}
	}

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
