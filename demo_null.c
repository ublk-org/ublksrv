// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <errno.h>
#include <error.h>

#include "ublksrv.h"

#define UBLKSRV_TGT_TYPE_DEMO  0

struct demo_queue_info {
	struct ublksrv_dev *dev;
	int qid;
	pthread_t thread;
};

static struct ublksrv_ctrl_dev *this_dev;

static pthread_mutex_t jbuf_lock;
static char jbuf[4096];

static void sig_handler(int sig)
{
	fprintf(stderr, "got signal %d\n", sig);
	ublksrv_ctrl_stop_dev(this_dev);
}

/*
 * io handler for each ublkdev's queue
 *
 * Just for showing how to build ublksrv target's io handling, so callers
 * can apply these APIs in their own thread context for making one ublk
 * block device.
 */
static void *demo_null_io_handler_fn(void *data)
{
	struct demo_queue_info *info = (struct demo_queue_info *)data;
	struct ublksrv_dev *dev = info->dev;
	unsigned dev_id = dev->ctrl_dev->dev_info.dev_id;
	unsigned short q_id = info->qid;
	struct ublksrv_queue *q;

	sched_setscheduler(getpid(), SCHED_RR, NULL);

	pthread_mutex_lock(&jbuf_lock);
	ublksrv_json_write_queue_info(dev->ctrl_dev, jbuf, sizeof jbuf,
			q_id, gettid());
	pthread_mutex_unlock(&jbuf_lock);
	q = ublksrv_queue_init(dev, q_id, NULL);
	if (!q) {
		fprintf(stderr, "ublk dev %d queue %d init queue failed\n",
				dev->ctrl_dev->dev_info.dev_id, q_id);
		return NULL;
	}

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

static void demo_null_set_parameters(struct ublksrv_ctrl_dev *cdev,
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

static int demo_null_io_handler(struct ublksrv_ctrl_dev *ctrl_dev)
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

	for (i = 0; i < dinfo->nr_hw_queues; i++) {
		info_array[i].dev = dev;
		info_array[i].qid = i;
		pthread_create(&info_array[i].thread, NULL,
				demo_null_io_handler_fn,
				&info_array[i]);
	}

	demo_null_set_parameters(ctrl_dev, dev);

	/* everything is fine now, start us */
	ret = ublksrv_ctrl_start_dev(ctrl_dev, getpid());
	if (ret < 0)
		goto fail;

	ublksrv_ctrl_get_info(ctrl_dev);
	ublksrv_ctrl_dump(ctrl_dev, jbuf);

	/* wait until we are terminated */
	for (i = 0; i < dinfo->nr_hw_queues; i++)
		pthread_join(info_array[i].thread, &thread_ret);
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

	ret = demo_null_io_handler(ctrl_dev);

	return ret;
}



static int demo_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	const struct ublksrv_ctrl_dev_info  *info = &dev->ctrl_dev->dev_info;
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
        strcpy(tgt_json.name, "null");


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

	ublksrv_complete_io(q, tag, iod->nr_sectors << 9);

	return 0;
}

void *null_alloc_io_buf(struct ublksrv_queue *q, int tag, int size)
{
	return malloc(size);
}

void null_free_io_buf(struct ublksrv_queue *q, void *buf, int tag)
{
	free(buf);
}

static struct ublksrv_tgt_type demo_tgt_type = {
	.type	= UBLKSRV_TGT_TYPE_DEMO,
	.name	=  "demo_null",
	.init_tgt = demo_init_tgt,
	.handle_io_async = demo_handle_io_async,
	//.alloc_io_buf = null_alloc_io_buf,
	//.free_io_buf = null_free_io_buf,
};

int main(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {
		.dev_id = -1,
		.max_io_buf_bytes = DEF_BUF_SIZE,
		.nr_hw_queues = DEF_NR_HW_QUEUES,
		.queue_depth = DEF_QD,
		.tgt_type = "demo_null",
		.tgt_ops = &demo_tgt_type,
		.flags = 0,
	};
	struct ublksrv_ctrl_dev *dev;
	char *type = NULL;
	int ret;
	static const struct option longopts[] = {
		{ "buf",		1,	NULL, 'b' },
		{ "need_get_data",	1,	NULL, 'g' },
		{ NULL }
	};
	int opt;
	bool use_buf = false;

	while ((opt = getopt_long(argc, argv, ":bg",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'b':
			use_buf = true;
			break;
		case 'g':
			data.flags |= UBLK_F_NEED_GET_DATA;
			break;
		}
	}

	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		error(EXIT_FAILURE, errno, "signal");
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		error(EXIT_FAILURE, errno, "signal");

	if (use_buf) {
		demo_tgt_type.alloc_io_buf = null_alloc_io_buf;
		demo_tgt_type.free_io_buf = null_free_io_buf;
	}

	pthread_mutex_init(&jbuf_lock, NULL);
	dev = ublksrv_ctrl_init(&data);
	if (!dev)
		error(EXIT_FAILURE, ENODEV, "ublksrv_ctrl_init");
	/* ugly, but signal handler needs this_dev */
	this_dev = dev;

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
