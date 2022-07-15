#include "ublksrv.h"

#define UBLKSRV_TGT_TYPE_DEMO  0

struct demo_queue_info {
	struct ublksrv_dev *dev;
	int qid;
	pthread_t thread;
};

static struct ublksrv_ctrl_dev *this_dev;
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

static unsigned long long demo_get_dev_blocks(const struct ublksrv_dev *dev)
{
	return dev->tgt.dev_size / dev->ctrl_dev->dev_info.block_size;
}

static void demo_null_io_handler(struct ublksrv_ctrl_dev *ctrl_dev)
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
		return;

	for (i = 0; i < dinfo->nr_hw_queues; i++) {
		info_array[i].dev = dev;
		info_array[i].qid = i;
		pthread_create(&info_array[i].thread, NULL,
				demo_null_io_handler_fn,
				&info_array[i]);
	}

	/* everything is fine now, start us */
	ublksrv_ctrl_start_dev(ctrl_dev, getpid(), demo_get_dev_blocks(dev));

	ublksrv_ctrl_get_info(ctrl_dev);
	ublksrv_ctrl_dump(ctrl_dev);

	/* wait until we are terminated */
	for (i = 0; i < dinfo->nr_hw_queues; i++)
		pthread_join(info_array[i].thread, &thread_ret);

	ublksrv_dev_deinit(dev);

	free(info_array);
}

static int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev)
{
	int cnt = 0, daemon_pid;
	int ret;

	if (ublksrv_ctrl_get_affinity(ctrl_dev) < 0)
		return -1;

	demo_null_io_handler(ctrl_dev);

	return 0;
}

static int demo_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	const struct ublksrv_ctrl_dev_info  *info = &dev->ctrl_dev->dev_info;
	struct ublksrv_tgt_info *tgt = &dev->tgt;

	if (type != UBLKSRV_TGT_TYPE_DEMO)
		return -1;

	tgt->dev_size = 250UL * 1024 * 1024 * 1024;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;

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
		.rq_max_blocks = DEF_BUF_SIZE / 512,
		.nr_hw_queues = DEF_NR_HW_QUEUES,
		.queue_depth = DEF_QD,
		.block_size = 512,
		.tgt_type = "demo_null",
		.tgt_ops = &demo_tgt_type,
	};
	struct ublksrv_ctrl_dev *dev;
	char *type = NULL;
	int ret;
	static const struct option longopts[] = {
		{ "buf",		1,	NULL, 'b' },
		{ NULL }
	};
	int opt;
	bool use_buf = false;

	while ((opt = getopt_long(argc, argv, ":b",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'b':
			use_buf = true;
			break;
		}
	}
#ifdef NEED_GET_DATA
	fprintf(stdout, "%s: UBLK_F_NEED_GET_DATA\n", __func__);		
	data.flags[0] = UBLK_F_NEED_GET_DATA;
#endif

	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		return -1;
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		return -1;

	if (use_buf) {
		demo_tgt_type.alloc_io_buf = null_alloc_io_buf;
		demo_tgt_type.free_io_buf = null_free_io_buf;
	}

	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		return -ENODEV;
	}
	/* ugly, but signal handler needs this_dev */
	this_dev = dev;

	ret = ublksrv_ctrl_add_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "can't add dev %d, ret %d\n", data.dev_id, ret);
		goto fail;
	}

	ret = ublksrv_start_daemon(dev);
	if (ret <= 0)
		goto fail_del_dev;

	ublksrv_ctrl_deinit(dev);
	return 0;

 fail_del_dev:
	ublksrv_ctrl_del_dev(dev);
 fail:
	ublksrv_ctrl_deinit(dev);

	return ret;
}
