#include <sys/epoll.h>
#include "ublksrv.h"

#define UBLKSRV_TGT_TYPE_DEMO  0

struct demo_queue_info {
	struct ublksrv_dev *dev;
	struct ublksrv_queue *q;
	int qid;

	/* for notify real io handler that we have io available */
	int efd, dead;

	pthread_t thread;

	pthread_t io_thread;

	pthread_spinlock_t lock;

	struct ublk_io *pending;
	struct ublk_io *processed;
};

static struct ublksrv_ctrl_dev *this_ctrl_dev;
static struct ublksrv_dev *this_dev;
static void sig_handler(int sig)
{
	struct ublksrv_queue *q = this_dev->__queues[0];
	fprintf(stderr, "got signal %d, stopping %d, %d %d\n", sig,
			q->stopping, q->cmd_inflight, q->tgt_io_inflight);
	ublksrv_ctrl_stop_dev(this_ctrl_dev);
}

static bool demo_add_list(struct ublk_io **head, struct ublk_io **new_list)
{
	struct ublk_io *io, *end = NULL;

	/* add pending into ->processed list */
	io = *head;
	while (io) {
		end = io;
		io = (struct ublk_io *)io->io_data;
	}

	if (end)
		end->io_data = (unsigned long)*new_list;
	else
		*head = *new_list;

	io = *new_list;
	*new_list = NULL;

	return !!io;
}

#define EPOLL_NR_EVENTS 1
static void *demo_event_real_io_handler_fn(void *data)
{
	struct demo_queue_info *info = (struct demo_queue_info *)data;
	struct ublksrv_dev *dev = info->dev;
	unsigned dev_id = dev->ctrl_dev->dev_info.dev_id;
	unsigned short q_id = info->qid;
	struct epoll_event events[EPOLL_NR_EVENTS];
	int epoll_fd = epoll_create(EPOLL_NR_EVENTS);
	struct epoll_event read_event;
	int ret;

	if (epoll_fd < 0) {
		fprintf(stderr, "ublk dev %d queue %d create epoll fd failed\n",
				dev_id, q_id);
		return NULL;
	}

	read_event.events = EPOLLIN;
	read_event.data.fd = info->efd;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, info->efd, &read_event);
	if (ret < 0) {
		fprintf(stderr, "ublk dev %d queue %d epoll_ctl(ADD) failed\n",
				dev_id, q_id);
		return NULL;
	}

	/* wait until the 1st io comes */
	//read(info->efd, &data, 8);
	epoll_wait(epoll_fd, events, EPOLL_NR_EVENTS, -1);

	while (!info->dead) {
		int added = 0;

		/* move all io in ->pending to ->processed */
		pthread_spin_lock(&info->lock);
		added = demo_add_list(&info->processed, &info->pending);
		pthread_spin_unlock(&info->lock);

		/*
		 * clear internal event before sending ublksrv event which
		 * generate new io(internal event) immediately
		 */
		read(info->efd, &data, 8);

		/* tell ublksrv io_uring context that we have io done */
		ublksrv_queue_send_event(info->q);

		ret = epoll_wait(epoll_fd, events, EPOLL_NR_EVENTS, -1);
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

	info->dead = 1;
	write(info->efd, &ev_data, 8);
	fprintf(stdout, "ublk dev %d queue %d exited\n", dev_id, q->q_id);
	ublksrv_queue_deinit(q);
	return NULL;
}

static unsigned long long demo_get_dev_blocks(const struct ublksrv_dev *dev)
{
	return dev->tgt.dev_size / dev->ctrl_dev->dev_info.block_size;
}

static void demo_event_io_handler(struct ublksrv_ctrl_dev *ctrl_dev)
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
	this_dev = dev;
	for (i = 0; i < dinfo->nr_hw_queues; i++) {
		int j;
		info_array[i].efd = eventfd(0, 0);
		info_array[i].dev = dev;
		info_array[i].qid = i;
		pthread_spin_init(&info_array[i].lock,
				PTHREAD_PROCESS_PRIVATE);
		pthread_create(&info_array[i].thread, NULL,
				demo_event_io_handler_fn,
				&info_array[i]);
		pthread_create(&info_array[i].io_thread, NULL,
				demo_event_real_io_handler_fn,
				&info_array[i]);
	}

	/* everything is fine now, start us */
	ublksrv_ctrl_start_dev(ctrl_dev, getpid(), demo_get_dev_blocks(dev));

	ublksrv_ctrl_get_info(ctrl_dev);
	ublksrv_ctrl_dump(ctrl_dev);

	/* wait until we are terminated */
	for (i = 0; i < dinfo->nr_hw_queues; i++) {
		int j;
		pthread_join(info_array[i].thread, &thread_ret);
		pthread_join(info_array[i].io_thread, &thread_ret);
		pthread_spin_destroy(&info_array[i].lock);
		close(info_array[i].efd);
	}

	ublksrv_dev_deinit(dev);

	free(info_array);
}

static int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev)
{
	int cnt = 0, daemon_pid;
	int ret;

	if (ublksrv_ctrl_get_affinity(ctrl_dev) < 0)
		return -1;

	demo_event_io_handler(ctrl_dev);

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
	struct demo_queue_info *info = (struct demo_queue_info *)
		ublksrv_queue_get_data(q);
	unsigned long long data = 1;
	struct ublk_io *io = &q->ios[tag];

	/* add current io into ->pending list */
	pthread_spin_lock(&info->lock);
	io->io_data = (unsigned long)info->pending;
	info->pending = io;
	pthread_spin_unlock(&info->lock);

	write(info->efd, &data, 8);
	return 0;
}

static void demo_handle_one_io(struct ublksrv_queue *q, struct ublk_io *io)
{
	int tag = ((unsigned long)io - (unsigned long)&q->ios[0]) / sizeof(*io);
	const struct ublksrv_io_desc *iod = ublksrv_get_iod(q, tag);

	ublksrv_complete_io(q, tag, iod->nr_sectors << 9);
}

static void demo_handle_event(struct ublksrv_queue *q)
{
	struct demo_queue_info *info = (struct demo_queue_info *)
		ublksrv_queue_get_data(q);
	int cnt = 0;

	/* complete all ios from ->processed list */
	while (true) {
		struct ublk_io *io, *list;

		pthread_spin_lock(&info->lock);
		list = info->processed;
		info->processed = NULL;
		pthread_spin_unlock(&info->lock);

		if (!list)
			break;

		io = list;
		while (io) {
			struct ublk_io *next = (struct ublk_io *)io->io_data;

			demo_handle_one_io(info->q, io);
			io = next;
			cnt++;
		}
	}

	ublksrv_queue_handled_event(info->q);
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
	struct ublksrv_dev_data data = {
		.dev_id = -1,
		.rq_max_blocks = DEF_BUF_SIZE / 512,
		.nr_hw_queues = DEF_NR_HW_QUEUES,
		.queue_depth = DEF_QD,
		.block_size = 512,
		.tgt_type = "demo_event",
		.tgt_ops = &demo_event_tgt_type,
	};
	struct ublksrv_ctrl_dev *dev;
	char *type = NULL;
	int ret;

	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		return -1;
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		return -1;

#ifdef NEED_GET_DATA
	fprintf(stdout, "%s: UBLK_F_NEED_GET_DATA\n", __func__);		
	data.flags[0] = UBLK_F_NEED_GET_DATA;
#endif

	data.ublksrv_flags = UBLKSRV_F_NEED_EVENTFD;
	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		return -ENODEV;
	}
	/* ugly, but signal handler needs this_dev */
	this_ctrl_dev = dev;

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
