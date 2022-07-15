#include "ublksrv_priv.h"

/*
 * /dev/ublkbN shares same lifetime with the ublk io daemon:
 *
 * 1) IO from /dev/ublkbN is handled by the io daemon directly
 *
 * 2) io cmd buffer is allocated from ublk driver, mapped to
 * io daemon vm space via mmap, and each hw queue has its own
 * io cmd buffer
 *
 * 3) io buffers are pre-allocated from the io daemon and pass
 * to ublk driver via io command, meantime ublk driver may choose
 * to pin these user pages before starting device
 *
 * Each /dev/ublkcN is owned by only one io daemon, and can't be
 * opened by other daemon. And the io daemon uses its allocated
 * io_uring to communicate with ublk driver.
 *
 * For each request of /dev/ublkbN, the io daemon submits one
 * sqe for both fetching IO from ublk driver and commiting IO result
 * to ublk driver, and the io daemon has to issue all sqes
 * to /dev/ublkcN before sending START_DEV to /dev/udc-control.
 *
 * After STOP_DEV is sent to /dev/udc-control, udc driver needs
 * to freeze the request queue, and completes all pending sqes,
 * meantime tell the io daemon via cqe->res that don't issue seq
 * any more, also delete /dev/ublkbN.  After io daemon figures out
 * all sqes have been free, exit itself. Then STOP_DEV returns.
 */

#define UBLKC_DEV	"/dev/ublkc"

/*
 * If ublksrv queue is idle in the past 20 seconds, start to discard
 * pages mapped to io buffer via madivise(MADV_DONTNEED), so these
 * pages can be available for others without needing swap out
 */
#define UBLKSRV_IO_IDLE_SECS    20

static void *ublksrv_io_handler_fn(void *data);

static struct ublksrv_tgt_type *tgt_list[UBLKSRV_TGT_TYPE_MAX] = {};

static int __ublksrv_tgt_init(struct ublksrv_dev *dev, const char *type_name,
		const struct ublksrv_tgt_type *ops, int type,
		int argc, char *argv[])
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	int ret;

	if (!ops)
		return -EINVAL;

	if (strcmp(ops->name, type_name))
		return -EINVAL;

	if (!ops->init_tgt)
		return -EINVAL;
	if (!ops->handle_io_async)
		return -EINVAL;
	if (!ops->alloc_io_buf ^ !ops->free_io_buf)
		return -EINVAL;

	optind = 0;     /* so that we can parse our arguments */
	tgt->ops = ops;
	ret = ops->init_tgt(dev, type, argc, argv);
	if (ret) {
		tgt->ops = NULL;
		return ret;
	}
	return 0;
}

static int ublksrv_tgt_init(struct ublksrv_dev *dev, const char *type_name,
		const struct ublksrv_tgt_type *ops,
		int argc, char *argv[])
{
	int i;

	if (type_name == NULL)
		return -EINVAL;

	if (ops)
		return __ublksrv_tgt_init(dev, type_name, ops,
				ops->type, argc, argv);

	for (i = 0; i < UBLKSRV_TGT_TYPE_MAX; i++) {
		const struct ublksrv_tgt_type  *lops = tgt_list[i];

		if (!__ublksrv_tgt_init(dev, type_name, lops, i, argc, argv))
			return 0;
	}

	return -EINVAL;
}

static inline void ublksrv_tgt_exit(struct ublksrv_tgt_info *tgt)
{
	int i;

	for (i = 1; i < tgt->nr_fds; i++)
		close(tgt->fds[i]);
}

static void ublksrv_tgt_deinit(struct ublksrv_dev *dev)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;

	ublksrv_tgt_exit(tgt);

	if (tgt->ops && tgt->ops->deinit_tgt)
		tgt->ops->deinit_tgt(dev);
}

void ublksrv_for_each_tgt_type(void (*handle_tgt_type)(unsigned idx,
			const struct ublksrv_tgt_type *type, void *data),
		void *data)
{
	int i;

	for (i = 0; i < UBLKSRV_TGT_TYPE_MAX; i++) {
		int len;

                const struct ublksrv_tgt_type  *type = tgt_list[i];

		if (!type)
			continue;
		handle_tgt_type(i, type, data);
	}
}

int ublksrv_register_tgt_type(struct ublksrv_tgt_type *type)
{
	if (type->type < UBLKSRV_TGT_TYPE_MAX && !tgt_list[type->type]) {
		tgt_list[type->type] = type;
		return 0;
	}
	return -1;
}

void ublksrv_unregister_tgt_type(struct ublksrv_tgt_type *type)
{
	if (type->type < UBLKSRV_TGT_TYPE_MAX && tgt_list[type->type]) {
		tgt_list[type->type] = NULL;
	}
}

static inline int ublksrv_queue_io_cmd(struct ublksrv_queue *q,
		struct ublk_io *io, unsigned tag)
{
	struct ublksrv_io_cmd *cmd;
	struct io_uring_sqe *sqe;
	unsigned int cmd_op;
	__u64 user_data;

	/* only freed io can be issued */
	if (!(io->flags & UBLKSRV_IO_FREE))
		return 0;

	/* we issue because we need either fetching or committing */
	if (!(io->flags &
		(UBLKSRV_NEED_FETCH_RQ | UBLKSRV_NEED_GET_DATA |
		 UBLKSRV_NEED_COMMIT_RQ_COMP)))
		return 0;

	if (io->flags & UBLKSRV_NEED_GET_DATA)
		cmd_op = UBLK_IO_NEED_GET_DATA;
	else if (io->flags & UBLKSRV_NEED_COMMIT_RQ_COMP)
		cmd_op = UBLK_IO_COMMIT_AND_FETCH_REQ;
	else if (io->flags & UBLKSRV_NEED_FETCH_RQ)
		cmd_op = UBLK_IO_FETCH_REQ;

	sqe = io_uring_get_sqe(&q->ring);
	if (!sqe) {
		syslog(LOG_ERR, "%s: run out of sqe %d, tag %d\n",
				__func__, q->q_id, tag);
		return -1;
	}

	cmd = (struct ublksrv_io_cmd *)ublksrv_get_sqe_cmd(sqe);

	if (cmd_op == UBLK_IO_COMMIT_AND_FETCH_REQ)
		cmd->result = io->result;

	/* These fields should be written once, never change */
	ublksrv_set_sqe_cmd_op(sqe, cmd_op);
	sqe->fd		= 0;	/*dev->cdev_fd*/
	sqe->opcode	=  IORING_OP_URING_CMD;
	sqe->flags	= IOSQE_FIXED_FILE;
	sqe->rw_flags	= 0;
	cmd->tag	= tag;
	cmd->addr	= (__u64)io->buf_addr;
	cmd->q_id	= q->q_id;

	user_data = build_user_data(tag, cmd_op, 0, 0);
	io_uring_sqe_set_data64(sqe, user_data);

	io->flags = 0;

	q->cmd_inflight += 1;

	ublksrv_log(LOG_INFO, "%s: (qid %d tag %u cmd_op %u) iof %x stopping %d\n",
			__func__, q->q_id, tag, cmd_op,
			io->flags, q->stopping);
	return 1;
}

int ublksrv_complete_io(struct ublksrv_queue *q, unsigned tag, int res)
{
	struct ublk_io *io = &q->ios[tag];

	ublksrv_mark_io_done(io, res);

	return ublksrv_queue_io_cmd(q, io, tag);
}

/*
 * eventfd is treated as special target IO which has to be queued
 * when queue is setup
 */
static inline int __ublksrv_queue_event(struct ublksrv_queue *q)
{
	if (q->efd > 0) {
		struct io_uring_sqe *sqe;
		__u64 user_data = build_eventfd_data();

		if (q->stopping)
			return -EINVAL;

		sqe = io_uring_get_sqe(&q->ring);
		if (!sqe) {
			syslog(LOG_ERR, "%s: queue %d run out of sqe\n",
				__func__, q->q_id);
			return -1;
		}

		io_uring_prep_poll_add(sqe, q->efd, POLLIN);
		io_uring_sqe_set_data64(sqe, user_data);
		q->tgt_io_inflight += 1;
	}
	return 0;
}

/*
 * This API is supposed to be called in ->handle_event() after current
 * events are handled.
 */
int ublksrv_queue_handled_event(struct ublksrv_queue *q)
{
	if (q->efd > 0) {
		unsigned long long data;
		const int cnt = sizeof(uint64_t);

		/* read has to be done, otherwise poll event won't be stopped */
		if (read(q->efd, &data, cnt) != cnt)
			syslog(LOG_ERR, "%s: read wrong bytes from eventfd\n",
					__func__);
		/*
		 * event needs to be issued immediately, since other io may rely
		 * it
		 */
		if (!__ublksrv_queue_event(q))
			io_uring_submit_and_wait(&q->ring, 0);
	}
	return 0;
}

/*
 * Send event to io command uring context, so that the queue pthread
 * can be waken up for handling io, then ->handle_event() will be
 * called to notify target code.
 *
 * This API is usually called from other context.
 */
int ublksrv_queue_send_event(struct ublksrv_queue *q)
{
	if (q->efd > 0) {
		unsigned long long data = 1;
		const int cnt = sizeof(uint64_t);

		if (write(q->efd, &data, cnt) != cnt) {
			syslog(LOG_ERR, "%s: read wrong bytes from eventfd\n",
					__func__);
			return -EPIPE;
		}
	}
	return 0;
}

/*
 * Issue all available commands to /dev/ublkcN  and the exact cmd is figured
 * out in queue_io_cmd with help of each io->status.
 *
 * todo: queue io commands with batching
 */
static void ublksrv_submit_fetch_commands(struct ublksrv_queue *q)
{
	int i = 0;

	for (i = 0; i < q->q_depth; i++)
		ublksrv_queue_io_cmd(q, &q->ios[i], i);

	__ublksrv_queue_event(q);
}

static int ublksrv_queue_is_done(struct ublksrv_queue *q)
{
	return q->stopping && (!q->cmd_inflight && !q->tgt_io_inflight);
}

/* used for allocating zero copy vma space */
static inline int ublk_queue_single_io_buf_size(struct ublksrv_dev *dev)
{
	unsigned max_io_sz = dev->ctrl_dev->dev_info.block_size *
		dev->ctrl_dev->dev_info.rq_max_blocks;
	unsigned int page_sz = getpagesize();

	return round_up(max_io_sz, page_sz);
}
static inline int ublk_queue_io_buf_size(struct ublksrv_dev *dev)
{
	unsigned depth = dev->ctrl_dev->dev_info.queue_depth;

	return ublk_queue_single_io_buf_size(dev) * depth;
}
static inline int ublk_io_buf_size(struct ublksrv_dev *dev)
{
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;

	return ublk_queue_io_buf_size(dev) * nr_queues;
}

/* mmap vm space for remapping block io request pages */
static void ublksrv_dev_deinit_io_bufs(struct ublksrv_dev *dev)
{
	unsigned long sz = ublk_io_buf_size(dev);

	if (dev->io_buf_start) {
		munmap(dev->io_buf_start, sz);
		dev->io_buf_start = NULL;
	}
}

/* mmap vm space for remapping block io request pages */
static int ublksrv_dev_init_io_bufs(struct ublksrv_dev *dev)
{
	unsigned long sz = ublk_io_buf_size(dev);
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;
	int i;
	void *addr;

	dev->io_buf_start = NULL;
	if (!(dev->ctrl_dev->dev_info.flags[0] & UBLK_F_SUPPORT_ZERO_COPY))
		return 0;

	addr = mmap(0, sz, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, dev->cdev_fd,
			UBLKSRV_IO_BUF_OFFSET);
	if (addr == MAP_FAILED)
		return -1;

	dev->io_buf_start = (char *)addr;

	for (i = 0; i < nr_queues; i++) {
		struct ublksrv_queue *q = ublksrv_get_queue(dev, i);

		q->io_buf = dev->io_buf_start + i * ublk_queue_io_buf_size(dev);
	}

	return 0;
}

static void ublksrv_dev_init_io_cmds(struct ublksrv_dev *dev, struct ublksrv_queue *q)
{
	struct io_uring *r = &q->ring;
	struct io_uring_sqe *sqe;
	int i;

	for (i = 0; i < q->q_depth; i++) {
		struct io_uring_sqe *sqe = ublksrv_uring_get_sqe(r, i, true);

		/* These fields should be written once, never change */
		sqe->flags = IOSQE_FIXED_FILE;
		sqe->rw_flags = 0;
		sqe->ioprio = 0;
		sqe->off = 0;
	}
}

static int ublksrv_queue_cmd_buf_sz(struct ublksrv_queue *q)
{
	int size =  q->q_depth * sizeof(struct ublksrv_io_desc);
	unsigned int page_sz = getpagesize();

	return round_up(size, page_sz);
}

void ublksrv_queue_deinit(struct ublksrv_queue *q)
{
	int i;

	if (q->efd > 0)
		close(q->efd);

	if (q->ring.ring_fd > 0) {
		io_uring_unregister_files(&q->ring);
		close(q->ring.ring_fd);
		q->ring.ring_fd = -1;
	}
	if (q->io_cmd_buf) {
		munmap(q->io_cmd_buf, ublksrv_queue_cmd_buf_sz(q));
		q->io_cmd_buf = NULL;
	}
	for (i = 0; i < q->q_depth; i++) {
		if (q->ios[i].buf_addr) {
			if (q->dev->tgt.ops->free_io_buf)
				q->dev->tgt.ops->free_io_buf(q,
						q->ios[i].buf_addr, i);
			else
				free(q->ios[i].buf_addr);
			q->ios[i].buf_addr = NULL;
		}
	}
	q->dev->__queues[q->q_id] = NULL;
	free(q);

}

static void ublksrv_build_cpu_str(char *buf, int len, cpu_set_t *cpuset)
{
	int nr_cores = sysconf(_SC_NPROCESSORS_ONLN);
	int i, offset = 0;

	for (i = 0; i < nr_cores; i++) {
		if (!CPU_ISSET(i, cpuset))
			continue;
		offset += snprintf(&buf[offset], len - offset, "%d ", i);
	}
}

static void ublksrv_set_sched_affinity(struct ublksrv_dev *dev,
		unsigned short q_id)
{
	const struct ublksrv_ctrl_dev *cdev = dev->ctrl_dev;
	unsigned dev_id = cdev->dev_info.dev_id;
	cpu_set_t *cpuset = &cdev->queues_cpuset[q_id];
	pthread_t thread = pthread_self();
	int ret, cnt = 0;
	char cpus[512];

	ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), cpuset);
	if (ret)
		syslog(LOG_INFO, "ublk dev %u queue %u set affinity failed",
				dev_id, q_id);

	ublksrv_build_cpu_str(cpus, 512, cpuset);

	if (!(cdev->dev_info.ublksrv_flags & UBLKSRV_F_HAS_IO_DAEMON))
		return;

	/* add queue info into shm buffer, be careful to add it just once */
	pthread_mutex_lock(&dev->shm_lock);
	dev->shm_offset += snprintf(dev->shm_addr + dev->shm_offset,
			UBLKSRV_SHM_SIZE - dev->shm_offset,
			"\tqueue %u: tid %d affinity(%s)\n",
			q_id, gettid(), cpus);
	pthread_mutex_unlock(&dev->shm_lock);
}

static void ublksrv_kill_eventfd(struct ublksrv_queue *q)
{
	if (q->stopping && q->efd > 0) {
		unsigned long long data = 1;

		write(q->efd, &data, 8);
	}
}

static int ublksrv_setup_eventfd(struct ublksrv_queue *q)
{
	const struct ublksrv_ctrl_dev_info *info = &q->dev->ctrl_dev->dev_info;

        if (!(info->ublksrv_flags & UBLKSRV_F_NEED_EVENTFD)) {
		q->efd = -1;
		return 0;
	}

	if (q->dev->tgt.tgt_ring_depth == 0) {
		syslog(LOG_INFO, "%s ublk dev %d queue %d zero tgt queue depth",
			info->dev_id, q->q_id);
		return -EINVAL;
	}

	if (!q->dev->tgt.ops->handle_event) {
		syslog(LOG_INFO, "%s ublk dev %d/%d not define ->handle_event",
			info->dev_id, q->q_id);
		return -EINVAL;
	}

	q->efd = eventfd(0, 0);
	if (q->efd < 0)
		return q->efd;
	return 0;
}

struct ublksrv_queue *ublksrv_queue_init(struct ublksrv_dev *dev,
		unsigned short q_id, void *queue_data)
{
	struct ublksrv_queue *q;
	const struct ublksrv_ctrl_dev *ctrl_dev = dev->ctrl_dev;
	int depth = ctrl_dev->dev_info.queue_depth;
	int i, ret = -1;
	int cmd_buf_size, io_buf_size;
	unsigned long off;
	int ring_depth = depth + dev->tgt.tgt_ring_depth;

	q = (struct ublksrv_queue *)malloc(sizeof(struct ublksrv_queue) + sizeof(struct ublk_io) *
		ctrl_dev->dev_info.queue_depth);
	dev->__queues[q_id] = q;

	q->dev = dev;
	q->stopping = 0;
	q->q_id = q_id;
	/* FIXME: depth has to be PO 2 */
	q->q_depth = depth;
	q->io_cmd_buf = NULL;
	q->cmd_inflight = 0;
	q->tgt_io_inflight = 0;
	q->tid = gettid();

	cmd_buf_size = ublksrv_queue_cmd_buf_sz(q);
	off = UBLKSRV_CMD_BUF_OFFSET +
		q_id * (UBLK_MAX_QUEUE_DEPTH * sizeof(struct ublksrv_io_desc));
	q->io_cmd_buf = (char *)mmap(0, cmd_buf_size, PROT_READ,
			MAP_SHARED | MAP_POPULATE, dev->cdev_fd, off);
	if (q->io_cmd_buf == MAP_FAILED)
		goto fail;

	io_buf_size = ctrl_dev->dev_info.block_size *
		ctrl_dev->dev_info.rq_max_blocks;
	for (i = 0; i < depth; i++) {
		q->ios[i].buf_addr = NULL;
		if (dev->tgt.ops->alloc_io_buf)
			q->ios[i].buf_addr = dev->tgt.ops->alloc_io_buf(q,
					i, io_buf_size);
		else
			if (posix_memalign((void **)&q->ios[i].buf_addr,
						getpagesize(), io_buf_size))
				goto fail;
		//q->ios[i].buf_addr = malloc(io_buf_size);
		if (!q->ios[i].buf_addr)
			goto fail;
		q->ios[i].flags = UBLKSRV_NEED_FETCH_RQ | UBLKSRV_IO_FREE;
	}

	ret = ublksrv_setup_ring(ring_depth, &q->ring, IORING_SETUP_SQE128);
	if (ret < 0)
		goto fail;

	ret = io_uring_register_files(&q->ring, dev->tgt.fds,
			dev->tgt.nr_fds + 1);
	if (ret)
		goto fail;

	ublksrv_dev_init_io_cmds(dev, q);

	if (prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0) != 0)
		syslog(LOG_INFO, "ublk dev %d queue %d set_io_flusher failed",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id);

	q->private_data = queue_data;


	if (ctrl_dev->queues_cpuset)
		ublksrv_set_sched_affinity(dev, q_id);

	setpriority(PRIO_PROCESS, getpid(), -20);

	if (ublksrv_setup_eventfd(q) < 0) {
		syslog(LOG_INFO, "ublk dev %d queue %d setup eventfd failed",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id);
		goto fail;
	}

	/* submit all io commands to ublk driver */
	ublksrv_submit_fetch_commands(q);

	return q;
 fail:
	ublksrv_queue_deinit(q);
	syslog(LOG_INFO, "ublk dev %d queue %d failed",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id);
	return NULL;
}

void ublksrv_dev_deinit(struct ublksrv_dev *dev)
{
	int i;

	ublksrv_dev_deinit_io_bufs(dev);

	if (dev->shm_fd >= 0) {
		munmap(dev->shm_addr, UBLKSRV_SHM_SIZE);
		close(dev->shm_fd);
	}

	ublksrv_tgt_deinit(dev);
	free(dev->thread);

	if (dev->cdev_fd >= 0) {
		close(dev->cdev_fd);
		dev->cdev_fd = -1;
	}
	free(dev);
}

static void ublksrv_setup_tgt_shm(struct ublksrv_dev *dev)
{
	int fd;
	char buf[64];
	unsigned pid = getpid();

	if (!(dev->ctrl_dev->dev_info.ublksrv_flags &
				UBLKSRV_F_HAS_IO_DAEMON))
		return;

	pthread_mutex_init(&dev->shm_lock, NULL);

	//if (dev->ctrl_dev->dev_info.ublksrv_pid <= 0)
	//	return;

	mkdir(UBLKSRV_SHM_DIR, S_IRUSR | S_IRUSR);
	snprintf(buf, 64, "%s_%d", UBLKSRV_SHM_DIR, pid);

	fd = shm_open(buf, O_CREAT|O_RDWR, S_IRUSR | S_IWUSR);

	ftruncate(fd, UBLKSRV_SHM_SIZE);

	dev->shm_addr = (char *)mmap(NULL, UBLKSRV_SHM_SIZE,
		PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	dev->shm_offset = sizeof(struct ublksrv_ctrl_dev_info);
	dev->shm_fd = fd;
	ublksrv_log(LOG_INFO, "%s create tgt posix shm %s %d %p", __func__,
				buf, fd, dev->shm_addr);
}

struct ublksrv_dev *ublksrv_dev_init(const struct ublksrv_ctrl_dev *ctrl_dev)
{
	int nr_queues = ctrl_dev->dev_info.nr_hw_queues;
	int dev_id = ctrl_dev->dev_info.dev_id;
	int queue_size;
	char buf[64];
	int ret = -1;
	int i;
	struct ublksrv_dev *dev = (struct ublksrv_dev *)calloc(1, sizeof(*dev));
	struct ublksrv_tgt_info *tgt;

	if (!dev)
		return dev;

	tgt = &dev->tgt;
	dev->ctrl_dev = ctrl_dev;
	dev->cdev_fd = -1;

	ublksrv_setup_tgt_shm(dev);

	snprintf(buf, 64, "%s%d", UBLKC_DEV, dev_id);
	dev->cdev_fd = open(buf, O_RDWR);
	if (dev->cdev_fd < 0) {
		syslog(LOG_ERR, "can't open %s, ret %d\n", buf, dev->cdev_fd);
		goto fail;
	}

	tgt->fds[0] = dev->cdev_fd;

	ret = ublksrv_dev_init_io_bufs(dev);
	if (ret) {
		syslog(LOG_ERR, "init buf failed\n");
		goto fail;
	}

	ret = ublksrv_tgt_init(dev, ctrl_dev->tgt_type, ctrl_dev->tgt_ops,
			ctrl_dev->tgt_argc, ctrl_dev->tgt_argv);
	if (ret) {
		syslog(LOG_ERR, "can't init tgt %d/%s/%d, ret %d\n",
				dev_id, ctrl_dev->tgt_type, ctrl_dev->tgt_argc,
				ret);
		goto fail;
	}

	return dev;
fail:
	ublksrv_dev_deinit(dev);
	return NULL;
}

/* Be careful, target io may not have one ublk_io associated with  */
static inline void ublksrv_handle_tgt_cqe(struct ublksrv_tgt_info *tgt,
	struct ublksrv_queue *q, struct io_uring_cqe *cqe)
{
	unsigned tag = user_data_to_tag(cqe->user_data);

	q->tgt_io_inflight -= 1;
	if (cqe->res < 0 && cqe->res != -EAGAIN) {
		syslog(LOG_WARNING, "%s: failed tgt io: res %d qid %u tag %u, cmd_op %u\n",
			__func__, cqe->res, q->q_id,
			user_data_to_tag(cqe->user_data),
			user_data_to_op(cqe->user_data));
	}

	if (is_eventfd_io(cqe->user_data)) {
		if (tgt->ops->handle_event)
			tgt->ops->handle_event(q);
	} else {
		if (tgt->ops->tgt_io_done)
			tgt->ops->tgt_io_done(q, cqe);
	}
}

static void ublksrv_handle_cqe(struct io_uring *r,
		struct io_uring_cqe *cqe, void *data)
{
	struct ublksrv_queue *q = container_of(r, struct ublksrv_queue, ring);
	struct ublksrv_dev *dev = q->dev;
	const struct ublksrv_ctrl_dev *ctrl_dev = dev->ctrl_dev;
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	unsigned tag = user_data_to_tag(cqe->user_data);
	unsigned cmd_op = user_data_to_op(cqe->user_data);
	int fetch = (cqe->res != UBLK_IO_RES_ABORT) && !q->stopping;
	struct ublk_io *io;

	ublksrv_log(LOG_INFO, "%s: res %d (qid %d tag %u cmd_op %u target %d event %d) stopping %d\n",
			__func__, cqe->res, q->q_id, tag, cmd_op,
			is_target_io(cqe->user_data),
			is_eventfd_io(cqe->user_data),
			q->stopping);

	/* Don't retrieve io in case of target io */
	if (is_target_io(cqe->user_data)) {
		ublksrv_handle_tgt_cqe(tgt, q, cqe);
		return;
	}

	io = &q->ios[tag];
	q->cmd_inflight--;

	if (!fetch) {
		q->stopping = 1;
		io->flags &= ~UBLKSRV_NEED_FETCH_RQ;
	}

	/*
	 * So far, only sync tgt's io handling is implemented.
	 *
	 * todo: support async tgt io handling via io_uring, and the ublksrv
	 * daemon can poll on both two rings.
	 */
	if (cqe->res == UBLK_IO_RES_OK) {
		tgt->ops->handle_io_async(q, tag);
	} else if (cqe->res == UBLK_IO_RES_NEED_GET_DATA) {
		io->flags |= UBLKSRV_NEED_GET_DATA | UBLKSRV_IO_FREE;
		ublksrv_queue_io_cmd(q, io, tag);
	} else {
		/*
		 * COMMIT_REQ will be completed immediately since no fetching
		 * piggyback is required.
		 *
		 * Marking IO_FREE only, then this io won't be issued since
		 * we only issue io with (UBLKSRV_IO_FREE | UBLKSRV_NEED_*)
		 *
		 * */
		io->flags = UBLKSRV_IO_FREE;
	}
}

static int ublksrv_reap_events_uring(struct io_uring *r)
{
	struct io_uring_cqe *cqe;
	unsigned head;
	int count = 0;

	io_uring_for_each_cqe(r, head, cqe) {
		ublksrv_handle_cqe(r, cqe, NULL);
		count += 1;
	}
	io_uring_cq_advance(r, count);

	return count;
}

static void ublksrv_queue_discard_io_pages(struct ublksrv_queue *q)
{
	const struct ublksrv_ctrl_dev *cdev = q->dev->ctrl_dev;
	unsigned int io_buf_size = cdev->dev_info.block_size *
		cdev->dev_info.rq_max_blocks;
	int i = 0;

	if (q->idle)
		return;

	for (i = 0; i < q->q_depth; i++)
		madvise(q->ios[i].buf_addr, io_buf_size, MADV_DONTNEED);
	q->idle = true;
}

int ublksrv_process_io(struct ublksrv_queue *q)
{
	int ret, reapped;
	struct __kernel_timespec ts = {
		.tv_sec = UBLKSRV_IO_IDLE_SECS,
		.tv_nsec = 0
        };
	struct __kernel_timespec *tsp = q->idle ? NULL : &ts;
	struct io_uring_cqe *cqe;

	ublksrv_log(LOG_INFO, "dev%d-q%d: to_submit %d inflight %u/%u stopping %d\n",
				q->dev->ctrl_dev->dev_info.dev_id,
				q->q_id, io_uring_sq_ready(&q->ring),
				q->cmd_inflight, q->tgt_io_inflight,
				q->stopping);

	if (ublksrv_queue_is_done(q))
		return -ENODEV;

	ret = io_uring_submit_and_wait_timeout(&q->ring, &cqe, 1, tsp, NULL);
	reapped = ublksrv_reap_events_uring(&q->ring);

	ublksrv_log(LOG_INFO, "submit result %d, reapped %d stop %d idle %d",
			ret, reapped, q->stopping, q->idle);

	if (q->stopping)
		ublksrv_kill_eventfd(q);
	else {
		if (ret == -ETIME && reapped == 0)
			ublksrv_queue_discard_io_pages(q);
		else if (q->idle)
			q->idle = false;
	}

	return reapped;
}
