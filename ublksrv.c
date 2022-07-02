#include "ublksrv.h"

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

struct ublksrv_queue_info {
	struct ublksrv_dev *dev;
	int qid;
	pthread_t thread;
};

static void *ublksrv_io_handler_fn(void *data);

int ublksrv_queue_io_cmd(struct ublksrv_queue *q, unsigned tag)
{
	struct ublk_io *io = &q->ios[tag];
	struct ublksrv_io_cmd *cmd;
	struct io_uring_sqe *sqe;
	unsigned int cmd_op;
	__u64 user_data;

	/* only freed io can be issued */
	if (!(io->flags & UBLKSRV_IO_FREE))
		return 0;

	/* we issue because we need either fetching or committing */
	if (!(io->flags &
		(UBLKSRV_NEED_FETCH_RQ | UBLKSRV_NEED_COMMIT_RQ_COMP)))
		return 0;

	if (io->flags & UBLKSRV_NEED_FETCH_RQ) {
		if (io->flags & UBLKSRV_NEED_COMMIT_RQ_COMP)
			cmd_op = UBLK_IO_COMMIT_AND_FETCH_REQ;
		else
			cmd_op = UBLK_IO_FETCH_REQ;
	} else if (io->flags & UBLKSRV_NEED_COMMIT_RQ_COMP) {
			cmd_op = UBLK_IO_COMMIT_REQ;
	} else {
		syslog(LOG_ERR, "io flags is zero, tag %d\n",
				(int)cmd->tag);
		return 0;
	}

	sqe = io_uring_get_sqe(&q->ring);
	if (!sqe) {
		syslog(LOG_ERR, "%s: run out of sqe %d, tag %d\n",
				__func__, q->q_id, tag);
		return -1;
	}

	cmd = (struct ublksrv_io_cmd *)ublksrv_get_sqe_cmd(sqe);


	if (cmd_op == UBLK_IO_COMMIT_REQ ||
			cmd_op == UBLK_IO_COMMIT_AND_FETCH_REQ)
		cmd->result = io->result;

	/* These fields should be written once, never change */
	ublksrv_set_sqe_cmd_op(sqe, cmd_op);
	sqe->fd		= 0;	/*dev->cdev_fd*/
	sqe->opcode	=  IORING_OP_URING_CMD;
	sqe->flags	|= IOSQE_FIXED_FILE;
	cmd->tag	= tag;
	cmd->addr	= (__u64)io->buf_addr;
	cmd->q_id	= q->q_id;

	user_data = build_user_data(tag, cmd_op, 0, 0);
	io_uring_sqe_set_data64(sqe, user_data);

	io->flags &= ~(UBLKSRV_IO_FREE | UBLKSRV_NEED_COMMIT_RQ_COMP);

	q->cmd_inflight += 1;

	ublksrv_log(LOG_INFO, "%s: (qid %d tag %u cmd_op %u) iof %x stopping %d\n",
			__func__, q->q_id, tag, cmd_op,
			io->flags, q->stopping);
	return 1;
}

/*
 * Issue all available commands to /dev/ublkcN  and the exact cmd is figured
 * out in queue_io_cmd with help of each io->status.
 *
 * todo: queue io commands with batching
 */
static void ublksrv_submit_fetch_commands(struct ublksrv_queue *q)
{
	unsigned cnt = 0;
	int i = 0;

	for (i = 0; i < q->q_depth; i++)
		ublksrv_queue_io_cmd(q, i);
}

static int ublksrv_queue_is_done(struct ublksrv_queue *q)
{
	return q->stopping && (!q->cmd_inflight && !q->tgt_io_inflight);
}

/*
 * Now STOP DEV ctrl command has been sent to /dev/ublk-control,
 * and wait until all pending fetch commands are canceled
 */
static void ublksrv_drain_fetch_commands(struct ublksrv_dev *dev,
		struct ublksrv_queue_info *info)
{
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;
	int i;
	void *ret;

	for (i = 0; i < nr_queues; i++)
		pthread_join(info[i].thread, &ret);
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
static void ublksrv_deinit_io_bufs(struct ublksrv_dev *dev)
{
	unsigned long sz = ublk_io_buf_size(dev);

	if (dev->io_buf_start) {
		munmap(dev->io_buf_start, sz);
		dev->io_buf_start = NULL;
	}
}

/* mmap vm space for remapping block io request pages */
static int ublksrv_init_io_bufs(struct ublksrv_dev *dev)
{
	unsigned long sz = ublk_io_buf_size(dev);
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;
	int i;
	void *addr;

	dev->io_buf_start = NULL;
	if (!(dev->ctrl_dev->dev_info.flags[0] & (1 << UBLK_F_SUPPORT_ZERO_COPY)))
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

static void ublksrv_init_io_cmds(struct ublksrv_dev *dev, struct ublksrv_queue *q)
{
	struct io_uring *r = &q->ring;
	struct io_uring_sqe *sqe;
	int i;

	for (i = 0; i < q->q_depth; i++) {
		struct io_uring_sqe *sqe = ublksrv_uring_get_sqe(r, i, true);

		/* These fields should be written once, never change */
		sqe->flags = IOSQE_FIXED_FILE;
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

static void ublksrv_queue_deinit(struct ublksrv_queue *q)
{
	int i;

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
			free(q->ios[i].buf_addr);
			q->ios[i].buf_addr = NULL;
		}
	}
	q->dev->__queues[q->q_id] = NULL;
	free(q);

}

static struct ublksrv_queue *ublksrv_queue_init(struct ublksrv_dev *dev,
		unsigned short q_id)
{
	struct ublksrv_queue *q;
	struct ublksrv_ctrl_dev *ctrl_dev = dev->ctrl_dev;
	int depth = ctrl_dev->dev_info.queue_depth;
	int i, ret = -1;
	int cmd_buf_size, io_buf_size;
	unsigned long off;
	int ring_depth = depth + ctrl_dev->tgt.tgt_ring_depth;

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
		if (posix_memalign((void **)&q->ios[i].buf_addr, getpagesize(), io_buf_size))
			goto fail;
		//q->ios[i].buf_addr = malloc(io_buf_size);
		if (!q->ios[i].buf_addr)
			goto fail;
		q->ios[i].flags = UBLKSRV_NEED_FETCH_RQ | UBLKSRV_IO_FREE;
	}

	ret = ublksrv_setup_ring(ring_depth, &q->ring, IORING_SETUP_SQE128);
	if (ret < 0)
		goto fail;

	ret = io_uring_register_files(&q->ring, ctrl_dev->tgt.fds,
			ctrl_dev->tgt.nr_fds + 1);
	if (ret)
		goto fail;

	ublksrv_init_io_cmds(dev, q);

	if (prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0) != 0)
		syslog(LOG_INFO, "ublk dev %d queue %d set_io_flusher failed",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id);

	return q;
 fail:
	ublksrv_queue_deinit(q);
	syslog(LOG_INFO, "ublk dev %d queue %d failed",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id);
	return NULL;
}

static void ublksrv_deinit(struct ublksrv_dev *dev)
{
	int i;

	ublksrv_deinit_io_bufs(dev);

	if (dev->shm_fd >= 0) {
		munmap(dev->shm_addr, UBLKSRV_SHM_SIZE);
		close(dev->shm_fd);
	}

	ublksrv_tgt_deinit(&dev->ctrl_dev->tgt, dev);
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

	if (!(dev->ctrl_dev->dev_info.flags[0] & (1 << UBLK_F_HAS_IO_DAEMON)))
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
	dev->shm_offset += sizeof(struct ublksrv_ctrl_dev_info);
	dev->shm_fd = fd;
	ublksrv_log(LOG_INFO, "%s create tgt posix shm %s %d %p", __func__,
				buf, fd, dev->shm_addr);
}

static struct ublksrv_dev *ublksrv_init(struct ublksrv_ctrl_dev *ctrl_dev,
	struct ublksrv_queue_info *info)
{
	int nr_queues = ctrl_dev->dev_info.nr_hw_queues;
	int dev_id = ctrl_dev->dev_info.dev_id;
	struct ublksrv_tgt_info *tgt = &ctrl_dev->tgt;
	int queue_size;
	char buf[64];
	int ret = -1;
	int i;
	struct ublksrv_dev *dev = (struct ublksrv_dev *)calloc(1, sizeof(*dev));

	if (!dev)
		return dev;

	dev->ctrl_dev = ctrl_dev;
	dev->cdev_fd = -1;

	ublksrv_setup_tgt_shm(dev);

	snprintf(buf, 64, "%s%d", UBLKC_DEV, dev_id);
	dev->cdev_fd = open(buf, O_RDWR);
	if (dev->cdev_fd < 0)
		goto fail;

	tgt->fds[0] = dev->cdev_fd;

	ret = ublksrv_init_io_bufs(dev);
	if (ret)
		goto fail;

	ret = -1;
	if (ublksrv_prepare_target(&dev->ctrl_dev->tgt, dev) < 0)
		goto fail;

	for (i = 0; i < nr_queues; i++) {
		info[i].dev = dev;
		info[i].qid = i;
		pthread_create(&info[i].thread, NULL, ublksrv_io_handler_fn,
				&info[i]);
	}

	return dev;
fail:
	ublksrv_deinit(dev);
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

	if (tgt->ops->tgt_io_done)
		tgt->ops->tgt_io_done(q, cqe);
}

static void ublksrv_handle_cqe(struct io_uring *r,
		struct io_uring_cqe *cqe, void *data)
{
	struct ublksrv_queue *q = container_of(r, struct ublksrv_queue, ring);
	struct ublksrv_dev *dev = q->dev;
	struct ublksrv_ctrl_dev *ctrl_dev = dev->ctrl_dev;
	struct ublksrv_tgt_info *tgt = &ctrl_dev->tgt;
	unsigned tag = user_data_to_tag(cqe->user_data);
	unsigned cmd_op = user_data_to_op(cqe->user_data);
	int fetch = (cqe->res != UBLK_IO_RES_ABORT) && !q->stopping;
	struct ublk_io *io;

	ublksrv_log(LOG_INFO, "%s: res %d (qid %d tag %u cmd_op %u target %d) stopping %d\n",
			__func__, cqe->res, q->q_id, tag, cmd_op,
			is_target_io(cqe->user_data), q->stopping);

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
	if (cqe->res == UBLK_IO_RES_OK && cmd_op != UBLK_IO_COMMIT_REQ) {
		tgt->ops->handle_io_async(q, tag);
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
	struct ublksrv_ctrl_dev *cdev = dev->ctrl_dev;
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

	/* add queue info into shm buffer, be careful to add it just once */
	pthread_mutex_lock(&dev->shm_lock);
	dev->shm_offset += snprintf(dev->shm_addr + dev->shm_offset,
			UBLKSRV_SHM_SIZE - dev->shm_offset,
			"\tqueue %u: tid %d affinity(%s)\n",
			q_id, gettid(), cpus);
	pthread_mutex_unlock(&dev->shm_lock);
}

static void *ublksrv_io_handler_fn(void *data)
{
	struct ublksrv_queue_info *info = (struct ublksrv_queue_info *)data;
	struct ublksrv_dev *dev = info->dev;
	unsigned dev_id = dev->ctrl_dev->dev_info.dev_id;
	unsigned short q_id = info->qid;
	struct ublksrv_queue *q;

	ublksrv_set_sched_affinity(dev, q_id);
	setpriority(PRIO_PROCESS, getpid(), -20);

	q = ublksrv_queue_init(dev, q_id);
	if (!q) {
		syslog(LOG_INFO, "ublk dev %d queue %d init queue failed",
				dev->ctrl_dev->dev_info.dev_id, q_id);
		return NULL;
	}

	syslog(LOG_INFO, "tid %d: ublk dev %d queue %d started", q->tid,
			dev_id, q->q_id);
	ublksrv_submit_fetch_commands(q);
	do {
		int submitted, reapped;

		ublksrv_log(LOG_INFO, "dev%d-q%d: to_submit %d inflight %u/%u stopping %d\n",
					dev_id, q->q_id, io_uring_sq_ready(&q->ring),
					q->cmd_inflight, q->tgt_io_inflight,
					q->stopping);
		if (ublksrv_queue_is_done(q))
			break;

		submitted = io_uring_submit_and_wait(&q->ring, 1);
		reapped = ublksrv_reap_events_uring(&q->ring);

		ublksrv_log(LOG_INFO, "submitted %d, reapped %d", submitted, reapped);
	} while (1);

	syslog(LOG_INFO, "ublk dev %d queue %d exited", dev_id, q->q_id);
	ublksrv_queue_deinit(q);
	return NULL;
}

static void sig_handler(int sig)
{
	if (sig == SIGTERM)
		syslog(LOG_INFO, "got TERM signal");
}

static void setup_pthread_sigmask()
{
	sigset_t   signal_mask;

	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		return;

	/* make sure SIGTERM won't be blocked */
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
}

static int ublksrv_create_pid_file(int dev_id)
{
	char pid_file[64];
	int ret, pid_fd;

	/* create pid file and lock it, so that others can't */
	snprintf(pid_file, 64, "%s-%d.pid", UBLKSRV_PID_FILE, dev_id);

	ret = create_pid_file(pid_file, CPF_CLOEXEC, &pid_fd);
	if (ret < 0) {
		/* -1 means the file is locked, and we need to remove it */
		if (ret == -1) {
			close(pid_fd);
			unlink(pid_file);
		}
		return ret;
	}
	close(pid_fd);
	return 0;
}

static void ublksrv_remove_pid_file(int dev_id)
{
	char pid_file[64];

	/* create pid file and lock it, so that others can't */
	snprintf(pid_file, 64, "%s-%d.pid", UBLKSRV_PID_FILE, dev_id);
	unlink(pid_file);
}

static void ublksrv_io_handler(void *data)
{
	struct ublksrv_ctrl_dev *ctrl_dev = (struct ublksrv_ctrl_dev *)data;
	struct ublksrv_tgt_info *tgt = &ctrl_dev->tgt;
	int dev_id = ctrl_dev->dev_info.dev_id;
	int ret;
	char buf[32];
	struct ublksrv_dev *dev;
	struct ublksrv_queue_info *info_array;

	snprintf(buf, 32, "%s-%d", "ublksrvd", dev_id);
	openlog(buf, LOG_PID, LOG_USER);

	syslog(LOG_INFO, "start ublksrv io daemon");

	if (ublksrv_create_pid_file(dev_id))
		return;

	setup_pthread_sigmask();

	info_array = (struct ublksrv_queue_info *)calloc(sizeof(
				struct ublksrv_queue_info),
			ctrl_dev->dev_info.nr_hw_queues);

	dev = ublksrv_init(ctrl_dev, info_array);
	if (!dev) {
		syslog(LOG_ERR, "start ubsrv failed");
		goto out;
	}

	/* wait until we are terminated */
	ublksrv_drain_fetch_commands(dev, info_array);

	ublksrv_deinit(dev);

	free(info_array);

 out:
	ublksrv_remove_pid_file(dev_id);
	syslog(LOG_INFO, "end ublksrv io daemon");
	closelog();
}

/* Not called from ublksrv daemon */
int ublksrv_start_io_daemon(struct ublksrv_ctrl_dev *dev)
{
	start_daemon(0, ublksrv_io_handler, dev);
	return 0;
}

int ublksrv_get_io_daemon_pid(struct ublksrv_ctrl_dev *ctrl_dev)
{
	int ret = -1, pid_fd;
	char buf[64];
	int daemon_pid;

	snprintf(buf, 64, "%s-%d.pid", UBLKSRV_PID_FILE,
			ctrl_dev->dev_info.dev_id);
	pid_fd = open(buf, O_RDONLY);
	if (pid_fd < 0)
		goto out;

	if (read(pid_fd, buf, sizeof(buf)) <= 0)
		goto out;

	daemon_pid = strtol(buf, NULL, 10);
	if (daemon_pid < 0)
		goto out;

	ret = kill(daemon_pid, 0);
	if (ret)
		goto out;

	return daemon_pid;
out:
	return ret;
}

/* Not called from ublksrv daemon */
int ublksrv_stop_io_daemon(struct ublksrv_ctrl_dev *ctrl_dev)
{
	int daemon_pid, cnt = 0;

	/* wait until daemon is exited, or timeout after 3 seconds */
	do {
		daemon_pid = ublksrv_get_io_daemon_pid(ctrl_dev);
		if (daemon_pid > 0) {
			usleep(100000);
			cnt++;
		}
	} while (daemon_pid > 0 && cnt < 30);

	if (daemon_pid > 0)
		return -1;

	return 0;
}
