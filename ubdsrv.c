#include "ubdsrv.h"

/*
 * /dev/ubdbN shares same lifetime with the ubd io daemon:
 *
 * 1) IO from /dev/ubdbN is handled by the io daemon directly
 *
 * 2) io cmd buffer is allocated from ubd driver, mapped to
 * io daemon vm space via mmap, and each hw queue has its own
 * io cmd buffer
 *
 * 3) io buffers are pre-allocated from the io daemon and pass
 * to ubd driver via io command, meantime ubd driver may choose
 * to pin these user pages before starting device
 *
 * Each /dev/ubdcN is owned by only one io daemon, and can't be
 * opened by other daemon. And the io daemon uses its allocated
 * io_uring to communicate with ubd driver.
 *
 * For each request of /dev/ubdbN, the io daemon submits one
 * sqe for both fetching IO from ubd driver and commiting IO result
 * to ubd driver, and the io daemon has to issue all sqes
 * to /dev/ubdcN before sending START_DEV to /dev/udc-control.
 *
 * After STOP_DEV is sent to /dev/udc-control, udc driver needs
 * to freeze the request queue, and completes all pending sqes,
 * meantime tell the io daemon via cqe->res that don't issue seq
 * any more, also delete /dev/ubdbN.  After io daemon figures out
 * all sqes have been free, exit itself. Then STOP_DEV returns.
 */

struct ubdsrv_dev this_dev;
static sig_atomic_t volatile ubdsrv_stop = 0;

static void *ubdsrv_io_handler_fn(void *data);

static int prep_io_cmd(struct ubdsrv_queue *q, struct io_uring_sqe *sqe,
		unsigned tag)
{
	struct ubdsrv_io_cmd *cmd = (struct ubdsrv_io_cmd *)&sqe->cmd;
	struct ubd_io *io;
	unsigned long cmd_op;
	__u64 user_data;

	io = &q->ios[tag];
	if (!(io->flags & UBDSRV_IO_FREE)) {
		syslog(LOG_ERR, "io isn't free qid %d, tag %d\n", q->q_id, tag);
		return -1;
	}

	if (io->flags & UBDSRV_NEED_FETCH_RQ) {
		if (io->flags & UBDSRV_NEED_COMMIT_RQ_COMP)
			cmd_op = UBD_IO_COMMIT_AND_FETCH_REQ;
		else
			cmd_op = UBD_IO_FETCH_REQ;
	} else if (io->flags & UBDSRV_NEED_COMMIT_RQ_COMP) {
			cmd_op = UBD_IO_COMMIT_REQ;
	} else {
		syslog(LOG_ERR, "io flags is zero, index %d, tag %d\n", index,
				cmd->tag);
		return -1;
	}

	if (cmd_op == UBD_IO_COMMIT_REQ ||
			cmd_op == UBD_IO_COMMIT_AND_FETCH_REQ)
		cmd->result = io->result;

	/* These fields should be written once, never change */
	sqe->cmd_op	= cmd_op;
	sqe->fd		= 0;	/*dev->cdev_fd*/
	sqe->opcode	=  IORING_OP_URING_CMD;
	sqe->flags	|= IOSQE_FIXED_FILE;
	cmd->tag	= tag;
	cmd->addr	= (__u64)io->buf_addr;
	cmd->q_id	= q->q_id;

	user_data = build_user_data(tag, cmd_op, 0);
	io_uring_sqe_set_data64(sqe, user_data);

	io->flags &= ~(UBDSRV_IO_FREE | UBDSRV_NEED_COMMIT_RQ_COMP);

	INFO(syslog(LOG_INFO, "%s: (qid %d tag %u cmd_op %u) iof %x stopping %d\n",
			__func__, q->q_id, tag, cmd_op,
			io->flags, q->stopping));
	return 1;
}

/*
 * Issue all available commands to /dev/ubdcN  and the exact cmd is figured
 * out in queue_io_cmd with help of each io->status.
 *
 * todo: queue io commands with batching
 */
static int ubdsrv_submit_fetch_commands(struct ubdsrv_queue *q)
{
	unsigned cnt = 0, to_handle = 0;
	int i = 0, ret = 0;
	struct io_uring_sqe *sqe;

	for (i = 0; i < q->q_depth; i++) {
		struct ubd_io *io = &q->ios[i];

		if (io->flags & UBDSRV_IO_HANDLING) {
			io->flags &= ~UBDSRV_IO_HANDLING;
			to_handle += 1;
			continue;
		}

		/* only freed io can be issued */
		if (!(io->flags & UBDSRV_IO_FREE))
			continue;

		/* we issue because we need either fetching or committing */
		if (!(io->flags &
			(UBDSRV_NEED_FETCH_RQ | UBDSRV_NEED_COMMIT_RQ_COMP)))
			continue;
		sqe = io_uring_get_sqe(&q->ring);
		if (!sqe)
			break;
		ret = prep_io_cmd(q, sqe, i);
		if (ret < 0)
			break;
		cnt += ret;
	}

	if (cnt > 0)
		q->cmd_inflight += cnt;

	return cnt + to_handle;
}

static int ubdsrv_queue_is_done(struct ubdsrv_queue *q)
{
	return q->stopping && (!q->cmd_inflight && !q->tgt_io_inflight);
}

static int ubdsrv_dev_is_done(struct ubdsrv_dev *dev)
{
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;
	int i, ret = 0;

	for (i = 0; i < nr_queues; i++)
		ret += ubdsrv_queue_is_done(ubdsrv_get_queue(dev, i));

	return ret == nr_queues;
}

/*
 * Now STOP DEV ctrl command has been sent to /dev/ubd-control,
 * and wait until all pending fetch commands are canceled
 */
static void ubdsrv_drain_fetch_commands(struct ubdsrv_dev *dev)
{
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;
	int i;
	void *ret;

	for (i = 0; i < nr_queues; i++)
		pthread_join(dev->thread[i], &ret);
}

/* used for allocating zero copy vma space */
static inline int ubd_queue_single_io_buf_size(struct ubdsrv_dev *dev)
{
	unsigned max_io_sz = dev->ctrl_dev->dev_info.block_size *
		dev->ctrl_dev->dev_info.rq_max_blocks;
	unsigned int page_sz = getpagesize();

	return round_up(max_io_sz, page_sz);
}
static inline int ubd_queue_io_buf_size(struct ubdsrv_dev *dev)
{
	unsigned depth = dev->ctrl_dev->dev_info.queue_depth;

	return ubd_queue_single_io_buf_size(dev) * depth;
}
static inline int ubd_io_buf_size(struct ubdsrv_dev *dev)
{
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;

	return ubd_queue_io_buf_size(dev) * nr_queues;
}

/* mmap vm space for remapping block io request pages */
static void ubdsrv_deinit_io_bufs(struct ubdsrv_dev *dev)
{
	unsigned long sz = ubd_io_buf_size(dev);

	if (dev->io_buf_start) {
		munmap(dev->io_buf_start, sz);
		dev->io_buf_start = NULL;
	}
}

/* mmap vm space for remapping block io request pages */
static int ubdsrv_init_io_bufs(struct ubdsrv_dev *dev)
{
	unsigned long sz = ubd_io_buf_size(dev);
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;
	int i;
	void *addr;

	dev->io_buf_start = NULL;
	if (!(dev->ctrl_dev->dev_info.flags[0] & (1 << UBD_F_SUPPORT_ZERO_COPY)))
		return 0;

	addr = mmap(0, sz, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, dev->cdev_fd,
			UBDSRV_IO_BUF_OFFSET);
	if (addr == MAP_FAILED)
		return -1;

	dev->io_buf_start = addr;

	for (i = 0; i < nr_queues; i++) {
		struct ubdsrv_queue *q = ubdsrv_get_queue(dev, i);

		q->io_buf = dev->io_buf_start + i * ubd_queue_io_buf_size(dev);
	}

	return 0;
}

static void ubdsrv_init_io_cmds(struct ubdsrv_dev *dev, struct ubdsrv_queue *q)
{
	struct io_uring *r = &q->ring;
	struct io_uring_sqe *sqe;
	int i;

	for (i = 0; i < q->q_depth; i++) {
		struct io_uring_sqe *sqe = ubdsrv_uring_get_sqe(r, i, true);

		/* These fields should be written once, never change */
		__WRITE_ONCE(sqe->flags, IOSQE_FIXED_FILE);
		__WRITE_ONCE(sqe->ioprio, 0);
		__WRITE_ONCE(sqe->off, 0);
	}
}

static int ubdsrv_queue_cmd_buf_sz(struct ubdsrv_queue *q)
{
	int size =  q->q_depth * sizeof(struct ubdsrv_io_desc);
	unsigned int page_sz = getpagesize();

	return round_up(size, page_sz);
}

static void ubdsrv_queue_deinit(struct ubdsrv_queue *q)
{
	int i;

	if (q->ring.ring_fd > 0) {
		io_uring_unregister_files(&q->ring);
		close(q->ring.ring_fd);
		q->ring.ring_fd = -1;
	}
	if (q->io_cmd_buf) {
		munmap(q->io_cmd_buf, ubdsrv_queue_cmd_buf_sz(q));
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

static struct ubdsrv_queue *ubdsrv_queue_init(struct ubdsrv_dev *dev,
		unsigned short q_id)
{
	struct ubdsrv_queue *q;
	struct ubdsrv_ctrl_dev *ctrl_dev = dev->ctrl_dev;
	int depth = ctrl_dev->dev_info.queue_depth;
	int i, ret = -1;
	int cmd_buf_size, io_buf_size;
	unsigned long off;
	int ring_depth = depth + ctrl_dev->tgt.tgt_ring_depth;

	q = malloc(sizeof(struct ubdsrv_queue) + sizeof(struct ubd_io) *
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
	memcpy(&q->cpuset, &ctrl_dev->queues_cpuset[q->q_id],
			sizeof(q->cpuset));

	cmd_buf_size = ubdsrv_queue_cmd_buf_sz(q);
	off = UBDSRV_CMD_BUF_OFFSET +
		q_id * (UBD_MAX_QUEUE_DEPTH * sizeof(struct ubdsrv_io_desc));
	q->io_cmd_buf = mmap(0, cmd_buf_size, PROT_READ,
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
		q->ios[i].flags = UBDSRV_NEED_FETCH_RQ | UBDSRV_IO_FREE;
	}

	ret = ubdsrv_setup_ring(ring_depth, &q->ring, IORING_SETUP_SQE128);
	if (ret < 0)
		goto fail;

	ret = io_uring_register_files(&q->ring, ctrl_dev->tgt.fds,
			ctrl_dev->tgt.nr_fds + 1);
	if (ret)
		goto fail;

	ubdsrv_init_io_cmds(dev, q);


	return q;
 fail:
	ubdsrv_queue_deinit(q);
	syslog(LOG_INFO, "ubd dev %d queue %d failed",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id);
	return NULL;
}

static void ubdsrv_deinit(struct ubdsrv_dev *dev)
{
	int i;

	ubdsrv_deinit_io_bufs(dev);

	if (dev->ctrl_dev->shm_fd >= 0) {
		munmap(dev->ctrl_dev->shm_addr, UBDSRV_SHM_SIZE);
		close(dev->ctrl_dev->shm_fd);
	}

	ubdsrv_tgt_exit(&dev->ctrl_dev->tgt);
	free(dev->thread);

	if (dev->cdev_fd >= 0) {
		close(dev->cdev_fd);
		dev->cdev_fd = -1;
	}
}

static void ubdsrv_setup_tgt_shm(struct ubdsrv_dev *dev)
{
	int fd;
	char buf[64];
	unsigned pid = getpid();

	//if (dev->ctrl_dev->dev_info.ubdsrv_pid <= 0)
	//	return;

	mkdir(UBDSRV_SHM_DIR, S_IRUSR | S_IRUSR);
	snprintf(buf, 64, "%s_%d", UBDSRV_SHM_DIR, pid);

	fd = shm_open(buf, O_CREAT|O_RDWR, S_IRUSR | S_IWUSR);

	ftruncate(fd, UBDSRV_SHM_SIZE);

	dev->ctrl_dev->shm_addr = mmap(NULL, UBDSRV_SHM_SIZE,
		PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	dev->ctrl_dev->shm_offset = 0;
	dev->ctrl_dev->shm_fd = fd;
	INFO(syslog(LOG_INFO, "%s create tgt posix shm %s %d %p", __func__,
				buf, fd, dev->ctrl_dev->shm_addr));
}

static int ubdsrv_init(struct ubdsrv_ctrl_dev *ctrl_dev, struct ubdsrv_dev *dev)
{
	int nr_queues = ctrl_dev->dev_info.nr_hw_queues;
	int dev_id = ctrl_dev->dev_info.dev_id;
	struct ubdsrv_tgt_info *tgt = &ctrl_dev->tgt;
	int queue_size;
	char buf[64];
	int ret = -1;
	int i;

	dev->ctrl_dev = ctrl_dev;
	dev->cdev_fd = -1;

	ubdsrv_setup_tgt_shm(dev);

	snprintf(buf, 64, "%s%d", UBDC_DEV, dev_id);
	dev->cdev_fd = open(buf, O_RDWR);
	if (dev->cdev_fd < 0)
		goto fail;

	tgt->fds[0] = dev->cdev_fd;

	ret = ubdsrv_init_io_bufs(dev);
	if (ret)
		goto fail;

	ret = -1;
	if (ubdsrv_prepare_io(&dev->ctrl_dev->tgt) < 0)
		goto fail;

	dev->thread = calloc(sizeof(pthread_t),
			ctrl_dev->dev_info.nr_hw_queues);
	if (!dev->thread)
		goto fail;

	for (i = 0; i < nr_queues; i++)
		pthread_create(&dev->thread[i], NULL, ubdsrv_io_handler_fn,
				&dev->ctrl_dev->q_id[i]);

	return 0;
fail:
	ubdsrv_deinit(dev);
	return ret;
}

static inline void ubdsrv_handle_tgt_cqe(struct ubdsrv_tgt_info *tgt,
	struct ubdsrv_queue *q, struct io_uring_cqe *cqe)
{
	q->tgt_io_inflight -= 1;
	if (cqe->res < 0 && cqe->res != -EAGAIN) {
		syslog(LOG_WARNING, "%s: failed tgt io: res %d qid %u tag %u, cmd_op %u\n",
			__func__, cqe->res, q->q_id,
			user_data_to_tag(cqe->user_data),
			user_data_to_op(cqe->user_data));
	}
	tgt->ops->complete_tgt_io(q, cqe);
}

static void ubdsrv_handle_cqe(struct io_uring *r,
		struct io_uring_cqe *cqe, void *data)
{
	struct ubdsrv_queue *q = container_of(r, struct ubdsrv_queue, ring);
	struct ubdsrv_dev *dev = q->dev;
	struct ubdsrv_ctrl_dev *ctrl_dev = dev->ctrl_dev;
	struct ubdsrv_tgt_info *tgt = &ctrl_dev->tgt;
	unsigned tag = user_data_to_tag(cqe->user_data);
	unsigned cmd_op = user_data_to_op(cqe->user_data);
	int fetch = (cqe->res != UBD_IO_RES_ABORT) && !q->stopping;
	struct ubd_io *io = &q->ios[tag];

	INFO(syslog(LOG_INFO, "%s: res %d (qid %d tag %u cmd_op %u target %d) iof %x stopping %d\n",
			__func__, cqe->res, q->q_id, tag, cmd_op,
			is_target_io(cqe->user_data), io->flags, q->stopping));

	if (is_target_io(cqe->user_data)) {
		ubdsrv_handle_tgt_cqe(tgt, q, cqe);
		return;
	}

	q->cmd_inflight--;

	if (!fetch) {
		q->stopping = 1;
		io->flags &= ~UBDSRV_NEED_FETCH_RQ;
	}

	/*
	 * So far, only sync tgt's io handling is implemented.
	 *
	 * todo: support async tgt io handling via io_uring, and the ubdsrv
	 * daemon can poll on both two rings.
	 */
	if (cqe->res == UBD_IO_RES_OK && cmd_op != UBD_IO_COMMIT_REQ) {
		tgt->ops->handle_io_async(q, io, tag);
	} else {
		/*
		 * COMMIT_REQ will be completed immediately since no fetching
		 * piggyback is required.
		 *
		 * Marking IO_FREE only, then this io won't be issued since
		 * we only issue io with (UBDSRV_IO_FREE | UBDSRV_NEED_*)
		 *
		 * */
		io->flags = UBDSRV_IO_FREE;
	}
}

static int ubdsrv_reap_events_uring(struct io_uring *r)
{
	struct io_uring_cqe *cqe;
	unsigned head;
	int count = 0;

	io_uring_for_each_cqe(r, head, cqe) {
		ubdsrv_handle_cqe(r, cqe, NULL);
		count += 1;
	}
	io_uring_cq_advance(r, count);
}

static void sig_handler(int sig)
{
	if (sig == SIGTERM)
		syslog(LOG_INFO, "got TERM signal");
}

static void ubdsrv_build_cpu_str(char *buf, int len, cpu_set_t *cpuset)
{
	int nr_cores = sysconf(_SC_NPROCESSORS_ONLN);
	int i, offset = 0;

	for (i = 0; i < nr_cores; i++) {
		if (!CPU_ISSET(i, cpuset))
			continue;
		offset += snprintf(&buf[offset], len - offset, "%d ", i);
	}
}

static void ubdsrv_set_sched_affinity(struct ubdsrv_dev *dev,
		unsigned short q_id)
{
	struct ubdsrv_ctrl_dev *cdev = dev->ctrl_dev;
	unsigned dev_id = cdev->dev_info.dev_id;
	cpu_set_t *cpuset = &cdev->queues_cpuset[q_id];
	pthread_t thread = pthread_self();
	int ret, cnt = 0;
	char cpus[512];

	ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), cpuset);
	if (ret)
		syslog(LOG_INFO, "ubd dev %u queue %u set affinity failed",
				dev_id, q_id);

	ubdsrv_build_cpu_str(cpus, 512, cpuset);

	/* add queue info into shm buffer, be careful to add it just once */
	pthread_mutex_lock(&cdev->lock);
	cdev->shm_offset += snprintf(cdev->shm_addr + cdev->shm_offset,
			UBDSRV_SHM_SIZE - cdev->shm_offset,
			"\tqueue %u: tid %d affinity(%s)\n",
			q_id, gettid(), cpus);
	pthread_mutex_unlock(&cdev->lock);
}

static void *ubdsrv_io_handler_fn(void *data)
{
	unsigned dev_id = this_dev.ctrl_dev->dev_info.dev_id;
	unsigned short q_id = *(unsigned short *)data;
	struct ubdsrv_queue *q;

	ubdsrv_set_sched_affinity(&this_dev, q_id);
	setpriority(PRIO_PROCESS, getpid(), -20);

	q = ubdsrv_queue_init(&this_dev, q_id);
	if (!q) {
		syslog(LOG_INFO, "ubd dev %d queue %d init queue failed",
				this_dev.ctrl_dev->dev_info.dev_id, q_id);
		return NULL;
	}

	syslog(LOG_INFO, "tid %d: ubd dev %d queue %d started", q->tid,
			dev_id, q->q_id);
	do {
		int to_submit, submitted, reapped;

		to_submit = ubdsrv_submit_fetch_commands(q);
		INFO(syslog(LOG_INFO, "dev%d-q%d: to_submit %d inflight %u/%u stopping %d\n",
					dev_id, q->q_id, to_submit,
					q->cmd_inflight, q->tgt_io_inflight,
					q->stopping));

		if (ubdsrv_queue_is_done(q))
			break;

		//submitted = io_uring_enter(&q->ring, to_submit, 1,
		//		IORING_ENTER_GETEVENTS);
		submitted = io_uring_submit_and_wait(&q->ring, 1);
		reapped = ubdsrv_reap_events_uring(&q->ring);

		INFO(syslog(LOG_INFO, "io_submit %d, submitted %d, reapped %d",
				to_submit, submitted, reapped));
	} while (1);

	syslog(LOG_INFO, "ubd dev %d queue %d exited", dev_id, q->q_id);
	ubdsrv_queue_deinit(q);
	return NULL;
}

static sigset_t   signal_mask;
static void ubdsrv_io_handler(void *data)
{
	struct ubdsrv_ctrl_dev *ctrl_dev = data;
	struct ubdsrv_tgt_info *tgt = &ctrl_dev->tgt;
	int dev_id = ctrl_dev->dev_info.dev_id;
	int ret, pid_fd;
	char buf[32];
	char pid_file[64];

	snprintf(buf, 32, "%s-%d", "ubdsrvd", dev_id);
	openlog(buf, LOG_PID, LOG_USER);

	syslog(LOG_INFO, "start ubdsrv io daemon");

	/* create pid file and lock it, so that others can't */
	snprintf(pid_file, 64, "%s-%d.pid", UBDSRV_PID_FILE, dev_id);
	ret = create_pid_file(pid_file, CPF_CLOEXEC, &pid_fd);
	if (ret < 0) {
		/* -1 means the file is locked, and we need to remove it */
		if (ret == -1) {
			close(pid_fd);
			goto out;
		}
		return;
	}
	close(pid_fd);

	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		goto out;

	/* make sure SIGTERM won't be blocked */
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	ret = ubdsrv_init(ctrl_dev, &this_dev);
	if (ret) {
		syslog(LOG_ERR, "start ubsrv failed %d", ret);
		goto out;
	}

	/* wait until we are terminated */
	ubdsrv_drain_fetch_commands(&this_dev);

	ubdsrv_deinit(&this_dev);

 out:
	unlink(pid_file);
	syslog(LOG_INFO, "end ubdsrv io daemon");
	closelog();
}

/* Not called from ubdsrv daemon */
int ubdsrv_start_io_daemon(struct ubdsrv_ctrl_dev *dev)
{
	start_daemon(0, ubdsrv_io_handler, dev);
	return 0;
}

int ubdsrv_get_io_daemon_pid(struct ubdsrv_ctrl_dev *ctrl_dev)
{
	int ret = -1, pid_fd;
	char buf[64];
	int daemon_pid;

	snprintf(buf, 64, "%s-%d.pid", UBDSRV_PID_FILE,
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

/* Not called from ubdsrv daemon */
int ubdsrv_stop_io_daemon(struct ubdsrv_ctrl_dev *ctrl_dev)
{
	int daemon_pid, cnt = 0;

	/* wait until daemon is exited, or timeout after 3 seconds */
	do {
		daemon_pid = ubdsrv_get_io_daemon_pid(ctrl_dev);
		if (daemon_pid > 0) {
			usleep(100000);
			cnt++;
		}
	} while (daemon_pid > 0 && cnt < 30);

	if (daemon_pid > 0)
		return -1;

	return 0;
}
