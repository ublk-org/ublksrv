#include "ubdsrv.h"
#include "utils.h"

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
	__u64 buf_addr;
	__u64 user_data;

	if (q->aborting && tag == -1) {
		cmd_op = UBD_IO_ABORT_QUEUE;
		buf_addr = 0;
		tag = 0;
		goto build_cmd;
	}

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
		__WRITE_ONCE(cmd->result, io->result);

	buf_addr = (__u64)io->buf_addr;
build_cmd:
	user_data = tag | (q->q_id << 16) | (cmd_op << 32);

	/* These fields should be written once, never change */
	__WRITE_ONCE(sqe->user_data, user_data);
	__WRITE_ONCE(sqe->cmd_op, cmd_op);
	__WRITE_ONCE(sqe->fd, /*dev->cdev_fd*/0);
	__WRITE_ONCE(sqe->opcode, IORING_OP_URING_CMD);
	__WRITE_ONCE(cmd->tag, tag);
	__WRITE_ONCE(cmd->addr, buf_addr);
	__WRITE_ONCE(cmd->q_id, q->q_id);

	if (cmd_op != UBD_IO_ABORT_QUEUE)
		io->flags &= ~(UBDSRV_IO_FREE
			 | UBDSRV_NEED_COMMIT_RQ_COMP);
	else
		q->aborting = 0;
	return 1;
}

/*
 * queue io command with @tag to ring
 *
 * fix me: batching submission
 */
static int queue_io_cmd(struct ubdsrv_queue *q, unsigned tail, unsigned tag)
{
	struct ubdsrv_uring *r = &q->ring;
	struct io_sq_ring *ring = &r->sq_ring;
	unsigned index, next_tail = tail + 1;
	struct io_uring_sqe *sqe;
	int ret;

	if (next_tail == atomic_load_acquire(ring->head)) {
		syslog(LOG_INFO, "ring is full, tail %u head %u\n", next_tail,
				*ring->head);
		return -1;
	}

	index = tail & r->sq_ring_mask;
	/* IORING_SETUP_SQE128 */
	sqe = ubdsrv_uring_get_sqe(r, index, true);

	ret = prep_io_cmd(q, sqe, tag);
	if (ret > 0)
		ring->array[index] = index;

	return ret;
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
	int tail = prep_queue_io_cmd(q);

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
		ret = queue_io_cmd(q, tail + cnt, i);
		if (ret < 0)
			break;
		cnt += ret;
	}

	if (q->aborting) {
		ret = queue_io_cmd(q, tail + cnt, -1);
		if (ret >= 0)
			cnt += ret;
	}

	if (cnt > 0) {
		commit_queue_io_cmd(q, tail + cnt);
		q->inflight += cnt;
	}

	INFO(syslog(LOG_INFO, "%s: queued %d, to_handle %d\n",
				__func__, cnt, to_handle));

	return cnt + to_handle;
}

static int ubdsrv_queue_is_done(struct ubdsrv_queue *q)
{
	return q->stopping && q->inflight == 0;
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

	while (1) {
		if (ubdsrv_dev_is_done(dev))
			break;
		if (!ubdsrv_stop)
			sleep(3);
		else
			usleep(10000);

		if (!ubdsrv_stop)
			continue;

		for (i = 0; i < nr_queues; i++) {
			struct ubdsrv_queue *q = ubdsrv_get_queue(dev, i);

			pthread_kill(q->thread, SIGTERM);
		}
	}

	for (i = 0; i < nr_queues; i++) {
		struct ubdsrv_queue *q = ubdsrv_get_queue(dev, i);
		pthread_join(q->thread, &ret);
	}
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
	struct ubdsrv_uring *r = &q->ring;
	struct io_uring_sqe *sqe;
	int i;

	for (i = 0; i < r->ring_depth; i++) {
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
		ubdsrv_io_uring_unregister_files(&q->ring);
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

static int ubdsrv_queue_init(struct ubdsrv_dev *dev, int q_id)
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
	q->inflight = 0;
	q->aborting = 0;

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

	ret = ubdsrv_setup_ring(&q->ring, IORING_SETUP_SQE128,
			ring_depth, NULL, 0);
	if (ret)
		goto fail;

	ret = ubdsrv_io_uring_register_files(&q->ring, ctrl_dev->tgt.fds,
			ctrl_dev->tgt.nr_fds + 1);
	if (ret)
		goto fail;

	ubdsrv_init_io_cmds(dev, q);

	pthread_create(&q->thread, NULL, ubdsrv_io_handler_fn, q);

	return 0;
 fail:
	ubdsrv_queue_deinit(q);
	syslog(LOG_INFO, "ubd dev %d queue %d failed",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id);
	return ret;
}

static void ubdsrv_deinit(struct ubdsrv_dev *dev)
{
	int i;

	ubdsrv_deinit_io_bufs(dev);

	for (i = 0; i < dev->ctrl_dev->dev_info.nr_hw_queues; i++)
		ubdsrv_queue_deinit(ubdsrv_get_queue(dev, i));

	if (dev->ctrl_dev->shm_fd >= 0) {
		munmap(dev->ctrl_dev->shm_addr, UBDSRV_SHM_SIZE);
		close(dev->ctrl_dev->shm_fd);
	}

	ubdsrv_tgt_exit(&dev->ctrl_dev->tgt);

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

	if (ubdsrv_prepare_io(&dev->ctrl_dev->tgt) < 0)
		goto fail;

	ret = ubdsrv_init_io_bufs(dev);
	if (ret)
		goto fail;

	for (i = 0; i < nr_queues; i++) {
		if (ubdsrv_queue_init(dev, i)) {
			syslog(LOG_INFO, "ubd dev %d queue %d init queue failed",
				dev->ctrl_dev->dev_info.dev_id, i);
			goto fail;
		}
	}

	return 0;
fail:
	ubdsrv_deinit(dev);
	return ret;
}

static void ubdsrv_handle_tgt_cqe(struct ubdsrv_dev *dev,
	struct ubdsrv_queue *q, struct io_uring_cqe *cqe)
{
	int tag = cqe->user_data & 0xffff;
	struct ubd_io *io = &q->ios[tag];

	io->result = cqe->res;

	/* Mark this IO as free and ready for issuing to ubd driver */
	io->flags |= (UBDSRV_NEED_COMMIT_RQ_COMP | UBDSRV_IO_FREE);

	/* clear handling */
	io->flags &= ~UBDSRV_IO_HANDLING;
}

static void ubdsrv_handle_cqe(struct ubdsrv_uring *r,
		struct io_uring_cqe *cqe, void *data)
{
	struct ubdsrv_queue *q = container_of(r, struct ubdsrv_queue, ring);
	struct ubdsrv_dev *dev = q->dev;
	struct ubdsrv_ctrl_dev *ctrl_dev = dev->ctrl_dev;
	struct ubdsrv_tgt_info *tgt = &ctrl_dev->tgt;
	int tag = cqe->user_data & 0xffff;
	int qid = (cqe->user_data >> 16) & 0xffff;
	unsigned last_cmd_op = cqe->user_data >> 32 & 0x7fffffff;
	int fetch = (cqe->res != UBD_IO_RES_ABORT);
	struct ubd_io *io = &q->ios[tag];

	INFO(syslog(LOG_INFO, "%s: user_data %lx res %d (qid %d tag %d, cmd_op %d) iof %x\n",
			__func__, cqe->user_data, cqe->res, qid, tag,
			last_cmd_op, io->flags));

	if (cqe->user_data & (1ULL << 63)) {
		ubdsrv_handle_tgt_cqe(dev, q, cqe);
		return;
	}

	q->inflight--;

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
	if (cqe->res == UBD_IO_RES_OK && last_cmd_op != UBD_IO_COMMIT_REQ &&
			last_cmd_op != UBD_IO_ABORT_QUEUE) {

		if (tgt->ops->handle_io) {
			io->result = tgt->ops->handle_io(dev, qid, tag);

			/* Mark this IO as free and ready for issuing to ubd driver */
			io->flags |= (UBDSRV_NEED_COMMIT_RQ_COMP | UBDSRV_IO_FREE);
		} else {
			tgt->ops->handle_io_async(dev, qid, tag);
		}
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

static void sig_handler(int sig)
{
	if (sig == SIGTERM) {
		syslog(LOG_INFO, "got TERM signal");
		ubdsrv_stop = 1;
	}
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

static void ubdsrv_set_sched_affinity(struct ubdsrv_queue *q)
{
	unsigned dev_id = q->dev->ctrl_dev->dev_info.dev_id;
	struct ubdsrv_ctrl_dev *cdev = q->dev->ctrl_dev;
	pthread_t thread = pthread_self();
	int ret, cnt = 0;
	char cpus[512];

	memcpy(&q->cpuset, &cdev->queues_cpuset[q->q_id], sizeof(q->cpuset));

	ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &q->cpuset);
	if (ret)
		syslog(LOG_INFO, "ubd dev %d queue %d set affinity failed",
				dev_id, q->q_id);
	q->tid = gettid();

	ubdsrv_build_cpu_str(cpus, 512, &q->cpuset);

	/* add queue info into shm buffer, be careful to add it just once */
	pthread_mutex_lock(&cdev->lock);
	cdev->shm_offset += snprintf(cdev->shm_addr + cdev->shm_offset,
			UBDSRV_SHM_SIZE - cdev->shm_offset,
			"\tqueue %d: tid %d affinity(%s)\n",
			q->q_id, q->tid, cpus);
	pthread_mutex_unlock(&cdev->lock);
}

static void *ubdsrv_io_handler_fn(void *data)
{
	struct ubdsrv_queue *q = data;
	int aborted = 0;
	unsigned dev_id = q->dev->ctrl_dev->dev_info.dev_id;

	INFO(syslog(LOG_INFO, "ubd dev %d queue %d started",
				dev_id, q->q_id));

	ubdsrv_set_sched_affinity(q);
	setpriority(PRIO_PROCESS, getpid(), -20);

	do {
		int to_submit, submitted, reapped;

		/* we need to abort queue */
		if (ubdsrv_stop && !aborted) {
			aborted = 1;
			q->aborting = 1;
		}

		to_submit = ubdsrv_submit_fetch_commands(q);
		INFO(syslog(LOG_INFO, "dev%d-q%d: to_submit %d inflight %d stopping %d\n",
					dev_id, q->q_id, to_submit, q->inflight,
					q->stopping));

		if (!q->inflight && q->stopping)
			break;
		submitted = io_uring_enter(&q->ring, to_submit, 1,
				IORING_ENTER_GETEVENTS);
		reapped = ubdsrv_reap_events_uring(&q->ring,
				ubdsrv_handle_cqe, NULL);
		INFO(syslog(LOG_INFO, "io_submit %d, submitted %d, reapped %d",
				to_submit, submitted, reapped));
	} while (1);
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
	pthread_sigmask(SIG_UNBLOCK, &signal_mask, NULL);

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
	syslog(LOG_INFO, "end ubdsrv io daemon, running %d", ubdsrv_stop);
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
