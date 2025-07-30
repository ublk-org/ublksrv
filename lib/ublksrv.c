// SPDX-License-Identifier: MIT or LGPL-2.1-only

#include <config.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "ublksrv_priv.h"
#include "ublksrv_aio.h"

bool ublksrv_is_recovering(const struct ublksrv_ctrl_dev *ctrl_dev)
{
	return ctrl_dev->tgt_argc == -1 || ctrl_dev->data->recover;
}

static inline struct ublksrv_io_desc *ublksrv_get_iod(
		const struct _ublksrv_queue *q, int tag)
{
        return &q->io_cmd_buf[tag];
}

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

/*
 * If ublksrv queue is idle in the past 20 seconds, start to discard
 * pages mapped to io buffer via madivise(MADV_DONTNEED), so these
 * pages can be available for others without needing swap out
 */
#define UBLKSRV_IO_IDLE_SECS    20

static int __ublksrv_tgt_init(struct _ublksrv_dev *dev, const char *type_name,
		const struct ublksrv_tgt_type *ops, int type,
		int argc, char *argv[])
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	int ret;

	if (!ops)
		return -EINVAL;

	if (strcmp(ops->name, type_name))
		return -EINVAL;

	if (!ops->handle_io_async)
		return -EINVAL;
	if (!ops->alloc_io_buf ^ !ops->free_io_buf)
		return -EINVAL;

	optind = 0;     /* so that we can parse our arguments */
	tgt->ops = ops;

	if (!ublksrv_is_recovering(dev->ctrl_dev)) {
		if (ops->init_tgt)
			ret = ops->init_tgt(local_to_tdev(dev), type, argc, argv);
		else
			ret = 0;
	} else {
		/* driver can recover via ->init_tgt() */
		if (ops->recovery_tgt)
			ret = ops->recovery_tgt(local_to_tdev(dev), type);
		else {
			if (ops->init_tgt)
				ret = ops->init_tgt(local_to_tdev(dev), type, argc, argv);
			else
				ret = -ENOTSUP;
		}
	}
	if (ret) {
		tgt->ops = NULL;
		return ret;
	}
	return 0;
}

static int ublksrv_tgt_init(struct _ublksrv_dev *dev, const char *type_name,
		const struct ublksrv_tgt_type *ops,
		int argc, char *argv[])
{
	if (type_name == NULL)
		return -EINVAL;

	if (ops)
		return __ublksrv_tgt_init(dev, type_name, ops,
				ops->type, argc, argv);

	return -EINVAL;
}

static inline void ublksrv_tgt_exit(struct ublksrv_tgt_info *tgt)
{
	int i;

	for (i = 1; i < tgt->nr_fds; i++)
		close(tgt->fds[i]);
}

static void ublksrv_tgt_deinit(struct _ublksrv_dev *dev)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;

	ublksrv_tgt_exit(tgt);

	if (tgt->ops && tgt->ops->deinit_tgt)
		tgt->ops->deinit_tgt(local_to_tdev(dev));
}

static inline bool ublksrv_queue_use_buf(const struct _ublksrv_queue *q)
{
	return !(q->state & (UBLKSRV_USER_COPY | UBLKSRV_ZERO_COPY));
}

static inline bool ublksrv_queue_alloc_buf(const struct _ublksrv_queue *q)
{
	return !(q->state & UBLKSRV_ZERO_COPY);
}

static void ublk_set_auto_buf_reg(struct io_uring_sqe *sqe,
				  unsigned short buf_idx,
				  unsigned char flags)
{
       struct ublk_auto_buf_reg buf = {
               .index = buf_idx,
               .flags = flags,
       };

       sqe->addr = ublk_auto_buf_reg_to_sqe_addr(&buf);
}

static inline int ublksrv_queue_io_cmd(struct _ublksrv_queue *q,
		struct ublk_io *io, unsigned tag)
{
	struct ublksrv_io_cmd *cmd;
	struct io_uring_sqe *sqe;
	unsigned int cmd_op = 0;
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

	sqe = ublksrv_alloc_sqe(&q->ring);
	if (!sqe) {
		ublk_err("%s: run out of sqe %d, tag %d\n",
				__func__, q->q_id, tag);
		return -1;
	}

	cmd = (struct ublksrv_io_cmd *)ublksrv_get_sqe_cmd(sqe);

	if (cmd_op == UBLK_IO_COMMIT_AND_FETCH_REQ)
		cmd->result = io->result;

	if (q->state & UBLKSRV_QUEUE_IOCTL_OP)
		cmd_op = _IOWR('u', _IOC_NR(cmd_op), struct ublksrv_io_cmd);

	/* These fields should be written once, never change */
	ublksrv_set_sqe_cmd_op(sqe, cmd_op);
	sqe->fd		= 0;	/*dev->cdev_fd*/
	sqe->opcode	=  IORING_OP_URING_CMD;
	sqe->flags	= IOSQE_FIXED_FILE;
	sqe->rw_flags	= 0;
	cmd->tag	= tag;
	if (ublksrv_queue_use_buf(q))
		cmd->addr	= (__u64)io->buf_addr;
	else
		cmd->addr	= 0;
	cmd->q_id	= q->q_id;

	if (q->state & UBLKSRV_AUTO_ZC)
		ublk_set_auto_buf_reg(sqe, tag, 0);

	user_data = build_user_data(tag, _IOC_NR(cmd_op), 0, 0);
	io_uring_sqe_set_data64(sqe, user_data);

	io->flags = 0;

	q->cmd_inflight += 1;

	ublk_dbg(UBLK_DBG_IO_CMD, "%s: (qid %d tag %u cmd_op %u) iof %x stopping %d\n",
			__func__, q->q_id, tag, cmd_op,
			io->flags, !!(q->state & UBLKSRV_QUEUE_STOPPING));
	return 1;
}

int ublksrv_complete_io(const struct ublksrv_queue *tq, unsigned tag, int res)
{
	struct _ublksrv_queue *q = tq_to_local(tq);

	struct ublk_io *io = &q->ios[tag];

	ublksrv_mark_io_done(io, res);

	return ublksrv_queue_io_cmd(q, io, tag);
}

/*
 * eventfd is treated as special target IO which has to be queued
 * when queue is setup
 */
static inline int __ublksrv_queue_event(struct _ublksrv_queue *q)
{
	if (q->efd >= 0) {
		struct io_uring_sqe *sqe;
		__u64 user_data = build_internal_data(UBLK_IO_OP_EVENTFD);

		if (q->state & UBLKSRV_QUEUE_STOPPING)
			return -EINVAL;

		sqe = io_uring_get_sqe(&q->ring);
		if (!sqe) {
			ublk_err("%s: queue %d run out of sqe\n",
				__func__, q->q_id);
			return -1;
		}

		io_uring_prep_poll_add(sqe, q->efd, POLLIN);
		io_uring_sqe_set_data64(sqe, user_data);
	}
	return 0;
}

/*
 * This API is supposed to be called in ->handle_event() after current
 * events are handled.
 */
int ublksrv_queue_handled_event(const struct ublksrv_queue *tq)
{
	struct _ublksrv_queue *q = tq_to_local(tq);

	if (q->efd >= 0) {
		uint64_t data;
		const int cnt = sizeof(uint64_t);

		/* read has to be done, otherwise poll event won't be stopped */
		if (read(q->efd, &data, cnt) != cnt)
			ublk_err("%s: read wrong bytes from eventfd\n",
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
int ublksrv_queue_send_event(const struct ublksrv_queue *tq)
{
	struct _ublksrv_queue *q = tq_to_local(tq);

	if (q->efd >= 0) {
		uint64_t data = 1;
		const int cnt = sizeof(uint64_t);

		if (write(q->efd, &data, cnt) != cnt) {
			ublk_err("%s: wrote wrong bytes to eventfd\n",
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
static void ublksrv_submit_fetch_commands(struct _ublksrv_queue *q)
{
	int i = 0;

	for (i = 0; i < q->q_depth; i++)
		ublksrv_queue_io_cmd(q, &q->ios[i], i);

	__ublksrv_queue_event(q);
}

static inline int __ublksrv_queue_is_done(const struct _ublksrv_queue *q)
{
	return (q->state & UBLKSRV_QUEUE_STOPPING) &&
		!io_uring_sq_ready(&q->ring);
}

int ublksrv_queue_is_done(const struct ublksrv_queue *tq)
{
	const struct _ublksrv_queue *q = tq_to_local(tq);
	return __ublksrv_queue_is_done(q);
}

/* used for allocating zero copy vma space */
static inline int ublk_queue_single_io_buf_size(struct _ublksrv_dev *dev)
{
	unsigned max_io_sz = dev->ctrl_dev->dev_info.max_io_buf_bytes;
	unsigned int page_sz = getpagesize();

	return round_up(max_io_sz, page_sz);
}
static inline int ublk_queue_io_buf_size(struct _ublksrv_dev *dev)
{
	unsigned depth = dev->ctrl_dev->dev_info.queue_depth;

	return ublk_queue_single_io_buf_size(dev) * depth;
}
static inline int ublk_io_buf_size(struct _ublksrv_dev *dev)
{
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;

	return ublk_queue_io_buf_size(dev) * nr_queues;
}

static int ublksrv_queue_cmd_buf_sz(struct _ublksrv_queue *q)
{
	int size =  q->q_depth * sizeof(struct ublksrv_io_desc);
	unsigned int page_sz = getpagesize();

	return round_up(size, page_sz);
}

static int queue_max_cmd_buf_sz(void)
{
	unsigned int page_sz = getpagesize();

	return round_up(UBLK_MAX_QUEUE_DEPTH * sizeof(struct ublksrv_io_desc),
			page_sz);
}

int ublksrv_queue_unconsumed_cqes(const struct ublksrv_queue *tq)
{
	if (tq->ring_ptr)
		return io_uring_cq_ready(tq->ring_ptr);

	return -1;
}

void ublksrv_queue_deinit(const struct ublksrv_queue *tq)
{
	struct _ublksrv_queue *q = tq_to_local(tq);
	int i;
	int nr_ios = q->dev->tgt.extra_ios + q->q_depth;

	if (q->dev->tgt.ops->deinit_queue)
		q->dev->tgt.ops->deinit_queue(tq);

	if (q->epollfd >= 0)
		close(q->epollfd);
	while (q->epoll_callbacks) {
		struct epoll_cb_data *next = q->epoll_callbacks->next;

		free(q->epoll_callbacks);
		q->epoll_callbacks = next;
	}

	if (q->efd >= 0)
		close(q->efd);

	io_uring_unregister_buffers(&q->ring);
	io_uring_unregister_ring_fd(&q->ring);

	if (q->ring.ring_fd > 0) {
		io_uring_unregister_files(&q->ring);
		close(q->ring.ring_fd);
		q->ring.ring_fd = -1;
	}
	if (q->io_cmd_buf) {
		munmap(q->io_cmd_buf, ublksrv_queue_cmd_buf_sz(q));
		q->io_cmd_buf = NULL;
	}
	for (i = 0; i < nr_ios; i++) {
		if (q->ios[i].buf_addr) {
			if (q->dev->tgt.ops->free_io_buf)
				q->dev->tgt.ops->free_io_buf(tq,
						q->ios[i].buf_addr, i);
			else
				free(q->ios[i].buf_addr);
			q->ios[i].buf_addr = NULL;
		}
		free(q->ios[i].data.private_data);
	}
	q->dev->__queues[q->q_id] = NULL;
	free(q);

}

void ublksrv_build_cpu_str(char *buf, int len, const cpu_set_t *cpuset)
{
	int nr_cores = sysconf(_SC_NPROCESSORS_ONLN);
	int i, offset = 0;

	for (i = 0; i < nr_cores; i++) {
		int n;

		if (!CPU_ISSET(i, cpuset))
			continue;
		n = snprintf(&buf[offset], len - offset, "%d ", i);
		if (n < 0 || n >= len - offset)
			break;
		offset += n;
	}
}

static void ublksrv_set_sched_affinity(struct _ublksrv_dev *dev,
		unsigned short q_id)
{
	const struct ublksrv_ctrl_dev *cdev = dev->ctrl_dev;
	unsigned dev_id = cdev->dev_info.dev_id;
	cpu_set_t *cpuset = ublksrv_get_queue_affinity(cdev, q_id);

	if (sched_setaffinity(0, sizeof(cpu_set_t), cpuset) < 0)
		ublk_err("ublk dev %u queue %u set affinity failed",
				dev_id, q_id);
}

static int ublksrv_prep_epoll_sqe(struct _ublksrv_queue *q)
{
	__u64 user_data = build_internal_data(UBLK_IO_OP_EPOLLFD);
	struct io_uring_sqe *sqe = ublksrv_alloc_sqe(&q->ring);

	if (!sqe) {
		ublk_err("%s: queue %d run out of sqe\n",
			 __func__, q->q_id);
		return -1;
	}

	io_uring_prep_poll_multishot(sqe, q->epollfd, POLLIN);
	io_uring_sqe_set_data64(sqe, user_data);
	return 0;
}

static int ublksrv_setup_epollfd(struct _ublksrv_queue *q)
{
	const struct ublksrv_ctrl_dev_info *info = &q->dev->ctrl_dev->dev_info;

	if (q->dev->tgt.tgt_ring_depth == 0) {
		ublk_err("ublk dev %d queue %d zero tgt queue depth",
			info->dev_id, q->q_id);
		return -EINVAL;
	}

	q->epollfd = epoll_create1(0);
	if (q->epollfd < 0)
		return -errno;

	return ublksrv_prep_epoll_sqe(q);
}

#define EPOLL_MAX_EVENTS 8
static void ublkdrv_process_epollfd(struct _ublksrv_queue *q, struct io_uring_cqe *cqe)
{
	struct epoll_event *e, events[EPOLL_MAX_EVENTS];
	int num_events;

	num_events = epoll_wait(q->epollfd, events, EPOLL_MAX_EVENTS, 0);
	e = events;
	while (num_events--) {
		struct epoll_cb_data *ecb = (struct epoll_cb_data *)e->data.u64;

		ecb->cb((struct ublksrv_queue *)q, e->events);
		e++;
	}

	if (cqe->flags & IORING_CQE_F_MORE)
		return;

	ublksrv_prep_epoll_sqe(q);
	io_uring_submit_and_wait(&q->ring, 0);
	return;
}

int ublksrv_epoll_mod_fd(struct ublksrv_queue *tq, int fd, int events)
{
	struct _ublksrv_queue *q = tq_to_local(tq);
	struct epoll_cb_data *ecd = q->epoll_callbacks;
	int ret = -1;

	pthread_spin_lock(&q->epoll_lock);
	while (ecd) {
		if (ecd->fd == fd) {
			struct epoll_event event;
			event.events = events;
			event.data.u64 = (uintptr_t)ecd;

			ret = epoll_ctl(q->epollfd, EPOLL_CTL_MOD, fd, &event);
			if (ret)
				ublk_err("Failed to add file descriptor to epoll\n");
			goto out;
		}
		ecd = ecd->next;
	}
 out:
	pthread_spin_unlock(&q->epoll_lock);
	return ret;
}

int ublksrv_epoll_add_fd(struct ublksrv_queue *tq, int fd, int events, epoll_cb cb)
{
	struct _ublksrv_queue *q = tq_to_local(tq);
	struct epoll_event event;
	struct epoll_cb_data *ecd;
	int ret = -1;

	pthread_spin_lock(&q->epoll_lock);
	if (q->epollfd == -1) {
		if (ublksrv_setup_epollfd(q) < 0) {
			ublk_err("ublk dev %d queue %d setup pollfd failed: %s",
				 q->dev->ctrl_dev->dev_info.dev_id, q->q_id,
				 strerror(-ret));
			goto out;
		}
	}

	ecd = calloc(1, sizeof(struct epoll_cb_data));
	if (!ecd) {
		ublk_err("failed to allocate epoll_cb_data\n");
		goto out;
	}
	ecd->fd           = fd;
	ecd->cb           = cb;
	ecd->next         = q->epoll_callbacks;
	q->epoll_callbacks = ecd;

	event.events = events;
	event.data.u64 = (uintptr_t)ecd;

	ret = epoll_ctl(q->epollfd, EPOLL_CTL_ADD, fd, &event);
	if (ret)
		ublk_err("Failed to add file descriptor to epoll\n");

 out:
	pthread_spin_unlock(&q->epoll_lock);
	return ret;
}

static void ublksrv_kill_eventfd(struct _ublksrv_queue *q)
{
	if ((q->state & UBLKSRV_QUEUE_STOPPING) && q->efd >= 0) {
		uint64_t data = 1;
		int ret;

		ret = write(q->efd, &data, sizeof(uint64_t));
		if (ret != sizeof(uint64_t))
			ublk_err("%s:%d write fail %d/%zu\n",
					__func__, __LINE__, ret, sizeof(uint64_t));
	}
}

/*
 * Return eventfs or negative errno
 */
static int ublksrv_setup_eventfd(struct _ublksrv_queue *q)
{
	const struct ublksrv_ctrl_dev_info *info = &q->dev->ctrl_dev->dev_info;

	if (!(info->ublksrv_flags & UBLKSRV_F_NEED_EVENTFD)) {
		q->efd = -1;
		return 0;
	}

	if (q->dev->tgt.tgt_ring_depth == 0) {
		ublk_err("ublk dev %d queue %d zero tgt queue depth",
			info->dev_id, q->q_id);
		return -EINVAL;
	}

	if (!q->dev->tgt.ops->handle_event) {
		ublk_err("ublk dev %d/%d not define ->handle_event",
			info->dev_id, q->q_id);
		return -EINVAL;
	}

	q->efd = eventfd(0, 0);
	if (q->efd < 0)
		return -errno;
	return 0;
}

static void ublksrv_queue_adjust_uring_io_wq_workers(struct _ublksrv_queue *q)
{
	struct _ublksrv_dev *dev = q->dev;
	unsigned int val[2] = {0, 0};
	int ret;

	if (!dev->tgt.iowq_max_workers[0] && !dev->tgt.iowq_max_workers[1])
		return;

	ret = io_uring_register_iowq_max_workers(&q->ring, val);
	if (ret)
		ublk_err("%s: register iowq max workers failed %d\n",
				__func__, ret);

	if (!dev->tgt.iowq_max_workers[0])
		dev->tgt.iowq_max_workers[0] = val[0];
	if (!dev->tgt.iowq_max_workers[1])
		dev->tgt.iowq_max_workers[1] = val[1];

	ret = io_uring_register_iowq_max_workers(&q->ring,
			dev->tgt.iowq_max_workers);
	if (ret)
		ublk_err("%s: register iowq max workers failed %d\n",
				__func__, ret);
}

static void ublksrv_calculate_depths(const struct _ublksrv_dev *dev, int
		*ring_depth, int *cq_depth, int *nr_ios)
{
	const struct ublksrv_ctrl_dev *cdev = dev->ctrl_dev;

	/*
	 * eventfd consumes one extra sqe, and it can be thought as one target
	 * depth
	 */
	int aio_depth = (cdev->dev_info.ublksrv_flags & UBLKSRV_F_NEED_EVENTFD)
		? 1 : 0;
	int depth = cdev->dev_info.queue_depth;
	int tgt_depth = dev->tgt.tgt_ring_depth + aio_depth;

	*nr_ios = depth + dev->tgt.extra_ios;

	/*
	 * queue_depth represents the max count of io commands issued from ublk driver.
	 *
	 * After io command is fetched from ublk driver, the consumed sqe for
	 * fetching io command has been available for target usage, so the uring
	 * depth can be set as the max(queue_depth, tgt_depth).
	 */
	depth = depth > tgt_depth ? depth : tgt_depth;
	*ring_depth = depth;
	*cq_depth = dev->cq_depth ? dev->cq_depth : depth;
}

const struct ublksrv_queue *ublksrv_queue_init_flags(const struct ublksrv_dev *tdev,
		unsigned short q_id, void *queue_data, int flags)
{
	struct io_uring_params p;
	struct _ublksrv_dev *dev = tdev_to_local(tdev);
	struct _ublksrv_queue *q;
	const struct ublksrv_ctrl_dev *ctrl_dev = dev->ctrl_dev;
	int depth = ctrl_dev->dev_info.queue_depth;
	int i, ret = -1;
	int cmd_buf_size, io_buf_size;
	unsigned long off;
	int io_data_size = round_up(dev->tgt.io_data_size,
			sizeof(unsigned long));
	int ring_depth, cq_depth, nr_ios;

	ublksrv_calculate_depths(dev, &ring_depth, &cq_depth, &nr_ios);

	/*
	 * Too many extra ios
	 */
	if (nr_ios > depth * 3)
		return NULL;

	q = (struct _ublksrv_queue *)malloc(sizeof(struct _ublksrv_queue) +
			sizeof(struct ublk_io) * nr_ios);
	dev->__queues[q_id] = q;

	q->epollfd = -1;
	q->epoll_callbacks = NULL;
	pthread_spin_init(&q->epoll_lock, PTHREAD_PROCESS_PRIVATE);

	q->tgt_ops = dev->tgt.ops;	//cache ops for fast path
	q->dev = dev;
	if (ctrl_dev->dev_info.flags & UBLK_F_CMD_IOCTL_ENCODE)
		q->state = UBLKSRV_QUEUE_IOCTL_OP;
	else
		q->state = 0;
	if (ctrl_dev->dev_info.flags & UBLK_F_USER_COPY)
		q->state |= UBLKSRV_USER_COPY;
	if (ctrl_dev->dev_info.flags & UBLK_F_SUPPORT_ZERO_COPY)
		q->state |= UBLKSRV_ZERO_COPY;
	if (ctrl_dev->dev_info.flags & UBLK_F_AUTO_BUF_REG)
		q->state |= UBLKSRV_AUTO_ZC;
	q->q_id = q_id;
	/* FIXME: depth has to be PO 2 */
	q->q_depth = depth;
	q->io_cmd_buf = NULL;
	q->cmd_inflight = 0;
	q->tid = ublksrv_gettid();

	cmd_buf_size = ublksrv_queue_cmd_buf_sz(q);
	off = UBLKSRV_CMD_BUF_OFFSET + q_id * queue_max_cmd_buf_sz();
	q->io_cmd_buf = mmap(0, cmd_buf_size, PROT_READ,
			MAP_SHARED | MAP_POPULATE, dev->cdev_fd, off);
	if (q->io_cmd_buf == MAP_FAILED) {
		ublk_err("ublk dev %d queue %d map io_cmd_buf failed",
				q->dev->ctrl_dev->dev_info.dev_id, q->q_id);
		goto fail;
	}

	io_buf_size = ctrl_dev->dev_info.max_io_buf_bytes;
	for (i = 0; i < nr_ios; i++) {
		q->ios[i].buf_addr = NULL;

		/* extra ios needn't to allocate io buffer */
		if (i >= q->q_depth)
			goto skip_alloc_buf;

		if (!ublksrv_queue_alloc_buf(q))
			goto skip_alloc_buf;

		if (dev->tgt.ops->alloc_io_buf)
			q->ios[i].buf_addr =
				dev->tgt.ops->alloc_io_buf(local_to_tq(q),
					i, io_buf_size);
		else
			if (posix_memalign((void **)&q->ios[i].buf_addr,
						getpagesize(), io_buf_size)) {
				ublk_err("ublk dev %d queue %d io %d posix_memalign failed",
						q->dev->ctrl_dev->dev_info.dev_id, q->q_id, i);
				goto fail;
			}
		//q->ios[i].buf_addr = malloc(io_buf_size);
		if (!q->ios[i].buf_addr) {
			ublk_err("ublk dev %d queue %d io %d alloc io_buf failed",
					q->dev->ctrl_dev->dev_info.dev_id, q->q_id, i);
			goto fail;
		}
skip_alloc_buf:
		q->ios[i].flags = UBLKSRV_NEED_FETCH_RQ | UBLKSRV_IO_FREE;
		q->ios[i].data.private_data = malloc(io_data_size);
		q->ios[i].data.tag = i;
		if (i < q->q_depth)
			q->ios[i].data.iod = ublksrv_get_iod(q, i);
		else
			q->ios[i].data.iod = NULL;

		//ublk_assert(io_data_size ^ (unsigned long)q->ios[i].data.private_data);
	}

	ublksrv_setup_ring_params(&p, cq_depth, flags);
	ret = io_uring_queue_init_params(ring_depth, &q->ring, &p);
	if (ret < 0) {
		ublk_err("ublk dev %d queue %d setup io_uring failed %d",
				q->dev->ctrl_dev->dev_info.dev_id, q->q_id, ret);
		goto fail;
	}

	q->ring_ptr = &q->ring;

	ret = io_uring_register_files(&q->ring, dev->tgt.fds,
			dev->tgt.nr_fds + 1);
	if (ret) {
		ublk_err("ublk dev %d queue %d register files failed %d",
				ctrl_dev->dev_info.dev_id, q->q_id, ret);
		goto fail;
	}

	if (ctrl_dev->dev_info.flags & (UBLK_F_SUPPORT_ZERO_COPY |
				UBLK_F_AUTO_BUF_REG)) {
		ret = io_uring_register_buffers_sparse(&q->ring, q->q_depth);
		if (ret) {
			ublk_err("ublk dev %d queue %d register spare buffers failed %d",
					ctrl_dev->dev_info.dev_id, q->q_id, ret);
			goto fail;
		}
	}

	io_uring_register_ring_fd(&q->ring);

	/*
	* N.B. PR_SET_IO_FLUSHER was added with Linux 5.6+.
	*/
#if defined(PR_SET_IO_FLUSHER)
	if (prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0) != 0)
		ublk_err("ublk dev %d queue %d set_io_flusher failed",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id);
#endif

	ublksrv_queue_adjust_uring_io_wq_workers(q);

	q->private_data = queue_data;

	if (ctrl_dev->tgt_ops->init_queue) {
		if (ctrl_dev->tgt_ops->init_queue(local_to_tq(q),
					&q->private_data))
			goto fail;
	}

	if (ctrl_dev->queues_cpuset)
		ublksrv_set_sched_affinity(dev, q_id);

	setpriority(PRIO_PROCESS, getpid(), -20);

	ret = ublksrv_setup_eventfd(q);
	if (ret < 0) {
		ublk_err("ublk dev %d queue %d setup eventfd failed: %s",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id,
			strerror(-ret));
		goto fail;
	}

	/* submit all io commands to ublk driver */
	ublksrv_submit_fetch_commands(q);

	return (struct ublksrv_queue *)q;
 fail:
	ublksrv_queue_deinit(local_to_tq(q));
	ublk_err("ublk dev %d queue %d failed",
			ctrl_dev->dev_info.dev_id, q_id);
	return NULL;
}

const struct ublksrv_queue *ublksrv_queue_init(const struct ublksrv_dev *tdev,
		unsigned short q_id, void *queue_data)
{
	return ublksrv_queue_init_flags(tdev, q_id, queue_data, IORING_SETUP_COOP_TASKRUN);
}

static int ublksrv_create_pid_file(struct _ublksrv_dev *dev)
{
	int dev_id = dev->ctrl_dev->dev_info.dev_id;
	char pid_file[64];
	int ret, pid_fd;

	if (!dev->ctrl_dev->run_dir)
		return 0;

	/* create pid file and lock it, so that others can't */
	snprintf(pid_file, 64, "%s/%d.pid", dev->ctrl_dev->run_dir, dev_id);

	ret = create_pid_file(pid_file, &pid_fd);
	if (ret < 0) {
		/* -1 means the file is locked, and we need to remove it */
		if (ret == -1) {
			close(pid_fd);
			unlink(pid_file);
		}
		return ret;
	}
	dev->pid_file_fd = pid_fd;
	return 0;
}

static void ublksrv_remove_pid_file(const struct _ublksrv_dev *dev)
{
	int dev_id = dev->ctrl_dev->dev_info.dev_id;
	char pid_file[64];

	if (!dev->ctrl_dev->run_dir)
		return;

	close(dev->pid_file_fd);
	snprintf(pid_file, 64, "%s/%d.pid", dev->ctrl_dev->run_dir, dev_id);
	unlink(pid_file);
}

void ublksrv_dev_deinit(const struct ublksrv_dev *tdev)
{
	struct _ublksrv_dev *dev = tdev_to_local(tdev);

	ublksrv_remove_pid_file(dev);

	ublksrv_tgt_deinit(dev);
	free(dev->thread);

	if (dev->cdev_fd >= 0) {
		close(dev->cdev_fd);
		dev->cdev_fd = -1;
	}
	free(dev);
}

const struct ublksrv_dev *ublksrv_dev_init(const struct ublksrv_ctrl_dev *ctrl_dev)
{
	int dev_id = ctrl_dev->dev_info.dev_id;
	char buf[64];
	int ret = -1;
	struct _ublksrv_dev *dev = (struct _ublksrv_dev *)calloc(1, sizeof(*dev));
	struct ublksrv_tgt_info *tgt;

	if (!dev)
		return local_to_tdev(dev);

	tgt = &dev->tgt;
	dev->ctrl_dev = ctrl_dev;
	dev->cdev_fd = -1;

	snprintf(buf, 64, "%s%d", UBLKC_DEV, dev_id);
	dev->cdev_fd = open(buf, O_RDWR | O_NONBLOCK);
	if (dev->cdev_fd < 0) {
		ublk_err("can't open %s, ret %d\n", buf, dev->cdev_fd);
		goto fail;
	}

	tgt->fds[0] = dev->cdev_fd;

	ret = ublksrv_tgt_init(dev, ctrl_dev->tgt_type, ctrl_dev->tgt_ops,
			ctrl_dev->tgt_argc, ctrl_dev->tgt_argv);
	if (ret) {
		ublk_err( "can't init tgt %d/%s/%d, ret %d\n",
				dev_id, ctrl_dev->tgt_type, ctrl_dev->tgt_argc,
				ret);
		goto fail;
	}

	ret = ublksrv_create_pid_file(dev);
	if (ret) {
		ublk_err( "can't create pid file for dev %d, ret %d\n",
				dev_id, ret);
		goto fail;
	}

	return local_to_tdev(dev);
fail:
	ublksrv_dev_deinit(local_to_tdev(dev));
	return NULL;
}

/* Be careful, target io may not have one ublk_io associated with  */
static inline void ublksrv_handle_tgt_cqe(struct _ublksrv_queue *q,
		struct io_uring_cqe *cqe)
{
	unsigned tag = user_data_to_tag(cqe->user_data);

	if (cqe->res < 0 && cqe->res != -EAGAIN) {
		ublk_err("%s: failed tgt io: res %d qid %u tag %u, cmd_op %u\n",
			__func__, cqe->res, q->q_id,
			user_data_to_tag(cqe->user_data),
			user_data_to_op(cqe->user_data));
	}

	if (is_internal_io(cqe->user_data)) {
		switch ((cqe->user_data >> 16) & 0xff) {
		case UBLK_IO_OP_EVENTFD:
			if (q->tgt_ops->handle_event)
				q->tgt_ops->handle_event(local_to_tq(q));
			return;
		case UBLK_IO_OP_EPOLLFD:
			ublkdrv_process_epollfd(q, cqe);
			return;
		}
	} else {
		if (q->tgt_ops->tgt_io_done)
			q->tgt_ops->tgt_io_done(local_to_tq(q),
					&q->ios[tag].data, cqe);
	}
}

static void ublksrv_handle_cqe(struct io_uring *r,
		struct io_uring_cqe *cqe, void *data)
{
	struct _ublksrv_queue *q = container_of(r, struct _ublksrv_queue, ring);
	unsigned tag = user_data_to_tag(cqe->user_data);
	unsigned cmd_op = user_data_to_op(cqe->user_data);
	int fetch = (cqe->res != UBLK_IO_RES_ABORT) &&
		!(q->state & UBLKSRV_QUEUE_STOPPING);
	struct ublk_io *io;

	ublk_dbg(UBLK_DBG_IO_CMD, "%s: res %d (qid %d tag %u cmd_op %u target %d/%x event %d) stopping %d\n",
			__func__, cqe->res, q->q_id, tag, cmd_op,
			is_target_io(cqe->user_data),
			user_data_to_tgt_data(cqe->user_data),
			is_internal_io(cqe->user_data),
			(q->state & UBLKSRV_QUEUE_STOPPING));

	/* Don't retrieve io in case of target io */
	if (is_target_io(cqe->user_data)) {
		ublksrv_handle_tgt_cqe(q, cqe);
		return;
	}

	io = &q->ios[tag];
	q->cmd_inflight--;

	if (!fetch) {
		q->state |= UBLKSRV_QUEUE_STOPPING;
		io->flags &= ~UBLKSRV_NEED_FETCH_RQ;
	}

	/*
	 * So far, only sync tgt's io handling is implemented.
	 *
	 * todo: support async tgt io handling via io_uring, and the ublksrv
	 * daemon can poll on both two rings.
	 */
	if (cqe->res == UBLK_IO_RES_OK) {
		//ublk_assert(tag < q->q_depth);
		q->tgt_ops->handle_io_async(local_to_tq(q), &io->data);
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

int ublksrv_queue_reap_events(const struct ublksrv_queue *tq)
{
	return ublksrv_reap_events_uring(&tq_to_local(tq)->ring);
}

static void ublksrv_queue_discard_io_pages(struct _ublksrv_queue *q)
{
	const struct ublksrv_ctrl_dev *cdev = q->dev->ctrl_dev;
	unsigned int io_buf_size = cdev->dev_info.max_io_buf_bytes;
	int i = 0;

	for (i = 0; i < q->q_depth; i++)
		madvise(q->ios[i].buf_addr, io_buf_size, MADV_DONTNEED);
}

static void ublksrv_queue_idle_enter(struct _ublksrv_queue *q)
{
	if (q->state & UBLKSRV_QUEUE_IDLE)
		return;

	ublk_dbg(UBLK_DBG_QUEUE, "dev%d-q%d: enter idle %x\n",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id, q->state);
	ublksrv_queue_discard_io_pages(q);
	q->state |= UBLKSRV_QUEUE_IDLE;

	if (q->tgt_ops->idle_fn)
		q->tgt_ops->idle_fn(local_to_tq(q), true);
}

static inline void ublksrv_queue_idle_exit(struct _ublksrv_queue *q)
{
	if (q->state & UBLKSRV_QUEUE_IDLE) {
		ublk_dbg(UBLK_DBG_QUEUE, "dev%d-q%d: exit idle %x\n",
			q->dev->ctrl_dev->dev_info.dev_id, q->q_id, q->state);
		q->state &= ~UBLKSRV_QUEUE_IDLE;
		if (q->tgt_ops->idle_fn)
			q->tgt_ops->idle_fn(local_to_tq(q), false);
	}
}

static void ublksrv_reset_aio_batch(struct _ublksrv_queue *q)
{
	q->nr_ctxs = 0;
}

static void ublksrv_submit_aio_batch(struct _ublksrv_queue *q)
{
	int i;

	for (i = 0; i < q->nr_ctxs; i++) {
		struct ublksrv_aio_ctx *ctx = q->ctxs[i];
		uint64_t data = 1;
		int ret;

		ret = write(ctx->efd, &data, sizeof(uint64_t));
		if (ret != sizeof(uint64_t))
			ublk_err("%s:%d write fail ctx[%d]: %d/%zu\n",
					__func__, __LINE__, i, ret, sizeof(uint64_t));
	}
}

int ublksrv_process_io(const struct ublksrv_queue *tq)
{
	struct _ublksrv_queue *q = tq_to_local(tq);
	int ret, reapped;
	struct __kernel_timespec ts = {
		.tv_sec = UBLKSRV_IO_IDLE_SECS,
		.tv_nsec = 0
        };
	struct __kernel_timespec *tsp = (q->state & UBLKSRV_QUEUE_IDLE) ?
		NULL : &ts;
	struct io_uring_cqe *cqe;

	ublk_dbg(UBLK_DBG_QUEUE, "dev%d-q%d: to_submit %d inflight %u/%u stopping %d\n",
				q->dev->ctrl_dev->dev_info.dev_id,
				q->q_id, io_uring_sq_ready(&q->ring),
				q->cmd_inflight, q->tgt_io_inflight,
				(q->state & UBLKSRV_QUEUE_STOPPING));

	if (__ublksrv_queue_is_done(q))
		return -ENODEV;

	ret = io_uring_submit_and_wait_timeout(&q->ring, &cqe, 1, tsp, NULL);

	ublksrv_reset_aio_batch(q);
	reapped = ublksrv_reap_events_uring(&q->ring);
	ublksrv_submit_aio_batch(q);

	if (q->tgt_ops->handle_io_background)
		q->tgt_ops->handle_io_background(local_to_tq(q),
				io_uring_sq_ready(&q->ring));

	ublk_dbg(UBLK_DBG_QUEUE, "submit result %d, reapped %d stop %d idle %d",
			ret, reapped, (q->state & UBLKSRV_QUEUE_STOPPING),
			(q->state & UBLKSRV_QUEUE_IDLE));

	if ((q->state & UBLKSRV_QUEUE_STOPPING))
		ublksrv_kill_eventfd(q);
	else {
		if (ret == -ETIME && reapped == 0 &&
				!io_uring_sq_ready(&q->ring))
			ublksrv_queue_idle_enter(q);
		else
			ublksrv_queue_idle_exit(q);
	}

	return reapped;
}

const struct ublksrv_queue *ublksrv_get_queue(const struct ublksrv_dev *dev,
		int q_id)
{
	return (const struct ublksrv_queue *)tdev_to_local(dev)->__queues[q_id];
}

/* called in ublksrv process context */
void ublksrv_apply_oom_protection()
{
	char oom_score_adj_path[64];
	pid_t pid = getpid();
	int fd;

	snprintf(oom_score_adj_path, 64, "/proc/%d/oom_score_adj", pid);

	fd = open(oom_score_adj_path, O_RDWR);
	if (fd > 0) {
		char val[32];
		int len, ret;

		len = snprintf(val, 32, "%d", -1000);
		ret = write(fd, val, len);
		if (ret != len)
			ublk_err("%s:%d write fail %d/%d\n",
					__func__, __LINE__, ret, len);
		close(fd);
	}
}

const struct ublksrv_ctrl_dev *ublksrv_get_ctrl_dev(
		const struct ublksrv_dev *dev)
{
	return tdev_to_local(dev)->ctrl_dev;
}

int ublksrv_get_pidfile_fd(const struct ublksrv_dev *dev)
{
	return tdev_to_local(dev)->pid_file_fd;
}

void *ublksrv_io_private_data(const struct ublksrv_queue *tq, int tag)
{
	struct _ublksrv_queue *q = tq_to_local(tq);

	return q->ios[tag].data.private_data;
}

unsigned int ublksrv_queue_state(const struct ublksrv_queue *q)
{
	return tq_to_local(q)->state;
}

const struct ublk_io_data *
ublksrv_queue_get_io_data(const struct ublksrv_queue *tq, int tag)
{
	struct _ublksrv_queue *q = tq_to_local(tq);

	return &q->ios[tag].data;
}

void *ublksrv_queue_get_io_buf(const struct ublksrv_queue *tq, int tag)
{
	struct _ublksrv_queue *q = tq_to_local(tq);

	if (tag < q->q_depth)
		return q->ios[tag].buf_addr;
	return NULL;
}

/*
 * The default io_uring cq depth equals to queue depth plus
 * .tgt_ring_depth, which is usually enough for typical ublk targets,
 * such as loop and qcow2, but it may not be enough for nbd with send_zc
 * which needs extra cqe for buffer notification.
 *
 * So add API to allow target to override default io_uring cq depth.
 */
void ublksrv_dev_set_cq_depth(struct ublksrv_dev *tdev, int cq_depth)
{
	tdev_to_local(tdev)->cq_depth = cq_depth;
}

int ublksrv_dev_get_cq_depth(struct ublksrv_dev *tdev)
{
	return tdev_to_local(tdev)->cq_depth;
}
