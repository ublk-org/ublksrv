// SPDX-License-Identifier: MIT or GPL-2.0-only

#if !defined(UBLKSRV_INTERNAL_H_)
#error "Never include <ublksrv_priv.h> directly; use <ublksrv.h> instead."
#endif

#ifndef UBLKSRV_PRIVATE_INC_H
#define UBLKSRV_PRIVATE_INC_H

#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/poll.h>

#include "ublk_cmd.h"
#include "ublksrv_utils.h"
#include "ublksrv.h"
#include "ublksrv_aio.h"


/* todo: relace the hardcode name with /dev/char/maj:min */
#ifdef UBLKC_PREFIX
#define	UBLKC_DEV	UBLKC_PREFIX "/ublkc"
#else
#define	UBLKC_DEV	"/dev/ublkc"
#endif
#define UBLKC_PATH_MAX	32

#ifdef __cplusplus
extern "C" {
#endif

struct ublksrv_tgt_jbuf {
	pthread_mutex_t lock;
	int jbuf_size;
	char *jbuf;
};

struct ublksrv_ctrl_data {
	struct ublksrv_tgt_jbuf jbuf;
	bool recover;
};

struct ublksrv_ctrl_dev {
	struct io_uring ring;

	int ctrl_fd;
	unsigned bs_shift;
	struct ublksrv_ctrl_dev_info  dev_info;
	struct ublksrv_ctrl_data *data;

	const char *tgt_type;
	const struct ublksrv_tgt_type *tgt_ops;

	/*
	 * default is UBLKSRV_RUN_DIR but can be specified via command line,
	 * pid file will be saved there
	 */
	const char *run_dir;

	union {
		/* used by ->init_tgt() */
		struct {
			int tgt_argc;
			char **tgt_argv;
		};
		/* used by ->recovery_tgt(), tgt_argc == -1 */
		struct {
			int padding;
			const char *recovery_jbuf;
		};
	};

	cpu_set_t *queues_cpuset;

	void *private_data;
	unsigned long reserved[3];
};

struct ublk_io {
	char *buf_addr;

#define UBLKSRV_NEED_FETCH_RQ		(1UL << 0)
#define UBLKSRV_NEED_COMMIT_RQ_COMP	(1UL << 1)
#define UBLKSRV_IO_FREE			(1UL << 2)
#define UBLKSRV_NEED_GET_DATA		(1UL << 3)
	unsigned int flags;

	/* result is updated after all target ios are done */
	unsigned int result;

	struct ublk_io_data  data;
};

struct epoll_cb_data {
	struct epoll_cb_data *next;
	int fd;
	epoll_cb cb;
};

struct _ublksrv_queue {
	/********** part of API, can't change ************/
	int q_id;
	int q_depth;

	struct io_uring *ring_ptr;
	struct _ublksrv_dev *dev;
	void *private_data;
	/*************************************************/

	/*
	 * Read only by ublksrv daemon, setup via mmap on /dev/ublkcN.
	 *
	 * ublksrv_io_desc(iod) is stored in this buffer, so iod
	 * can be retrieved by request's tag directly.
	 * 
	 * ublksrv writes the iod into this array, and notify ublksrv daemon
	 * by issued io_uring command beforehand.
	 * */
	struct ublksrv_io_desc *io_cmd_buf;
	char *io_buf;

	unsigned cmd_inflight, tgt_io_inflight;	//obsolete
	unsigned state;

	int epollfd;
	struct epoll_cb_data *epoll_callbacks;
	pthread_spinlock_t epoll_lock;

	/* eventfd */
	int efd;

	/* cache tgt ops */
	const struct ublksrv_tgt_type *tgt_ops;

	/*
	 * ring for submit io command to ublk driver, can only be issued
	 * from ublksrv daemon.
	 *
	 * ring depth == dev_info->queue_depth.
	 */
	struct io_uring ring;

	unsigned  tid;

#define UBLKSRV_NR_CTX_BATCH 4
	int nr_ctxs;
	struct ublksrv_aio_ctx *ctxs[UBLKSRV_NR_CTX_BATCH];

	unsigned long reserved[8];

	struct ublk_io ios[0];
};

struct _ublksrv_dev {
	//keep same with ublksrv_dev
	/********** part of API, can't change ************/
	struct ublksrv_tgt_info tgt;
	/************************************************/

	struct _ublksrv_queue *__queues[MAX_NR_HW_QUEUES];
	char	*io_buf_start;
	pthread_t *thread;
	int cdev_fd;
	int pid_file_fd;

	const struct ublksrv_ctrl_dev *ctrl_dev;
	void	*target_data;
	int	cq_depth;
	int	pad;

	/* reserved isn't necessary any more */
	unsigned long reserved[3];
};

#define local_to_tq(q)	((struct ublksrv_queue *)(q))
#define tq_to_local(q)	((struct _ublksrv_queue *)(q))

#define local_to_tdev(d)	((struct ublksrv_dev *)(d))
#define tdev_to_local(d)	((struct _ublksrv_dev *)(d))

struct ublksrv_tgt_jbuf *ublksrv_tgt_get_jbuf(const struct ublksrv_ctrl_dev *cdev);

static inline struct ublksrv_ctrl_data *ublksrv_get_ctrl_data(const struct ublksrv_ctrl_dev *cdev)
{
	return cdev->data;
}

static inline bool ublk_is_unprivileged(const struct ublksrv_ctrl_dev *ctrl_dev)
{
	return !!(ctrl_dev->dev_info.flags & UBLK_F_UNPRIVILEGED_DEV);
}

static inline cpu_set_t *ublksrv_get_queue_affinity(
		const struct ublksrv_ctrl_dev *dev, int qid)
{
	unsigned char *buf = (unsigned char *)&dev->queues_cpuset[qid];

	if (ublk_is_unprivileged(dev))
		return (cpu_set_t *)&buf[UBLKC_PATH_MAX];

	return &dev->queues_cpuset[qid];
}

static inline void ublksrv_mark_io_done(struct ublk_io *io, int res)
{
	/*
	 * mark io done by target, so that ->ubq_daemon can commit its
	 * result and fetch new request via io_uring command.
	 */
	io->flags |= (UBLKSRV_NEED_COMMIT_RQ_COMP | UBLKSRV_IO_FREE);

	io->result = res;
}

static inline struct io_uring_sqe *ublksrv_alloc_sqe(struct io_uring *r)
{
	unsigned left = io_uring_sq_space_left(r);

	if (left < 1)
		io_uring_submit(r);
	return io_uring_get_sqe(r);
}

int create_pid_file(const char *pid_file, int *pid_fd);

extern void ublksrv_build_cpu_str(char *buf, int len, const cpu_set_t *cpuset);

/*
 * bit63: target io, bit62: internal data.
 *
 * Internal data is a flag to indicate that this is a SQE used for
 * internal purposes in ublksrv. I.e. eventfd or epollfd management.
 */
static inline __u64 build_internal_data(unsigned op)
{
	assert(!(op >> 8));

	return (op << 16) | (0x3ULL << 62);
}

static inline int is_internal_io(__u64 user_data)
{
	return (user_data & (1ULL << 62)) != 0;
}

static inline int is_target_io(__u64 user_data)
{
	return (user_data & (1ULL << 63)) != 0;
}

static inline void ublksrv_setup_ring_params(struct io_uring_params *p,
		int cq_depth, unsigned flags)
{
	memset(p, 0, sizeof(*p));
	p->flags = flags | IORING_SETUP_CQSIZE;
	p->cq_entries = cq_depth;
}

static inline struct io_uring_sqe *ublksrv_uring_get_sqe(struct io_uring *r,
		int idx, bool is_sqe128)
{
	if (is_sqe128)
		return  &r->sq.sqes[idx << 1];
	return  &r->sq.sqes[idx];
}

static inline void *ublksrv_get_sqe_cmd(struct io_uring_sqe *sqe)
{
	return (void *)&sqe->addr3;
}

static inline void ublksrv_set_sqe_cmd_op(struct io_uring_sqe *sqe, __u32 cmd_op)
{
	__u32 *addr = (__u32 *)&sqe->off;

	addr[0] = cmd_op;
	addr[1] = 0;
}

/*
 * ublksrv_aio_ctx is used to offload IO handling from ublksrv io_uring
 * context.
 *
 * ublksrv_aio_ctx is bound with one single pthread which has to belong
 * to same process of the io_uring where IO is originated, so we can
 * support to handle IO from multiple queues of the same device. At
 * default, ublksrv_aio_ctx supports to handle device wide aio or io
 * offloading except for UBLKSRV_AIO_QUEUE_WIDE.
 *
 * Meantime ublksrv_aio_ctx can be created per each queue, and only handle
 * IOs from this queue.
 *
 * The final io handling in the aio context depends on user's implementation,
 * either sync or async IO submitting is supported.
 */
struct ublksrv_aio_ctx {
	struct ublksrv_aio_list submit;

	/* per-queue completion list */
	struct ublksrv_aio_list *complete;

	int efd;		//for wakeup us

#define UBLKSRV_AIO_QUEUE_WIDE	(1U << 0)
	unsigned int		flags;
	bool dead;

	const struct ublksrv_dev *dev;

	void *ctx_data;

	unsigned long reserved[8];
};

#define UBLK_TGT_MAX_JBUF_SZ 8192

static inline bool tgt_realloc_jbuf(struct ublksrv_tgt_jbuf *j)
{
	if (j->jbuf == NULL)
		j->jbuf_size = 512;
	else
		j->jbuf_size += 512;

	if (j->jbuf_size < UBLK_TGT_MAX_JBUF_SZ) {
		j->jbuf = (char *)realloc((void *)j->jbuf, j->jbuf_size);
		return true;
	}
	return false;
}

static inline void ublksrv_tgt_jbuf_init(struct ublksrv_ctrl_dev *cdev,
		struct ublksrv_tgt_jbuf *j, bool recover)
{
	pthread_mutex_init(&j->lock, NULL);
	if (recover) {
		j->jbuf = ublksrv_tgt_get_dev_data(cdev);
		if (j->jbuf)
			j->jbuf_size = ublksrv_json_get_length(j->jbuf);
	} else {
		j->jbuf = NULL;
		j->jbuf_size = 0;
		tgt_realloc_jbuf(j);
	}
}

static inline void ublksrv_tgt_jbuf_exit(struct ublksrv_tgt_jbuf *jbuf)
{
	free(jbuf->jbuf);
}


#ifdef __cplusplus
}
#endif

#endif
