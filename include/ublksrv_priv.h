// SPDX-License-Identifier: MIT or GPL-2.0-only

#if !defined(UBLKSRV_INTERNAL_H_)
#error "Never include <ublksrv_priv.h> directly; use <ublksrv.h> instead."
#endif

#ifndef UBLKSRV_PRIVATE_INC_H
#define UBLKSRV_PRIVATE_INC_H

#include "ublk_cmd.h"
#include "ublksrv.h"
#include "liburing.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ublksrv_ctrl_dev {
	struct io_uring ring;

	int ctrl_fd;
	unsigned bs_shift;
	struct ublksrv_ctrl_dev_info  dev_info;

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
		/* used by ->recovery_tgt() */
		const char *recovery_jbuf;
	};

	cpu_set_t *queues_cpuset;

	unsigned long reserved[4];
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

struct _ublksrv_queue {
	int q_id;
	int q_depth;

	struct io_uring *ring_ptr;
	struct _ublksrv_dev *dev;
	void *private_data;

	/*
	 * Read only by ublksrv daemon, setup via mmap on /dev/ublkcN.
	 *
	 * ublksrv_io_desc(iod) is stored in this buffer, so iod
	 * can be retrieved by request's tag directly.
	 * 
	 * ublksrv writes the iod into this array, and notify ublksrv daemon
	 * by issued io_uring command beforehand.
	 * */
	char *io_cmd_buf;
	char *io_buf;

	unsigned cmd_inflight, tgt_io_inflight;	//obsolete
	unsigned state;

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
	struct ublksrv_tgt_info tgt;

	struct _ublksrv_queue *__queues[MAX_NR_HW_QUEUES];
	char	*io_buf_start;
	pthread_t *thread;
	int cdev_fd;
	int pid_file_fd;

	const struct ublksrv_ctrl_dev *ctrl_dev;
	void	*target_data;

	unsigned long reserved[4];
};

#define local_to_tq(q)	((struct ublksrv_queue *)(q))
#define tq_to_local(q)	((struct _ublksrv_queue *)(q))

#define local_to_tdev(d)	((struct ublksrv_dev *)(d))
#define tdev_to_local(d)	((struct _ublksrv_dev *)(d))

static inline void ublksrv_mark_io_done(struct ublk_io *io, int res)
{
	/*
	 * mark io done by target, so that ->ubq_daemon can commit its
	 * result and fetch new request via io_uring command.
	 */
	io->flags |= (UBLKSRV_NEED_COMMIT_RQ_COMP | UBLKSRV_IO_FREE);

	io->result = res;
}

static inline bool ublksrv_io_done(struct ublk_io *io)
{
	return io->flags & UBLKSRV_IO_FREE;
}

int create_pid_file(const char *pid_file, int *pid_fd);

extern void ublksrv_build_cpu_str(char *buf, int len, const cpu_set_t *cpuset);

/* bit63: target io, bit62: eventfd data */
static inline __u64 build_eventfd_data()
{
	return 0x3ULL << 62;
}

static inline int is_eventfd_io(__u64 user_data)
{
	return (user_data & (1ULL << 62)) != 0;
}

static inline int is_target_io(__u64 user_data)
{
	return (user_data & (1ULL << 63)) != 0;
}

/* two helpers for setting up io_uring */
static inline int ublksrv_setup_ring(int depth, struct io_uring *r,
		unsigned flags)
{
	struct io_uring_params p;

	memset(&p, 0, sizeof(p));
        p.flags = flags | IORING_SETUP_CQSIZE;
        p.cq_entries = depth;

        return io_uring_queue_init_params(depth, r, &p);
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

#ifdef __cplusplus
}
#endif

#endif
