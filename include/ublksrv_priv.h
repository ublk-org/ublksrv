// SPDX-License-Identifier: MIT or GPL-2.0-only

#ifndef UBLKSRV_PRIVATE_INC_H
#define UBLKSRV_PRIVATE_INC_H

#include <poll.h>

#include "ublksrv.h"

#ifdef __cplusplus
extern "C" {
#endif

#define local_to_tq(q)	((struct ublksrv_queue *)(q))
#define tq_to_local(q)	((struct _ublksrv_queue *)(q))

#define local_to_tdev(d)	((struct ublksrv_dev *)(d))
#define tdev_to_local(d)	((struct _ublksrv_dev *)(d))

int create_pid_file(const char *pid_file, int *pid_fd);

extern void ublksrv_build_cpu_str(char *buf, int len, const cpu_set_t *cpuset);

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

static inline int is_target_io(__u64 user_data)
{
	return (user_data & (1ULL << 63)) != 0;
}

/* bit63: target io, bit62: eventfd data */
static inline __u64 build_eventfd_data()
{
	return 0x3ULL << 62;
}

static inline int is_eventfd_io(__u64 user_data)
{
	return (user_data & (1ULL << 62)) != 0;
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
