// SPDX-License-Identifier: MIT or GPL-2.0-only

#ifndef UBLKSRV_PRIVATE_INC_H
#define UBLKSRV_PRIVATE_INC_H

#include <poll.h>

#include "ublksrv.h"

#ifdef __cplusplus
extern "C" {
#endif

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

static inline struct ublksrv_queue *ublksrv_get_queue(const struct ublksrv_dev *dev,
		int q_id)
{
	return dev->__queues[q_id];
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

	*addr = cmd_op;
}

#ifdef DEBUG
static inline void ublksrv_log(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
}

static inline void ublksrv_printf(FILE *stream, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stream, fmt, ap);
}
#else
static inline void ublksrv_log(int priority, const char *fmt, ...) { }
static inline void ublksrv_printf(FILE *stream, const char *fmt, ...) {}
#endif

static inline unsigned ilog2(unsigned x)
{
    return sizeof(unsigned) * 8 - 1 - __builtin_clz(x);
}

#define round_up(val, rnd) \
	(((val) + (rnd - 1)) & ~(rnd - 1))

#ifndef offsetof
#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)
#endif
#define container_of(ptr, type, member) ({                              \
	unsigned long __mptr = (unsigned long)(ptr);                    \
	((type *)(__mptr - offsetof(type, member))); })

#ifdef __cplusplus
}
#endif

#endif
