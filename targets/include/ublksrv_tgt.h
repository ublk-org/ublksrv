// SPDX-License-Identifier: MIT or GPL-2.0-only

#ifndef UBLKSRV_TGT_INC_H
#define UBLKSRV_TGT_INC_H

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <libgen.h>
#include <coroutine>
#include <iostream>
#include <type_traits>
#include <sched.h>

#include "ublksrv_utils.h"
#include "ublksrv.h"

#define ublk_assert(x)  do { \
	if (!(x)) {	\
		ublk_err("%s %d: assert!\n", __func__, __LINE__); \
		assert(x);	\
	}	\
} while (0)

static inline unsigned ilog2(unsigned x)
{
    return sizeof(unsigned) * 8 - 1 - __builtin_clz(x);
}

#define MAX_NR_UBLK_DEVS	128

/*
 * Our convention is to use this macro instead of raw `co_await` to make it
 * easy to log `tag` when debugging coroutine issues.
 */
#define co_await__suspend_always(tag) {                                       \
	static_assert(std::is_same<decltype(tag), int>::value, "tag not int");\
	co_await std::suspend_always();                                       \
}

using co_handle_type = std::coroutine_handle<>;
struct co_io_job {
    struct promise_type {
        co_io_job get_return_object() {
            return {std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_never initial_suspend() {
            return {};
        }
        std::suspend_never final_suspend() noexcept {
            return {};
        }
        void return_void() {}
        void unhandled_exception() {}
    };

    co_handle_type coro;

    co_io_job(co_handle_type h): coro(h) {}

    operator co_handle_type() const { return coro; }
};

struct ublk_io_tgt {
	co_handle_type co;
	const struct io_uring_cqe *tgt_io_cqe;
	int queued_tgt_io;	/* obsolete */
};

/* don't overlap with _IO_NR(UBLK_U_IO_*) and UBLK_IO_OP_* */
#define  UBLK_USER_COPY_READ 	0x80
#define  UBLK_USER_COPY_WRITE   0x81

static inline struct ublk_io_tgt *__ublk_get_io_tgt_data(const struct ublk_io_data *io)
{
	return (struct ublk_io_tgt *)io->private_data;
}

static inline struct ublk_io_tgt *ublk_get_io_tgt_data(
		const struct ublksrv_queue *q, int tag)
{
	return (struct ublk_io_tgt *)ublksrv_io_private_data(q, tag);
}

static inline void ublksrv_tgt_set_io_data_size(struct ublksrv_tgt_info *tgt)
{
	tgt->io_data_size = sizeof(struct ublk_io_tgt);
}

//static_assert(sizeof(struct ublk_io_tgt) == sizeof(struct ublk_io), "ublk_io is defined as wrong");

enum {
	UBLK_UNIQUE_TAG_BITS = 16,
	UBLK_UNIQUE_TAG_MASK = (1 << UBLK_UNIQUE_TAG_BITS) - 1,
};

static inline unsigned int ublk_unique_tag(unsigned short hwq,
		unsigned short tag)
{
	return (hwq << UBLK_UNIQUE_TAG_BITS) | (tag & UBLK_UNIQUE_TAG_MASK);
}

static inline unsigned short ublk_unique_tag_to_hwq(unsigned int unique_tag)
{
        return unique_tag >> UBLK_UNIQUE_TAG_BITS;
}

static inline unsigned short ublk_unique_tag_to_tag(unsigned int unique_tag)
{
        return unique_tag & UBLK_UNIQUE_TAG_MASK;
}

static inline bool ublk_param_is_valid(const struct ublk_params *p)
{
	if (p->basic.logical_bs_shift < 9 || p->basic.logical_bs_shift > 12)
		return false;
	if (p->basic.logical_bs_shift > p->basic.physical_bs_shift)
		return false;
	return true;
}

static inline int ublk_queue_alloc_sqes(const struct ublksrv_queue *q,
		struct io_uring_sqe *sqes[], int nr_sqes)
{
	struct io_uring *r = q->ring_ptr;
	int i;

	if (io_uring_sq_space_left(r) < (unsigned)nr_sqes)
		io_uring_submit(r);

	for (i = 0; i < nr_sqes; i++) {
		sqes[i] = io_uring_get_sqe(r);
		if (!sqes[i])
			return i;
	}

	return nr_sqes;
}

static inline enum io_uring_op ublk_to_uring_fs_op(
		const struct ublksrv_io_desc *iod, bool zc)
{
	unsigned ublk_op = ublksrv_get_op(iod);

	if (ublk_op == UBLK_IO_OP_READ)
		return zc ? IORING_OP_READ_FIXED : IORING_OP_READ;
	else if (ublk_op == UBLK_IO_OP_WRITE)
		return zc ? IORING_OP_WRITE_FIXED : IORING_OP_WRITE;
	assert(0);
}

int ublksrv_main(const struct ublksrv_tgt_type *tgt_type, int argc, char *argv[]);

static inline unsigned short ublk_cmd_op_nr(unsigned int op)
{
	return _IOC_NR(op);
}

/* if the OP is in the space of UBLK_IO_OP_* */
static inline int is_ublk_io_cmd(unsigned int op)
{
	return op < UBLK_IO_FETCH_REQ;
}

/* called after one cqe is received */
static inline int ublksrv_tgt_process_cqe(const struct ublk_io_tgt *io, int *io_res)
{
	const struct io_uring_cqe *cqe = io->tgt_io_cqe;

	assert(cqe);
	if (is_ublk_io_cmd(user_data_to_op(cqe->user_data)))
		*io_res = cqe->res;
	return cqe->res;
}

static inline void ublksrv_tgt_io_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	int tag = user_data_to_tag(cqe->user_data);
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	ublk_assert(tag == data->tag);
	io->tgt_io_cqe = cqe;
	io->co.resume();
}

static inline void __set_sqe_cmd_op(struct io_uring_sqe *sqe, __u32 cmd_op)
{
	__u32 *addr = (__u32 *)&sqe->off;

	addr[0] = cmd_op;
	addr[1] = 0;
}

static inline struct ublksrv_io_cmd *__get_sqe_cmd(struct io_uring_sqe *sqe)
{
	return (struct ublksrv_io_cmd *)&sqe->addr3;
}

static inline void io_uring_prep_buf_register(struct io_uring_sqe *sqe,
		int dev_fd, int tag, int q_id, __u64 index)
{
	struct ublksrv_io_cmd *cmd = __get_sqe_cmd(sqe);

	io_uring_prep_read(sqe, dev_fd, 0, 0, 0);
	sqe->opcode		= IORING_OP_URING_CMD;
	sqe->flags 		= 0;
	__set_sqe_cmd_op(sqe, UBLK_U_IO_REGISTER_IO_BUF);

	cmd->tag		= tag;
	cmd->addr		= index;
	cmd->q_id		= q_id;
}

static inline void io_uring_prep_buf_unregister(struct io_uring_sqe *sqe,
		int dev_fd, int tag, int q_id, __u64 index)
{
	struct ublksrv_io_cmd *cmd = __get_sqe_cmd(sqe);

	io_uring_prep_read(sqe, dev_fd, 0, 0, 0);
	sqe->opcode		= IORING_OP_URING_CMD;
	sqe->flags 		= 0;
	__set_sqe_cmd_op(sqe, UBLK_U_IO_UNREGISTER_IO_BUF);

	cmd->tag		= tag;
	cmd->addr		= index;
	cmd->q_id		= q_id;
}

static inline bool ublksrv_tgt_queue_zc(const struct ublksrv_queue *q)
{
	return ublksrv_queue_state(q) & UBLKSRV_ZERO_COPY;
}

static inline bool ublksrv_tgt_queue_auto_zc(const struct ublksrv_queue *q)
{
	return ublksrv_queue_state(q) & UBLKSRV_AUTO_ZC;
}

#endif
