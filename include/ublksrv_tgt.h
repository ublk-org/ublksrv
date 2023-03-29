// SPDX-License-Identifier: MIT or GPL-2.0-only

#ifndef UBLKSRV_TGT_INC_H
#define UBLKSRV_TGT_INC_H

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <libgen.h>
#include <coroutine>
#include <iostream>
#include <type_traits>

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
#define UBLKSRV_PID_DIR  "/tmp/ublksrvd"

/* json device data is stored at this offset of pid file */
#define JSON_OFFSET   32

char *ublksrv_tgt_return_json_buf(struct ublksrv_dev *dev, int *size);
char *ublksrv_tgt_realloc_json_buf(struct ublksrv_dev *dev, int *size);

static inline unsigned ublksrv_convert_cmd_op(const struct ublksrv_io_desc *iod)
{
	unsigned ublk_op = ublksrv_get_op(iod);

	switch (ublk_op) {
	case UBLK_IO_OP_READ:
		return IORING_OP_READ;
	case UBLK_IO_OP_WRITE:
		return IORING_OP_WRITE;
	case UBLK_IO_OP_FLUSH:
		return IORING_OP_FSYNC;
	case UBLK_IO_OP_DISCARD:
	case UBLK_IO_OP_WRITE_SAME:
	case UBLK_IO_OP_WRITE_ZEROES:
		return IORING_OP_FALLOCATE;
	default:
		return -1;
	}
}

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
	/* evaluate communication cost, ublksrv_null vs /dev/nullb0 */
	UBLKSRV_TGT_TYPE_NULL,

	/* ublksrv_loop vs. /dev/loop */
	UBLKSRV_TGT_TYPE_LOOP,

	UBLKSRV_TGT_TYPE_QCOW2,

	UBLKSRV_TGT_TYPE_NBD,

	UBLKSRV_TGT_TYPE_MAX = 256,
};
extern int ublksrv_register_tgt_type(struct ublksrv_tgt_type *type);
extern void ublksrv_unregister_tgt_type(struct ublksrv_tgt_type *type);

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
	if (p->basic.logical_bs_shift < 9 || p->basic.physical_bs_shift > 12)
		return false;
	if (p->basic.logical_bs_shift > p->basic.physical_bs_shift)
		return false;
	return true;
}

int ublk_json_write_tgt_str(struct ublksrv_dev *dev, char **jbuf,
		int *len, const char *name, const char *val);
int ublk_json_write_tgt_long(struct ublksrv_dev *dev, char **jbuf,
		int *len, const char *name, long val);
int ublk_json_write_tgt_ulong(struct ublksrv_dev *dev, char **jbuf,
		int *len, const char *name, unsigned long val);
int ublk_json_write_dev_info(struct ublksrv_dev *dev, char **jbuf, int *len);
int ublk_json_write_params(struct ublksrv_dev *dev, char **jbuf, int *len,
		const struct ublk_params *p);
int ublk_json_write_target_base(struct ublksrv_dev *dev, char **jbuf, int *len,
		const struct ublksrv_tgt_base_json *tgt);

static inline void ublk_get_sqe_pair(struct io_uring *r,
		struct io_uring_sqe **sqe, struct io_uring_sqe **sqe2)
{
	unsigned left = io_uring_sq_space_left(r);

	if (left < 2)
		io_uring_submit(r);
	*sqe = io_uring_get_sqe(r);
	if (sqe2)
		*sqe2 = io_uring_get_sqe(r);
}

#endif
