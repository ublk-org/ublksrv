#ifndef UBDSRV_TGT_INC_H
#define UBDSRV_TGT_INC_H

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <inttypes.h>
#include <math.h>
#include <getopt.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <syslog.h>
#include <signal.h>

struct ubdsrv_ctrl_dev;
struct ubdsrv_dev;
struct ubdsrv_queue;
struct ubd_io;
struct ubdsrv_tgt_info;

#define  UBDSRV_TGT_MAX_FDS	8

enum {
	/* evaluate communication cost, ubdsrv_null vs /dev/nullb0 */
	UBDSRV_TGT_TYPE_NULL,

	/* ubdsrv_loop vs. /dev/loop */
	UBDSRV_TGT_TYPE_LOOP,

	UBDSRV_TGT_TYPE_MAX,
};

struct ubdsrv_tgt_info_loop {
	char backing_file[1024];
};

struct ubdsrv_tgt_info_null {
	int data;
};

struct ubdsrv_tgt_type {
	int  type;
	const char *name;
	int (*init_tgt)(struct ubdsrv_tgt_info *, int type, int argc,
			char *argv[]);
	/*
	 * c++20 coroutine is stackless, and can't be nested, so any
	 * functions called from ->handle_io_async can't be defined as
	 * coroutine, and please keep it in mind.
	 */
	co_io_job (*handle_io_async)(struct ubdsrv_queue *, int tag);

	void (*tgt_io_done)(struct ubdsrv_queue *, struct io_uring_cqe *);

	/*
	 * Called in daemon task context, and before starting per-queue
	 * thread.
	 *
	 * Usually, tgt code can setup output for list command; meantime
	 * prepare for handling io, or all kinds of things.
	 */
	int (*prepare_target)(struct ubdsrv_tgt_info *, struct ubdsrv_dev *);

	void (*usage_for_add)(void);

	void (*deinit_tgt)(struct ubdsrv_tgt_info *, struct ubdsrv_dev *);
};

struct ubdsrv_tgt_info {
	unsigned long long dev_size;
	unsigned int tgt_ring_depth;	/* at most in-flight ios */
	unsigned int nr_fds;
	int fds[UBDSRV_TGT_MAX_FDS];
	union {
		struct ubdsrv_tgt_info_loop loop;
		struct ubdsrv_tgt_info_null null;
	};
	const struct ubdsrv_tgt_type *ops;
};

static inline unsigned ubdsrv_convert_cmd_op(const struct ubdsrv_io_desc *iod)
{
	unsigned ubd_op = ubdsrv_get_op(iod);

	switch (ubd_op) {
	case UBD_IO_OP_READ:
		return IORING_OP_READ;
	case UBD_IO_OP_WRITE:
		return IORING_OP_WRITE;
	case UBD_IO_OP_FLUSH:
		return IORING_OP_FSYNC;
	case UBD_IO_OP_DISCARD:
	case UBD_IO_OP_WRITE_SAME:
	case UBD_IO_OP_WRITE_ZEROES:
		return IORING_OP_FALLOCATE;
	default:
		return -1;
	}
}

int ubdsrv_tgt_init(struct ubdsrv_tgt_info *tgt, char *type,
		int argc, char *argv[]);
int ubdsrv_register_tgt_type(struct ubdsrv_tgt_type *type);
int ubdsrv_prepare_target(struct ubdsrv_tgt_info *tgt, struct ubdsrv_dev *dev);
void ubdsrv_for_each_tgt_type(void (*handle_tgt_type)(unsigned idx,
			const struct ubdsrv_tgt_type *type, void *data),
		void *data);
void ubdsrv_tgt_deinit(struct ubdsrv_tgt_info *tgt, struct ubdsrv_dev *dev);

#endif
