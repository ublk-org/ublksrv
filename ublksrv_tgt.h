#ifndef UBLKSRV_TGT_INC_H
#define UBLKSRV_TGT_INC_H

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

struct ublksrv_ctrl_dev;
struct ublksrv_dev;
struct ublksrv_queue;
struct ublk_io;
struct ublksrv_tgt_info;

#define  UBLKSRV_TGT_MAX_FDS	8

enum {
	/* evaluate communication cost, ublksrv_null vs /dev/nullb0 */
	UBLKSRV_TGT_TYPE_NULL,

	/* ublksrv_loop vs. /dev/loop */
	UBLKSRV_TGT_TYPE_LOOP,

	UBLKSRV_TGT_TYPE_MAX,
};

struct ublksrv_tgt_type {
	int  type;
	const char *name;
	int (*init_tgt)(struct ublksrv_tgt_info *, int type, int argc,
			char *argv[]);
	/*
	 * c++20 coroutine is stackless, and can't be nested, so any
	 * functions called from ->handle_io_async can't be defined as
	 * coroutine, and please keep it in mind.
	 */
	int (*handle_io_async)(struct ublksrv_queue *, int tag);

	void (*tgt_io_done)(struct ublksrv_queue *, struct io_uring_cqe *);

	/*
	 * Called in daemon task context, and before starting per-queue
	 * thread.
	 *
	 * Usually, tgt code can setup output for list command; meantime
	 * prepare for handling io, or all kinds of things.
	 */
	int (*prepare_target)(struct ublksrv_tgt_info *, struct ublksrv_dev *);

	void (*usage_for_add)(void);

	void (*deinit_tgt)(struct ublksrv_tgt_info *, struct ublksrv_dev *);
};

struct ublksrv_tgt_info {
	unsigned long long dev_size;
	unsigned int tgt_ring_depth;	/* at most in-flight ios */
	unsigned int nr_fds;
	int fds[UBLKSRV_TGT_MAX_FDS];
	void *tgt_data;
	const struct ublksrv_tgt_type *ops;
};

int ublksrv_tgt_init(struct ublksrv_tgt_info *tgt, char *type,
		const struct ublksrv_tgt_type *ops,
		int argc, char *argv[]);
int ublksrv_register_tgt_type(struct ublksrv_tgt_type *type);
int ublksrv_prepare_target(struct ublksrv_tgt_info *tgt, struct ublksrv_dev *dev);
void ublksrv_for_each_tgt_type(void (*handle_tgt_type)(unsigned idx,
			const struct ublksrv_tgt_type *type, void *data),
		void *data);
void ublksrv_tgt_deinit(struct ublksrv_tgt_info *tgt, struct ublksrv_dev *dev);

#endif
