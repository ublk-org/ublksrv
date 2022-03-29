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

#include "dep.h"
//#include "../arch/arch.h"
//#include "../os/linux/io_uring.h"
#include "io_uring.h"

struct ubdsrv_ctrl_dev;
struct ubdsrv_dev;
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
	int backing_fd;
	char backing_file[1024];
};

struct ubdsrv_tgt_info_null {
	int data;
};

struct ubdsrv_tgt_type {
	char *name;
	int (*init_tgt)(struct ubdsrv_tgt_info *, int type, int argc,
			char *argv[]);
	int (*handle_io)(struct ubdsrv_dev *, int qid, int tag);
	int (*handle_io_async)(struct ubdsrv_dev *, int qid, int tag);
	int (*prepare_io)(struct ubdsrv_tgt_info *);
};

struct ubdsrv_tgt_info {
	unsigned long long dev_size;
	unsigned int type;
	unsigned int tgt_ring_depth;	/* at most in-flight ios */
	unsigned int nr_fds;
	int fds[UBDSRV_TGT_MAX_FDS];
	union {
		struct ubdsrv_tgt_info_loop loop;
		struct ubdsrv_tgt_info_null null;
	};
	const struct ubdsrv_tgt_type *ops;
};

static inline unsigned ubdsrv_convert_cmd_op(struct ubdsrv_io_desc *iod)
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

static inline void ubdsrv_tgt_exit(struct ubdsrv_tgt_info *tgt)
{
	int i;

	for (i = 1; i < tgt->nr_fds; i++)
		close(tgt->fds[i]);
}

static int ubdsrv_prepare_io(struct ubdsrv_tgt_info *tgt)
{
	if (tgt->ops->prepare_io)
		return tgt->ops->prepare_io(tgt);
}
#endif
