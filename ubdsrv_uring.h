#ifndef UBDSRV_URING_INC_H
#define UBDSRV_URING_INC_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <sys/resource.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>

#include "liburing.h"
//#include "../arch/arch.h"

#include "dep.h"

static inline int ubdsrv_setup_ring(int depth, struct io_uring *r,
		unsigned flags)
{
	struct io_uring_params p;

	memset(&p, 0, sizeof(p));
        p.flags = flags | IORING_SETUP_CQSIZE;
        p.cq_entries = depth;

        return io_uring_queue_init_params(depth, r, &p);
}

static inline struct io_uring_sqe *ubdsrv_uring_get_sqe(struct io_uring *r,
		int idx, bool is_sqe128)
{
	if (is_sqe128)
		return  &r->sq.sqes[idx << 1];
	return  &r->sq.sqes[idx];
}

#endif
