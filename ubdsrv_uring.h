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

#include "io_uring.h"
//#include "../arch/arch.h"

#include "dep.h"

struct io_sq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	unsigned *flags;
	unsigned *array;
};

struct io_cq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	struct io_uring_cqe *cqes;
};

struct ubdsrv_uring {
	unsigned sq_ring_mask, cq_ring_mask;
	int ring_fd, ring_depth;
	struct io_sq_ring sq_ring;
	struct io_uring_sqe *sqes;
	struct io_cq_ring cq_ring;
};

static inline struct io_uring_sqe *ubdsrv_uring_get_sqe(struct ubdsrv_uring *r,
		int idx, int is_sqe128)
{
	if (is_sqe128)
		return  &r->sqes[idx << 1];
	return  &r->sqes[idx];
}

/********* part of following code is stolen from t/io_uring.c *****/
static inline int io_uring_enter(struct ubdsrv_uring *r, unsigned int to_submit,
			  unsigned int min_complete, unsigned int flags)
{
	return syscall(__NR_io_uring_enter, r->ring_fd, to_submit,
			min_complete, flags, NULL, 0);
}

static inline int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
	/*
	 * Clamp CQ ring size at our SQ ring size, we don't need more entries
	 * than that.
	 */
	p->flags |= IORING_SETUP_CQSIZE;
	p->cq_entries = entries;

	return syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_register_buffers(struct ubdsrv_uring *r,
		struct iovec *iovecs, int nr_vecs)
{
	return syscall(__NR_io_uring_register, r->ring_fd,
			IORING_REGISTER_BUFFERS, iovecs, nr_vecs);
}

static inline int io_uring_unregister_buffers(struct ubdsrv_uring *r)
{
	return syscall(__NR_io_uring_register, r->ring_fd,
			IORING_UNREGISTER_BUFFERS, NULL, 0);
}

int ubdsrv_setup_ring(struct ubdsrv_uring *r, unsigned flags, int depth);
int ubdsrv_reap_events_uring(struct ubdsrv_uring *r,
		void (*handle_cqe)(struct ubdsrv_uring *r,
			struct io_uring_cqe *cqe, void *data), void *data);
int ubdsrv_io_uring_register_files(struct ubdsrv_uring *r,
		int *fds, int nr_fds);
void ubdsrv_io_uring_unregister_files(struct ubdsrv_uring *r);
#endif
