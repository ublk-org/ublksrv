/*
#include "ubdsrv_uring.h"

int ubdsrv_io_uring_register_files(struct ubdsrv_uring *r,
		int *fds, int nr_fds)
{
	return syscall(__NR_io_uring_register, r->ring_fd,
			IORING_REGISTER_FILES, fds, nr_fds);
}

void ubdsrv_io_uring_unregister_files(struct ubdsrv_uring *r)
{
	syscall(__NR_io_uring_register, r->ring_fd,
			IORING_UNREGISTER_FILES, NULL, 0);
}

int ubdsrv_reap_events_uring(struct ubdsrv_uring *r,
		void (*handle_cqe)(struct ubdsrv_uring *r,
			struct io_uring_cqe *cqe, void *data), void *data)
{
	struct io_cq_ring *ring = &r->cq_ring;
	struct io_uring_cqe *cqe;
	unsigned head, reaped = 0;

	head = *ring->head;
	do {
		read_barrier();
		if (head == atomic_load_acquire(ring->tail))
			break;
		cqe = &ring->cqes[head & r->cq_ring_mask];
		reaped++;
		if (handle_cqe)
			handle_cqe(r, cqe, data);
		head++;
	} while (1);

	if (reaped)
		atomic_store_release(ring->head, head);
	return reaped;
}

int ubdsrv_setup_ring(struct io_uring *r, unsigned flags, int depth)
{
	return io_uring_queue_init(depth, r, flags)
}*/
