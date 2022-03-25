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

int ubdsrv_setup_ring(struct ubdsrv_uring *r, unsigned flags, int depth,
		struct iovec *base, int nr_buf)
{
	struct io_sq_ring *sring = &r->sq_ring;
	struct io_cq_ring *cring = &r->cq_ring;
	struct io_uring_params p;
	int fd;
	void *ptr;
	struct rlimit rlim;
	int ret;
	int mut = (flags & IORING_SETUP_SQE128) ? 2 : 1;

	memset(&p, 0, sizeof(p));

	p.flags |= flags;

	fd = io_uring_setup(depth, &p);
	if (fd < 0) {
		perror("io_uring_setup");
		return 1;
	}

	r->ring_depth = p.sq_entries;
	r->ring_fd = fd;

	//io_uring_probe(fd);

	if (nr_buf) {
		/* setup fixed buffers */
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;

		/* ignore potential error, not needed on newer kernels */
		setrlimit(RLIMIT_MEMLOCK, &rlim);
		ret = io_uring_register_buffers(r, base, nr_buf);
		if (ret < 0) {
			perror("io_uring_register_buffers");
			return 1;
		}
	}

	ptr = mmap(0, p.sq_off.array + p.sq_entries * sizeof(__u32),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQ_RING);
	sring->head = ptr + p.sq_off.head;
	sring->tail = ptr + p.sq_off.tail;
	sring->ring_mask = ptr + p.sq_off.ring_mask;
	sring->ring_entries = ptr + p.sq_off.ring_entries;
	sring->flags = ptr + p.sq_off.flags;
	sring->array = ptr + p.sq_off.array;
	r->sq_ring_mask = *sring->ring_mask;

	r->sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe)*mut,
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQES);

	ptr = mmap(0, p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_CQ_RING);
	cring->head = ptr + p.cq_off.head;
	cring->tail = ptr + p.cq_off.tail;
	cring->ring_mask = ptr + p.cq_off.ring_mask;
	cring->ring_entries = ptr + p.cq_off.ring_entries;
	cring->cqes = ptr + p.cq_off.cqes;
	r->cq_ring_mask = *cring->ring_mask;

	syslog(LOG_INFO, "depth %u sqs %u/%x cqs %u/%x", depth,
			p.sq_entries, r->sq_ring_mask,
			p.cq_entries, r->cq_ring_mask);

	return 0;
}
