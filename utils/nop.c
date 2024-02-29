/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <liburing.h>

/* gcc -g -o nop nop.c -luring */

/* test nop over uring and see io_uring is working */
static int test_nop()
{
	struct io_uring _ring;
	struct io_uring *ring = &_ring;
	struct io_uring_params p = { };
	int ret, i;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;

	p.flags = IORING_SETUP_SQE128;
	ret = io_uring_queue_init_params(64, ring, &p);
	if (ret < 0) {
		fprintf(stderr, "ring can't be setup %d\n", ret);
		goto err;
	}

	ret = -EINVAL;
	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed ret %d\n", ret);
		return ret;
	}

	io_uring_prep_nop(sqe);
	sqe->user_data = 1;
	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		goto err;
	}
	if (!cqe->user_data) {
		fprintf(stderr, "Unexpected 0 user_data\n");
		goto err;
	}
	io_uring_cqe_seen(ring, cqe);
	fprintf(stdout, "nop over uring run successfully\n");
err:
	io_uring_queue_exit(ring);
	return ret;
}

int main(int argc, char *argv[])
{
	test_nop();

	return 0;
}
