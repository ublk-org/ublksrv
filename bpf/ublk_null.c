// SPDX-License-Identifier: GPL-2.0

#include "ublk_null.skel.h"

static void ublk_null_test(void)
{
	struct ublk_null *obj = ublk_null__open_and_load();
	int err = 0;

	if (!obj) {
		printf("load ublk null bpf prog failed\n");
		return;
	}

	err = ublk_null__attach(obj);
	if (err) {
		printf("attach ublk_null failed %d\n", err);
		exit(-1);
	} else {
		int fd = bpf_program__fd(obj->progs.ublk_null_handle_io);
		int fd2 = bpf_program__fd(obj->progs.ublk_null_handle_io_sleep);
		int fd3 = bpf_program__fd(obj->progs.ublk_null_handle_io_task);

		printf("attach ublk_null: prog fd %d %d %d\n", fd, fd2, fd3);
	}
	ublk_null__detach(obj);
	ublk_null__destroy(obj);
}

int main(void)
{

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	ublk_null_test();

	return 0;
}
