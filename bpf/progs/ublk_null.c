// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <linux/const.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern struct ublksrv_io_desc *ublk_bpf_get_iod(unsigned long handle) __ksym;
extern int ublk_bpf_complete_io(unsigned long handle, int res) __ksym;

static inline int __ublk_null_handle_io(u64 *h)
{
	unsigned long off = -1, sects = -1;
	u64 hh = *h;
	struct ublksrv_io_desc *iod = ublk_bpf_get_iod(hh);
	int res;

	if (iod) {
		res = iod->nr_sectors << 9;
		off = iod->start_sector;
		sects = iod->nr_sectors;
	} else
		res = -EINVAL;

	ublk_bpf_complete_io(hh, res);
	//bpf_printk("io: %lx-%d id %u qid %u tag %u res %d / %d\n",
	//				off, sects, id, qid, tag, res, res2);
	return UBLK_BPF_IO_HANDLED;
}

SEC("fmod_ret.s/ublk_bpf_queue_io_cmd")
int ublk_null_handle_io_sleep(u64 *h)
{
	return __ublk_null_handle_io(h);
}

SEC("fmod_ret/ublk_bpf_queue_io_cmd")
int ublk_null_handle_io(u64 *h)
{
	return __ublk_null_handle_io(h);
}

SEC("fmod_ret.s/ublk_bpf_run_io_task")
int ublk_null_handle_io_task(u64 *h)
{
	return __ublk_null_handle_io(h);
}

char LICENSE[] SEC("license") = "GPL";
