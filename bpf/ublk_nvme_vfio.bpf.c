// SPDX-License-Identifier: GPL-2.0
/*
 * BPF NVMe VFIO target for ublk — full NVMe SQ submission from BPF.
 *
 * Complete I/O submission path runs in BPF (queue_rq context):
 *   1. DMA-map bio pages → IOVA
 *   2. Build 64-byte NVMe RW command directly in arena SQ buffer
 *   3. Ring doorbell via ublk_bpf_mmio_writel() if last/commit
 *
 * Returns 0 → kernel forwards to userspace for CQ polling + completion.
 *
 * Arena is a single flat buffer. Userspace computes the layout (SQ/CQ/PRP
 * offsets per queue) and writes per-queue offsets to sq_state map entries.
 * BPF accesses regions via these offsets rather than fixed 2D arrays.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Arena address space annotation. Clang emits addr_space_cast instructions
 * so the BPF JIT converts between kernel vmalloc VA and arena offset.
 */
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#define __arena __attribute__((address_space(1)))
#else
#define __arena
#endif

/* CO-RE local struct definitions for module BTF */
struct ublk_bpf_ctx___local {
	void *ub;
	void *bar0;
	unsigned long bar0_size;
} __attribute__((preserve_access_index));

struct ublk_bpf_ops___local {
	int (*queue_io_cmd)(struct ublk_bpf_ctx___local *ctx,
			    struct request *req, bool last);
	void (*commit_io_cmd)(struct ublk_bpf_ctx___local *ctx, int ubq_id);
	void (*complete_io_cmd)(struct ublk_bpf_ctx___local *ctx,
				struct request *req);
};

struct ublksrv_io_desc___local {
	__u32 op_flags;
	union {
		__u32 nr_sectors;
		__u32 nr_zones;
	};
	__u64 start_sector;
	__u64 addr;
} __attribute__((preserve_access_index));

#define ublk_bpf_ctx ublk_bpf_ctx___local
#define ublk_bpf_ops ublk_bpf_ops___local
#define ublksrv_io_desc ublksrv_io_desc___local

/* NVMe opcodes */
#define NVME_CMD_FLUSH	0x00
#define NVME_CMD_WRITE	0x01
#define NVME_CMD_READ	0x02
#define NVME_CMD_DSM	0x09

/* NVMe DSM flags */
#define NVME_DSMGMT_AD	0x04	/* Attribute - Deallocate */

/* ublk I/O op codes */
#define UBLK_IO_OP_READ		0
#define UBLK_IO_OP_WRITE	1
#define UBLK_IO_OP_FLUSH	2
#define UBLK_IO_OP_DISCARD	3

/* ublk I/O flags */
#define UBLK_IO_F_FUA	(1U << 13)

/* NVMe RW FUA flag in cdw12 */
#define NVME_RW_FUA	(1 << 14)

/*
 * NVMe SQ entry layout — 64 bytes.
 * Fields packed exactly as NVMe spec for RW commands.
 */
struct nvme_rw_cmd {
	__u8  opcode;
	__u8  flags;
	__u16 cid;
	__u32 nsid;
	__u64 rsvd2;
	__u64 metadata;
	__u64 prp1;
	__u64 prp2;
	__u64 slba;
	__u16 length;
	__u16 control;
	__u32 dsmgmt;
	__u32 reftag;
	__u16 apptag;
	__u16 appmask;
} __attribute__((aligned(64)));

/*
 * Per-queue state in BPF_MAP_TYPE_ARRAY (not arena, not .bss).
 *
 * Must be in an array map because bpf_spin_lock requires a constant
 * offset within a map value. Array map lookup returns a pointer at
 * fixed offset 0, satisfying the verifier.
 *
 * Arena offsets (sq_arena_off, prp_arena_off) are set by userspace
 * based on the unified pool layout. BPF uses these to index into
 * the flat arena_pool[] buffer.
 */
struct sq_state {
	struct bpf_spin_lock sq_lock;	/* protects sq_tail + SQ entry + doorbell */
	__u64 sq_dma;		/* IOVA from userspace VFIO DMA mapping */
	__u64 prp_base_iova;	/* IOVA base for PRP list pages */
	__u32 sq_arena_off;	/* arena byte offset to SQ entries */
	__u32 cq_arena_off;	/* arena byte offset to CQ entries */
	__u32 prp_arena_off;	/* arena byte offset to PRP lists */
	__u16 sq_tail;
	__u16 last_sq_tail;	/* last doorbell value (for flush logic) */
	__u16 qsize;		/* SQ size (depth + 1) */
	__u16 qdepth;		/* queue depth (for PRP index) */
	__u32 db_offset;	/* BAR0 doorbell offset */
} __attribute__((aligned(64)));

/* Each PRP list is one page (512 entries × 8 bytes = 4096) */
#define PRP_LIST_SIZE	__PAGE_SIZE

/* Maximum arena capacity — validated at runtime by userspace */
#define MAX_ARENA_PAGES	16384	/* 64MB max */
#define MAX_ARENA_SIZE	(MAX_ARENA_PAGES * __PAGE_SIZE)

/* Maximum queue count — verifier bound for sq_queues map */
#define MAX_QUEUES	64

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, MAX_ARENA_PAGES);
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, (1ull << 32) | (~0u - MAX_ARENA_SIZE + 1));
#else
	__ulong(map_extra, (1ull << 44) | (~0u - MAX_ARENA_SIZE + 1));
#endif
} arena SEC(".maps");

/* Per-queue state — array map for bpf_spin_lock support */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct sq_state);
	__uint(max_entries, MAX_QUEUES);
} sq_queues SEC(".maps");

/* Single flat arena buffer — all regions accessed via offsets from sq_state */
char __arena arena_pool[MAX_ARENA_SIZE];

/* Stats in .bss (readable by userspace after I/O) */
__u64 bpf_sq_submissions;
__u64 bpf_doorbell_rings;

/* Configuration from userspace (.rodata) */
const volatile __u32 nsid = 1;
const volatile __u8  lba_shift = 9;

/* kfunc declarations */
extern struct ublksrv_io_desc *ublk_bpf_get_iod(struct request *req) __ksym;
extern void ublk_bpf_complete_io(struct request *req, int res) __ksym;
extern int ublk_bpf_map_dma(struct request *req) __ksym;
extern void ublk_bpf_unmap_dma(struct request *req) __ksym;
extern void ublk_bpf_mmio_writel(struct ublk_bpf_ctx *ctx,
				 __u32 offset, __u32 value) __ksym;

/*
 * Get PRP list pointer in arena for a given queue/tag.
 * Returns NULL if offset would exceed arena bounds.
 */
static __always_inline volatile __u64 __arena *
arena_prp_list(struct sq_state *qs, __u16 tag)
{
	__u32 off = qs->prp_arena_off + (__u32)tag * PRP_LIST_SIZE;

	if (off + PRP_LIST_SIZE > MAX_ARENA_SIZE)
		return NULL;
	return (volatile __u64 __arena *)&arena_pool[off];
}

SEC("struct_ops/queue_io_cmd")
int BPF_PROG(nvme_queue_io_cmd, void *bctx, struct request *req, bool last)
{
	struct nvme_rw_cmd __arena *sqe;
	const struct ublksrv_io_desc *iod;
	__u8 op;
	__u64 slba;
	__u16 nlb, tail;
	int ret, qid;

	qid = req->mq_hctx->queue_num;
	if (qid >= MAX_QUEUES)
		return -22;
	qid &= (MAX_QUEUES - 1);

	iod = ublk_bpf_get_iod(req);
	if (!iod)
		return -22;

	op = iod->op_flags & 0xff;

	if (op != UBLK_IO_OP_READ && op != UBLK_IO_OP_WRITE &&
	    op != UBLK_IO_OP_FLUSH && op != UBLK_IO_OP_DISCARD)
		return 0;

	if (op == UBLK_IO_OP_READ || op == UBLK_IO_OP_WRITE) {
		ret = ublk_bpf_map_dma(req);
		if (ret < 0)
			return ret;

		iod = ublk_bpf_get_iod(req);
		if (!iod)
			return -22;
	}

	{
	__u32 qkey = qid;
	struct sq_state *qs = bpf_map_lookup_elem(&sq_queues, &qkey);

	if (!qs)
		return -22;

	{
		struct nvme_rw_cmd cmd = {};

		cmd.cid = (__u16)req->tag;
		cmd.nsid = nsid;

		if (op == UBLK_IO_OP_FLUSH) {
			cmd.opcode = NVME_CMD_FLUSH;

		} else if (op == UBLK_IO_OP_DISCARD) {
			__u16 tag = (__u16)req->tag;
			__u64 prp_iova;
			volatile __u64 __arena *dsm;

			if (tag >= qs->qdepth)
				return -22;

			slba = iod->start_sector >> (lba_shift - 9);
			nlb = iod->nr_sectors >> (lba_shift - 9);
			prp_iova = qs->prp_base_iova +
				   (__u64)tag * PRP_LIST_SIZE;

			dsm = arena_prp_list(qs, tag);
			if (!dsm)
				return -22;
			dsm[0] = (__u64)nlb << 32;
			dsm[1] = slba;

			cmd.opcode = NVME_CMD_DSM;
			cmd.prp1 = prp_iova;
			cmd.slba = (__u64)NVME_DSMGMT_AD << 32;

		} else {
			/* READ / WRITE */
			__u64 addr = iod->addr;
			__u32 io_size;
			__u32 first_page_len;

			slba = iod->start_sector >> (lba_shift - 9);
			nlb = (iod->nr_sectors >> (lba_shift - 9)) - 1;
			io_size = (__u32)(nlb + 1) << lba_shift;
			first_page_len = 0x1000 - ((__u32)addr & 0xFFF);

			cmd.opcode = (op == UBLK_IO_OP_WRITE)
					? NVME_CMD_WRITE : NVME_CMD_READ;
			cmd.slba = slba;
			cmd.length = nlb;
			cmd.control = (iod->op_flags & UBLK_IO_F_FUA)
					? NVME_RW_FUA : 0;
			cmd.prp1 = addr;

			if (io_size > first_page_len) {
				__u32 remaining = io_size - first_page_len;

				addr = (addr & ~0xFFFULL) + 0x1000;

				if (remaining <= 0x1000) {
					cmd.prp2 = addr;
				} else {
					__u16 tag = (__u16)req->tag;
					volatile __u64 __arena *plist;
					__u64 prp_iova;
					int i;

					if (tag >= qs->qdepth)
						return -22;

					plist = arena_prp_list(qs, tag);
					if (!plist)
						return -22;
					prp_iova = qs->prp_base_iova +
						(__u64)tag * PRP_LIST_SIZE;

					for (i = 0; remaining > 0 &&
					     i < 512; i++) {
						plist[i] = addr;
						addr += 0x1000;
						remaining =
							(remaining > 0x1000)
							? remaining - 0x1000
							: 0;
					}
					cmd.prp2 = prp_iova;
				}
			}
		}

		/*
		 * 4. Lock → SQ copy → advance tail → unlock → doorbell.
		 */
		{
		bool ring_db = false;
		__u32 db_off;
		__u32 sq_off;

		bpf_spin_lock(&qs->sq_lock);

		tail = qs->sq_tail;
		if (tail >= qs->qsize)
			tail = 0;

		/* Access SQ entry via arena offset */
		sq_off = qs->sq_arena_off + (__u32)tail * 64;
		if (sq_off + 64 > MAX_ARENA_SIZE) {
			bpf_spin_unlock(&qs->sq_lock);
			return -22;
		}
		sqe = (struct nvme_rw_cmd __arena *)&arena_pool[sq_off];

		/* Volatile-copy all 64 bytes to arena SQ slot */
		{
			volatile __u64 __arena *dst = (__u64 __arena *)sqe;
			__u64 *src = (__u64 *)&cmd;

			dst[0] = src[0];
			dst[1] = src[1];
			dst[2] = src[2];
			dst[3] = src[3];
			dst[4] = src[4];
			dst[5] = src[5];
			dst[6] = src[6];
			dst[7] = src[7];
		}

		/* Advance tail */
		tail = tail + 1;
		if (tail >= qs->qsize)
			tail = 0;
		qs->sq_tail = tail;
		db_off = qs->db_offset;

		/* Decide whether to ring doorbell */
		if (last) {
			qs->last_sq_tail = tail;
			ring_db = true;
		} else {
			__u16 next_tail = tail + 1;

			if (next_tail >= qs->qsize)
				next_tail = 0;
			if (next_tail == qs->last_sq_tail) {
				qs->last_sq_tail = tail;
				ring_db = true;
			}
		}

		bpf_spin_unlock(&qs->sq_lock);

		if (ring_db) {
			ublk_bpf_mmio_writel((struct ublk_bpf_ctx *)bctx,
					     db_off, tail);
			bpf_doorbell_rings++;
		}
		bpf_sq_submissions++;
		}
	}
	}

	return 0;
}

SEC("struct_ops/commit_io_cmd")
void BPF_PROG(nvme_commit_io_cmd, void *bctx, int ubq_id)
{
	__u32 qkey = ubq_id;
	struct sq_state *qs;

	if (ubq_id < 0 || ubq_id >= MAX_QUEUES)
		return;
	qs = bpf_map_lookup_elem(&sq_queues, &qkey);
	if (!qs)
		return;
	if (qs->sq_tail != qs->last_sq_tail) {
		ublk_bpf_mmio_writel((struct ublk_bpf_ctx *)bctx,
				     qs->db_offset, qs->sq_tail);
		qs->last_sq_tail = qs->sq_tail;
	}
}

SEC("struct_ops/complete_io_cmd")
void BPF_PROG(nvme_complete_io_cmd, void *bctx, struct request *req)
{
	ublk_bpf_unmap_dma(req);
}

SEC(".struct_ops.link")
struct ublk_bpf_ops ublk_nvme_vfio_bpf_ops = {
	.queue_io_cmd = (void *)nvme_queue_io_cmd,
	.commit_io_cmd = (void *)nvme_commit_io_cmd,
	.complete_io_cmd = (void *)nvme_complete_io_cmd,
};

char _license[] SEC("license") = "GPL";
