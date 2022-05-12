#ifndef USER_BLK_DRV_CMD_INC_H
#define USER_BLK_DRV_CMD_INC_H

#include <linux/types.h>

/* ubd server command definition */

/*
 * Admin commands, issued by ubd server, and handled by ubd driver.
 */
#define	UBD_CMD_GET_QUEUE_AFFINITY	0x01
#define	UBD_CMD_GET_DEV_INFO	0x02
#define	UBD_CMD_ADD_DEV		0x04
#define	UBD_CMD_DEL_DEV		0x05
#define	UBD_CMD_START_DEV	0x06
#define	UBD_CMD_STOP_DEV	0x07

/*
 * IO commands, issued by ubd server, and handled by ubd driver.
 *
 * FETCH_REQ: issued via sqe(URING_CMD) beforehand for fetching IO request
 *      from ubd driver, should be issued only when starting device. After
 *      the associated cqe is returned, request's tag can be retrieved via
 *      cqe->userdata.
 *
 * COMMIT_AND_FETCH_REQ: issued via sqe(URING_CMD) after ubdserver handled
 *      this IO request, request's handling result is committed to ubd
 *      driver, meantime FETCH_REQ is piggyback, and FETCH_REQ has to be
 *      handled before completing io request.
 *
 * COMMIT_REQ: issued via sqe(URING_CMD) after ubdserver handled this IO
 *      request, request's handling result is committed to ubd driver.
 */
#define	UBD_IO_FETCH_REQ		0x20
#define	UBD_IO_COMMIT_AND_FETCH_REQ	0x21
#define	UBD_IO_COMMIT_REQ		0x22

/* only ABORT means that no re-fetch */
#define UBD_IO_RES_OK			0
#define UBD_IO_RES_ABORT		(-ENODEV)

#define UBDSRV_CMD_BUF_OFFSET	0
#define UBDSRV_IO_BUF_OFFSET	0x80000000

/* tag bit is 12bit, so at most 4096 IOs for each queue */
#define UBD_MAX_QUEUE_DEPTH	4096

/*
 * zero copy requires 4k block size, and can remap ubd driver's io
 * request into ubdsrv's vm space
 */
#define UBD_F_SUPPORT_ZERO_COPY	0

/* shipped via sqe->cmd of io_uring command */
struct ubdsrv_ctrl_cmd {
	/* sent to which device, must be valid */
	__u32	dev_id;

	/* sent to which queue, must be -1 if the cmd isn't for queue */
	__u16	queue_id;
	/*
	 * cmd specific buffer, can be IN or OUT.
	 */
	__u16	len;
	__u64	addr;

	/* inline data */
	__u64	data[2];
};

struct ubdsrv_ctrl_dev_info {
	__u16	nr_hw_queues;
	__u16	queue_depth;
	__u16	block_size;
	__u16	state;

	__u32	rq_max_blocks;
	__u32	dev_id;

	__u64   dev_blocks;

	__s32	ubdsrv_pid;
	__s32	reserved0;
	__u64	flags[2];

	__u64	reserved1[10];
};

#define		UBD_IO_OP_READ		0
#define		UBD_IO_OP_WRITE		1
#define		UBD_IO_OP_FLUSH		2
#define		UBD_IO_OP_DISCARD	3
#define		UBD_IO_OP_WRITE_SAME	4
#define		UBD_IO_OP_WRITE_ZEROES	5

#define		UBD_IO_F_FAILFAST_DEV		(1U << 8)
#define		UBD_IO_F_FAILFAST_TRANSPORT	(1U << 9)
#define		UBD_IO_F_FAILFAST_DRIVER	(1U << 10)
#define		UBD_IO_F_META			(1U << 11)
#define		UBD_IO_F_INTEGRITY		(1U << 12)
#define		UBD_IO_F_FUA			(1U << 13)
#define		UBD_IO_F_PREFLUSH		(1U << 14)
#define		UBD_IO_F_NOUNMAP		(1U << 15)
#define		UBD_IO_F_SWAP			(1U << 16)

/*
 * io cmd is described by this structure, and stored in share memory, indexed
 * by request tag.
 *
 * The data is stored by ubd driver, and read by ubdsrv after one fetch command
 * returns.
 */
struct ubdsrv_io_desc {
	/* op: bit 0-7, flags: bit 8-31 */
	__u32		op_flags;

	/*
	 * tag: bit 0 - 11, max: 4096
	 *
	 * blocks: bit 12 ~ 31, max: 1M blocks
	 */
	__u32		tag_blocks;

	/* start block for this io */
	__u64		start_block;

	/* buffer address in ubdsrv daemon vm space, from ubd driver */
	__u64		addr;
};

static inline __u8 ubdsrv_get_op(const struct ubdsrv_io_desc *iod)
{
	return iod->op_flags & 0xff;
}

static inline __u32 ubdsrv_get_flags(const struct ubdsrv_io_desc *iod)
{
	return iod->op_flags >> 8;
}

static inline __u32 ubdsrv_get_blocks(const struct ubdsrv_io_desc *iod)
{
	return iod->tag_blocks >> 12;
}

/* issued to ubd driver via /dev/ubdcN */
struct ubdsrv_io_cmd {
	__u16	q_id;

	/* for fetch/commit which result */
	__u16	tag;

	/* io result, it is valid for COMMIT* command only */
	__s32	result;

	/*
	 * userspace buffer address in ubdsrv daemon process, valid for
	 * FETCH* command only
	 */
	__u64	addr;
};

#endif
