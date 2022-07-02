#ifndef UBLKSRV_INC_H
#define UBLKSRV_INC_H

#include <stdbool.h>
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
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <syslog.h>
#include <signal.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>
#include <sys/prctl.h>

#include "liburing.h"

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "ublk_cmd.h"
#include "ublksrv_tgt.h"

#define MAX_NR_UBLK_DEVS	128

#define	CTRL_DEV	"/dev/ublk-control"
#define	MAX_NR_HW_QUEUES 32
#define	MAX_QD		1024
#define	MAX_BUF_SIZE	(1024 << 10)

#define	DEF_NR_HW_QUEUES 1
#define	DEF_QD		256
#define	DEF_BUF_SIZE	(512 << 10)

#define UBLKSRV_PID_FILE  "/var/run/ublksrvd"

#define UBLKC_DEV	"/dev/ublkc"

#define UBLKSRV_SHM_DIR	"ublksrv"

#define UBLKSRV_SHM_SIZE  1024

/*
 * Generic data for creating one ublk device
 *
 * Target specific data is handled by ->init_tgt
 */
struct ublksrv_dev_data {
	int   dev_id;
	__u16	nr_hw_queues;
	__u16	queue_depth;
	__u16	block_size;
	__u32	rq_max_blocks;
	__u64	flags[2];
	__u64   reserved[8];
};

struct ublksrv_ctrl_dev {
	struct io_uring ring;

	int ctrl_fd;
	unsigned bs_shift;
	struct ublksrv_ctrl_dev_info  dev_info;

	struct ublksrv_tgt_info tgt;
	cpu_set_t *queues_cpuset;
};

struct ublk_io {
	char *buf_addr;

#define UBLKSRV_NEED_FETCH_RQ		(1UL << 0)
#define UBLKSRV_NEED_COMMIT_RQ_COMP	(1UL << 1)
#define UBLKSRV_IO_FREE			(1UL << 2)
	unsigned int flags;

	union {
		/* result is updated after all target ios are done */
		unsigned int result;

		/* current completed target io cqe */
		int queued_tgt_io;
	};
	struct io_uring_cqe *tgt_io_cqe;
	unsigned long io_data;
};

struct ublksrv_queue {
	int q_id;
	int q_depth;

	/*
	 * Read only by ublksrv daemon, setup via mmap on /dev/ublkcN.
	 *
	 * ublksrv_io_desc(iod) is stored in this buffer, so iod
	 * can be retrieved by request's tag directly.
	 * 
	 * ublksrv writes the iod into this array, and notify ublksrv daemon
	 * by issued io_uring command beforehand.
	 * */
	char *io_cmd_buf;
	char *io_buf;

	unsigned cmd_inflight, tgt_io_inflight;
	unsigned short stopping;

	/*
	 * ring for submit io command to ublk driver, can only be issued
	 * from ublksrv daemon.
	 *
	 * ring depth == dev_info->queue_depth.
	 */
	struct io_uring ring;

	unsigned  tid;
	struct ublksrv_dev *dev;

	struct ublk_io ios[0];
};

struct ublksrv_dev {
	struct ublksrv_ctrl_dev	*ctrl_dev;
	void	*target_data;

	struct ublksrv_queue *__queues[MAX_NR_HW_QUEUES];
	char	*io_buf_start;
	pthread_t *thread;
	int cdev_fd;

	/*
	 * for communication with control task which may not be in
	 * same process with io context
	 */
	int shm_fd;
	char *shm_addr;
	unsigned int shm_offset;
	pthread_mutex_t shm_lock;
};

static inline struct ublksrv_io_desc *ublksrv_get_iod(struct ublksrv_queue *q, int tag)
{
        return (struct ublksrv_io_desc *)
                &(q->io_cmd_buf[tag * sizeof(struct ublksrv_io_desc)]);
}

static inline void ublksrv_mark_io_done(struct ublk_io *io, int res)
{
	/*
	 * mark io done by target, so that ->ubq_daemon can commit its
	 * result and fetch new request via io_uring command.
	 */
	io->flags |= (UBLKSRV_NEED_COMMIT_RQ_COMP | UBLKSRV_IO_FREE);

	io->result = res;
}

static inline bool ublksrv_io_done(struct ublk_io *io)
{
	return io->flags & UBLKSRV_IO_FREE;
}

static inline struct ublksrv_queue *ublksrv_get_queue(const struct ublksrv_dev *dev,
		int q_id)
{
	return dev->__queues[q_id];
}

static inline int is_target_io(__u64 user_data)
{
	return (user_data & (1ULL << 63)) != 0;
}

static inline __u64 build_user_data(unsigned tag, unsigned op,
		unsigned tgt_data, unsigned is_target_io)
{
	assert(!(tag >> 16) && !(op >> 8) && !(tgt_data >> 16));

	return tag | (op << 16) | (tgt_data << 24) | (__u64)is_target_io << 63;
}

static inline unsigned int user_data_to_tag(__u64 user_data)
{
	return user_data & 0xffff;
}

static inline unsigned int user_data_to_op(__u64 user_data)
{
	return (user_data >> 16) & 0xff;
}

static inline unsigned int user_data_to_tgt_data(__u64 user_data)
{
	return (user_data >> 24) & 0xffff;
}

int ublksrv_start_io_daemon(struct ublksrv_ctrl_dev *dev);
int ublksrv_stop_io_daemon(struct ublksrv_ctrl_dev *dev);
int ublksrv_get_io_daemon_pid(struct ublksrv_ctrl_dev *ctrl_dev);

/* two helpers for setting up io_uring */
static inline int ublksrv_setup_ring(int depth, struct io_uring *r,
		unsigned flags)
{
	struct io_uring_params p;

	memset(&p, 0, sizeof(p));
        p.flags = flags | IORING_SETUP_CQSIZE;
        p.cq_entries = depth;

        return io_uring_queue_init_params(depth, r, &p);
}

static inline struct io_uring_sqe *ublksrv_uring_get_sqe(struct io_uring *r,
		int idx, bool is_sqe128)
{
	if (is_sqe128)
		return  &r->sq.sqes[idx << 1];
	return  &r->sq.sqes[idx];
}

static inline void *ublksrv_get_sqe_cmd(struct io_uring_sqe *sqe)
{
	return (void *)&sqe->addr3;
}

static inline void ublksrv_set_sqe_cmd_op(struct io_uring_sqe *sqe, __u32 cmd_op)
{
	__u32 *addr = (__u32 *)&sqe->off;

	*addr = cmd_op;
}

extern int ublksrv_queue_io_cmd(struct ublksrv_queue *q, unsigned tag);

#ifdef __cplusplus
}
#endif

#endif
