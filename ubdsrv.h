#ifndef UBDSRV_INC_H
#define UBDSRV_INC_H

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

#include "liburing.h"

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "ubd_cmd.h"
#include "ubdsrv_tgt.h"

#define MAX_NR_UBD_DEVS	128

#define	CTRL_DEV	"/dev/ubd-control"
#define	MAX_NR_HW_QUEUES 32
#define	MAX_QD		1024
#define	MAX_BUF_SIZE	(1024 << 10)

#define	DEF_NR_HW_QUEUES 1
#define	DEF_QD		256
#define	DEF_BUF_SIZE	(512 << 10)

#define UBDSRV_PID_FILE  "/var/run/ubdsrvd"

#define UBDC_DEV	"/dev/ubdc"

#define UBDSRV_SHM_DIR	"ubdsrv"

#define UBDSRV_SHM_SIZE  1024

struct ubdsrv_ctrl_dev {
	struct io_uring ring;

	unsigned bs_shift;
	struct ubdsrv_ctrl_dev_info  dev_info;

	struct ubdsrv_tgt_info tgt;

	int shm_fd;
	char *shm_addr;
	unsigned int shm_offset;
	pthread_mutex_t lock;

	cpu_set_t *queues_cpuset;
	unsigned short *q_id;
};

struct ubd_io {
	char *buf_addr;

#define UBDSRV_NEED_FETCH_RQ		(1UL << 0)
#define UBDSRV_NEED_COMMIT_RQ_COMP	(1UL << 1)
#define UBDSRV_IO_FREE			(1UL << 2)
	unsigned int flags;
	unsigned int result;
};

struct ubdsrv_queue {
	int q_id;
	int q_depth;

	/*
	 * Read only by ubdsrv daemon, setup via mmap on /dev/ubdcN.
	 *
	 * ubdsrv_io_desc(iod) is stored in this buffer, so iod
	 * can be retrieved by request's tag directly.
	 * 
	 * ubdsrv writes the iod into this array, and notify ubdsrv daemon
	 * by issued io_uring command beforehand.
	 * */
	char *io_cmd_buf;
	char *io_buf;

	unsigned cmd_inflight, tgt_io_inflight;
	unsigned short stopping;

	/*
	 * ring for submit io command to ubd driver, can only be issued
	 * from ubdsrv daemon.
	 *
	 * ring depth == dev_info->queue_depth.
	 */
	struct io_uring ring;

	cpu_set_t cpuset;
	unsigned  tid;
	struct ubdsrv_dev *dev;

	struct ubd_io ios[0];
};

struct ubdsrv_dev {
	struct ubdsrv_ctrl_dev	*ctrl_dev;
	int cdev_fd;

	struct ubdsrv_queue *__queues[MAX_NR_HW_QUEUES];
	char	*io_buf_start;
	pthread_t *thread;
};

static inline struct ubdsrv_io_desc *ubdsrv_get_iod(struct ubdsrv_queue *q, int tag)
{
        return (struct ubdsrv_io_desc *)
                &(q->io_cmd_buf[tag * sizeof(struct ubdsrv_io_desc)]);
}

static inline void ubdsrv_mark_io_done(struct ubd_io *io, int res)
{
	/*
	 * mark io done by target, so that ->ubq_daemon can commit its
	 * result and fetch new request via io_uring command.
	 */
	io->flags |= (UBDSRV_NEED_COMMIT_RQ_COMP | UBDSRV_IO_FREE);

	io->result = res;
}

static inline struct ubdsrv_queue *ubdsrv_get_queue(struct ubdsrv_dev *dev,
		int q_id)
{
	return dev->__queues[q_id];
}

static inline int is_target_io(__u64 user_data)
{
	return (user_data & (1ULL << 63)) != 0;
}

static inline __u64 build_user_data(unsigned tag, unsigned op,
		unsigned is_target_io)
{
	return tag | (op << 16) | (__u64)is_target_io << 63;
}

static inline unsigned int user_data_to_tag(__u64 user_data)
{
	return user_data & 0xffff;
}

static inline unsigned int user_data_to_op(__u64 user_data)
{
	return (user_data >> 16) & 0xffff;
}

int ubdsrv_start_io_daemon(struct ubdsrv_ctrl_dev *dev);
int ubdsrv_stop_io_daemon(struct ubdsrv_ctrl_dev *dev);
int ubdsrv_get_io_daemon_pid(struct ubdsrv_ctrl_dev *ctrl_dev);

/* two helpers for setting up io_uring */
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

static inline void *ubdsrv_get_sqe_cmd(struct io_uring_sqe *sqe)
{
	return (void *)&sqe->addr3;
}

static inline void ubdsrv_set_sqe_cmd_op(struct io_uring_sqe *sqe, __u32 cmd_op)
{
	__u32 *addr = (__u32 *)&sqe->off;

	*addr = cmd_op;
}

#ifdef __cplusplus
}
#endif

#endif
