#ifndef UBDSRV_INC_H
#define UBDSRV_INC_H

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

#include "ubd_cmd.h"
#include "ubdsrv_tgt.h"
#include "ubdsrv_uring.h"
#include "utils.h"

#define MAX_NR_UBD_DEVS	128

#define	CTRL_DEV	"/dev/ubd-control"
#define	MAX_NR_HW_QUEUES 1
#define	MAX_QD		128
#define	MAX_BUF_SIZE	(256 << 10)

#define UBDSRV_PID_FILE  "/var/run/ubdsrvd"

#define UBDC_DEV	"/dev/ubdc"

#define UBDSRV_SHM_DIR	"ubdsrv"

#define INFO(s)

#define UBDSRV_SHM_SIZE  512

struct ubdsrv_ctrl_dev {
	struct ubdsrv_uring ring;

	unsigned bs_shift;
	struct ubdsrv_ctrl_dev_info  dev_info;

	struct ubdsrv_tgt_info tgt;

	int shm_fd;
	char *shm_addr;
};

struct ubd_io {
	char *buf_addr;

#define UBDSRV_NEED_FETCH_RQ		(1UL << 0)
#define UBDSRV_NEED_COMMIT_RQ_COMP	(1UL << 1)
#define UBDSRV_IO_FREE			(1UL << 2)
#define UBDSRV_IO_HANDLING		(1UL << 3)
#define UBDSRV_NEED_GET_DATA		(1UL << 4)
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
	void *io_buf;

	unsigned inflight;
	unsigned stopping;

	/*
	 * ring for submit io command to ubd driver, can only be issued
	 * from ubdsrv daemon.
	 *
	 * ring depth == dev_info->queue_depth.
	 */
	struct ubdsrv_uring ring;

	struct ubd_io ios[0];
};

struct ubdsrv_dev {
	struct ubdsrv_ctrl_dev	*ctrl_dev;
	int cdev_fd;

	struct ubdsrv_queue	*queues;
	void	*io_buf_start;
};

static inline struct ubdsrv_io_desc *ubdsrv_get_iod(struct ubdsrv_queue *q, int tag)
{
        return (struct ubdsrv_io_desc *)
                &(q->io_cmd_buf[tag * sizeof(struct ubdsrv_io_desc)]);
}

static inline int prep_queue_io_cmd(struct ubdsrv_queue *q)
{
	struct ubdsrv_uring *r = &q->ring;
	struct io_sq_ring *ring = &r->sq_ring;

	return *ring->tail;
}

static inline void commit_queue_io_cmd(struct ubdsrv_queue *q, unsigned tail)
{
	struct ubdsrv_uring *r = &q->ring;
	struct io_sq_ring *ring = &r->sq_ring;

	atomic_store_release(ring->tail, tail);
}

static inline void ubdsrv_mark_io_handling(struct ubd_io *io)
{
	/*
	 * mark handling, so that ubdsrv_submit_fetch_commands() will
	 * count us for submission
	 */
	io->flags |= UBDSRV_IO_HANDLING;
}

int ubdsrv_start_io_daemon(struct ubdsrv_ctrl_dev *dev);
int ubdsrv_stop_io_daemon(struct ubdsrv_ctrl_dev *dev);
int ubdsrv_get_io_daemon_pid(struct ubdsrv_ctrl_dev *ctrl_dev);

#endif
