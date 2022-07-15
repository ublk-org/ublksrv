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
#include <sys/eventfd.h>
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

#ifdef __cplusplus
extern "C" {
#endif

#include "ublk_cmd.h"

#define	MAX_NR_HW_QUEUES 32
#define	MAX_QD		1024
#define	MAX_BUF_SIZE	(1024 << 10)

#define	DEF_NR_HW_QUEUES 1
#define	DEF_QD		256
#define	DEF_BUF_SIZE	(512 << 10)

#define UBLKSRV_SHM_DIR	"ublksrv"
#define UBLKSRV_SHM_SIZE  1024

/************ stored in ublksrv_ctrl_dev_info->ublksrv_flags *******/
/*
 * HAS_IO_DAEMON means io handler has its own daemon context which isn't
 * same with control command context, so shared memory communication is
 * required between control task and io daemon
 */
#define UBLKSRV_F_HAS_IO_DAEMON		(1UL << 0)

/*
 * target may not use io_uring for handling io, so eventfd is required
 * for wakeup io command io_uring context
 */
#define UBLKSRV_F_NEED_EVENTFD		(1UL << 1)

/*
 * Generic data for creating one ublk device
 *
 * Target specific data is handled by ->init_tgt
 */
struct ublksrv_dev_data {
	int		dev_id;
	unsigned	rq_max_blocks;
	unsigned short	nr_hw_queues;
	unsigned short	queue_depth;
	unsigned short	block_size;
	const char	*tgt_type;
	const struct ublksrv_tgt_type *tgt_ops;
	int		tgt_argc;
	char		**tgt_argv;
	unsigned long	flags[2];
	unsigned long	ublksrv_flags;
	unsigned long   reserved[7];
};

struct ublksrv_ctrl_dev {
	struct io_uring ring;

	int ctrl_fd;
	unsigned bs_shift;
	struct ublksrv_ctrl_dev_info  dev_info;

	const char *tgt_type;
	const struct ublksrv_tgt_type *tgt_ops;
	int tgt_argc;
	char **tgt_argv;

	cpu_set_t *queues_cpuset;
};

struct ublk_io {
	char *buf_addr;

#define UBLKSRV_NEED_FETCH_RQ		(1UL << 0)
#define UBLKSRV_NEED_COMMIT_RQ_COMP	(1UL << 1)
#define UBLKSRV_IO_FREE			(1UL << 2)
#define UBLKSRV_NEED_GET_DATA		(1UL << 3)
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

	void *private_data;

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
	bool stopping, idle;

	/* eventfd */
	int efd;

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

#define  UBLKSRV_TGT_MAX_FDS	32
enum {
	/* evaluate communication cost, ublksrv_null vs /dev/nullb0 */
	UBLKSRV_TGT_TYPE_NULL,

	/* ublksrv_loop vs. /dev/loop */
	UBLKSRV_TGT_TYPE_LOOP,

	UBLKSRV_TGT_TYPE_MAX = 256,
};

struct ublksrv_tgt_type;

struct ublksrv_tgt_info {
	unsigned long long dev_size;
	unsigned int tgt_ring_depth;	/* at most in-flight ios */
	unsigned int nr_fds;
	int fds[UBLKSRV_TGT_MAX_FDS];
	void *tgt_data;
	const struct ublksrv_tgt_type *ops;
};

struct ublksrv_tgt_type {
	int  type;
	const char *name;

	/*
	 * initialize this new target, argc/argv includes target specific
	 * command line parameters
	 */
	int (*init_tgt)(struct ublksrv_dev *, int type, int argc,
			char *argv[]);

	/*
	 * One IO request comes from /dev/ublkbN, so notify target code
	 * for handling the IO. Inside target code, the IO can be handled
	 * with our io_uring too, if this is true, ->tgt_io_done callback
	 * has to be implemented. Otherwise, target can implement
	 * ->handle_event() for processing io completion there.
	 */
	int (*handle_io_async)(struct ublksrv_queue *, int tag);

	/*
	 * target io is handled by our io_uring, and once the target io
	 * is completed, this callback is called
	 */
	void (*tgt_io_done)(struct ublksrv_queue *, struct io_uring_cqe *);

	/*
	 * Someone has written to our eventfd, so let target handle the
	 * event, most of times, it is for handling io completion by
	 * calling ublksrv_complete_io() which has to be run in ubq_daemon
	 * context.
	 *
	 * Follows the typical scenario:
	 *
	 * 1) one target io is completed in target pthread context, so
	 * target code calls ublksrv_queue_send_event for notifying ubq
	 * daemon
	 *
	 * 2) ubq daemon gets notified, so wakeup from io_uring_enter(),
	 * then found eventfd is completed, so call ->handle_event()
	 *
	 * 3) inside ->handle_event(), if any io represented by one io
	 * command is completed, ublksrv_complete_io() is called for
	 * this io.
	 *
	 * 4) after returning from ->handle_event(), ubq_daemon will
	 * queue & submit the eventfd io immediately for getting
	 * notification from future event.
	 */
	void (*handle_event)(struct ublksrv_queue *);

	/*
	 * show target specific command line for adding new device
	 *
	 * Be careful: this callback is the only one which is not run from
	 * ublk device daemon task context.
	 */
	void (*usage_for_add)(void);

	/* deinitialize this target */
	void (*deinit_tgt)(struct ublksrv_dev *);

	void *(*alloc_io_buf)(struct ublksrv_queue *q, int tag, int size);
	void (*free_io_buf)(struct ublksrv_queue *q, void *buf, int tag);
};

struct ublksrv_dev {
	struct ublksrv_tgt_info tgt;

	struct ublksrv_queue *__queues[MAX_NR_HW_QUEUES];
	char	*io_buf_start;
	pthread_t *thread;
	int cdev_fd;

	const struct ublksrv_ctrl_dev *ctrl_dev;
	void	*target_data;
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

extern void ublksrv_ctrl_deinit(struct ublksrv_ctrl_dev *dev);
extern struct ublksrv_ctrl_dev *ublksrv_ctrl_init(struct ublksrv_dev_data *data);
extern int ublksrv_ctrl_get_affinity(struct ublksrv_ctrl_dev *ctrl_dev);
extern int ublksrv_ctrl_add_dev(struct ublksrv_ctrl_dev *dev);
extern int ublksrv_ctrl_del_dev(struct ublksrv_ctrl_dev *dev);
extern int ublksrv_ctrl_get_info(struct ublksrv_ctrl_dev *dev);
extern int ublksrv_ctrl_stop_dev(struct ublksrv_ctrl_dev *dev);
extern void ublksrv_ctrl_dump(struct ublksrv_ctrl_dev *dev);
extern int ublksrv_ctrl_start_dev(struct ublksrv_ctrl_dev *ctrl_dev,
		int daemon_pid, unsigned long long dev_blocks);

extern struct ublksrv_dev *ublksrv_dev_init(const struct ublksrv_ctrl_dev *
		ctrl_dev);
extern void ublksrv_dev_deinit(struct ublksrv_dev *dev);

static inline void *ublksrv_queue_get_data(const struct ublksrv_queue *q)
{
	return q->private_data;
}

extern struct ublksrv_queue *ublksrv_queue_init(struct ublksrv_dev *dev,
		unsigned short q_id, void *queue_data);
extern void ublksrv_queue_deinit(struct ublksrv_queue *q);
extern int ublksrv_queue_handled_event(struct ublksrv_queue *q);
extern int ublksrv_queue_send_event(struct ublksrv_queue *q);

extern int ublksrv_process_io(struct ublksrv_queue *q);
extern int ublksrv_complete_io(struct ublksrv_queue *q, unsigned tag, int res);

extern int ublksrv_register_tgt_type(struct ublksrv_tgt_type *type);
extern void ublksrv_unregister_tgt_type(struct ublksrv_tgt_type *type);
extern void ublksrv_for_each_tgt_type(void (*handle_tgt_type)(unsigned idx,
			const struct ublksrv_tgt_type *type, void *data),
		void *data);

#ifdef __cplusplus
}
#endif

#endif
