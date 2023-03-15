// SPDX-License-Identifier: MIT or LGPL-2.1-only

#ifndef UBLKSRV_INC_H
#define UBLKSRV_INC_H

#include <stdbool.h>
#include <assert.h>

#include "liburing.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "ublk_cmd.h"

#define	MAX_NR_HW_QUEUES 32
#define	MAX_QD		UBLK_MAX_QUEUE_DEPTH
#define	MAX_BUF_SIZE    (32U << 20)

#define	DEF_NR_HW_QUEUES 1
#define	DEF_QD		128
#define	DEF_BUF_SIZE	(512 << 10)

/************ stored in ublksrv_ctrl_dev_info->ublksrv_flags *******/
/*
 * target may not use io_uring for handling io, so eventfd is required
 * for wakeup io command io_uring context
 */
#define UBLKSRV_F_NEED_EVENTFD		(1UL << 1)

struct io_uring;
struct io_uring_cqe;
struct ublksrv_aio_ctx;
struct ublksrv_ctrl_dev;

/**
 * Generic data for creating one ublk control device, which is used for
 * sending control commands to /dev/ublk-control.
 *
 * Control commands(UBLK_CMD_*) are defined in ublk_cmd.h.
 */
struct ublksrv_dev_data {
	int		dev_id;
	unsigned	max_io_buf_bytes;
	unsigned short	nr_hw_queues;
	unsigned short	queue_depth;
	const char	*tgt_type;
	const struct ublksrv_tgt_type *tgt_ops;
	int		tgt_argc;
	char		**tgt_argv;
	const char	*run_dir;
	unsigned long	flags;
	unsigned long	ublksrv_flags;
	unsigned long   reserved[7];
};

/**
 * IO data passed to target io handling callbacks, such as
 * ->handle_io_async() and ->tgt_io_done().
 */
struct ublk_io_data {
	/** tag of this io data, unique in queue wide */
	int tag;
	unsigned int pad;

	/** io description from ublk driver */
	const struct ublksrv_io_desc *iod;

	/**
	 * IO private data, created in ublksrv_queue_init(),
	 * data size is specified in ublksrv_tgt_info.io_data_size
	 */
	void *private_data;
};

/* queue state is only retrieved via ublksrv_queue_state() API */
#define UBLKSRV_QUEUE_STOPPING	(1U << 0)
#define UBLKSRV_QUEUE_IDLE	(1U << 1)

/**
 * ublksrv_queue is 1:1 mapping with ublk driver's blk-mq queue, and
 * has same queue depth with ublk driver's blk-mq queue.
 */
struct ublksrv_queue {
	/** queue id */
	int q_id;

	/** So far, all queues in same device has same depth */
	int q_depth;

	/** io uring for handling io commands() from ublk driver */
	struct io_uring *ring_ptr;

	/** which device this queue belongs to */
	const struct ublksrv_dev *dev;

	/** queue's private data, passed from ublksrv_queue_init() */
	void *private_data;
};

struct ublksrv_tgt_type;

#define  UBLKSRV_TGT_MAX_FDS	32

/**
 *
 * ublksrv_tgt_info: target data
 *
 */
struct ublksrv_tgt_info {
	/** device size */
	unsigned long long dev_size;

	/**
	 * target ring depth, for handling target IOs
	 */
	unsigned int tgt_ring_depth;

	/** how many FDs regisgered */
	unsigned int nr_fds;

	/** file descriptor table */
	int fds[UBLKSRV_TGT_MAX_FDS];

	/** target private data */
	void *tgt_data;

	/**
	 * Extra IO slots for each queue, target code can reserve some
	 * slots for handling internal IO, such as meta data IO, then
	 * ublk_io instances can be assigned for these extra IOs.
	 *
	 * IO slot is useful for storing coroutine data which is for
	 * handling this (meta) IO.
	 */
	unsigned int extra_ios;

	/** size of io private data */
	unsigned int io_data_size;

	/**
	 * target io handling type, target main job is to implement
	 * callbacks defined in this type
	 */
	const struct ublksrv_tgt_type *ops;

	/**
	 * If target needs to override default max workers for io_uring,
	 * initialize io_wq_max_workers with proper value, otherwise
	 * keep them as zero
	 */
	unsigned int iowq_max_workers[2];

	unsigned long reserved[4];
};

/**
 * ublksrv device
 */
struct ublksrv_dev {
	/** device data */
	struct ublksrv_tgt_info tgt;
};

/**
 *
 * ublksrv_tgt_type: target type
 *
 */
struct ublksrv_tgt_type {
	/**
	 * One IO request comes from /dev/ublkbN, so notify target code
	 * for handling the IO. Inside target code, the IO can be handled
	 * with our io_uring too, if this is true, ->tgt_io_done callback
	 * has to be implemented. Otherwise, target can implement
	 * ->handle_event() for processing io completion there.
	 *
	 *  Required.
	 */
	int (*handle_io_async)(const struct ublksrv_queue *,
			const struct ublk_io_data *io);

	/**
	 * target io is handled by our io_uring, and once the target io
	 * is completed, this callback is called.
	 *
	 * Optional, only required iff this target io is handled by ublksrv's
	 * io_uring.
	 */
	void (*tgt_io_done)(const struct ublksrv_queue *,
			const struct ublk_io_data *io,
			const struct io_uring_cqe *);

	/**
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
	 *
	 * Optional. Only needed if target IO is handled by target its
	 * own pthread context.
	 */
	void (*handle_event)(const struct ublksrv_queue *);

	/**
	 * One typical use case is to flush meta data, which is usually done
	 * in background. So there isn't any tag from libublksrv for this kind
	 * of IOs, and the target code has to request for allocating extra ios
	 * by passing tgt_type->extra_ios and let this callback consume & handle
	 * these extra IOs.
	 *
	 * nr_queued_io: count of queued IOs in ublksrv_reap_events_uring of
	 * this time
	 *
	 * Optional.
	 */
	void (*handle_io_background)(const struct ublksrv_queue *, int
			nr_queued_io);

	/**
	 * show target specific command line for adding new device
	 *
	 * Be careful: this callback is the only one which is not run from
	 * ublk device daemon task context.
	 */
	void (*usage_for_add)(void);

	/**
	 * initialize this new target, argc/argv includes target specific
	 * command line parameters
	 *
	 * Required.
	 */
	int (*init_tgt)(struct ublksrv_dev *, int type, int argc,
			char *argv[]);

	/**
	 * Deinitialize this target
	 *
	 * Optional.
	 */
	void (*deinit_tgt)(const struct ublksrv_dev *);

	/**
	 * callback for allocating io buffer
	 *
	 * Optional.
	 */
	void *(*alloc_io_buf)(const struct ublksrv_queue *q, int tag, int size);
	/**
	 * callback for freeing io buffer
	 *
	 * Optional.
	 */
	void (*free_io_buf)(const struct ublksrv_queue *q, void *buf, int tag);

	/**
	 * Called when the ublksrv io_uring is idle.
	 *
	 * Optional.
	 */
	void (*idle_fn)(const struct ublksrv_queue *q, bool enter);

	/** target type */
	int  type;

	/** flags required for ublk driver */
	unsigned ublk_flags;

	/** flags required for ublksrv */
	unsigned ublksrv_flags;
	unsigned pad;

	/** target name */
	const char *name;

	/**
	 * recovery callback for this target
	 *
	 * Required.
	 */
	int (*recovery_tgt)(struct ublksrv_dev *, int type);

	/**
	 * queue_data_ptr points to address of q->priviate_data, so that
	 * we still can pass 'const struct ublksrv_queue *', meantime
	 * queue data can be stored to q->private_data via queue_data_ptr.
	 *
	 * ->init_queue provides one chance to override/init the passed
	 * "queue_data" to ublksrv_queue_init(), "queue_data" is set to
	 * q->private_data before calling ->init_queue()
	 */
	int (*init_queue)(const struct ublksrv_queue *, void **queue_data_ptr);

	/** deinit queue data, counter pair of ->init_queue */
	void (*deinit_queue)(const struct ublksrv_queue *);

	unsigned long reserved[5];
};

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

/*
 * ublksrv control device APIs, for sending control commands
 * to /dev/ublk-control
 */
extern void ublksrv_ctrl_deinit(struct ublksrv_ctrl_dev *dev);
extern struct ublksrv_ctrl_dev *ublksrv_ctrl_init(struct ublksrv_dev_data *data);
extern int ublksrv_ctrl_get_affinity(struct ublksrv_ctrl_dev *ctrl_dev);
extern int ublksrv_ctrl_add_dev(struct ublksrv_ctrl_dev *dev);
extern int ublksrv_ctrl_del_dev(struct ublksrv_ctrl_dev *dev);
extern int ublksrv_ctrl_get_info(struct ublksrv_ctrl_dev *dev);
extern int ublksrv_ctrl_stop_dev(struct ublksrv_ctrl_dev *dev);
extern void ublksrv_ctrl_dump(struct ublksrv_ctrl_dev *dev, const char *buf);
extern int ublksrv_ctrl_start_dev(struct ublksrv_ctrl_dev *ctrl_dev,
		int daemon_pid);
extern int ublksrv_ctrl_set_params(struct ublksrv_ctrl_dev *dev,
		struct ublk_params *params);
extern int ublksrv_ctrl_get_params(struct ublksrv_ctrl_dev *dev,
		struct ublk_params *params);
extern int ublksrv_ctrl_start_recovery(struct ublksrv_ctrl_dev *dev);
extern int ublksrv_ctrl_end_recovery(struct ublksrv_ctrl_dev *dev,
		int daemon_pid);
extern const struct ublksrv_ctrl_dev_info *ublksrv_ctrl_get_dev_info(
		const struct ublksrv_ctrl_dev *dev);
extern const char *ublksrv_ctrl_get_run_dir(const struct ublksrv_ctrl_dev *dev);
extern void ublksrv_ctrl_prep_recovery(struct ublksrv_ctrl_dev *dev,
		const char *tgt_type, const struct ublksrv_tgt_type *tgt_ops,
		const char *recovery_jbuf);
extern const char *ublksrv_ctrl_get_recovery_jbuf(const struct ublksrv_ctrl_dev *dev);

/* ublksrv device ("/dev/ublkcN") level APIs */
extern const struct ublksrv_dev *ublksrv_dev_init(const struct ublksrv_ctrl_dev *
		ctrl_dev);
extern void ublksrv_dev_deinit(const struct ublksrv_dev *dev);
extern const struct ublksrv_ctrl_dev *ublksrv_get_ctrl_dev(
		const struct ublksrv_dev *dev);
extern int ublksrv_get_pidfile_fd(const struct ublksrv_dev *dev);
extern void ublksrv_dev_set_cq_depth(struct ublksrv_dev *tdev, int cq_depth);
extern int ublksrv_dev_get_cq_depth(struct ublksrv_dev *tdev);

/* target json has to include the following key/value */
#define UBLKSRV_TGT_NAME_MAX_LEN 32
struct ublksrv_tgt_base_json {
	char name[UBLKSRV_TGT_NAME_MAX_LEN];
	int type;
	unsigned int pad;
	unsigned long long dev_size;
	unsigned long reserved[8];
};

/* APIs for serializing/deserializing device data to/from json string */
extern int ublksrv_json_write_dev_info(const struct ublksrv_ctrl_dev *dev,
		char *buf, int len);
extern int ublksrv_json_read_dev_info(const char *json_buf,
		struct ublksrv_ctrl_dev_info *info);
extern int ublksrv_json_write_queue_info(const struct ublksrv_ctrl_dev *dev,
		char *jbuf, int len, int qid, int ubq_daemon_tid);
extern int ublksrv_json_read_queue_info(const char *jbuf, int qid,
		unsigned *tid, char *affinity_buf, int len);
extern int ublksrv_json_read_target_info(const char *jbuf, char *tgt_buf,
		int len);
extern int ublksrv_json_read_target_str_info(const char *jbuf, int len,
		const char *name, char *val);
extern int ublksrv_json_read_target_ulong_info(const char *jbuf,
		const char *name, long *val);
extern int ublksrv_json_write_target_str_info(char *jbuf, int len,
		const char *name, const char *val);
extern int ublksrv_json_write_target_long_info(char *jbuf, int len,
		const char *name, long val);
extern int ublksrv_json_write_target_ulong_info(char *jbuf, int len,
		const char *name, unsigned long val);
extern void ublksrv_json_dump(const char *jbuf);
extern int ublksrv_json_read_target_base_info(const char *jbuf,
		struct ublksrv_tgt_base_json *tgt);
extern int ublksrv_json_write_target_base_info(char *jbuf, int len,
		const struct ublksrv_tgt_base_json *tgt);
extern int ublksrv_json_read_params(struct ublk_params *p,
		const char *jbuf);
extern int ublksrv_json_write_params(const struct ublk_params *p,
		char *jbuf, int len);
extern int ublksrv_json_dump_params(const char *jbuf);
extern int ublksrv_json_get_length(const char *jbuf);

/* ublksrv queue level APIs */
extern void *ublksrv_io_private_data(const struct ublksrv_queue *q, int tag);
extern const struct ublk_io_data *ublksrv_queue_get_io_data(
		const struct ublksrv_queue *tq, int tag);
extern unsigned int ublksrv_queue_state(const struct ublksrv_queue *q);
extern const struct ublksrv_queue *ublksrv_queue_init(const struct ublksrv_dev *dev,
		unsigned short q_id, void *queue_data);
extern void ublksrv_queue_deinit(const struct ublksrv_queue *q);
extern int ublksrv_queue_handled_event(const struct ublksrv_queue *q);
extern int ublksrv_queue_send_event(const struct ublksrv_queue *q);
extern const struct ublksrv_queue *ublksrv_get_queue(const struct ublksrv_dev *dev,
		int q_id);
extern int ublksrv_process_io(const struct ublksrv_queue *q);
extern int ublksrv_complete_io(const struct ublksrv_queue *q, unsigned tag, int res);
extern void ublksrv_apply_oom_protection(void);

#ifdef __cplusplus
}
#endif
#endif
