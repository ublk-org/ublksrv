// SPDX-License-Identifier: MIT or LGPL-2.1-only

#include <config.h>

#include "ublksrv_priv.h"

#define	CTRL_DEV	"/dev/ublk-control"

#define CTRL_CMD_HAS_DATA	1
#define CTRL_CMD_HAS_BUF	2
#define CTRL_CMD_NO_TRANS	4

struct ublksrv_ctrl_cmd_data {
	unsigned int cmd_op;
	unsigned short flags;
	unsigned short _pad;

	__u64 data[1];
	__u16 dev_path_len;
	__u16 pad;
	__u32 reserved;

	__u64 addr;
	__u32 len;
};

#define ublk_un_privileged_prep_data(dev, data)	 \
	char buf[UBLKC_PATH_MAX];			\
	if (ublk_is_unprivileged(dev)) {			\
		snprintf(buf, UBLKC_PATH_MAX, "%s%d", UBLKC_DEV, \
			dev->dev_info.dev_id);			\
		data.flags |= CTRL_CMD_HAS_BUF | CTRL_CMD_HAS_DATA;	\
		data.len = sizeof(buf);	\
		data.dev_path_len = UBLKC_PATH_MAX;	\
		data.addr = (__u64)buf;	\
	}

static const unsigned int ctrl_cmd_op[] = {
	[UBLK_CMD_GET_QUEUE_AFFINITY]	= UBLK_U_CMD_GET_QUEUE_AFFINITY,
	[UBLK_CMD_GET_DEV_INFO]		= UBLK_U_CMD_GET_DEV_INFO,
	[UBLK_CMD_ADD_DEV]		= UBLK_U_CMD_ADD_DEV,
	[UBLK_CMD_DEL_DEV]		= UBLK_U_CMD_DEL_DEV,
	[UBLK_CMD_START_DEV]		= UBLK_U_CMD_START_DEV,
	[UBLK_CMD_STOP_DEV]		= UBLK_U_CMD_STOP_DEV,
	[UBLK_CMD_SET_PARAMS]		= UBLK_U_CMD_SET_PARAMS,
	[UBLK_CMD_GET_PARAMS]		= UBLK_U_CMD_GET_PARAMS,
	[UBLK_CMD_START_USER_RECOVERY]	= UBLK_U_CMD_START_USER_RECOVERY,
	[UBLK_CMD_END_USER_RECOVERY]	= UBLK_U_CMD_END_USER_RECOVERY,
	[UBLK_CMD_GET_DEV_INFO2]	= UBLK_U_CMD_GET_DEV_INFO2,
};

static unsigned int legacy_op_to_ioctl(unsigned int op)
{
	assert(_IOC_TYPE(op) == 0);
	assert(_IOC_DIR(op) == 0);
	assert(_IOC_SIZE(op) == 0);
	assert(op >= UBLK_CMD_GET_QUEUE_AFFINITY &&
			op <= UBLK_CMD_GET_DEV_INFO2);

	return ctrl_cmd_op[op];
}


/*******************ctrl dev operation ********************************/
static inline void ublksrv_ctrl_init_cmd(struct ublksrv_ctrl_dev *dev,
		struct io_uring_sqe *sqe,
		struct ublksrv_ctrl_cmd_data *data)
{
	struct ublksrv_ctrl_dev_info *info = &dev->dev_info;
	struct ublksrv_ctrl_cmd *cmd = (struct ublksrv_ctrl_cmd *)ublksrv_get_sqe_cmd(sqe);
	unsigned int cmd_op = data->cmd_op;

	sqe->fd = dev->ctrl_fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->ioprio = 0;

	if (data->flags & CTRL_CMD_HAS_BUF) {
		cmd->addr = data->addr;
		cmd->len = data->len;
	}

	if (data->flags & CTRL_CMD_HAS_DATA) {
		cmd->data[0] = data->data[0];
		cmd->dev_path_len = data->dev_path_len;
	}

	cmd->dev_id = info->dev_id;
	cmd->queue_id = -1;

	if (!(data->flags & CTRL_CMD_NO_TRANS) &&
			(info->flags & UBLK_F_CMD_IOCTL_ENCODE))
		cmd_op = legacy_op_to_ioctl(cmd_op);
	ublksrv_set_sqe_cmd_op(sqe, cmd_op);

	io_uring_sqe_set_data(sqe, cmd);

	ublk_ctrl_dbg(UBLK_DBG_CTRL_CMD, "dev %d cmd_op %x/%x, user_data %p\n",
			dev->dev_info.dev_id, data->cmd_op, cmd_op, cmd);
}

static int __ublksrv_ctrl_cmd(struct ublksrv_ctrl_dev *dev,
		struct ublksrv_ctrl_cmd_data *data)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret = -EINVAL;

	sqe = io_uring_get_sqe(&dev->ring);
	if (!sqe) {
		fprintf(stderr, "can't get sqe ret %d\n", ret);
		return ret;
	}

	ublksrv_ctrl_init_cmd(dev, sqe, data);

	ret = io_uring_submit(&dev->ring);
	if (ret < 0) {
		fprintf(stderr, "uring submit ret %d\n", ret);
		return ret;
	}

	ret = io_uring_wait_cqe(&dev->ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait cqe: %s\n", strerror(-ret));
		return ret;
	}
	io_uring_cqe_seen(&dev->ring, cqe);

	ublk_ctrl_dbg(UBLK_DBG_CTRL_CMD, "dev %d, ctrl cqe res %d, user_data %llx\n",
			dev->dev_info.dev_id, cqe->res, cqe->user_data);
	return cqe->res;
}

void ublksrv_ctrl_deinit(struct ublksrv_ctrl_dev *dev)
{
	close(dev->ring.ring_fd);
	close(dev->ctrl_fd);
	free(dev->queues_cpuset);
	free(dev);
}

struct ublksrv_ctrl_dev *ublksrv_ctrl_init(struct ublksrv_dev_data *data)
{
	struct ublksrv_ctrl_dev *dev = (struct ublksrv_ctrl_dev *)calloc(1,
			sizeof(*dev));
	struct ublksrv_ctrl_dev_info *info = &dev->dev_info;
	int ret;

	dev->ctrl_fd = open(CTRL_DEV, O_RDWR);
	if (dev->ctrl_fd < 0) {
		fprintf(stderr, "control dev %s can't be opened: %m\n", CTRL_DEV);
		exit(dev->ctrl_fd);
	}

	/* -1 means we ask ublk driver to allocate one free to us */
	info->dev_id = data->dev_id;
	info->nr_hw_queues = data->nr_hw_queues;
	info->queue_depth = data->queue_depth;
	info->max_io_buf_bytes = data->max_io_buf_bytes;
	info->flags = data->flags;
	info->ublksrv_flags = data->ublksrv_flags;

	dev->run_dir = data->run_dir;
	dev->tgt_type = data->tgt_type;
	dev->tgt_ops = data->tgt_ops;
	dev->tgt_argc = data->tgt_argc;
	dev->tgt_argv = data->tgt_argv;

	/* 32 is enough to send ctrl commands */
	ret = ublksrv_setup_ring(&dev->ring, 32, 32, IORING_SETUP_SQE128);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		free(dev);
		return NULL;
	}

	return dev;
}

/* queues_cpuset is only used for setting up queue pthread daemon */
int ublksrv_ctrl_get_affinity(struct ublksrv_ctrl_dev *ctrl_dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_GET_QUEUE_AFFINITY,
		.flags	= CTRL_CMD_HAS_DATA | CTRL_CMD_HAS_BUF,
	};
	unsigned char *buf;
	int i, ret;
	int len;
	int path_len;

	if (ublk_is_unprivileged(ctrl_dev))
		path_len = UBLKC_PATH_MAX;
	else
		path_len = 0;

	len = (sizeof(cpu_set_t) + path_len) * ctrl_dev->dev_info.nr_hw_queues;
	buf = malloc(len);

	if (!buf)
		return -ENOMEM;

	for (i = 0; i < ctrl_dev->dev_info.nr_hw_queues; i++) {
		data.data[0] = i;
		data.dev_path_len = path_len;
		data.len = sizeof(cpu_set_t) + path_len;
		data.addr = (__u64)&buf[i * data.len];

		if (path_len)
			snprintf((char *)data.addr, UBLKC_PATH_MAX, "%s%d",
					UBLKC_DEV, ctrl_dev->dev_info.dev_id);

		ret = __ublksrv_ctrl_cmd(ctrl_dev, &data);
		if (ret < 0) {
			free(buf);
			return ret;
		}
	}
	ctrl_dev->queues_cpuset = (cpu_set_t *)buf;

	return 0;
}

/*
 * Start the ublksrv device:
 *
 * 1) fork a daemon for handling IO command from driver
 *
 * 2) wait for the device becoming ready: the daemon should submit
 * sqes to /dev/ublkcN, just like usb's urb usage, each request needs
 * one sqe. If one IO request comes to kernel driver of /dev/ublkbN,
 * the sqe for this request is completed, and the daemon gets notified.
 * When every io request of driver gets its own sqe queued, we think
 * /dev/ublkbN is ready to start
 *
 * 3) in current process context, sent START_DEV command to
 * /dev/ublk-control with device id, which will cause ublk driver to
 * expose /dev/ublkbN
 */
int ublksrv_ctrl_start_dev(struct ublksrv_ctrl_dev *ctrl_dev,
		int daemon_pid)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_START_DEV,
		.flags	= CTRL_CMD_HAS_DATA,
	};
	int ret;

	ublk_un_privileged_prep_data(ctrl_dev, data);

	ctrl_dev->dev_info.ublksrv_pid = data.data[0] = daemon_pid;

	ret = __ublksrv_ctrl_cmd(ctrl_dev, &data);

	return ret;
}

/*
 * Stop the ublksrv device:
 *
 * 1) send STOP_DEV command to /dev/ublk-control with device id provided
 *
 * 2) ublk driver gets this command, freeze /dev/ublkbN, then complete all
 * pending seq, meantime tell the daemon via cqe->res to not submit sqe
 * any more, since we are being closed. Also delete /dev/ublkbN.
 *
 * 3) the ublk daemon figures out that all sqes are completed, and free,
 * then close /dev/ublkcN and exit itself.
 */
static int __ublksrv_ctrl_add_dev(struct ublksrv_ctrl_dev *dev, unsigned cmd_op)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= cmd_op,
		.flags	= CTRL_CMD_HAS_BUF | CTRL_CMD_NO_TRANS,
		.addr = (__u64)&dev->dev_info,
		.len = sizeof(struct ublksrv_ctrl_dev_info),
	};

	return __ublksrv_ctrl_cmd(dev, &data);
}

int ublksrv_ctrl_add_dev(struct ublksrv_ctrl_dev *dev)
{
	int ret = __ublksrv_ctrl_add_dev(dev, UBLK_U_CMD_ADD_DEV);

	if (ret < 0)
		return __ublksrv_ctrl_add_dev(dev, UBLK_CMD_ADD_DEV);

	return ret;
}

int ublksrv_ctrl_del_dev(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op = UBLK_CMD_DEL_DEV,
		.flags = 0,
	};

	ublk_un_privileged_prep_data(dev, data);

	return __ublksrv_ctrl_cmd(dev, &data);
}

static int __ublksrv_ctrl_get_info_no_trans(struct ublksrv_ctrl_dev *dev,
		unsigned cmd_op)
{
	char buf[UBLKC_PATH_MAX + sizeof(dev->dev_info)];
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= cmd_op,
		.flags	= CTRL_CMD_HAS_BUF | CTRL_CMD_NO_TRANS,
		.addr = (__u64)&dev->dev_info,
		.len = sizeof(struct ublksrv_ctrl_dev_info),
	};
	bool has_dev_path = false;
	int ret;

	if (ublk_is_unprivileged(dev) && _IOC_NR(data.cmd_op) == UBLK_CMD_GET_DEV_INFO)
		return -EINVAL;

	if (_IOC_NR(data.cmd_op) == UBLK_CMD_GET_DEV_INFO2) {
		snprintf(buf, UBLKC_PATH_MAX, "%s%d", UBLKC_DEV,
			dev->dev_info.dev_id);
		data.flags |= CTRL_CMD_HAS_BUF | CTRL_CMD_HAS_DATA;
		data.len = sizeof(buf);
		data.dev_path_len = UBLKC_PATH_MAX;
		data.addr = (__u64)buf;
		has_dev_path = true;
	}

	ret = __ublksrv_ctrl_cmd(dev, &data);
	if (ret >= 0 && has_dev_path)
		memcpy(&dev->dev_info, &buf[UBLKC_PATH_MAX],
				sizeof(dev->dev_info));
	return ret;
}

static int __ublksrv_ctrl_get_info(struct ublksrv_ctrl_dev *dev,
		unsigned cmd_op)
{
	unsigned new_code = legacy_op_to_ioctl(cmd_op);
	int ret = __ublksrv_ctrl_get_info_no_trans(dev, new_code);

	/*
	 * Try ioctl cmd encoding first, then fallback to legacy command
	 * opcode if ioctl encoding fails
	 */
	if (ret < 0)
		ret = __ublksrv_ctrl_get_info_no_trans(dev, cmd_op);

	return ret;
}

/*
 * Deal with userspace/kernel compatibility
 *
 * 1) if kernel is capable of handling UBLK_F_UNPRIVILEGED_DEV,
 * - ublksrv supports UBLK_F_UNPRIVILEGED_DEV
 *   ublksrv should send UBLK_CMD_GET_DEV_INFO2, given anytime unprivileged
 *   application needs to query devices it owns, when the application has
 *   no idea if UBLK_F_UNPRIVILEGED_DEV is set given the capability info
 *   is stateless, and application always get it via control command
 *
 * - ublksrv doesn't support UBLK_F_UNPRIVILEGED_DEV
 *   UBLK_CMD_GET_DEV_INFO is always sent to kernel, and the feature of
 *   UBLK_F_UNPRIVILEGED_DEV isn't available for user
 *
 * 2) if kernel isn't capable of handling UBLK_F_UNPRIVILEGED_DEV
 * - ublksrv supports UBLK_F_UNPRIVILEGED_DEV
 *   UBLK_CMD_GET_DEV_INFO2 is tried first, and will be failed, then
 *   UBLK_CMD_GET_DEV_INFO is retried given UBLK_F_UNPRIVILEGED_DEV
 *   can't be set
 *
 * - ublksrv doesn't support UBLK_F_UNPRIVILEGED_DEV
 *   UBLK_CMD_GET_DEV_INFO is always sent to kernel, and the feature of
 *   UBLK_F_UNPRIVILEGED_DEV isn't available for user
 *
 */
int ublksrv_ctrl_get_info(struct ublksrv_ctrl_dev *dev)
{
	int ret;

	unsigned cmd_op	=
#ifdef UBLK_CMD_GET_DEV_INFO2
		UBLK_CMD_GET_DEV_INFO2;
#else
		UBLK_CMD_GET_DEV_INFO;
#endif
	ret = __ublksrv_ctrl_get_info(dev, cmd_op);

	if (cmd_op == UBLK_CMD_GET_DEV_INFO)
		return ret;

	if (ret < 0) {
		/* unprivileged does support GET_DEV_INFO2 */
		if (ublk_is_unprivileged(dev))
			return ret;
		/*
		 * fallback to GET_DEV_INFO since driver may not support
		 * GET_DEV_INFO2
		 */
		ret = __ublksrv_ctrl_get_info(dev, UBLK_CMD_GET_DEV_INFO);
	}

	return ret;
}

int ublksrv_ctrl_stop_dev(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_STOP_DEV,
	};
	int ret;

	ublk_un_privileged_prep_data(dev, data);

	ret = __ublksrv_ctrl_cmd(dev, &data);
	return ret;
}

static const char *ublksrv_dev_state_desc(struct ublksrv_ctrl_dev *dev)
{
	switch (dev->dev_info.state) {
	case UBLK_S_DEV_DEAD:
		return "DEAD";
	case UBLK_S_DEV_LIVE:
		return "LIVE";
	case UBLK_S_DEV_QUIESCED:
		return "QUIESCED";
	default:
		return "UNKNOWN";
	};
}

void ublksrv_ctrl_dump(struct ublksrv_ctrl_dev *dev, const char *jbuf)
{
	struct ublksrv_ctrl_dev_info *info = &dev->dev_info;
	int i, ret;
	struct ublk_params p;

	ret = ublksrv_ctrl_get_params(dev, &p);
	if (ret < 0) {
		fprintf(stderr, "failed to get params %m\n");
		return;
	}

	printf("dev id %d: nr_hw_queues %d queue_depth %d block size %d dev_capacity %lld\n",
			info->dev_id,
                        info->nr_hw_queues, info->queue_depth,
                        1 << p.basic.logical_bs_shift, p.basic.dev_sectors);
	printf("\tmax rq size %d daemon pid %d flags 0x%llx state %s\n",
                        info->max_io_buf_bytes,
			info->ublksrv_pid, info->flags,
			ublksrv_dev_state_desc(dev));
	printf("\tublkc: %u:%d ublkb: %u:%u owner: %u:%u\n",
			p.devt.char_major, p.devt.char_minor,
			p.devt.disk_major, p.devt.disk_minor,
			info->owner_uid, info->owner_gid);

	if (jbuf) {
		char buf[512];

		for(i = 0; i < info->nr_hw_queues; i++) {
			unsigned tid;

			ublksrv_json_read_queue_info(jbuf, i, &tid, buf, 512);
			printf("\tqueue %u: tid %d affinity(%s)\n",
					i, tid, buf);
		}

		ublksrv_json_read_target_info(jbuf, buf, 512);
		printf("\ttarget %s\n", buf);
	}
}

int ublksrv_ctrl_set_params(struct ublksrv_ctrl_dev *dev,
		struct ublk_params *params)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_SET_PARAMS,
		.flags	= CTRL_CMD_HAS_BUF,
		.addr = (__u64)params,
		.len = sizeof(*params),
	};
	char buf[UBLKC_PATH_MAX + sizeof(*params)];

	params->len = sizeof(*params);

	if (ublk_is_unprivileged(dev)) {
		snprintf(buf, UBLKC_PATH_MAX, "%s%d", UBLKC_DEV,
			dev->dev_info.dev_id);
		memcpy(&buf[UBLKC_PATH_MAX], params, sizeof(*params));
		data.flags |= CTRL_CMD_HAS_BUF | CTRL_CMD_HAS_DATA;
		data.len = sizeof(buf);
		data.dev_path_len = UBLKC_PATH_MAX;
		data.addr = (__u64)buf;
	}

	return __ublksrv_ctrl_cmd(dev, &data);
}

int ublksrv_ctrl_get_params(struct ublksrv_ctrl_dev *dev,
		struct ublk_params *params)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_GET_PARAMS,
		.flags	= CTRL_CMD_HAS_BUF,
		.addr = (__u64)params,
		.len = sizeof(*params),
	};
	char buf[UBLKC_PATH_MAX + sizeof(*params)];
	int ret;

	params->len = sizeof(*params);

	if (ublk_is_unprivileged(dev)) {
		snprintf(buf, UBLKC_PATH_MAX, "%s%d", UBLKC_DEV,
			dev->dev_info.dev_id);
		memcpy(&buf[UBLKC_PATH_MAX], params, sizeof(*params));
		data.flags |= CTRL_CMD_HAS_BUF | CTRL_CMD_HAS_DATA;
		data.len = sizeof(buf);
		data.dev_path_len = UBLKC_PATH_MAX;
		data.addr = (__u64)buf;
	}

	ret = __ublksrv_ctrl_cmd(dev, &data);
	if (ret >= 0 && ublk_is_unprivileged(dev))
		memcpy(params, &buf[UBLKC_PATH_MAX], sizeof(*params));

	return 0;
}

int ublksrv_ctrl_start_recovery(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_START_USER_RECOVERY,
		.flags = 0,
	};
	int ret;

	ublk_un_privileged_prep_data(dev, data);

	ret = __ublksrv_ctrl_cmd(dev, &data);
	return ret;
}

int ublksrv_ctrl_end_recovery(struct ublksrv_ctrl_dev *dev, int daemon_pid)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_END_USER_RECOVERY,
		.flags = CTRL_CMD_HAS_DATA,
	};
	int ret;

	ublk_un_privileged_prep_data(dev, data);

	dev->dev_info.ublksrv_pid = data.data[0] = daemon_pid;

	ret = __ublksrv_ctrl_cmd(dev, &data);
	return ret;
}

int ublksrv_ctrl_get_features(struct ublksrv_ctrl_dev *dev,
		__u64 *features)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_U_CMD_GET_FEATURES,
		.flags	= CTRL_CMD_HAS_BUF,
		.addr = (__u64)features,
		.len = sizeof(*features),
	};

	return __ublksrv_ctrl_cmd(dev, &data);
}

const struct ublksrv_ctrl_dev_info *ublksrv_ctrl_get_dev_info(
		const struct ublksrv_ctrl_dev *dev)
{
	return &dev->dev_info;
}

const char *ublksrv_ctrl_get_run_dir(const struct ublksrv_ctrl_dev *dev)
{
	return dev->run_dir;
}

void ublksrv_ctrl_prep_recovery(struct ublksrv_ctrl_dev *dev,
		const char *tgt_type, const struct ublksrv_tgt_type *tgt_ops,
		const char *recovery_jbuf)
{
	dev->tgt_type = tgt_type;
	dev->tgt_ops = tgt_ops;
	dev->recovery_jbuf = recovery_jbuf;
}

const char *ublksrv_ctrl_get_recovery_jbuf(const struct ublksrv_ctrl_dev *dev)
{
	return dev->recovery_jbuf;
}
