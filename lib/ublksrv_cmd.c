#include "ublksrv_priv.h"

#define	CTRL_DEV	"/dev/ublk-control"

#define CTRL_CMD_HAS_DATA	1
#define CTRL_CMD_HAS_BUF	2

struct ublksrv_ctrl_cmd_data {
	unsigned short cmd_op;
	unsigned short flags;

	__u64 data[2];
	__u64 addr;
	__u32 len;
};

/*******************ctrl dev operation ********************************/
static inline void ublksrv_ctrl_init_cmd(struct ublksrv_ctrl_dev *dev,
		struct io_uring_sqe *sqe,
		struct ublksrv_ctrl_cmd_data *data)
{
	struct ublksrv_ctrl_dev_info *info = &dev->dev_info;
	struct ublksrv_ctrl_cmd *cmd = (struct ublksrv_ctrl_cmd *)ublksrv_get_sqe_cmd(sqe);

	sqe->fd = dev->ctrl_fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->ioprio = 0;

	if (data->flags & CTRL_CMD_HAS_BUF) {
		cmd->addr = data->addr;
		cmd->len = data->len;
	}

	if (data->flags & CTRL_CMD_HAS_DATA) {
		cmd->data[0] = data->data[0];
		cmd->data[1] = data->data[1];
	}

	cmd->dev_id = info->dev_id;
	cmd->queue_id = -1;

	ublksrv_set_sqe_cmd_op(sqe, data->cmd_op);

	io_uring_sqe_set_data(sqe, cmd);

	ublksrv_printf(stdout, "dev %d cmd_op %u, user_data %llx\n",
			dev->dev_info.dev_id, data->cmd_op, cmd);
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

	ublksrv_printf(stdout, "dev %d, ctrl cqe res %d, user_data %llx\n",
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
		fprintf(stderr, "conrol dev %s can't be opened\n", CTRL_DEV);
		exit(dev->ctrl_fd);
	}

	/* -1 means we ask ublk driver to allocate one free to us */
	info->dev_id = data->dev_id;
	info->nr_hw_queues = data->nr_hw_queues;
	info->queue_depth = data->queue_depth;
	info->block_size = data->block_size;
	info->rq_max_blocks = data->rq_max_blocks;
	info->flags = data->flags;
	info->ublksrv_flags = data->ublksrv_flags;
	dev->bs_shift = ilog2(info->block_size);

	dev->run_dir = data->run_dir;
	dev->tgt_type = data->tgt_type;
	dev->tgt_ops = data->tgt_ops;
	dev->tgt_argc = data->tgt_argc;
	dev->tgt_argv = data->tgt_argv;

	/* 32 is enough to send ctrl commands */
	ret = ublksrv_setup_ring(32, &dev->ring, IORING_SETUP_SQE128);
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
	cpu_set_t *sets;
	int i;

	sets = (cpu_set_t *)calloc(sizeof(cpu_set_t), ctrl_dev->dev_info.nr_hw_queues);
	if (!sets)
		return -1;

	for (i = 0; i < ctrl_dev->dev_info.nr_hw_queues; i++) {
		data.data[0] = i;
		data.data[1] = 0;
		data.addr = (__u64)&sets[i];
		data.len = sizeof(cpu_set_t);

		if (__ublksrv_ctrl_cmd(ctrl_dev, &data) < 0) {
			free(sets);
			return -1;
		}
	}
	ctrl_dev->queues_cpuset = sets;

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
		int daemon_pid, unsigned long long dev_blocks)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_START_DEV,
		.flags	= CTRL_CMD_HAS_DATA,
	};
	int ret;

	ctrl_dev->dev_info.ublksrv_pid = data.data[0] = daemon_pid;
	ctrl_dev->dev_info.dev_blocks = data.data[1] = dev_blocks;

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
int ublksrv_ctrl_add_dev(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_ADD_DEV,
		.flags	= CTRL_CMD_HAS_BUF,
		.addr = (__u64)&dev->dev_info,
		.len = sizeof(struct ublksrv_ctrl_dev_info),
	};

	return __ublksrv_ctrl_cmd(dev, &data);
}

int ublksrv_ctrl_del_dev(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op = UBLK_CMD_DEL_DEV,
		.flags = 0,
	};

	return __ublksrv_ctrl_cmd(dev, &data);
}

int ublksrv_ctrl_get_info(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_GET_DEV_INFO,
		.flags	= CTRL_CMD_HAS_BUF,
		.addr = (__u64)&dev->dev_info,
		.len = sizeof(struct ublksrv_ctrl_dev_info),
	};

	return __ublksrv_ctrl_cmd(dev, &data);
}

int ublksrv_ctrl_stop_dev(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_STOP_DEV,
	};
	int ret;

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
	default:
		return "UNKNOWN";
	};
}

void ublksrv_ctrl_dump(struct ublksrv_ctrl_dev *dev, const char *jbuf)
{
	struct ublksrv_ctrl_dev_info *info = &dev->dev_info;
	int i;

	printf("dev id %d: nr_hw_queues %d queue_depth %d block size %d dev_capacity %lld\n",
			info->dev_id,
                        info->nr_hw_queues, info->queue_depth,
                        info->block_size, info->dev_blocks);
	printf("\tmax rq size %d daemon pid %d flags 0x%llx state %s\n",
                        info->block_size * info->rq_max_blocks,
			info->ublksrv_pid, info->flags,
			ublksrv_dev_state_desc(dev));

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
