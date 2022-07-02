#include "ublksrv.h"

#define CTRL_CMD_HAS_DATA	1
#define CTRL_CMD_HAS_BUF	2

struct ublksrv_ctrl_cmd_data {
	unsigned short cmd_op;
	unsigned short flags;

	__u64 data;
	__u64 addr;
	__u32 len;
};

/********************cmd handling************************/
static char *full_cmd;

static char *pop_cmd(int *argc, char *argv[])
{
	char *cmd = argv[1];
	if (*argc < 2) {
		printf("%s: missing command\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	memmove(&argv[1], &argv[2], *argc * sizeof(argv[0]));
	(*argc)--;

	full_cmd = mprintf("%s %s", full_cmd, cmd);
	return cmd;
}


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
		cmd->data[0] = data->data;
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

static void ublksrv_dev_deinit(struct ublksrv_ctrl_dev *dev)
{
	close(dev->ring.ring_fd);
	close(dev->ctrl_fd);
	free(dev->queues_cpuset);
	free(dev);
}

static struct ublksrv_ctrl_dev *ublksrv_dev_init(struct ublksrv_dev_data *data)
{
	struct ublksrv_ctrl_dev *dev = (struct ublksrv_ctrl_dev *)calloc(1,
			sizeof(*dev));
	struct ublksrv_ctrl_dev_info *info = &dev->dev_info;
	int ret;

	if (!dev)
		die("allocate dev failed\n");

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
	info->flags[0] = data->flags[0];
	info->flags[1] = data->flags[1];
	dev->bs_shift = ilog2(info->block_size);

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
static int ublksrv_get_affinity(struct ublksrv_ctrl_dev *ctrl_dev)
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
		data.data = i;
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
static int ublksrv_start_dev(struct ublksrv_ctrl_dev *ctrl_dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_START_DEV,
		.flags	= CTRL_CMD_HAS_DATA,
	};
	int cnt = 0, daemon_pid;
	int ret;

	if (ublksrv_get_affinity(ctrl_dev) < 0)
		return -1;

	switch (fork()) {
	case -1:
		return -1;
	case 0:
		ublksrv_start_io_daemon(ctrl_dev);
		break;
	}

	/* wait until daemon is started, or timeout after 3 seconds */
	do {
		daemon_pid = ublksrv_get_io_daemon_pid(ctrl_dev);
		if (daemon_pid < 0) {
			usleep(100000);
			cnt++;
		}
	} while (daemon_pid < 0 && cnt < 30);

	if (daemon_pid < 0)
		return -1;

	ctrl_dev->dev_info.ublksrv_pid = data.data = daemon_pid;
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

static int ublksrv_add_dev(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_ADD_DEV,
		.flags	= CTRL_CMD_HAS_BUF,
		.addr = (__u64)&dev->dev_info,
		.len = sizeof(struct ublksrv_ctrl_dev_info),
	};

	return __ublksrv_ctrl_cmd(dev, &data);
}

static int ublksrv_del_dev(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op = UBLK_CMD_DEL_DEV,
		.flags = 0,
	};

	return __ublksrv_ctrl_cmd(dev, &data);
}

static int ublksrv_get_dev_info(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_GET_DEV_INFO,
		.flags	= CTRL_CMD_HAS_BUF,
		.addr = (__u64)&dev->dev_info,
		.len = sizeof(struct ublksrv_ctrl_dev_info),
	};

	return __ublksrv_ctrl_cmd(dev, &data);
}

static int ublksrv_stop_dev(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_cmd_data data = {
		.cmd_op	= UBLK_CMD_STOP_DEV,
	};
	int ret;

	ret = __ublksrv_ctrl_cmd(dev, &data);
	if (ret)
		return ret;

	return ublksrv_stop_io_daemon(dev);
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

static void ublksrv_dump(struct ublksrv_ctrl_dev *dev)
{
	struct ublksrv_ctrl_dev_info *info = &dev->dev_info;
	int fd;
	char buf[64];
	char *addr;

	printf("dev id %d: nr_hw_queues %d queue_depth %d block size %d dev_capacity %lld\n",
			info->dev_id,
                        info->nr_hw_queues, info->queue_depth,
                        info->block_size, info->dev_blocks);
	printf("\tmax rq size %d daemon pid %d flags %lx state %s\n",
                        info->block_size * info->rq_max_blocks,
			info->ublksrv_pid, info->flags[0],
			ublksrv_dev_state_desc(dev));

	snprintf(buf, 64, "%s_%d", UBLKSRV_SHM_DIR, info->ublksrv_pid);
	fd = shm_open(buf, O_RDONLY, 0);
	if (fd <= 0)
		return;
	addr = (char *)mmap(NULL, UBLKSRV_SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	addr += sizeof(struct ublksrv_ctrl_dev_info);
	printf("\t%s\n", addr);
}

int cmd_dev_add(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "type",		1,	NULL, 't' },
		{ "number",		1,	NULL, 'n' },
		{ "queues",		1,	NULL, 'q' },
		{ "depth",		1,	NULL, 'd' },
		{ "zero_copy",		1,	NULL, 'z' },
		{ NULL }
	};
	struct ublksrv_dev_data data = {0};
	struct ublksrv_ctrl_dev *dev;
	char *type = NULL;
	int opt, ret, zcopy = 0;

	data.queue_depth = DEF_QD;
	data.nr_hw_queues = DEF_NR_HW_QUEUES;
	data.dev_id = -1;
	data.block_size = 512;

	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:z",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			data.dev_id = strtol(optarg, NULL, 10);
			break;
		case 't':
			type = optarg;
			break;
		case 'z':
			data.flags[0] |= 1ULL << UBLK_F_SUPPORT_ZERO_COPY;
			data.block_size = 4096;
			break;
		case 'q':
			data.nr_hw_queues = strtol(optarg, NULL, 10);
			break;
		case 'd':
			data.queue_depth = strtol(optarg, NULL, 10);
			break;
		}
	}
	data.rq_max_blocks = DEF_BUF_SIZE / data.block_size;
	if (data.nr_hw_queues > MAX_NR_HW_QUEUES)
		data.nr_hw_queues = MAX_NR_HW_QUEUES;
	if (data.queue_depth > MAX_QD)
		data.queue_depth = MAX_QD;

	dev = ublksrv_dev_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		return -ENODEV;
	}

	optind = 0;	/* so that tgt code can parse their arguments */
	ret = ublksrv_tgt_init(&dev->tgt, type, NULL, argc, argv);
	if (ret) {
		fprintf(stderr, "can't init tgt %d, ret %d\n", data.dev_id, ret);
		goto fail_deinit_tgt;
	}

	ret = ublksrv_add_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "can't add dev %d, ret %d\n", data.dev_id, ret);
		goto fail;
	}

	ret = ublksrv_start_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "start dev failed %d, ret %d\n", data.dev_id,
				ret);
		ublksrv_del_dev(dev);
		goto fail;
	}
	ret = ublksrv_get_dev_info(dev);
	ublksrv_dump(dev);

 fail_deinit_tgt:
	ublksrv_tgt_deinit(&dev->tgt, NULL);

 fail:
	ublksrv_dev_deinit(dev);

	return ret;
}

struct tgt_types_name {
	char names[4096];
	unsigned pos;
};

static void collect_tgt_types(unsigned int idx,
		const struct ublksrv_tgt_type *type, void *pdata)
{
	struct tgt_types_name *data = (struct tgt_types_name *)pdata;

	if (idx > 0)
		data->pos += snprintf(data->names + data->pos,
				4096 - data->pos, "|");
	data->pos += snprintf(data->names + data->pos, 4096 - data->pos,
			"%s", type->name);
}

static void show_tgt_add_usage(unsigned int idx,
		const struct ublksrv_tgt_type *type, void *data)
{
	if (type->usage_for_add)
		type->usage_for_add();
}

static void cmd_dev_add_usage(char *cmd)
{
	struct tgt_types_name data = {
		.pos = 0,
	};

	data.pos += snprintf(data.names + data.pos, 4096 - data.pos, "{");
	ublksrv_for_each_tgt_type(collect_tgt_types, &data);
	data.pos += snprintf(data.names + data.pos, 4096 - data.pos, "}");

	printf("%s add -t %s -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH\n", cmd, data.names);
	ublksrv_for_each_tgt_type(show_tgt_add_usage, NULL);
}

static int __cmd_dev_del(int number, bool log)
{
	struct ublksrv_ctrl_dev *dev;
	int ret;
	struct ublksrv_dev_data data = {
		.dev_id = number,
	};

	dev = ublksrv_dev_init(&data);

	ret = ublksrv_get_dev_info(dev);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d\n", number);
		goto fail;
	}

	ret = ublksrv_stop_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "stop dev %d failed\n", number);
		goto fail;
	}

	ret = ublksrv_del_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "delete dev %d failed\n", number);
		goto fail;
	}

fail:
	ublksrv_dev_deinit(dev);
	return ret;
}

int cmd_dev_del(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		1,	NULL, 'n' },
		{ "all",		0,	NULL, 'a' },
		{ NULL }
	};
	struct ublksrv_ctrl_dev *dev;
	int number = -1;
	int opt, ret, i;

	while ((opt = getopt_long(argc, argv, "n:a",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			break;

		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		}
	}

	if (number >= 0)
		return __cmd_dev_del(number, true);

	for (i = 0; i < MAX_NR_UBLK_DEVS; i++)
		ret = __cmd_dev_del(i, false);

	return ret;
}

static void cmd_dev_del_usage(char *cmd)
{
	printf("%s del -n DEV_ID [-a | --all]\n", cmd);
}

static int list_one_dev(int number, bool log)
{
	struct ublksrv_dev_data data = {
		.dev_id = number,
	};
	struct ublksrv_ctrl_dev *dev = ublksrv_dev_init(&data);
	int ret;

	ret = ublksrv_get_dev_info(dev);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d\n", number);
	} else
		ublksrv_dump(dev);

	ublksrv_dev_deinit(dev);

	return ret;
}

int cmd_list_dev_info(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		0,	NULL, 'n' },
		{ NULL }
	};
	struct ublksrv_ctrl_dev *dev;
	int number = -1;
	int opt, ret, i;

	while ((opt = getopt_long(argc, argv, "n:",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		}
	}

	if (number >= 0)
		return list_one_dev(number, true);

	for (i = 0; i < MAX_NR_UBLK_DEVS; i++)
		list_one_dev(i, false);

	return ret;
}

static void cmd_dev_list_usage(char *cmd)
{
	printf("%s list [-n DEV_ID]\n", cmd);
}

int main(int argc, char *argv[])
{
	char *cmd;
	int ret;
	char exe[256];

	full_cmd = argv[0];
	strncpy(exe, full_cmd, 256);

	setvbuf(stdout, NULL, _IOLBF, 0);

	cmd = pop_cmd(&argc, argv);

	if (!strcmp(cmd, "add"))
		ret = cmd_dev_add(argc, argv);
	if (!strcmp(cmd, "del"))
		ret = cmd_dev_del(argc, argv);
	if (!strcmp(cmd, "list"))
		ret = cmd_list_dev_info(argc, argv);

	if (!strcmp(cmd, "help")) {
		cmd_dev_add_usage(exe);
		cmd_dev_del_usage(exe);
		cmd_dev_list_usage(exe);
	}

	ublksrv_printf(stdout, "cmd %s: result %d\n", cmd, ret);

	return ret;
}
