#include "utils.h"
#include "ubdsrv.h"

#define CTRL_CMD_HAS_DATA	1
#define CTRL_CMD_HAS_BUF	2

struct ubdsrv_ctrl_cmd_data {
	unsigned short cmd_op;
	unsigned short flags;

	__u64 data;
	__u64 addr;
	__u32 len;
};

static int ctrl_fd = -1;

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
static inline void init_cmd(struct ubdsrv_ctrl_dev *dev,
		struct io_uring_sqe *sqe,
		struct ubdsrv_ctrl_cmd_data *data)
{
	struct ubdsrv_ctrl_dev_info *info = &dev->dev_info;
	struct ubdsrv_ctrl_cmd *cmd = (struct ubdsrv_ctrl_cmd *)&sqe->cmd;

	sqe->fd = ctrl_fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->user_data = (unsigned long) -1;
	sqe->ioprio = 0;
	sqe->off = 0;

	if (data->flags & CTRL_CMD_HAS_BUF) {
		cmd->addr = data->addr;
		cmd->len = data->len;
	}

	if (data->flags & CTRL_CMD_HAS_DATA) {
		cmd->data[0] = data->data;
	}

	cmd->dev_id = info->dev_id;
	cmd->queue_id = -1;

	sqe->cmd_op = data->cmd_op;
}

static int queue_cmd(struct ubdsrv_ctrl_dev *dev,
		struct ubdsrv_ctrl_cmd_data *data)
{
	struct ubdsrv_uring *r = &dev->ring;
	struct io_sq_ring *ring = &r->sq_ring;
	unsigned index, tail, next_tail;
	struct io_uring_sqe *sqe;

	next_tail = tail = *ring->tail;
	next_tail++;

	if (next_tail == atomic_load_acquire(ring->head))
		return -1;

	index = tail & r->sq_ring_mask;
	/* IORING_SETUP_SQE128 */
	sqe = ubdsrv_uring_get_sqe(r, index, true);

	init_cmd(dev, sqe, data);

	ring->array[index] = index;
	tail = next_tail;

	atomic_store_release(ring->tail, tail);

	return 0;
}

static void ubdsrv_ctrl_handle_cqe(struct ubdsrv_uring *r,
		struct io_uring_cqe *cqe, void *data)
{
	struct ubdsrv_ctrl_dev *dev =
		container_of(r, struct ubdsrv_ctrl_dev, ring);

	INFO(fprintf(stdout, "dev %d, ctrl cqe res %d, user_data %llx\n",
			dev->dev_info.dev_id, cqe->res, cqe->user_data));
	int *cnt = data;

	if (cqe->res >= 0 && cnt)
		(*cnt)++;
}

static int reap_events_uring(struct ubdsrv_ctrl_dev *dev)
{
	int cnt = 0;

	ubdsrv_reap_events_uring(&dev->ring,
			ubdsrv_ctrl_handle_cqe, &cnt);

	return cnt;
}

static void setup_ctrl_dev()
{
	ctrl_fd = open(CTRL_DEV, O_RDWR);
	if (ctrl_fd < 0) {
		fprintf(stderr, "conrol dev %s can't be opened\n", CTRL_DEV);
		exit(ctrl_fd);
	}
}

static void ubdsrv_dev_deinit(struct ubdsrv_ctrl_dev *dev)
{
	close(dev->ring.ring_fd);
	free(dev);
}

static struct ubdsrv_ctrl_dev *ubdsrv_dev_init(int dev_id, bool zcopy)
{
	struct ubdsrv_ctrl_dev *dev = malloc(sizeof(*dev));
	struct ubdsrv_ctrl_dev_info *info = &dev->dev_info;

	if (!dev)
		die("allocate dev failed\n");

	memset(dev, 0, sizeof(*dev));
	if (zcopy)
		dev->dev_info.flags[0] |= (1ULL << UBD_F_SUPPORT_ZERO_COPY);
	else
		dev->dev_info.flags[0] &= ~(1ULL << UBD_F_SUPPORT_ZERO_COPY);

	/* -1 means we ask ubd driver to allocate one free to us */
	info->dev_id = dev_id;
	info->nr_hw_queues = DEF_NR_HW_QUEUES;
	info->queue_depth = DEF_QD;
	info->block_size = zcopy ? 4096 : 512;
	dev->bs_shift = ilog2(info->block_size);
	info->rq_max_blocks = DEF_BUF_SIZE / info->block_size;

	/* 32 is enough to send ctrl commands */
	if (ubdsrv_setup_ring(&dev->ring, IORING_SETUP_SQE128, 32, NULL, 0))
		exit(-1);

	pthread_mutex_init(&dev->lock, NULL);

	return dev;
}

static int __ubdsrv_ctrl_cmd(struct ubdsrv_ctrl_dev *dev,
		struct ubdsrv_ctrl_cmd_data *data)
{
	unsigned flags = IORING_ENTER_GETEVENTS;
	int ret;

	ret = queue_cmd(dev, data);
	if (ret) {
		fprintf(stderr, "can't queue cmd %x\n", data->cmd_op);
		return -1;
	}

	ret = io_uring_enter(&dev->ring, 1, 1, flags);
	ret = reap_events_uring(dev);

	return ret - 1;
}

/* queues_cpuset is only used for setting up queue pthread daemon */
static int ubdsrv_get_affinity(struct ubdsrv_ctrl_dev *ctrl_dev)
{
	struct ubdsrv_ctrl_cmd_data data = {
		.cmd_op	= UBD_CMD_GET_QUEUE_AFFINITY,
		.flags	= CTRL_CMD_HAS_DATA | CTRL_CMD_HAS_BUF,
	};
	cpu_set_t *sets;
	int i;

	sets = calloc(sizeof(cpu_set_t), ctrl_dev->dev_info.nr_hw_queues);
	if (!sets)
		return -1;

	for (i = 0; i < ctrl_dev->dev_info.nr_hw_queues; i++) {
		data.data = i;
		data.addr = (__u64)&sets[i];
		data.len = sizeof(cpu_set_t);

		if (__ubdsrv_ctrl_cmd(ctrl_dev, &data) < 0) {
			free(sets);
			return -1;
		}
	}
	ctrl_dev->queues_cpuset = sets;
	ctrl_dev->q_id = calloc(sizeof(unsigned short),
			ctrl_dev->dev_info.nr_hw_queues);
	if (!ctrl_dev->q_id)
		return -1;

	/* for creating queue inside ->ubq_daemon context */
	for (i = 0; i < ctrl_dev->dev_info.nr_hw_queues; i++)
		ctrl_dev->q_id[i] = i;

	return 0;
}

/*
 * Start the ubdsrv device:
 *
 * 1) fork a daemon for handling IO command from driver
 *
 * 2) wait for the device becoming ready: the daemon should submit
 * sqes to /dev/ubdcN, just like usb's urb usage, each request needs
 * one sqe. If one IO request comes to kernel driver of /dev/ubdbN,
 * the sqe for this request is completed, and the daemon gets notified.
 * When every io request of driver gets its own sqe queued, we think
 * /dev/ubdbN is ready to start
 *
 * 3) in current process context, sent START_DEV command to
 * /dev/ubd-control with device id, which will cause ubd driver to
 * expose /dev/ubdbN
 */
static int ubdsrv_start_dev(struct ubdsrv_ctrl_dev *ctrl_dev)
{
	struct ubdsrv_ctrl_cmd_data data = {
		.cmd_op	= UBD_CMD_START_DEV,
		.flags	= CTRL_CMD_HAS_DATA,
	};
	int cnt = 0, daemon_pid;
	int ret;

	if (ubdsrv_get_affinity(ctrl_dev) < 0)
		return -1;

	switch (fork()) {
	case -1:
		return -1;
	case 0:
		ubdsrv_start_io_daemon(ctrl_dev);
		break;
	}

	/* wait until daemon is started, or timeout after 3 seconds */
	do {
		daemon_pid = ubdsrv_get_io_daemon_pid(ctrl_dev);
		if (daemon_pid < 0) {
			usleep(100000);
			cnt++;
		}
	} while (daemon_pid < 0 && cnt < 30);

	if (daemon_pid < 0)
		return -1;

	ctrl_dev->dev_info.ubdsrv_pid = data.data = daemon_pid;
	ret = __ubdsrv_ctrl_cmd(ctrl_dev, &data);

	/* disk is added now, so queue cpusets can be freed */
	free(ctrl_dev->queues_cpuset);
	free(ctrl_dev->q_id);
	ctrl_dev->queues_cpuset = NULL;
	ctrl_dev->q_id = NULL;
	return ret;
}

/*
 * Stop the ubdsrv device:
 *
 * 1) send STOP_DEV command to /dev/ubd-control with device id provided
 *
 * 2) ubd driver gets this command, freeze /dev/ubdbN, then complete all
 * pending seq, meantime tell the daemon via cqe->res to not submit sqe
 * any more, since we are being closed. Also delete /dev/ubdbN.
 *
 * 3) the ubd daemon figures out that all sqes are completed, and free,
 * then close /dev/ubdcN and exit itself.
 */
static int ubdsrv_stop_dev(struct ubdsrv_ctrl_dev *dev)
{
	struct ubdsrv_ctrl_cmd_data data = {
		.cmd_op	= UBD_CMD_STOP_DEV,
	};
	int ret;

	ret = __ubdsrv_ctrl_cmd(dev, &data);
	if (ret)
		return ret;

	ubdsrv_stop_io_daemon(dev);
}

static void ubdsrv_dump(struct ubdsrv_ctrl_dev *dev)
{
	struct ubdsrv_ctrl_dev_info *info = &dev->dev_info;
	int fd;
	char buf[64];
	char *addr;

	printf("dev id %d: nr_hw_queues %d queue_depth %d block size %d dev_capacity %lld\n",
			info->dev_id,
                        info->nr_hw_queues, info->queue_depth,
                        info->block_size, info->dev_blocks);
	printf("\t max rq size: %d daemon pid: %d flags %lx\n",
                        info->block_size * info->rq_max_blocks,
			info->ubdsrv_pid, info->flags[0]);

	snprintf(buf, 64, "%s_%d", UBDSRV_SHM_DIR, info->ubdsrv_pid);
	fd = shm_open(buf, O_RDONLY, 0);
	if (fd <= 0)
		return;
	addr = mmap(NULL, UBDSRV_SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	printf("\t %s\n", addr);
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
	struct ubdsrv_ctrl_dev *dev;
	int number = -1;
	char *type = NULL;
	unsigned int queues = 0;
	unsigned int depth = 0;
	int opt, ret, zcopy = 0;
	struct ubdsrv_ctrl_cmd_data data = {
		.cmd_op	= UBD_CMD_ADD_DEV,
		.flags	= CTRL_CMD_HAS_BUF,
	};

	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:z",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		case 't':
			type = optarg;
			break;
		case 'z':
			zcopy = 1;
			break;
		case 'q':
			queues = strtol(optarg, NULL, 10);
			break;
		case 'd':
			depth = strtol(optarg, NULL, 10);
			break;
		}
	}

	setup_ctrl_dev();

	dev = ubdsrv_dev_init(number, zcopy);
	if (queues && queues <= MAX_NR_HW_QUEUES)
		dev->dev_info.nr_hw_queues = queues;
	if (depth && depth <= MAX_QD)
		dev->dev_info.queue_depth = depth;

	optind = 0;	/* so that tgt code can parse their arguments */
	if (ubdsrv_tgt_init(&dev->tgt, type, argc, argv))
		die("usbsrv: target init failed\n");

	data.addr = (__u64)&dev->dev_info;
	data.len = sizeof(struct ubdsrv_ctrl_dev_info);
	ret = __ubdsrv_ctrl_cmd(dev, &data);
	if (ret < 0) {
		fprintf(stderr, "can't add dev %d\n", number);
		goto fail;
	}

	ret = ubdsrv_start_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "start dev failed %d\n", number);
		data.cmd_op = UBD_CMD_DEL_DEV;
		data.flags = 0;
		__ubdsrv_ctrl_cmd(dev, &data);
		goto fail;
	}
	ubdsrv_dump(dev);
 fail:
	ubdsrv_dev_deinit(dev);

	return ret;
}

struct tgt_types_name {
	char names[4096];
	unsigned pos;
};

static void collect_tgt_types(unsigned int idx,
		const struct ubdsrv_tgt_type *type, void *pdata)
{
	struct tgt_types_name *data = pdata;

	if (idx > 0)
		data->pos += snprintf(data->names + data->pos,
				4096 - data->pos, "|");
	data->pos += snprintf(data->names + data->pos, 4096 - data->pos,
			"%s", type->name);
}

static void show_tgt_add_usage(unsigned int idx,
		const struct ubdsrv_tgt_type *type, void *data)
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
	ubdsrv_for_each_tgt_type(collect_tgt_types, &data);
	data.pos += snprintf(data.names + data.pos, 4096 - data.pos, "}");

	printf("%s add -t %s -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH\n", cmd, data.names);
	ubdsrv_for_each_tgt_type(show_tgt_add_usage, NULL);
}

static int __cmd_dev_del(int number, bool log)
{
	struct ubdsrv_ctrl_cmd_data data = {
		.cmd_op	= UBD_CMD_GET_DEV_INFO,
		.flags	= CTRL_CMD_HAS_BUF,
	};
	struct ubdsrv_ctrl_dev *dev;
	int ret;

	dev = ubdsrv_dev_init(number, false);

	data.addr = (__u64)&dev->dev_info;
	data.len = sizeof(struct ubdsrv_ctrl_dev_info);
	ret = __ubdsrv_ctrl_cmd(dev, &data);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d\n", number);
		goto fail;
	}

	ret = ubdsrv_stop_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "stop dev %d failed\n", number);
		goto fail;
	}

	data.cmd_op = UBD_CMD_DEL_DEV;
	data.flags = 0;
	ret = __ubdsrv_ctrl_cmd(dev, &data);
	if (ret < 0) {
		fprintf(stderr, "delete dev %d failed\n", number);
		goto fail;
	}

fail:
	ubdsrv_dev_deinit(dev);
	return ret;
}

int cmd_dev_del(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		1,	NULL, 'n' },
		{ "all",		0,	NULL, 'a' },
		{ NULL }
	};
	struct ubdsrv_ctrl_dev *dev;
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

	setup_ctrl_dev();
	if (number >= 0)
		return __cmd_dev_del(number, true);

	for (i = 0; i < MAX_NR_UBD_DEVS; i++)
		ret = __cmd_dev_del(i, false);

	return ret;
}

static void cmd_dev_del_usage(char *cmd)
{
	printf("%s del -n DEV_ID [-a | --all]\n", cmd);
}

static int list_one_dev(int number, bool log)
{
	struct ubdsrv_ctrl_dev *dev = ubdsrv_dev_init(number, false);
	struct ubdsrv_ctrl_cmd_data data = {
		.cmd_op	= UBD_CMD_GET_DEV_INFO,
		.flags	= CTRL_CMD_HAS_BUF,
		.addr = (__u64)&dev->dev_info,
		.len = sizeof(struct ubdsrv_ctrl_dev_info),
	};
	int ret;

	ret = __ubdsrv_ctrl_cmd(dev, &data);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d\n", number);
	} else
		ubdsrv_dump(dev);

	ubdsrv_dev_deinit(dev);

	return ret;
}

int cmd_list_dev_info(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		0,	NULL, 'n' },
		{ NULL }
	};
	struct ubdsrv_ctrl_dev *dev;
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

	setup_ctrl_dev();

	if (number >= 0)
		return list_one_dev(number, true);

	for (i = 0; i < MAX_NR_UBD_DEVS; i++)
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

	INFO(printf("cmd %s: result %d\n", cmd, ret));

	return 0;
}
