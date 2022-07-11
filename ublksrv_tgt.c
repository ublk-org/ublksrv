#include "ublksrv_tgt.h"

/********************cmd handling************************/
static char *full_cmd;

struct ublksrv_queue_info {
	struct ublksrv_dev *dev;
	int qid;
	pthread_t thread;
};

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

static void *ublksrv_io_handler_fn(void *data)
{
	struct ublksrv_queue_info *info = (struct ublksrv_queue_info *)data;
	struct ublksrv_dev *dev = info->dev;
	unsigned dev_id = dev->ctrl_dev->dev_info.dev_id;
	unsigned short q_id = info->qid;
	struct ublksrv_queue *q;

	q = ublksrv_queue_init(dev, q_id, NULL);
	if (!q) {
		syslog(LOG_INFO, "ublk dev %d queue %d init queue failed",
				dev->ctrl_dev->dev_info.dev_id, q_id);
		return NULL;
	}

	syslog(LOG_INFO, "tid %d: ublk dev %d queue %d started", q->tid,
			dev_id, q->q_id);
	do {
		if (ublksrv_process_io(q, NULL) < 0)
			break;
	} while (1);

	syslog(LOG_INFO, "ublk dev %d queue %d exited", dev_id, q->q_id);
	ublksrv_queue_deinit(q);
	return NULL;
}

static void sig_handler(int sig)
{
	if (sig == SIGTERM)
		syslog(LOG_INFO, "got TERM signal");
}

static void setup_pthread_sigmask()
{
	sigset_t   signal_mask;

	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		return;

	/* make sure SIGTERM won't be blocked */
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
}

static int ublksrv_create_pid_file(int dev_id)
{
	char pid_file[64];
	int ret, pid_fd;

	/* create pid file and lock it, so that others can't */
	snprintf(pid_file, 64, "%s-%d.pid", UBLKSRV_PID_FILE, dev_id);

	ret = create_pid_file(pid_file, CPF_CLOEXEC, &pid_fd);
	if (ret < 0) {
		/* -1 means the file is locked, and we need to remove it */
		if (ret == -1) {
			close(pid_fd);
			unlink(pid_file);
		}
		return ret;
	}
	close(pid_fd);
	return 0;
}

static void ublksrv_remove_pid_file(int dev_id)
{
	char pid_file[64];

	/* create pid file and lock it, so that others can't */
	snprintf(pid_file, 64, "%s-%d.pid", UBLKSRV_PID_FILE, dev_id);
	unlink(pid_file);
}

/*
 * Now STOP DEV ctrl command has been sent to /dev/ublk-control,
 * and wait until all pending fetch commands are canceled
 */
static void ublksrv_drain_fetch_commands(struct ublksrv_dev *dev,
		struct ublksrv_queue_info *info)
{
	unsigned nr_queues = dev->ctrl_dev->dev_info.nr_hw_queues;
	int i;
	void *ret;

	for (i = 0; i < nr_queues; i++)
		pthread_join(info[i].thread, &ret);
}


static void ublksrv_io_handler(void *data)
{
	const struct ublksrv_ctrl_dev *ctrl_dev = (struct ublksrv_ctrl_dev *)data;
	int dev_id = ctrl_dev->dev_info.dev_id;
	int ret, i;
	char buf[32];
	struct ublksrv_dev *dev;
	struct ublksrv_queue_info *info_array;

	snprintf(buf, 32, "%s-%d", "ublksrvd", dev_id);
	openlog(buf, LOG_PID, LOG_USER);

	syslog(LOG_INFO, "start ublksrv io daemon");

	dev = ublksrv_dev_init(ctrl_dev);
	if (!dev) {
		syslog(LOG_ERR, "dev-%d start ubsrv failed", dev_id);
		goto out;
	}

	/*
	 * has to be called after ublksrv_dev_init returns, so that
	 * the control task can observe disk size configured
	 */
	if (ublksrv_create_pid_file(dev_id)) {
		syslog(LOG_ERR, "dev-%d create pid file failed", dev_id);
		goto out_dev_deinit;
	}

	setup_pthread_sigmask();

	info_array = (struct ublksrv_queue_info *)calloc(sizeof(
				struct ublksrv_queue_info),
			ctrl_dev->dev_info.nr_hw_queues);

	for (i = 0; i < ctrl_dev->dev_info.nr_hw_queues; i++) {
		info_array[i].dev = dev;
		info_array[i].qid = i;
		pthread_create(&info_array[i].thread, NULL,
				ublksrv_io_handler_fn,
				&info_array[i]);
	}

	/* wait until we are terminated */
	ublksrv_drain_fetch_commands(dev, info_array);
	free(info_array);
	ublksrv_remove_pid_file(dev_id);

out_dev_deinit:
	ublksrv_dev_deinit(dev);
out:
	syslog(LOG_INFO, "end ublksrv io daemon");
	closelog();
}

/* Not called from ublksrv daemon */
static int ublksrv_start_io_daemon(const struct ublksrv_ctrl_dev *dev)
{
	start_daemon(0, ublksrv_io_handler, (void *)dev);
	return 0;
}

static int ublksrv_get_io_daemon_pid(const struct ublksrv_ctrl_dev *ctrl_dev)
{
	int ret = -1, pid_fd;
	char buf[64];
	int daemon_pid;

	snprintf(buf, 64, "%s-%d.pid", UBLKSRV_PID_FILE,
			ctrl_dev->dev_info.dev_id);
	pid_fd = open(buf, O_RDONLY);
	if (pid_fd < 0)
		goto out;

	if (read(pid_fd, buf, sizeof(buf)) <= 0)
		goto out;

	daemon_pid = strtol(buf, NULL, 10);
	if (daemon_pid < 0)
		goto out;

	ret = kill(daemon_pid, 0);
	if (ret)
		goto out;

	return daemon_pid;
out:
	return ret;
}

/* Not called from ublksrv daemon */
static int ublksrv_stop_io_daemon(const struct ublksrv_ctrl_dev *ctrl_dev)
{
	int daemon_pid, cnt = 0;

	/* wait until daemon is exited, or timeout after 3 seconds */
	do {
		daemon_pid = ublksrv_get_io_daemon_pid(ctrl_dev);
		if (daemon_pid > 0) {
			usleep(100000);
			cnt++;
		}
	} while (daemon_pid > 0 && cnt < 30);

	if (daemon_pid > 0)
		return -1;

	return 0;
}

static int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev)
{
	int cnt = 0, daemon_pid;
	int ret;

	if (ublksrv_ctrl_get_affinity(ctrl_dev) < 0)
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

	return daemon_pid;
}

static unsigned long long get_dev_blocks(struct ublksrv_ctrl_dev *ctrl_dev,
		int daemon_pid)
{
	unsigned long long dev_blocks = 0;

	if (ctrl_dev->dev_info.ublksrv_flags & UBLKSRV_F_HAS_IO_DAEMON) {
		char *addr;
		int fd = ublksrv_open_shm(ctrl_dev, &addr, daemon_pid);

		if (fd > 0) {
			const struct ublksrv_ctrl_dev_info *info =
				(struct ublksrv_ctrl_dev_info *)addr;
			dev_blocks = info->dev_blocks;
			ublksrv_close_shm(ctrl_dev, fd, addr);
		} else {
			fprintf(stderr, "can't open shmem %d\n",
					ctrl_dev->dev_info.dev_id);
		}
	} else {
		dev_blocks = ctrl_dev->dev_info.dev_blocks;
	}

	return dev_blocks;
}

static int cmd_dev_add(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "type",		1,	NULL, 't' },
		{ "number",		1,	NULL, 'n' },
		{ "queues",		1,	NULL, 'q' },
		{ "depth",		1,	NULL, 'd' },
		{ "zero_copy",		1,	NULL, 'z' },
		{ "refetch",		1,	NULL, 'r' },
		{ NULL }
	};
	struct ublksrv_dev_data data = {0};
	struct ublksrv_ctrl_dev *dev;
	char *type = NULL;
	int opt, ret, zcopy = 0, pin_page = 0;
	int daemon_pid;
	int refetch = 0;

	data.queue_depth = DEF_QD;
	data.nr_hw_queues = DEF_NR_HW_QUEUES;
	data.dev_id = -1;
	data.block_size = 512;
	data.ublksrv_flags |= UBLKSRV_F_HAS_IO_DAEMON;

	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:p:r:z",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			data.dev_id = strtol(optarg, NULL, 10);
			break;
		case 't':
			data.tgt_type = optarg;
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
		case 'p':
			pin_page = strtol(optarg, NULL, 10);
			break;
		case 'r':
			refetch = strtol(optarg, NULL, 10);
			break;
		}
	}
	data.rq_max_blocks = DEF_BUF_SIZE / data.block_size;
	if (data.nr_hw_queues > MAX_NR_HW_QUEUES)
		data.nr_hw_queues = MAX_NR_HW_QUEUES;
	if (data.queue_depth > MAX_QD)
		data.queue_depth = MAX_QD;
	if (pin_page)
		data.flags[0] |= 1ULL << UBLK_F_PIN_PAGES_FOR_IO;
	if (refetch)
		data.flags[0] |= 1ULL << UBLK_F_NEED_REFETCH;

	//optind = 0;	/* so that tgt code can parse their arguments */
	data.tgt_argc = argc;
	data.tgt_argv = argv;
	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		return -ENODEV;
	}

	ret = ublksrv_ctrl_add_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "can't add dev %d, ret %d\n", data.dev_id, ret);
		goto fail;
	}

	ret = ublksrv_start_daemon(dev);
	if (ret <= 0)
		goto fail_del_dev;

	ret = ublksrv_ctrl_start_dev(dev, ret, get_dev_blocks(dev, ret));
	if (ret < 0) {
		fprintf(stderr, "start dev failed %d, ret %d\n", data.dev_id,
				ret);
		goto fail_stop_daemon;
	}
	ret = ublksrv_ctrl_get_info(dev);
	ublksrv_ctrl_dump(dev);
	ublksrv_ctrl_deinit(dev);
	return 0;

 fail_stop_daemon:
	ublksrv_stop_io_daemon(dev);
 fail_del_dev:
	ublksrv_ctrl_del_dev(dev);
 fail:
	ublksrv_ctrl_deinit(dev);

	return ret;
}

struct tgt_types_name {
	unsigned pos;
	char names[4096 - sizeof(unsigned)];
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

	printf("%s add -t %s -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH -p PIN_PAGE_WHEN_HANDLING_IO \n", cmd, data.names);
	ublksrv_for_each_tgt_type(show_tgt_add_usage, NULL);
}

static int __cmd_dev_del(int number, bool log)
{
	struct ublksrv_ctrl_dev *dev;
	int ret;
	struct ublksrv_dev_data data = {
		.dev_id = number,
	};

	dev = ublksrv_ctrl_init(&data);

	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d\n", number);
		goto fail;
	}

	ret = ublksrv_ctrl_stop_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "stop dev %d failed\n", number);
		goto fail;
	}

	ret = ublksrv_stop_io_daemon(dev);
	if (ret < 0)
		fprintf(stderr, "stop daemon %d failed\n", number);

	ret = ublksrv_ctrl_del_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "delete dev %d failed\n", number);
		goto fail;
	}

fail:
	ublksrv_ctrl_deinit(dev);
	return ret;
}

static int cmd_dev_del(int argc, char *argv[])
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
	struct ublksrv_ctrl_dev *dev = ublksrv_ctrl_init(&data);
	int ret;

	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d\n", number);
	} else
		ublksrv_ctrl_dump(dev);

	ublksrv_ctrl_deinit(dev);

	return ret;
}

static int cmd_list_dev_info(int argc, char *argv[])
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
