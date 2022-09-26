// SPDX-License-Identifier: MIT or GPL-2.0-only

#include "ublksrv_tgt.h"

/* per-task variable */
static pthread_mutex_t jbuf_lock;
static int jbuf_size = 0;
static int queues_stored = 0;
static char *jbuf = NULL;

/********************cmd handling************************/
static char *full_cmd;

struct ublksrv_queue_info {
	struct ublksrv_dev *dev;
	int qid;
	pthread_t thread;
};

static char *mprintf(const char *fmt, ...)
{
	va_list args;
	char *str;
	int ret;

	va_start(args, fmt);
	ret = vasprintf(&str, fmt, args);
	va_end(args);

	return str;
}

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

static int start_daemon(void (*child_fn)(void *), void *data)
{
	char path[PATH_MAX];
	int fd;

	if (setsid() == -1)
		return -1;

	getcwd(path, PATH_MAX);

	switch (fork()) {
	case -1: return -1;
	case 0:  break;
	default: _exit(EXIT_SUCCESS);
	}

	chdir(path);

	close(STDIN_FILENO);
	fd = open("/dev/null", O_RDWR);
	if (fd != STDIN_FILENO)
		return -1;
	if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO)
		return -1;
	if (dup2(fd, STDERR_FILENO) != STDERR_FILENO)
		return -1;

	child_fn(data);
	return 0;
}

char *__ublksrv_tgt_return_json_buf(struct ublksrv_dev *dev, int *size)
{
	if (jbuf == NULL) {
		jbuf_size = 1024;
		jbuf = (char *)realloc((void *)jbuf, jbuf_size);
	}
	*size = jbuf_size;

	return jbuf;
}

char *ublksrv_tgt_return_json_buf(struct ublksrv_dev *dev, int *size)
{
	char *buf;

	pthread_mutex_lock(&jbuf_lock);
	buf = __ublksrv_tgt_return_json_buf(dev, size);
	pthread_mutex_unlock(&jbuf_lock);

	return buf;
}

static char *__ublksrv_tgt_realloc_json_buf(struct ublksrv_dev *dev, int *size)
{
	if (jbuf == NULL)
		jbuf_size = 1024;
	else
		jbuf_size += 1024;

	jbuf = (char *)realloc((void *)jbuf, jbuf_size);
	*size = jbuf_size;

	return jbuf;
}

char *ublksrv_tgt_realloc_json_buf(struct ublksrv_dev *dev, int *size)
{
	char *buf;

	pthread_mutex_lock(&jbuf_lock);
	buf = __ublksrv_tgt_realloc_json_buf(dev, size);
	pthread_mutex_unlock(&jbuf_lock);

	return buf;
}

static int ublksrv_tgt_store_dev_data(struct ublksrv_dev *dev,
		const char *buf)
{
	int ret;
	int len = ublksrv_json_get_length(buf);

	ret = pwrite(dev->pid_file_fd, buf, len, JSON_OFFSET);
	if (ret <= 0)
		syslog(LOG_ERR, "fail to write json data to pid file, ret %d\n",
				ret);

	return ret;
}

static char *ublksrv_tgt_get_dev_data(struct ublksrv_ctrl_dev *cdev)
{
	int dev_id = cdev->dev_info.dev_id;
	struct stat st;
	char pid_file[256];
	char *buf;
	int size, fd, ret;

	if (!cdev->run_dir)
		return 0;

	snprintf(pid_file, 256, "%s/%d.pid", cdev->run_dir, dev_id);
	fd = open(pid_file, O_RDONLY);

	if (fd <= 0)
		return NULL;

	if (fstat(fd, &st) < 0)
		return NULL;

	if (st.st_size <=  JSON_OFFSET)
		return NULL;

	size = st.st_size - JSON_OFFSET;
	buf = (char *)malloc(size);
	ret = pread(fd, buf, size, JSON_OFFSET);
	if (ret <= 0)
		fprintf(stderr, "fail to read json from %s ret %d\n",
				pid_file, ret);
	close(fd);

	return buf;
}

static void *ublksrv_io_handler_fn(void *data)
{
	struct ublksrv_queue_info *info = (struct ublksrv_queue_info *)data;
	struct ublksrv_dev *dev = info->dev;
	unsigned dev_id = dev->ctrl_dev->dev_info.dev_id;
	unsigned short q_id = info->qid;
	struct ublksrv_queue *q;
	int ret;
	int buf_size;
	char *buf;

	pthread_mutex_lock(&jbuf_lock);
	do {
		buf = __ublksrv_tgt_realloc_json_buf(dev, &buf_size);
		ret = ublksrv_json_write_queue_info(dev->ctrl_dev, buf, buf_size,
				q_id, gettid());
	} while (ret < 0);
	queues_stored++;

	/*
	 * A bit ugly to store json buffer to pid file here, but no easy
	 * way to do it in control task side, so far, so good
	 */
	if (queues_stored == dev->ctrl_dev->dev_info.nr_hw_queues)
		ublksrv_tgt_store_dev_data(dev, buf);
	pthread_mutex_unlock(&jbuf_lock);

	q = ublksrv_queue_init(dev, q_id, NULL);
	if (!q) {
		syslog(LOG_INFO, "ublk dev %d queue %d init queue failed",
				dev->ctrl_dev->dev_info.dev_id, q_id);
		return NULL;
	}

	syslog(LOG_INFO, "tid %d: ublk dev %d queue %d started", q->tid,
			dev_id, q->q_id);
	do {
		if (ublksrv_process_io(q) < 0)
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

	pthread_mutex_init(&jbuf_lock, NULL);

	dev = ublksrv_dev_init(ctrl_dev);
	if (!dev) {
		syslog(LOG_ERR, "dev-%d start ubsrv failed", dev_id);
		goto out;
	}

	setup_pthread_sigmask();
	ublksrv_apply_oom_protection();

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
	free(jbuf);

out_dev_deinit:
	ublksrv_dev_deinit(dev);
out:
	syslog(LOG_INFO, "end ublksrv io daemon");
	closelog();
}

/* Not called from ublksrv daemon */
static int ublksrv_start_io_daemon(const struct ublksrv_ctrl_dev *dev)
{
	start_daemon(ublksrv_io_handler, (void *)dev);
	return 0;
}

static int ublksrv_check_dev_data(const char *buf, int size)
{
	struct ublk_params p;

	if (size < JSON_OFFSET)
		return -EINVAL;

	return ublksrv_json_read_params(&p, &buf[JSON_OFFSET]);
}

static int ublksrv_get_io_daemon_pid(const struct ublksrv_ctrl_dev *ctrl_dev,
		bool check_data)
{
	int ret = -1, pid_fd;
	char path[256];
	char *buf = NULL;
	int size = JSON_OFFSET;
	int daemon_pid;
	struct stat st;

	snprintf(path, 256, "%s/%d.pid", ctrl_dev->run_dir,
			ctrl_dev->dev_info.dev_id);

	pid_fd = open(path, O_RDONLY);
	if (pid_fd < 0)
		goto out;

	if (fstat(pid_fd, &st) < 0)
		goto out;

	if (check_data)
		size = st.st_size;
	else
		size = JSON_OFFSET;

	buf = (char *)malloc(size);
	if (read(pid_fd, buf, size) <= 0)
		goto out;

	daemon_pid = strtol(buf, NULL, 10);
	if (daemon_pid < 0)
		goto out;

	ret = kill(daemon_pid, 0);
	if (ret)
		goto out;

	if (check_data) {
		ret = ublksrv_check_dev_data(buf, size);
		if (ret)
			goto out;
	}
	ret = daemon_pid;
out:
	if (pid_fd > 0)
		close(pid_fd);
	free(buf);
	return ret;
}

/* Not called from ublksrv daemon */
static int ublksrv_stop_io_daemon(const struct ublksrv_ctrl_dev *ctrl_dev)
{
	int daemon_pid, cnt = 0;

	/* wait until daemon is exited, or timeout after 3 seconds */
	do {
		daemon_pid = ublksrv_get_io_daemon_pid(ctrl_dev, false);
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
		daemon_pid = ublksrv_get_io_daemon_pid(ctrl_dev, true);
		if (daemon_pid < 0) {
			usleep(100000);
			cnt++;
		}
	} while (daemon_pid < 0 && cnt < 30);

	return daemon_pid;
}

static int __mkpath(char *dir, mode_t mode)
{
	struct stat sb;

	if (!dir)
		return -EINVAL;

	if (!stat(dir, &sb))
		return 0;

	__mkpath(dirname(strdupa(dir)), mode);

	return mkdir(dir, mode);
}

static int mkpath(const char *dir)
{
	return __mkpath(strdupa(dir), 0700);
}

static void ublksrv_tgt_set_params(struct ublksrv_ctrl_dev *cdev,
		const char *jbuf)
{
	int dev_id = cdev->dev_info.dev_id;
	struct ublk_params p;
	int ret;

	ret = ublksrv_json_read_params(&p, jbuf);
	if (ret >= 0) {
		ret = ublksrv_ctrl_set_params(cdev, &p);
		if (ret)
			fprintf(stderr, "set param for dev %d failed %d\n",
					dev_id, ret);
	} else {
		fprintf(stderr, "params not found for dev %d failed %d\n",
				dev_id, ret);
	}
}

static int cmd_dev_add(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "type",		1,	NULL, 't' },
		{ "number",		1,	NULL, 'n' },
		{ "queues",		1,	NULL, 'q' },
		{ "depth",		1,	NULL, 'd' },
		{ "zero_copy",		1,	NULL, 'z' },
		{ "uring_comp",		1,	NULL, 'u' },
		{ "need_get_data",	1,	NULL, 'g' },
		{ NULL }
	};
	struct ublksrv_dev_data data = {0};
	struct ublksrv_ctrl_dev *dev;
	const struct ublksrv_tgt_type *tgt_type;
	char *type = NULL;
	int opt, ret, zcopy = 0;
	int daemon_pid;
	int uring_comp = 0;
	int need_get_data = 0;
	const char *dump_buf;

	data.queue_depth = DEF_QD;
	data.nr_hw_queues = DEF_NR_HW_QUEUES;
	data.dev_id = -1;
	data.ublksrv_flags |= UBLKSRV_F_HAS_IO_DAEMON;
	data.run_dir = UBLKSRV_PID_DIR;

	mkpath(data.run_dir);

	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:u:g:z",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			data.dev_id = strtol(optarg, NULL, 10);
			break;
		case 't':
			data.tgt_type = optarg;
			break;
		case 'z':
			data.flags |= UBLK_F_SUPPORT_ZERO_COPY;
			break;
		case 'q':
			data.nr_hw_queues = strtol(optarg, NULL, 10);
			break;
		case 'd':
			data.queue_depth = strtol(optarg, NULL, 10);
			break;
		case 'u':
			uring_comp = strtol(optarg, NULL, 10);
			break;
		case 'g':
			need_get_data = strtol(optarg, NULL, 10);
			break;
		}
	}
	data.max_io_buf_bytes = DEF_BUF_SIZE;
	if (data.nr_hw_queues > MAX_NR_HW_QUEUES)
		data.nr_hw_queues = MAX_NR_HW_QUEUES;
	if (data.queue_depth > MAX_QD)
		data.queue_depth = MAX_QD;
	if (uring_comp)
		data.flags |= UBLK_F_URING_CMD_COMP_IN_TASK;
	if (need_get_data)
		data.flags |= UBLK_F_NEED_GET_DATA;

	if (data.tgt_type == NULL)
		return -EINVAL;
	tgt_type = ublksrv_find_tgt_type(data.tgt_type);
	if (tgt_type == NULL)
		return -EINVAL;
	data.flags |= tgt_type->ublk_flags;
	data.ublksrv_flags |= tgt_type->ublksrv_flags;

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

	data.dev_id = dev->dev_info.dev_id;
	ret = ublksrv_start_daemon(dev);
	if (ret <= 0) {
		fprintf(stderr, "start dev %d daemon failed, ret %d\n",
				data.dev_id, ret);
		goto fail_del_dev;
	}

	dump_buf = ublksrv_tgt_get_dev_data(dev);
	ublksrv_tgt_set_params(dev, dump_buf);

	ret = ublksrv_ctrl_start_dev(dev, ret);
	if (ret < 0) {
		fprintf(stderr, "start dev %d failed, ret %d\n", data.dev_id,
				ret);
		goto fail_stop_daemon;
	}
	ret = ublksrv_ctrl_get_info(dev);
	ublksrv_ctrl_dump(dev, dump_buf);
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
                  sizeof(data->names) - data->pos, "|");
	data->pos += snprintf(data->names + data->pos,
                sizeof(data->names) - data->pos, "%s", type->name);
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

	data.pos += snprintf(data.names + data.pos, sizeof(data.names) - data.pos, "{");
	ublksrv_for_each_tgt_type(collect_tgt_types, &data);
	data.pos += snprintf(data.names + data.pos, sizeof(data.names) - data.pos, "}");

	printf("%s add -t %s -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH "
			"-u URING_COMP -g NEED_GET_DATA\n",
			cmd, data.names);
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

static int list_one_dev(int number, bool log, bool verbose)
{
	struct ublksrv_dev_data data = {
		.dev_id = number,
		.run_dir = UBLKSRV_PID_DIR,
	};
	struct ublksrv_ctrl_dev *dev = ublksrv_ctrl_init(&data);
	int ret;

	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d\n", number);
	} else {
		const char *buf = ublksrv_tgt_get_dev_data(dev);

		if (verbose)
			ublksrv_json_dump(buf);
		else
			ublksrv_ctrl_dump(dev, buf);
	}

	ublksrv_ctrl_deinit(dev);

	return ret;
}

static int cmd_list_dev_info(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		0,	NULL, 'n' },
		{ "verbose",		0,	NULL, 'v' },
		{ NULL }
	};
	struct ublksrv_ctrl_dev *dev;
	int number = -1;
	int opt, ret, i;
	bool verbose = false;

	while ((opt = getopt_long(argc, argv, "n:v",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		case 'v':
			verbose = 1;
			break;
		}
	}

	if (number >= 0)
		return list_one_dev(number, true, verbose);

	for (i = 0; i < MAX_NR_UBLK_DEVS; i++)
		list_one_dev(i, false, verbose);

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
