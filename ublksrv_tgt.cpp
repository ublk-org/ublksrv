// SPDX-License-Identifier: MIT or GPL-2.0-only

#include "config.h"
#include "ublksrv_tgt.h"

/* per-task variable */
static pthread_mutex_t jbuf_lock;
static int jbuf_size = 0;
static int queues_stored = 0;
static char *jbuf = NULL;

struct ublksrv_queue_info {
	const struct ublksrv_dev *dev;
	int qid;
	pthread_t thread;
};


/********************cmd handling************************/
static char *full_cmd;
static struct ublksrv_tgt_type *tgt_list[UBLKSRV_TGT_TYPE_MAX] = {};

int ublk_json_write_dev_info(struct ublksrv_dev *dev, char **jbuf, int *len)
{
	int ret = 0;

	do {
		ret = ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev),
				*jbuf, *len);
		if (ret < 0)
			*jbuf = ublksrv_tgt_realloc_json_buf(dev, len);
	} while (ret < 0);

	return ret;
}

int ublk_json_write_params(struct ublksrv_dev *dev, char **jbuf, int *len,
		const struct ublk_params *p)
{
	int ret = 0;

	do {
		ret = ublksrv_json_write_params(p, *jbuf, *len);
		if (ret < 0)
			*jbuf = ublksrv_tgt_realloc_json_buf(dev, len);
	} while (ret < 0);

	return ret;
}

int ublk_json_write_target_base(struct ublksrv_dev *dev, char **jbuf, int *len,
		const struct ublksrv_tgt_base_json *tgt)
{
	int ret = 0;

	do {
		ret = ublksrv_json_write_target_base_info(*jbuf, *len, tgt);
		if (ret < 0)
			*jbuf = ublksrv_tgt_realloc_json_buf(dev, len);
	} while (ret < 0);

	return ret;

}

int ublk_json_write_tgt_str(struct ublksrv_dev *dev, char **jbuf,
		int *len, const char *name, const char *val)
{
	int ret = 0;

	do {
		if (val)
			ret = ublksrv_json_write_target_str_info(*jbuf,
				*len, name, val);

		if (ret < 0)
			*jbuf = ublksrv_tgt_realloc_json_buf(dev, len);
	} while (ret < 0);

	return ret;
}

int ublk_json_write_tgt_ulong(struct ublksrv_dev *dev, char **jbuf,
		int *len, const char *name, unsigned long val)
{
	int ret = 0;

	do {
		ret = ublksrv_json_write_target_ulong_info(*jbuf,
				*len, name, val);
		if (ret < 0)
			*jbuf = ublksrv_tgt_realloc_json_buf(dev, len);
	} while (ret < 0);

	return ret;
}

int ublk_json_write_tgt_long(struct ublksrv_dev *dev, char **jbuf,
		int *len, const char *name, long val)
{
	int ret = 0;

	do {
		ret = ublksrv_json_write_target_long_info(*jbuf,
				*len, name, val);
		if (ret < 0)
			*jbuf = ublksrv_tgt_realloc_json_buf(dev, len);
	} while (ret < 0);

	return ret;
}

static const struct ublksrv_tgt_type *ublksrv_find_tgt_type(const char *name)
{
	int i;

	for (i = 0; i < UBLKSRV_TGT_TYPE_MAX; i++) {
		const struct ublksrv_tgt_type *type = tgt_list[i];

		if (type == NULL)
			continue;

		if (!strcmp(type->name, name))
			return type;
	}

	return NULL;
}

static void ublksrv_for_each_tgt_type(void (*handle_tgt_type)(unsigned idx,
			const struct ublksrv_tgt_type *type, void *data),
		void *data)
{
	int i;

	for (i = 0; i < UBLKSRV_TGT_TYPE_MAX; i++) {
                const struct ublksrv_tgt_type  *type = tgt_list[i];

		if (!type)
			continue;
		handle_tgt_type(i, type, data);
	}
}

int ublksrv_register_tgt_type(struct ublksrv_tgt_type *type)
{
	if (type->type < UBLKSRV_TGT_TYPE_MAX && !tgt_list[type->type]) {
		tgt_list[type->type] = type;
		return 0;
	}
	return -1;
}

void ublksrv_unregister_tgt_type(struct ublksrv_tgt_type *type)
{
	if (type->type < UBLKSRV_TGT_TYPE_MAX && tgt_list[type->type]) {
		tgt_list[type->type] = NULL;
	}
}


static char *mprintf(const char *fmt, ...)
{
	va_list args;
	char *str;
	int ret;

	va_start(args, fmt);
	ret = vasprintf(&str, fmt, args);
	va_end(args);

	if (ret < 0) {
		return NULL;
	}

	return str;
}

static char *pop_cmd(int *argc, char *argv[])
{
	char *cmd = argv[1];
	if (*argc < 2) {
		return NULL;
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
	char *res;

	if (setsid() == -1)
		return -1;

	res = getcwd(path, PATH_MAX);
	if (!res)
		ublk_err("%s: %d getcwd failed %m\n", __func__, __LINE__);

	switch (fork()) {
	case -1: return -1;
	case 0:  break;
	default: _exit(EXIT_SUCCESS);
	}

	if (chdir(path) != 0)
		ublk_err("%s: %d chdir failed %m\n", __func__, __LINE__);

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

static char *__ublksrv_tgt_realloc_json_buf(const struct ublksrv_dev *dev, int *size)
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

static int ublksrv_tgt_store_dev_data(const struct ublksrv_dev *dev,
		const char *buf)
{
	int ret;
	int len = ublksrv_json_get_length(buf);
	int fd = ublksrv_get_pidfile_fd(dev);

	if (fd < 0) {
		ublk_err( "fail to get fd of pid file, ret %d\n",
				fd);
		return fd;
	}

	ret = pwrite(fd, buf, len, JSON_OFFSET);
	if (ret <= 0)
		ublk_err( "fail to write json data to pid file, ret %d\n",
				ret);

	return ret;
}

static char *ublksrv_tgt_get_dev_data(struct ublksrv_ctrl_dev *cdev)
{
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int dev_id = info->dev_id;
	struct stat st;
	char pid_file[256];
	char *buf;
	int size, fd, ret;
	const char *run_dir = ublksrv_ctrl_get_run_dir(cdev);

	if (!run_dir)
		return 0;

	snprintf(pid_file, 256, "%s/%d.pid", run_dir, dev_id);
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
	const struct ublksrv_dev *dev = info->dev;
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(cdev);
	unsigned dev_id = dinfo->dev_id;
	unsigned short q_id = info->qid;
	const struct ublksrv_queue *q;
	int ret;
	int buf_size;
	char *buf;
	const char *jbuf;
	bool recoverying = dinfo->state == UBLK_S_DEV_QUIESCED;

	pthread_mutex_lock(&jbuf_lock);

	if (!recoverying) {
		do {
			buf = __ublksrv_tgt_realloc_json_buf(dev, &buf_size);
			ret = ublksrv_json_write_queue_info(cdev, buf, buf_size,
					q_id, ublksrv_gettid());
		} while (ret < 0);
		jbuf = buf;
	} else {
		jbuf = ublksrv_ctrl_get_recovery_jbuf(cdev);
	}
	queues_stored++;

	/*
	 * A bit ugly to store json buffer to pid file here, but no easy
	 * way to do it in control task side, so far, so good
	 */
	if (queues_stored == dinfo->nr_hw_queues)
		ublksrv_tgt_store_dev_data(dev, jbuf);
	pthread_mutex_unlock(&jbuf_lock);

	q = ublksrv_queue_init(dev, q_id, NULL);
	if (!q) {
		ublk_err("ublk dev %d queue %d init queue failed",
				dev_id, q_id);
		return NULL;
	}

	ublk_log("tid %d: ublk dev %d queue %d started", ublksrv_gettid(),
			dev_id, q->q_id);
	do {
		if (ublksrv_process_io(q) < 0)
			break;
	} while (1);

	ublk_log("ublk dev %d queue %d exited", dev_id, q->q_id);
	ublksrv_queue_deinit(q);
	return NULL;
}

static void sig_handler(int sig)
{
	if (sig == SIGTERM)
		ublk_log("got TERM signal");
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
static void ublksrv_drain_fetch_commands(const struct ublksrv_dev *dev,
		struct ublksrv_queue_info *info)
{
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	unsigned nr_queues = dinfo->nr_hw_queues;
	int i;
	void *ret;

	for (i = 0; i < nr_queues; i++)
		pthread_join(info[i].thread, &ret);
}


static void ublksrv_io_handler(void *data)
{
	const struct ublksrv_ctrl_dev *ctrl_dev = (struct ublksrv_ctrl_dev *)data;
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ctrl_dev);
	int dev_id = dinfo->dev_id;
	int i;
	char buf[32];
	const struct ublksrv_dev *dev;
	struct ublksrv_queue_info *info_array;

	snprintf(buf, 32, "%s-%d", "ublksrvd", dev_id);
	openlog(buf, LOG_PID, LOG_USER);

	ublk_log("start ublksrv io daemon %s\n", buf);

	pthread_mutex_init(&jbuf_lock, NULL);

	dev = ublksrv_dev_init(ctrl_dev);
	if (!dev) {
		ublk_err( "dev-%d start ubsrv failed", dev_id);
		goto out;
	}

	setup_pthread_sigmask();

	if (!(dinfo->flags & UBLK_F_UNPRIVILEGED_DEV))
		ublksrv_apply_oom_protection();

	info_array = (struct ublksrv_queue_info *)calloc(sizeof(
				struct ublksrv_queue_info),
			dinfo->nr_hw_queues);

	for (i = 0; i < dinfo->nr_hw_queues; i++) {
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

	ublksrv_dev_deinit(dev);
out:
	ublk_log("end ublksrv io daemon");
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
	const char *run_dir = ublksrv_ctrl_get_run_dir(ctrl_dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ctrl_dev);
	int ret = -1, pid_fd;
	char path[256];
	char *buf = NULL;
	int size = JSON_OFFSET;
	int daemon_pid;
	struct stat st;

	if (!run_dir)
		return -EINVAL;

	snprintf(path, 256, "%s/%d.pid", run_dir, info->dev_id);

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

/* Wait until ublk device is setup by udev */
static void ublksrv_check_dev(const struct ublksrv_ctrl_dev_info *info)
{
	unsigned int max_time = 1000000, wait = 0;
	char buf[64];

	snprintf(buf, 64, "%s%d", "/dev/ublkc", info->dev_id);

	while (wait < max_time) {
		int fd = open(buf, O_RDWR);

		if (fd > 0) {
			close(fd);
			break;
		}

		usleep(100000);
		wait += 100000;
	}
}

static int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev)
{
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ctrl_dev);
	int cnt = 0, daemon_pid, ret;

	ublksrv_check_dev(dinfo);

	ret = ublksrv_ctrl_get_affinity(ctrl_dev);
	if (ret < 0) {
		fprintf(stderr, "dev %d get affinity failed %d\n",
				dinfo->dev_id, ret);
		return -1;
	}

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

//todo: resolve stack usage warning for mkpath/__mkpath
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
static int __mkpath(char *dir, mode_t mode)
{
	struct stat sb;
	int ret;
	mode_t mask;

	if (!dir)
		return -EINVAL;

	if (!stat(dir, &sb))
		return 0;

	__mkpath(dirname(strdupa(dir)), mode);

	mask = umask(0);
	ret = mkdir(dir, mode);
	umask(mask);

	return ret;
}

static int mkpath(const char *dir)
{
	return __mkpath(strdupa(dir), S_IRWXU | S_IRWXG | S_IRWXO);
}
#pragma GCC diagnostic pop

static void ublksrv_tgt_set_params(struct ublksrv_ctrl_dev *cdev,
		const char *jbuf)
{
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int dev_id = info->dev_id;
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
		{ "user_recovery",	1,	NULL, 'r'},
		{ "user_recovery_reissue",	1,	NULL, 'i'},
		{ "debug_mask",	1,	NULL, 0},
		{ "unprivileged",	0,	NULL, 0},
		{ NULL }
	};
	struct ublksrv_dev_data data = {0};
	struct ublksrv_ctrl_dev *dev;
	const struct ublksrv_tgt_type *tgt_type;
	int opt, ret;
	int uring_comp = 0;
	int need_get_data = 0;
	int user_recovery = 0;
	int user_recovery_reissue = 0;
	int unprivileged = 0;
	const char *dump_buf;
	int option_index = 0;
	unsigned int debug_mask = 0;

	data.queue_depth = DEF_QD;
	data.nr_hw_queues = DEF_NR_HW_QUEUES;
	data.dev_id = -1;
	data.run_dir = UBLKSRV_PID_DIR;

	mkpath(data.run_dir);

	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:u:g:r:i:z",
				  longopts, &option_index)) != -1) {
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
		case 'r':
			user_recovery = strtol(optarg, NULL, 10);
			break;
		case 'i':
			user_recovery_reissue = strtol(optarg, NULL, 10);
			break;
		case 0:
			if (!strcmp(longopts[option_index].name, "debug_mask"))
				debug_mask = strtol(optarg, NULL, 16);
			if (!strcmp(longopts[option_index].name, "unprivileged"))
				unprivileged = 1;
			break;
		}
	}

	ublk_set_debug_mask(debug_mask);

	data.max_io_buf_bytes = DEF_BUF_SIZE;
	if (data.nr_hw_queues > MAX_NR_HW_QUEUES)
		data.nr_hw_queues = MAX_NR_HW_QUEUES;
	if (data.queue_depth > MAX_QD)
		data.queue_depth = MAX_QD;
	if (uring_comp)
		data.flags |= UBLK_F_URING_CMD_COMP_IN_TASK;
	if (need_get_data)
		data.flags |= UBLK_F_NEED_GET_DATA;
	if (user_recovery)
		data.flags |= UBLK_F_USER_RECOVERY;
	if (user_recovery_reissue)
		data.flags |= UBLK_F_USER_RECOVERY | UBLK_F_USER_RECOVERY_REISSUE;
	if (unprivileged)
		data.flags |= UBLK_F_UNPRIVILEGED_DEV;

	if (data.tgt_type == NULL) {
		fprintf(stderr, "no dev type specified\n");
		return -EINVAL;
	}
	tgt_type = ublksrv_find_tgt_type(data.tgt_type);
	if (tgt_type == NULL) {
		fprintf(stderr, "unknown dev type: %s\n", data.tgt_type);
		return -EINVAL;
	}
	data.tgt_ops = tgt_type;
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

	{
		const struct ublksrv_ctrl_dev_info *info =
			ublksrv_ctrl_get_dev_info(dev);
		data.dev_id = info->dev_id;
	}
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

static void cmd_dev_add_usage(const char *cmd)
{
	struct tgt_types_name data = {
		.pos = 0,
	};

	data.pos += snprintf(data.names + data.pos, sizeof(data.names) - data.pos, "{");
	ublksrv_for_each_tgt_type(collect_tgt_types, &data);
	data.pos += snprintf(data.names + data.pos, sizeof(data.names) - data.pos, "}");

	printf("%s add -t %s\n", cmd, data.names);
	printf("\t-n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH\n");
	printf("\t-u URING_COMP -g NEED_GET_DATA -r USER_RECOVERY\n");
	printf("\t-i USER_RECOVERY_REISSUE --debug_mask=0x{DBG_MASK}\n");
	printf("\t--unprivileged\n\n");
	printf("\ttarget specific command line:\n");
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
			fprintf(stderr, "can't get dev info from %d: %d\n", number, ret);
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

static void cmd_dev_del_usage(const char *cmd)
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
			fprintf(stderr, "can't get dev info from %d: %d\n", number, ret);
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
	int number = -1;
	int opt, i;
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

	return 0;
}

static void cmd_dev_list_usage(const char *cmd)
{
	printf("%s list [-n DEV_ID]\n", cmd);
}

static int __cmd_dev_user_recover(int number, bool verbose)
{
	const struct ublksrv_tgt_type *tgt_type;
	struct ublksrv_dev_data data = {
		.dev_id = number,
		.run_dir = UBLKSRV_PID_DIR,
	};
	struct ublksrv_ctrl_dev_info  dev_info;
	struct ublksrv_ctrl_dev *dev;
	struct ublksrv_tgt_base_json tgt_json = {0};
	char *buf = NULL;
	char pid_file[64];
	int ret;

	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "ublksrv_ctrl_init failure dev %d\n", number);
		return -ENOMEM;
	}

	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		fprintf(stderr, "can't get dev info from %d\n", number);
		goto fail;
	}

	ret = ublksrv_ctrl_start_recovery(dev);
	if (ret < 0) {
			fprintf(stderr, "can't start recovery for %d\n", number);
		goto fail;
	}

	buf = ublksrv_tgt_get_dev_data(dev);
	if (!buf) {
		fprintf(stderr, "get dev %d data failed\n", number);
		ret = -1;
		goto fail;
	}

	ret = ublksrv_json_read_dev_info(buf, &dev_info);
	if (ret < 0) {
		fprintf(stderr, "can't read dev info for %d\n", number);
		goto fail;
	}

	if (dev_info.dev_id != number) {
		fprintf(stderr, "dev id doesn't match read %d for dev %d\n",
				dev_info.dev_id, number);
		goto fail;
	}

	ret = ublksrv_json_read_target_base_info(buf, &tgt_json);
	if (ret < 0) {
		fprintf(stderr, "can't read dev info for %d\n", number);
		goto fail;
	}

	snprintf(pid_file, 64, "%s/%d.pid", data.run_dir, number);
	ret = unlink(pid_file);
	if (ret < 0) {
		fprintf(stderr, "can't delete old pid_file for %d, error:%s\n",
				number, strerror(errno));
		goto fail;
	}

	tgt_type = ublksrv_find_tgt_type(tgt_json.name);
	if (!tgt_type) {
		fprintf(stderr, "can't find target type %s\n", tgt_json.name);
		goto fail;
	}

	ublksrv_ctrl_prep_recovery(dev, tgt_json.name, tgt_type, buf);

	ret = ublksrv_start_daemon(dev);
	if (ret < 0) {
		fprintf(stderr, "start daemon %d failed\n", number);
		goto fail;
	}

	ret = ublksrv_ctrl_end_recovery(dev, ret);
	if (ret < 0) {
		fprintf(stderr, "end recovery for %d failed\n", number);
		goto fail;
	}

	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		fprintf(stderr, "can't get dev info from %d\n", number);
		goto fail;
	}

	if (verbose) {
		free(buf);
		buf = ublksrv_tgt_get_dev_data(dev);
		ublksrv_ctrl_dump(dev, buf);
	}

 fail:
	free(buf);
	ublksrv_ctrl_deinit(dev);
	return ret;
}

static int cmd_dev_user_recover(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		0,	NULL, 'n' },
		{ "verbose",	0,	NULL, 'v' },
		{ NULL }
	};
	int number = -1;
	int opt;
	bool verbose = false;

	while ((opt = getopt_long(argc, argv, "n:v",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		case 'v':
			verbose = true;
			break;
		}
	}

	return __cmd_dev_user_recover(number, verbose);
}

static void cmd_dev_recover_usage(const char *cmd)
{
	printf("%s recover [-n DEV_ID]\n", cmd);
}

static void cmd_usage(const char *cmd)
{
	cmd_dev_add_usage(cmd);
	cmd_dev_del_usage(cmd);
	cmd_dev_list_usage(cmd);
	cmd_dev_recover_usage(cmd);

	printf("%s -v [--version]\n", cmd);
	printf("%s -h [--help]\n", cmd);
}

int main(int argc, char *argv[])
{
	const char *prog_name = "ublk";

	char *cmd;
	int ret;
	char exe[PATH_MAX];

	full_cmd = argv[0];
	strncpy(exe, full_cmd, PATH_MAX - 1);

	setvbuf(stdout, NULL, _IOLBF, 0);

	cmd = pop_cmd(&argc, argv);
	if (cmd == NULL) {
		printf("%s: missing command\n", argv[0]);
		cmd_usage(prog_name);
		return EXIT_FAILURE;
	}

	if (!strcmp(cmd, "add"))
		ret = cmd_dev_add(argc, argv);
	else if (!strcmp(cmd, "del"))
		ret = cmd_dev_del(argc, argv);
	else if (!strcmp(cmd, "list"))
		ret = cmd_list_dev_info(argc, argv);
	else if (!strcmp(cmd, "recover"))
		ret = cmd_dev_user_recover(argc, argv);
	else if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
		cmd_usage(prog_name);
		ret = EXIT_SUCCESS;
	} else if (!strcmp(cmd, "-v") || !strcmp(cmd, "--version")) {
		fprintf(stdout, "%s\n", PACKAGE_STRING);
		ret = EXIT_SUCCESS;
	} else {
		fprintf(stderr, "unknown command: %s\n", cmd);
		cmd_usage(prog_name);
		ret = EXIT_FAILURE;
	}

	ublk_ctrl_dbg(UBLK_DBG_CTRL_CMD, "cmd %s: result %d\n", cmd, ret);

	return ret;
}
