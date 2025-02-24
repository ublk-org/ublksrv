// SPDX-License-Identifier: MIT or GPL-2.0-only

#include "config.h"
#include "ublksrv_tgt.h"

#define ERROR_EVTFD_DEVID   0xfffffffffffffffe

static void ublksrv_ctrl_data_init(struct ublksrv_ctrl_dev *cdev,
		struct ublksrv_ctrl_data *data, bool recover)
{
	ublksrv_tgt_jbuf_init(cdev, &data->jbuf, recover);
	sem_init(&data->queue_sem, 0, 0);
	data->recover = recover;
	ublksrv_ctrl_set_priv_data(cdev, data);
}

static void ublksrv_ctrl_data_exit(struct ublksrv_ctrl_dev *cdev,
		struct ublksrv_ctrl_data *data)
{
	ublksrv_ctrl_set_priv_data(cdev, NULL);
	ublksrv_tgt_jbuf_exit(&data->jbuf);
}

struct ublksrv_tgt_jbuf *ublksrv_tgt_get_jbuf(const struct ublksrv_ctrl_dev *cdev)
{
	struct ublksrv_ctrl_data *data = ublksrv_get_ctrl_data(cdev);

	return &data->jbuf;
}

int ublk_json_write_dev_info(const struct ublksrv_ctrl_dev *cdev)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_dev_info(cdev,
				j->jbuf, j->jbuf_size);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublk_json_write_params(const struct ublksrv_ctrl_dev *cdev,
		const struct ublk_params *p)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_params(p, j->jbuf, j->jbuf_size);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublk_json_write_target_base(const struct ublksrv_ctrl_dev *cdev,
		const struct ublksrv_tgt_base_json *tgt)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_target_base_info(j->jbuf, j->jbuf_size, tgt);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;

}

int ublk_json_write_tgt_str(const struct ublksrv_ctrl_dev *cdev, const char *name, const char *val)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		if (val)
			ret = ublksrv_json_write_target_str_info(j->jbuf,
					j->jbuf_size, name, val);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublk_json_write_tgt_ulong(const struct ublksrv_ctrl_dev *cdev, const char *name, unsigned long val)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_target_ulong_info(j->jbuf, j->jbuf_size,
				name, val);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublk_json_write_tgt_long(const struct ublksrv_ctrl_dev *cdev, const char *name, long val)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_target_long_info(j->jbuf, j->jbuf_size,
				name, val);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

static int ublk_json_write_queue_info(const struct ublksrv_ctrl_dev *cdev,
		unsigned int qid, int tid)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_queue_info(cdev, j->jbuf, j->jbuf_size,
				qid, tid);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

static void *ublksrv_queue_handler(void *data)
{
	struct ublksrv_queue_info *info = (struct ublksrv_queue_info *)data;
	const struct ublksrv_dev *dev = info->dev;
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	struct ublksrv_ctrl_data *cdata = ublksrv_get_ctrl_data(cdev);
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(cdev);
	unsigned dev_id = dinfo->dev_id;
	unsigned short q_id = info->qid;
	const struct ublksrv_queue *q;

	ublk_json_write_queue_info(cdev, q_id, ublksrv_gettid());

	sem_post(&cdata->queue_sem);

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

static void setup_pthread_sigmask(bool fg)
{
	sigset_t   signal_mask;

	/* don't setup sigmask in case of foreground task */
	if (fg)
		return;

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

int ublksrv_tgt_send_dev_event(int evtfd, int dev_id)
{
	uint64_t id;

	if (evtfd < 0)
		return -EBADF;

	if (dev_id >= 0)
		id = dev_id + 1;
	else
		id = ERROR_EVTFD_DEVID;

	if (write(evtfd, &id, sizeof(id)) != sizeof(id))
		return -EINVAL;

	return 0;
}

static int ublksrv_tgt_start_dev(struct ublksrv_ctrl_dev *cdev,
		const struct ublksrv_dev *dev, int evtfd, bool recover)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(cdev);
	int dev_id = dinfo->dev_id;
	int ret;

	if (!j || !j->jbuf) {
		fprintf(stderr, "json buffer is NULL, dev %d\n", dev_id);
		return -EINVAL;
	}

	pthread_mutex_lock(&j->lock);
	ublksrv_tgt_set_params(cdev, j->jbuf);
	ublksrv_tgt_store_dev_data(dev, j->jbuf);
	pthread_mutex_unlock(&j->lock);

	if (recover)
		ret = ublksrv_ctrl_end_recovery(cdev, getpid());
	else
		ret = ublksrv_ctrl_start_dev(cdev, getpid());
	if (ret < 0) {
		fprintf(stderr, "fail to start dev %d, ret %d\n", dev_id, ret);
		return ret;
	}

	ret = ublksrv_ctrl_get_info(cdev);
	if (ret < 0) {
		fprintf(stderr, "fail to get dev %d info, ret %d\n", dev_id, ret);
		return ret;
	}

	// dump dev info in case of foreground creation
	if (evtfd == -1)
		ublksrv_ctrl_dump(cdev, j->jbuf);
	else {
		if (ublksrv_tgt_send_dev_event(evtfd, dev_id)) {
			ublk_err("fail to write eventfd from target daemon\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int ublksrv_device_handler(struct ublksrv_ctrl_dev *ctrl_dev, int evtfd, bool recover)
{
	struct ublksrv_ctrl_data cdata;
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ctrl_dev);
	int dev_id = dinfo->dev_id;
	char buf[32];
	const struct ublksrv_dev *dev;
	struct ublksrv_queue_info *info_array;
	int i, ret = -EINVAL;

	ublksrv_ctrl_data_init(ctrl_dev, &cdata, recover);

	snprintf(buf, 32, "%s-%d", "ublksrvd", dev_id);
	openlog(buf, LOG_PID, LOG_USER);

	ublk_log("start ublksrv io daemon %s\n", buf);

	dev = ublksrv_dev_init(ctrl_dev);
	if (!dev) {
		ublk_err( "dev-%d start ubsrv failed", dev_id);
		goto out;
	}

	setup_pthread_sigmask(evtfd == -1);

	if (!(dinfo->flags & UBLK_F_UNPRIVILEGED_DEV))
		ublksrv_apply_oom_protection();

	info_array = (struct ublksrv_queue_info *)calloc(sizeof(
				struct ublksrv_queue_info),
			dinfo->nr_hw_queues);

	for (i = 0; i < dinfo->nr_hw_queues; i++) {
		info_array[i].dev = dev;
		info_array[i].qid = i;
		pthread_create(&info_array[i].thread, NULL,
				ublksrv_queue_handler,
				&info_array[i]);
	}

	for (i = 0; i < dinfo->nr_hw_queues; i++)
		sem_wait(&cdata.queue_sem);

	ret = ublksrv_tgt_start_dev(ctrl_dev, dev, evtfd, recover);
	if (ret) {
		fprintf(stderr, "dev-%d start dev failed, ret %d\n", dev_id, ret);
		goto free;
	}

	/* wait until we are terminated */
	ublksrv_drain_fetch_commands(dev, info_array);
free:
	free(info_array);

	ublksrv_dev_deinit(dev);
out:
	/* deleting dev can only move on when the ublkc is closed */
	if (ret)
		ublksrv_ctrl_del_dev(ctrl_dev);
	ublk_log("end ublksrv io daemon");
	ublksrv_ctrl_data_exit(ctrl_dev, &cdata);
	closelog();

	return ret;
}

/* Not called from ublksrv daemon */
int ublksrv_stop_io_daemon(const struct ublksrv_ctrl_dev *ctrl_dev)
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

void ublksrv_tgt_set_params(struct ublksrv_ctrl_dev *cdev,
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

int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev, int evtfd, bool recover)
{
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ctrl_dev);
	int ret;

	ublksrv_check_dev(dinfo);

	ret = ublksrv_ctrl_get_affinity(ctrl_dev);
	if (ret < 0) {
		fprintf(stderr, "dev %d get affinity failed %d\n",
				dinfo->dev_id, ret);
		return ret;
	}

	return ublksrv_device_handler(ctrl_dev, evtfd, recover);
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

/*
 * This function parses all the standard options that all targets support
 * and populates ublksrv_dev_data.
 */
int ublksrv_parse_std_opts(struct ublksrv_dev_data *data, int *efd, int argc, char *argv[])
{
	int opt;
	int uring_comp = 0;
	int need_get_data = 0;
	int user_recovery = 0;
	int user_recovery_fail_io = 0;
	int user_recovery_reissue = 0;
	int unprivileged = 0;
	int option_index = 0;
	unsigned int debug_mask = 0;
	static const struct option longopts[] = {
		{ "type",		1,	NULL, 't' },
		{ "number",		1,	NULL, 'n' },
		{ "queues",		1,	NULL, 'q' },
		{ "depth",		1,	NULL, 'd' },
		{ "uring_comp",		1,	NULL, 'u' },
		{ "need_get_data",	1,	NULL, 'g' },
		{ "user_recovery",	1,	NULL, 'r'},
		{ "user_recovery_fail_io",	1,	NULL, 'e'},
		{ "user_recovery_reissue",	1,	NULL, 'i'},
		{ "debug_mask",	1,	NULL, 0},
		{ "unprivileged",	0,	NULL, 0},
		{ "usercopy",	0,	NULL, 0},
		{ "eventfd",	1,	NULL, 0},
		{ NULL }
	};

	data->queue_depth = DEF_QD;
	data->nr_hw_queues = DEF_NR_HW_QUEUES;
	data->dev_id = -1;
	data->run_dir = ublksrv_get_pid_dir();

	mkpath(data->run_dir);

	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:u:g:r:e:i:",
				  longopts, &option_index)) != -1) {
		switch (opt) {
		case 'n':
			data->dev_id = strtol(optarg, NULL, 10);
			break;
		case 't':
			data->tgt_type = optarg;
			break;
		case 'z':
			data->flags |= UBLK_F_SUPPORT_ZERO_COPY;
			break;
		case 'q':
			data->nr_hw_queues = strtol(optarg, NULL, 10);
			break;
		case 'd':
			data->queue_depth = strtol(optarg, NULL, 10);
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
		case 'e':
			user_recovery_fail_io = strtol(optarg, NULL, 10);
			break;
		case 'i':
			user_recovery_reissue = strtol(optarg, NULL, 10);
			break;
		case 0:
			if (!strcmp(longopts[option_index].name, "debug_mask"))
				debug_mask = strtol(optarg, NULL, 16);
			if (!strcmp(longopts[option_index].name, "unprivileged"))
				unprivileged = 1;
			if (!strcmp(longopts[option_index].name, "usercopy"))
				data->flags |= UBLK_F_USER_COPY;
			if (!strcmp(longopts[option_index].name, "eventfd") && efd)
				*efd = strtol(optarg, NULL, 10);
			break;
		}
	}

	data->max_io_buf_bytes = DEF_BUF_SIZE;
	if (data->nr_hw_queues > MAX_NR_HW_QUEUES)
		data->nr_hw_queues = MAX_NR_HW_QUEUES;
	if (data->queue_depth > MAX_QD)
		data->queue_depth = MAX_QD;
	if (uring_comp)
		data->flags |= UBLK_F_URING_CMD_COMP_IN_TASK;
	if (need_get_data)
		data->flags |= UBLK_F_NEED_GET_DATA;
	if (user_recovery)
		data->flags |= UBLK_F_USER_RECOVERY;
	if (user_recovery_fail_io)
		data->flags |= UBLK_F_USER_RECOVERY | UBLK_F_USER_RECOVERY_FAIL_IO;
	if (user_recovery_reissue)
		data->flags |= UBLK_F_USER_RECOVERY | UBLK_F_USER_RECOVERY_REISSUE;
	if (unprivileged)
		data->flags |= UBLK_F_UNPRIVILEGED_DEV;

	ublk_set_debug_mask(debug_mask);

	return 0;
}

void ublksrv_print_std_opts(void)
{
	printf("\t-n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH\n");
	printf("\t-u URING_COMP -g NEED_GET_DATA -r USER_RECOVERY\n");
	printf("\t-i USER_RECOVERY_REISSUE -e USER_RECOVERY_FAIL_IO\n");
	printf("\t--debug_mask=0x{DBG_MASK} --unprivileged\n\n");
}

int ublksrv_cmd_dev_add(const struct ublksrv_tgt_type *tgt_type, int argc, char *argv[])
{
	struct ublksrv_dev_data data = {0};
	struct ublksrv_ctrl_dev *dev;
	int ret, evtfd = -1;

	ublksrv_parse_std_opts(&data, &evtfd, argc, argv);

	if (data.tgt_type && strcmp(data.tgt_type, tgt_type->name)) {
		fprintf(stderr, "Wrong tgt_type specified\n");
		return -EINVAL;
	}

	data.tgt_type = tgt_type->name;
	data.tgt_ops = tgt_type;
	data.flags |= tgt_type->ublk_flags;
	data.ublksrv_flags |= tgt_type->ublksrv_flags;

	//optind = 0;	/* so that tgt code can parse their arguments */
	data.tgt_argc = argc;
	data.tgt_argv = argv;
	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		return -EOPNOTSUPP;
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
	ret = ublksrv_start_daemon(dev, evtfd, false);
	if (ret < 0) {
		fprintf(stderr, "start dev %d daemon failed, ret %d\n",
				data.dev_id, ret);
		goto fail_del_dev;
	}

	ublksrv_ctrl_deinit(dev);
	return 0;

 fail_del_dev:
	ublksrv_ctrl_del_dev(dev);
 fail:
	ublksrv_ctrl_deinit(dev);

	ublksrv_tgt_send_dev_event(evtfd, -1);

	return ret;
}

char *ublksrv_pop_cmd(int *argc, char *argv[])
{
	char *cmd = argv[1];
	if (*argc < 2) {
		return NULL;
	}

	memmove(&argv[1], &argv[2], *argc * sizeof(argv[0]));
	(*argc)--;

	return cmd;
}

static int __cmd_dev_user_recover(const struct ublksrv_tgt_type *tgt_type,
		int number, bool verbose, int evtfd)
{
	struct ublksrv_dev_data data = {
		.dev_id = number,
		.tgt_type = tgt_type->name,
		.tgt_ops = tgt_type,
		.run_dir = ublksrv_get_pid_dir(),
	};
	struct ublksrv_ctrl_dev_info  dev_info;
	struct ublksrv_ctrl_dev *dev;
	struct ublksrv_tgt_base_json tgt_json = {0};
	char *buf = NULL;
	int ret;
	unsigned elapsed = 0;

	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "ublksrv_ctrl_init failure dev %d\n", number);
		ret = -EOPNOTSUPP;
		goto exit;
	}

	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		fprintf(stderr, "can't get dev info from %d\n", number);
		goto fail;
	}

	while (elapsed < 30000000) {
		unsigned unit = 100000;
		ret = ublksrv_ctrl_start_recovery(dev);
		if (ret < 0 && ret != -EBUSY) {
			fprintf(stderr, "can't start recovery for %d ret %d\n",
					number, ret);
			goto fail;
		}
		if (ret >= 0)
			break;
		usleep(unit);
		elapsed += unit;
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

	ret = ublksrv_start_daemon(dev, evtfd, true);
	if (ret < 0) {
		fprintf(stderr, "start daemon %d failed\n", number);
		goto fail;
	}

 fail:
	free(buf);
	ublksrv_ctrl_deinit(dev);
 exit:
	ublksrv_tgt_send_dev_event(evtfd, -1);
	return ret;
}

int ublksrv_cmd_dev_user_recover(const struct ublksrv_tgt_type *tgt_type, int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		0,	NULL, 'n' },
		{ "verbose",	0,	NULL, 'v' },
		{ "eventfd",	1,	NULL, 0},
		{ NULL }
	};
	int option_index = 0;
	int number = -1;
	int opt;
	bool verbose = false;
	int evtfd = -1;

	while ((opt = getopt_long(argc, argv, "n:v",
				  longopts, &option_index)) != -1) {
		switch (opt) {
		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		case 'v':
			verbose = true;
			break;
		case 0:
			if (!strcmp(longopts[option_index].name, "eventfd"))
				evtfd = strtol(optarg, NULL, 10);
		}
	}

	return __cmd_dev_user_recover(tgt_type, number, verbose, evtfd);
}

static void cmd_usage(const struct ublksrv_tgt_type *tgt_type)
{
	if (tgt_type->usage_for_add)
		tgt_type->usage_for_add();
}

int ublksrv_tgt_cmd_main(const struct ublksrv_tgt_type *tgt_type, int argc, char *argv[])
{
	const char *cmd;
	int ret;

	setvbuf(stdout, NULL, _IOLBF, 0);

	cmd = ublksrv_pop_cmd(&argc, argv);
	if (cmd == NULL) {
		printf("%s: missing command\n", argv[0]);
		cmd_usage(tgt_type);
		return EXIT_FAILURE;
	}

	if (!strcmp(cmd, "add"))
		ret = ublksrv_cmd_dev_add(tgt_type, argc, argv);
	else if (!strcmp(cmd, "recover"))
		ret = ublksrv_cmd_dev_user_recover(tgt_type, argc, argv);
	else if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
		cmd_usage(tgt_type);
		ret = EXIT_SUCCESS;
	} else {
		fprintf(stderr, "unknown command: %s\n", cmd);
		cmd_usage(tgt_type);
		ret = EXIT_FAILURE;
	}

	ublk_ctrl_dbg(UBLK_DBG_CTRL_CMD, "cmd %s: result %d\n", cmd, ret);

	return ret;
}
