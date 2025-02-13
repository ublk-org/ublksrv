// SPDX-License-Identifier: MIT or GPL-2.0-only

#include "config.h"
#include "ublksrv_tgt.h"

/* per-task variable */
static pthread_mutex_t jbuf_lock;
static int jbuf_size = 0;
static int queues_stored = 0;
static char *jbuf = NULL;

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

int start_daemon(void (*child_fn)(void *), void *data)
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

	pthread_mutex_lock(&jbuf_lock);

	if (!ublksrv_is_recovering(cdev)) {
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
int ublksrv_start_io_daemon(const struct ublksrv_ctrl_dev *dev)
{
	start_daemon(ublksrv_io_handler, (void *)dev);
	return 0;
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

int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev)
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
