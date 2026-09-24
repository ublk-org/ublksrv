// SPDX-License-Identifier: MIT or GPL-2.0-only

#include "config.h"
#include <semaphore.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include "ublksrv_tgt.h"

#define ERROR_EVTFD_DEVID   0xfffffffffffffffe

/* ---------- Shared memory zero-copy (UBLK_F_SHMEM_ZC) ---------- */
#define UBLK_SHMEM_SOCK_DIR	"/run/ublk"

struct ublk_shmem_entry {
	int fd;
	void *mmap_base;
	size_t size;
};

static struct ublk_shmem_entry shmem_table[UBLK_BUF_MAX];
static int shmem_count;

/* Saved across parse/add phases for shmem_zc setup */
static char *shmem_htlb_path;
static bool shmem_rdonly;

static void ublk_shmem_sock_path(int dev_id, char *buf, size_t len)
{
	snprintf(buf, len, "%s/ublkb%d.sock", UBLK_SHMEM_SOCK_DIR, dev_id);
}

static int ublk_shmem_sock_create(int dev_id)
{
	struct sockaddr_un addr;
	char path[108];
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	mkdir(UBLK_SHMEM_SOCK_DIR, 0755);
	ublk_shmem_sock_path(dev_id, path, sizeof(path));
	unlink(path);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -1;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	listen(fd, 4);
	return fd;
}

static void ublk_shmem_sock_destroy(int dev_id, int sock_fd)
{
	char path[108];

	if (sock_fd >= 0)
		close(sock_fd);
	ublk_shmem_sock_path(dev_id, path, sizeof(path));
	unlink(path);
}

static int ublk_shmem_recv_fd(int client_fd)
{
	char buf[1];
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	union {
		char cmsg_buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct msghdr msg;
	struct cmsghdr *cmsg;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = u.cmsg_buf;
	msg.msg_controllen = sizeof(u.cmsg_buf);

	if (recvmsg(client_fd, &msg, 0) <= 0)
		return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS)
		return -1;

	return *(int *)CMSG_DATA(cmsg);
}

static void ublk_shmem_unregister_all(void)
{
	for (int i = 0; i < shmem_count; i++) {
		if (shmem_table[i].mmap_base) {
			munmap(shmem_table[i].mmap_base,
			       shmem_table[i].size);
			close(shmem_table[i].fd);
			shmem_table[i].mmap_base = NULL;
		}
	}
	shmem_count = 0;
}

static void ublk_shmem_handle_client(int sock_fd,
				     struct ublksrv_ctrl_dev *cdev)
{
	int client_fd, memfd, idx;
	int32_t reply;
	off_t size;
	void *base;
	int ret;

	client_fd = accept(sock_fd, NULL, NULL);
	if (client_fd < 0)
		return;

	memfd = ublk_shmem_recv_fd(client_fd);
	if (memfd < 0) {
		reply = -1;
		goto out;
	}

	size = lseek(memfd, 0, SEEK_END);
	if (size <= 0) {
		reply = -1;
		close(memfd);
		goto out;
	}
	base = mmap(NULL, size, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, memfd, 0);
	if (base == MAP_FAILED) {
		reply = -1;
		close(memfd);
		goto out;
	}

	if (shmem_count >= UBLK_BUF_MAX) {
		munmap(base, size);
		close(memfd);
		reply = -ENOMEM;
		goto out;
	}

	ret = ublksrv_ctrl_reg_buf(cdev, base, size, 0);
	if (ret < 0) {
		munmap(base, size);
		close(memfd);
		reply = ret;
		goto out;
	}

	idx = shmem_count++;
	shmem_table[idx].fd = memfd;
	shmem_table[idx].mmap_base = base;
	shmem_table[idx].size = size;
	reply = idx;
out:
	send(client_fd, &reply, sizeof(reply), 0);
	close(client_fd);
}

struct shmem_listener_info {
	int dev_id;
	int stop_efd;
	int sock_fd;
	struct ublksrv_ctrl_dev *cdev;
};

static void *ublk_shmem_listener_fn(void *data)
{
	struct shmem_listener_info *info = (struct shmem_listener_info *)data;
	struct pollfd pfds[2];

	info->sock_fd = ublk_shmem_sock_create(info->dev_id);
	if (info->sock_fd < 0)
		return NULL;

	pfds[0].fd = info->sock_fd;
	pfds[0].events = POLLIN;
	pfds[1].fd = info->stop_efd;
	pfds[1].events = POLLIN;

	while (1) {
		int ret = poll(pfds, 2, -1);

		if (ret < 0)
			break;
		if (pfds[1].revents & POLLIN)
			break;
		if (pfds[0].revents & POLLIN)
			ublk_shmem_handle_client(info->sock_fd, info->cdev);
	}

	return NULL;
}

static int ublk_shmem_htlb_setup(const char *htlb_path, bool rdonly,
				  struct ublksrv_ctrl_dev *cdev)
{
	int fd, idx, ret;
	struct stat st;
	void *base;

	fd = open(htlb_path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "htlb: can't open %s: %m\n", htlb_path);
		return -errno;
	}

	if (fstat(fd, &st) < 0 || st.st_size <= 0) {
		fprintf(stderr, "htlb: invalid file size\n");
		close(fd);
		return -EINVAL;
	}

	base = mmap(NULL, st.st_size,
		    rdonly ? PROT_READ : PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, 0);
	if (base == MAP_FAILED) {
		fprintf(stderr, "htlb: mmap failed: %m\n");
		close(fd);
		return -ENOMEM;
	}

	if (shmem_count >= UBLK_BUF_MAX) {
		munmap(base, st.st_size);
		close(fd);
		return -ENOMEM;
	}

	ret = ublksrv_ctrl_reg_buf(cdev, base, st.st_size,
				   rdonly ? UBLK_SHMEM_BUF_READ_ONLY : 0);
	if (ret < 0) {
		fprintf(stderr, "htlb: reg_buf failed: %d\n", ret);
		munmap(base, st.st_size);
		close(fd);
		return ret;
	}

	idx = shmem_count++;
	shmem_table[idx].fd = fd;
	shmem_table[idx].mmap_base = base;
	shmem_table[idx].size = st.st_size;

	return 0;
}

/* Get shmem buffer address for I/O handling */
void *ublk_shmem_get_buf(unsigned idx, unsigned offset)
{
	if (idx >= UBLK_BUF_MAX || !shmem_table[idx].mmap_base)
		return NULL;
	return (char *)shmem_table[idx].mmap_base + offset;
}

size_t ublk_shmem_get_size(unsigned idx)
{
	if (idx >= UBLK_BUF_MAX || !shmem_table[idx].mmap_base)
		return 0;
	return shmem_table[idx].size;
}

/* ------ end shmem_zc ------ */

struct ublksrv_queue_info {
	const struct ublksrv_dev *dev;
	int qid;
	unsigned short io_thread_idx;
	pthread_t thread;
	sem_t *queue_sem;

	/*
	 * Set by the io thread before it posts ->queue_sem, so the value is
	 * visible to the device handler once its sem_wait() returns.
	 */
	bool init_done;
};

static void ublk_set_queue_pthread_affinity(const struct ublksrv_ctrl_dev *cdev,
					    unsigned qid)
{
	cpu_set_t set;
	int idx, i, j = 0;

	CPU_ZERO(&set);
	if (sched_getaffinity(0, sizeof(set), &set) == -1) {
		ublk_err("sched_getaffinity, %s\n", strerror(errno));
		return;
	}

	srand(ublksrv_gettid());
	idx = rand() % CPU_COUNT(&set);

	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &set)) {
			if (j++ == idx)
				continue;
			CPU_CLR(i, &set);
		}
	}

	sched_setaffinity(0, sizeof(set), &set);
}

static void *ublksrv_queue_handler(void *data)
{
	struct ublksrv_queue_info *info = (struct ublksrv_queue_info *)data;
	const struct ublksrv_dev *dev = info->dev;
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(cdev);
	unsigned dev_id = dinfo->dev_id;
	unsigned short q_id = info->qid;
	unsigned short idx = info->io_thread_idx;
	unsigned nr_io_threads = ublksrv_flags_io_threads(dinfo->ublksrv_flags);
	const struct ublksrv_queue *q;
	unsigned to_submit;
	int ret;

	ret = ublk_json_write_queue_thread_info(cdev, q_id, idx,
			ublksrv_gettid());
	if (ret < 0)
		ublk_err("ublk dev %d queue %d io thread %u: tid not recorded in json, ret %d",
				dev_id, q_id, idx, ret);

	q = ublksrv_queue_init_thread(dev, q_id, NULL, IORING_SETUP_COOP_TASKRUN |
		IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN, idx);
	if (!q) {
		ublk_err("ublk dev %d queue %d io thread %u init queue failed",
				dev_id, q_id, idx);
		sem_post(info->queue_sem);
		return NULL;
	}

	/*
	 * ublksrv_queue_init_thread() only prepares the fetch commands and
	 * leaves the submit to the first ublksrv_process_io().  Submit them
	 * before reporting success: the abort path below relies on the
	 * driver cancelling every fetch of a thread which did start, and the
	 * driver can only cancel what it has already received.  A fetch
	 * submitted after that cancel pass would be accepted and never
	 * complete, leaving this thread in ublksrv_process_io() for good.
	 * This must be done by this thread since the ring is single issuer,
	 * and a short submit is as bad as a failed one: whatever it left in
	 * the SQ would go in after the cancel pass all the same.
	 */
	to_submit = io_uring_sq_ready(q->ring_ptr);
	ret = io_uring_submit(q->ring_ptr);
	if (ret < 0)
		ublk_err("ublk dev %d queue %d io thread %u submit fetch commands failed: %s",
				dev_id, q_id, idx, strerror(-ret));
	else if ((unsigned)ret != to_submit)
		ublk_err("ublk dev %d queue %d io thread %u submitted %d of %u fetch commands",
				dev_id, q_id, idx, ret, to_submit);
	if (ret < 0 || (unsigned)ret != to_submit) {
		ublksrv_queue_deinit(q);
		sem_post(info->queue_sem);
		return NULL;
	}

	/*
	 * Narrowing the thread to a single cpu of the queue's affinity mask
	 * only makes sense while the queue has one io thread. With several,
	 * each would draw its own cpu independently -- and from a
	 * process-global rand() at that -- so threads of one queue would
	 * routinely land on the same cpu and serialise against each other.
	 * Leave them spread over the queue's mask instead, which is what
	 * makes serving a queue from several threads worth anything.
	 */
	if (nr_io_threads == 1)
		ublk_set_queue_pthread_affinity(cdev, q_id);
	info->init_done = true;
	sem_post(info->queue_sem);

	ublk_log("tid %d: ublk dev %d queue %d io thread %u started",
			ublksrv_gettid(), dev_id, q->q_id, idx);
	do {
		if (ublksrv_process_io(q) < 0)
			break;
	} while (1);

	ublk_log("ublk dev %d queue %d io thread %u exited", dev_id, q->q_id,
			idx);
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

static bool ublksrv_queues_started(const struct ublksrv_queue_info *info,
		unsigned nr_threads)
{
	unsigned i;

	for (i = 0; i < nr_threads; i++)
		if (!info[i].init_done)
			return false;
	return true;
}

/*
 * Now STOP DEV ctrl command has been sent to /dev/ublk-control,
 * and wait until all pending fetch commands are canceled
 */
static void ublksrv_drain_fetch_commands(struct ublksrv_queue_info *info,
		unsigned nr_threads)
{
	unsigned i;
	void *ret;

	for (i = 0; i < nr_threads; i++)
		pthread_join(info[i].thread, &ret);
}

static int ublksrv_tgt_send_dev_event(int evtfd, int dev_id)
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

static void ublk_tgt_set_params(struct ublksrv_ctrl_dev *cdev)
{
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int dev_id = info->dev_id;
	struct ublk_params p;
	int ret;

	ret = ublk_json_read_params(&p, cdev);
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

static int ublksrv_tgt_start_dev(struct ublksrv_ctrl_dev *cdev,
		const struct ublksrv_dev *dev, int evtfd)
{
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(cdev);
	int dev_id = dinfo->dev_id;
	int ret;

	ublk_tgt_store_dev_data(dev);

	if (ublksrv_is_recovering(cdev))
		ret = ublksrv_ctrl_end_recovery(cdev, getpid());
	else {
		ublk_tgt_set_params(cdev);
		ret = ublksrv_ctrl_start_dev(cdev, getpid());
	}
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
		ublk_ctrl_dump(cdev);
	else {
		if (ublksrv_tgt_send_dev_event(evtfd, dev_id)) {
			ublk_err("fail to write eventfd from target daemon\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int ublksrv_device_handler(struct ublksrv_ctrl_dev *ctrl_dev, int evtfd)
{
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ctrl_dev);
	int dev_id = dinfo->dev_id;
	char buf[32];
	const struct ublksrv_dev *dev;
	struct ublksrv_queue_info *info_array = NULL;
	struct shmem_listener_info linfo = {};
	linfo.sock_fd = -1;
	pthread_t listener;
	int i, ret = -EINVAL;
	int nr_wanted;
	unsigned nr_io_threads;
	unsigned nr_threads = 0;
	sem_t queue_sem;
	bool has_shmem_zc = dinfo->flags & UBLK_F_SHMEM_ZC;

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

	/*
	 * One thread per (queue, io thread) pair, laid out so that the
	 * threads of a queue are adjacent.
	 */
	nr_io_threads = ublksrv_flags_io_threads(dinfo->ublksrv_flags);
	if (nr_io_threads > MAX_IO_THREADS_PER_QUEUE) {
		/* recover trusts the driver's flags, which add did not check */
		fprintf(stderr, "dev-%d asks for %u io threads per queue, max %d\n",
				dev_id, nr_io_threads, MAX_IO_THREADS_PER_QUEUE);
		goto free;
	}
	if (dinfo->nr_hw_queues > MAX_NR_HW_QUEUES) {
		/* likewise for the queue count, which add clamps but recover takes as is */
		fprintf(stderr, "dev-%d has %u queues, max %d\n",
				dev_id, dinfo->nr_hw_queues, MAX_NR_HW_QUEUES);
		goto free;
	}
	nr_wanted = dinfo->nr_hw_queues * nr_io_threads;

	info_array = (struct ublksrv_queue_info *)calloc(sizeof(
				struct ublksrv_queue_info),
			nr_wanted);

	sem_init(&queue_sem, 0, 0);

	for (i = 0; i < nr_wanted; i++) {
		info_array[i].dev = dev;
		info_array[i].qid = i / nr_io_threads;
		info_array[i].io_thread_idx = i % nr_io_threads;
		info_array[i].queue_sem = &queue_sem;
		if (pthread_create(&info_array[i].thread, NULL,
					ublksrv_queue_handler,
					&info_array[i])) {
			ublk_err("ublk dev %d queue %d io thread %d create thread failed",
					dev_id, info_array[i].qid,
					info_array[i].io_thread_idx);
			break;
		}
		nr_threads++;
	}

	for (i = 0; i < nr_threads; i++)
		sem_wait(&queue_sem);

	/*
	 * The device only becomes ready once every tag of every queue has
	 * been fetched, and START_DEV waits for that without a timeout. So
	 * a queue thread which failed to start would hang us here forever;
	 * fail the device instead.
	 */
	if (nr_threads < nr_wanted ||
			!ublksrv_queues_started(info_array, nr_threads)) {
		fprintf(stderr, "dev-%d not all queue threads started\n", dev_id);
		ret = -EIO;
		goto abort;
	}

	ret = ublksrv_tgt_start_dev(ctrl_dev, dev, evtfd);
	if (ret) {
		fprintf(stderr, "dev-%d start dev failed, ret %d\n", dev_id, ret);
		goto abort;
	}

	/* Register hugetlbfs buffer after device is started */
	if (has_shmem_zc && shmem_htlb_path) {
		ret = ublk_shmem_htlb_setup(shmem_htlb_path, shmem_rdonly,
					     ctrl_dev);
		if (ret < 0) {
			fprintf(stderr, "htlb setup failed: %d\n", ret);
			ublksrv_ctrl_stop_dev(ctrl_dev);
			/* the io threads must exit before the device is freed */
			ublksrv_drain_fetch_commands(info_array, nr_threads);
			goto free;
		}
	}

	/* Start shmem listener thread for memfd fd-passing */
	if (has_shmem_zc) {
		linfo.dev_id = dev_id;
		linfo.cdev = ctrl_dev;
		linfo.stop_efd = eventfd(0, 0);
		if (linfo.stop_efd >= 0)
			pthread_create(&listener, NULL,
				       ublk_shmem_listener_fn, &linfo);
	}

	/* wait until we are terminated */
	ublksrv_drain_fetch_commands(info_array, nr_threads);

	/* Stop shmem listener thread */
	if (has_shmem_zc && linfo.stop_efd >= 0) {
		uint64_t stop_val = 1;
		write(linfo.stop_efd, &stop_val, sizeof(stop_val));
		pthread_join(listener, NULL);
		close(linfo.stop_efd);
		ublk_shmem_sock_destroy(dev_id, linfo.sock_fd);
	}
	if (has_shmem_zc)
		ublk_shmem_unregister_all();
	goto free;
 abort:
	/*
	 * Delete the device so the driver cancels the fetch commands of the
	 * threads which did start, letting them leave ublksrv_process_io();
	 * they must be joined before ublksrv_dev_deinit() frees the device
	 * out from under them.  Should the async delete itself fail, stop
	 * the device instead: on one which never started that goes straight
	 * to cancelling the commands, and it exists on every kernel.
	 */
	if (ublksrv_ctrl_del_dev_async(ctrl_dev) < 0) {
		int err = ublksrv_ctrl_stop_dev(ctrl_dev);

		/*
		 * With neither, the fetch commands stay pending and the join
		 * below never returns; say so, since that is the very hang
		 * this path is meant to turn into an error.
		 */
		if (err < 0)
			ublk_err("dev-%d: can't delete or stop the device (%d), io threads may not exit",
					dev_id, err);
	}
	ublksrv_drain_fetch_commands(info_array, nr_threads);
 free:
	free(info_array);

	ublksrv_dev_deinit(dev);
out:
	/* deleting dev can only move on when the ublkc is closed */
	if (ret)
		ublksrv_ctrl_del_dev(ctrl_dev);
	ublk_log("end ublksrv io daemon");
	closelog();

	return ret;
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

static int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev, int evtfd)
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

	return ublksrv_device_handler(ctrl_dev, evtfd);
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

	__mkpath(dirname(strdupa(dir)), 0755);

	mask = umask(0);
	ret = mkdir(dir, mode);
	umask(mask);

	return ret;
}

/*
 * The run dir is shared with unprivileged users, who create their own
 * pid files in it, so make it sticky like /tmp: nobody can remove or
 * replace another user's pid file, and the kernel's protected_symlinks
 * and protected_regular checks apply.
 */
static int mkpath(const char *dir)
{
	const mode_t mode = S_IRWXU | S_IRWXG | S_IRWXO | S_ISVTX;
	struct stat sb;
	int ret, fd;

	ret = __mkpath(strdupa(dir), mode);
	if (ret)
		return ret;

	/*
	 * Older versions created it 0777 without the sticky bit. Check and
	 * fix the dir through one fd, so it can't be swapped for a symlink
	 * in between. A symlink isn't ours to repair.
	 */
	fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return 0;
	if (!fstat(fd, &sb) && sb.st_uid == geteuid() &&
			(sb.st_mode & S_IWOTH) && !(sb.st_mode & S_ISVTX))
		ret = fchmod(fd, (sb.st_mode & 07777) | S_ISVTX);
	close(fd);

	return ret;
}
#pragma GCC diagnostic pop

/*
 * This function parses all the standard options that all targets support
 * and populates ublksrv_dev_data.
 */
static int ublksrv_parse_add_opts(struct ublksrv_dev_data *data, int *efd, int argc, char *argv[])
{
	int opt;
	int uring_comp = 0;
	int need_get_data = 0;
	int user_recovery = 0;
	int user_recovery_fail_io = 0;
	int user_recovery_reissue = 0;
	int unprivileged = 0;
	int zero_copy = 0;
	int batch_io = 0;
	int shmem_zc = 0;
	int io_threads = 1;
	int seq_tags = 0;
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
		{ "max_io_buf_bytes",	1,	NULL, 0},
		{ "threads_per_queue",	1,	NULL, 'T'},
		{ "seq_tags",	0,	NULL, 'S'},
		{ "zerocopy",	0,	NULL, 'z'},
		{ "batch-io",	0,	NULL, 'b'},
		{ "shmem_zc",	0,	NULL, 0},
		{ "htlb",	1,	NULL, 0},
		{ "rdonly_shmem_buf",	0,	NULL, 0},
		{ NULL }
	};

	data->queue_depth = DEF_QD;
	data->nr_hw_queues = DEF_NR_HW_QUEUES;
	data->max_io_buf_bytes = DEF_BUF_SIZE;
	data->dev_id = -1;
	data->run_dir = ublksrv_get_pid_dir();

	mkpath(data->run_dir);

	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:u:g:r:e:i:T:zbS",
				  longopts, &option_index)) != -1) {
		switch (opt) {
		case 'n':
			data->dev_id = strtol(optarg, NULL, 10);
			break;
		case 't':
			data->tgt_type = optarg;
			break;
		case 'z':
			zero_copy = 1;
			break;
		case 'T':
			io_threads = strtol(optarg, NULL, 10);
			break;
		case 'S':
			seq_tags = 1;
			break;
		case 'b':
			batch_io = 1;
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
			if (!strcmp(longopts[option_index].name, "max_io_buf_bytes"))
				data->max_io_buf_bytes = strtol(optarg, NULL, 10);
			if (!strcmp(longopts[option_index].name, "shmem_zc"))
				shmem_zc = 1;
			if (!strcmp(longopts[option_index].name, "htlb"))
				shmem_htlb_path = strdup(optarg);
			if (!strcmp(longopts[option_index].name, "rdonly_shmem_buf"))
				shmem_rdonly = true;
			break;
		}
	}

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
	if (zero_copy)
		data->flags |= UBLK_F_SUPPORT_ZERO_COPY;
	if (batch_io)
		data->flags |= UBLK_F_BATCH_IO;
	if (shmem_zc)
		data->flags |= UBLK_F_SHMEM_ZC;
	if (seq_tags)
		data->ublksrv_flags |= UBLKSRV_F_SEQ_TAG_PARTITION;

	/*
	 * Range-check before encoding: the field is six bits wide, so an
	 * out of range count would otherwise be silently truncated into a
	 * legal-looking one. What needs the target's own flags or the
	 * driver's features is checked in ublksrv_cmd_dev_add().
	 */
	if (io_threads < 1 || io_threads > MAX_IO_THREADS_PER_QUEUE) {
		fprintf(stderr, "io threads per queue %d out of range [1, %d]\n",
				io_threads, MAX_IO_THREADS_PER_QUEUE);
		return -EINVAL;
	}
	if (io_threads > data->queue_depth) {
		fprintf(stderr, "io threads per queue %d exceeds queue depth %u\n",
				io_threads, data->queue_depth);
		return -EINVAL;
	}
	ublksrv_flags_set_io_threads(&data->ublksrv_flags, io_threads);

	ublk_set_debug_mask(debug_mask);

	return 0;
}

static void ublksrv_print_std_opts(void)
{
	printf("\t-n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH\n");
	printf("\t-u URING_COMP -g NEED_GET_DATA -r USER_RECOVERY\n");
	printf("\t-i USER_RECOVERY_REISSUE -e USER_RECOVERY_FAIL_IO\n");
	printf("\t-T THREADS_PER_QUEUE [-S]\n");
	printf("\t\tserve each queue from several io threads; -S gives each\n");
	printf("\t\tthread one contiguous block of tags instead of an\n");
	printf("\t\tinterleaved set\n");
	printf("\t--debug_mask=0x{DBG_MASK} --unprivileged\n");
}

/*
 * Probe whether the running kernel honors IORING_RECVSEND_FIXED_BUF on a
 * plain io_uring recv (the always-needed half of net AUTO_BUF_REG zero
 * copy; plain-send fixed-buf support lands in the same 7.2 series). A
 * pre-7.2 kernel rejects the flag at issue time with -EINVAL/-EOPNOTSUPP,
 * so submit a real recv against a preloaded socketpair and a registered
 * buffer, and treat a non-positive cqe result as "unsupported".
 *
 * Returns true iff supported. Any setup failure is reported as unsupported
 * so the caller conservatively falls back to the copy path.
 */
static bool ublksrv_probe_net_fixed_buf(void)
{
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct iovec iov;
	char rbuf[8] = {0};
	const char sbuf[8] = "zcprobe";
	int sv[2], res;
	bool supported = false;

	if (io_uring_queue_init(2, &ring, 0) < 0)
		return false;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		goto exit_ring;

	iov.iov_base = rbuf;
	iov.iov_len = sizeof(rbuf);
	if (io_uring_register_buffers(&ring, &iov, 1) < 0)
		goto close_sock;

	/* preload data so a supported recv completes instead of blocking */
	if (write(sv[1], sbuf, sizeof(sbuf)) != (ssize_t)sizeof(sbuf))
		goto unreg;

	sqe = io_uring_get_sqe(&ring);
	/*
	 * For a fixed-buffer send/recv against a userspace-registered buffer,
	 * sqe->addr is an absolute address inside the registered buffer (the
	 * kernel derives the in-buffer offset as addr - buf_base), exactly
	 * like IORING_OP_READ_FIXED. So pass the buffer's own base (offset 0),
	 * not NULL - NULL is outside the buffer and faults with -EFAULT even on
	 * a supporting kernel. An unsupported kernel rejects the flag earlier
	 * with -EINVAL regardless of the address.
	 */
	io_uring_prep_recv(sqe, sv[0], rbuf, sizeof(rbuf), MSG_DONTWAIT);
	sqe->ioprio |= IORING_RECVSEND_FIXED_BUF;
	sqe->buf_index = 0;

	if (io_uring_submit(&ring) < 0)
		goto unreg;
	if (io_uring_wait_cqe(&ring, &cqe) < 0)
		goto unreg;

	res = cqe->res;
	io_uring_cqe_seen(&ring, cqe);
	/* supported: bytes copied into the registered buffer (res > 0) */
	supported = res > 0;

 unreg:
	io_uring_unregister_buffers(&ring);
 close_sock:
	close(sv[0]);
	close(sv[1]);
 exit_ring:
	io_uring_queue_exit(&ring);

	return supported;
}

static int ublksrv_cmd_dev_add(const struct ublksrv_tgt_type *tgt_type, int argc, char *argv[])
{
	struct ublksrv_dev_data data = {0};
	struct ublksrv_ctrl_dev *dev;
	int ret, evtfd = -1;
	unsigned nr_io_threads;

	ret = ublksrv_parse_add_opts(&data, &evtfd, argc, argv);
	if (ret)
		goto fail_send_event;

	if (data.tgt_type && strcmp(data.tgt_type, tgt_type->name)) {
		fprintf(stderr, "Wrong tgt_type specified\n");
		return -EINVAL;
	}

	data.tgt_type = tgt_type->name;
	data.tgt_ops = tgt_type;
	data.flags |= tgt_type->ublk_flags;
	data.ublksrv_flags |= tgt_type->ublksrv_flags;

	nr_io_threads = ublksrv_flags_io_threads(data.ublksrv_flags);
	if (nr_io_threads > 1) {
		unsigned max = tgt_type->max_io_threads_per_queue;

		/*
		 * The driver hands out one io daemon per io, but not for a
		 * batch io device: it clears UBLK_F_PER_IO_DAEMON for those,
		 * and ublksrv's batch code arms every tag of a queue from a
		 * single thread anyway.
		 */
		if (data.flags & UBLK_F_BATCH_IO) {
			fprintf(stderr, "io threads per queue is not supported with BATCH_IO\n");
			ret = -EINVAL;
			goto fail_send_event;
		}

		if (nr_io_threads > (max ? max : 1)) {
			fprintf(stderr, "target %s supports at most %u io thread(s) per queue\n",
					tgt_type->name, max ? max : 1);
			ret = -EINVAL;
			goto fail_send_event;
		}
	}

	//optind = 0;	/* so that tgt code can parse their arguments */
	data.tgt_argc = argc;
	data.tgt_argv = argv;

	/* try UBLK_F_AUTO_BUF_REG at default */
	if (data.flags & UBLK_F_SUPPORT_ZERO_COPY)
		data.flags |= UBLK_F_AUTO_BUF_REG;

	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		ret = -EOPNOTSUPP;
		goto fail_send_event;
	}

	if (nr_io_threads > 1 ||
	    data.flags & (UBLK_F_SUPPORT_ZERO_COPY | UBLK_F_BATCH_IO |
			  UBLK_F_SHMEM_ZC)) {
		__u64 features = 0;

		ret = ublksrv_ctrl_get_features(dev, &features);
		if (ret)
			goto fail;

		/*
		 * Serving a queue from several threads needs each tag's fetch
		 * to be allowed from its own task. Check before creating the
		 * device so an old driver fails here rather than leaving
		 * START_DEV waiting for tags nobody may fetch.
		 */
		if (nr_io_threads > 1 && !(features & UBLK_F_PER_IO_DAEMON)) {
			fprintf(stderr, "UBLK_F_PER_IO_DAEMON not supported by kernel\n");
			ret = -ENOTSUP;
			goto fail;
		}

		if ((data.flags & UBLK_F_SUPPORT_ZERO_COPY) &&
		    !(features & UBLK_F_SUPPORT_ZERO_COPY)) {
			ret = -ENOTSUP;
			goto fail;
		}

		if ((data.flags & UBLK_F_BATCH_IO) &&
		    !(features & UBLK_F_BATCH_IO)) {
			fprintf(stderr, "UBLK_F_BATCH_IO not supported by kernel\n");
			ret = -ENOTSUP;
			goto fail;
		}

		if ((data.flags & UBLK_F_SHMEM_ZC) &&
		    !(features & UBLK_F_SHMEM_ZC)) {
			fprintf(stderr, "UBLK_F_SHMEM_ZC not supported by kernel\n");
			ret = -ENOTSUP;
			goto fail;
		}

		/* disable UBLK_F_AUTO_BUF_REG if it isn't supported yet */
		if ((data.flags & UBLK_F_SUPPORT_ZERO_COPY) &&
		    !(features & UBLK_F_AUTO_BUF_REG)) {
			data.flags &= ~UBLK_F_AUTO_BUF_REG;
			ublksrv_ctrl_deinit(dev);
			dev = ublksrv_ctrl_init(&data);
		}

		/*
		 * A net target (e.g. nbd) references the request's registered
		 * buffer from a plain send/recv via IORING_RECVSEND_FIXED_BUF.
		 * That only works from the 7.2 kernel on, independently of the
		 * ublk-side UBLK_F_AUTO_BUF_REG feature checked above. If the
		 * running kernel lacks it, fall back to the copy path by
		 * dropping both zero-copy flags before the device is created.
		 */
		if ((data.flags & UBLK_F_AUTO_BUF_REG) &&
		    (data.ublksrv_flags & UBLKSRV_F_ZC_NEEDS_NET_FIXED_BUF) &&
		    !ublksrv_probe_net_fixed_buf()) {
			fprintf(stderr, "ublk: kernel lacks io_uring net "
				"registered-buffer send/recv; "
				"falling back to copy (no zero copy)\n");
			data.flags &= ~(UBLK_F_AUTO_BUF_REG |
					UBLK_F_SUPPORT_ZERO_COPY);
			ublksrv_ctrl_deinit(dev);
			dev = ublksrv_ctrl_init(&data);
		}
	}

	if (!dev) {
		fprintf(stderr, "can't re-init dev %d\n", data.dev_id);
		ret = -EOPNOTSUPP;
		goto fail_send_event;
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

		/*
		 * ADD_DEV fills in the flags the driver actually gave this
		 * device, which is the only place the per-io daemon promise
		 * can be confirmed rather than inferred from GET_FEATURES:
		 * the driver withholds it per device, not per kernel.
		 */
		if (nr_io_threads > 1 &&
				!(info->flags & UBLK_F_PER_IO_DAEMON)) {
			fprintf(stderr, "dev %d has no UBLK_F_PER_IO_DAEMON, can't use %u io threads per queue\n",
					data.dev_id, nr_io_threads);
			ret = -ENOTSUP;
			goto fail_del_dev;
		}
	}
	ret = ublksrv_start_daemon(dev, evtfd);
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
 fail_send_event:
	ublksrv_tgt_send_dev_event(evtfd, -1);

	return ret;
}

static char *ublksrv_pop_cmd(int *argc, char *argv[])
{
	char *cmd = argv[1];
	if (*argc < 2) {
		return NULL;
	}

	(*argc)--;
	memmove(&argv[1], &argv[2], *argc * sizeof(argv[0]));

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

	dev = ublksrv_ctrl_recover_init(&data);
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

	if (dev_info.dev_id != (unsigned)number) {
		fprintf(stderr, "dev id doesn't match read %d for dev %d\n",
				dev_info.dev_id, number);
		goto fail;
	}

	ret = ublksrv_json_read_target_base_info(buf, &tgt_json);
	if (ret < 0) {
		fprintf(stderr, "can't read dev info for %d\n", number);
		goto fail;
	}

	ret = ublksrv_start_daemon(dev, evtfd);
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

static int ublksrv_cmd_dev_user_recover(const struct ublksrv_tgt_type *tgt_type, int argc, char *argv[])
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
	const char *type = tgt_type ? tgt_type->name : "TYPE";

	printf("ublk[.%s] add -t %s\n", type, type);
	ublksrv_print_std_opts();
	if (tgt_type && tgt_type->usage_for_add)
		tgt_type->usage_for_add();
	else {
		printf("\tFor additional arguments specific to %s, run:\n", type);
		printf("\t\tublk help -t %s\n", type);
	}
	printf("ublk[.%s] recover -n DEV_ID\n", type);
	printf("ublk[.%s] help -t %s\n", type, type);
	printf("ublk del -n DEV_ID [ -a | --all]\n");
	printf("ublk list -n DEV_ID -v\n");
	printf("ublk set_affinity -n DEV_ID -q QID --cpuset SET\n");
	printf("ublk features\n");
	printf("ublk -v | --version\n");
}

int ublksrv_main(const struct ublksrv_tgt_type *tgt_type, int argc, char *argv[])
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
