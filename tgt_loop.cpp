// SPDX-License-Identifier: MIT or GPL-2.0-only

#include "ublk_cmd.h"
#include <atomic>
#include <config.h>

#include <linux/blkzoned.h>
#include <poll.h>
#include <stdint.h>
#include <sys/epoll.h>
#include "ublksrv_tgt.h"
#include <sys/queue.h>

static bool user_copy;
static bool block_device;

static bool backing_supports_discard(char *name)
{
	int fd;
	char buf[512];
	int len;

	len = snprintf(buf, 512, "/sys/block/%s/queue/discard_max_hw_bytes",
			basename(name));
	buf[len] = 0;
	fd = open(buf, O_RDONLY);
	if (fd > 0) {
		char val[128];
		int ret = pread(fd, val, 128, 0);
		unsigned long long bytes = 0;

		close(fd);
		if (ret > 0)
			bytes = strtol(val, NULL, 10);

		if (bytes > 0)
			return true;
	}
	return false;
}

static int loop_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery,
		const char *jbuf)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	int fd, ret;
	long direct_io = 0;
	struct ublk_params p;
	char file[PATH_MAX];

	ublk_assert(jbuf);

	ret = ublksrv_json_read_target_str_info(jbuf, PATH_MAX, "backing_file", file);
	if (ret < 0) {
		ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublksrv_json_read_target_ulong_info(jbuf, "direct_io",
			&direct_io);
	if (ret) {
		ublk_err( "%s: read target direct_io failed %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublksrv_json_read_params(&p, jbuf);
	if (ret) {
		ublk_err( "%s: read ublk params failed %d\n",
				__func__, ret);
		return ret;
	}

	fd = open(file, O_RDWR);
	if (fd < 0) {
		ublk_err( "%s: backing file %s can't be opened\n",
				__func__, file);
		return fd;
	}

	if (direct_io)
		fcntl(fd, F_SETFL, O_DIRECT);

	ublksrv_tgt_set_io_data_size(tgt);
	tgt->dev_size = p.basic.dev_sectors << 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 1;
	tgt->fds[1] = fd;
	user_copy = info->flags & UBLK_F_USER_COPY;
	if (user_copy)
		tgt->tgt_ring_depth *= 2;

	return 0;
}

static int loop_recovery_tgt(struct ublksrv_dev *dev, int type)
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	const char *jbuf = ublksrv_ctrl_get_recovery_jbuf(cdev);

	ublk_assert(type == UBLKSRV_TGT_TYPE_LOOP);
	ublk_assert(info->state == UBLK_S_DEV_QUIESCED);

	return loop_setup_tgt(dev, type, true, jbuf);
}

static int loop_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
		*argv[])
{
	int buffered_io = 0;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	static const struct option lo_longopts[] = {
		{ "file",		1,	NULL, 'f' },
		{ "buffered_io",	no_argument, &buffered_io, 1},
		{ NULL }
	};
	unsigned long long bytes;
	struct stat st;
	int fd, opt;
	char *file = NULL;
	int jbuf_size;
	char *jbuf;
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD,
		.basic = {
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift	= 12,
			.io_min_shift	= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
		},

		.discard = {
			.max_discard_sectors	= UINT_MAX >> 9,
			.max_discard_segments	= 1,
		},
	};
	bool can_discard = false;

	strcpy(tgt_json.name, "loop");

	if (type != UBLKSRV_TGT_TYPE_LOOP)
		return -1;

	while ((opt = getopt_long(argc, argv, "-:f:",
				  lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			file = strdup(optarg);
			break;
		}
	}

	if (!file)
		return -1;

	fd = open(file, O_RDWR);
	if (fd < 0) {
		ublk_err( "%s: backing file %s can't be opened\n",
				__func__, file);
		return -2;
	}

	if (info->flags & UBLK_F_ZONED) {
		uint32_t zone_size;
		if (ioctl(fd, BLKGETZONESZ, &zone_size)) {
			syslog(LOG_ERR, "%s: BLKGETSONESZ ioctl failed for %s\n", __func__, file);
			return -1;
		}

		if (zone_size == 0) {
			syslog(LOG_ERR, "%s: target %s is not zoned\n",
				__func__, file);
			return -1;
		}

		dev->tgt.zone_size_sectors = zone_size;

		p.basic.chunk_sectors = zone_size;
		p.types |= UBLK_PARAM_TYPE_ZONED;
		/* TODO: lift these values from loop target */
		p.zoned.max_open_zones = 14;
		p.zoned.max_active_zones = 14;
		p.zoned.max_zone_append_sectors = zone_size;
	}

	if (fstat(fd, &st) < 0)
		return -2;

	if (S_ISBLK(st.st_mode)) {
		unsigned int bs, pbs;

		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
			return -1;
		if (ioctl(fd, BLKSSZGET, &bs) != 0)
			return -1;
		if (ioctl(fd, BLKPBSZGET, &pbs) != 0)
			return -1;
		block_device = true;
		p.basic.logical_bs_shift = ilog2(bs);
		p.basic.physical_bs_shift = ilog2(pbs);
		can_discard = backing_supports_discard(file);
	} else if (S_ISREG(st.st_mode)) {
		block_device = false;
		bytes = st.st_size;
		can_discard = true;
		p.basic.logical_bs_shift = ilog2(st.st_blksize);
		p.basic.physical_bs_shift = ilog2(st.st_blksize);
	} else {
		bytes = 0;
	}

	/*
	 * in case of buffered io, use common bs/pbs so that all FS
	 * image can be supported
	 */
	if (buffered_io || !ublk_param_is_valid(&p) ||
			fcntl(fd, F_SETFL, O_DIRECT)) {
		p.basic.logical_bs_shift = 9;
		p.basic.physical_bs_shift = 12;
		buffered_io = 1;
	}

	tgt_json.dev_size = bytes;
	p.basic.dev_sectors = bytes >> 9;

	if (st.st_blksize && can_discard)
		p.discard.discard_granularity = st.st_blksize;
	else
		p.types &= ~UBLK_PARAM_TYPE_DISCARD;

	jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	ublk_json_write_dev_info(dev, &jbuf, &jbuf_size);
	ublk_json_write_target_base(dev, &jbuf, &jbuf_size, &tgt_json);
	ublk_json_write_tgt_str(dev, &jbuf, &jbuf_size, "backing_file", file);
	ublk_json_write_tgt_long(dev, &jbuf, &jbuf_size, "direct_io", !buffered_io);
	ublk_json_write_params(dev, &jbuf, &jbuf_size, &p);

	close(fd);

	return loop_setup_tgt(dev, type, false, jbuf);
}

static void loop_usage_for_add(void)
{
	printf("           loop: -f backing_file [--buffered_io]\n");
	printf("           	default is direct IO to backing file\n");
}

static inline int loop_fallocate_mode(const struct ublksrv_io_desc *iod)
{
       __u16 ublk_op = ublksrv_get_op(iod);
       __u32 flags = ublksrv_get_flags(iod);
       int mode = FALLOC_FL_KEEP_SIZE;

       /* follow logic of linux kernel loop */
       if (ublk_op == UBLK_IO_OP_DISCARD) {
               mode |= FALLOC_FL_PUNCH_HOLE;
       } else if (ublk_op == UBLK_IO_OP_WRITE_ZEROES) {
               if (flags & UBLK_IO_F_NOUNMAP)
                       mode |= FALLOC_FL_ZERO_RANGE;
               else
                       mode |= FALLOC_FL_PUNCH_HOLE;
       } else {
               mode |= FALLOC_FL_ZERO_RANGE;
       }

       return mode;
}

static void loop_queue_tgt_read(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag)
{
	unsigned ublk_op = ublksrv_get_op(iod);

	if (user_copy) {
		struct io_uring_sqe *sqe, *sqe2;
		__u64 pos = ublk_pos(q->q_id, tag, 0);
		void *buf = ublksrv_queue_get_io_buf(q, tag);

		ublk_get_sqe_pair(q->ring_ptr, &sqe, &sqe2);
		io_uring_prep_read(sqe, 1 /*fds[1]*/,
				buf,
				iod->nr_sectors << 9,
				iod->start_sector << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_IO_LINK);
		sqe->user_data = build_user_data(tag, ublk_op, 1, 1);

		io_uring_prep_write(sqe2, 0 /*fds[0]*/,
				buf, iod->nr_sectors << 9, pos);
		io_uring_sqe_set_flags(sqe2, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe2->user_data = build_user_data(tag, ublk_op, 0, 1);
	} else {
		struct io_uring_sqe *sqe;
		void *buf = (void *)iod->addr;

		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_read(sqe, 1 /*fds[1]*/,
			buf,
			iod->nr_sectors << 9,
			iod->start_sector << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
	}
}

static void loop_queue_tgt_write_pos(const struct ublksrv_queue *q,
				 const struct ublksrv_io_desc *iod, int tag, __u64 pos)
{
	unsigned ublk_op = ublksrv_get_op(iod);

	if (user_copy) {
		struct io_uring_sqe *sqe, *sqe2;
		__u64 rpos = ublk_pos(q->q_id, tag, 0);
		void *buf = ublksrv_queue_get_io_buf(q, tag);

		ublk_get_sqe_pair(q->ring_ptr, &sqe, &sqe2);
		io_uring_prep_read(sqe, 0 /*fds[0]*/,
			buf, iod->nr_sectors << 9, rpos);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_IO_LINK);
		sqe->user_data = build_user_data(tag, ublk_op, 1, 1);

		io_uring_prep_write(sqe2, 1 /*fds[1]*/,
			buf, iod->nr_sectors << 9,
			pos);
		io_uring_sqe_set_flags(sqe2, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe2->user_data = build_user_data(tag, ublk_op, 0, 1);
	} else {
		struct io_uring_sqe *sqe;
		void *buf = (void *)iod->addr;

		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_write(sqe, 1 /*fds[1]*/,
			buf,
			iod->nr_sectors << 9,
			pos);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
	}
}

static void loop_queue_tgt_write(const struct ublksrv_queue *q,
				 const struct ublksrv_io_desc *iod, int tag)
{
	loop_queue_tgt_write_pos(q, iod, tag, iod->start_sector << 9);
}

#include <atomic>

std::atomic<struct ublk_io_tgt*> owner = nullptr;

static bool zone_lock(struct ublk_io_tgt* io) {
	struct ublk_io_tgt* tmp = nullptr;
	return owner.compare_exchange_strong(tmp, io);
}

static void zone_unlock(struct ublk_io_tgt *io)
{
	 bool ok = owner.compare_exchange_strong(io, nullptr);
	 assert(ok);
}

static void zone_enqueue(const struct ublksrv_queue *q, struct ublk_io_tgt* io) {
	// Enqueue locally
	struct ublksrv_queue *mq = (struct ublksrv_queue *)q;

	struct iod_queue_entry* element = (struct iod_queue_entry*) malloc(sizeof(struct iod_queue_entry));
	assert(element != nullptr);

	element->io = io;

	STAILQ_INSERT_TAIL(&mq->waiting, element, entry);

}

static bool loop_handle_io_queued(struct ublksrv_queue *q)
{
	if (!STAILQ_EMPTY(&q->waiting)) {
		struct iod_queue_entry* entry = STAILQ_FIRST(&q->waiting);
		struct ublk_io_tgt *io = entry->io;
		STAILQ_REMOVE_HEAD(&q->waiting, entry);
		free(entry);
		io->co.resume();
	}

	return STAILQ_EMPTY(&q->waiting);
}

static int loop_zone_get_wp(const struct ublksrv_queue *q,
			    const struct ublksrv_io_desc *iod,
			    __u64* out_wp)
{
	int nr_zones = 1;
	struct blk_zone_report *report;
	int ret = 0;

	if (!out_wp)
		return EINVAL;

	report = (struct blk_zone_report *) malloc(
		sizeof(struct blk_zone_report) +
		sizeof(struct blk_zone) * nr_zones);

	if (!report) {
		syslog(LOG_ERR, "%s: failed to allocate", __func__);
		return ENOMEM;
	}

	report->sector = iod->start_sector;
	report->nr_zones = nr_zones;

	ret = ioctl(q->dev->tgt.fds[1], BLKREPORTZONE, report);
	if (ret) {
		syslog(LOG_ERR, "%s: BLKREPORTZONE failed\n", __func__);
		ret = EIO;
		goto out;
	}

	if (report->nr_zones == 0) {
		ret = EIO;
		goto out;
	}

	*out_wp = report->zones[0].wp;

out:
	free(report);
	return ret;
}

static int loop_handle_zone_append(const struct ublksrv_queue *q,
				   const struct ublk_io_data *data, int tag)
{
	const struct ublksrv_io_desc *iod = data->iod;
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	__u64 wp;

	if (zone_lock(io)) {
		int ret = loop_zone_get_wp(q, iod, &wp);
		if (ret) {
			return -ret;
		}
		loop_queue_tgt_write_pos(q, iod, tag, wp << 9);
		io->zone_append_alba = wp;
		return 3;
	} else {
		zone_enqueue(q, io);
		return 2;
	}
}

static bool loop_handle_report_zones(const struct ublksrv_queue *q,
				       const struct ublk_io_data *data, int tag)
{
	const struct ublksrv_io_desc *iod = data->iod;
	unsigned ublk_op = ublksrv_get_op(iod);

	ublk_assert(ublk_op == UBLK_IO_OP_REPORT_ZONES);

	struct blk_zone_report *report;
	int ret = 0;
	size_t write_size;
	unsigned int nr_zones = iod->nr_zones;
	void *buf = ublksrv_queue_get_io_buf(q, tag);

	report = (struct blk_zone_report *) malloc(
		sizeof(struct blk_zone_report) +
		sizeof(struct blk_zone) * nr_zones);

	if (!report) {
		syslog(LOG_ERR, "%s: failed to allocate", __func__);
		ublksrv_complete_io(q, tag, -errno);
		return false;
	}

	report->sector = iod->start_sector;
	report->nr_zones = nr_zones;

	ret = ioctl(q->dev->tgt.fds[1], BLKREPORTZONE, report);
	if (ret) {
		syslog(LOG_ERR, "%s: BLKREPORTZONE failed\n", __func__);
		free(report);
		ublksrv_complete_io(q, tag, ret);
		return false;
	}

	if (report->nr_zones == 0) {
		/* Reporting zero length zone to indicate end */
		write_size = sizeof(struct blk_zone);
		memset(buf, 0, write_size);
		goto out_write;
	}

	write_size = sizeof(struct blk_zone) * report->nr_zones;

	// Trusting the kernel to not ask for a report larger than max IO size
	memcpy(buf, &report->zones[0], write_size);


 out_write:
	// User_copy required
	assert(user_copy);
	free(report);
	__u64 pos = ublk_pos(q->q_id, tag, 0);
	struct io_uring_sqe *sqe;
	ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
	io_uring_prep_write(sqe, 0 /*fds[0]*/, buf, write_size, pos);
	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
	/* bit63 marks us as tgt io */
	sqe->user_data = build_user_data(tag, ublk_op, 0, 1);

	return true;

}

static int loop_queue_tgt_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	const struct ublksrv_io_desc *iod = data->iod;
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	struct io_uring_sqe *sqe;
	unsigned ublk_op = ublksrv_get_op(iod);
	int ret = 1;

	switch (ublk_op) {
	case UBLK_IO_OP_FLUSH:
		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_sync_file_range(sqe, 1 /*fds[1]*/,
				iod->nr_sectors << 9,
				iod->start_sector << 9,
				IORING_FSYNC_DATASYNC);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
	case UBLK_IO_OP_DISCARD:
		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_fallocate(sqe, 1 /*fds[1]*/,
				loop_fallocate_mode(iod),
				iod->start_sector << 9,
				iod->nr_sectors << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
		break;
	case UBLK_IO_OP_READ:
		loop_queue_tgt_read(q, iod, tag);
		break;
	case UBLK_IO_OP_WRITE:
		loop_queue_tgt_write(q, iod, tag);
		break;
	case UBLK_IO_OP_ZONE_APPEND:
		ret = loop_handle_zone_append(q, data, tag);
		break;
	case UBLK_IO_OP_REPORT_ZONES:
		if (!loop_handle_report_zones(q, data, tag))
			ret = 4;
		break;
	default:
		return -EINVAL;
	}

	ublk_dbg(UBLK_DBG_IO, "%s: tag %d ublk io %x %llx %u\n", __func__, tag,
			iod->op_flags, iod->start_sector, iod->nr_sectors << 9);

	return ret;
}

static bool loop_handle_zone_ops(const struct ublksrv_queue *q,
				   const struct ublk_io_data *data, int tag)
{
	const struct ublksrv_io_desc *iod = data->iod;
	unsigned ublk_op = ublksrv_get_op(iod);
	unsigned long ioctl_op = 0;
	int ret;

	switch (ublk_op) {
	case UBLK_IO_OP_ZONE_OPEN:
		ioctl_op = BLKOPENZONE;
		break;
	case UBLK_IO_OP_ZONE_CLOSE:
		ioctl_op = BLKCLOSEZONE;
		break;
	case UBLK_IO_OP_ZONE_FINISH:
		ioctl_op = BLKFINISHZONE;
		break;
	case UBLK_IO_OP_ZONE_RESET:
		ioctl_op = BLKRESETZONE;
		break;
	}

	if (ioctl_op) {
		struct blk_zone_range range = {
			.sector = iod->start_sector,
			.nr_sectors = q->dev->tgt.zone_size_sectors,
		};

		ret = ioctl(q->dev->tgt.fds[1], ioctl_op, &range);

		if (ret > 0) {
		       ret = 0;
		}

		ublksrv_complete_io(q, tag, ret);
		return true;
	}
	return false;
}

static co_io_job __loop_handle_io_async(const struct ublksrv_queue *q,
					const struct ublk_io_data *data,
					int tag)
{
	int ret;
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	const struct ublksrv_io_desc *iod = data->iod;

	if (loop_handle_zone_ops(q, data, tag))
		co_return;

	io->queued_tgt_io = 0;
 again:
	ret = loop_queue_tgt_io(q, data, tag);
	io->suspend_reason = ret;

	if (ret == 2) {
		// Waiting for lock
		co_await__suspend_always(tag);
		goto again;
	}

	if (ret == 4) {
		co_return;
	}

	if (ret > 0) {
		if (io->queued_tgt_io)
			ublk_err("bad queued_tgt_io %d\n", io->queued_tgt_io);
		io->queued_tgt_io += 1;

		co_await__suspend_always(tag);
		io->queued_tgt_io -= 1;


		if (io->tgt_io_cqe->res == -EAGAIN)
			goto again;

		if (io->suspend_reason == 3)
			zone_unlock(io);

		unsigned ublk_op = ublksrv_get_op(iod);
		if (ublk_op == UBLK_IO_OP_ZONE_APPEND)
			ublksrv_complete_io_alba(q, tag, io->tgt_io_cqe->res,
						 io->zone_append_alba);
		else
			ublksrv_complete_io(q, tag, io->tgt_io_cqe->res);
	} else if (ret < 0) {
		ublk_err( "fail to queue io %d, ret %d\n", tag, tag);
	} else {
		ublk_err( "no sqe %d\n", tag);
	}
}

static int loop_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	if (block_device && ublksrv_get_op(data->iod) == UBLK_IO_OP_DISCARD) {
		__u64 r[2];
		int res;

		io_uring_submit(q->ring_ptr);

		r[0] = data->iod->start_sector << 9;
		r[1] = data->iod->nr_sectors << 9;
		res = ioctl(q->dev->tgt.fds[1], BLKDISCARD, &r);
		ublksrv_complete_io(q, data->tag, res);
	} else {
		io->co = __loop_handle_io_async(q, data, data->tag);
	}
	return 0;
}

static void loop_tgt_io_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	int tag = user_data_to_tag(cqe->user_data);
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	if (user_data_to_tgt_data(cqe->user_data))
		return;

	ublk_assert(tag == data->tag);
	if (!io->queued_tgt_io && io->suspend_reason == 1)
		ublk_err("%s: wrong queued_tgt_io: res %d qid %u tag %u, cmd_op %u\n",
			__func__, cqe->res, q->q_id,
			user_data_to_tag(cqe->user_data),
			user_data_to_op(cqe->user_data));
	io->tgt_io_cqe = cqe;
	io->co.resume();
}

static void loop_deinit_tgt(const struct ublksrv_dev *dev)
{
	fsync(dev->tgt.fds[1]);
	close(dev->tgt.fds[1]);
}

struct ublksrv_tgt_type loop_tgt_type = {
	.handle_io_async = loop_handle_io_async,
	.tgt_io_done = loop_tgt_io_done,
	.handle_io_queued = loop_handle_io_queued,
	.usage_for_add = loop_usage_for_add,
	.init_tgt = loop_init_tgt,
	.deinit_tgt = loop_deinit_tgt,
	.type = UBLKSRV_TGT_TYPE_LOOP,
	.name = "loop",
	.recovery_tgt = loop_recovery_tgt,
};

static void tgt_loop_init() __attribute__((constructor));

static void tgt_loop_init(void)
{
	ublksrv_register_tgt_type(&loop_tgt_type);
}
