// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include "ublksrv_tgt.h"

struct loop_tgt_data {
	bool user_copy;
	bool block_device;
	unsigned long offset;
};

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
	unsigned long direct_io = 0;
	struct ublk_params p;
	char file[PATH_MAX];
	struct loop_tgt_data *tgt_data = (struct loop_tgt_data*)dev->tgt.tgt_data;
	struct stat sb;

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

	ret = ublksrv_json_read_target_ulong_info(jbuf, "offset",
			&tgt_data->offset);
	if (ret) {
		ublk_err( "%s: read target offset failed %d\n",
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

	if (fstat(fd, &sb) < 0) {
		ublk_err( "%s: unable to stat %s\n",
				  __func__, file);
		return -1;
	}

	tgt_data->block_device = S_ISBLK(sb.st_mode);

	if (direct_io)
		fcntl(fd, F_SETFL, O_DIRECT);

	ublksrv_tgt_set_io_data_size(tgt);
	tgt->dev_size = p.basic.dev_sectors << 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 1;
	tgt->fds[1] = fd;
	tgt_data->user_copy = info->flags & UBLK_F_USER_COPY;
	if (tgt_data->user_copy)
		tgt->tgt_ring_depth *= 2;


	return 0;
}

static int loop_recovery_tgt(struct ublksrv_dev *dev, int type)
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const char *jbuf = ublksrv_ctrl_get_recovery_jbuf(cdev);

	ublk_assert(type == UBLKSRV_TGT_TYPE_LOOP);

	dev->tgt.tgt_data = calloc(sizeof(struct loop_tgt_data), 1);

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
		{ "offset",		required_argument, NULL, 'o'},
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
	unsigned long offset = 0;

	strcpy(tgt_json.name, "loop");

	if (type != UBLKSRV_TGT_TYPE_LOOP)
		return -1;

	while ((opt = getopt_long(argc, argv, "-:f:o:",
				  lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			file = strdup(optarg);
			break;
		case 'o':
			offset = strtoul(optarg, NULL, 10);
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
		p.basic.logical_bs_shift = ilog2(bs);
		p.basic.physical_bs_shift = ilog2(pbs);
		can_discard = backing_supports_discard(file);
	} else if (S_ISREG(st.st_mode)) {
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

	if (bytes > 0) {
		unsigned long long offset_bytes = offset << 9;

		if (offset_bytes >= bytes) {
			ublk_err( "%s: offset %lu greater than device size %llu",
					  __func__, offset, bytes);
			return -2;
		}
		bytes -= offset_bytes;
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
	ublk_json_write_tgt_ulong(dev, &jbuf, &jbuf_size, "offset", offset);
	ublk_json_write_params(dev, &jbuf, &jbuf_size, &p);

	close(fd);

	dev->tgt.tgt_data = calloc(sizeof(struct loop_tgt_data), 1);

	return loop_setup_tgt(dev, type, false, jbuf);
}

static void loop_usage_for_add(void)
{
	printf("           loop: -f backing_file [--buffered_io] [--offset NUM]\n");
	printf("           	default is direct IO to backing file\n");
	printf("           	offset skips first NUM sectors on backing file\n");
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
	const struct loop_tgt_data *tgt_data = (struct loop_tgt_data*) q->dev->tgt.tgt_data;

	if (tgt_data->user_copy) {
		struct io_uring_sqe *sqe, *sqe2;
		__u64 pos = ublk_pos(q->q_id, tag, 0);
		void *buf = ublksrv_queue_get_io_buf(q, tag);

		ublk_get_sqe_pair(q->ring_ptr, &sqe, &sqe2);
		io_uring_prep_read(sqe, 1 /*fds[1]*/,
				buf,
				iod->nr_sectors << 9,
				(iod->start_sector + tgt_data->offset) << 9);
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
			(iod->start_sector + tgt_data->offset) << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
	}
}

static void loop_queue_tgt_write(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag)
{
	unsigned ublk_op = ublksrv_get_op(iod);
	const struct loop_tgt_data *tgt_data = (struct loop_tgt_data*) q->dev->tgt.tgt_data;

	if (tgt_data->user_copy) {
		struct io_uring_sqe *sqe, *sqe2;
		__u64 pos = ublk_pos(q->q_id, tag, 0);
		void *buf = ublksrv_queue_get_io_buf(q, tag);

		ublk_get_sqe_pair(q->ring_ptr, &sqe, &sqe2);
		io_uring_prep_read(sqe, 0 /*fds[0]*/,
			buf, iod->nr_sectors << 9, pos);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_IO_LINK);
		sqe->user_data = build_user_data(tag, ublk_op, 1, 1);

		io_uring_prep_write(sqe2, 1 /*fds[1]*/,
			buf, iod->nr_sectors << 9,
			(iod->start_sector + tgt_data->offset) << 9);
		io_uring_sqe_set_flags(sqe2, IOSQE_FIXED_FILE);
		sqe2->rw_flags |= RWF_DSYNC;
		/* bit63 marks us as tgt io */
		sqe2->user_data = build_user_data(tag, ublk_op, 0, 1);
	} else {
		struct io_uring_sqe *sqe;
		void *buf = (void *)iod->addr;

		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_write(sqe, 1 /*fds[1]*/,
			buf,
			iod->nr_sectors << 9,
			(iod->start_sector + tgt_data->offset) << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		sqe->rw_flags |= RWF_DSYNC;
		/* bit63 marks us as tgt io */
		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
	}
}

static int loop_queue_tgt_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	const struct ublksrv_io_desc *iod = data->iod;
	struct io_uring_sqe *sqe;
	unsigned ublk_op = ublksrv_get_op(iod);
	const struct loop_tgt_data *tgt_data = (struct loop_tgt_data*) q->dev->tgt.tgt_data;

	switch (ublk_op) {
	case UBLK_IO_OP_FLUSH:
		ublk_get_sqe_pair(q->ring_ptr, &sqe, NULL);
		io_uring_prep_sync_file_range(sqe, 1 /*fds[1]*/,
				iod->nr_sectors << 9,
				(iod->start_sector + tgt_data->offset) << 9,
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
				(iod->start_sector + tgt_data->offset) << 9,
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
	default:
		return -EINVAL;
	}

	ublk_dbg(UBLK_DBG_IO, "%s: tag %d ublk io %x %llx %u\n", __func__, tag,
			iod->op_flags, iod->start_sector, iod->nr_sectors << 9);

	return 1;
}

static co_io_job __loop_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	int ret;
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	io->queued_tgt_io = 0;
 again:
	ret = loop_queue_tgt_io(q, data, tag);
	if (ret > 0) {
		if (io->queued_tgt_io)
			ublk_err("bad queued_tgt_io %d\n", io->queued_tgt_io);
		io->queued_tgt_io += 1;

		co_await__suspend_always(tag);
		io->queued_tgt_io -= 1;

		if (io->tgt_io_cqe->res == -EAGAIN)
			goto again;

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
	const struct loop_tgt_data *tgt_data = (struct loop_tgt_data*) q->dev->tgt.tgt_data;

	if (tgt_data->block_device && ublksrv_get_op(data->iod) == UBLK_IO_OP_DISCARD) {
		__u64 r[2];
		int res;

		io_uring_submit(q->ring_ptr);

		r[0] = (data->iod->start_sector + tgt_data->offset) << 9;
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
	if (!io->queued_tgt_io)
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
	free(dev->tgt.tgt_data);
}

struct ublksrv_tgt_type  loop_tgt_type = {
	.handle_io_async = loop_handle_io_async,
	.tgt_io_done = loop_tgt_io_done,
	.usage_for_add	=  loop_usage_for_add,
	.init_tgt = loop_init_tgt,
	.deinit_tgt	=  loop_deinit_tgt,
	.type	= UBLKSRV_TGT_TYPE_LOOP,
	.name	=  "loop",
	.recovery_tgt = loop_recovery_tgt,
};

static void tgt_loop_init() __attribute__((constructor));

static void tgt_loop_init(void)
{
	ublksrv_register_tgt_type(&loop_tgt_type);
}
