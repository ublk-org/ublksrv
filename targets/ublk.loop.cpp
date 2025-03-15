// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include "ublksrv_tgt.h"

struct loop_tgt_data {
	bool user_copy;
	bool zero_copy;
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

static int loop_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(cdev);
	int fd, ret;
	unsigned long direct_io = 0;
	struct ublk_params p;
	char file[PATH_MAX];
	struct loop_tgt_data *tgt_data = (struct loop_tgt_data*)dev->tgt.tgt_data;
	struct stat sb;

	ret = ublk_json_read_target_str_info(cdev, "backing_file", file);
	if (ret < 0) {
		ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_ulong_info(cdev, "direct_io",
			&direct_io);
	if (ret) {
		ublk_err( "%s: read target direct_io failed %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_ulong_info(cdev, "offset",
			&tgt_data->offset);
	if (ret) {
		ublk_err( "%s: read target offset failed %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_params(&p, cdev);
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

	tgt_data->zero_copy = info->flags & UBLK_F_SUPPORT_ZERO_COPY;
	tgt_data->user_copy = info->flags & UBLK_F_USER_COPY;
	if (tgt_data->zero_copy || tgt_data->user_copy)
		tgt->tgt_ring_depth *= 2;

	return 0;
}

static int loop_recover_tgt(struct ublksrv_dev *dev, int type)
{
	dev->tgt.tgt_data = calloc(sizeof(struct loop_tgt_data), 1);

	return loop_setup_tgt(dev, type, true);
}

static int loop_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
		*argv[])
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int buffered_io = 0;
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
	struct ublksrv_tgt_base_json tgt_json = { 0 };
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD |
			UBLK_PARAM_TYPE_DMA_ALIGN,
		.basic = {
			.attrs                  = UBLK_ATTR_VOLATILE_CACHE | UBLK_ATTR_FUA,
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
		.dma = {
			.alignment = 511,
		},
	};
	bool can_discard = false;
	unsigned long offset = 0;

	if (ublksrv_is_recovering(cdev))
		return loop_recover_tgt(dev, 0);

	strcpy(tgt_json.name, "loop");

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

	ublk_json_write_dev_info(cdev);
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_tgt_str(cdev, "backing_file", file);
	ublk_json_write_tgt_long(cdev, "direct_io", !buffered_io);
	ublk_json_write_tgt_ulong(cdev, "offset", offset);
	ublk_json_write_params(cdev, &p);

	close(fd);

	dev->tgt.tgt_data = calloc(sizeof(struct loop_tgt_data), 1);

	return loop_setup_tgt(dev, type, false);
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

static inline void lo_rw_handle_fua(struct io_uring_sqe *sqe,
		const struct ublksrv_io_desc *iod)
{
	if (ublksrv_get_op(iod) == UBLK_IO_OP_WRITE && (iod->op_flags & UBLK_IO_F_FUA))
		sqe->rw_flags |= RWF_DSYNC;
}

static int lo_rw_user_copy(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct loop_tgt_data *tgt_data)
{
	unsigned ublk_op = ublksrv_get_op(iod);
	struct io_uring_sqe *sqe[2];
	__u64 pos = ublk_pos(q->q_id, tag, 0);
	void *buf = ublksrv_queue_get_io_buf(q, tag);

	ublk_queue_alloc_sqes(q, sqe, 2);
	if (ublk_op == UBLK_IO_OP_READ) {
		/* read from backing file to io buffer */
		io_uring_prep_read(sqe[0], 1 /*fds[1]*/,
				buf,
				iod->nr_sectors << 9,
				(iod->start_sector + tgt_data->offset) << 9);
		io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE | IOSQE_IO_LINK);
		sqe[0]->user_data = build_user_data(tag, ublk_op, 0, 1);

		/* copy io buffer to ublkc device */
		io_uring_prep_write(sqe[1], 0 /*fds[0]*/,
				buf, iod->nr_sectors << 9, pos);
		io_uring_sqe_set_flags(sqe[1], IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe[1]->user_data = build_user_data(tag, UBLK_USER_COPY_WRITE, 0, 1);
	} else {
		/* copy ublkc device data to io buffer */
		io_uring_prep_read(sqe[0], 0 /*fds[0]*/,
			buf, iod->nr_sectors << 9, pos);
		io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE | IOSQE_IO_LINK);
		sqe[0]->user_data = build_user_data(tag, UBLK_USER_COPY_READ, 0, 1);

		/* write data in io buffer to backing file */
		io_uring_prep_write(sqe[1], 1 /*fds[1]*/,
			buf, iod->nr_sectors << 9,
			(iod->start_sector + tgt_data->offset) << 9);
		io_uring_sqe_set_flags(sqe[1], IOSQE_FIXED_FILE);
		lo_rw_handle_fua(sqe[1], iod);
		/* bit63 marks us as tgt io */
		sqe[1]->user_data = build_user_data(tag, ublk_op, 0, 1);
	}
	return 2;
}

static int lo_rw(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct loop_tgt_data *tgt_data)
{
	enum io_uring_op uring_op = ublk_to_uring_fs_op(iod, false);
	void *buf = (void *)iod->addr;
	struct io_uring_sqe *sqe[1];

	ublk_queue_alloc_sqes(q, sqe, 1);
	io_uring_prep_rw(uring_op,
		sqe[0],
		1 /*fds[1]*/,
		buf,
		iod->nr_sectors << 9,
		(iod->start_sector + tgt_data->offset) << 9);
	io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE);
	lo_rw_handle_fua(sqe[0], iod);

	sqe[0]->user_data = build_user_data(tag, ublksrv_get_op(iod), 0, 1);
	return 1;
}

static int lo_rw_zero_copy(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct loop_tgt_data *tgt_data)
{
	unsigned ublk_op = ublksrv_get_op(iod);
	enum io_uring_op uring_op = ublk_to_uring_fs_op(iod, true);
	struct io_uring_sqe *sqe[3];

	ublk_queue_alloc_sqes(q, sqe, 3);

	io_uring_prep_buf_register(sqe[0], 0, tag, q->q_id, tag);
	sqe[0]->user_data = build_user_data(tag,
			ublk_cmd_op_nr(UBLK_U_IO_REGISTER_IO_BUF),
			0,
			1);
	sqe[0]->flags |= IOSQE_CQE_SKIP_SUCCESS | IOSQE_FIXED_FILE | IOSQE_IO_LINK;

	io_uring_prep_rw(uring_op,
			sqe[1],
			1 /*fds[1]*/,
			0,
			iod->nr_sectors << 9,
			(iod->start_sector + tgt_data->offset) << 9);
	sqe[1]->buf_index = tag;
	sqe[1]->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
	sqe[1]->user_data = build_user_data(tag, ublk_op, 0, 1);

	io_uring_prep_buf_unregister(sqe[2], 0, tag, q->q_id, tag);
	sqe[2]->flags |= IOSQE_FIXED_FILE;
	sqe[2]->user_data = build_user_data(tag,
			ublk_cmd_op_nr(UBLK_U_IO_UNREGISTER_IO_BUF),
			0,
			1);

	// buf register is marked as IOSQE_CQE_SKIP_SUCCESS
	return 2;
}

static int loop_queue_tgt_rw(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct loop_tgt_data *data)
{
	/* zero_copy has top priority */
	if (data->zero_copy)
		return lo_rw_zero_copy(q, iod, tag, data);
	if (data->user_copy)
		return lo_rw_user_copy(q, iod, tag, data);
	return lo_rw(q, iod, tag, data);
}

static int loop_handle_flush(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag)
{
	struct io_uring_sqe *sqe[1];
	unsigned ublk_op = ublksrv_get_op(iod);

	ublk_queue_alloc_sqes(q, sqe, 1);
	io_uring_prep_fsync(sqe[0],
			1 /*fds[1]*/,
			IORING_FSYNC_DATASYNC);
	io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE);
	/* bit63 marks us as tgt io */
	sqe[0]->user_data = build_user_data(tag, ublk_op, 0, 1);

	return 1;
}

static int loop_handle_discard(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct loop_tgt_data *data)
{
	struct io_uring_sqe *sqe[1];
	unsigned ublk_op = ublksrv_get_op(iod);

	ublk_queue_alloc_sqes(q, sqe, 1);
	io_uring_prep_fallocate(sqe[0], 1 /*fds[1]*/,
				loop_fallocate_mode(iod),
				(iod->start_sector + data->offset) << 9,
				iod->nr_sectors << 9);
	io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE);
	/* bit63 marks us as tgt io */
	sqe[0]->user_data = build_user_data(tag, ublk_op, 0, 1);
	return 1;
}

static int loop_queue_tgt_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	const struct ublksrv_io_desc *iod = data->iod;
	unsigned ublk_op = ublksrv_get_op(iod);
	const struct loop_tgt_data *tgt_data = (struct loop_tgt_data*) q->dev->tgt.tgt_data;
	int ret;

	switch (ublk_op) {
	case UBLK_IO_OP_FLUSH:
		ret = loop_handle_flush(q, iod, tag);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
	case UBLK_IO_OP_DISCARD:
		ret = loop_handle_discard(q, iod, tag, tgt_data);
		break;
	case UBLK_IO_OP_READ:
	case UBLK_IO_OP_WRITE:
		ret = loop_queue_tgt_rw(q, iod, tag, tgt_data);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	ublk_dbg(UBLK_DBG_IO, "%s: tag %d ublk io %x %llx %u\n", __func__, tag,
			iod->op_flags, iod->start_sector, iod->nr_sectors << 9);
	return ret;
}

static co_io_job __loop_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	int ret;

 again:
	ret = loop_queue_tgt_io(q, data, tag);
	if (ret > 0) {
		int io_res = 0;
		while (ret-- > 0) {
			int res;

			co_await__suspend_always(tag);
			res = ublksrv_tgt_process_cqe(io, &io_res);
			if (res < 0 && io_res >= 0)
				io_res = res;
		}
		if (io_res == -EAGAIN)
			goto again;
		ublksrv_complete_io(q, tag, io_res);
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
	ublksrv_tgt_io_done(q, data, cqe);
}

static void loop_deinit_tgt(const struct ublksrv_dev *dev)
{
	fsync(dev->tgt.fds[1]);
	close(dev->tgt.fds[1]);
	free(dev->tgt.tgt_data);
}

static void loop_cmd_usage()
{
	const char *name = "loop";

	printf("ublk.%s add -t %s\n", name, name);
	ublksrv_print_std_opts();
	printf("\t-f backing_file [--buffered_io] [--offset NUM]\n");
	printf("\t\tdefault is direct IO to backing file\n");
	printf("\t\toffset skips first NUM sectors on backing file\n");
}

static const struct ublksrv_tgt_type  loop_tgt_type = {
	.handle_io_async = loop_handle_io_async,
	.tgt_io_done = loop_tgt_io_done,
	.usage_for_add = loop_cmd_usage,
	.init_tgt = loop_init_tgt,
	.deinit_tgt	=  loop_deinit_tgt,
	.name	=  "loop",
};

int main(int argc, char *argv[])
{
	return ublksrv_tgt_cmd_main(&loop_tgt_type, argc, argv);
}
