#include "ubdsrv.h"

static int loop_init_tgt(struct ubdsrv_tgt_info *tgt, int type, int argc, char
		*argv[])
{
	static const struct option lo_longopts[] = {
		{ "file",		1,	NULL, 'f' },
		{ NULL }
	};
	struct ubdsrv_ctrl_dev *cdev = container_of(tgt,
			struct ubdsrv_ctrl_dev, tgt);
	unsigned long long bytes;
	struct stat st;
	int fd, opt;
	char *file = NULL;

	if (type != UBDSRV_TGT_TYPE_LOOP)
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
		fprintf(stderr, "__func__, backing file %s can't be opened\n",
				__func__, file);
		return -2;
	}

	if (fstat(fd, &st) < 0)
		return -2;

	if (S_ISBLK(st.st_mode)) {
		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
			return -1;
	} else if (S_ISREG(st.st_mode)) {
		bytes = st.st_size;
	} else {
		bytes = 0;
	}

	strncpy(tgt->loop.backing_file, file, 1024);
	tgt->dev_size = bytes;

	tgt->tgt_ring_depth = cdev->dev_info.queue_depth;
	cdev->dev_info.dev_blocks = tgt->dev_size / cdev->dev_info.block_size;

	close(fd);

	return 0;
}

static void loop_usage_for_add(void)
{
	printf("           loop: -f backing_file\n");
}

static int loop_prepare_io(struct ubdsrv_tgt_info *tgt)
{
	const char *file = tgt->loop.backing_file;
	int fd;

	fd = open(file, O_RDWR | O_DIRECT);
	if (fd < 0) {
		syslog(LOG_ERR, "%s: %s backing file %s can't be opened\n",
				__func__, file);
		return -1;
	}

	tgt->nr_fds = 1;
	tgt->fds[1] = fd;

	return 0;
}

static void loop_handle_fallocate_async(struct io_uring_sqe *sqe,
		const struct ubdsrv_io_desc *iod)
{
	__u16 ubd_op = ubdsrv_get_op(iod);
	__u32 flags = ubdsrv_get_flags(iod);
	__u32 mode = FALLOC_FL_KEEP_SIZE;

	sqe->addr = iod->nr_sectors << 9;

	/* follow logic of linux kernel loop */
	if (ubd_op == UBD_IO_OP_DISCARD) {
		mode |= FALLOC_FL_PUNCH_HOLE;
	} else if (ubd_op == UBD_IO_OP_WRITE_ZEROES) {
		if (flags & UBD_IO_F_NOUNMAP)
			mode |= FALLOC_FL_ZERO_RANGE;
		else
			mode |= FALLOC_FL_PUNCH_HOLE;
	} else {
		mode |= FALLOC_FL_ZERO_RANGE;
	}
	sqe->len = mode;
}

static int loop_queue_tgt_io(struct ubdsrv_queue *q, struct ubd_io *io,
		int tag)
{
	const struct ubdsrv_io_desc *iod = ubdsrv_get_iod(q, tag);
	unsigned io_op = ubdsrv_convert_cmd_op(iod);
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&q->ring);
	if (!sqe)
		return 0;

	/* bit63 marks us as tgt io */
	sqe->flags = IOSQE_FIXED_FILE;
	sqe->user_data = build_user_data(tag, io_op, 1);
	sqe->fd = 1;
	sqe->opcode = io_op;
	switch (io_op) {
	case IORING_OP_FALLOCATE:
		loop_handle_fallocate_async(sqe, iod);
		break;
	case IORING_OP_FSYNC:
		sqe->fsync_flags = IORING_FSYNC_DATASYNC;
		sqe->len = iod->nr_sectors << 9;
		break;
	default:
		sqe->addr = iod->addr;
		sqe->len = iod->nr_sectors << 9;
	}
	sqe->off = iod->start_sector << 9;

	q->tgt_io_inflight += 1;

	ubdsrv_log(LOG_INFO, "%s: tag %d ubd io %x %llx %u\n", __func__, tag,
			iod->op_flags, iod->start_sector, iod->nr_sectors << 9);
	ubdsrv_log(LOG_INFO, "%s: queue io op %d(%llu %llx %llx)"
				" (qid %d tag %u, cmd_op %u target: %d, user_data %llx) iof %x\n",
			__func__, io_op, sqe->off, sqe->len, sqe->addr,
			q->q_id, tag, io_op, 1, sqe->user_data, io->flags);

	return 1;
}

static co_io_job loop_handle_io_async(struct ubdsrv_queue *q, struct ubd_io *io,
		int tag)
{
	struct io_uring_cqe *cqe;
	int ret;

	io->queued_tgt_io = 0;
 again:
	ret = loop_queue_tgt_io(q, io, tag);
	if (ret) {
		if (io->queued_tgt_io)
			ubdsrv_log(LOG_INFO, "bad queued_tgt_io %d\n",
					io->queued_tgt_io);
		io->queued_tgt_io += 1;

		co_io_job_submit_and_wait();
		io->queued_tgt_io -= 1;

		cqe = io->tgt_io_cqe;
		if (cqe->res == -EAGAIN)
			goto again;

		/* all target io is done, so this io command is completed */
		ubdsrv_mark_io_done(io, cqe->res);

		/* commit and re-fetch to ubd driver */
		ubdsrv_queue_io_cmd(q, tag);
	} else {
		ubdsrv_log(LOG_INFO, "no sqe %d\n", tag);
	}
}

static int loop_prepare_target(struct ubdsrv_tgt_info *tgt,
		struct ubdsrv_dev *dev)
{
	struct ubdsrv_ctrl_dev *cdev = container_of(tgt,
			struct ubdsrv_ctrl_dev, tgt);
	int ret;

	ret = loop_prepare_io(tgt);

	if (ret)
		return ret;

	cdev->shm_offset += snprintf(cdev->shm_addr + cdev->shm_offset,
			UBDSRV_SHM_SIZE - cdev->shm_offset,
			"target type: %s backing file: %s\n",
			tgt->ops->name, tgt->loop.backing_file);
	return 0;
}

struct ubdsrv_tgt_type  loop_tgt_type = {
	.type	= UBDSRV_TGT_TYPE_LOOP,
	.name	=  "loop",
	.init_tgt = loop_init_tgt,
	.handle_io_async = loop_handle_io_async,
	.prepare_target	=  loop_prepare_target,
	.usage_for_add	=  loop_usage_for_add,
};

static void tgt_loop_init() __attribute__((constructor));

static void tgt_loop_init(void)
{
	ubdsrv_register_tgt_type(&loop_tgt_type);
}
