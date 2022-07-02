#include "ublksrv_tgt.h"

static const char *loop_tgt_backfile(struct ublksrv_tgt_info *tgt)
{
	return (const char *)tgt->tgt_data;
}

static int loop_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
		*argv[])
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info  *info = &dev->ctrl_dev->dev_info;
	struct ublksrv_ctrl_dev_info  *shm_info =
		(struct ublksrv_ctrl_dev_info  *)dev->shm_addr;
	static const struct option lo_longopts[] = {
		{ "file",		1,	NULL, 'f' },
		{ NULL }
	};
	unsigned long long bytes;
	struct stat st;
	int fd, opt;
	char *file = NULL;

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

	fd = open(file, O_RDWR | O_DIRECT);
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

	tgt->tgt_data = strdup(file);
	tgt->dev_size = bytes;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 1;
	tgt->fds[1] = fd;

	pthread_mutex_lock(&dev->shm_lock);
	*shm_info = *info;
	shm_info->dev_blocks = tgt->dev_size / info->block_size;
	dev->shm_offset += snprintf(dev->shm_addr + dev->shm_offset,
			UBLKSRV_SHM_SIZE - dev->shm_offset,
			"target type: %s backing file: %s\n",
			tgt->ops->name, loop_tgt_backfile(tgt));
	pthread_mutex_unlock(&dev->shm_lock);

	return 0;
}

static void loop_usage_for_add(void)
{
	printf("           loop: -f backing_file\n");
}

static void loop_handle_fallocate_async(struct io_uring_sqe *sqe,
		const struct ublksrv_io_desc *iod)
{
	__u16 ublk_op = ublksrv_get_op(iod);
	__u32 flags = ublksrv_get_flags(iod);
	__u32 mode = FALLOC_FL_KEEP_SIZE;

	sqe->addr = iod->nr_sectors << 9;

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
	sqe->len = mode;
}

static int loop_queue_tgt_io(struct ublksrv_queue *q, struct ublk_io *io,
		int tag)
{
	const struct ublksrv_io_desc *iod = ublksrv_get_iod(q, tag);
	unsigned io_op = ublksrv_convert_cmd_op(iod);
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&q->ring);
	if (!sqe)
		return 0;

	/* bit63 marks us as tgt io */
	sqe->flags = IOSQE_FIXED_FILE;
	sqe->user_data = build_user_data(tag, io_op, 0, 1);
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

	ublksrv_log(LOG_INFO, "%s: tag %d ublk io %x %llx %u\n", __func__, tag,
			iod->op_flags, iod->start_sector, iod->nr_sectors << 9);
	ublksrv_log(LOG_INFO, "%s: queue io op %d(%llu %llx %llx)"
				" (qid %d tag %u, cmd_op %u target: %d, user_data %llx) iof %x\n",
			__func__, io_op, sqe->off, sqe->len, sqe->addr,
			q->q_id, tag, io_op, 1, sqe->user_data, io->flags);

	return 1;
}

static co_io_job __loop_handle_io_async(struct ublksrv_queue *q,
		struct ublk_io *io, int tag)
{
	struct io_uring_cqe *cqe;
	int ret;

	io->queued_tgt_io = 0;
 again:
	ret = loop_queue_tgt_io(q, io, tag);
	if (ret) {
		if (io->queued_tgt_io)
			ublksrv_log(LOG_INFO, "bad queued_tgt_io %d\n",
					io->queued_tgt_io);
		io->queued_tgt_io += 1;

		co_io_job_submit_and_wait();
		io->queued_tgt_io -= 1;

		cqe = io->tgt_io_cqe;
		if (cqe->res == -EAGAIN)
			goto again;

		ublksrv_complete_io(q, tag, cqe->res);
	} else {
		ublksrv_log(LOG_INFO, "no sqe %d\n", tag);
	}
}

static int loop_handle_io_async(struct ublksrv_queue *q, int tag)
{
	struct ublk_io_tgt *io = (struct ublk_io_tgt *)&q->ios[tag];

	io->co = __loop_handle_io_async(q, (struct ublk_io *)io, tag);
	return 0;
}

static void loop_tgt_io_done(struct ublksrv_queue *q, struct io_uring_cqe *cqe)
{
	int tag = user_data_to_tag(cqe->user_data);
	struct ublk_io *io = &q->ios[tag];

	if (!io->queued_tgt_io)
		syslog(LOG_WARNING, "%s: wrong queued_tgt_io: res %d qid %u tag %u, cmd_op %u\n",
			__func__, cqe->res, q->q_id,
			user_data_to_tag(cqe->user_data),
			user_data_to_op(cqe->user_data));
	io->tgt_io_cqe = cqe;
	((struct ublk_io_tgt *)io)->co.resume();
}

static void loop_deinit_tgt(struct ublksrv_dev *dev)
{
	free(dev->tgt.tgt_data);
}

struct ublksrv_tgt_type  loop_tgt_type = {
	.type	= UBLKSRV_TGT_TYPE_LOOP,
	.name	=  "loop",
	.init_tgt = loop_init_tgt,
	.handle_io_async = loop_handle_io_async,
	.tgt_io_done = loop_tgt_io_done,
	.usage_for_add	=  loop_usage_for_add,
	.deinit_tgt	=  loop_deinit_tgt,
};

static void tgt_loop_init() __attribute__((constructor));

static void tgt_loop_init(void)
{
	ublksrv_register_tgt_type(&loop_tgt_type);
}
