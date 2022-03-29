#include "ubdsrv.h"
#include "utils.h"

static int null_init_tgt(struct ubdsrv_tgt_info *tgt, int type, int argc,
		char *argv[])
{
	struct ubdsrv_ctrl_dev *cdev = container_of(tgt,
			struct ubdsrv_ctrl_dev, tgt);

	if (type != UBDSRV_TGT_TYPE_NULL)
		return -1;

	tgt->type = type;
	tgt->dev_size = 250UL * 1024 * 1024 * 1024;
	tgt->tgt_ring_depth = cdev->dev_info.queue_depth;

	cdev->dev_info.dev_blocks = tgt->dev_size / cdev->dev_info.block_size;

	return 0;
}

static int null_handle_io(struct ubdsrv_dev *dev, int qid, int tag)
{
	return 0;
}

struct ubdsrv_tgt_ops  null_ops = {
	.name	=  "null",
	.init_tgt = null_init_tgt,
	.handle_io = null_handle_io,
};

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
		fprintf(stderr, "backing file %s can't be opened\n", file);
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

	tgt->type = type;
	strncpy(tgt->loop.backing_file, file, 1024);
	tgt->dev_size = bytes;

	tgt->tgt_ring_depth = cdev->dev_info.queue_depth;
	cdev->dev_info.dev_blocks = tgt->dev_size / cdev->dev_info.block_size;

	close(fd);

	return 0;
}

static int loop_prepare_io(struct ubdsrv_tgt_info *tgt)
{
	const char *file = tgt->loop.backing_file;
	int fd;

	fd = open(file, O_RDWR | O_DIRECT);
	if (fd < 0) {
		syslog(LOG_ERR, "%s backing file %s can't be opened\n", file);
		return -1;
	}

	tgt->nr_fds = 1;
	tgt->fds[1] = fd;

	return 0;
}

static void loop_handle_fallocate_async(struct io_uring_sqe *sqe,
		struct ubdsrv_io_desc *iod)
{
	__u16 ubd_op = ubdsrv_get_op(iod);
	__u32 flags = ubdsrv_get_flags(iod);
	__u32 mode = FALLOC_FL_KEEP_SIZE;

	sqe->addr = ubdsrv_get_blocks(iod) << 9;

	/* follow logic of linux kernel loop */
	if (ubd_op == UBD_IO_OP_DISCARD) {
		mode |= FALLOC_FL_PUNCH_HOLE;
	} else if (ubd_op == UBD_IO_OP_WRITE_ZEROES) {
		if (flags & (1U << UBD_IO_F_NOUNMAP))
			mode |= FALLOC_FL_ZERO_RANGE;
		else
			mode |= FALLOC_FL_PUNCH_HOLE;
	} else {
		mode |= FALLOC_FL_ZERO_RANGE;
	}
	sqe->len = mode;
}

static int loop_handle_io_async(struct ubdsrv_dev *dev, int qid, int tag)
{
	struct ubdsrv_queue *q = &dev->queues[qid];
	struct ubdsrv_io_desc *iod = ubdsrv_get_iod(q, tag);
	struct ubd_io *io = &q->ios[tag];

	struct ubdsrv_uring *r = &q->ring;
	struct io_sq_ring *ring = &r->sq_ring;
	struct io_uring_sqe *sqe;
	unsigned io_op = ubdsrv_convert_cmd_op(iod);
	unsigned index, tail = prep_queue_io_cmd(q);

	if (tail + 1 == atomic_load_acquire(ring->head)) {
		syslog(LOG_INFO, "ring is full, tail %u head %u\n", tail,
				*ring->head);
		return -1;
	}

	ubdsrv_mark_io_handling(io);

	index = tail & r->sq_ring_mask;
	sqe = ubdsrv_uring_get_sqe(r, index, true);

	/* bit63 marks us as tgt io */
	//sqe->flags = IOSQE_FIXED_FILE;
	sqe->user_data = tag | (q->q_id << 16) | (1ULL << 63);
	sqe->fd = 1;
	sqe->opcode = io_op;
	switch (io_op) {
	case IORING_OP_FALLOCATE:
		loop_handle_fallocate_async(sqe, iod);
		break;
	case IORING_OP_FSYNC:
		sqe->fsync_flags = IORING_FSYNC_DATASYNC;
		sqe->len = ubdsrv_get_blocks(iod) << 9;
		break;
	default:
		sqe->addr = iod->addr;
		sqe->len = ubdsrv_get_blocks(iod) << 9;
	}
	sqe->off = iod->start_block << 9;

	ring->array[index] = index;

	commit_queue_io_cmd(q, tail + 1);

	INFO(syslog(LOG_INFO, "%s: queue io op %d(%llu %llu) user_data %lx iof %x\n",
			__func__, io_op, sqe->off, sqe->len, sqe->user_data,
			io->flags));

	return 0;
}

struct ubdsrv_tgt_ops  loop_ops = {
	.name	=  "loop",
	.init_tgt = loop_init_tgt,
	.handle_io_async = loop_handle_io_async,
	.prepare_io	=  loop_prepare_io,
};

const static struct ubdsrv_tgt_ops *tgt_list[] = {
	[UBDSRV_TGT_TYPE_NULL]	=	&null_ops,
	[UBDSRV_TGT_TYPE_LOOP]	=	&loop_ops,
};

int ubdsrv_tgt_init(struct ubdsrv_tgt_info *tgt, char *type, int argc, char
		*argv[])
{
	int i;

	if (type == NULL)
		return -1;

	for (i = 0; i < UBDSRV_TGT_TYPE_MAX; i++) {
		const struct ubdsrv_tgt_ops  *ops = tgt_list[i];

		if (strcmp(ops->name, type))
			continue;

		if (!ops->init_tgt(tgt, i, argc, argv)) {
			tgt->ops = ops;
			return 0;
		}
	}

	return -1;
}

