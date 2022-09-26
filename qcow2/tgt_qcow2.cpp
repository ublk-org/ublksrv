// SPDX-License-Identifier: GPL-2.0
#include "ublksrv_tgt.h"
#include "qcow2_format.h"
#include "qcow2.h"

#define HEADER_SIZE  512
#define QCOW2_UNMAPPED   (u64)(-1)

static int qcow2_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
		*argv[])
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info  *info = &dev->ctrl_dev->dev_info;
	static const struct option lo_longopts[] = {
		{ "file",		1,	NULL, 'f' },
		{ NULL }
	};
	unsigned long long bytes;
	struct stat st;
	int jbuf_size;
	char *jbuf;
	int fd, opt, ret;
	void *header_buf;
	QCowHeader *header;
	char *file = NULL;
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			//.attrs = UBLK_ATTR_READ_ONLY,
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift	= 12,
			.io_min_shift	= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
		},
	};
	Qcow2State *qs;

	//1024 queue depth is enough for qcow2, then we can store
	//tag & l1 entry index in single u32 variable.
	if (info->queue_depth > QCOW2_MAX_QUEUE_DEPTH)
		return -EINVAL;

	//qcow2 target doesn't support MQ yet
	if (info->nr_hw_queues > 1)
		return -EINVAL;

	strcpy(tgt_json.name, "qcow2");

	if (type != UBLKSRV_TGT_TYPE_QCOW2)
		return -EINVAL;

	while ((opt = getopt_long(argc, argv, "-:f:",
				  lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			file = strdup(optarg);
			break;
		}
	}

	if (!file)
		return -EINVAL;

	if (posix_memalign((void **)&header_buf, 512, HEADER_SIZE))
		return -EINVAL;

	header = (QCowHeader *)header_buf;
	fd = open(file, O_RDWR | O_DIRECT);
	if (fd < 0) {
		syslog(LOG_ERR, "%s backing file %s can't be opened\n",
				__func__, file);
		return -EINVAL;
	}

	ret = read(fd, header_buf, HEADER_SIZE);
	if (ret != HEADER_SIZE) {
		syslog(LOG_ERR, "%s: return backing file %s %d %d\n",
				__func__, file, HEADER_SIZE, ret);
		return -EINVAL;
	}

	tgt_json.dev_size = tgt->dev_size = be64_to_cpu(header->size);
	p.basic.dev_sectors = tgt->dev_size >> 9,
	p.basic.chunk_sectors = 1 << (be32_to_cpu(header->cluster_bits) - 9);
	tgt->tgt_ring_depth = info->queue_depth * 4;
	tgt->extra_ios = QCOW2_PARA::META_MAX_TAGS;
	tgt->nr_fds = 1;
	tgt->fds[1] = fd;
	dev->target_data = qs = make_qcow2state(file, dev);

	jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	ublksrv_json_write_dev_info(dev->ctrl_dev, jbuf, jbuf_size);
	ublksrv_json_write_target_base_info(jbuf, jbuf_size, &tgt_json);
	do {
		ret = ublksrv_json_write_params(&p, jbuf, jbuf_size);
		if (ret < 0)
			goto realloc;

		ret = ublksrv_json_write_target_str_info(jbuf, jbuf_size,
				"backing_file", file);
		if (ret < 0)
			goto realloc;

		ret = ublksrv_json_write_target_ulong_info(jbuf, jbuf_size,
				"version", qs->header.get_version());
		if (ret < 0)
			goto realloc;
		ret = ublksrv_json_write_target_ulong_info(jbuf, jbuf_size,
				"cluster_bits", qs->header.get_cluster_bits());
		if (ret < 0)
			goto realloc;
		ret = ublksrv_json_write_target_ulong_info(jbuf, jbuf_size,
				"header_length", qs->header.get_header_length());
		if (ret < 0)
			goto realloc;

		ret = ublksrv_json_write_target_ulong_info(jbuf, jbuf_size,
				"l1_size", qs->header.get_l1_size());
		if (ret < 0)
			goto realloc;
		ret = ublksrv_json_write_target_ulong_info(jbuf, jbuf_size,
				"refcount_table_clusters",
				qs->header.get_refcount_table_clusters());
		if (ret < 0)
			goto realloc;
		ret = ublksrv_json_write_target_ulong_info(jbuf, jbuf_size,
				"refcount_order",
			qs->header.get_refcount_order());
 realloc:
		if (ret < 0)
			jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	} while (ret < 0);

	qs->header.dump_ext();

	return 0;
}

static void qcow2_usage_for_add(void)
{
	printf("           qcow2: -f backing_file\n");
}

/* todo: flush meta dirty data */
static inline int qcow2_queue_tgt_fsync(struct ublksrv_queue *q, unsigned io_op,
		int tag, u32 len, u64 offset)
{
	int fd = q->dev->tgt.fds[1];
	struct io_uring_sqe *sqe = io_uring_get_sqe(&q->ring);

	if (!sqe) {
		qcow2_log("%s: tag %d offset %llx op %d, no sqe\n",
				__func__, tag, offset, io_op);
		return -ENOMEM;
	}

	io_uring_prep_sync_file_range(sqe, fd, len ,offset,
			IORING_FSYNC_DATASYNC);
	sqe->user_data = build_user_data(tag, io_op, 0, 1);
	qcow2_io_log("%s: queue io op %d(%llu %llx %llx)"
				" (qid %d tag %u, cmd_op %u target: %d, user_data %llx)\n",
			__func__, io_op, sqe->off, sqe->len, sqe->addr,
			q->q_id, tag, io_op, 1, sqe->user_data);
	q->tgt_io_inflight += 1;
	return 1;
}

static inline int qcow2_queue_tgt_zero_cluster(const Qcow2State *qs,
		struct ublksrv_queue *q, int tag, u64 offset)
{
	int mode = FALLOC_FL_ZERO_RANGE;
	int fd = q->dev->tgt.fds[1];
	struct io_uring_sqe *sqe = io_uring_get_sqe(&q->ring);

	if (!sqe) {
		qcow2_log("%s: tag %d offset %llx op %d, no sqe for zeroing\n",
			__func__, tag, offset, IORING_OP_FALLOCATE);
		return -ENOMEM;
	}

	io_uring_prep_fallocate(sqe, fd, mode, offset,
			(1ULL << qs->header.cluster_bits));
	sqe->user_data = build_user_data(tag,
			IORING_OP_FALLOCATE, 0, 1);
	qcow2_io_log("%s: queue io op %d(%llx %llx %llx)"
				" (qid %d tag %u, target: %d, user_data %llx)\n",
			__func__, IORING_OP_FALLOCATE, offset,
			sqe->len, sqe->addr, q->q_id, tag, 1, sqe->user_data);
	q->tgt_io_inflight += 1;
	return 1;
}

static inline int qcow2_queue_tgt_rw_fast(struct ublksrv_queue *q,
		unsigned io_op, int tag, u64 offset,
		const struct ublksrv_io_desc *iod)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&q->ring);

	if (!sqe) {
		qcow2_log("%s: tag %d offset %llx op %d, no sqe for rw\n",
				__func__, tag, offset, io_op);
		return -ENOMEM;
	}

	io_uring_prep_rw(io_op, sqe, 1, (void *)iod->addr,
			iod->nr_sectors << 9, offset);
	sqe->flags = IOSQE_FIXED_FILE;
	sqe->user_data = build_user_data(tag, io_op, 0, 1);
	qcow2_io_log("%s: queue io op %d(%llu %llx %llx)"
				" (qid %d tag %u, cmd_op %u target: %d, user_data %llx)\n",
			__func__, io_op, sqe->off, sqe->len, sqe->addr,
			q->q_id, tag, io_op, 1, sqe->user_data);
	q->tgt_io_inflight += 1;

	return 1;

}

static inline int qcow2_queue_tgt_rw(struct ublksrv_queue *q, unsigned io_op,
		int tag, u64 offset, const struct ublksrv_io_desc *iod,
		u32 *expected_op)
{
	Qcow2State *qs = dev_to_qcow2state(q->dev);
	u64 cluster_start = offset & ~((1ULL << qs->header.cluster_bits) - 1);
	Qcow2ClusterState *cs = qs->cluster_allocator.
		get_cluster_state(cluster_start);
	u8 cs_state = (cs == nullptr ? QCOW2_ALLOC_DONE : cs->get_state());

	if (cs_state >= QCOW2_ALLOC_ZEROED) {
		*expected_op = io_op;
		return qcow2_queue_tgt_rw_fast(q, io_op, tag, offset, iod);
	}

	if (io_op == IORING_OP_WRITE) {
		if (cs_state == QCOW2_ALLOC_ZEROING) {
			cs->add_waiter(tag);
			throw MetaUpdateException();
		}

		if (cs_state == QCOW2_ALLOC_STARTED) {
			int ret = qcow2_queue_tgt_zero_cluster(qs, q, tag,
					cluster_start);
			if (ret >= 0)
				cs->set_state(QCOW2_ALLOC_ZEROING);
			*expected_op = IORING_OP_FALLOCATE;
			return ret;
		}
		return 0;
	} else {
		memset((void *)iod->addr, 0,
				iod->nr_sectors << 9);
		return 0;
	}
}

/* return how many sqes queued */
static int qcow2_queue_tgt_io(struct ublksrv_queue *q, unsigned io_op,
		int tag, u64 offset, u32 *exp_op)
{
	const struct ublksrv_io_desc *iod = ublksrv_get_iod(q, tag);
	int ret;

	//we don't support discard yet
	if (io_op == IORING_OP_FALLOCATE)
		return -ENOTSUP;

	if (io_op == IORING_OP_FSYNC) {
		ret = qcow2_queue_tgt_fsync(q, io_op, tag,
				iod->nr_sectors << 9, offset);
		*exp_op = io_op;
	} else
		ret = qcow2_queue_tgt_rw(q, io_op, tag, offset, iod, exp_op);

	return ret;
}

static inline bool l2_entry_read_as_zero(u64 entry)
{
	if (!entry || (entry & 0x1))
		return true;
	return false;
}

static co_io_job __qcow2_handle_io_async(struct ublksrv_queue *q,
		struct ublk_io *io, int tag)
{
	Qcow2State *qs = dev_to_qcow2state(q->dev);
	const struct ublksrv_io_desc *iod = ublksrv_get_iod(q, tag);
	unsigned long start = iod->start_sector << 9;
	u64 mapped_start;
	qcow2_io_ctx_t ioc(tag, q->q_id);
	struct io_uring_cqe *cqe;
	int ret = 0;
	unsigned int op = ublksrv_get_op(iod);

	qcow2_io_log("%s: tag %d, ublk op %x virt %llx/%u\n",
			__func__, tag, op, start, (iod->nr_sectors << 9));

	qcow2_assert((start + (unsigned long)(iod->nr_sectors << 9)) <=
			qs->get_dev_size());
again:
	try {
		mapped_start = qs->cluster_map.map_cluster(ioc, start,
				op == UBLK_IO_OP_WRITE);
	} catch (MetaIoException &meta_error) {

		co_io_job_submit_and_wait(tag);

		cqe = io->tgt_io_cqe;
		io->tgt_io_cqe = NULL;
		ret = qcow2_meta_io_done(q, cqe);
		if (ret == -EAGAIN)
			goto again;
		if (ret < 0)
			goto exit;
	} catch (MetaUpdateException &meta_update_error) {
		co_io_job_submit_and_wait(tag);

		cqe = io->tgt_io_cqe;
		io->tgt_io_cqe = NULL;
		ret = qcow2_meta_io_done(q, cqe);
		if (ret == -EAGAIN)
			goto again;
		if (ret < 0)
			goto exit;
		goto again;
	}

	qcow2_io_log("%s: tag %d, ublk op %x virt %llx/%u to host %llx\n",
			__func__, tag, op, start, (iod->nr_sectors << 9),
			mapped_start);

	if (!mapped_start) {
		// write to unallocated cluster, so have to allocate first
		if ((op == UBLK_IO_OP_READ) &&
			l2_entry_read_as_zero(mapped_start)) {
			ret = iod->nr_sectors << 9;
			memset((void *)iod->addr, 0, ret);
		} else {
			qcow2_log("%s: tag %d virt %llx op %d map failed\n",
					__func__, tag, start, op);
			ret = -EIO;
		}
	} else {
		const struct ublksrv_io_desc *iod = ublksrv_get_iod(q, tag);
		unsigned io_op = ublksrv_convert_cmd_op(iod);
		unsigned exp_op;

		mapped_start &= ((1ULL << 63) - 1);

		qcow2_assert(mapped_start + (iod->nr_sectors << 9) <=
				qs->cluster_allocator.max_physical_size);
queue_io:
		//the only exception is from handling zeroing cluster
		try {
			ret = qcow2_queue_tgt_io(q, io_op, tag, mapped_start,
					&exp_op);
		} catch (MetaUpdateException &meta_error) {
			co_io_job_submit_and_wait(tag);
			goto queue_io;
		}
		if (ret > 0) {
			u32 cqe_op;
			u64 cluster_start = mapped_start &
				~((1ULL << qs->header.cluster_bits) - 1);

			co_io_job_submit_and_wait(tag);
			cqe = io->tgt_io_cqe;
			ret = cqe->res;
			if (ret == -EAGAIN) {
				qcow2_log("%s zeroing cluster IO eagain\n",
							__func__);
				//submit this write IO again
				if (user_data_to_op(cqe->user_data) == io_op)
					goto queue_io;

				//if the cluster zeroing IO isn't done, retry
				if (qs->cluster_allocator.
				    alloc_cluster_reset(cluster_start))
					goto queue_io;
			}

			qcow2_io_log("%s: io done, tag %d res %d user_data %llx\n",
							__func__, tag, ret,
							cqe->user_data);
			if (exp_op != io_op) {
				if (user_data_to_op(cqe->user_data) == IORING_OP_FALLOCATE)
					qs->cluster_allocator.alloc_cluster_zeroed(q,
						tag, cluster_start);
				goto queue_io;
			}
		} else if (ret == 0) {
			ret = iod->nr_sectors << 9;
		}
	}
exit:
	if (ret < 0)
		qcow2_log("%s io failed(%d %llx %lu) ret %d\n", __func__,
				op, start, iod->nr_sectors, ret);
	qcow2_io_log("%s tag %d io complete(%d %llx %lu) ret %d\n", __func__,
				tag, op, start, iod->nr_sectors, ret);
	ublksrv_complete_io(q, tag, ret);
}

static int qcow2_handle_io_async(struct ublksrv_queue *q, int tag)
{
	struct ublk_io_tgt *io = (struct ublk_io_tgt *)&q->ios[tag];

	io->co = __qcow2_handle_io_async(q, (struct ublk_io *)io, tag);
	return 0;
}

static void qcow2_deinit_tgt(struct ublksrv_dev *dev)
{
	Qcow2State *qs = dev_to_qcow2state(dev);

	//now all io slots are available, just use the zero tag
	qcow2_io_ctx_t ioc(0, 0);

	qs->dump_meta();

	delete qs;
}

static void qcow2_tgt_io_done(struct ublksrv_queue *q, struct io_uring_cqe *cqe)
{
	unsigned tag = user_data_to_tag(cqe->user_data);
	struct ublk_io *io = &q->ios[tag];

	qcow2_io_log("%s: res %d qid %u tag %u, cmd_op %u\n",
			__func__, cqe->res, q->q_id,
			user_data_to_tag(cqe->user_data),
			user_data_to_op(cqe->user_data));
	//special tag is ignored, so far it is used in sending
	//fsync during flushing meta
	if (tag != 0xffff) {
		io->tgt_io_cqe = cqe;
		((struct ublk_io_tgt *)io)->co.resume();
	}
}

static void qcow2_handle_io_bg(struct ublksrv_queue *q, int nr_queued_io)
{
	Qcow2State *qs = dev_to_qcow2state(q->dev);

	meta_log("%s %d, queued io %d\n", __func__, __LINE__, nr_queued_io);
	qs->kill_slices(q);

	qs->meta_flushing.run_flush(q, nr_queued_io);
}

struct ublksrv_tgt_type  qcow2_tgt_type = {
	.handle_io_async = qcow2_handle_io_async,
	.tgt_io_done = qcow2_tgt_io_done,
	.handle_io_background = qcow2_handle_io_bg,
	.usage_for_add	=  qcow2_usage_for_add,
	.init_tgt = qcow2_init_tgt,
	.deinit_tgt	=  qcow2_deinit_tgt,
	.type	= UBLKSRV_TGT_TYPE_QCOW2,
	.name	=  "qcow2",
};

static void tgt_qcow2_init() __attribute__((constructor));

static void tgt_qcow2_init(void)
{
	ublksrv_register_tgt_type(&qcow2_tgt_type);
}