// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include "ublksrv_tgt.h"

#ifndef IORING_NOP_INJECT_RESULT
#define IORING_NOP_INJECT_RESULT        (1U << 0)
#endif

#ifndef IORING_NOP_FIXED_BUFFER
#define IORING_NOP_FIXED_BUFFER         (1U << 3)
#endif

static int null_recover_tgt(struct ublksrv_dev *dev, int type);

static int null_setup_tgt(struct ublksrv_dev *dev)
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(cdev);
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	struct ublk_params p;
	int ret;

	ret = ublk_json_read_params(&p, cdev);
	if (ret) {
		ublk_err( "%s: read ublk params failed %d\n",
				__func__, ret);
		return ret;
	}

	tgt->dev_size = p.basic.dev_sectors << 9;
	tgt->tgt_ring_depth = info->queue_depth;
	if (info->flags & UBLK_F_SUPPORT_ZERO_COPY)
		tgt->tgt_ring_depth *= 2;
	tgt->nr_fds = 0;
	ublksrv_tgt_set_io_data_size(tgt);

	return 0;
}

static int null_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(cdev);
	struct ublksrv_tgt_base_json tgt_json = { 0 };
	unsigned long long dev_size = 250UL * 1024 * 1024 * 1024;
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.attrs                  = UBLK_ATTR_VOLATILE_CACHE,
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift		= 12,
			.io_min_shift		= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
			.dev_sectors		= dev_size >> 9,
		},
	};

	if (info->flags & UBLK_F_UNPRIVILEGED_DEV)
		return -1;

	if (ublksrv_is_recovering(cdev))
		return null_recover_tgt(dev, 0);

	strcpy(tgt_json.name, "null");

	ublk_json_write_dev_info(cdev);
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_params(cdev, &p);
	tgt_json.dev_size = dev_size;

	return null_setup_tgt(dev);
}

static int null_recover_tgt(struct ublksrv_dev *dev, int type)
{
	return null_setup_tgt(dev);
}

static int null_submit_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	unsigned ublk_op = ublksrv_get_op(data->iod);
	struct io_uring_sqe *sqe[3];

	if (!ublksrv_tgt_queue_zc(q))
		return 0;

	ublk_queue_alloc_sqes(q, sqe, 3);

	io_uring_prep_buf_register(sqe[0], 0, tag, q->q_id, tag);
	sqe[0]->flags |= IOSQE_CQE_SKIP_SUCCESS | IOSQE_FIXED_FILE| IOSQE_IO_LINK;
	sqe[0]->user_data = build_user_data(tag,
			ublk_cmd_op_nr(UBLK_U_IO_REGISTER_IO_BUF),
			0,
			1);

	io_uring_prep_nop(sqe[1]);
	sqe[1]->buf_index = tag;
	sqe[1]->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
	sqe[1]->rw_flags = IORING_NOP_FIXED_BUFFER | IORING_NOP_INJECT_RESULT;
	sqe[1]->len = data->iod->nr_sectors << 9; 	/* injected result */
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

static co_io_job __null_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	int ret;

again:
	ret = null_submit_io(q, data, tag);
	if (ret >= 0) {
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
	} else {
		ublk_err( "fail to queue io %d, ret %d\n", tag, ret);
	}
	co_return;
}

static int null_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	if (ublksrv_tgt_queue_zc(q))
		io->co = __null_handle_io_async(q, data, data->tag);
	else
		ublksrv_complete_io(q, data->tag, data->iod->nr_sectors << 9);

	return 0;
}

static void null_tgt_io_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	ublksrv_tgt_io_done(q, data, cqe);
}

static const struct ublksrv_tgt_type  null_tgt_type = {
	.handle_io_async = null_handle_io_async,
	.tgt_io_done = null_tgt_io_done,
	.init_tgt = null_init_tgt,
	.name	=  "null",
};


int main(int argc, char *argv[])
{
	return ublksrv_tgt_cmd_main(&null_tgt_type, argc, argv);
}
