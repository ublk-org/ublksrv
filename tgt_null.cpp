// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include "ublksrv_tgt.h"

static int null_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	int jbuf_size;
	char *jbuf = ublksrv_tgt_return_json_buf(dev, &jbuf_size);
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	unsigned long long dev_size = 250UL * 1024 * 1024 * 1024;
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift		= 12,
			.io_min_shift		= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
			.dev_sectors		= dev_size >> 9,
		},
	};

	strcpy(tgt_json.name, "null");

	if (type != UBLKSRV_TGT_TYPE_NULL)
		return -1;

	tgt_json.dev_size = tgt->dev_size = dev_size;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;
	ublksrv_tgt_set_io_data_size(tgt);

	ublk_json_write_dev_info(dev, &jbuf, &jbuf_size);
	ublk_json_write_target_base(dev, &jbuf, &jbuf_size, &tgt_json);
	ublk_json_write_params(dev, &jbuf, &jbuf_size, &p);

	return 0;
}

static int null_recovery_tgt(struct ublksrv_dev *dev, int type)
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const char *jbuf = ublksrv_ctrl_get_recovery_jbuf(cdev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	int ret;
	struct ublk_params p;

	ublk_assert(jbuf);
	ublk_assert(info->state == UBLK_S_DEV_QUIESCED);
	ublk_assert(type == UBLKSRV_TGT_TYPE_NULL);

	ret = ublksrv_json_read_params(&p, jbuf);
	if (ret) {
		ublk_err( "%s: read ublk params failed %d\n",
				__func__, ret);
		return ret;
	}

	ublksrv_tgt_set_io_data_size(tgt);
	tgt->dev_size = p.basic.dev_sectors << 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;
	return 0;
}

static co_io_job __null_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	ublksrv_complete_io(q, tag, data->iod->nr_sectors << 9);

	co_return;
}

static int null_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	io->co = __null_handle_io_async(q, data, data->tag);

	return 0;
}

struct ublksrv_tgt_type  null_tgt_type = {
	.handle_io_async = null_handle_io_async,
	.init_tgt = null_init_tgt,
	.type	= UBLKSRV_TGT_TYPE_NULL,
	.name	=  "null",
	.recovery_tgt = null_recovery_tgt,
};

static void tgt_null_init() __attribute__((constructor));

static void tgt_null_init(void)
{
	ublksrv_register_tgt_type(&null_tgt_type);
}

