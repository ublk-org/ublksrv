#include "ubdsrv.h"

static int null_init_tgt(struct ubdsrv_tgt_info *tgt, int type, int argc,
		char *argv[])
{
	struct ubdsrv_ctrl_dev *cdev = container_of(tgt,
			struct ubdsrv_ctrl_dev, tgt);

	if (type != UBDSRV_TGT_TYPE_NULL)
		return -1;

	tgt->dev_size = 250UL * 1024 * 1024 * 1024;
	tgt->tgt_ring_depth = cdev->dev_info.queue_depth;

	cdev->dev_info.dev_blocks = tgt->dev_size / cdev->dev_info.block_size;

	return 0;
}

static co_io_job null_handle_io_async(struct ubdsrv_queue *q, struct ubd_io *io,
		int tag)
{
	const struct ubdsrv_io_desc *iod = ubdsrv_get_iod(q, tag);

	ubdsrv_mark_io_done(io, iod->nr_sectors << 9);

	/* commit and re-fetch to ubd driver */
	ubdsrv_queue_io_cmd(q, tag);

	co_io_job_return();
}

static int null_prepare_target(struct ubdsrv_tgt_info *tgt,
		struct ubdsrv_dev *dev)
{
	struct ubdsrv_ctrl_dev *cdev = container_of(tgt,
			struct ubdsrv_ctrl_dev, tgt);

	tgt->nr_fds = 0;

	cdev->shm_offset += snprintf(cdev->shm_addr + cdev->shm_offset,
			UBDSRV_SHM_SIZE - cdev->shm_offset,
			"target type: %s\n", tgt->ops->name);

	return 0;
}

struct ubdsrv_tgt_type  null_tgt_type = {
	.type	= UBDSRV_TGT_TYPE_NULL,
	.name	=  "null",
	.init_tgt = null_init_tgt,
	.handle_io_async = null_handle_io_async,
	.prepare_target	=  null_prepare_target,
};

static void tgt_null_init() __attribute__((constructor));

static void tgt_null_init(void)
{
	ubdsrv_register_tgt_type(&null_tgt_type);
}

