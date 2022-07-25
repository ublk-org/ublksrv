#include "ublksrv_tgt.h"

static int null_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info  *info = &dev->ctrl_dev->dev_info;
	struct ublksrv_ctrl_dev_info  *shm_info =
		(struct ublksrv_ctrl_dev_info  *)dev->shm_addr;
	int jbuf_size;
	char *jbuf = ublksrv_tgt_return_json_buf(dev, &jbuf_size);
	struct ublksrv_tgt_base_json tgt_json = {
		.name = "null",
		.type = type,
	};

	if (type != UBLKSRV_TGT_TYPE_NULL)
		return -1;

	tgt_json.dev_size = tgt->dev_size = 250UL * 1024 * 1024 * 1024;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;

	ublksrv_json_write_dev_info(dev->ctrl_dev, jbuf, jbuf_size);
	ublksrv_json_write_target_base_info(jbuf, jbuf_size, &tgt_json);

	pthread_mutex_lock(&dev->shm_lock);
	*shm_info = *info;
	shm_info->dev_blocks = tgt->dev_size / info->block_size;
	dev->shm_offset += snprintf(dev->shm_addr + dev->shm_offset,
			UBLKSRV_SHM_SIZE - dev->shm_offset,
			"target type: %s\n", tgt->ops->name);
	pthread_mutex_unlock(&dev->shm_lock);
	return 0;
}

static co_io_job __null_handle_io_async(struct ublksrv_queue *q,
		struct ublk_io *io, int tag)
{
	const struct ublksrv_io_desc *iod = ublksrv_get_iod(q, tag);

	ublksrv_complete_io(q, tag, iod->nr_sectors << 9);

	co_io_job_return();
}

static int null_handle_io_async(struct ublksrv_queue *q, int tag)
{
	struct ublk_io_tgt *io = (struct ublk_io_tgt *)&q->ios[tag];

	io->co = __null_handle_io_async(q, (struct ublk_io *)io, tag);

	return 0;
}

struct ublksrv_tgt_type  null_tgt_type = {
	.type	= UBLKSRV_TGT_TYPE_NULL,
	.name	=  "null",
	.init_tgt = null_init_tgt,
	.handle_io_async = null_handle_io_async,
};

static void tgt_null_init() __attribute__((constructor));

static void tgt_null_init(void)
{
	ublksrv_register_tgt_type(&null_tgt_type);
}

