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

static int null_handle_io(struct ubdsrv_dev *dev, int qid, int tag)
{
	return 0;
}

struct ubdsrv_tgt_type  null_tgt_type = {
	.type	= UBDSRV_TGT_TYPE_NULL,
	.name	=  "null",
	.init_tgt = null_init_tgt,
	.handle_io = null_handle_io,
};

static void tgt_null_init() __attribute__((constructor));

static void tgt_null_init(void)
{
	ubdsrv_register_tgt_type(&null_tgt_type);
}

