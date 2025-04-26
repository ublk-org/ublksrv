// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include "ublksrv_tgt.h"
#include <iscsi/iscsi.h>
#include <iscsi/scsi-lowlevel.h>


struct iscsi_tgt_data {
	char url[4096];
	char initiator[256];
	struct iscsi_context *iscsi;
	int lun;
	size_t capacity;
	int block_size;
	int block_shift;
};

typedef struct iscsi_cb_data {
	struct iscsi_cb_data *next;
	const struct ublksrv_queue *q;
	struct scsi_iovec iov;
	ssize_t count;
	struct unmap_list unmap;
} iscsi_cb_data_t;

struct iscsi_queue_data {
	iscsi_cb_data_t *io_list;
	pthread_spinlock_t io_list_lock;
	iscsi_cb_data_t ios[];
};

static unsigned char zero_page[4096];

static inline struct iscsi_queue_data *
iscsi_get_queue_data(const struct ublksrv_queue *q)
{
	return (struct iscsi_queue_data *)q->private_data;
}

static inline int cb_data_to_tag(iscsi_cb_data_t *cb)
{
	struct iscsi_queue_data *q_data = iscsi_get_queue_data(cb->q);
	int tag;

	tag = ((unsigned long)cb - (unsigned long)&q_data->ios[0]) / sizeof(*cb);
	return tag;
}

static void iscsi_handle_event(const struct ublksrv_queue *q)
{
	struct iscsi_queue_data *q_data = iscsi_get_queue_data(q);
	iscsi_cb_data_t *cb_data, *tmp;

	pthread_spin_lock(&q_data->io_list_lock);
	cb_data = q_data->io_list;
	q_data->io_list = NULL;
	pthread_spin_unlock(&q_data->io_list_lock);

	ublksrv_queue_handled_event(q);
	
	while (cb_data) {
		unsigned int tag;

		tmp = cb_data->next;

		tag = cb_data_to_tag(cb_data);
		ublksrv_complete_io(cb_data->q, tag, cb_data->count);
		cb_data = tmp;
	}
}

void rw_async_cb(struct iscsi_context *iscsi, int status, void *command_data, void *private_data)
{
	iscsi_cb_data_t *cb_data = (iscsi_cb_data_t *)private_data;
	const struct ublksrv_queue *q = cb_data->q;
	struct iscsi_queue_data *q_data = iscsi_get_queue_data(q);
	struct scsi_task *task = (struct scsi_task *)command_data;

	if (status != SCSI_STATUS_GOOD) {
		fprintf(stderr, "iscsi task failed with \"%s\"\n", iscsi_get_error(iscsi));
		cb_data->count = -EIO;
	}
	
	pthread_spin_lock(&q_data->io_list_lock);
	cb_data->next = q_data->io_list;
	q_data->io_list = cb_data;
	pthread_spin_unlock(&q_data->io_list_lock);

	ublksrv_queue_send_event(q);
	scsi_free_scsi_task(task);
}

static int iscsi_tgt_read(const struct ublksrv_queue *q,
			  const struct ublksrv_io_desc *iod, int tag)
{
	const struct ublksrv_dev *dev = q->dev;
	struct iscsi_tgt_data *iscsi_data = (struct iscsi_tgt_data *)dev->tgt.tgt_data;
	struct iscsi_queue_data *q_data = iscsi_get_queue_data(q);
	iscsi_cb_data_t *cb_data = &q_data->ios[tag];
	struct scsi_task *task;

	if ((iod->nr_sectors + iod->start_sector) * 512 > iscsi_data->capacity) {
		return -EINVAL;
	}

	cb_data->count = iod->nr_sectors * 512;

	cb_data->iov.iov_base = (void *)iod->addr;
	cb_data->iov.iov_len = iod->nr_sectors * 512;
	task = iscsi_read16_iov_task(iscsi_data->iscsi, iscsi_data->lun,
				     iod->start_sector >> iscsi_data->block_shift,
				     iod->nr_sectors * 512, iscsi_data->block_size,
				     0, 0, 0, 0, 0,
				     rw_async_cb, cb_data, &cb_data->iov, 1);
	if (task == NULL) {
		ublk_err("Failed to read from iSCSI LUN. %s\n", iscsi_get_error(iscsi_data->iscsi));
		return -ENOMEM;
	}
 
	return 0;
}

static int iscsi_tgt_write(const struct ublksrv_queue *q,
			   const struct ublksrv_io_desc *iod, int tag)
{
	const struct ublksrv_dev *dev = q->dev;
	struct iscsi_tgt_data *iscsi_data = (struct iscsi_tgt_data *)dev->tgt.tgt_data;
	struct iscsi_queue_data *q_data = iscsi_get_queue_data(q);
	iscsi_cb_data_t *cb_data = &q_data->ios[tag];
	struct scsi_task *task;

	if ((iod->nr_sectors + iod->start_sector) * 512 > iscsi_data->capacity) {
		return -EINVAL;
	}

	cb_data->count = iod->nr_sectors * 512;

	cb_data->iov.iov_base = (void *)iod->addr;
	cb_data->iov.iov_len = iod->nr_sectors * 512;
	task = iscsi_write16_iov_task(iscsi_data->iscsi, iscsi_data->lun,
				      iod->start_sector >> iscsi_data->block_shift,
				      NULL, iod->nr_sectors * 512, iscsi_data->block_size,
				      0, 0, 0, 0, 0,
				      rw_async_cb, cb_data, &cb_data->iov, 1);
	if (task == NULL) {
		ublk_err("Failed to write to iSCSI LUN. %s\n", iscsi_get_error(iscsi_data->iscsi));
		return -ENOMEM;
	}
 
	return 0;
}

static int iscsi_tgt_flush(const struct ublksrv_queue *q,
			   const struct ublksrv_io_desc *iod, int tag)
{
	const struct ublksrv_dev *dev = q->dev;
	struct iscsi_tgt_data *iscsi_data = (struct iscsi_tgt_data *)dev->tgt.tgt_data;
	struct iscsi_queue_data *q_data = iscsi_get_queue_data(q);
	iscsi_cb_data_t *cb_data = &q_data->ios[tag];
	struct scsi_task *task;

	cb_data->count = 0;

	task = iscsi_synchronizecache16_task(iscsi_data->iscsi, iscsi_data->lun, 
					     0, 0, 0, 0,
					     rw_async_cb, cb_data);
	if (task == NULL) {
		ublk_err("Failed to flush iSCSI LUN. %s\n", iscsi_get_error(iscsi_data->iscsi));
		return -ENOMEM;
	}
 
	return 0;
}

static int iscsi_tgt_unmap(const struct ublksrv_queue *q,
			   const struct ublksrv_io_desc *iod, int tag)
{
	const struct ublksrv_dev *dev = q->dev;
	struct iscsi_tgt_data *iscsi_data = (struct iscsi_tgt_data *)dev->tgt.tgt_data;
	struct iscsi_queue_data *q_data = iscsi_get_queue_data(q);
	iscsi_cb_data_t *cb_data = &q_data->ios[tag];
	struct scsi_task *task;

	if ((iod->nr_sectors + iod->start_sector) * 512 > iscsi_data->capacity) {
		return -EINVAL;
	}

	cb_data->unmap.lba = iod->start_sector >> iscsi_data->block_shift;
	cb_data->unmap.num = iod->nr_sectors >> iscsi_data->block_shift;
	cb_data->count = 0;

	task = iscsi_unmap_task(iscsi_data->iscsi, iscsi_data->lun,
				0, 0, &cb_data->unmap, 1,
				rw_async_cb, cb_data);
	if (task == NULL) {
		ublk_err("Failed to unmap iSCSI LUN. %s\n", iscsi_get_error(iscsi_data->iscsi));
		return -ENOMEM;
	}
 
	return 0;
}

static int iscsi_tgt_write_zeroes(const struct ublksrv_queue *q,
				  const struct ublksrv_io_desc *iod, int tag)
{
	const struct ublksrv_dev *dev = q->dev;
	struct iscsi_tgt_data *iscsi_data = (struct iscsi_tgt_data *)dev->tgt.tgt_data;
	struct iscsi_queue_data *q_data = iscsi_get_queue_data(q);
	iscsi_cb_data_t *cb_data = &q_data->ios[tag];
	struct scsi_task *task;

	if ((iod->nr_sectors + iod->start_sector) * 512 > iscsi_data->capacity) {
		return -EINVAL;
	}

	cb_data->count = 0;

	task = iscsi_writesame16_task(iscsi_data->iscsi, iscsi_data->lun,
				      iod->start_sector >> iscsi_data->block_shift,
				      zero_page, iscsi_data->block_size,
				      iod->nr_sectors >> iscsi_data->block_shift,
				      0, 0, 0, 0,
				      rw_async_cb, cb_data);
	if (task == NULL) {
		ublk_err("Failed to writesame16 to iSCSI LUN. %s\n", iscsi_get_error(iscsi_data->iscsi));
		return -ENOMEM;
	}
 
	return 0;
}

static int iscsi_handle_io_async(const struct ublksrv_queue *q,
				 const struct ublk_io_data *data)
{
	const struct ublksrv_io_desc *iod = data->iod;
	unsigned ublk_op = ublksrv_get_op(iod);
	int ret = -ENOTSUP;

	switch (ublk_op) {
	case UBLK_IO_OP_READ:
		ret = iscsi_tgt_read(q, iod, data->tag);
		break;
	case UBLK_IO_OP_WRITE:
		ret = iscsi_tgt_write(q, iod, data->tag);
		break;
	case UBLK_IO_OP_DISCARD:
		ret = iscsi_tgt_unmap(q, iod, data->tag);
		break;
	case UBLK_IO_OP_FLUSH:
		ret = iscsi_tgt_flush(q, iod, data->tag);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
		ret = iscsi_tgt_write_zeroes(q, iod, data->tag);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret) {
		ublksrv_complete_io(q, data->tag, ret);
	}
	return ret;
}

static struct iscsi_tgt_data *iscsi_init(const char *iscsiurl,
					 const char *initiator)
{
	struct iscsi_tgt_data *iscsi_data;
	struct iscsi_url *url;
	struct scsi_task *task = NULL;
	struct scsi_readcapacity16 *rc16;

	iscsi_data = (struct iscsi_tgt_data *)calloc(sizeof(struct iscsi_tgt_data), 1);
	if (iscsi_data == NULL) {
		ublk_err( "%s: failed to calloc tgt_data\n", __func__);
		return NULL;
	}

	strncpy(iscsi_data->url, iscsiurl, sizeof(iscsi_data->url));
	strncpy(iscsi_data->initiator, initiator, sizeof(iscsi_data->initiator));

	iscsi_data->iscsi = iscsi_create_context(initiator);
	if (iscsi_data->iscsi == NULL) {
		fprintf(stderr, "failed to init context\n");
		goto fail_free;
	}

	url = iscsi_parse_full_url(iscsi_data->iscsi, iscsiurl);
	if (url == NULL) {
		fprintf(stderr, "%s\n", iscsi_get_error(iscsi_data->iscsi));
		goto fail_context;
	}
	iscsi_data->lun = url->lun;
	
	iscsi_set_session_type(iscsi_data->iscsi, ISCSI_SESSION_NORMAL);
	iscsi_set_header_digest(iscsi_data->iscsi, ISCSI_HEADER_DIGEST_NONE_CRC32C);
	
	if (iscsi_full_connect_sync(iscsi_data->iscsi, url->portal, url->lun) != 0) {
		fprintf(stderr, "Failed to connect to iSCSI LUN : %s\n",
			       iscsi_get_error(iscsi_data->iscsi));
		goto fail_url;
	}

	task = iscsi_readcapacity16_sync(iscsi_data->iscsi, iscsi_data->lun);
	if (task == NULL || task->status != SCSI_STATUS_GOOD) {
		fprintf(stderr,"Failed to send readcapacity16 command\n");
		goto fail_disconnect;
	}
	rc16 = (struct scsi_readcapacity16 *)scsi_datain_unmarshall(task);
	if (rc16 == NULL) {
		fprintf(stderr, "failed to unmarshall readcapacity16 data\n");
		goto fail_disconnect;
	}
	iscsi_data->capacity = rc16->block_length * (rc16->returned_lba + 1);
	iscsi_data->block_size = rc16->block_length;
	scsi_free_scsi_task(task);
	task = NULL;
	
	if (iscsi_mt_service_thread_start(iscsi_data->iscsi)) {
		fprintf(stderr, "failed to start service thread\n");
		goto fail_disconnect;
	}

	iscsi_destroy_url(url);
	return iscsi_data;

 fail_disconnect:
	if (task) {
		scsi_free_scsi_task(task);
	}
	iscsi_logout_sync(iscsi_data->iscsi);
 fail_url:
	iscsi_destroy_url(url);
 fail_context:
	iscsi_destroy_context(iscsi_data->iscsi);
 fail_free:
	free(iscsi_data);
	return NULL;
}

static void iscsi_exit(struct iscsi_tgt_data *iscsi_data)
{
	if (iscsi_data) {
		iscsi_mt_service_thread_stop(iscsi_data->iscsi);
		iscsi_logout_sync(iscsi_data->iscsi);
		iscsi_destroy_context(iscsi_data->iscsi);
		free(iscsi_data);
	}
}

static int iscsi_setup_tgt(struct ublksrv_dev *dev)
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
	tgt->nr_fds = 0;

	return 0;
}

static int iscsi_recover_tgt(struct ublksrv_dev *dev, int type)
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	char url[PATH_MAX], initiator[PATH_MAX];
	struct iscsi_tgt_data *iscsi_data = NULL;
	int ret;

	ret = ublk_json_read_target_str_info(cdev, "url", url);
	if (ret < 0) {
		ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
				__func__, ret);
		return ret;
	}
	ret = ublk_json_read_target_str_info(cdev, "initiator-name", initiator);
	if (ret < 0) {
		ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
				__func__, ret);
		return ret;
	}

	iscsi_data = iscsi_init(url, initiator);
	dev->tgt.tgt_data = iscsi_data;
	if (dev->tgt.tgt_data == NULL) {
		fprintf(stderr, "Failed to initialize iscsi\n");
		return -ENOMEM;
	}

	return iscsi_setup_tgt(dev);
}

static int iscsi_init_tgt(struct ublksrv_dev *dev, int type, int argc,
			  char *argv[])
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(cdev);
	struct ublksrv_tgt_base_json tgt_json = { 0 };
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.attrs		  = UBLK_ATTR_VOLATILE_CACHE,
			.physical_bs_shift	= 12,
			.io_opt_shift		= 12,
			.io_min_shift		= 9,
		},
	};
	static const struct option lo_longopts[] = {
		{ "iscsi",                          1, NULL, 1024 },
		{ "initiator-name", required_argument, NULL, 1025 },
		{ NULL }
	};
	int opt;
	struct iscsi_tgt_data *iscsi_data = NULL;
	const char *iscsiurl = NULL, *initiator = NULL;

	if (info->flags & UBLK_F_UNPRIVILEGED_DEV)
		return -1;

	if (ublksrv_is_recovering(cdev))
		return iscsi_recover_tgt(dev, 0);

	strcpy(tgt_json.name, "iscsi");

	while ((opt = getopt_long(argc, argv, "-:",
				  lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 1024:
			iscsiurl = optarg;
			break;
		case 1025:
			initiator = optarg;
			break;
		}
	}

	if (iscsiurl == NULL) {
		fprintf(stderr, "Must specify --iscsi=ISCSI_URL\n");
		return -EINVAL;
	}
	if (initiator == NULL) {
		fprintf(stderr, "Must specify --initiator-name=STRING\n");
		return -EINVAL;
	}

	iscsi_data = iscsi_init(iscsiurl, initiator);
	switch (iscsi_data->block_size) {
	case 512:
		p.basic.logical_bs_shift	= 9;
		iscsi_data->block_shift         = 0;
		break;
	case 4096:
		p.basic.logical_bs_shift	= 12;
		iscsi_data->block_shift         = 3;
		break;
	default:
		fprintf(stderr, "Unsupported block size %d\n", iscsi_data->block_size);
		return -EINVAL;
	}

	dev->tgt.tgt_data = iscsi_data;
	if (dev->tgt.tgt_data == NULL) {
		fprintf(stderr, "Failed to initialize iscsi\n");
		return -ENOMEM;
	}

	tgt_json.dev_size = iscsi_data->capacity;
	p.basic.dev_sectors = iscsi_data->capacity >> 9;

	ublk_json_write_dev_info(cdev);
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_tgt_str(cdev, "url", iscsi_data->url);
	ublk_json_write_tgt_str(cdev, "initiator-name", iscsi_data->initiator);
	ublk_json_write_params(cdev, &p);

	return iscsi_setup_tgt(dev);
}

static void iscsi_deinit_tgt(const struct ublksrv_dev *dev)
{
	struct iscsi_tgt_data *iscsi_data = (struct iscsi_tgt_data *)dev->tgt.tgt_data;

	iscsi_exit(iscsi_data);
}

static int iscsi_init_queue(const struct ublksrv_queue *q,
		void **queue_data_ptr)
{
	struct iscsi_queue_data *data = (struct iscsi_queue_data *)calloc(sizeof(*data) +
				sizeof(data->ios[0]) * q->q_depth, 1);
	int i;

	if (!data)
		return -ENOMEM;

	pthread_spin_init(&data->io_list_lock, PTHREAD_PROCESS_PRIVATE);
	for (i = 0; i < q->q_depth; i++) {
		data->ios[i].q = q;
	}
	*queue_data_ptr = (void *)data;
	return 0;
}

static void iscsi_deinit_queue(const struct ublksrv_queue *q)
{
	struct iscsi_queue_data *data = iscsi_get_queue_data(q);

	free(data);
}

static void iscsi_cmd_usage()
{
	printf("\t--iscsi ISCSI-URL --initiator-name=STRING\n");
}

static const struct ublksrv_tgt_type  iscsi_tgt_type = {
	.handle_io_async = iscsi_handle_io_async,
	.handle_event = iscsi_handle_event,
	.usage_for_add = iscsi_cmd_usage,
	.init_tgt = iscsi_init_tgt,
	.deinit_tgt = iscsi_deinit_tgt,
	.ublksrv_flags = UBLKSRV_F_NEED_EVENTFD,
	.name	=  "iscsi",
	.init_queue = iscsi_init_queue,
	.deinit_queue = iscsi_deinit_queue,
};

int main(int argc, char *argv[])
{
	return ublksrv_tgt_cmd_main(&iscsi_tgt_type, argc, argv);
}
