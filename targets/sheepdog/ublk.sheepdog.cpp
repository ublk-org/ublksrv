// SPDX-License-Identifier: GPL-2.0-only
/*
 * ublk.sheepdog.cpp - UBLK device server for sheepdog
 *
 * Copyright (c) 2026 Hannes Reinecke, SUSE
 */

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include <linux/falloc.h>
#include <stdlib.h>
#include <pthread.h>

#include "ublksrv_tgt.h"
#include "sheepdog_proto.h"
#include "sheep.h"

struct sheepdog_dev {
	char cluster_host[256];
	char cluster_port[16];
	char vdi_name[256];
	struct sheepdog_vdi vdi;
	unsigned long send_timeout;
	unsigned long recv_timeout;
	bool unlock;
};

static inline struct sd_io_context *
io_tgt_to_sd_io(const struct ublk_io_tgt *io)
{
	return (struct sd_io_context *)(io + 1);
}

static int sheepdog_setup_tgt(struct ublksrv_dev *ub_dev, int type)
{
	struct ublksrv_tgt_info *tgt = &ub_dev->tgt;
	const struct ublksrv_ctrl_dev *cdev =
		ublksrv_get_ctrl_dev(ub_dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int fd, ret;
	char vdi_name[256];
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)ub_dev->tgt.tgt_data;

	ret = ublk_json_read_target_str_info(cdev, "vdi_name", vdi_name);
	if (ret < 0) {
		ublk_err( "%s: read vdi name failed, error %d\n",
				__func__, ret);
		return ret;
	}
	strncpy(dev->vdi_name, vdi_name, 256);

	ret = ublk_json_read_target_str_info(cdev, "sheepdog_host",
					     dev->cluster_host);
	if (ret) {
		ublk_err( "%s: read hostname failed, error %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_str_info(cdev, "sheepdog_port",
					     dev->cluster_port);
	if (ret) {
		ublk_err( "%s: read port id failed, error %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_ulong_info(cdev, "send_timeout",
					       &dev->send_timeout);
	if (ret) {
		ublk_err( "%s: read send timeout failed, error %d\n",
			  __func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_ulong_info(cdev, "recv_timeout",
					       &dev->recv_timeout);
	if (ret) {
		ublk_err( "%s: read recv timeout failed, error %d\n",
			  __func__, ret);
		return ret;
	}

	fd = sd_connect(dev->cluster_host, dev->cluster_port,
			dev->send_timeout, dev->recv_timeout);
	if (fd < 0) {
		ublk_err( "%s: cannot connect to sheepdog cluster\n",
			  __func__);
		return fd;
	}

	ret = sd_vdi_lookup(fd, dev->vdi_name, 0, NULL,
			    &dev->vdi.vid, dev->unlock ? false : true);
	if (ret < 0) {
		dev->vdi.vid = 0;
		close(fd);
		return ret;
	}
	if (dev->unlock) {
		ret = sd_vdi_release(fd, &dev->vdi);
		if (ret < 0) {
			ublk_err( "%s: failed to release VID %x\n",
				  __func__, dev->vdi.vid);
			close(fd);
			return ret;
		}
		ret = sd_vdi_lookup(fd, dev->vdi_name, 0, NULL,
				    &dev->vdi.vid, true);
		if (ret < 0) {
			dev->vdi.vid = 0;
			close(fd);
			return ret;
		}
	}
	ret = sd_read_inode(fd, &dev->vdi, false);
	close(fd);
	if (ret < 0) {
		ublk_err( "%s: failed to read params for VID %x\n",
			  __func__, dev->vdi.vid);
		return ret;
	}

	tgt->io_data_size = sizeof(struct ublk_io_tgt) +
		sizeof(struct sd_io_context);
	tgt->dev_size = dev->vdi.inode.vdi_size >> 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;
	tgt->extra_ios = 0;

	return 0;
}

static int sheepdog_recover_tgt(struct ublksrv_dev *ub_dev, int type)
{
	struct sheepdog_dev *dev;

	ub_dev->tgt.tgt_data =
		(struct sheepdog_dev *)calloc(1, sizeof(struct sheepdog_dev));
	dev = (struct sheepdog_dev *)ub_dev->tgt.tgt_data;
	dev->unlock = true;
	pthread_mutex_init(&dev->vdi.inode_lock, NULL);
	return sheepdog_setup_tgt(ub_dev, type);
}

static int sheepdog_init_tgt(struct ublksrv_dev *ub_dev, int type,
			     int argc, char *argv[])
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(ub_dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int unlock = 0;
	static const struct option sheepdog_longopts[] = {
		{ "host",	required_argument, NULL, 'h'},
		{ "port",	required_argument, NULL, 'p'},
		{ "vdi_name",	required_argument, NULL, 'v' },
		{ "send_tmo",	required_argument, NULL, 's'},
		{ "read_tmo",	required_argument, NULL, 'r'},
		{ "lbs",	required_argument, NULL, 'b'},
		{ "unlock",	no_argument, &unlock, 'u'},
		{ NULL }
	};
	int opt, lbs = 9, ret;
	unsigned long send_tmo = SD_SEND_TMO, recv_tmo = SD_RECV_TMO;
	char *vdi_name = NULL;
	const char *cluster_host = "127.0.0.1";
	const char *cluster_port = "7000";
	struct sheepdog_dev *dev;
	struct ublksrv_tgt_base_json tgt_json = { 0 };
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD |
			UBLK_PARAM_TYPE_DMA_ALIGN,
		.basic = {
			.attrs                  = UBLK_ATTR_FUA,
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift	= 12,
			.io_min_shift	= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
		},

		.discard = {
			.max_discard_sectors	= SD_DATA_OBJ_SIZE >> 9,
			.max_discard_segments	= 1,
		},
		.dma = {
			.alignment = 511,
		},
	};

	if (ublksrv_is_recovering(cdev))
		return sheepdog_recover_tgt(ub_dev, 0);

	strcpy(tgt_json.name, "sheepdog");

	while ((opt = getopt_long(argc, argv, "h:p:v:b:s:r:",
				  sheepdog_longopts, NULL)) != -1) {
		switch (opt) {
		case 'v':
			vdi_name = optarg;
			break;
		case 'b':
			errno = 0;
			lbs = strtoul(optarg, NULL, 10);
			if (lbs == ULONG_MAX && errno)
				return -EINVAL;
			if (lbs < 9)
				return -EINVAL;
			break;
		case 'h':
			cluster_host = optarg;
			break;
		case 'p':
			cluster_port = optarg;
			break;
		case 's':
			errno = 0;
			send_tmo = strtoul(optarg, NULL, 10);
			if (send_tmo == ULONG_MAX && errno)
				return -EINVAL;
			if (send_tmo < 5)
				return -EINVAL;
			break;
		case 'r':
			errno = 0;
			recv_tmo = strtoul(optarg, NULL, 10);
			if (recv_tmo == ULONG_MAX && errno)
				return -EINVAL;
			if (recv_tmo < send_tmo)
				return -EINVAL;
			break;
		}
	}

	if (!vdi_name) {
		ublk_err( "%s: no VDI name\n", __func__);
		return -EINVAL;
	}

	ublk_json_write_dev_info(cdev);
	ublk_json_write_tgt_str(cdev, "sheepdog_host", cluster_host);
	ublk_json_write_tgt_str(cdev, "sheepdog_port", cluster_port);
	ublk_json_write_tgt_str(cdev, "vdi_name", vdi_name);
	ublk_json_write_tgt_ulong(cdev, "logical_block_shift", lbs);
	ublk_json_write_tgt_ulong(cdev, "send_timeout", send_tmo);
	ublk_json_write_tgt_ulong(cdev, "recv_timeout", recv_tmo);

	ub_dev->tgt.tgt_data = (struct sheepdog_dev *)calloc(1, sizeof(*dev));
	dev = (struct sheepdog_dev *)ub_dev->tgt.tgt_data;
	pthread_mutex_init(&dev->vdi.inode_lock, NULL);
	if (unlock)
		dev->unlock = true;
	else
		dev->unlock = false;

	ret = sheepdog_setup_tgt(ub_dev, type);
	if (ret < 0)
		return ret;

	ublk_json_write_tgt_ulong(cdev, "vid", dev->vdi.vid);
	ublk_json_write_tgt_ulong(cdev, "ctime", dev->vdi.inode.create_time);

	p.basic.physical_bs_shift = dev->vdi.inode.block_size_shift;
	p.basic.chunk_sectors = 1 << (p.basic.physical_bs_shift - 9);
	p.basic.dev_sectors = dev->vdi.inode.vdi_size >> 9;
	p.discard.discard_granularity = p.basic.chunk_sectors;
	p.discard.max_discard_sectors = p.basic.chunk_sectors;
	if (lbs > 9) {
		if (lbs > p.basic.physical_bs_shift) {
			ublk_err( "%s: logical block size %d too large\n",
				  __func__, lbs);
			return -EINVAL;
		}
		p.basic.logical_bs_shift = lbs;
	}
	tgt_json.dev_size = p.basic.dev_sectors << 9;
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_params(cdev, &p);

	return ret;
}

static int sheepdog_init_queue(const struct ublksrv_queue *q,
			       void **queue_data_ptr)
{
	struct ublksrv_tgt_info *tgt =
		(struct ublksrv_tgt_info *)&q->dev->tgt;
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)tgt->tgt_data;
	struct sheepdog_queue_ctx *q_ctx;
	int fd;

	q_ctx = (struct sheepdog_queue_ctx *)
		calloc(1, sizeof(struct sheepdog_queue_ctx));
	if (!q_ctx)
		return -ENOMEM;

	fd = sd_connect(dev->cluster_host, dev->cluster_port,
			dev->send_timeout, dev->recv_timeout);
	if (fd < 0) {
		ublk_err("%s: failed to connect to sheepdog\n",
			 __func__);
		free(q_ctx);
		return fd;
	}
	q_ctx->fd = fd;
	*queue_data_ptr = (void *)q_ctx;
	return 0;
}

static void sheepdog_deinit_queue(const struct ublksrv_queue *q)
{
	struct ublksrv_tgt_info *tgt =
		(struct ublksrv_tgt_info *)&q->dev->tgt;
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)tgt->tgt_data;
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;

	if (q->private_data) {
		if (dev)
			sd_vdi_release(q_ctx->fd, &dev->vdi);
		close(q_ctx->fd);
		free(q_ctx);
	}
}

static int sheepdog_queue_tgt_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		struct ublk_io_tgt *io)
{
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;
	struct sd_io_context *sd_io = io_tgt_to_sd_io(io);
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)q->dev->tgt.tgt_data;
	const struct ublksrv_io_desc *iod = data->iod;
	uint32_t object_size = SD_OBJECT_SIZE(&dev->vdi);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	int ublk_op = ublksrv_get_op(iod);
	size_t len = object_size - start;
	int ret = 0;

	if (total > len) {
		ublk_err("%s: op %u access beyond object size off %lu total %u\n",
			 __func__, ublk_op, offset, total);
		ret = -EIO;
	}
	memset(&sd_io->req, 0, sizeof(sd_io->req));
	memset(&sd_io->rsp, 0, sizeof(sd_io->rsp));
	sd_io->req.id = data->tag;
	switch (ublk_op) {
	case UBLK_IO_OP_WRITE:
		ret = sd_exec_write(q_ctx->fd, &dev->vdi, iod, sd_io);
		break;
	case UBLK_IO_OP_READ:
		ret = sd_exec_read(q_ctx->fd, &dev->vdi, iod, sd_io);
		break;
	case UBLK_IO_OP_DISCARD:
	case UBLK_IO_OP_WRITE_ZEROES:
		ret = sd_exec_discard(q_ctx->fd, &dev->vdi, iod, sd_io,
			ublk_op == UBLK_IO_OP_DISCARD ? false : true);
		break;
	default:
		ublk_err("%s: tag %u op %u not supported\n",
			 __func__, data->tag, ublk_op);
		ret = -EOPNOTSUPP;
		break;
	}

	ublk_dbg(UBLK_DBG_IO, "%s: tag %d opcode %x len %u ret %d\n", __func__,
		 data->tag, sd_io->req.opcode, total, ret);
	return ret < 0 ? ret : total;
}

static int sheepdog_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	int ret;

	ret = sheepdog_queue_tgt_io(q, data, io);
	ublksrv_complete_io(q, data->tag, ret);
	return 0;
}

static void sheepdog_deinit_tgt(const struct ublksrv_dev *ub_dev)
{
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)ub_dev->tgt.tgt_data;

	if (dev) {
		pthread_mutex_destroy(&dev->vdi.inode_lock);
		free(dev);
	}
}

static void sheepdog_cmd_usage()
{
	printf("\t-v|--vdi_name vdi_name\n");
	printf("\t[-h|--host host] [-p|--port port]\n");
	printf("\t[-u|--unlock]\n");
}

static const struct ublksrv_tgt_type  sheepdog_tgt_type = {
	.handle_io_async = sheepdog_handle_io_async,
	.usage_for_add = sheepdog_cmd_usage,
	.init_tgt = sheepdog_init_tgt,
	.deinit_tgt = sheepdog_deinit_tgt,
	.name	=  "sheepdog",
	.init_queue = sheepdog_init_queue,
	.deinit_queue = sheepdog_deinit_queue,
};

int main(int argc, char *argv[])
{
	return ublksrv_main(&sheepdog_tgt_type, argc, argv);
}
