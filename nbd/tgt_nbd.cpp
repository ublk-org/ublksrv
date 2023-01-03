// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>
#include "ublksrv_tgt.h"
#include "cliserv.h"
#include "nbd.h"

static int nbd_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	static const struct option nbd_longopts[] = {
		{ "host",	required_argument, 0, 0},
		{ "unix",	required_argument, 0, 0},
		{ "name",	required_argument, 0, 0},
		{ NULL }
	};
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	int jbuf_size;
	char *jbuf = ublksrv_tgt_return_json_buf(dev, &jbuf_size);
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	int ret, i;

	uint16_t flags = 0;
	const char *port = NBD_DEFAULT_PORT;
	uint16_t needed_flags = 0;
	uint32_t cflags = NBD_FLAG_C_FIXED_NEWSTYLE;
	unsigned char bs_shift = 9;
	const char *hostname = NULL;
	char name[128] = {0};
	const char *unix_path = NULL;
	u64 size64 = 0;
	bool can_opt_go = true;

	/* todo: support tls */
	char *certfile = NULL;
	char *keyfile = NULL;
	char *cacertfile = NULL;
	char *tlshostname = NULL;
	bool tls = false;

	int opt;
	int option_index = 0;

	strcpy(tgt_json.name, "nbd");

	if (type != UBLKSRV_TGT_TYPE_NBD)
		return -1;

	strcpy(name, "");
	while ((opt = getopt_long(argc, argv, "-:f:",
				  nbd_longopts, &option_index)) != -1) {
		if (opt < 0)
			break;
		if (opt > 0)
			continue;

		//fprintf(stderr, "option %s", nbd_longopts[option_index].name);
		//if (optarg)
		//    fprintf(stderr, " with arg %s", optarg);
		//printf("\n");
		if (!strcmp(nbd_longopts[option_index].name, "host"))
		      hostname = optarg;
		if (!strcmp(nbd_longopts[option_index].name, "unix"))
		      unix_path = optarg;
		if (!strcmp(nbd_longopts[option_index].name, "name"))
			strncpy(name, optarg, sizeof(name));
	}

	for (i = 0; i < info->nr_hw_queues; i++) {
		int sock;
		unsigned int opts = 0;

		if (unix_path != NULL)
			sock = openunix(unix_path);
		else
			sock = opennet(hostname, port, false);

		if (sock >= 0)
			negotiate(&sock, &size64, &flags, name,
					needed_flags, cflags, opts, certfile,
					keyfile, cacertfile, tlshostname, tls,
					can_opt_go);

		tgt->fds[i + 1] = sock;
		//fprintf(stderr, "%s:%s size %luMB flags %x sock %d\n",
		//		hostname, port, size64 >> 20, flags, sock);
	}

	tgt_json.dev_size = tgt->dev_size = size64;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = info->nr_hw_queues;

	ublksrv_tgt_set_io_data_size(tgt);

	ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, jbuf_size);
	ublksrv_json_write_target_base_info(jbuf, jbuf_size, &tgt_json);

	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.logical_bs_shift	= bs_shift,
			.physical_bs_shift	= 12,
			.io_opt_shift		= 12,
			.io_min_shift		= bs_shift,
			.max_sectors		= info->max_io_buf_bytes >> 9,
			.dev_sectors		= size64 >> 9,
		},
	};
	do {
		ret = ublksrv_json_write_params(&p, jbuf, jbuf_size);
		if (ret < 0)
			jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	} while (ret < 0);

	return 0;
}

static int nbd_recovery_tgt(struct ublksrv_dev *dev, int type)
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
		syslog(LOG_ERR, "%s: read ublk params failed %d\n",
				__func__, ret);
		return ret;
	}

	ublksrv_tgt_set_io_data_size(tgt);
	tgt->dev_size = p.basic.dev_sectors << 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;
	return 0;
}

static co_io_job __nbd_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	ublksrv_complete_io(q, tag, data->iod->nr_sectors << 9);

	co_return;
}

static int nbd_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	io->co = __nbd_handle_io_async(q, data, data->tag);

	return 0;
}

static void nbd_deinit_tgt(const struct ublksrv_dev *dev)
{
	const struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	int i;

	for (i = 0; i < info->nr_hw_queues; i++) {
		int fd = tgt->fds[i + 1];

		shutdown(fd, SHUT_RDWR);
		close(fd);
	}
}

static void nbd_usage_for_add(void)
{
	printf("           nbd: --host=$HOST [--port=$PORT] | --unix=$UNIX_PATH\n");
}

struct ublksrv_tgt_type  nbd_tgt_type = {
	.handle_io_async = nbd_handle_io_async,
	.usage_for_add	=  nbd_usage_for_add,
	.init_tgt = nbd_init_tgt,
	.deinit_tgt = nbd_deinit_tgt,
	.type	= UBLKSRV_TGT_TYPE_NBD,
	.name	=  "nbd",
	.recovery_tgt = nbd_recovery_tgt,
};

static void tgt_nbd_init() __attribute__((constructor));

static void tgt_nbd_init(void)
{
	ublksrv_register_tgt_type(&nbd_tgt_type);
}

