// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>
#include "ublksrv_tgt.h"
#include "cliserv.h"
#include "nbd.h"

#define NBD_MAX_NAME	512

#define NBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, name, val) do { \
	int ret;						\
	if (val)						\
		ret = ublksrv_json_write_target_str_info(jbuf,	\
				jbuf_size, name, val);		\
	else							\
		ret = 0;					\
	if (ret < 0)						\
		jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);	\
	else							\
		break;						\
} while (1)

enum nbd_recv_state {
	NBD_RECV_IDLE,
	NBD_RECV_REPLY,
	NBD_RECV_DATA,
};

struct nbd_queue_data {
	enum nbd_recv_state recv;
	unsigned short in_flight_read_ios;

	struct nbd_reply reply;
};

struct nbd_io_data {
	struct nbd_request req;
	unsigned int cmd_cookie;
};

static inline struct nbd_queue_data *
nbd_get_queue_data(const struct ublksrv_queue *q)
{
	return (struct nbd_queue_data *)q->private_data;
}

static inline struct nbd_io_data *
io_tgt_to_nbd_data(const struct ublk_io_tgt *io)
{
	return (struct nbd_io_data *)(io + 1);
}

static void nbd_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	int jbuf_size;
	char *jbuf = ublksrv_tgt_return_json_buf(dev, &jbuf_size);
	int i;

	uint16_t flags = 0;
	const char *port = NBD_DEFAULT_PORT;
	uint16_t needed_flags = 0;
	uint32_t cflags = NBD_FLAG_C_FIXED_NEWSTYLE;

	char host_name[NBD_MAX_NAME] = {0};
	char exp_name[NBD_MAX_NAME] = {0};
	char unix_path[NBD_MAX_NAME] = {0};
	u64 size64 = 0;
	bool can_opt_go = true;

	/* todo: support tls */
	char *certfile = NULL;
	char *keyfile = NULL;
	char *cacertfile = NULL;
	char *tlshostname = NULL;
	bool tls = false;

	ublk_assert(jbuf);
	ublk_assert(type == UBLKSRV_TGT_TYPE_NBD);
	ublk_assert(!recovery || info->state == UBLK_S_DEV_QUIESCED);

	ublksrv_json_read_target_str_info(jbuf, NBD_MAX_NAME, "host",
			host_name);
	ublksrv_json_read_target_str_info(jbuf, NBD_MAX_NAME, "unix",
			unix_path);
	ublksrv_json_read_target_str_info(jbuf, NBD_MAX_NAME, "export_name",
			exp_name);

	//fprintf(stderr, "%s: host %s unix %s exp_name %s\n", __func__,
	//		host_name, unix_path, exp_name);
	for (i = 0; i < info->nr_hw_queues; i++) {
		int sock;
		unsigned int opts = 0;

		if (strlen(unix_path))
			sock = openunix(unix_path);
		else
			sock = opennet(host_name, port, false);

		if (sock >= 0)
			negotiate(&sock, &size64, &flags, exp_name,
					needed_flags, cflags, opts, certfile,
					keyfile, cacertfile, tlshostname, tls,
					can_opt_go);

		tgt->fds[i + 1] = sock;
		//fprintf(stderr, "%s:%s size %luMB flags %x sock %d\n",
		//		hostname, port, size64 >> 20, flags, sock);
	}

	tgt->dev_size = size64;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = info->nr_hw_queues;
	tgt->extra_ios = 1;	//one extra slot for receiving nbd reply

	tgt->io_data_size = sizeof(struct ublk_io_tgt) +
		sizeof(struct nbd_io_data);
}

static int nbd_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	static const struct option nbd_longopts[] = {
		{ "host",	required_argument, 0, 0},
		{ "unix",	required_argument, 0, 0},
		{ "export_name",	required_argument, 0, 0},
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
	int ret;
	int opt;
	int option_index = 0;
	unsigned char bs_shift = 9;
	const char *host_name = NULL;
	const char *unix_path = NULL;
	const char *exp_name = NULL;

	strcpy(tgt_json.name, "nbd");

	if (type != UBLKSRV_TGT_TYPE_NBD)
		return -1;

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
		      host_name = optarg;
		if (!strcmp(nbd_longopts[option_index].name, "unix"))
		      unix_path = optarg;
		if (!strcmp(nbd_longopts[option_index].name, "export_name"))
			exp_name = optarg;
	}

	ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, jbuf_size);
	NBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "host", host_name);
	NBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "unix", unix_path);
	NBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "export_name", exp_name);

	nbd_setup_tgt(dev, type, false);

	tgt_json.dev_size = tgt->dev_size;
	ublksrv_json_write_target_base_info(jbuf, jbuf_size, &tgt_json);

	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.logical_bs_shift	= bs_shift,
			.physical_bs_shift	= 12,
			.io_opt_shift		= 12,
			.io_min_shift		= bs_shift,
			.max_sectors		= info->max_io_buf_bytes >> 9,
			.dev_sectors		= tgt->dev_size >> 9,
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
	nbd_setup_tgt(dev, type, true);

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

static int nbd_init_queue(const struct ublksrv_queue *q,
		void **queue_data_ptr)
{
	struct nbd_queue_data *data =
		(struct nbd_queue_data *)calloc(sizeof(*data), 1);

	if (!data)
		return -ENOMEM;

	data->recv = NBD_RECV_IDLE;

	*queue_data_ptr = (void *)data;
	return 0;
}

static void nbd_deinit_queue(const struct ublksrv_queue *q)
{
	struct nbd_queue_data *data = nbd_get_queue_data(q);

	free(data);
}

struct ublksrv_tgt_type  nbd_tgt_type = {
	.handle_io_async = nbd_handle_io_async,
	.usage_for_add	=  nbd_usage_for_add,
	.init_tgt = nbd_init_tgt,
	.deinit_tgt = nbd_deinit_tgt,
	.type	= UBLKSRV_TGT_TYPE_NBD,
	.name	=  "nbd",
	.recovery_tgt = nbd_recovery_tgt,
	.init_queue = nbd_init_queue,
	.deinit_queue = nbd_deinit_queue,
};

static void tgt_nbd_init() __attribute__((constructor));

static void tgt_nbd_init(void)
{
	ublksrv_register_tgt_type(&nbd_tgt_type);
}

