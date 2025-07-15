// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include "ublksrv_tgt.h"
#include <nfsc/libnfs.h>


struct nfs_url *url;

typedef struct nfs_tgt_data {
	char url[4096];
	struct nfs_context *nfs;
	struct nfsfh *nfsfh;
	size_t capacity;
} nfs_tgt_data_t;

typedef struct nfs_cb_data {
	struct nfs_cb_data *next;
	const struct ublksrv_queue *q;
	ssize_t count;
} nfs_cb_data_t;

struct nfs_queue_data {
	nfs_tgt_data_t *nfs_data;
	int events;
	nfs_cb_data_t ios[];
};

static inline struct nfs_queue_data *
nfs_get_queue_data(const struct ublksrv_queue *q)
{
	return (struct nfs_queue_data *)q->private_data;
}

static inline int cb_data_to_tag(nfs_cb_data_t *cb)
{
	struct nfs_queue_data *q_data = nfs_get_queue_data(cb->q);
	int tag;

	tag = ((unsigned long)cb - (unsigned long)&q_data->ios[0]) / sizeof(*cb);
	return tag;
}

void rw_async_cb(int status, struct nfs_context *nfs,
		 void *data, void *private_data)
{
	nfs_cb_data_t *cb_data = (nfs_cb_data_t *)private_data;
	const struct ublksrv_queue *q = cb_data->q;
	unsigned int tag;

	tag = cb_data_to_tag(cb_data);

	if (status < 0) {
		ublk_err("pread/pwrite failed with \"%s\"\n", (char *)data);
		status = -EIO;
	}
	ublksrv_complete_io(q, tag, status);
}

void nfs_socket_cb(struct ublksrv_queue *q, int revents)
{
	struct nfs_queue_data *q_data = nfs_get_queue_data(q);
	struct nfs_context *nfs = q_data->nfs_data->nfs;
	int events;

	if (nfs_service(nfs, revents) < 0) {
		ublk_err("nfs_service failed\n");
	}

	/* This is the fast path so only call ublksrv_epoll_mod_fd() if the set
	 * of events have changed.
	 */
	events = nfs_which_events(nfs);
	if (events != q_data->events) {
		ublksrv_epoll_mod_fd(q, nfs_get_fd(nfs), events);
		q_data->events = events;
	}
}

static int nfs_tgt_read(const struct ublksrv_queue *q,
			const struct ublksrv_io_desc *iod, int tag)
{
	struct nfs_queue_data *q_data = nfs_get_queue_data(q);
	struct nfs_tgt_data *nfs_data = q_data->nfs_data;
	nfs_cb_data_t *cb_data = &q_data->ios[tag];

	if ((iod->nr_sectors + iod->start_sector) * 512 > nfs_data->capacity) {
		return -EINVAL;
	}

	if (nfs_pread_async(nfs_data->nfs, nfs_data->nfsfh,
			    (void *)iod->addr,
			    iod->nr_sectors * 512, iod->start_sector * 512,
			    rw_async_cb, cb_data) < 0) {
		ublk_err("Failed to read from nfs file. %s\n", nfs_get_error(nfs_data->nfs));
		return -ENOMEM;
	}

	return 0;
}

static int nfs_tgt_write(const struct ublksrv_queue *q,
			 const struct ublksrv_io_desc *iod, int tag)
{
	struct nfs_queue_data *q_data = nfs_get_queue_data(q);
	struct nfs_tgt_data *nfs_data = q_data->nfs_data;
	nfs_cb_data_t *cb_data = &q_data->ios[tag];

	if ((iod->nr_sectors + iod->start_sector) * 512 > nfs_data->capacity) {
		return -EINVAL;
	}

	if (nfs_pwrite_async(nfs_data->nfs, nfs_data->nfsfh,
			     (void *)iod->addr,
			     iod->nr_sectors * 512, iod->start_sector * 512,
			     rw_async_cb, cb_data) < 0) {
		ublk_err("Failed to write to nfs file. %s\n", nfs_get_error(nfs_data->nfs));
		return -ENOMEM;
	}

	return 0;
}

static int nfs_tgt_flush(const struct ublksrv_queue *q,
			 const struct ublksrv_io_desc *iod, int tag)
{
	struct nfs_queue_data *q_data = nfs_get_queue_data(q);
	struct nfs_tgt_data *nfs_data = q_data->nfs_data;
	nfs_cb_data_t *cb_data = &q_data->ios[tag];

	if (nfs_fsync_async(nfs_data->nfs, nfs_data->nfsfh,
			    rw_async_cb, cb_data) < 0) {
		ublk_err("Failed to fsync nfs file. %s\n", nfs_get_error(nfs_data->nfs));
		return -ENOMEM;
	}

	return 0;
}

static int nfs_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	const struct ublksrv_io_desc *iod = data->iod;
	unsigned ublk_op = ublksrv_get_op(iod);
	int ret = -ENOTSUP;

	switch (ublk_op) {
	case UBLK_IO_OP_READ:
		ret = nfs_tgt_read(q, iod, data->tag);
		break;
	case UBLK_IO_OP_WRITE:
		ret = nfs_tgt_write(q, iod, data->tag);
		break;
	case UBLK_IO_OP_DISCARD:
		ublk_err("UBLK_IO_OP_DISCARD is not supported");
		break;
	case UBLK_IO_OP_FLUSH:
		ret = nfs_tgt_flush(q, iod, data->tag);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
		ublk_err("UBLK_IO_OP_WRITE_ZEROS is not supported");
		break;
	default:
		ret = -EINVAL;
	}

	if (ret) {
		ublksrv_complete_io(q, data->tag, ret);
	}
	return ret;
}

static struct nfs_tgt_data *nfs_init(const char *nfsurl)
{
	struct nfs_tgt_data *nfs_data;
	struct nfs_stat_64 st;

	nfs_data = (struct nfs_tgt_data *)calloc(sizeof(struct nfs_tgt_data), 1);
	if (nfs_data == NULL) {
		ublk_err( "%s: failed to calloc tgt_data\n", __func__);
		return NULL;
	}

	strncpy(nfs_data->url, nfsurl, sizeof(nfs_data->url));

	nfs_data->nfs = nfs_init_context();
	if (nfs_data->nfs == NULL) {
		fprintf(stderr, "failed to init context\n");
		goto fail_free;
	}

	url = nfs_parse_url_full(nfs_data->nfs, nfs_data->url);
	if (url == NULL) {
		fprintf(stderr, "%s\n", nfs_get_error(nfs_data->nfs));
		goto fail_context;
	}

	if (nfs_mount(nfs_data->nfs, url->server, url->path) != 0) {
		fprintf(stderr, "Failed to mount nfs share : %s\n",
			       nfs_get_error(nfs_data->nfs));
		goto fail_url;
	}

	if (nfs_stat64(nfs_data->nfs, url->file, &st) < 0) {
		fprintf(stderr, "Failed to stat %s\n", url->file);
		goto fail_url;
	}
	nfs_data->capacity = st.nfs_size;

	if (nfs_open(nfs_data->nfs, url->file, O_RDWR, &nfs_data->nfsfh) != 0) {
		fprintf(stderr, "Failed to open nfs file : %s\n",
			       nfs_get_error(nfs_data->nfs));
		goto fail_url;
	}

	return nfs_data;

 fail_url:
	nfs_destroy_url(url);
 fail_context:
	nfs_destroy_context(nfs_data->nfs);
 fail_free:
	free(nfs_data);
	return NULL;
}

static void nfs_exit(struct nfs_tgt_data *nfs_data)
{
	if (nfs_data) {
		nfs_close(nfs_data->nfs, nfs_data->nfsfh);
		nfs_destroy_context(nfs_data->nfs);
		free(nfs_data);
	}
}

static int nfs_setup_tgt(struct ublksrv_dev *dev)
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

static int nfs_recover_tgt(struct ublksrv_dev *dev, int type)
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	char url[PATH_MAX];
	int ret;

	ret = ublk_json_read_target_str_info(cdev, "url", url);
	if (ret < 0) {
		ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
				__func__, ret);
		return ret;
	}

	return nfs_setup_tgt(dev);
}

static int nfs_init_tgt(struct ublksrv_dev *dev, int type, int argc,
			char *argv[])
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(cdev);
	struct ublksrv_tgt_base_json tgt_json = { 0 };
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.attrs		  = UBLK_ATTR_VOLATILE_CACHE,
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift		= 12,
			.io_min_shift		= 9,
		},
	};
	static const struct option lo_longopts[] = {
		{ "nfs",	     1,	NULL, 1024 },
		{ NULL }
	};
	int opt;
	struct nfs_tgt_data *nfs_data = NULL;
	const char *nfsurl = NULL;

	if (info->flags & UBLK_F_UNPRIVILEGED_DEV)
		return -1;

	if (ublksrv_is_recovering(cdev))
		return nfs_recover_tgt(dev, 0);

	strcpy(tgt_json.name, "nfs");

	while ((opt = getopt_long(argc, argv, "-:",
				  lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 1024:
			nfsurl = optarg;
			break;
		}
	}

	if (nfsurl == NULL) {
		fprintf(stderr, "Must specify --nfs=NFS_URL\n");
		return -EINVAL;
	}

	nfs_data = nfs_init(nfsurl);
	if (nfs_data == NULL) {
		fprintf(stderr, "Failed to initialize nfs\n");
		return -ENOMEM;
	}

	tgt_json.dev_size = nfs_data->capacity;
	p.basic.dev_sectors = nfs_data->capacity >> 9;

	ublk_json_write_dev_info(cdev);
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_tgt_str(cdev, "url", nfs_data->url);
	ublk_json_write_params(cdev, &p);

	nfs_exit(nfs_data);
	return nfs_setup_tgt(dev);
}

static void nfs_deinit_tgt(const struct ublksrv_dev *dev)
{
	if (url)
		nfs_destroy_url(url);
}

static int nfs_init_queue(const struct ublksrv_queue *q,
		void **queue_data_ptr)
{
	struct nfs_queue_data *data = (struct nfs_queue_data *)calloc(sizeof(*data) +
				sizeof(data->ios[0]) * q->q_depth, 1);
	struct nfs_context *nfs;
	int i;
	char url[PATH_MAX];
	int ret;

	ret = ublk_json_read_target_str_info(ublksrv_get_ctrl_dev(q->dev), "url", url);
	if (ret < 0) {
		ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
				__func__, ret);
		return ret;
	}

	if (!data)
		return -ENOMEM;

	data->nfs_data = nfs_init(url);
	
	for (i = 0; i < q->q_depth; i++)
		data->ios[i].q = q;

	*queue_data_ptr = (void *)data;
	nfs = data->nfs_data->nfs;
	ublksrv_epoll_add_fd((struct ublksrv_queue *)q, nfs_get_fd(nfs), nfs_which_events(nfs), nfs_socket_cb);

	return 0;
}

static void nfs_deinit_queue(const struct ublksrv_queue *q)
{
	struct nfs_queue_data *data = nfs_get_queue_data(q);

	nfs_exit(data->nfs_data);
	free(data);
}

static void nfs_cmd_usage()
{
	printf("\t--nfs NFS-URL\n");
}

static const struct ublksrv_tgt_type  nfs_tgt_type = {
	.handle_io_async = nfs_handle_io_async,
	.usage_for_add = nfs_cmd_usage,
	.init_tgt = nfs_init_tgt,
	.deinit_tgt = nfs_deinit_tgt,
	.name	=  "nfs",
	.init_queue = nfs_init_queue,
	.deinit_queue = nfs_deinit_queue,
};

int main(int argc, char *argv[])
{
	return ublksrv_main(&nfs_tgt_type, argc, argv);
}
