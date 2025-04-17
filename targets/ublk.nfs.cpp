// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include "ublksrv_tgt.h"
#include <nfsc/libnfs.h>
#include <sys/eventfd.h>

#define NFS_EVTFD_OP  0xff

//#define NFS_DEBUG_IO  1
//#define NFS_DEBUG_EVT  1

#ifdef NFS_DEBUG_IO
#define NFS_IO_DBG  printf
#else
#define NFS_IO_DBG(...)
#endif

#ifdef NFS_DEBUG_EVT
#define NFS_EVT_DBG  printf
#else
#define NFS_EVT_DBG(...)
#endif

#define EVT_BUF_BGID 		1
#define EVT_BUF_SIZE 		8
#define NR_EVT_BUFS 		64
#define EVT_BR_MASK 		(NR_EVT_BUFS - 1)

struct nfs_tgt_data {
	char url[4096];
	struct nfs_context *nfs;
	struct nfsfh *nfsfh;
	size_t capacity;
	int mshot_evt;
};

typedef struct nfs_cb_data {
	struct nfs_cb_data *next;
	const struct ublksrv_queue *q;
	int tag;
	ssize_t count;
} nfs_cb_data_t;

struct nfs_queue_data {
	nfs_cb_data_t *io_list;
	pthread_spinlock_t io_list_lock;
	uint32_t events;
	int evtfd;
	uint64_t  evt_data[NR_EVT_BUFS];
	struct io_uring_buf_ring *br;
};

static void nfs_submit_event_read_mshot(const struct ublksrv_queue *q);

static inline int use_mshot_evt(const struct nfs_queue_data *data)
{
	return !!data->br;
}

static inline bool is_evtfd_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	return data->tag >= q->q_depth;
}

static inline struct nfs_queue_data *
nfs_get_queue_data(const struct ublksrv_queue *q)
{
	return (struct nfs_queue_data *)q->private_data;
}

static int nfs_send_event(struct nfs_queue_data *q_data)
{
	uint64_t data = 1;
	const int cnt = sizeof(uint64_t);

	if (write(q_data->evtfd, &data, cnt) != cnt) {
		ublk_err("%s: wrote wrong bytes to eventfd\n",
				__func__);
		return -EPIPE;
	}
	return 0;
}

static void nfs_handle_event(const struct ublksrv_queue *q)
{
	struct nfs_queue_data *q_data = nfs_get_queue_data(q);
	nfs_cb_data_t *cb_data, *tmp;

	pthread_spin_lock(&q_data->io_list_lock);
	cb_data = q_data->io_list;
	q_data->io_list = NULL;
	q_data->events = 0;
	pthread_spin_unlock(&q_data->io_list_lock);

	while (cb_data) {
		tmp = cb_data->next;

		ublksrv_complete_io(cb_data->q, cb_data->tag, cb_data->count);
		free(cb_data);
		cb_data = tmp;
	}

	if (!use_mshot_evt(q_data)) {
		pthread_spin_lock(&q_data->io_list_lock);
		ublksrv_queue_handled_event(q);
		pthread_spin_unlock(&q_data->io_list_lock);
	}
}

static void nfs_tgt_io_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	int tag = user_data_to_tag(cqe->user_data);
	ublk_assert(tag == data->tag);

	if (!(cqe->flags & IORING_CQE_F_MORE) || cqe->res < 0)
		nfs_submit_event_read_mshot(q);

	NFS_EVT_DBG("%s: queue %d tag %d cqe(res %d flags %x user data %llx)\n",
			__func__, q->q_id, tag,
			cqe->res, cqe->flags, cqe->user_data);

	if (is_evtfd_io(q, data))
		nfs_handle_event(q);
}

void rw_async_cb(int status, struct nfs_context *nfs,
		 void *data, void *private_data)
{
	nfs_cb_data_t *cb_data = (nfs_cb_data_t *)private_data;
	const struct ublksrv_queue *q = cb_data->q;
	struct nfs_queue_data *q_data = nfs_get_queue_data(q);
	int send_event;

	if (status < 0) {
		fprintf(stderr, "pread/pwrite failed with \"%s\"\n", (char *)data);
		status = -EIO;
	}
	cb_data->count = status;

	pthread_spin_lock(&q_data->io_list_lock);
	cb_data->next = q_data->io_list;
	q_data->io_list = cb_data;
	send_event = (q_data->events == 0);
	q_data->events++;
	pthread_spin_unlock(&q_data->io_list_lock);

	NFS_EVT_DBG("%s: queue %u tag %u nfs io done(%d), events %d / %d\n",
			__func__, q->q_id, cb_data->tag, status,
			q_data->events, send_event);

	if (!use_mshot_evt(q_data)) {
		ublksrv_queue_send_event(q);
	} else {
		if (send_event)
			nfs_send_event(q_data);
	}
}

static int nfs_tgt_read(const struct ublksrv_queue *q,
			const struct ublksrv_io_desc *iod, int tag)
{
	const struct ublksrv_dev *dev = q->dev;
	struct nfs_tgt_data *nfs_data = (struct nfs_tgt_data *)dev->tgt.tgt_data;
	nfs_cb_data_t *cb_data;

	if ((iod->nr_sectors + iod->start_sector) * 512 > nfs_data->capacity) {
		return -EINVAL;
	}

	cb_data = (nfs_cb_data_t *)malloc(sizeof(*cb_data));
	if (cb_data == NULL) {
		ublk_err("Malloc failed in nfs_tgt_read");
		return -ENOMEM;
	}
	cb_data->q = q;
	cb_data->tag = tag;

	if (nfs_pread_async(nfs_data->nfs, nfs_data->nfsfh,
			    (void *)iod->addr,
			    iod->nr_sectors * 512, iod->start_sector * 512,
			    rw_async_cb, cb_data) < 0) {
		ublk_err("Failed to read from nfs file. %s\n", nfs_get_error(nfs_data->nfs));
		free(cb_data);
		return -ENOMEM;
	}

	return 0;
}

static int nfs_tgt_write(const struct ublksrv_queue *q,
			 const struct ublksrv_io_desc *iod, int tag)
{
	const struct ublksrv_dev *dev = q->dev;
	struct nfs_tgt_data *nfs_data = (struct nfs_tgt_data *)dev->tgt.tgt_data;
	nfs_cb_data_t *cb_data;

	if ((iod->nr_sectors + iod->start_sector) * 512 > nfs_data->capacity) {
		return -EINVAL;
	}

	cb_data = (nfs_cb_data_t *)malloc(sizeof(*cb_data));
	if (cb_data == NULL) {
		ublk_err("Malloc failed in nfs_tgt_read");
		return -ENOMEM;
	}
	cb_data->q = q;
	cb_data->tag = tag;

	if (nfs_pwrite_async(nfs_data->nfs, nfs_data->nfsfh,
			     (void *)iod->addr,
			     iod->nr_sectors * 512, iod->start_sector * 512,
			     rw_async_cb, cb_data) < 0) {
		ublk_err("Failed to write to nfs file. %s\n", nfs_get_error(nfs_data->nfs));
		free(cb_data);
		return -ENOMEM;
	}

	return 0;
}

static int nfs_tgt_flush(const struct ublksrv_queue *q,
			 const struct ublksrv_io_desc *iod, int tag)
{
	const struct ublksrv_dev *dev = q->dev;
	struct nfs_tgt_data *nfs_data = (struct nfs_tgt_data *)dev->tgt.tgt_data;
	nfs_cb_data_t *cb_data;

	cb_data = (nfs_cb_data_t *)malloc(sizeof(*cb_data));
	if (cb_data == NULL) {
		ublk_err("Malloc failed in nfs_tgt_read");
		return -ENOMEM;
	}
	cb_data->q = q;
	cb_data->tag = tag;

	if (nfs_fsync_async(nfs_data->nfs, nfs_data->nfsfh,
			    rw_async_cb, cb_data) < 0) {
		ublk_err("Failed to fsync nfs file. %s\n", nfs_get_error(nfs_data->nfs));
		free(cb_data);
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

	NFS_IO_DBG("%s: queue %d tag %d op %d\n", __func__,
			q->q_id, data->tag, ublk_op);
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
	struct nfs_url *url;
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

	if (nfs_mt_service_thread_start(nfs_data->nfs)) {
		fprintf(stderr, "failed to start service thread\n");
		goto fail_close;
	}

	nfs_destroy_url(url);
	return nfs_data;

 fail_close:
	nfs_close(nfs_data->nfs, nfs_data->nfsfh);
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
		nfs_mt_service_thread_stop(nfs_data->nfs);
		nfs_destroy_context(nfs_data->nfs);
		free(nfs_data);
	}
}

static int nfs_setup_tgt(struct ublksrv_dev *dev, int mshot_evt)
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
	tgt->tgt_ring_depth = info->queue_depth + !!mshot_evt;
	//one extra slot for handling eventfd notfication
	tgt->extra_ios = !!mshot_evt;

	tgt->nr_fds = 0;

	return 0;
}

static int nfs_recover_tgt(struct ublksrv_dev *dev, int type)
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	char url[PATH_MAX];
	struct nfs_tgt_data *nfs_data = NULL;
	int ret;
	unsigned long mshot_evt;

	ret = ublk_json_read_target_str_info(cdev, "url", url);
	if (ret < 0) {
		ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_ulong_info(cdev, "mshot_evt", &mshot_evt);
	if (ret) {
		ublk_err( "%s: read target mshot_evt failed %d\n",
				__func__, ret);
		return ret;
	}

	nfs_data = nfs_init(url);
	dev->tgt.tgt_data = nfs_data;
	if (dev->tgt.tgt_data == NULL) {
		fprintf(stderr, "Failed to initialize nfs\n");
		return -ENOMEM;
	}

	return nfs_setup_tgt(dev, mshot_evt);
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
		{ "mshot_evt",	     0,	NULL, 0 },
		{ NULL }
	};
	int opt;
	struct nfs_tgt_data *nfs_data = NULL;
	const char *nfsurl = NULL;
	int mshot_evt = 0;

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
		case 0:
			mshot_evt = 1;
			break;
		}
	}

	if (nfsurl == NULL) {
		fprintf(stderr, "Must specify --nfs=NFS_URL\n");
		return -EINVAL;
	}

	nfs_data = nfs_init(nfsurl);
	dev->tgt.tgt_data = nfs_data;
	if (dev->tgt.tgt_data == NULL) {
		fprintf(stderr, "Failed to initialize nfs\n");
		return -ENOMEM;
	}
	nfs_data->mshot_evt = mshot_evt;

	tgt_json.dev_size = nfs_data->capacity;
	p.basic.dev_sectors = nfs_data->capacity >> 9;

	ublk_json_write_dev_info(cdev);
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_tgt_str(cdev, "url", nfs_data->url);
	ublk_json_write_tgt_long(cdev, "mshot_evt", mshot_evt);
	ublk_json_write_params(cdev, &p);

	return nfs_setup_tgt(dev, mshot_evt);
}

static void nfs_deinit_tgt(const struct ublksrv_dev *dev)
{
	struct nfs_tgt_data *nfs_data = (struct nfs_tgt_data *)dev->tgt.tgt_data;

	nfs_exit(nfs_data);
}

static void nfs_deinit_queue(const struct ublksrv_queue *q)
{
	struct nfs_queue_data *q_data = nfs_get_queue_data(q);

	io_uring_free_buf_ring(q->ring_ptr, q_data->br, NR_EVT_BUFS, EVT_BUF_BGID);
	close(q_data->evtfd);
	free(q_data);
}

static void __nfs_submit_event_read_mshot(const struct ublksrv_queue *q,
		struct nfs_queue_data *data)
{
	struct io_uring *r = q->ring_ptr;
	struct io_uring_sqe *sqe[1];

	io_uring_buf_ring_add(data->br, &data->evt_data[0],
			sizeof(data->evt_data), 1, EVT_BR_MASK, 0);
	io_uring_buf_ring_advance(data->br, 1);

	/* submit read_multishot for covering eventfd notification */
	ublk_queue_alloc_sqes(q, sqe, 1);
	io_uring_prep_read_multishot(sqe[0], data->evtfd, 0, 0, EVT_BUF_BGID);
	sqe[0]->user_data = build_user_data(q->q_depth, NFS_EVTFD_OP, 0, 1);
	io_uring_submit_and_wait(r, 0);
}

static void nfs_submit_event_read_mshot(const struct ublksrv_queue *q)
{
	__nfs_submit_event_read_mshot(q, nfs_get_queue_data(q));
}

static int nfs_init_queue(const struct ublksrv_queue *q,
		void **queue_data_ptr)
{
	struct nfs_tgt_data *ddata = (struct nfs_tgt_data*)q->dev->tgt.tgt_data;
	struct nfs_queue_data *data =
		(struct nfs_queue_data *)calloc(sizeof(*data), 1);
	struct io_uring *r = q->ring_ptr;
	int ret;

	if (!data)
		return -ENOMEM;

	pthread_spin_init(&data->io_list_lock, PTHREAD_PROCESS_PRIVATE);
	if (!ddata->mshot_evt)
		goto out;

	data->br = io_uring_setup_buf_ring(r, NR_EVT_BUFS, EVT_BUF_BGID, IOU_PBUF_RING_INC, &ret);
	if (!data->br) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return ret;
	}

	data->evtfd = eventfd(0, 0);
	__nfs_submit_event_read_mshot(q, data);

	NFS_EVT_DBG("%s: queue %d submit eventfd sqe\n", __func__, q->q_id);
out:
	*queue_data_ptr = (void *)data;
	return 0;
}

static void nfs_cmd_usage()
{
	printf("\t--nfs NFS-URL\n");
}

static const struct ublksrv_tgt_type  nfs_tgt_type = {
	.handle_io_async = nfs_handle_io_async,
	.tgt_io_done = nfs_tgt_io_done,
	.handle_event = nfs_handle_event,
	.usage_for_add = nfs_cmd_usage,
	.init_tgt = nfs_init_tgt,
	.deinit_tgt = nfs_deinit_tgt,
	.ublksrv_flags = UBLKSRV_F_NEED_EVENTFD,
	.name	=  "nfs",
	.init_queue = nfs_init_queue,
	.deinit_queue = nfs_deinit_queue,
};

int main(int argc, char *argv[])
{
	return ublksrv_tgt_cmd_main(&nfs_tgt_type, argc, argv);
}
