// SPDX-License-Identifier: MIT or LGPL-2.1-only

#ifndef UBLKSRV_AIO_INC_H
#define UBLKSRV_AIO_INC_H

/*
 * APIs for offloading IO handling in non-ublksrv context, refer to
 * demo_event.c for how to use these APIs
 */

#ifdef __cplusplus
extern "C" {
#endif

struct ublksrv_aio_ctx;
struct ublksrv_aio;

/*
 * return value:
 *
 * > 0 : the request is done
 * = 0 : submitted successfully, but not done
 * < 0 : submitted not successfully
 */
typedef int (ublksrv_aio_submit_fn)(struct ublksrv_aio_ctx *ctx,
		struct ublksrv_aio *req);

#define ublksrv_aio_qid(val)  ((val >> 13) & 0x7ff)
#define ublksrv_aio_tag(val)  (val & 0x1fff)

static inline unsigned ublksrv_aio_pid_tag(unsigned qid, unsigned tag)
{
	return tag | (qid << 13);
}

struct ublksrv_aio {
	struct ublksrv_io_desc io;
	union {
		int res;	/* output */
		int fd;		/* input */
	};

	/* reserved 31 ~ 24, bit 23 ~ 13: qid, bit 12 ~ 0: tag */
	unsigned id;
	struct ublksrv_aio *next;
	unsigned long data[0];
};

struct aio_list {
	struct ublksrv_aio *head, *tail;
};

static inline void aio_list_init(struct aio_list *al)
{
	al->head = al->tail = NULL;
}

static inline void aio_list_add(struct aio_list *al, struct ublksrv_aio *io)
{
	io->next = NULL;

	if (al->tail)
		al->tail->next = io;
	else
		al->head = io;
	al->tail = io;
}

static inline void aio_list_splice(struct aio_list *n,
		struct aio_list *head)
{
	if (!n->head)
		return;

	if (head->tail)
		head->tail->next = n->head;
	else
		head->head = n->head;

	head->tail = n->tail;

	aio_list_init(n);
}

static inline int aio_list_empty(const struct aio_list *al)
{
	return al->head == NULL;
}

static inline struct ublksrv_aio *aio_list_pop(struct aio_list *al)
{
	struct ublksrv_aio *io = al->head;

	if (io) {
		al->head = io->next;
		if (!al->head)
			al->tail = NULL;

		io->next = NULL;
	}

	return io;
}

struct ublksrv_aio_list {
	pthread_spinlock_t lock;
	struct aio_list list;
};

static inline void ublksrv_aio_init_list(struct ublksrv_aio_list *l)
{
	pthread_spin_init(&l->lock, PTHREAD_PROCESS_PRIVATE);
	aio_list_init(&l->list);
}

struct ublksrv_aio_ctx *ublksrv_aio_ctx_init(const struct ublksrv_dev *dev,
		unsigned flags);
void ublksrv_aio_ctx_shutdown(struct ublksrv_aio_ctx *ctx);
void ublksrv_aio_ctx_deinit(struct ublksrv_aio_ctx *ctx);
struct ublksrv_aio *ublksrv_aio_alloc_req(struct ublksrv_aio_ctx *ctx,
		int payload_size);
void ublksrv_aio_free_req(struct ublksrv_aio_ctx *ctx, struct ublksrv_aio *req);
void ublksrv_aio_submit_req(struct ublksrv_aio_ctx *ctx,
		const struct ublksrv_queue *q, struct ublksrv_aio *req);
void ublksrv_aio_get_completed_reqs(struct ublksrv_aio_ctx *ctx,
		const struct ublksrv_queue *q,
		struct aio_list *al);
int ublksrv_aio_submit_worker(struct ublksrv_aio_ctx *ctx,
		ublksrv_aio_submit_fn *fn, struct aio_list *submitted);
void ublksrv_aio_complete_worker(struct ublksrv_aio_ctx *ctx,
		struct aio_list *completed);
void ublksrv_aio_handle_event(struct ublksrv_aio_ctx *ctx,
		const struct ublksrv_queue *q);
int ublksrv_aio_get_efd(struct ublksrv_aio_ctx *ctx);
void ublksrv_aio_set_ctx_data(struct ublksrv_aio_ctx *ctx, void *data);
void *ublksrv_aio_get_ctx_data(struct ublksrv_aio_ctx *ctx);
bool ublksrv_aio_ctx_dead(struct ublksrv_aio_ctx *ctx);
const struct ublksrv_dev *ublksrv_aio_get_dev(struct ublksrv_aio_ctx *ctx);

#ifdef __cplusplus
}
#endif
#endif
