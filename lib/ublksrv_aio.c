// SPDX-License-Identifier: MIT or LGPL-2.1-only

#define _GNU_SOURCE
#include "ublksrv_aio.h"
#include <sys/epoll.h>

static inline void aio_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(LOG_INFO, fmt, ap);
}

int ublksrv_aio_submit_worker(struct ublksrv_aio_ctx *ctx,
		ublksrv_aio_submit_fn *fn, struct aio_list *done)
{
	struct ublksrv_aio *req = NULL;
	unsigned long long data;
	struct aio_list sl;
	int total = 0;
	bool more;

	aio_list_init(&sl);
again:
	pthread_spin_lock(&ctx->submit.lock);
	aio_list_splice(&ctx->submit.list, &sl);
	pthread_spin_unlock(&ctx->submit.lock);

	while (req = aio_list_pop(&sl)) {
		int ret = fn(ctx, req);

		/*
		 * submission failed, so set result for this request,
		 * otherwise it is user's responsibility to set correct
		 * ->res after the request is completed
		 */
		if (ret < 0) {
			req->res = ret;
			aio_log("ublk aio submission fail, %d\n", ret);
		}
		total += 1;
		if (ret && done)
			aio_list_add(done, req);
	}

	read(ctx->efd, &data, 8);

	pthread_spin_lock(&ctx->submit.lock);
	more = !aio_list_empty(&ctx->submit.list);
	pthread_spin_unlock(&ctx->submit.lock);
	if (more)
		goto again;

	return total;
}

static void move_to_queue_complete_list(struct ublksrv_aio_ctx *ctx,
		struct ublksrv_queue *q, struct aio_list *list)
{
	struct ublksrv_aio_list *compl;

	if (aio_list_empty(list))
		return;

	compl = &ctx->complete[q->q_id];
	pthread_spin_lock(&compl->lock);
	aio_list_splice(list, &compl->list);
	pthread_spin_unlock(&compl->lock);
}

void ublksrv_aio_complete_worker(struct ublksrv_aio_ctx *ctx,
		struct aio_list *completed)
{
	struct aio_list this, others;
	struct ublksrv_aio *req = NULL;
	struct ublksrv_queue *this_q = NULL;

	if (aio_list_empty(completed))
		return;

	if (ctx->flags & UBLKSRV_AIO_QUEUE_WIDE) {
		this_q = ublksrv_get_queue(ctx->dev,
				ublksrv_aio_qid(completed->head->id));
		move_to_queue_complete_list(ctx, this_q, completed);
		ublksrv_queue_send_event(this_q);
		return;
	}

	aio_list_init(&this);
	aio_list_init(&others);

	while (!aio_list_empty(completed)) {
		struct ublksrv_aio_list *compl;

		this_q = ublksrv_get_queue(ctx->dev,
				ublksrv_aio_qid(completed->head->id));

		while (req = aio_list_pop(completed)) {
			struct ublksrv_queue *q = ublksrv_get_queue(ctx->dev,
					ublksrv_aio_qid(req->id));

			if (q == this_q)
				aio_list_add(&this, req);
			else
				aio_list_add(&others, req);
		}

		move_to_queue_complete_list(ctx, this_q, &this);
		ublksrv_queue_send_event(this_q);
		aio_list_splice(&others, completed);
	}
}

struct ublksrv_aio_ctx *ublksrv_aio_ctx_init(struct ublksrv_dev *dev, unsigned
		flags)
{
	unsigned nr_hw_queues = dev->ctrl_dev->dev_info.nr_hw_queues;
	struct ublksrv_aio_ctx *ctx;
	int ret, i;

	if (!(dev->ctrl_dev->dev_info.ublksrv_flags & UBLKSRV_F_NEED_EVENTFD))
		return NULL;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->complete = malloc(nr_hw_queues * sizeof(struct ublksrv_aio_list));
	if (!ctx->complete) {
		free(ctx);
		return NULL;
	}
	for (i = 0; i < nr_hw_queues; i++)
		ublksrv_aio_init_list(&ctx->complete[i]);

	ublksrv_aio_init_list(&ctx->submit);

	ctx->flags = flags;
	ctx->dev = dev;
	ctx->dead = false;
	ctx->efd = eventfd(0, O_NONBLOCK);

	return ctx;
}

/* called before pthread_join() of the pthread context */
void ublksrv_aio_ctx_shutdown(struct ublksrv_aio_ctx *ctx)
{
	unsigned long long data = 1;

	ctx->dead = true;
	write(ctx->efd, &data, 8);
}

/* called afer pthread_join() of the pthread context returns */
void ublksrv_aio_ctx_deinit(struct ublksrv_aio_ctx *ctx)
{
	close(ctx->efd);
	free(ctx);
}

struct ublksrv_aio *ublksrv_aio_alloc_req(struct ublksrv_aio_ctx *ctx,
		int payload_size)
{
	const int sz = (sizeof(struct ublksrv_aio) + payload_size + 7) & ~ 0x7;

	return (struct ublksrv_aio *)calloc(1, sz);
}

void ublksrv_aio_free_req(struct ublksrv_aio_ctx *ctx, struct ublksrv_aio *req)
{
	free(req);
}

void ublksrv_aio_submit_req(struct ublksrv_aio_ctx *ctx,
		struct ublksrv_queue *q, struct ublksrv_aio *req)
{
	unsigned long long data = 1;

	pthread_spin_lock(&ctx->submit.lock);
	aio_list_add(&ctx->submit.list, req);
	pthread_spin_unlock(&ctx->submit.lock);

	write(ctx->efd, &data, 8);
}

void ublksrv_aio_get_completed_reqs(struct ublksrv_aio_ctx *ctx,
		const struct ublksrv_queue *q,
		struct aio_list *al)
{
	struct ublksrv_aio_list *compl = &ctx->complete[q->q_id];

	pthread_spin_lock(&compl->lock);
	aio_list_splice(&compl->list, al);
	pthread_spin_unlock(&compl->lock);
}

void ublksrv_aio_handle_event(struct ublksrv_aio_ctx *ctx,
		struct ublksrv_queue *q)
{
	struct ublksrv_aio_list *compl = &ctx->complete[q->q_id];
	struct ublksrv_aio *req;
	struct aio_list al;

	aio_list_init(&al);
	pthread_spin_lock(&compl->lock);
	aio_list_splice(&compl->list, &al);
	ublksrv_queue_handled_event(q);
	pthread_spin_unlock(&compl->lock);

	while (req = aio_list_pop(&al)) {
		ublksrv_complete_io(q, ublksrv_aio_tag(req->id),
				req->res);
		ublksrv_aio_free_req(ctx, req);
	}
}
