#include "ublksrv.h"

static struct ublksrv_tgt_type *tgt_list[UBLKSRV_TGT_TYPE_MAX] = {};

int ublksrv_register_tgt_type(struct ublksrv_tgt_type *type)
{
	if (type->type < UBLKSRV_TGT_TYPE_MAX && !tgt_list[type->type]) {
		tgt_list[type->type] = type;
		return 0;
	}

	die("usbsrv: target %s/%d can't be registered\n",
			type->name, type->type);
	return -1;
}

static int __ublksrv_tgt_init(struct ublksrv_tgt_info *tgt, const char *type_name,
		const struct ublksrv_tgt_type *ops, int type,
		int argc, char *argv[])
{
	if (strcmp(ops->name, type_name))
		return -EINVAL;

	optind = 0;     /* so that we can parse our arguments */
	tgt->ops = ops;
	if (!ops->init_tgt(tgt, type, argc, argv)) {
		return 0;
	}
	tgt->ops = NULL;
	return -EINVAL;
}

int ublksrv_tgt_init(struct ublksrv_tgt_info *tgt, const char *type_name,
		const struct ublksrv_tgt_type *ops,
		int argc, char *argv[])
{
	int i;

	if (type_name == NULL)
		return -EINVAL;

	if (ops)
		return __ublksrv_tgt_init(tgt, type_name, ops,
				ops->type, argc, argv);

	for (i = 0; i < UBLKSRV_TGT_TYPE_MAX; i++) {
		const struct ublksrv_tgt_type  *lops = tgt_list[i];

		if (!__ublksrv_tgt_init(tgt, type_name, lops, i, argc, argv))
			return 0;
	}

	return -EINVAL;
}

void ublksrv_for_each_tgt_type(void (*handle_tgt_type)(unsigned idx,
			const struct ublksrv_tgt_type *type, void *data),
		void *data)
{
	int i;

	for (i = 0; i < UBLKSRV_TGT_TYPE_MAX; i++) {
		int len;

                const struct ublksrv_tgt_type  *type = tgt_list[i];

		if (!type)
			continue;
		handle_tgt_type(i, type, data);
	}
}

static inline void ublksrv_tgt_exit(struct ublksrv_tgt_info *tgt)
{
	int i;

	for (i = 1; i < tgt->nr_fds; i++)
		close(tgt->fds[i]);
}

void ublksrv_tgt_deinit(struct ublksrv_tgt_info *tgt, struct ublksrv_dev *dev)
{
	ublksrv_tgt_exit(tgt);

	if (tgt->ops->deinit_tgt)
		tgt->ops->deinit_tgt(tgt, dev);
}
