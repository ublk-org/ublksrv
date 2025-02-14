// SPDX-License-Identifier: MIT or GPL-2.0-only

#include "config.h"
#include "ublksrv_tgt.h"

/********************cmd handling************************/
static struct ublksrv_tgt_type *tgt_list[UBLKSRV_TGT_TYPE_MAX] = {};

static const struct ublksrv_tgt_type *ublksrv_find_tgt_type(const char *name)
{
	int i;

	for (i = 0; i < UBLKSRV_TGT_TYPE_MAX; i++) {
		const struct ublksrv_tgt_type *type = tgt_list[i];

		if (type == NULL)
			continue;

		if (!strcmp(type->name, name))
			return type;
	}

	return NULL;
}

static void ublksrv_for_each_tgt_type(void (*handle_tgt_type)(unsigned idx,
			const struct ublksrv_tgt_type *type, void *data),
		void *data)
{
	int i;

	for (i = 0; i < UBLKSRV_TGT_TYPE_MAX; i++) {
                const struct ublksrv_tgt_type  *type = tgt_list[i];

		if (!type)
			continue;
		handle_tgt_type(i, type, data);
	}
}

int ublksrv_register_tgt_type(struct ublksrv_tgt_type *type)
{
	if (type->type < UBLKSRV_TGT_TYPE_MAX && !tgt_list[type->type]) {
		tgt_list[type->type] = type;
		return 0;
	}
	return -1;
}

void ublksrv_unregister_tgt_type(struct ublksrv_tgt_type *type)
{
	if (type->type < UBLKSRV_TGT_TYPE_MAX && tgt_list[type->type]) {
		tgt_list[type->type] = NULL;
	}
}


static char *pop_cmd(int *argc, char *argv[])
{
	char *cmd = argv[1];
	if (*argc < 2) {
		return NULL;
	}

	memmove(&argv[1], &argv[2], *argc * sizeof(argv[0]));
	(*argc)--;

	return cmd;
}

static int ublksrv_execve_helper(const char *type, int argc, char *argv[])
{
	char *cmd, **nargv;
	char *nenv[] = { NULL };
	int i;

	asprintf(&cmd, "ublk.%s", type);
	nargv = (char **)calloc(argc + 1, sizeof(char *));
	if (!nargv)
		return -ENOMEM;
	nargv[0] = cmd;
	for (i = 1; i < argc; i++)
		nargv[i] = argv[i];

	return execve(nargv[0], nargv, nenv);
}

static int cmd_dev_add(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {0};
	struct ublksrv_ctrl_dev *dev;
	const struct ublksrv_tgt_type *tgt_type;
	int ret;
	const char *dump_buf;

	ublksrv_parse_std_opts(&data, argc, argv);
  
	if (data.tgt_type == NULL) {
		fprintf(stderr, "no dev type specified\n");
		return -EINVAL;
	}
	tgt_type = ublksrv_find_tgt_type(data.tgt_type);
	if (tgt_type == NULL) {
		ret = ublksrv_execve_helper(data.tgt_type, argc, argv);
		if (ret) {
			fprintf(stderr, "failed to spawn target\n");
			return ret;
		}
	}
	data.tgt_ops = tgt_type;
	data.flags |= tgt_type->ublk_flags;
	data.ublksrv_flags |= tgt_type->ublksrv_flags;

	//optind = 0;	/* so that tgt code can parse their arguments */
	data.tgt_argc = argc;
	data.tgt_argv = argv;
	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		return -EOPNOTSUPP;
	}

	ret = ublksrv_ctrl_add_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "can't add dev %d, ret %d\n", data.dev_id, ret);
		goto fail;
	}

	{
		const struct ublksrv_ctrl_dev_info *info =
			ublksrv_ctrl_get_dev_info(dev);
		data.dev_id = info->dev_id;
	}
	ret = ublksrv_start_daemon(dev);
	if (ret <= 0) {
		fprintf(stderr, "start dev %d daemon failed, ret %d\n",
				data.dev_id, ret);
		goto fail_del_dev;
	}

	dump_buf = ublksrv_tgt_get_dev_data(dev);
	ublksrv_tgt_set_params(dev, dump_buf);

	ret = ublksrv_ctrl_start_dev(dev, ret);
	if (ret < 0) {
		fprintf(stderr, "start dev %d failed, ret %d\n", data.dev_id,
				ret);
		goto fail_stop_daemon;
	}
	ret = ublksrv_ctrl_get_info(dev);
	ublksrv_ctrl_dump(dev, dump_buf);
	ublksrv_ctrl_deinit(dev);
	return 0;

 fail_stop_daemon:
	ublksrv_stop_io_daemon(dev);
 fail_del_dev:
	ublksrv_ctrl_del_dev(dev);
 fail:
	ublksrv_ctrl_deinit(dev);

	return ret;
}

struct tgt_types_name {
	unsigned pos;
	char names[4096 - sizeof(unsigned)];
};

static void collect_tgt_types(unsigned int idx,
		const struct ublksrv_tgt_type *type, void *pdata)
{
	struct tgt_types_name *data = (struct tgt_types_name *)pdata;

	if (idx > 0)
		data->pos += snprintf(data->names + data->pos,
                  sizeof(data->names) - data->pos, "|");
	data->pos += snprintf(data->names + data->pos,
                sizeof(data->names) - data->pos, "%s", type->name);
}

static void show_tgt_add_usage(unsigned int idx,
		const struct ublksrv_tgt_type *type, void *data)
{
	if (type->usage_for_add)
		type->usage_for_add();
}

static void cmd_dev_add_usage(const char *cmd)
{
	struct tgt_types_name data = {
		.pos = 0,
	};

	data.pos += snprintf(data.names + data.pos, sizeof(data.names) - data.pos, "{");
	ublksrv_for_each_tgt_type(collect_tgt_types, &data);
	data.pos += snprintf(data.names + data.pos, sizeof(data.names) - data.pos, "}");

	printf("%s add -t %s\n", cmd, data.names);
	printf("\t-n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH\n");
	printf("\t-u URING_COMP -g NEED_GET_DATA -r USER_RECOVERY\n");
	printf("\t-i USER_RECOVERY_REISSUE -e USER_RECOVERY_FAIL_IO\n");
	printf("\t--debug_mask=0x{DBG_MASK} --unprivileged\n\n");
	printf("\ttarget specific command line:\n");
	ublksrv_for_each_tgt_type(show_tgt_add_usage, NULL);
}

static int __cmd_dev_del(int number, bool log, bool async)
{
	struct ublksrv_ctrl_dev *dev;
	int ret;
	struct ublksrv_dev_data data = {
		.dev_id = number,
		.run_dir = ublksrv_get_pid_dir(),
	};

	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "ublksrv_ctrl_init failed id %d\n", number);
		return -EOPNOTSUPP;
	}

	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		ret = 0;
		if (log)
			fprintf(stderr, "can't get dev info from %d: %d\n", number, ret);
		goto fail;
	}

	ret = ublksrv_ctrl_stop_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "stop dev %d failed\n", number);
		goto fail;
	}

	ret = ublksrv_stop_io_daemon(dev);
	if (ret < 0)
		fprintf(stderr, "stop daemon %d failed\n", number);

	if (async)
		ret = ublksrv_ctrl_del_dev_async(dev);
	else
		ret = ublksrv_ctrl_del_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "delete dev %d failed %d\n", number, ret);
		goto fail;
	}

fail:
	ublksrv_ctrl_deinit(dev);
	return ret;
}

static int cmd_dev_del(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		1,	NULL, 'n' },
		{ "all",		0,	NULL, 'a' },
		{ "async",		0,	NULL,  0  },
		{ NULL }
	};
	int number = -1;
	int opt, ret, i;
	unsigned async = 0;
	int option_index = 0;

	while ((opt = getopt_long(argc, argv, "n:a",
				  longopts, &option_index)) != -1) {
		switch (opt) {
		case 'a':
			break;

		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		case 0:
			if (!strcmp(longopts[option_index].name, "async"))
				async = 1;
		}
	}

	if (number >= 0)
		return __cmd_dev_del(number, true, async);

	for (i = 0; i < MAX_NR_UBLK_DEVS; i++) {
		ret = __cmd_dev_del(i, false, async);
		if (ret == -EOPNOTSUPP)
			return ret;
	}

	return ret;
}

static void cmd_dev_del_usage(const char *cmd)
{
	printf("%s del -n DEV_ID [-a | --all]\n", cmd);
}

static int list_one_dev(int number, bool log, bool verbose)
{
	struct ublksrv_dev_data data = {
		.dev_id = number,
		.run_dir = ublksrv_get_pid_dir(),
	};
	struct ublksrv_ctrl_dev *dev = ublksrv_ctrl_init(&data);
	int ret;

	if (!dev) {
		fprintf(stderr, "ublksrv_ctrl_init failed id %d\n", number);
		return -EOPNOTSUPP;
	}
	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d: %d\n", number, ret);
	} else {
		const char *buf = ublksrv_tgt_get_dev_data(dev);

		if (verbose && buf)
			ublksrv_json_dump(buf);
		else
			ublksrv_ctrl_dump(dev, buf);
	}

	ublksrv_ctrl_deinit(dev);

	return ret;
}

static int cmd_list_dev_info(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		0,	NULL, 'n' },
		{ "verbose",		0,	NULL, 'v' },
		{ NULL }
	};
	int number = -1;
	int opt, i;
	bool verbose = false;

	while ((opt = getopt_long(argc, argv, "n:v",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		case 'v':
			verbose = 1;
			break;
		}
	}

	if (number >= 0)
		return list_one_dev(number, true, verbose);

	for (i = 0; i < MAX_NR_UBLK_DEVS; i++) {
		int ret = list_one_dev(i, false, verbose);

		if (ret == -EOPNOTSUPP)
			return ret;
	}

	return 0;
}

static void cmd_dev_list_usage(const char *cmd)
{
	printf("%s list [-n DEV_ID]\n", cmd);
}

#define const_ilog2(x) (63 - __builtin_clzll(x))

static int cmd_dev_get_features(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {
		.dev_id = -1,
		.run_dir = ublksrv_get_pid_dir(),
	};
	struct ublksrv_ctrl_dev *dev = ublksrv_ctrl_init(&data);
	__u64 features = 0;
	int ret;
	static const char *feat_map[] = {
		[const_ilog2(UBLK_F_SUPPORT_ZERO_COPY)] = "ZERO_COPY",
		[const_ilog2(UBLK_F_URING_CMD_COMP_IN_TASK)] = "COMP_IN_TASK",
		[const_ilog2(UBLK_F_NEED_GET_DATA)] = "GET_DATA",
		[const_ilog2(UBLK_F_USER_RECOVERY)] = "USER_RECOVERY",
		[const_ilog2(UBLK_F_USER_RECOVERY_REISSUE)] = "RECOVERY_REISSUE",
		[const_ilog2(UBLK_F_UNPRIVILEGED_DEV)] = "UNPRIVILEGED_DEV",
		[const_ilog2(UBLK_F_CMD_IOCTL_ENCODE)] = "CMD_IOCTL_ENCODE",
		[const_ilog2(UBLK_F_USER_COPY)] = "USER_COPY",
		[const_ilog2(UBLK_F_ZONED)] = "ZONED",
		[const_ilog2(UBLK_F_USER_RECOVERY_FAIL_IO)] = "RECOVERY_FAIL_IO",
	};

	if (!dev) {
		fprintf(stderr, "ublksrv_ctrl_init failed id\n");
		return -EOPNOTSUPP;
	}

	ret = ublksrv_ctrl_get_features(dev, &features);
	if (!ret) {
		int i;

		printf("ublk_drv features: 0x%llx\n", features);

		for (i = 0; i < sizeof(features) * 8; i++) {
			const char *feat;

			if (!((1ULL << i)  & features))
				continue;
			if (i < sizeof(feat_map) / sizeof(feat_map[0]))
				feat = feat_map[i];
			else
				feat = "unknown";
			printf("\t%-20s: 0x%llx\n", feat, 1ULL << i);
		}
	}

	return ret;
}

static void cmd_dev_get_features_help(const char *cmd)
{
	printf("%s features\n", cmd);
}

static int __cmd_dev_user_recover(int number, bool verbose)
{
	const struct ublksrv_tgt_type *tgt_type;
	struct ublksrv_dev_data data = {
		.dev_id = number,
		.run_dir = ublksrv_get_pid_dir(),
	};
	struct ublksrv_ctrl_dev_info  dev_info;
	struct ublksrv_ctrl_dev *dev;
	struct ublksrv_tgt_base_json tgt_json = {0};
	char *buf = NULL;
	char pid_file[64];
	int ret;
	unsigned elapsed = 0;

	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "ublksrv_ctrl_init failure dev %d\n", number);
		return -EOPNOTSUPP;
	}

	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		fprintf(stderr, "can't get dev info from %d\n", number);
		goto fail;
	}

	while (elapsed < 30000000) {
		unsigned unit = 100000;
		ret = ublksrv_ctrl_start_recovery(dev);
		if (ret < 0 && ret != -EBUSY) {
			fprintf(stderr, "can't start recovery for %d ret %d\n",
					number, ret);
			goto fail;
		}
		if (ret >= 0)
			break;
		usleep(unit);
		elapsed += unit;
	}

	buf = ublksrv_tgt_get_dev_data(dev);
	if (!buf) {
		fprintf(stderr, "get dev %d data failed\n", number);
		ret = -1;
		goto fail;
	}

	ret = ublksrv_json_read_dev_info(buf, &dev_info);
	if (ret < 0) {
		fprintf(stderr, "can't read dev info for %d\n", number);
		goto fail;
	}

	if (dev_info.dev_id != number) {
		fprintf(stderr, "dev id doesn't match read %d for dev %d\n",
				dev_info.dev_id, number);
		goto fail;
	}

	ret = ublksrv_json_read_target_base_info(buf, &tgt_json);
	if (ret < 0) {
		fprintf(stderr, "can't read dev info for %d\n", number);
		goto fail;
	}

	snprintf(pid_file, 64, "%s/%d.pid", data.run_dir, number);
	ret = unlink(pid_file);
	if (ret < 0) {
		fprintf(stderr, "can't delete old pid_file for %d, error:%s\n",
				number, strerror(errno));
		goto fail;
	}

	tgt_type = ublksrv_find_tgt_type(tgt_json.name);
	if (!tgt_type) {
		fprintf(stderr, "can't find target type %s\n", tgt_json.name);
		goto fail;
	}

	ublksrv_ctrl_prep_recovery(dev, tgt_json.name, tgt_type, buf);

	ret = ublksrv_start_daemon(dev);
	if (ret < 0) {
		fprintf(stderr, "start daemon %d failed\n", number);
		goto fail;
	}

	ret = ublksrv_ctrl_end_recovery(dev, ret);
	if (ret < 0) {
		fprintf(stderr, "end recovery for %d failed\n", number);
		goto fail;
	}

	ret = ublksrv_ctrl_get_info(dev);
	if (ret < 0) {
		fprintf(stderr, "can't get dev info from %d\n", number);
		goto fail;
	}

	if (verbose) {
		free(buf);
		buf = ublksrv_tgt_get_dev_data(dev);
		ublksrv_ctrl_dump(dev, buf);
	}

 fail:
	free(buf);
	ublksrv_ctrl_deinit(dev);
	return ret;
}

static int cmd_dev_user_recover(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		0,	NULL, 'n' },
		{ "verbose",	0,	NULL, 'v' },
		{ NULL }
	};
	int number = -1;
	int opt;
	bool verbose = false;

	while ((opt = getopt_long(argc, argv, "n:v",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		case 'v':
			verbose = true;
			break;
		}
	}

	return __cmd_dev_user_recover(number, verbose);
}

static void cmd_dev_recover_usage(const char *cmd)
{
	printf("%s recover [-n DEV_ID]\n", cmd);
}

static void cmd_usage(const char *cmd)
{
	cmd_dev_add_usage(cmd);
	cmd_dev_del_usage(cmd);
	cmd_dev_list_usage(cmd);
	cmd_dev_recover_usage(cmd);
	cmd_dev_get_features_help(cmd);

	printf("%s -v [--version]\n", cmd);
	printf("%s -h [--help]\n", cmd);
}

int main(int argc, char *argv[])
{
	const char *prog_name = "ublk";

	char *cmd;
	int ret;
	char exe[PATH_MAX];

	strncpy(exe, argv[0], PATH_MAX - 1);

	setvbuf(stdout, NULL, _IOLBF, 0);

	cmd = pop_cmd(&argc, argv);
	if (cmd == NULL) {
		printf("%s: missing command\n", argv[0]);
		cmd_usage(prog_name);
		return EXIT_FAILURE;
	}

	if (!strcmp(cmd, "add"))
		ret = cmd_dev_add(argc, argv);
	else if (!strcmp(cmd, "del"))
		ret = cmd_dev_del(argc, argv);
	else if (!strcmp(cmd, "list"))
		ret = cmd_list_dev_info(argc, argv);
	else if (!strcmp(cmd, "recover"))
		ret = cmd_dev_user_recover(argc, argv);
	else if (!strcmp(cmd, "features"))
		ret = cmd_dev_get_features(argc, argv);
	else if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
		cmd_usage(prog_name);
		ret = EXIT_SUCCESS;
	} else if (!strcmp(cmd, "-v") || !strcmp(cmd, "--version")) {
		fprintf(stdout, "%s\n", PACKAGE_STRING);
		ret = EXIT_SUCCESS;
	} else {
		fprintf(stderr, "unknown command: %s\n", cmd);
		cmd_usage(prog_name);
		ret = EXIT_FAILURE;
	}

	ublk_ctrl_dbg(UBLK_DBG_CTRL_CMD, "cmd %s: result %d\n", cmd, ret);

	return ret;
}
