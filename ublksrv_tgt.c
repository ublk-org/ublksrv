#include "ublksrv.h"

/********************cmd handling************************/
static char *full_cmd;

static char *pop_cmd(int *argc, char *argv[])
{
	char *cmd = argv[1];
	if (*argc < 2) {
		printf("%s: missing command\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	memmove(&argv[1], &argv[2], *argc * sizeof(argv[0]));
	(*argc)--;

	full_cmd = mprintf("%s %s", full_cmd, cmd);
	return cmd;
}

static int ublksrv_start_daemon(struct ublksrv_ctrl_dev *ctrl_dev)
{
	int cnt = 0, daemon_pid;
	int ret;

	if (ublksrv_get_affinity(ctrl_dev) < 0)
		return -1;

	switch (fork()) {
	case -1:
		return -1;
	case 0:
		ublksrv_start_io_daemon(ctrl_dev);
		break;
	}

	/* wait until daemon is started, or timeout after 3 seconds */
	do {
		daemon_pid = ublksrv_get_io_daemon_pid(ctrl_dev);
		if (daemon_pid < 0) {
			usleep(100000);
			cnt++;
		}
	} while (daemon_pid < 0 && cnt < 30);

	return daemon_pid;
}

static int cmd_dev_add(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "type",		1,	NULL, 't' },
		{ "number",		1,	NULL, 'n' },
		{ "queues",		1,	NULL, 'q' },
		{ "depth",		1,	NULL, 'd' },
		{ "zero_copy",		1,	NULL, 'z' },
		{ NULL }
	};
	struct ublksrv_dev_data data = {0};
	struct ublksrv_ctrl_dev *dev;
	char *type = NULL;
	int opt, ret, zcopy = 0;
	int daemon_pid;

	data.queue_depth = DEF_QD;
	data.nr_hw_queues = DEF_NR_HW_QUEUES;
	data.dev_id = -1;
	data.block_size = 512;
	data.flags[0] |= (1 << UBLK_F_HAS_IO_DAEMON);

	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:z",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			data.dev_id = strtol(optarg, NULL, 10);
			break;
		case 't':
			data.tgt_type = optarg;
			break;
		case 'z':
			data.flags[0] |= 1ULL << UBLK_F_SUPPORT_ZERO_COPY;
			data.block_size = 4096;
			break;
		case 'q':
			data.nr_hw_queues = strtol(optarg, NULL, 10);
			break;
		case 'd':
			data.queue_depth = strtol(optarg, NULL, 10);
			break;
		}
	}
	data.rq_max_blocks = DEF_BUF_SIZE / data.block_size;
	if (data.nr_hw_queues > MAX_NR_HW_QUEUES)
		data.nr_hw_queues = MAX_NR_HW_QUEUES;
	if (data.queue_depth > MAX_QD)
		data.queue_depth = MAX_QD;
	//optind = 0;	/* so that tgt code can parse their arguments */
	data.tgt_argc = argc;
	data.tgt_argv = argv;
	dev = ublksrv_dev_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		return -ENODEV;
	}

	ret = ublksrv_add_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "can't add dev %d, ret %d\n", data.dev_id, ret);
		goto fail;
	}

	ret = ublksrv_start_daemon(dev);
	if (ret <= 0)
		goto fail_del_dev;

	ret = ublksrv_start_dev(dev, ret);
	if (ret < 0) {
		fprintf(stderr, "start dev failed %d, ret %d\n", data.dev_id,
				ret);
		goto fail_stop_daemon;
	}
	ret = ublksrv_get_dev_info(dev);
	ublksrv_dump(dev);
	ublksrv_dev_deinit(dev);
	return 0;

 fail_stop_daemon:
	ublksrv_stop_io_daemon(dev);
 fail_del_dev:
	ublksrv_del_dev(dev);
 fail:
	ublksrv_dev_deinit(dev);

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
				4096 - data->pos, "|");
	data->pos += snprintf(data->names + data->pos, 4096 - data->pos,
			"%s", type->name);
}

static void show_tgt_add_usage(unsigned int idx,
		const struct ublksrv_tgt_type *type, void *data)
{
	if (type->usage_for_add)
		type->usage_for_add();
}

static void cmd_dev_add_usage(char *cmd)
{
	struct tgt_types_name data = {
		.pos = 0,
	};

	data.pos += snprintf(data.names + data.pos, 4096 - data.pos, "{");
	ublksrv_for_each_tgt_type(collect_tgt_types, &data);
	data.pos += snprintf(data.names + data.pos, 4096 - data.pos, "}");

	printf("%s add -t %s -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH\n", cmd, data.names);
	ublksrv_for_each_tgt_type(show_tgt_add_usage, NULL);
}

static int __cmd_dev_del(int number, bool log)
{
	struct ublksrv_ctrl_dev *dev;
	int ret;
	struct ublksrv_dev_data data = {
		.dev_id = number,
	};

	dev = ublksrv_dev_init(&data);

	ret = ublksrv_get_dev_info(dev);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d\n", number);
		goto fail;
	}

	ret = ublksrv_stop_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "stop dev %d failed\n", number);
		goto fail;
	}

	ret = ublksrv_stop_io_daemon(dev);
	if (ret < 0)
		fprintf(stderr, "stop daemon %d failed\n", number);

	ret = ublksrv_del_dev(dev);
	if (ret < 0) {
		fprintf(stderr, "delete dev %d failed\n", number);
		goto fail;
	}

fail:
	ublksrv_dev_deinit(dev);
	return ret;
}

static int cmd_dev_del(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		1,	NULL, 'n' },
		{ "all",		0,	NULL, 'a' },
		{ NULL }
	};
	struct ublksrv_ctrl_dev *dev;
	int number = -1;
	int opt, ret, i;

	while ((opt = getopt_long(argc, argv, "n:a",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			break;

		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		}
	}

	if (number >= 0)
		return __cmd_dev_del(number, true);

	for (i = 0; i < MAX_NR_UBLK_DEVS; i++)
		ret = __cmd_dev_del(i, false);

	return ret;
}

static void cmd_dev_del_usage(char *cmd)
{
	printf("%s del -n DEV_ID [-a | --all]\n", cmd);
}

static int list_one_dev(int number, bool log)
{
	struct ublksrv_dev_data data = {
		.dev_id = number,
	};
	struct ublksrv_ctrl_dev *dev = ublksrv_dev_init(&data);
	int ret;

	ret = ublksrv_get_dev_info(dev);
	if (ret < 0) {
		if (log)
			fprintf(stderr, "can't get dev info from %d\n", number);
	} else
		ublksrv_dump(dev);

	ublksrv_dev_deinit(dev);

	return ret;
}

static int cmd_list_dev_info(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		0,	NULL, 'n' },
		{ NULL }
	};
	struct ublksrv_ctrl_dev *dev;
	int number = -1;
	int opt, ret, i;

	while ((opt = getopt_long(argc, argv, "n:",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		}
	}

	if (number >= 0)
		return list_one_dev(number, true);

	for (i = 0; i < MAX_NR_UBLK_DEVS; i++)
		list_one_dev(i, false);

	return ret;
}

static void cmd_dev_list_usage(char *cmd)
{
	printf("%s list [-n DEV_ID]\n", cmd);
}

int main(int argc, char *argv[])
{
	char *cmd;
	int ret;
	char exe[256];

	full_cmd = argv[0];
	strncpy(exe, full_cmd, 256);

	setvbuf(stdout, NULL, _IOLBF, 0);

	cmd = pop_cmd(&argc, argv);

	if (!strcmp(cmd, "add"))
		ret = cmd_dev_add(argc, argv);
	if (!strcmp(cmd, "del"))
		ret = cmd_dev_del(argc, argv);
	if (!strcmp(cmd, "list"))
		ret = cmd_list_dev_info(argc, argv);

	if (!strcmp(cmd, "help")) {
		cmd_dev_add_usage(exe);
		cmd_dev_del_usage(exe);
		cmd_dev_list_usage(exe);
	}

	ublksrv_printf(stdout, "cmd %s: result %d\n", cmd, ret);

	return ret;
}
