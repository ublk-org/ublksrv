// SPDX-License-Identifier: MIT or GPL-2.0-only

#include "config.h"
#include "ublksrv_tgt.h"
#include <sys/eventfd.h>

static int list_one_dev(int number, bool log, bool verbose);

static int ublksrv_execve_helper(const char *op, const char *type, int argc, char *argv[])
{
	char *cmd, *fp, *ldlp, **nargv, *evtfd_str;
	char *nenv[] = { NULL, NULL };
	char full_path[256];
	ssize_t fp_len;
	int daemon = strcmp(op, "help");
	int res, i, evtfd = -1;

	asprintf(&cmd, "ublk.%s", type);

	/*
	 * Create full path to the ublk.<type> binary. It must be in the
	 * same directory as the main ublk binary itself.
	 */
	memset(full_path, 0, sizeof(full_path));
	fp_len = readlink("/proc/self/exe", full_path, sizeof(full_path));
	if (fp_len < 0 || fp_len >= sizeof(full_path))
		return -EINVAL;
	asprintf(&fp, "%s.%s", full_path, type);

	nargv = (char **)calloc(argc + 4, sizeof(char *));
	if (!nargv)
		return -ENOMEM;
	nargv[0] = cmd;
	nargv[1] = (char *)op;
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--eventfd"))
			return -EINVAL;
		nargv[i + 1] = argv[i];
	}

	if (daemon) {
		evtfd = eventfd(0, 0);
		if (evtfd < 0) {
			fprintf(stderr, "Failed to create eventfd %s\n", strerror(errno));
			return errno;
		}
		asprintf(&evtfd_str, "%d", evtfd);
		nargv[argc + 1] = strdup("--eventfd");
		nargv[argc + 2] = evtfd_str;
	}

	/*
	 * We need to copy LD_LIBRARY_PATH if we run ublk from the build directory
	 * as the binary .libs/ublk.<type> might otherwise not find the locally
	 * built library.
	 * In this case libtool will set the LD_LIBRARY_PATH env for us before it
	 * runs the main .libs/ublk binary.
	 */
	if (getenv("LD_LIBRARY_PATH")) {
		asprintf(&ldlp, "LD_LIBRARY_PATH=%s", getenv("LD_LIBRARY_PATH"));
		nenv[0] = ldlp;
	}

	if (!daemon) {
exec:
		if (execve(fp, nargv, nenv) < 0) {
			fprintf(stderr, "Failed to execve() %s. %s\n", fp, strerror(errno));
			if (evtfd >= 0)
				ublksrv_tgt_send_dev_event(evtfd, -1);
			return errno;
		}
	}

	setsid();
	res = fork();
	if (res == 0)
		goto exec;
	if (res > 0) {
		uint64_t id;

		res = read(evtfd, &id, sizeof(id));
		close(evtfd);

		if (res == sizeof(id))
			return list_one_dev(id - 1, false, false);
		return res;
	}
	return res;
}

static void cmd_dev_add_usage(const char *cmd)
{
	printf("%s add -t TYPE\n", cmd);
	ublksrv_print_std_opts();
	printf("\tFor type specific options, run:\n");
	printf("\t\tublk help -t <type>\n");
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

	printf("%s help -t <target>\n", cmd);
	printf("%s -v [--version]\n", cmd);
	printf("%s -h [--help]\n", cmd);
}

static int cmd_dev_add(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {0};

	ublksrv_parse_std_opts(&data, NULL, argc, argv);
  
	if (data.tgt_type == NULL) {
		fprintf(stderr, "no dev type specified\n");
		return -EINVAL;
	}
	return ublksrv_execve_helper("add", data.tgt_type, argc, argv);
}

static int cmd_dev_help(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {0};

	ublksrv_parse_std_opts(&data, NULL, argc, argv);
  
	if (data.tgt_type == NULL) {
		cmd_usage("ublk");
		return EXIT_SUCCESS;
	}

	return ublksrv_execve_helper("help", data.tgt_type, argc, argv);
}

static int cmd_dev_recover(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {0};
	struct ublksrv_ctrl_dev *dev;
	char tgt_type[32] = {0};
	char *buf = NULL;
	int ret;

	ublksrv_parse_std_opts(&data, NULL, argc, argv);
  
	if (data.dev_id < 0) {
		fprintf(stderr, "wrong dev_id provided for recover\n");
		return EXIT_FAILURE;
	}
	dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "initialize ctrl dev %d failed\n", data.dev_id);
		return EXIT_FAILURE;
	}
	buf = ublksrv_tgt_get_dev_data(dev);
	if (!buf) {
		fprintf(stderr, "get dev %d data failed\n", data.dev_id);
		return EXIT_FAILURE;
	}

	ret = ublksrv_json_read_target_str_info(buf, 32, "name", tgt_type);
	if (ret < 0) {
		fprintf(stderr, "can't get target type for %d\n", data.dev_id);
		return EXIT_FAILURE;
	}

	free(buf);

	return ublksrv_execve_helper("recover", tgt_type, argc, argv);
}

int main(int argc, char *argv[])
{
	const char *prog_name = "ublk";
	char *cmd;
	int ret;
	char exe[PATH_MAX];

	strncpy(exe, argv[0], PATH_MAX - 1);

	setvbuf(stdout, NULL, _IOLBF, 0);

	cmd = ublksrv_pop_cmd(&argc, argv);
	if (cmd == NULL) {
		printf("%s: missing command\n", argv[0]);
		cmd_usage(prog_name);
		return EXIT_FAILURE;
	}

	if (!strcmp(cmd, "add"))
		ret = cmd_dev_add(argc, argv);
	else if (!strcmp(cmd, "del"))
		ret = cmd_dev_del(argc, argv);
	else if (!strcmp(cmd, "help"))
		ret = cmd_dev_help(argc, argv);
	else if (!strcmp(cmd, "list"))
		ret = cmd_list_dev_info(argc, argv);
	else if (!strcmp(cmd, "recover"))
		ret = cmd_dev_recover(argc, argv);
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
