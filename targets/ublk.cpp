// SPDX-License-Identifier: MIT or GPL-2.0-only

#include "config.h"
#include "ublksrv_tgt.h"
#include <filesystem>
#include <sys/eventfd.h>

static int list_one_dev(int number, bool log, bool verbose);

template<typename cb_t>
static void for_each_dev(cb_t && cb)
{
	for (auto & entry : std::filesystem::directory_iterator("/sys/class/ublk-char")) {
		unsigned dev_id;
		if (sscanf(entry.path().filename().c_str(), "ublkc%u", &dev_id) == 1)
			cb(dev_id);
	}
}

/*
 * returns 0 on success and -errno on failure
 */
static int ublksrv_execv_helper(const char *type, int argc, char *argv[])
{
	char *cmd, *fp, **nargv, *evtfd_str;
	char full_path[256];
	ssize_t fp_len;
	int daemon = strcmp(argv[1], "help");
	int res, i;
	int pfd[2] = { -1, -1};

	asprintf(&cmd, "ublk.%s", type);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--eventfd"))
			return -EINVAL;
	}

	/*
	 * Create full path to the ublk.<type> binary. It must be in the
	 * same directory as the main ublk binary itself.
	 */
	memset(full_path, 0, sizeof(full_path));
	fp_len = readlink("/proc/self/exe", full_path, sizeof(full_path));
	if (fp_len < 0 || (size_t)fp_len >= sizeof(full_path))
		return -EINVAL;
	asprintf(&fp, "%s.%s", full_path, type);

	nargv = (char **)calloc(argc + 3, sizeof(char *));
	if (!nargv)
		return -ENOMEM;
	memcpy(&nargv[1], &argv[1], (argc - 1) * sizeof(char *));
	nargv[0] = cmd;

	if (daemon) {
		if (pipe(pfd)) {
			fprintf(stderr, "Failed to create pipe %s\n", strerror(errno));
			return -errno;
		}
		asprintf(&evtfd_str, "%d", pfd[1]);
		nargv[argc] = strdup("--eventfd");
		nargv[argc + 1] = evtfd_str;
	}

	if (!daemon) {
exec:
		close(pfd[0]);
		execv(fp, nargv);

		/* only reach here is execve failed */
		fprintf(stderr, "Failed to execve() %s. %s\n", fp, strerror(errno));
		return -errno;
	}

	setsid();
	res = fork();
	if (res == 0) {
		/* prepare for detaching */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		goto exec;
	}
	if (res > 0) {
		uint64_t id;

		close(pfd[1]);
		res = read(pfd[0], &id, sizeof(id));
		close(pfd[0]);

		if (res == 0)
			res = -EINVAL;
		if (res == sizeof(id))
			return list_one_dev(id - 1, false, false);
		return res;
	}
	if (res == -1)
		res = -errno;
	return res;
}

static int ublksrv_stop_io_daemon(const struct ublksrv_ctrl_dev *ctrl_dev)
{
	int daemon_pid, cnt = 0;

	/* wait until daemon is exited, or timeout after 3 seconds */
	do {
		daemon_pid = ublksrv_get_io_daemon_pid(ctrl_dev, false);
		if (daemon_pid > 0) {
			usleep(100000);
			cnt++;
		}
	} while (daemon_pid > 0 && cnt < 30);

	if (daemon_pid > 0)
		return -1;

	return 0;
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
	if (ret < 0 && ret != -ENODEV) {
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
	int opt, ret = 0;
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

	for_each_dev([&](unsigned dev_id) {
		if (ret != -EOPNOTSUPP)
			ret = __cmd_dev_del(dev_id, false, async);
	});

	return ret;
}

static int cmd_dev_set_affinity(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		1,	NULL, 'n' },
		{ "queue",		1,	NULL, 'q' },
		{ "cpuset",		1,	NULL, 0},
		{ NULL }
	};
	int number = -1, qid = -1;
	int opt, ret;
	int option_index = 0;
	const char *cpuset = NULL;
	cpu_set_t *set = NULL;

	while ((opt = getopt_long(argc, argv, "n:q:",
				  longopts, &option_index)) != -1) {
		switch (opt) {
		case 'n':
			number = strtol(optarg, NULL, 10);
			break;
		case 'q':
			qid = strtol(optarg, NULL, 10);
			break;
		case 0:
			if (!strcmp(longopts[option_index].name, "cpuset")) {
				cpuset = optarg;
			}
		}
	}

	if (number < 0) {
		fprintf(stderr, "Must specify -n / --number\n");
		return -EINVAL;
	}
	if (qid < 0) {
		fprintf(stderr, "Must specify -q / --queue\n");
		return -EINVAL;
	}
	if (!cpuset) {
		fprintf(stderr, "Must specify --cpuset\n");
		return -EINVAL;
	}
	/*
	 * The cpuset string for set_affinity is a single set
	 */
	set = ublk_make_cpuset(1, cpuset);
  
	ret = ublk_queue_set_affinity(number, qid, set);
	free(set);
	return ret;
}

static int list_one_dev(int number, bool log, bool verbose)
{
	struct ublksrv_dev_data data = {
		.dev_id = number,
		.run_dir = ublksrv_get_pid_dir(),
	};
	struct ublksrv_ctrl_dev *dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		return -EOPNOTSUPP;
	}
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
	int opt, ret = 0;
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

	for_each_dev([&](unsigned dev_id) {
		if (ret != -EOPNOTSUPP)
			ret = list_one_dev(dev_id, false, verbose);
	});

	return 0;
}

#define const_ilog2(x) (63 - __builtin_clzll(x))

static int cmd_dev_get_features(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {
		.dev_id = -1,
		.run_dir = ublksrv_get_pid_dir(),
	};
	struct ublksrv_ctrl_dev *dev = ublksrv_ctrl_init(&data);
	if (!dev) {
		fprintf(stderr, "can't init dev %d\n", data.dev_id);
		return -EOPNOTSUPP;
	}
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
		[const_ilog2(UBLK_F_UPDATE_SIZE)] = "UPDATE_SIZE",
		[const_ilog2(UBLK_F_AUTO_BUF_REG)] = "AUTO_ZC",
	};

	if (!dev) {
		fprintf(stderr, "ublksrv_ctrl_init failed id\n");
		return -EOPNOTSUPP;
	}

	ret = ublksrv_ctrl_get_features(dev, &features);
	if (!ret) {
		int i;

		printf("ublk_drv features: 0x%llx\n", features);

		for (i = 0; (size_t)i < sizeof(features) * 8; i++) {
			const char *feat;

			if (!((1ULL << i)  & features))
				continue;
			if ((size_t)i < sizeof(feat_map) / sizeof(feat_map[0]))
				feat = feat_map[i];
			else
				feat = "unknown";
			printf("\t%-20s: 0x%llx\n", feat, 1ULL << i);
		}
	}

	return ret;
}

static void args_parse_number_type(struct ublksrv_dev_data *data, int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "number",		1,	NULL, 'n' },
		{ "type",		1,	NULL, 't' },
		{ NULL }
	};
	int opt, option_index = 0;

	while ((opt = getopt_long(argc, argv, "-:n:t:",
				  longopts, &option_index)) != -1) {
		switch (opt) {
		case 'n':
			data->dev_id = strtol(optarg, NULL, 10);
			break;
		case 't':
			data->tgt_type = optarg;
			break;
		}
	}
}

static int cmd_dev_add(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {0};

	args_parse_number_type(&data, argc, argv);
  
	if (data.tgt_type == NULL) {
		fprintf(stderr, "no dev type specified\n");
		return -EINVAL;
	}
	return ublksrv_execv_helper(data.tgt_type, argc, argv);
}

static int cmd_dev_help(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {0};

	args_parse_number_type(&data, argc, argv);

	if (data.tgt_type == NULL) {
		char *av[2] = { (char *)"ublk", (char *)"help"};

		ublksrv_main(NULL, 2, av);
		return EXIT_SUCCESS;
	}

	return ublksrv_execv_helper(data.tgt_type, argc, argv);
}

static int cmd_dev_recover(int argc, char *argv[])
{
	struct ublksrv_ctrl_dev *dev;
	char tgt_type[32] = {0};
	char *buf = NULL;
	struct ublksrv_dev_data data = {
	  .dev_id = -1,
	  .run_dir = ublksrv_get_pid_dir(),
	};
	int ret;

	args_parse_number_type(&data, argc, argv);

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

	return ublksrv_execv_helper(tgt_type, argc, argv);
}

int main(int argc, char *argv[])
{
	char *cmd;
	int ret;

	setvbuf(stdout, NULL, _IOLBF, 0);

	if (argc < 2) {
		printf("%s: missing command\n", argv[0]);
		cmd_dev_help(argc, argv);
		return EXIT_FAILURE;
	}
	cmd = argv[1];

	if (!strcmp(cmd, "add"))
		ret = cmd_dev_add(argc, argv);
	else if (!strcmp(cmd, "del"))
		ret = cmd_dev_del(argc, argv);
	else if (!strcmp(cmd, "set_affinity"))
		ret = cmd_dev_set_affinity(argc, argv);
	else if (!strcmp(cmd, "list"))
		ret = cmd_list_dev_info(argc, argv);
	else if (!strcmp(cmd, "recover"))
		ret = cmd_dev_recover(argc, argv);
	else if (!strcmp(cmd, "features"))
		ret = cmd_dev_get_features(argc, argv);
	else if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
		ret = cmd_dev_help(argc, argv);
	} else if (!strcmp(cmd, "-v") || !strcmp(cmd, "--version")) {
		fprintf(stdout, "%s\n", PACKAGE_STRING);
		ret = EXIT_SUCCESS;
	} else {
		fprintf(stderr, "unknown command: %s\n", cmd);
		cmd_dev_help(argc, argv);
		ret = EXIT_FAILURE;
	}

	ublk_ctrl_dbg(UBLK_DBG_CTRL_CMD, "cmd %s: result %d\n", cmd, ret);

	return ret;
}
