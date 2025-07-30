// SPDX-License-Identifier: MIT or LGPL-2.1-only

#include <config.h>

#include <iostream>
#include "nlohmann/json.hpp"
#include "ublksrv_priv.h"

/* json device data is stored at this offset of pid file */
#define JSON_OFFSET   32

#define UBLKSRV_PID_DIR  "/run/ublksrvd"

#define  parse_json(j, jbuf)	\
	try {						\
		j = json::parse(std::string(jbuf));	\
	} catch (json::parse_error& ex) {		\
		std::cerr << "parse error at byte " << ex.byte << std::endl; \
		return -EINVAL;				\
	}						\

using json = nlohmann::json;

static inline int dump_json_to_buf(json &j, char *jbuf, int len)
{
	std::string s;
	int j_len;

	s = j.dump();
	j_len = s.length();
	if (j_len < len) {
		strcpy(jbuf, s.c_str());
		return j_len;
	}
	return -EINVAL;
}

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(ublksrv_ctrl_dev_info,
	nr_hw_queues,
	queue_depth,
	state,
	pad0,
	max_io_buf_bytes,
	dev_id,
	ublksrv_pid,
	pad1,
	flags,
	ublksrv_flags,
	owner_uid,
	owner_gid,
	reserved1,
	reserved2)


/*
 * build one json string with dev_info head, and result is stored
 * in 'buf'.
 */
int ublksrv_json_write_dev_info(const struct ublksrv_ctrl_dev *cdev,
		char *jbuf, int len)
{
	const struct ublksrv_ctrl_dev_info *info = &cdev->dev_info;
	json j_info = *info;
	json j;

	j["dev_info"] = j_info;

	return dump_json_to_buf(j, jbuf, len);
}

/* Fill 'info' from the json string pointed by 'json_buf' */
int ublksrv_json_read_dev_info(const char *jbuf,
		struct ublksrv_ctrl_dev_info *info)
{
	json j;

	parse_json(j, jbuf);

	if (!j.contains("dev_info"))
		return -EINVAL;

	auto sj = j["dev_info"];

	*info = sj.get<struct ublksrv_ctrl_dev_info>();

	return 0;
}

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(struct ublk_param_basic,
	attrs,
	logical_bs_shift,
	physical_bs_shift,
	io_opt_shift,
	io_min_shift,
	max_sectors,
	chunk_sectors,
	dev_sectors,
	virt_boundary_mask)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(struct ublk_param_discard,
	discard_alignment,
	discard_granularity,
	max_discard_sectors,
	max_write_zeroes_sectors,
	max_discard_segments,
	reserved0)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(struct ublk_param_devt,
	char_major,
	char_minor,
	disk_major,
	disk_minor)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(struct ublk_param_zoned,
	max_open_zones,
	max_active_zones,
	max_zone_append_sectors,
	reserved,
	reserved2,
	reserved3)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(struct ublk_param_dma_align,
	alignment,
	pad)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(struct ublk_param_segment,
	seg_boundary_mask,
	max_segment_size,
	max_segments,
	pad)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(struct ublk_params,
	len, types, basic, discard, devt, zoned, dma, seg)

struct ublksrv_tgt_jbuf *ublksrv_tgt_get_jbuf(const struct ublksrv_ctrl_dev *cdev)
{
	struct ublksrv_ctrl_data *data = ublksrv_get_ctrl_data(cdev);

	return &data->jbuf;
}

int ublk_json_write_dev_info(const struct ublksrv_ctrl_dev *cdev)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_dev_info(cdev,
				j->jbuf, j->jbuf_size);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublksrv_json_write_params(const struct ublk_params *p,
		char *jbuf, int len)
{
	json j;
	std::string s;

	parse_json(j, jbuf);

	j["params"] = *p;

	return dump_json_to_buf(j, jbuf, len);
}

int ublk_json_write_params(const struct ublksrv_ctrl_dev *cdev,
		const struct ublk_params *p)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_params(p, j->jbuf, j->jbuf_size);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublksrv_json_read_params(struct ublk_params *p,
		const char *jbuf)
{
	json j, sj;
	std::string s;

	parse_json(j, jbuf);

	if (!j.contains("params"))
		return -EINVAL;

	*p = j["params"];

	return 0;
}

int ublk_json_read_params(struct ublk_params *p,
			  const struct ublksrv_ctrl_dev *cdev)
{
	int ret;

	pthread_mutex_lock(&cdev->data->jbuf.lock);
	ret = ublksrv_json_read_params(p, cdev->data->jbuf.jbuf);
	pthread_mutex_unlock(&cdev->data->jbuf.lock);

	return ret;
}
  
int ublksrv_json_dump_params(const char *jbuf)
{
	json j;
	std::string s;

	parse_json(j, jbuf);

	if (!j.contains("params"))
		return -EINVAL;

	std::cout << std::setw(4) << j["params"] << '\n';

	return 0;
}

int ublksrv_json_read_target_str_info(const char *jbuf, int len,
		const char *name, char *val)
{
	json j;
	std::string s;

	parse_json(j, jbuf);

	if (!j.contains("target"))
		return -EINVAL;

	auto tj = j["target"];

	if (!tj.contains(name))
		return -EINVAL;

	std::string str = tj[std::string(name)];
	if (str.length() < (unsigned)len) {
		strcpy(val, str.c_str());
		return 0;
	}

	return -EINVAL;
}

int ublk_json_read_target_str_info(const struct ublksrv_ctrl_dev *cdev,
				   const char *name, char *val)
{
	struct ublksrv_tgt_jbuf *j = &cdev->data->jbuf;
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	ret = ublksrv_json_read_target_str_info(j->jbuf, j->jbuf_size, name, val);
	pthread_mutex_unlock(&j->lock);

	return ret;
}
    
  
int ublksrv_json_read_target_ulong_info(const char *jbuf,
		const char *name, unsigned long *val)
{
	json j;
	std::string s;

	parse_json(j, jbuf);

	if (!j.contains("target"))
		return -EINVAL;

	auto tj = j["target"];

	if (!tj.contains(name))
		return -EINVAL;

	*val = tj[std::string(name)];

	return 0;
}

int ublk_json_read_target_ulong_info(const struct ublksrv_ctrl_dev *cdev,
		const char *name, unsigned long *val)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	pthread_mutex_lock(&j->lock);
	ret = ublksrv_json_read_target_ulong_info(j->jbuf, name, val);
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublksrv_json_write_target_str_info(char *jbuf, int len,
		const char *name, const char *val)
{
	json j;
	std::string s;

	parse_json(j, jbuf);

	j["target"][std::string(name)] = val;;

	return dump_json_to_buf(j, jbuf, len);
}

int ublk_json_write_tgt_str(const struct ublksrv_ctrl_dev *cdev, const char *name, const char *val)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		if (val)
			ret = ublksrv_json_write_target_str_info(j->jbuf,
					j->jbuf_size, name, val);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublksrv_json_write_target_long_info(char *jbuf, int len,
		const char *name, long val)
{
	json j;
	std::string s;

	parse_json(j, jbuf);

	j["target"][std::string(name)] = val;;

	return dump_json_to_buf(j, jbuf, len);
}

int ublk_json_write_tgt_long(const struct ublksrv_ctrl_dev *cdev, const char *name, long val)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_target_long_info(j->jbuf, j->jbuf_size,
				name, val);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublksrv_json_write_target_ulong_info(char *jbuf, int len, const char *name,
		unsigned long val)
{
	json j;
	std::string s;

	parse_json(j, jbuf);

	j["target"][std::string(name)] = val;;

	return dump_json_to_buf(j, jbuf, len);
}

int ublk_json_write_tgt_ulong(const struct ublksrv_ctrl_dev *cdev, const char *name, unsigned long val)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_target_ulong_info(j->jbuf, j->jbuf_size,
				name, val);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublksrv_json_write_target_base_info(char *jbuf, int len,
		const struct ublksrv_tgt_base_json *tgt)
{
	json j;
	std::string s;

	parse_json(j, jbuf);

	j["target"]["name"] = tgt->name;
	j["target"]["type"] = tgt->type;
	j["target"]["dev_size"] = tgt->dev_size;

	return dump_json_to_buf(j, jbuf, len);
}

int ublk_json_write_target_base(const struct ublksrv_ctrl_dev *cdev,
		const struct ublksrv_tgt_base_json *tgt)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_target_base_info(j->jbuf, j->jbuf_size, tgt);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;

}

int ublksrv_json_read_target_base_info(const char *jbuf,
		struct ublksrv_tgt_base_json *tgt)
{
	json j;
	std::string s;

	parse_json(j, jbuf);

	if (!j.contains("target"))
		return -EINVAL;

	auto tj = j["target"];

	if (!tj.contains("name") || !tj.contains("type") ||
			!tj.contains("dev_size"))
		return -EINVAL;

	std::string str = tj["name"];
	if (str.length() >= UBLKSRV_TGT_NAME_MAX_LEN)
		return -EINVAL;
	strcpy(tgt->name, str.c_str());
	tgt->type = tj["type"];
	tgt->dev_size = tj["dev_size"];

	return 0;
}

int ublksrv_json_read_target_info(const char *jbuf, char *tgt_buf, int len)
{
	json j;

	parse_json(j, jbuf);

	if (j.contains("target")) {
		auto tj = j["target"];

		return dump_json_to_buf(tj, tgt_buf, len);
	}
	return 0;
}

int ublksrv_json_write_queue_info(const struct ublksrv_ctrl_dev *cdev,
		char *jbuf, int len, int qid, int ubq_daemon_tid)
{
	json j;
	std::string s;
	char name[16];
	char cpus[4096];
	cpu_set_t *cpuset = ublksrv_get_queue_affinity(cdev, qid);

	parse_json(j, jbuf);

	snprintf(name, 16, "%d", qid);

	ublksrv_build_cpu_str(cpus, 512, cpuset);

	j["queues"][std::string(name)]["qid"] = qid;
	j["queues"][std::string(name)]["tid"] = ubq_daemon_tid;
	j["queues"][std::string(name)]["affinity"] = cpus;

	return dump_json_to_buf(j, jbuf, len);
}

int ublk_json_write_queue_info(const struct ublksrv_ctrl_dev *cdev,
		unsigned int qid, int tid)
{
	struct ublksrv_tgt_jbuf *j = ublksrv_tgt_get_jbuf(cdev);
	int ret = 0;

	if (!j)
		return -EINVAL;

	pthread_mutex_lock(&j->lock);
	do {
		ret = ublksrv_json_write_queue_info(cdev, j->jbuf, j->jbuf_size,
				qid, tid);
	} while (ret < 0 && tgt_realloc_jbuf(j));
	pthread_mutex_unlock(&j->lock);

	return ret;
}

int ublksrv_json_read_queue_info(const char *jbuf, int qid, unsigned *tid,
		char *affinity_buf, int len)
{
	json j;
	char name[16];
	std::string str;

	parse_json(j, jbuf);

	snprintf(name, 16, "%d", qid);

	auto qj = j["queues"][name];

	*tid = qj["tid"];
	str = qj["affinity"];

	if (str.length() < (unsigned)len) {
		strcpy(affinity_buf, str.c_str());
		return 0;
	}
	return -EINVAL;
}

void ublksrv_json_dump(const char *jbuf)
{
	auto j = json::parse(jbuf);

	std::cout << std::setw(4) << j << '\n';
}

/* the end null character is always counted */
int ublksrv_json_get_length(const char *jbuf)
{
	auto j = json::parse(jbuf);

	return j.dump().length() + 1;
}

int ublksrv_tgt_store_dev_data(const struct ublksrv_dev *dev,
		const char *buf)
{
	int ret;
	int len = ublksrv_json_get_length(buf);
	int fd = ublksrv_get_pidfile_fd(dev);

	if (fd < 0) {
		ublk_err( "fail to get fd of pid file, ret %d\n",
				fd);
		return fd;
	}

	ret = pwrite(fd, buf, len, JSON_OFFSET);
	if (ret <= 0)
		ublk_err( "fail to write json data to pid file, ret %d\n",
				ret);

	return ret;
}

int ublk_tgt_store_dev_data(const struct ublksrv_dev *dev)
{
	int ret;
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	int fd;
	const char *buf;
	int len;

	pthread_mutex_lock(&cdev->data->jbuf.lock);
	buf = cdev->data->jbuf.jbuf;
	len = ublksrv_json_get_length(buf);
	fd = ublksrv_get_pidfile_fd(dev);

	if (fd < 0) {
		ublk_err( "fail to get fd of pid file, ret %d\n",
				fd);
		ret = fd;
		goto finished;
	}

	ret = pwrite(fd, buf, len, JSON_OFFSET);
	if (ret <= 0)
		ublk_err( "fail to write json data to pid file, ret %d\n",
				ret);

 finished:
	pthread_mutex_unlock(&cdev->data->jbuf.lock);
	return ret;
}

char *ublksrv_tgt_get_dev_data(struct ublksrv_ctrl_dev *cdev)
{
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int dev_id = info->dev_id;
	struct stat st;
	char pid_file[256];
	char *buf;
	int size, fd, ret;
	const char *run_dir = ublksrv_ctrl_get_run_dir(cdev);

	if (!run_dir)
		return 0;

	snprintf(pid_file, 256, "%s/%d.pid", run_dir, dev_id);
	fd = open(pid_file, O_RDONLY);

	if (fd <= 0)
		return NULL;

	if (fstat(fd, &st) < 0)
		return NULL;

	if (st.st_size <=  JSON_OFFSET)
		return NULL;

	size = st.st_size - JSON_OFFSET;
	buf = (char *)malloc(size);
	ret = pread(fd, buf, size, JSON_OFFSET);
	if (ret <= 0)
		fprintf(stderr, "fail to read json from %s ret %d\n",
				pid_file, ret);
	close(fd);

	return buf;
}

int ublksrv_check_dev_data(const char *buf, int size)
{
	struct ublk_params p;

	if (size < JSON_OFFSET)
		return -EINVAL;

	return ublksrv_json_read_params(&p, &buf[JSON_OFFSET]);
}

int ublksrv_get_io_daemon_pid(const struct ublksrv_ctrl_dev *ctrl_dev,
			      bool check_data)
{
	const char *run_dir = ublksrv_ctrl_get_run_dir(ctrl_dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ctrl_dev);
	int ret = -1, pid_fd;
	char path[256];
	char *buf = NULL;
	int size = JSON_OFFSET;
	int daemon_pid;
	struct stat st;

	if (!run_dir)
		return -EINVAL;

	snprintf(path, 256, "%s/%d.pid", run_dir, info->dev_id);

	pid_fd = open(path, O_RDONLY);
	if (pid_fd < 0)
		goto out;

	if (fstat(pid_fd, &st) < 0)
		goto out;

	if (check_data)
		size = st.st_size;
	else
		size = JSON_OFFSET;

	buf = (char *)malloc(size);
	if (read(pid_fd, buf, size) <= 0)
		goto out;

	daemon_pid = strtol(buf, NULL, 10);
	if (daemon_pid < 0)
		goto out;

	ret = kill(daemon_pid, 0);
	if (ret)
		goto out;

	if (check_data) {
		ret = ublksrv_check_dev_data(buf, size);
		if (ret)
			goto out;
	}
	ret = daemon_pid;
out:
	if (pid_fd > 0)
		close(pid_fd);
	free(buf);
	return ret;
}

const char *ublksrv_get_pid_dir(void)
{
	return UBLKSRV_PID_DIR;
}
