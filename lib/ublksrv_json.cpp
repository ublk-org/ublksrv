#include <iostream>
#include "nlohmann/json.hpp"
#include "ublksrv_priv.h"

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

/*
 * build one json string with dev_info head, and result is stored
 * in 'buf'.
 */
int ublksrv_json_write_dev_info(const struct ublksrv_ctrl_dev *cdev,
		char *jbuf, int len)
{
	const struct ublksrv_ctrl_dev_info *info = &cdev->dev_info;
	json j;

	j["dev_info"]["dev_id"] = info->dev_id;
	j["dev_info"]["nr_hw_queues"] = info->nr_hw_queues;
	j["dev_info"]["queue_depth"] = info->queue_depth;
	j["dev_info"]["state"] = info->state;
	j["dev_info"]["flags"] = info->flags;
	j["dev_info"]["ublksrv_flags"] = info->ublksrv_flags;

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

	if (sj.contains("dev_id"))
		info->dev_id = j["dev_info"]["dev_id"];
	else
		info->dev_id = -1;

	if (sj.contains("nr_hw_queues"))
		info->nr_hw_queues = j["dev_info"]["nr_hw_queues"];
	else
		info->nr_hw_queues = DEF_NR_HW_QUEUES;

	if (sj.contains("queue_depth"))
		info->queue_depth = j["dev_info"]["queue_depth"];
	else
		info->queue_depth = DEF_NR_HW_QUEUES;

	if (sj.contains("state"))
		info->flags = j["dev_info"]["state"];
	else
		info->state = 0;

	if (sj.contains("flags"))
		info->flags = j["dev_info"]["flags"];
	else
		info->flags = 0;

	if (sj.contains("ublksrv_flags"))
		info->ublksrv_flags = j["dev_info"]["ublksrv_flags"];
	else
		info->ublksrv_flags = 0;

	return 0;
}

int ublksrv_json_write_target_str_info(char *jbuf, int len,
		const char *name, const char *val)
{
	json j;
	std::string s;
	int j_len;

	parse_json(j, jbuf);

	j["target"][std::string(name)] = val;;

	return dump_json_to_buf(j, jbuf, len);
}

int ublksrv_json_write_target_long_info(char *jbuf, int len,
		const char *name, long val)
{
	json j;
	std::string s;
	int j_len;

	parse_json(j, jbuf);

	j["target"][std::string(name)] = val;;

	return dump_json_to_buf(j, jbuf, len);
}

int ublksrv_json_write_target_ulong_info(char *jbuf, int len, const char *name,
		unsigned long val)
{
	json j;
	std::string s;
	int j_len;

	parse_json(j, jbuf);

	j["target"][std::string(name)] = val;;

	return dump_json_to_buf(j, jbuf, len);
}

int ublksrv_json_write_target_base_info(char *jbuf, int len,
		const struct ublksrv_tgt_base_json *tgt)
{
	json j;
	std::string s;
	int j_len;

	parse_json(j, jbuf);

	j["target"]["name"] = tgt->name;
	j["target"]["type"] = tgt->type;
	j["target"]["dev_size"] = tgt->dev_size;

	return dump_json_to_buf(j, jbuf, len);
}

int ublksrv_json_read_target_base_info(const char *jbuf,
		struct ublksrv_tgt_base_json *tgt)
{
	json j;
	std::string s;
	int j_len;

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
	int j_len;
	char name[16];
	char cpus[512];

	parse_json(j, jbuf);

	snprintf(name, 16, "%d", qid);

	ublksrv_build_cpu_str(cpus, 512, &cdev->queues_cpuset[qid]);

	j["queues"][std::string(name)]["qid"] = qid;
	j["queues"][std::string(name)]["tid"] = ubq_daemon_tid;
	j["queues"][std::string(name)]["affinity"] = cpus;

	return dump_json_to_buf(j, jbuf, len);
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

	if (str.length() < len) {
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
