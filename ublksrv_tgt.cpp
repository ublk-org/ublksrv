// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <stdio.h>
#include <sw/redis++/redis++.h>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include "ublksrv_tgt.h"

#define PAGE_SIZE 4096
using namespace sw::redis;

Redis redis = Redis("tcp://192.168.188.129:6385");
std::unordered_map<std::string, std::string> cache;


static bool backing_supports_discard(char *name)
{
	int fd;
	char buf[512];
	int len;

	len = snprintf(buf, 512, "/sys/block/%s/queue/discard_max_hw_bytes",
			basename(name));
	buf[len] = 0;
	fd = open(buf, O_RDONLY);
	if (fd > 0) {
		char val[128];
		int ret = pread(fd, val, 128, 0);
		unsigned long long bytes = 0;

		close(fd);
		if (ret > 0)
			bytes = strtol(val, NULL, 10);

		if (bytes > 0)
			return true;
	}
	return false;
}

static int loop_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery,
		const char *jbuf)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	int fd, ret;
	long direct_io = 0;
	struct ublk_params p;
	char file[PATH_MAX];

	ublk_assert(jbuf);

	ret = ublksrv_json_read_target_str_info(jbuf, PATH_MAX, "backing_file", file);
	if (ret < 0) {
		ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublksrv_json_read_target_ulong_info(jbuf, "direct_io",
			&direct_io);
	if (ret) {
		ublk_err( "%s: read target direct_io failed %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublksrv_json_read_params(&p, jbuf);
	if (ret) {
		ublk_err( "%s: read ublk params failed %d\n",
				__func__, ret);
		return ret;
	}

	fd = open(file, O_RDWR);
	if (fd < 0) {
		ublk_err( "%s: backing file %s can't be opened\n",
				__func__, file);
		return fd;
	}

	if (direct_io)
		fcntl(fd, F_SETFL, O_DIRECT);

	ublksrv_tgt_set_io_data_size(tgt);
	tgt->dev_size = p.basic.dev_sectors << 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 1;
	tgt->fds[1] = fd;

	return 0;
}

static int loop_recovery_tgt(struct ublksrv_dev *dev, int type)
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	const char *jbuf = ublksrv_ctrl_get_recovery_jbuf(cdev);

	ublk_assert(type == UBLKSRV_TGT_TYPE_LOOP);
	ublk_assert(info->state == UBLK_S_DEV_QUIESCED);

	return loop_setup_tgt(dev, type, true, jbuf);
}

static int loop_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
		*argv[])
{
	int buffered_io = 0;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	static const struct option lo_longopts[] = {
		{ "file",		1,	NULL, 'f' },
		{ "buffered_io",	no_argument, &buffered_io, 1},
		{ NULL }
	};
	unsigned long long bytes;
	struct stat st;
	int fd, opt;
	char *file = NULL;
	int jbuf_size;
	char *jbuf;
	struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD,
		.basic = {
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift	= 12,
			.io_min_shift	= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
		},

		.discard = {
			.max_discard_sectors	= UINT_MAX >> 9,
			.max_discard_segments	= 1,
		},
	};
	bool can_discard = false;

	strcpy(tgt_json.name, "loop");

	if (type != UBLKSRV_TGT_TYPE_LOOP)
		return -1;

	while ((opt = getopt_long(argc, argv, "-:f:",
				  lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			file = strdup(optarg);
			break;
		}
	}

	if (!file)
		return -1;

	fd = open(file, O_RDWR);
	if (fd < 0) {
		ublk_err( "%s: backing file %s can't be opened\n",
				__func__, file);
		return -2;
	}

	if (fstat(fd, &st) < 0)
		return -2;

	if (S_ISBLK(st.st_mode)) {
		unsigned int bs, pbs;

		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
			return -1;
		if (ioctl(fd, BLKSSZGET, &bs) != 0)
			return -1;
		if (ioctl(fd, BLKPBSZGET, &pbs) != 0)
			return -1;
		p.basic.logical_bs_shift = ilog2(bs);
		p.basic.physical_bs_shift = ilog2(pbs);
		can_discard = backing_supports_discard(file);
	} else if (S_ISREG(st.st_mode)) {
		bytes = st.st_size;
		can_discard = true;
		p.basic.logical_bs_shift = ilog2(st.st_blksize);
		p.basic.physical_bs_shift = ilog2(st.st_blksize);
	} else {
		bytes = 0;
	}

	/*
	 * in case of buffered io, use common bs/pbs so that all FS
	 * image can be supported
	 */
	if (buffered_io || !ublk_param_is_valid(&p) ||
			fcntl(fd, F_SETFL, O_DIRECT)) {
		p.basic.logical_bs_shift = 9;
		p.basic.physical_bs_shift = 12;
		buffered_io = 1;
	}

	tgt_json.dev_size = bytes;
	p.basic.dev_sectors = bytes >> 9;

	if (st.st_blksize && can_discard)
		p.discard.discard_granularity = st.st_blksize;
	else
		p.types &= ~UBLK_PARAM_TYPE_DISCARD;

	jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	ublk_json_write_dev_info(dev, &jbuf, &jbuf_size);
	ublk_json_write_target_base(dev, &jbuf, &jbuf_size, &tgt_json);
	ublk_json_write_tgt_str(dev, &jbuf, &jbuf_size, "backing_file", file);
	ublk_json_write_tgt_long(dev, &jbuf, &jbuf_size, "direct_io", !buffered_io);
	ublk_json_write_params(dev, &jbuf, &jbuf_size, &p);

	close(fd);

	return loop_setup_tgt(dev, type, false, jbuf);
}

static void loop_usage_for_add(void)
{
	printf("           loop: -f backing_file [--buffered_io]\n");
	printf("           	default is direct IO to backing file\n");
}

static inline int loop_fallocate_mode(const struct ublksrv_io_desc *iod)
{
       __u16 ublk_op = ublksrv_get_op(iod);
       __u32 flags = ublksrv_get_flags(iod);
       int mode = FALLOC_FL_KEEP_SIZE;

       /* follow logic of linux kernel loop */
       if (ublk_op == UBLK_IO_OP_DISCARD) {
               mode |= FALLOC_FL_PUNCH_HOLE;
       } else if (ublk_op == UBLK_IO_OP_WRITE_ZEROES) {
               if (flags & UBLK_IO_F_NOUNMAP)
                       mode |= FALLOC_FL_ZERO_RANGE;
               else
                       mode |= FALLOC_FL_PUNCH_HOLE;
       } else {
               mode |= FALLOC_FL_ZERO_RANGE;
       }

       return mode;
}

static int loop_queue_tgt_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	const struct ublksrv_io_desc *iod = data->iod;
	struct io_uring_sqe *sqe = io_uring_get_sqe(q->ring_ptr);
	unsigned ublk_op = ublksrv_get_op(iod);

	if (!sqe)
		return 0;

	switch (ublk_op) {
	case UBLK_IO_OP_FLUSH:
		io_uring_prep_sync_file_range(sqe, 1 /*fds[1]*/,
				iod->nr_sectors << 9,
				iod->start_sector << 9,
				IORING_FSYNC_DATASYNC);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
	case UBLK_IO_OP_DISCARD:
		io_uring_prep_fallocate(sqe, 1 /*fds[1]*/,
				loop_fallocate_mode(iod),
				iod->start_sector << 9,
				iod->nr_sectors << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		break;
	case UBLK_IO_OP_READ:
		io_uring_prep_read(sqe, 1 /*fds[1]*/,
				(void *)iod->addr,
				iod->nr_sectors << 9,
				iod->start_sector << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		break;
	case UBLK_IO_OP_WRITE:
		io_uring_prep_write(sqe, 1 /*fds[1]*/,
				(void *)iod->addr,
				iod->nr_sectors << 9,
				iod->start_sector << 9);
		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		break;
	default:
		return -EINVAL;
	}

	/* bit63 marks us as tgt io */
	sqe->user_data = build_user_data(tag, ublk_op, 0, 1);

	ublk_dbg(UBLK_DBG_IO, "%s: tag %d ublk io %x %llx %u\n", __func__, tag,
			iod->op_flags, iod->start_sector, iod->nr_sectors << 9);
	ublk_dbg(UBLK_DBG_IO, "%s: queue io op %d(%llu %x %llx)"
				" (qid %d tag %u, cmd_op %u target: %d, user_data %llx)\n",
			__func__, ublk_op, sqe->off, sqe->len, sqe->addr,
			q->q_id, tag, ublk_op, 1, sqe->user_data);

	return 1;
}

static co_io_job __loop_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	int ret;
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	io->queued_tgt_io = 0;
 again:
	ret = loop_queue_tgt_io(q, data, tag);
	if (ret > 0) {
		if (io->queued_tgt_io)
			ublk_err("bad queued_tgt_io %d\n", io->queued_tgt_io);
		io->queued_tgt_io += 1;

		co_await__suspend_always(tag);
		io->queued_tgt_io -= 1;

		if (io->tgt_io_cqe->res == -EAGAIN)
			goto again;


		
		/* REDIS HANDLING*/

		const struct ublksrv_io_desc *iod = data->iod;
		unsigned ublk_op = ublksrv_get_op(iod);
		//ublk_log("start handling request!- op is %d, start sector: %llu, num_of_sectors: %d",ublk_op, iod->start_sector, iod->nr_sectors);
		if (ublk_op == UBLK_IO_OP_WRITE) { 
			try { 
				int num_of_pages = iod->nr_sectors >> 3; 
				for (int i = 0; i < num_of_pages; i++)
				{
					std::string key = std::to_string(iod->start_sector +(i << 3));
					std::string value = std::string(static_cast<const char*>((void*)(iod->addr +(i* PAGE_SIZE))),PAGE_SIZE);	
					cache[key] = value;			
				}
				if (cache.size() > 1024) {
					//redis.set("above","100");
 	   				auto pipeline = redis.pipeline();

					for (const auto& pair : cache) {
        					pipeline.set(pair.first, pair.second);
    					}
  					pipeline.exec();
  					cache.clear();
				}
				ublksrv_complete_io(q, tag, io->tgt_io_cqe->res);
			}
			catch (const std::exception& e) { 
				//ublk_dbg(UBLK_DBG_IO, "failed to SET key-value to redis");
			}
 		}
		else if (ublk_op == UBLK_IO_OP_READ) { 
			try { 
				int num_of_pages = iod->nr_sectors >> 3; 
				for (int i = 0; i < num_of_pages; i++)
				{
					std::string key = std::to_string(iod->start_sector + (i << 3));
					auto it = cache.find(key);
					if (it != cache.end()) {
						std::memcpy((void*) (iod->addr + (i*PAGE_SIZE)), it->second.c_str(),PAGE_SIZE);
					    }
					else {
					        OptionalString value = redis.get(key);
						if (value) { 
							std::memcpy((void*) (iod->addr + (i*PAGE_SIZE)), value->data(),value->size());
						}
					}
					
				}
			}
			catch (const std::exception& e) { 
				//ublk_dbg(UBLK_DBG_IO, "failed to GET value from redis");
			}
			ublksrv_complete_io(q, tag, io->tgt_io_cqe->res);
		}
		else {	
			ublksrv_complete_io(q, tag, io->tgt_io_cqe->res);
		}
	} else if (ret < 0) {
		ublk_err( "fail to queue io %d, ret %d\n", tag, tag);
	} else {
		ublk_err( "no sqe %d\n", tag);
	}
}

static int loop_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	io->co = __loop_handle_io_async(q, data, data->tag);
	return 0;
}

static void loop_tgt_io_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	int tag = user_data_to_tag(cqe->user_data);
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	ublk_assert(tag == data->tag);
	if (!io->queued_tgt_io)
		ublk_err("%s: wrong queued_tgt_io: res %d qid %u tag %u, cmd_op %u\n",
			__func__, cqe->res, q->q_id,
			user_data_to_tag(cqe->user_data),
			user_data_to_op(cqe->user_data));
	io->tgt_io_cqe = cqe;
	io->co.resume();
}

static void loop_deinit_tgt(const struct ublksrv_dev *dev)
{
	fsync(dev->tgt.fds[1]);
	close(dev->tgt.fds[1]);
}

struct ublksrv_tgt_type  loop_tgt_type = {
	.handle_io_async = loop_handle_io_async,
	.tgt_io_done = loop_tgt_io_done,
	.usage_for_add	=  loop_usage_for_add,
	.init_tgt = loop_init_tgt,
	.deinit_tgt	=  loop_deinit_tgt,
	.type	= UBLKSRV_TGT_TYPE_LOOP,
	.name	=  "loop",
	.recovery_tgt = loop_recovery_tgt,
};

static void tgt_loop_init() __attribute__((constructor));

static void tgt_loop_init(void)
{
	ublksrv_register_tgt_type(&loop_tgt_type);
}
