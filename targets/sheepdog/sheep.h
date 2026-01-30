// SPDX-License-Identifier: GPL-2.0
/*
 * sheep.h - Definitions for sheepdog device server
 *
 * Copyright (c) 2026 Hannes Reinecke, SUSE
 */
#ifndef __SHEEP_H__
#define __SHEEP_H__

#ifdef __cplusplus
extern "C" {
#endif

#define SD_SEND_TMO 5
#define SD_RECV_TMO 60

struct sheepdog_vdi {
	char vdi_name[256];
	uint32_t vid;
	pthread_mutex_t inode_lock;
	struct sd_inode inode;
};

struct sheepdog_queue_ctx {
	int fd;
};

enum sd_io_state {
	SD_SEND_REQ,
	SD_SEND_DATA,
	SD_RECV_RSP,
	SD_RECV_DATA,
};

struct sd_io_context {
	enum sd_io_state state;
	struct sd_req req;
	struct sd_rsp rsp;
	void *addr;
};

#define SD_OBJECT_SIZE(v) (UINT32_C(1) << (v)->inode.block_size_shift)

 int sd_connect(const char *cluster_host, const char *cluster_port,
		unsigned int send_tmo, unsigned int recv_tmo);
int sd_vdi_lookup(int fd, const char *vdi_name, uint32_t snapid,
		const char *tag, uint32_t *vid, bool lock);
int sd_vdi_release(int fd, struct sheepdog_vdi *vdi);
int sd_read_inode(int fd, struct sheepdog_vdi *vdi, bool snapshot);
int sd_exec_read(int fd, struct sheepdog_vdi *sd_vdi,
		 const struct ublksrv_io_desc *iod,
		 struct sd_io_context *sd_io);
int sd_exec_discard(int fd, struct sheepdog_vdi *sd_vdi,
		    const struct ublksrv_io_desc *iod,
		    struct sd_io_context *sd_io, bool write_zeroes);
int sd_exec_write(int fd, struct sheepdog_vdi *sd_vdi,
		  const struct ublksrv_io_desc *iod,
		  struct sd_io_context *sd_io);

#ifdef __cplusplus
}
#endif
#endif /* __SHEEP_H__ */
