// SPDX-License-Identifier: MIT or GPL-2.0-only

#ifndef UBLK_NVME_H
#define UBLK_NVME_H

#include <linux/types.h>

/* NVMe Register Offsets (BAR0) */
#define NVME_REG_CAP    0x0000  /* Controller Capabilities */
#define NVME_REG_VS     0x0008  /* Version */
#define NVME_REG_CC     0x0014  /* Controller Configuration */
#define NVME_REG_CSTS   0x001c  /* Controller Status */
#define NVME_REG_AQA    0x0024  /* Admin Queue Attributes */
#define NVME_REG_ASQ    0x0028  /* Admin Submission Queue Base */
#define NVME_REG_ACQ    0x0030  /* Admin Completion Queue Base */

/* Controller Configuration Register */
#define NVME_CC_ENABLE  (1 << 0)
#define NVME_CC_CSS_NVM (0 << 4)
#define NVME_CC_MPS_4K  (0 << 7)
#define NVME_CC_IOSQES  (6 << 16)  /* 2^6 = 64 bytes */
#define NVME_CC_IOCQES  (4 << 20)  /* 2^4 = 16 bytes */
#define NVME_CC_SHN_NORMAL (1 << 14)

/* Controller Status Register */
#define NVME_CSTS_RDY   (1 << 0)
#define NVME_CSTS_SHST_MASK (3 << 2)
#define NVME_CSTS_SHST_COMPLETE (2 << 2)

/* Admin Command Opcodes */
#define NVME_ADMIN_DELETE_SQ    0x00
#define NVME_ADMIN_CREATE_SQ    0x01
#define NVME_ADMIN_DELETE_CQ    0x04
#define NVME_ADMIN_CREATE_CQ    0x05
#define NVME_ADMIN_IDENTIFY     0x06

/* Identify CNS values */
#define NVME_ID_CNS_NS          0x00  /* Identify Namespace */
#define NVME_ID_CNS_CTRL        0x01  /* Identify Controller */

/* Controller VWC (Volatile Write Cache) */
#define NVME_CTRL_VWC_PRESENT   (1 << 0)

/* I/O Command Opcodes */
#define NVME_CMD_FLUSH          0x00
#define NVME_CMD_WRITE          0x01
#define NVME_CMD_READ           0x02
#define NVME_CMD_DSM            0x09  /* Dataset Management (discard/deallocate) */

/* Command Flags */
#define NVME_RW_FUA             (1 << 14)

/* Dataset Management Attributes (CDW11) */
#define NVME_DSMGMT_AD          (1 << 2)  /* Attribute - Deallocate */

/* Dataset Management Range */
struct nvme_dsm_range {
	__le32	cattr;  /* Context Attributes */
	__le32	nlb;    /* Number of Logical Blocks */
	__le64	slba;   /* Starting LBA */
};

/* NVMe Command Structures */
struct nvme_common_command {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	nsid;
	__u32	cdw2[2];
	__u64	metadata;
	__u64	prp1;
	__u64	prp2;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
};

struct nvme_rw_command {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	nsid;
	__u64	rsvd2;
	__u64	metadata;
	__u64	prp1;
	__u64	prp2;
	__u64	slba;
	__u16	length;
	__u16	control;
	__u32	dsmgmt;
	__u32	reftag;
	__u16	apptag;
	__u16	appmask;
};

struct nvme_create_cq {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	rsvd1[5];
	__u64	prp1;
	__u64	rsvd8;
	__u16	cqid;
	__u16	qsize;
	__u16	cq_flags;
	__u16	irq_vector;
	__u32	rsvd12[4];
};

struct nvme_create_sq {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	rsvd1[5];
	__u64	prp1;
	__u64	rsvd8;
	__u16	sqid;
	__u16	qsize;
	__u16	sq_flags;
	__u16	cqid;
	__u32	rsvd12[4];
};

struct nvme_delete_queue {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	rsvd1[9];
	__u16	qid;
	__u16	rsvd10;
	__u32	rsvd11[5];
};

struct nvme_identify {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	nsid;
	__u64	rsvd2[2];
	__u64	prp1;
	__u64	prp2;
	__u32	cns;
	__u32	rsvd11[5];
};

struct nvme_completion {
	__u32	result;
	__u32	rsvd;
	__u16	sq_head;
	__u16	sq_id;
	__u16	command_id;
	__u16	status;
};

/* Identify Namespace Structure (partial) */
struct nvme_lbaf {
	__le16	ms;
	__u8	ds;
	__u8	rp;
};

struct nvme_id_ns {
	__le64	nsze;
	__le64	ncap;
	__le64	nuse;
	__u8	nsfeat;
	__u8	nlbaf;
	__u8	flbas;
	__u8	mc;
	__u8	dpc;
	__u8	dps;
	__u8	nmic;
	__u8	rescap;
	__u8	fpi;
	__u8	dlfeat;
	__le16	nawun;
	__le16	nawupf;
	__le16	nacwu;
	__le16	nabsn;
	__le16	nabo;
	__le16	nabspf;
	__le16	noiob;
	__u8	nvmcap[16];
	__le16	npwg;
	__le16	npwa;
	__le16	npdg;
	__le16	npda;
	__le16	nows;
	__u8	rsvd74[18];
	__le32	anagrpid;
	__u8	rsvd96[3];
	__u8	nsattr;
	__le16	nvmsetid;
	__le16	endgid;
	__u8	nguid[16];
	__u8	eui64[8];
	struct nvme_lbaf lbaf[64];
};

/* Power State Descriptor */
struct nvme_id_power_state {
	__le16	max_power;	/* centiwatts */
	__u8	rsvd2;
	__u8	flags;
	__le32	entry_lat;	/* microseconds */
	__le32	exit_lat;	/* microseconds */
	__u8	read_tput;
	__u8	read_lat;
	__u8	write_tput;
	__u8	write_lat;
	__le16	idle_power;
	__u8	idle_scale;
	__u8	rsvd19;
	__le16	active_power;
	__u8	active_work_scale;
	__u8	rsvd23[9];
};

/* Identify Controller Structure */
struct nvme_id_ctrl {
	__le16	vid;		/* PCI Vendor ID */
	__le16	ssvid;		/* PCI Subsystem Vendor ID */
	char	sn[20];		/* Serial Number */
	char	mn[40];		/* Model Number */
	char	fr[8];		/* Firmware Revision */
	__u8	rab;		/* Recommended Arbitration Burst */
	__u8	ieee[3];	/* IEEE OUI Identifier */
	__u8	cmic;		/* Controller Multi-Path I/O and Namespace Sharing */
	__u8	mdts;		/* Maximum Data Transfer Size */
	__le16	cntlid;		/* Controller ID */
	__le32	ver;		/* Version */
	__le32	rtd3r;		/* RTD3 Resume Latency */
	__le32	rtd3e;		/* RTD3 Entry Latency */
	__le32	oaes;		/* Optional Async Events Supported */
	__le32	ctratt;		/* Controller Attributes */
	__u8	rsvd100[11];
	__u8	cntrltype;	/* Controller Type */
	__u8	fguid[16];	/* FRU GUID */
	__le16	crdt1;		/* Command Retry Delay Time 1 */
	__le16	crdt2;		/* Command Retry Delay Time 2 */
	__le16	crdt3;		/* Command Retry Delay Time 3 */
	__u8	rsvd134[122];
	__le16	oacs;		/* Optional Admin Command Support */
	__u8	acl;		/* Abort Command Limit */
	__u8	aerl;		/* Async Event Request Limit */
	__u8	frmw;		/* Firmware Updates */
	__u8	lpa;		/* Log Page Attributes */
	__u8	elpe;		/* Error Log Page Entries */
	__u8	npss;		/* Number of Power States Support */
	__u8	avscc;		/* Admin Vendor Specific Command Config */
	__u8	apsta;		/* Autonomous Power State Transition Attrs */
	__le16	wctemp;		/* Warning Composite Temperature Threshold */
	__le16	cctemp;		/* Critical Composite Temperature Threshold */
	__le16	mtfa;		/* Maximum Time for Firmware Activation */
	__le32	hmpre;		/* Host Memory Buffer Preferred Size */
	__le32	hmmin;		/* Host Memory Buffer Minimum Size */
	__u8	tnvmcap[16];	/* Total NVM Capacity */
	__u8	unvmcap[16];	/* Unallocated NVM Capacity */
	__le32	rpmbs;		/* Replay Protected Memory Block Support */
	__le16	edstt;		/* Extended Device Self-test Time */
	__u8	dsto;		/* Device Self-test Options */
	__u8	fwug;		/* Firmware Update Granularity */
	__le16	kas;		/* Keep Alive Support */
	__le16	hctma;		/* Host Controlled Thermal Management Attrs */
	__le16	mntmt;		/* Minimum Thermal Management Temperature */
	__le16	mxtmt;		/* Maximum Thermal Management Temperature */
	__le32	sanicap;	/* Sanitize Capabilities */
	__le32	hmminds;	/* Host Memory Buffer Minimum Descriptor Entry Size */
	__le16	hmmaxd;		/* Host Memory Maximum Descriptors Entries */
	__le16	nvmsetidmax;	/* NVM Set Identifier Maximum */
	__le16	endgidmax;	/* Endurance Group Identifier Maximum */
	__u8	anatt;		/* ANA Transition Time */
	__u8	anacap;		/* Asymmetric Namespace Access Capabilities */
	__le32	anagrpmax;	/* ANA Group Identifier Maximum */
	__le32	nanagrpid;	/* Number of ANA Group Identifiers */
	__u8	rsvd352[160];
	__u8	sqes;		/* Submission Queue Entry Size */
	__u8	cqes;		/* Completion Queue Entry Size */
	__le16	maxcmd;		/* Maximum Outstanding Commands */
	__le32	nn;		/* Number of Namespaces */
	__le16	oncs;		/* Optional NVM Command Support */
	__le16	fuses;		/* Fused Operation Support */
	__u8	fna;		/* Format NVM Attributes */
	__u8	vwc;		/* Volatile Write Cache */
	__le16	awun;		/* Atomic Write Unit Normal */
	__le16	awupf;		/* Atomic Write Unit Power Fail */
	__u8	nvscc;		/* NVM Vendor Specific Command Config */
	__u8	nwpc;		/* Namespace Write Protection Capabilities */
	__le16	acwu;		/* Atomic Compare & Write Unit */
	__u8	rsvd534[2];
	__le32	sgls;		/* SGL Support */
	__le32	mnan;		/* Maximum Number of Allowed Namespaces */
	__u8	rsvd544[224];
	char	subnqn[256];	/* NVM Subsystem NVMe Qualified Name */
	__u8	rsvd1024[768];
	__le32	ioccsz;		/* I/O Queue Command Capsule Supported Size */
	__le32	iorcsz;		/* I/O Queue Response Capsule Supported Size */
	__le16	icdoff;		/* In Capsule Data Offset */
	__u8	ctrattr;	/* Controller Attributes */
	__u8	msdbd;		/* Maximum SGL Data Block Descriptors */
	__u8	rsvd1804[2];
	__u8	dctype;		/* Dirty Close Type */
	__u8	rsvd1807[241];
	struct nvme_id_power_state psd[32];	/* Power State Descriptors */
	__u8	vs[1024];	/* Vendor Specific */
};

#endif /* UBLK_NVME_H */
