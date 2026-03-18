// SPDX-License-Identifier: MIT or GPL-2.0-only

/*
 * VFIO-based ublk NVMe/PCI Target
 *
 * NOTE: This target is primarily intended for learning and educational purposes.
 * It demonstrates how to implement a ublk target that interfaces directly with
 * NVMe hardware via VFIO, and serves as a reference for understanding both the
 * ublk target interface and NVMe command submission at a low level.
 *
 * This target accesses NVMe devices directly via VFIO, bypassing the kernel
 * NVMe driver. It provides an alternative I/O path for testing and performance
 * analysis.
 *
 * Idea is from SPDK project.
 *
 * Usage:
 *   Standard mode (with IOMMU):
 *     sudo ublk.nvme_vfio add -q 1 -d 128 --pci 0000:01:00.0
 *
 *   NoIOMMU mode (for VM testing, uses virtual addresses as IOVAs):
 *     sudo ublk.nvme_vfio add --noiommu -q 1 -d 128 --pci 0000:01:00.0
 *
 * Prerequisites:
 *   Standard mode (iommufd + VFIO cdev):
 *     - IOMMU enabled (intel_iommu=on or amd_iommu=on)
 *     - vfio-pci module loaded
 *     - /dev/iommu available (CONFIG_IOMMUFD)
 *
 *   NoIOMMU mode (legacy VFIO container/group):
 *     - vfio-pci module loaded
 *     - noiommu mode is automatically enabled when --noiommu is passed
 *
 *   Both modes:
 *     - Device will be automatically bound to vfio-pci
 *
 */

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include <limits.h>
#include <linux/vfio.h>
#include <linux/iommufd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <endian.h>
#include <fcntl.h>

#include "ublksrv_tgt.h"
#include "nvme.h"

#include "dma_buf.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Types referenced by the BPF skeleton (must precede skel.h) */
struct nvme_rw_cmd {
	__u8  opcode;
	__u8  flags;
	__u16 cid;
	__u32 nsid;
	__u64 rsvd2;
	__u64 metadata;
	__u64 prp1;
	__u64 prp2;
	__u64 slba;
	__u16 length;
	__u16 control;
	__u32 dsmgmt;
	__u32 reftag;
	__u16 apptag;
	__u16 appmask;
} __attribute__((aligned(64)));

struct sq_state {
	__u32 sq_lock;		/* bpf_spin_lock (opaque to userspace) */
	__u32 _pad0;
	__u64 sq_dma;
	__u64 prp_base_iova;
	__u32 sq_arena_off;	/* arena byte offset to SQ entries */
	__u32 cq_arena_off;	/* arena byte offset to CQ entries */
	__u32 prp_arena_off;	/* arena byte offset to PRP lists */
	__u16 sq_tail;
	__u16 last_sq_tail;
	__u16 qsize;
	__u16 qdepth;
	__u32 db_offset;
} __attribute__((aligned(64)));

/* NVMe CQ entry — must match BPF's struct nvme_cqe */
struct nvme_cqe {
	__u32 result;
	__u32 rsvd;
	__u16 sq_head;
	__u16 sq_id;
	__u16 command_id;
	__u16 status;
};

#include "ublk_nvme_vfio.bpf.skel.h"

#define PAGE_SIZE 4096
#define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define ADMIN_Q_SIZE 64

/*
 * Unified pool layout — computed once, used by both hugepage and arena paths.
 *
 * Layout (all sections page-aligned):
 *   admin_sq | admin_cq | identify | io_sq[0..N-1] | io_cq[0..N-1] |
 *   prp[0..N-1] | [io_buf[0..N-1]]
 *
 * Identify buffer placed after admin CQ so Phase 1 (admin-only) can use it.
 */
struct nvme_pool_layout {
	size_t admin_sq_off, admin_sq_size;
	size_t admin_cq_off, admin_cq_size;
	size_t identify_off;
	size_t io_sq_off, io_sq_stride;   /* io_sq[i] at io_sq_off + i * io_sq_stride */
	size_t io_cq_off, io_cq_stride;
	size_t prp_off, prp_stride;       /* prp[q] at prp_off + q * prp_stride */
	size_t io_buf_off, io_buf_stride;  /* 0 if not needed (BPF/zero-copy) */
	size_t total_size;
};

/*
 * Compute unified pool layout.
 *
 * @nr_queues: number of IO queues (0 = admin-only layout)
 * @depth: IO queue depth (entries, not including wrap slot)
 * @io_buf_size: per-tag IO buffer size (0 = no IO buffers)
 */
static void nvme_compute_pool_layout(struct nvme_pool_layout *layout,
				     int nr_queues, int depth,
				     size_t io_buf_size)
{
	size_t off = 0;

	layout->admin_sq_off = off;
	layout->admin_sq_size = PAGE_ALIGN(ADMIN_Q_SIZE * 64);
	off += layout->admin_sq_size;

	layout->admin_cq_off = off;
	layout->admin_cq_size = PAGE_ALIGN(ADMIN_Q_SIZE * 16);
	off += layout->admin_cq_size;

	layout->identify_off = off;
	off += PAGE_SIZE;

	if (nr_queues > 0) {
		int qsize = depth + 1;

		layout->io_sq_off = off;
		layout->io_sq_stride = PAGE_ALIGN(qsize * 64);
		off += nr_queues * layout->io_sq_stride;

		layout->io_cq_off = off;
		layout->io_cq_stride = PAGE_ALIGN(qsize * 16);
		off += nr_queues * layout->io_cq_stride;

		layout->prp_off = off;
		layout->prp_stride = depth * PAGE_SIZE;
		off += nr_queues * layout->prp_stride;

		if (io_buf_size > 0) {
			layout->io_buf_off = off;
			layout->io_buf_stride = depth * io_buf_size;
			off += nr_queues * layout->io_buf_stride;
		} else {
			layout->io_buf_off = 0;
			layout->io_buf_stride = 0;
		}
	} else {
		layout->io_sq_off = layout->io_cq_off = 0;
		layout->io_sq_stride = layout->io_cq_stride = 0;
		layout->prp_off = layout->prp_stride = 0;
		layout->io_buf_off = layout->io_buf_stride = 0;
	}

	layout->total_size = off;
}

static size_t nvme_admin_pool_size(void)
{
	return PAGE_ALIGN(ADMIN_Q_SIZE * 64) +
	       PAGE_ALIGN(ADMIN_Q_SIZE * 16) +
	       PAGE_SIZE;
}

/*
 * Memory barriers (aligned with SPDK barrier.h)
 */
#if defined(__x86_64__) || defined(__i386__)
#define ublk_wmb()	__asm__ __volatile__("sfence" ::: "memory")
#define ublk_rmb()	__asm__ __volatile__("lfence" ::: "memory")
#define ublk_mb()	__asm__ __volatile__("mfence" ::: "memory")
#elif defined(__aarch64__)
#define ublk_wmb()	__asm__ __volatile__("dsb st" ::: "memory")
#define ublk_rmb()	__asm__ __volatile__("dsb ld" ::: "memory")
#define ublk_mb()	__asm__ __volatile__("dsb sy" ::: "memory")
#else
#define ublk_wmb()	__sync_synchronize()
#define ublk_rmb()	__sync_synchronize()
#define ublk_mb()	__sync_synchronize()
#endif

/* DMA read barrier - compiler barrier on x86 (matches kernel dma_rmb()) */
#if defined(__x86_64__) || defined(__i386__)
#define ublk_dma_rmb()  __asm__ __volatile__("" ::: "memory")
#elif defined(__aarch64__)
#define ublk_dma_rmb()  __asm__ __volatile__("dmb oshld" ::: "memory")
#else
#define ublk_dma_rmb()  ublk_rmb()
#endif

#ifdef DEBUG
#define nvme_dbg  ublk_dbg
#else
#define nvme_dbg(...)
#endif

#define nvme_log(fmt, ...) fprintf(stdout, "nvme_vfio: " fmt, ##__VA_ARGS__)

/* MMIO write with implicit wmb (like Linux writel) */
static inline void nvme_writel_mmio(__u32 val, volatile __u32 *addr)
{
	ublk_wmb();
	*addr = val;
}

/* MMIO read with implicit rmb (like Linux readl) */
static inline __u32 nvme_readl_mmio(volatile __u32 *addr)
{
	__u32 val = *addr;
	ublk_rmb();
	return val;
}

/* READ_ONCE - prevent compiler from caching or reordering reads */
template<typename T>
static inline T read_once(const T& x) {
	return *static_cast<const volatile T*>(&x);
}
#define READ_ONCE(x) read_once(x)

/*
 * DMA Mapping Tracking
 */
struct nvme_dma_mapping {
	__u64 vaddr;
	__u64 iova;
	size_t size;
};

/* Per-I/O private data for PRP list support */
struct nvme_io_priv {
	struct nvme_dma_mapping data_mapping;  /* I/O data buffer mapping */
	struct nvme_dma_mapping prp_mapping;   /* PRP list buffer mapping */
	__le64 *prp_list;                       /* PRP list buffer (virtual addr) */

	/*
	 * BPF mode: NVMe CQE can arrive before the io_uring FETCH CQE
	 * is consumed by userspace. We must defer ublksrv_complete_io
	 * until the FETCH is consumed, otherwise COMMIT_AND_FETCH
	 * conflicts with the pending FETCH in the io_uring CQ ring.
	 */
	bool fetch_done;	/* FETCH consumed by userspace */
	bool cqe_early;		/* CQE arrived before FETCH consumed */
	int  cqe_result;	/* saved result for deferred completion */
};

/* Queue Structure */
struct nvme_queue {
	__u16 qid;
	__u16 qsize;

	/* Queue memory */
	void *sq_buffer;
	void *cq_buffer;
	__u64 sq_iova;
	__u64 cq_iova;

	/* DMA mappings for queue buffers */
	struct nvme_dma_mapping sq_mapping;
	struct nvme_dma_mapping cq_mapping;

	/* Queue state */
	__u16 sq_tail;
	__u16 last_sq_tail;	/* Last value written to SQ doorbell */
	__u16 cq_head;
	__u8 cq_phase;

	/* Doorbell registers */
	volatile __u32 *sq_doorbell;
	volatile __u32 *cq_doorbell;

	/* Last CQE result (CDW0) — needed for Set Features response */
	__u32 last_cqe_result;
};

/* Target Private Data */
struct nvme_vfio_tgt_data {
	__u32 nsid;
	__u32 lba_shift;
	__u64 dev_size;

	bool user_copy;  /* UBLK_F_USER_COPY mode flag */
	bool zero_copy;  /* UBLK_F_BPF_DMA: kernel maps bio pages via iommufd */

	/* VFIO handles */
	int container_fd;
	int group_fd;
	int device_fd;
	int iommu_group;
	int use_noiommu;

	/* iommufd handles (used when IOMMU is available, -1 for noiommu) */
	int iommufd;
	__u32 ioas_id;
	__u32 dev_id;

	/* NoIOMMU mode flag */
	int force_noiommu;	/* --noiommu flag: use virtual addresses as IOVAs */

	/* MMIO mapping */
	volatile void *bar0;
	size_t bar0_size;

	/* Queues */
	struct nvme_queue admin_queue;
	struct nvme_queue *io_queues;
	int nr_io_queues;

	/* Device info */
	unsigned int queue_depth;
	unsigned int max_io_buf_bytes;

	/* Capabilities */
	unsigned int db_stride;
	unsigned int max_transfer_shift;
	__u8 vwc;  /* Volatile Write Cache present */
	__u8 mdts;		/* Maximum Data Transfer Size (power of 2) */
	__le32 sgls;		/* SGL Support capabilities */

	/* DMA IOVA allocation */
	__u64 next_iova;
	pthread_spinlock_t iova_lock;	/* Protects next_iova allocation */

	/* DMA buffer pool for pinned DMA memory */
	struct dma_buf_pool dma_pool;

	/* Unified pool layout (offsets from dma_pool.base) */
	struct nvme_pool_layout layout;

	char pci_addr[16];
	int numa_node;

	/* Extra hugepages allocated by nvme_ensure_hugepages() */
	unsigned long extra_hugepages;

	/* Hugepage size in bytes (read from /proc/meminfo) */
	size_t hugepage_size;

	/* BPF mode: SQ submission handled by BPF struct_ops */
	bool bpf_mode;
	struct ublk_nvme_vfio *bpf_skel;
	struct bpf_link *bpf_link;
	void *arena_mmap;		/* mmap'd arena base */
	size_t arena_mmap_size;
	struct nvme_dma_mapping arena_dma_mapping;
};

/* Helper: Read 32-bit register */
static inline __u32 nvme_readl(volatile void *bar, unsigned int offset)
{
	return *(volatile __u32 *)((char *)bar + offset);
}

/* Helper: Write 32-bit register */
static inline void nvme_writel(volatile void *bar, unsigned int offset, __u32 val)
{
	*(volatile __u32 *)((char *)bar + offset) = val;
}

/* Helper: Read 64-bit register */
static inline __u64 nvme_readq(volatile void *bar, unsigned int offset)
{
	return *(volatile __u64 *)((char *)bar + offset);
}

/* Helper: Write 64-bit register */
static inline void nvme_writeq(volatile void *bar, unsigned int offset, __u64 val)
{
	*(volatile __u64 *)((char *)bar + offset) = val;
}

/* Validate parameters against NVMe hardware capabilities */
static int nvme_validate_params(struct nvme_vfio_tgt_data *data, __u64 cap)
{
	unsigned int mqes = (cap & 0xFFFF) + 1;

	/* NVMe spec allows queue IDs 1-65535 for I/O queues */
	if (data->nr_io_queues > 65535) {
		ublk_err("nr_io_queues %u exceeds NVMe max (65535)\n",
			 data->nr_io_queues);
		return -EINVAL;
	}

	/* Clamp queue depth to MQES instead of erroring */
	if (data->queue_depth > mqes) {
		nvme_log("Clamping queue_depth %u to MQES %u\n",
			 data->queue_depth, mqes);
		data->queue_depth = mqes;
	}

	return 0;
}

/* Enable VFIO noiommu mode via sysfs */
static int nvme_enable_noiommu_mode(void)
{
	const char *path = "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode";
	int fd;
	char buf[8];
	ssize_t ret;

	/* Check if already enabled */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ublk_err("Cannot read %s: %s\n", path, strerror(errno));
		return -1;
	}
	ret = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (ret > 0) {
		buf[ret] = '\0';
		if (buf[0] == 'Y' || buf[0] == '1')
			return 0;  /* Already enabled */
	}

	/* Enable noiommu mode */
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		ublk_err("Cannot write %s: %s (run as root?)\n", path, strerror(errno));
		return -1;
	}
	ret = write(fd, "Y\n", 2);
	close(fd);

	if (ret != 2) {
		ublk_err("Failed to enable noiommu mode\n");
		return -1;
	}

	nvme_log("Enabled VFIO noiommu mode\n");
	return 0;
}

/* Get IOMMU group for a PCI device */
static int get_iommu_group(const char *pci_addr, int *use_noiommu)
{
	char path[256];
	char link[256];
	char *group_name;
	ssize_t len;

	*use_noiommu = 0;

	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/iommu_group", pci_addr);

	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0) {
		/* No IOMMU group - use noiommu mode */
		*use_noiommu = 1;
		ublk_err("No IOMMU found, will use no-IOMMU mode (unsafe)\n");
		return 0;  /* noiommu uses group 0 typically */
	}
	link[len] = '\0';

	group_name = strrchr(link, '/');
	if (!group_name) {
		ublk_err("Invalid iommu_group link: %s\n", link);
		return -1;
	}

	int group_num = atoi(group_name + 1);

	/* Check if this is a noiommu group by looking for "noiommu" in path */
	if (strstr(link, "noiommu")) {
		*use_noiommu = 1;
		ublk_err("Using no-IOMMU mode for group %d (unsafe)\n", group_num);
	}

	return group_num;
}

/* Get NUMA node for a PCI device, returns -1 if not available */
static int get_pci_numa_node(const char *pci_addr)
{
	char path[256];
	char buf[32];
	int fd, numa_node = -1;

	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/numa_node", pci_addr);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (read(fd, buf, sizeof(buf)) > 0)
		numa_node = atoi(buf);

	close(fd);
	return numa_node;
}

/* Get CPU list string for a NUMA node, returns 0 on success */
static int get_numa_cpulist(int numa_node, char *buf, size_t buflen)
{
	char path[256];
	int fd;
	ssize_t len;

	if (numa_node < 0 || !buf || buflen == 0)
		return -1;

	snprintf(path, sizeof(path),
		"/sys/devices/system/node/node%d/cpulist", numa_node);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, buflen - 1);
	close(fd);

	if (len <= 0)
		return -1;

	/* Remove trailing newline */
	buf[len] = '\0';
	if (buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	return 0;
}

static void nvme_log_numa_info(const struct nvme_vfio_tgt_data *data)
{
	char cpulist[256];

	nvme_log("Initializing VFIO NVMe target for %s (numa node %d)\n",
		 data->pci_addr, data->numa_node);
	if (get_numa_cpulist(data->numa_node, cpulist, sizeof(cpulist)) == 0)
		nvme_log("For good performance, start via: taskset -c %s(numa node %d)\n",
			 cpulist, data->numa_node);
}

static inline bool nvme_use_iommu(struct nvme_vfio_tgt_data *data)
{
	return !data->use_noiommu && !data->force_noiommu;
}

/* Check if controller supports SGL for NVM commands */
static inline bool nvme_sgl_supported(struct nvme_vfio_tgt_data *data)
{
	/* Bits 0-1: 0=not supported, 1=byte aligned, 2=dword aligned */
	return (le32toh(data->sgls) & 0x3) != 0;
}

/*
 * Get IOVA for buffer based on current mode
 */
static __u64 nvme_get_iova(struct nvme_vfio_tgt_data *data, void *vaddr, size_t size)
{
	__u64 iova;

	/* NoIOMMU mode: use physical address from /proc/self/pagemap */
	if (!nvme_use_iommu(data)) {
		uint64_t phys = dma_buf_pool_virt_to_phys(&data->dma_pool, vaddr);
		return (phys == DMA_BUF_PHYS_ERROR) ? 0 : phys;
	}

	/* Standard IOMMU mode: allocate sequential IOVA */
	pthread_spin_lock(&data->iova_lock);
	iova = data->next_iova;
	data->next_iova += (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	pthread_spin_unlock(&data->iova_lock);
	return iova;
}

/*
 * Perform VFIO DMA mapping if needed
 */
static int nvme_do_vfio_map(struct nvme_vfio_tgt_data *data,
			    void *vaddr, __u64 iova, size_t size)
{
	struct iommu_ioas_map map = {};

	if (!nvme_use_iommu(data))
		return 0;

	map.size = sizeof(map);
	map.flags = IOMMU_IOAS_MAP_FIXED_IOVA |
		    IOMMU_IOAS_MAP_WRITEABLE |
		    IOMMU_IOAS_MAP_READABLE;
	map.ioas_id = data->ioas_id;
	map.user_va = (__u64)vaddr;
	map.length = (size + PAGE_SIZE - 1) & ~((__u64)PAGE_SIZE - 1);
	map.iova = iova;

	if (ioctl(data->iommufd, IOMMU_IOAS_MAP, &map) < 0) {
		ublk_err("IOMMU_IOAS_MAP: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

/* Unbind device from current driver */
static int unbind_driver(const char *pci_addr)
{
	char path[256];
	int fd, retry;

	if (strlen(pci_addr) > 16) {
		ublk_err("Invalid PCI address length\n");
		return -1;
	}

	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/driver/unbind", pci_addr);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		return 0;
	}

	if (write(fd, pci_addr, strlen(pci_addr)) < 0) {
		ublk_err("unbind device: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);

	/* Wait for driver to fully unbind */
	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/driver", pci_addr);

	for (retry = 0; retry < 50; retry++) {
		char driver_link[256];
		ssize_t len;

		len = readlink(path, driver_link, sizeof(driver_link) - 1);
		if (len < 0) {
			return 0;
		}
		usleep(100000);
	}

	ublk_err("Warning: driver unbind may not be complete\n");
	return 0;
}

/*
 * Bind device to vfio-pci driver using driver_override.
 *
 * The driver_override approach is preferred over new_id + bind because
 * writing to new_id triggers auto-probe which races with the explicit
 * bind, causing EBUSY errors on the first attempt.
 */
static int bind_vfio_pci(const char *pci_addr)
{
	char path[256];
	int fd;

	/* Set driver_override to vfio-pci */
	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/driver_override", pci_addr);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		ublk_err("open driver_override: %s\n", strerror(errno));
		return -1;
	}
	if (write(fd, "vfio-pci", 8) < 0) {
		ublk_err("write driver_override: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	/* Trigger driver probe for the device */
	fd = open("/sys/bus/pci/drivers_probe", O_WRONLY);
	if (fd < 0) {
		ublk_err("open drivers_probe: %s\n", strerror(errno));
		return -1;
	}
	if (write(fd, pci_addr, strlen(pci_addr)) < 0) {
		ublk_err("write drivers_probe: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	usleep(200000);  /* 200ms for driver probe to complete */

	return 0;
}

/* Setup device binding to vfio-pci */
static int setup_vfio_binding(const char *pci_addr)
{
	char path[256];
	char driver_link[256];
	ssize_t len;

	if (strlen(pci_addr) > 16) {
		ublk_err("Invalid PCI address length\n");
		return -1;
	}

	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/driver", pci_addr);

	len = readlink(path, driver_link, sizeof(driver_link) - 1);
	if (len > 0) {
		driver_link[len] = '\0';
		if (strstr(driver_link, "vfio-pci")) {
			return 0;
		}

		nvme_log("Unbinding %s from current driver\n", pci_addr);
		if (unbind_driver(pci_addr) < 0) {
			return -1;
		}
	}

	nvme_log("Binding %s to vfio-pci\n", pci_addr);
	return bind_vfio_pci(pci_addr);
}

/* Get I/O private data for a tag */
static inline struct nvme_io_priv *nvme_get_io_priv(
	const struct ublksrv_queue *q, int tag)
{
	struct ublk_io_tgt *io = (struct ublk_io_tgt *)ublksrv_io_private_data(q, tag);
	return (struct nvme_io_priv *)(io + 1);
}

/*
 * Hugepage-based DMA pool management
 */

/* Get hugepage size from /proc/meminfo (returns 0 on error) */
static size_t nvme_get_hugepage_size(void)
{
	unsigned long size_kb = 0;
	FILE *fp;
	char buf[64];

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return 0;

	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "Hugepagesize: %lu kB", &size_kb) == 1)
			break;
	}
	fclose(fp);

	return size_kb * 1024;
}

/* Get number of free hugepages */
static unsigned long nvme_get_free_hugepages(void)
{
	unsigned long free_pages = 0;
	FILE *fp;
	char buf[64];

	fp = fopen("/proc/meminfo", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp)) {
			if (sscanf(buf, "HugePages_Free: %lu", &free_pages) == 1)
				break;
		}
		fclose(fp);
	}

	return free_pages;
}

/* Adjust nr_hugepages by delta (positive to increase, negative to decrease) */
static int nvme_adjust_hugepages(long delta)
{
	unsigned long current_pages = 0;
	long new_pages;
	FILE *fp;
	char buf[64];

	if (delta == 0)
		return 0;

	fp = fopen("/proc/sys/vm/nr_hugepages", "r");
	if (!fp)
		return -errno;
	if (fgets(buf, sizeof(buf), fp))
		current_pages = strtoul(buf, NULL, 10);
	fclose(fp);

	new_pages = (long)current_pages + delta;
	if (new_pages < 0)
		new_pages = 0;

	fp = fopen("/proc/sys/vm/nr_hugepages", "w");
	if (!fp)
		return -errno;

	fprintf(fp, "%ld\n", new_pages);
	fclose(fp);

	return 0;
}

static int nvme_ensure_hugepages(size_t needed_bytes, size_t hugepage_size,
				 unsigned long *extra_allocated)
{
	size_t needed_pages = (needed_bytes + hugepage_size - 1) / hugepage_size;
	unsigned long free_pages, extra;
	int ret;

	*extra_allocated = 0;

	free_pages = nvme_get_free_hugepages();
	if (free_pages >= needed_pages)
		return 0;

	extra = needed_pages - free_pages;

	ret = nvme_adjust_hugepages(extra);
	if (ret < 0)
		return ret;

	/* Verify allocation succeeded */
	free_pages = nvme_get_free_hugepages();
	if (free_pages < needed_pages) {
		ublk_err("Failed to allocate %zu hugepages (only %lu free)\n",
			needed_pages, free_pages);
		return -ENOMEM;
	}

	*extra_allocated = extra;
	return 0;
}

/*
 * Two-phase hugepage pool init.
 *
 * Phase 1 (early_init): Allocate the full hugepage pool sized from CLI
 * args (the maximum). Compute admin-only layout so controller init and
 * Identify can use the pool head.
 *
 * Phase 2 (finish_init): Recompute layout with final params (nr_io_queues
 * may have been clamped by Set Features). No memory operations — pool is
 * already big enough. This is effectively a nop.
 */
static int nvme_hugepage_pool_early_init(struct nvme_vfio_tgt_data *data)
{
	size_t io_buf_size = data->zero_copy ? 0 : data->max_io_buf_bytes;
	size_t hps = data->hugepage_size;
	size_t total;
	int ret;

	/* Compute full layout using CLI args (maximum sizes) */
	nvme_compute_pool_layout(&data->layout, data->nr_io_queues,
				 data->queue_depth, io_buf_size);
	total = (data->layout.total_size + hps - 1) & ~(hps - 1);

	ret = nvme_ensure_hugepages(total, hps, &data->extra_hugepages);
	if (ret < 0)
		return ret;

	ret = dma_buf_pool_init(&data->dma_pool, total);
	if (ret < 0) {
		nvme_adjust_hugepages(-(long)data->extra_hugepages);
		return ret;
	}

	if (!nvme_use_iommu(data)) {
		if (dma_buf_pool_read_pagemap(&data->dma_pool) < 0) {
			dma_buf_pool_deinit(&data->dma_pool);
			nvme_adjust_hugepages(-(long)data->extra_hugepages);
			return -1;
		}
	}

	nvme_log("DMA pool: hugepage_size=%zuKB, total_size=%zuMB, extra=%lu\n",
		 hps >> 10, total >> 20, data->extra_hugepages);

	return 0;
}

static int nvme_hugepage_pool_finish_init(struct nvme_vfio_tgt_data *data)
{
	size_t io_buf_size = data->zero_copy ? 0 : data->max_io_buf_bytes;

	/* Recompute layout with final nr_io_queues (may be clamped) */
	nvme_compute_pool_layout(&data->layout, data->nr_io_queues,
				 data->queue_depth, io_buf_size);

	nvme_log("DMA pool layout: %zuMB used of %zuMB allocated "
		 "(%d queues x %d depth)\n",
		 data->layout.total_size >> 20, data->dma_pool.size >> 20,
		 data->nr_io_queues, data->queue_depth);

	return 0;
}

static void nvme_pool_deinit(struct nvme_vfio_tgt_data *data)
{
	dma_buf_pool_deinit(&data->dma_pool);
}

/* Get PRP list buffer for given queue/tag — uses layout offsets */
static void *nvme_pool_get_prp(struct nvme_vfio_tgt_data *data, int qid, int tag)
{
	size_t offset = data->layout.prp_off +
			qid * data->layout.prp_stride +
			tag * PAGE_SIZE;

	return (char *)data->dma_pool.base + offset;
}

/* Get I/O buffer for given queue/tag — uses layout offsets */
static inline void *nvme_pool_get_io_buf(struct nvme_vfio_tgt_data *data,
					  int qid, int tag)
{
	size_t offset = data->layout.io_buf_off +
			qid * data->layout.io_buf_stride +
			tag * data->max_io_buf_bytes;

	return (char *)data->dma_pool.base + offset;
}

/* Get identify buffer */
static void *nvme_pool_get_identify_buf(struct nvme_vfio_tgt_data *data)
{
	return (char *)data->dma_pool.base + data->layout.identify_off;
}

/*
 * Map buffer for DMA
 */
static __u64 nvme_map_dma(struct nvme_vfio_tgt_data *data,
			  void *vaddr, size_t size,
			  struct nvme_dma_mapping *mapping)
{
	__u64 iova;

	if (!mapping)
		return 0;

	iova = nvme_get_iova(data, vaddr, size);
	if (!iova)
		return 0;

	if (nvme_do_vfio_map(data, vaddr, iova, size) < 0)
		return 0;

	mapping->vaddr = (__u64)vaddr;
	mapping->iova = iova;
	mapping->size = size;

	return iova;
}

/* Unmap DMA buffer */
static void nvme_unmap_dma(struct nvme_vfio_tgt_data *data,
			   struct nvme_dma_mapping *mapping)
{
	if (!mapping || !mapping->iova)
		return;

	if (nvme_use_iommu(data)) {
		struct iommu_ioas_unmap unmap = {};

		unmap.size = sizeof(unmap);
		unmap.ioas_id = data->ioas_id;
		unmap.iova = mapping->iova;
		unmap.length = mapping->size;
		ioctl(data->iommufd, IOMMU_IOAS_UNMAP, &unmap);
	}

	mapping->vaddr = 0;
	mapping->iova = 0;
	mapping->size = 0;
}

/*
 * Initialize NVMe queue pair
 */
/*
 * Initialize an NVMe queue pair using layout offsets.
 *
 * For admin queue (qid=0): uses layout.admin_sq_off / admin_cq_off
 * For IO queues (qid>0): uses layout.io_sq_off + idx * io_sq_stride
 *
 * In BPF mode, the arena is already IOMMU-mapped as a single region,
 * so we derive IOVAs from the arena base IOVA + offset instead of
 * calling nvme_map_dma() per buffer.
 */
static int nvme_queue_init(struct nvme_vfio_tgt_data *data,
			   struct nvme_queue *q, __u16 qid, __u16 depth)
{
	volatile void *bar = data->bar0;
	struct nvme_pool_layout *L = &data->layout;
	size_t sq_off, cq_off, sq_buf_size, cq_buf_size;

	if (qid == 0) {
		/* Admin queue */
		sq_off = L->admin_sq_off;
		cq_off = L->admin_cq_off;
		sq_buf_size = L->admin_sq_size;
		cq_buf_size = L->admin_cq_size;
	} else {
		/* IO queue — qid is 1-based, array index is qid-1 */
		int idx = qid - 1;

		sq_off = L->io_sq_off + idx * L->io_sq_stride;
		cq_off = L->io_cq_off + idx * L->io_cq_stride;
		sq_buf_size = L->io_sq_stride;
		cq_buf_size = L->io_cq_stride;
	}

	q->sq_buffer = (char *)data->dma_pool.base + sq_off;
	q->cq_buffer = (char *)data->dma_pool.base + cq_off;
	memset(q->sq_buffer, 0, sq_buf_size);
	memset(q->cq_buffer, 0, cq_buf_size);

	if (data->bpf_mode) {
		/* Arena is already IOMMU-mapped — derive IOVAs from base */
		__u64 arena_iova = data->arena_dma_mapping.iova;

		q->sq_iova = arena_iova + sq_off;
		q->cq_iova = arena_iova + cq_off;
	} else {
		q->sq_iova = nvme_map_dma(data, q->sq_buffer, sq_buf_size,
					  &q->sq_mapping);
		q->cq_iova = nvme_map_dma(data, q->cq_buffer, cq_buf_size,
					  &q->cq_mapping);
		if (!q->sq_iova || !q->cq_iova) {
			ublk_err("Failed to map queue %d for DMA\n", qid);
			nvme_unmap_dma(data, &q->sq_mapping);
			nvme_unmap_dma(data, &q->cq_mapping);
			return -ENOMEM;
		}
	}

	q->qid = qid;
	q->qsize = depth;
	q->sq_tail = 0;
	q->last_sq_tail = 0;
	q->cq_head = 0;
	q->cq_phase = 1;

	ublk_wmb();

	q->sq_doorbell = (volatile __u32 *)
		((char *)bar + 0x1000 + (2 * qid * data->db_stride));
	q->cq_doorbell = (volatile __u32 *)
		((char *)bar + 0x1000 + ((2 * qid + 1) * data->db_stride));

	return 0;
}

static void nvme_queue_deinit(struct nvme_vfio_tgt_data *data,
			      struct nvme_queue *q)
{
	if (!q)
		return;

	nvme_unmap_dma(data, &q->sq_mapping);
	nvme_unmap_dma(data, &q->cq_mapping);

	q->sq_buffer = NULL;
	q->cq_buffer = NULL;
	q->sq_iova = 0;
	q->cq_iova = 0;
}

/* Wait for admin command completion */
static int nvme_wait_admin_completion(struct nvme_vfio_tgt_data *data)
{
	struct nvme_queue *adminq = &data->admin_queue;
	struct nvme_completion *cq = (struct nvme_completion *)adminq->cq_buffer;
	int timeout = 5000;

	while (timeout-- > 0) {
		struct nvme_completion *cqe = &cq[adminq->cq_head];
		__u8 phase = (cqe->status >> 0) & 1;

		if (phase == adminq->cq_phase) {
			__u16 status = (cqe->status >> 1);

			adminq->last_cqe_result = cqe->result;
			adminq->cq_head = (adminq->cq_head + 1) % adminq->qsize;
			if (adminq->cq_head == 0)
				adminq->cq_phase = !adminq->cq_phase;

			nvme_writel_mmio(adminq->cq_head, adminq->cq_doorbell);

			return (status == 0) ? 0 : -EIO;
		}

		usleep(1000);
	}

	ublk_err("Admin command timeout\n");
	return -ETIMEDOUT;
}

/* Submit admin command */
static int nvme_submit_admin_cmd(struct nvme_vfio_tgt_data *data,
				 void *cmd, size_t cmd_size)
{
	struct nvme_queue *adminq = &data->admin_queue;

	memcpy((char *)adminq->sq_buffer + (adminq->sq_tail * 64), cmd, cmd_size);

	adminq->sq_tail = (adminq->sq_tail + 1) % adminq->qsize;
	nvme_writel_mmio(adminq->sq_tail, adminq->sq_doorbell);

	return nvme_wait_admin_completion(data);
}

/* Create admin queue */
static int nvme_create_admin_queue(struct nvme_vfio_tgt_data *data)
{
	struct nvme_queue *q = &data->admin_queue;
	volatile void *bar = data->bar0;
	int ret;

	ret = nvme_queue_init(data, q, 0, ADMIN_Q_SIZE);
	if (ret < 0)
		return ret;

	nvme_writel(bar, NVME_REG_AQA,
		    ((ADMIN_Q_SIZE - 1) << 16) | (ADMIN_Q_SIZE - 1));
	nvme_writeq(bar, NVME_REG_ASQ, q->sq_iova);
	nvme_writeq(bar, NVME_REG_ACQ, q->cq_iova);

	return 0;
}

/* Initialize NVMe controller */
static int nvme_init_controller(struct nvme_vfio_tgt_data *data)
{
	volatile void *bar = data->bar0;
	__u32 cc, csts;
	int timeout;

	/* Disable controller */
	cc = nvme_readl(bar, NVME_REG_CC);
	cc &= ~NVME_CC_ENABLE;
	nvme_writel(bar, NVME_REG_CC, cc);

	/* Wait for ready = 0 */
	timeout = 5000;
	do {
		csts = nvme_readl(bar, NVME_REG_CSTS);
		if (!(csts & NVME_CSTS_RDY))
			break;
		usleep(1000);
	} while (timeout-- > 0);

	if (timeout <= 0) {
		ublk_err("Controller failed to disable\n");
		return -1;
	}

	if (nvme_create_admin_queue(data) < 0) {
		return -1;
	}

	/* Configure and enable controller */
	cc = NVME_CC_ENABLE | NVME_CC_CSS_NVM | NVME_CC_MPS_4K |
	     NVME_CC_IOSQES | NVME_CC_IOCQES;
	nvme_writel(bar, NVME_REG_CC, cc);

	/* Wait for ready = 1 */
	timeout = 5000;
	do {
		csts = nvme_readl(bar, NVME_REG_CSTS);
		if (csts & NVME_CSTS_RDY)
			break;
		usleep(1000);
	} while (timeout-- > 0);

	if (timeout <= 0) {
		ublk_err("Controller failed to become ready\n");
		return -1;
	}

	return 0;
}

/*
 * Negotiate I/O queue count with the controller via Set Features.
 *
 * NVMe spec §5.21.1.7: The host must issue Set Features (Number of
 * Queues) before creating any I/O queues. The controller returns the
 * number it can actually support (may be less than requested).
 */
static int nvme_set_num_queues(struct nvme_vfio_tgt_data *data)
{
	struct nvme_features cmd = {};
	int requested = data->nr_io_queues;
	__u32 result;
	int granted_sq, granted_cq, granted;

	cmd.opcode = NVME_ADMIN_SET_FEATURES;
	cmd.fid = NVME_FEAT_NUM_QUEUES;
	cmd.dword11 = ((__u32)(requested - 1) << 16) | (requested - 1);

	int ret = nvme_submit_admin_cmd(data, &cmd, sizeof(cmd));
	if (ret < 0) {
		ublk_err("Set Features (Number of Queues) failed\n");
		return ret;
	}

	result = data->admin_queue.last_cqe_result;
	granted_sq = (result & 0xFFFF) + 1;
	granted_cq = ((result >> 16) & 0xFFFF) + 1;
	granted = granted_sq < granted_cq ? granted_sq : granted_cq;

	if (granted < requested) {
		nvme_log("Controller granted %d I/O queues (requested %d)\n",
			 granted, requested);
		data->nr_io_queues = granted;
	} else {
		nvme_log("Controller supports %d I/O queues\n", granted);
	}

	return 0;
}

/* Identify controller - get controller capabilities including VWC */
static int nvme_identify_controller(struct nvme_vfio_tgt_data *data)
{
	struct nvme_identify cmd = {};
	struct nvme_id_ctrl *ctrl;
	struct nvme_dma_mapping ctrl_mapping = {};
	__u64 ctrl_iova;
	int ret;

	ctrl = (struct nvme_id_ctrl *)nvme_pool_get_identify_buf(data);
	if (!ctrl) {
		ublk_err("Failed to get identify buffer from pool\n");
		return -ENOMEM;
	}
	memset(ctrl, 0, PAGE_SIZE);

	ctrl_iova = nvme_map_dma(data, ctrl, PAGE_SIZE, &ctrl_mapping);
	if (!ctrl_iova) {
		return -ENOMEM;
	}

	cmd.opcode = NVME_ADMIN_IDENTIFY;
	cmd.nsid = 0;
	cmd.prp1 = ctrl_iova;
	cmd.cns = NVME_ID_CNS_CTRL;

	ret = nvme_submit_admin_cmd(data, &cmd, sizeof(cmd));
	if (ret < 0) {
		ublk_err("Identify controller failed\n");
		goto fail_unmap;
	}

	/* Store volatile write cache capability */
	data->vwc = ctrl->vwc;
	data->mdts = ctrl->mdts;
	data->sgls = ctrl->sgls;

	nvme_log("Controller: VWC=%s, MDTS=%u (%uKB), SGL=%s\n",
			(data->vwc & NVME_CTRL_VWC_PRESENT) ? "yes" : "no",
			data->mdts, data->mdts ? (1U << data->mdts) * 4 : 0,
			nvme_sgl_supported(data) ? "yes" : "no");

	nvme_unmap_dma(data, &ctrl_mapping);
	return 0;

fail_unmap:
	nvme_unmap_dma(data, &ctrl_mapping);
	return ret;
}

/* Identify namespace */
static int nvme_identify_namespace(struct nvme_vfio_tgt_data *data,
				   struct ublk_params *params)
{
	unsigned int max_bytes = data->max_io_buf_bytes;
	struct nvme_identify cmd = {};
	struct nvme_id_ns *ns;
	struct nvme_dma_mapping ns_mapping = {};
	__u64 ns_iova;
	__u8 lba_format;
	int ret = -ENOMEM;

	ns = (struct nvme_id_ns *)nvme_pool_get_identify_buf(data);
	if (!ns) {
		ublk_err("Failed to get identify buffer from pool\n");
		return -ENOMEM;
	}
	memset(ns, 0, PAGE_SIZE);

	ns_iova = nvme_map_dma(data, ns, PAGE_SIZE, &ns_mapping);
	if (!ns_iova) {
		return -ENOMEM;
	}

	cmd.opcode = NVME_ADMIN_IDENTIFY;
	cmd.nsid = 1;
	cmd.prp1 = ns_iova;
	cmd.cns = NVME_ID_CNS_NS;

	ret = nvme_submit_admin_cmd(data, &cmd, sizeof(cmd));
	if (ret < 0) {
		ublk_err("Identify namespace failed\n");
		goto fail_unmap;
	}

	data->nsid = 1;
	lba_format = ns->flbas & 0x0F;
	data->lba_shift = ns->lbaf[lba_format].ds;
	data->dev_size = le64toh(ns->nsze) << data->lba_shift;

	nvme_log("Namespace 1: size=%llu bytes, LBA size=%u bytes\n",
	       (unsigned long long)data->dev_size, 1U << data->lba_shift);

	/* Populate ublk parameters */
	/* TODO: re-enable discard after BPF DSM encoding is validated */
	params->types = UBLK_PARAM_TYPE_BASIC;
	params->basic.logical_bs_shift = data->lba_shift;
	params->basic.physical_bs_shift = data->lba_shift;
	params->basic.io_opt_shift = data->lba_shift;
	params->basic.io_min_shift = data->lba_shift;
	params->basic.dev_sectors = data->dev_size >> 9;
	/*
	 * Enforce MDTS (Maximum Data Transfer Size) limit.
	 * MDTS is a power-of-2 exponent; max transfer = (1 << mdts) * PAGE_SIZE.
	 * If MDTS is 0, there's no controller limit (use buffer size).
	 */
	if (data->mdts) {
		unsigned int mdts_bytes = (1U << data->mdts) * PAGE_SIZE;

		if (mdts_bytes < max_bytes)
			max_bytes = mdts_bytes;
	}
	params->basic.max_sectors = max_bytes >> 9;

	/*
	 * Segment parameters and virt_boundary_mask are only needed for PRP
	 * mode. SGL can describe arbitrary addresses without page alignment.
	 */
	if (!nvme_sgl_supported(data)) {
		params->types |= UBLK_PARAM_TYPE_SEGMENT;
		params->basic.virt_boundary_mask = PAGE_SIZE - 1;
		params->seg.seg_boundary_mask = PAGE_SIZE - 1;
		params->seg.max_segment_size = 32 << 20;
		params->seg.max_segments = 127;
	}

	/* Set write cache attributes if VWC is present */
	if (data->vwc & NVME_CTRL_VWC_PRESENT)
		params->basic.attrs = UBLK_ATTR_VOLATILE_CACHE | UBLK_ATTR_FUA;

	/* Discard parameters - single segment only (ublk limitation) */
	params->discard.discard_alignment = 0;
	params->discard.discard_granularity = 1U << data->lba_shift;
	params->discard.max_discard_sectors = UINT_MAX >> 9;
	params->discard.max_discard_segments = 1;

	nvme_unmap_dma(data, &ns_mapping);
	return 0;
fail_unmap:
	nvme_unmap_dma(data, &ns_mapping);
	return ret;
}

/* Create I/O queue pair */
static int nvme_create_io_queue(struct nvme_vfio_tgt_data *data,
				int qid, int qsize)
{
	struct nvme_create_cq create_cq = {};
	struct nvme_create_sq create_sq = {};
	struct nvme_queue *ioq = &data->io_queues[qid - 1];
	int ret;

	ret = nvme_queue_init(data, ioq, qid, qsize);
	if (ret < 0)
		return ret;

	create_cq.opcode = NVME_ADMIN_CREATE_CQ;
	create_cq.prp1 = ioq->cq_iova;
	create_cq.cqid = qid;
	create_cq.qsize = qsize - 1;
	create_cq.cq_flags = 0x01;
	create_cq.irq_vector = 0;

	ret = nvme_submit_admin_cmd(data, &create_cq, sizeof(create_cq));
	if (ret < 0) {
		ublk_err("Create I/O CQ %d failed\n", qid);
		goto err_deinit;
	}

	create_sq.opcode = NVME_ADMIN_CREATE_SQ;
	create_sq.prp1 = ioq->sq_iova;
	create_sq.sqid = qid;
	create_sq.qsize = qsize - 1;
	create_sq.sq_flags = 0x01;
	create_sq.cqid = qid;

	ret = nvme_submit_admin_cmd(data, &create_sq, sizeof(create_sq));
	if (ret < 0) {
		ublk_err("Create I/O SQ %d failed\n", qid);
		goto err_deinit;
	}

	return 0;

err_deinit:
	nvme_queue_deinit(data, ioq);
	return -1;
}

/* Delete I/O queue */
static int nvme_delete_io_queue(struct nvme_vfio_tgt_data *data, int qid)
{
	struct nvme_delete_queue cmd = {};

	cmd.opcode = NVME_ADMIN_DELETE_SQ;
	cmd.qid = qid;
	nvme_submit_admin_cmd(data, &cmd, sizeof(cmd));

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = NVME_ADMIN_DELETE_CQ;
	cmd.qid = qid;
	nvme_submit_admin_cmd(data, &cmd, sizeof(cmd));

	return 0;
}

/*
 * Load BPF struct_ops program for NVMe SQ submission from BPF.
 *
 * The BPF program uses an arena map for the SQ buffer. We:
 * 1. Open/load the BPF skeleton (allocates arena pages)
 * 2. Set .rodata params (nsid, lba_shift) before load
 * 3. mmap the arena to get userspace VA of SQ entries
 * 4. IOMMU-map the arena pages so NVMe hardware can read them
 * 5. Set per-queue state in .bss (IOVA, qsize, doorbell offset)
 * 6. Create NVMe I/O queues pointing SQ at arena IOVA
 * 7. Attach the struct_ops
 */
/*
 * Two-phase arena pool init.
 *
 * Phase 1 (early_init): Load BPF skeleton, get arena mmap, fault admin
 * pages, IOMMU-map full arena capacity. Init pool as external.
 * Called BEFORE controller init — rodata uses defaults (nsid=1, lba_shift=9).
 *
 * Phase 2 (finish_init): Compute full layout with final params, fault
 * remaining pages, update pool size. Validate rodata matches Identify.
 */
static int nvme_arena_pool_early_init(struct nvme_vfio_tgt_data *data)
{
	struct ublk_nvme_vfio *skel;
	void *arena_mmap;
	size_t admin_size, arena_capacity;
	__u64 arena_iova;
	int ret;

	nvme_log("BPF: opening skeleton...\n");
	skel = ublk_nvme_vfio::open();
	if (!skel) {
		ret = -errno;
		ublk_err("BPF: failed to open skeleton: %s (errno=%d)\n",
			 strerror(errno), errno);
		return ret;
	}

	/* Set .rodata defaults before load — validated after Identify */
	skel->rodata->nsid = 1;
	skel->rodata->lba_shift = 9;

	nvme_log("BPF: loading (default nsid=1 lba_shift=9)...\n");
	ret = ublk_nvme_vfio::load(skel);
	if (ret) {
		ublk_err("BPF: failed to load: %d (%s)\n",
			 ret, strerror(-ret));
		ublk_nvme_vfio::destroy(skel);
		return ret;
	}

	/* Get arena mmap pointer from libbpf */
	{
		size_t mmap_sz;

		arena_mmap = bpf_map__initial_value(skel->maps.arena, &mmap_sz);
	}
	if (!arena_mmap) {
		ublk_err("BPF: arena not mapped by skeleton\n");
		ublk_nvme_vfio::destroy(skel);
		return -ENOMEM;
	}

	data->bpf_skel = skel;
	data->arena_mmap = arena_mmap;

	/* Compute admin-only layout */
	nvme_compute_pool_layout(&data->layout, 0, 0, 0);
	admin_size = data->layout.total_size;

	/* Fault-in admin pages only */
	for (size_t off = 0; off < admin_size; off += PAGE_SIZE)
		((volatile char *)arena_mmap)[off];

	/*
	 * IOMMU-map the full arena capacity upfront.
	 * Unfaulted pages cost only IOMMU page table entries, not RAM.
	 */
	arena_capacity = (__u32)bpf_map__max_entries(skel->maps.arena) *
			 PAGE_SIZE;
	data->arena_mmap_size = arena_capacity;

	arena_iova = nvme_map_dma(data, arena_mmap, arena_capacity,
				  &data->arena_dma_mapping);
	if (!arena_iova) {
		ublk_err("BPF: IOMMU-map arena failed\n");
		ublk_nvme_vfio::destroy(skel);
		data->bpf_skel = NULL;
		return -ENOMEM;
	}

	/* Init pool as external (arena owns the mmap) */
	dma_buf_pool_init_external(&data->dma_pool, arena_mmap, admin_size);

	nvme_log("BPF: arena at %p, admin=%zu bytes, capacity=%zu bytes, "
		 "IOVA=0x%llx\n", arena_mmap, admin_size, arena_capacity,
		 (unsigned long long)arena_iova);

	return 0;
}

static int nvme_arena_pool_finish_init(struct nvme_vfio_tgt_data *data)
{
	size_t admin_size, arena_capacity;

	/*
	 * Validate BPF rodata matches Identify results.
	 * rodata was frozen at load time with defaults (nsid=1, lba_shift=9).
	 */
	if (data->nsid != 1)
		nvme_log("WARNING: nsid=%u but BPF rodata has nsid=1\n",
			 data->nsid);
	if (data->lba_shift != 9)
		nvme_log("WARNING: lba_shift=%u but BPF rodata has lba_shift=9\n",
			 data->lba_shift);

	/* Compute full layout (no IO buffers in BPF mode) */
	nvme_compute_pool_layout(&data->layout, data->nr_io_queues,
				 data->queue_depth, 0);

	/* Validate against arena capacity */
	arena_capacity = data->arena_mmap_size;
	if (data->layout.total_size > arena_capacity) {
		ublk_err("Arena too small: need %zu, have %zu "
			 "(%d queues x %d depth)\n",
			 data->layout.total_size, arena_capacity,
			 data->nr_io_queues, data->queue_depth);
		return -ENOSPC;
	}

	/* Fault-in remaining arena pages (admin pages already faulted) */
	admin_size = nvme_admin_pool_size();
	for (size_t off = admin_size; off < data->layout.total_size;
	     off += PAGE_SIZE)
		((volatile char *)data->arena_mmap)[off];

	/* Update pool size to full layout */
	data->dma_pool.size = data->layout.total_size;

	nvme_log("BPF: arena %zu pages faulted (%zuKB) of %zu capacity\n",
		 data->layout.total_size / PAGE_SIZE,
		 data->layout.total_size >> 10,
		 arena_capacity / PAGE_SIZE);

	return 0;
}

/*
 * Create BPF-mode I/O queues using unified layout offsets.
 * Sets sq_state map entries and issues NVMe Create CQ/SQ admin commands.
 */
static int nvme_bpf_create_io_queues(struct nvme_vfio_tgt_data *data)
{
	__u64 arena_iova = data->arena_dma_mapping.iova;
	struct nvme_pool_layout *L = &data->layout;
	int ret;

	for (int i = 0; i < data->nr_io_queues; i++) {
		int qid = i + 1;
		int qsize = data->queue_depth + 1;

		/* Set BPF sq_state map entry with layout offsets */
		struct sq_state qs = {};

		qs.sq_dma = arena_iova + L->io_sq_off + i * L->io_sq_stride;
		qs.prp_base_iova = arena_iova + L->prp_off +
				    i * L->prp_stride;
		qs.sq_arena_off = L->io_sq_off + i * L->io_sq_stride;
		qs.cq_arena_off = L->io_cq_off + i * L->io_cq_stride;
		qs.prp_arena_off = L->prp_off + i * L->prp_stride;
		qs.sq_tail = 0;
		qs.last_sq_tail = 0;
		qs.qsize = qsize;
		qs.qdepth = data->queue_depth;
		qs.db_offset = 0x1000 + (2 * qid) * data->db_stride;

		int map_fd = bpf_map__fd(data->bpf_skel->maps.sq_queues);
		__u32 key = i;

		if (bpf_map_update_elem(map_fd, &key, &qs, BPF_ANY) < 0) {
			ublk_err("BPF: failed to init sq_queues[%d]\n", i);
			return -1;
		}

		/* Create NVMe IO queue using nvme_queue_init (uses layout) */
		ret = nvme_queue_init(data, &data->io_queues[i], qid, qsize);
		if (ret < 0)
			return ret;

		/* Issue NVMe Create CQ + SQ admin commands */
		struct nvme_create_cq create_cq = {};

		create_cq.opcode = NVME_ADMIN_CREATE_CQ;
		create_cq.prp1 = data->io_queues[i].cq_iova;
		create_cq.cqid = qid;
		create_cq.qsize = qsize - 1;
		create_cq.cq_flags = 0x01;
		create_cq.irq_vector = 0;

		ret = nvme_submit_admin_cmd(data, &create_cq, sizeof(create_cq));
		if (ret < 0) {
			ublk_err("BPF: Create I/O CQ %d failed\n", qid);
			return ret;
		}

		struct nvme_create_sq create_sq = {};

		create_sq.opcode = NVME_ADMIN_CREATE_SQ;
		create_sq.prp1 = data->io_queues[i].sq_iova;
		create_sq.sqid = qid;
		create_sq.qsize = qsize - 1;
		create_sq.sq_flags = 0x01;
		create_sq.cqid = qid;

		ret = nvme_submit_admin_cmd(data, &create_sq, sizeof(create_sq));
		if (ret < 0) {
			ublk_err("BPF: Create I/O SQ %d failed\n", qid);
			return ret;
		}
	}

	return 0;
}

static int nvme_bpf_attach(struct nvme_vfio_tgt_data *data)
{
	nvme_log("BPF: attaching struct_ops...\n");
	data->bpf_link = bpf_map__attach_struct_ops(
				data->bpf_skel->maps.ublk_nvme_vfio_bpf_ops);
	if (!data->bpf_link) {
		int ret = -errno;

		ublk_err("BPF: failed to attach struct_ops: %d\n", ret);
		return ret;
	}

	nvme_log("BPF struct_ops attached, arena %zuKB at IOVA 0x%llx\n",
		 data->layout.total_size >> 10,
		 (unsigned long long)data->arena_dma_mapping.iova);
	return 0;
}

static void nvme_bpf_cleanup(struct nvme_vfio_tgt_data *data)
{
	if (data->bpf_skel) {
		nvme_log("BPF stats: %llu SQ submissions, %llu doorbell rings\n",
			 (unsigned long long)data->bpf_skel->bss->bpf_sq_submissions,
			 (unsigned long long)data->bpf_skel->bss->bpf_doorbell_rings);
	}
	if (data->bpf_link) {
		bpf_link__destroy(data->bpf_link);
		data->bpf_link = NULL;
	}
	if (data->arena_mmap) {
		nvme_unmap_dma(data, &data->arena_dma_mapping);
		/* arena mmap is owned by skeleton — don't munmap */
		data->arena_mmap = NULL;
	}
	if (data->bpf_skel) {
		ublk_nvme_vfio::destroy(data->bpf_skel);
		data->bpf_skel = NULL;
	}
}
/*
 * Perform NVMe controller shutdown sequence.
 * Sets SHN to normal, waits for shutdown complete, then disables controller.
 */
static void nvme_shutdown_controller(struct nvme_vfio_tgt_data *data)
{
	volatile void *bar = data->bar0;
	__u32 cc, csts;
	int i;

	if (!bar)
		return;

	/* Set shutdown notification */
	cc = nvme_readl(bar, NVME_REG_CC);
	cc |= NVME_CC_SHN_NORMAL;
	nvme_writel(bar, NVME_REG_CC, cc);

	/* Wait for shutdown complete */
	for (i = 0; i < 5000; i++) {
		csts = nvme_readl(bar, NVME_REG_CSTS);
		if ((csts & NVME_CSTS_SHST_MASK) == NVME_CSTS_SHST_COMPLETE)
			break;
		usleep(1000);
	}

	/* Disable controller */
	cc &= ~NVME_CC_ENABLE;
	nvme_writel(bar, NVME_REG_CC, cc);

	/* Wait for ready to clear */
	for (i = 0; i < 5000; i++) {
		csts = nvme_readl(bar, NVME_REG_CSTS);
		if (!(csts & NVME_CSTS_RDY))
			break;
		usleep(1000);
	}
}

/*
 * Clean up all nvme_vfio resources.
 * Called from both error path in init and normal deinit.
 * If shutdown_ctrl is true, perform proper controller shutdown sequence.
 */
static void nvme_vfio_cleanup(struct nvme_vfio_tgt_data *data, bool shutdown_ctrl)
{
	int i;

	if (!data)
		return;

	if (data->bpf_mode)
		nvme_bpf_cleanup(data);

	/* Delete I/O queues */
	if (data->io_queues) {
		for (i = 0; i < data->nr_io_queues; i++) {
			nvme_delete_io_queue(data, i + 1);
			if (data->bpf_mode) {
				/* SQ and CQ both in arena — no separate unmap */
			} else
				nvme_queue_deinit(data, &data->io_queues[i]);
		}
		free(data->io_queues);
	}

	if (shutdown_ctrl)
		nvme_shutdown_controller(data);

	nvme_queue_deinit(data, &data->admin_queue);

	if (data->bar0 && data->bar0 != MAP_FAILED)
		munmap((void *)data->bar0, data->bar0_size);

	if (data->iommufd >= 0) {
		/* iommufd path: detach device, destroy IOAS, then close fds */
		struct vfio_device_detach_iommufd_pt detach = {};
		struct iommu_destroy destroy = {};

		detach.argsz = sizeof(detach);
		ioctl(data->device_fd, VFIO_DEVICE_DETACH_IOMMUFD_PT, &detach);

		destroy.size = sizeof(destroy);
		destroy.id = data->ioas_id;
		ioctl(data->iommufd, IOMMU_DESTROY, &destroy);

		if (data->device_fd >= 0)
			close(data->device_fd);
		close(data->iommufd);
	} else {
		/* Legacy noiommu path */
		if (data->device_fd >= 0)
			close(data->device_fd);
		if (data->group_fd >= 0)
			close(data->group_fd);
		if (data->container_fd >= 0)
			close(data->container_fd);
	}

	pthread_spin_destroy(&data->iova_lock);
	nvme_pool_deinit(data);
	nvme_adjust_hugepages(-(long)data->extra_hugepages);

	free(data);
}

/* Flush any pending SQ submissions */
static inline void nvme_sq_flush(struct nvme_queue *nvmeq)
{
	if (nvmeq->sq_tail != nvmeq->last_sq_tail) {
		nvme_writel_mmio(nvmeq->sq_tail, nvmeq->sq_doorbell);
		nvmeq->last_sq_tail = nvmeq->sq_tail;
	}
}

/* Submit command to SQ */
static inline void nvme_sq_submit_cmd(struct nvme_queue *nvmeq)
{
	__u16 next_tail, pending;

	if (++nvmeq->sq_tail == nvmeq->qsize)
		nvmeq->sq_tail = 0;

	/* Flush when batch reaches 32 or SQ is full */
	pending = (nvmeq->sq_tail + nvmeq->qsize - nvmeq->last_sq_tail)
		  % nvmeq->qsize;
	if (pending < 32) {
		next_tail = nvmeq->sq_tail + 1;
		if (next_tail == nvmeq->qsize)
			next_tail = 0;
		if (next_tail != nvmeq->last_sq_tail)
			return;
	}

	nvme_sq_flush(nvmeq);
}

/* Check if CQE is pending */
static inline bool nvme_cqe_pending(struct nvme_queue *nvmeq)
{
	struct nvme_completion *cqe = &((struct nvme_completion *)nvmeq->cq_buffer)[nvmeq->cq_head];

	return (le16toh(READ_ONCE(cqe->status)) & 1) == nvmeq->cq_phase;
}

/* Update CQ head and phase */
static inline void nvme_update_cq_head(struct nvme_queue *nvmeq)
{
	__u32 tmp = nvmeq->cq_head + 1;

	if (tmp == nvmeq->qsize) {
		nvmeq->cq_head = 0;
		nvmeq->cq_phase ^= 1;
	} else {
		nvmeq->cq_head = tmp;
	}
}

/* Perform synchronous user copy between ublk device and NVMe IO buffer.
 * fds[0] always contains the ublk char device fd (set by library). */
static int nvme_user_copy_sync(const struct ublksrv_queue *q, int tag,
			       void *io_buf, size_t len, bool to_ublk)
{
	int cdev_fd = q->dev->tgt.fds[0];
	__u64 pos = ublk_pos(q->q_id, tag, 0);
	ssize_t ret;

	if (to_ublk) {
		/* READ completion: copy from NVMe buffer to ublk device */
		ret = pwrite(cdev_fd, io_buf, len, pos);
	} else {
		/* WRITE request: copy from ublk device to NVMe buffer */
		ret = pread(cdev_fd, io_buf, len, pos);
	}

	if (ret < 0) {
		ublk_err("user copy %s failed: %s\n",
			 to_ublk ? "pwrite" : "pread", strerror(errno));
		return -errno;
	}
	if ((size_t)ret != len) {
		ublk_err("user copy short %s: %zd/%zu\n",
			 to_ublk ? "pwrite" : "pread", ret, len);
		return -EIO;
	}

	return 0;
}

/* Poll completion queue */
static inline int nvme_poll_cq(const struct ublksrv_queue *q,
			       struct nvme_queue *nvmeq,
			       struct nvme_vfio_tgt_data *data)
{
	int nr_cqes = 0;

	while (nvme_cqe_pending(nvmeq)) {
		struct nvme_completion *cqe = &((struct nvme_completion *)nvmeq->cq_buffer)[nvmeq->cq_head];
		__u16 status_field, status, cid;
		int tag, result;
		const struct ublk_io_data *io_data;
		const struct ublksrv_io_desc *iod;

		ublk_dma_rmb();

		status_field = READ_ONCE(cqe->status);
		cid = READ_ONCE(cqe->command_id);
		status = status_field >> 1;
		tag = cid;

		io_data = ublksrv_queue_get_io_data(q, tag);
		iod = io_data->iod;

		if (status == 0) {
			/* Discard returns 0 on success, read/write returns bytes */
			if (ublksrv_get_op(iod) == UBLK_IO_OP_DISCARD) {
				result = 0;
			} else {
				result = iod->nr_sectors << 9;
				/*
				 * For READ with user_copy (non-zero-copy), copy
				 * data from NVMe buffer to ublk device.
				 * In zero-copy mode, the device DMA'd directly
				 * to the bio pages - no copy needed.
				 */
				if (data->user_copy && !data->zero_copy &&
				    ublksrv_get_op(iod) == UBLK_IO_OP_READ) {
					void *io_buf = nvme_pool_get_io_buf(data, q->q_id, tag);
					int ret = nvme_user_copy_sync(q, tag, io_buf, result, true);
					if (ret < 0)
						result = ret;
				}
			}
		} else {
			fprintf(stderr, "NVMe error: op=%d tag=%d status=0x%x\n",
				 ublksrv_get_op(iod), tag, status);
			result = -EIO;
		}

		/*
		 * In BPF mode, check if the FETCH for this tag has been
		 * consumed by the io_uring event loop. If not, defer the
		 * completion — calling ublksrv_complete_io now would send
		 * COMMIT_AND_FETCH while the original FETCH CQE is still
		 * unconsumed in the io_uring CQ ring, corrupting the
		 * io_uring command sequence for this tag.
		 */
		if (data->bpf_mode) {
			struct nvme_io_priv *priv = nvme_get_io_priv(q, tag);

			if (!priv->fetch_done) {
				/* Defer: save result, complete when
				 * FETCH is consumed in queue_io */
				priv->cqe_early = true;
				priv->cqe_result = result;
				nvme_update_cq_head(nvmeq);
				nr_cqes++;
				continue;
			}
			priv->fetch_done = false;
		}

		ublksrv_queue_dec_tgt_io_inflight(q);
		ublksrv_complete_io(q, tag, result);

		nvme_update_cq_head(nvmeq);
		nr_cqes++;
	}

	if (nr_cqes)
		nvme_writel_mmio(nvmeq->cq_head, nvmeq->cq_doorbell);

	return nr_cqes;
}

/* Setup PRP entries for a command */
static inline int nvme_setup_prps(struct nvme_rw_command *cmd,
				  struct nvme_vfio_tgt_data *data,
				  struct nvme_io_priv *priv,
				  void *io_buf, __u64 iova, size_t len)
{
	size_t remaining;
	__u64 first_page_len;

	cmd->prp1 = htole64(iova);
	remaining = len;

	first_page_len = PAGE_SIZE - (iova & (PAGE_SIZE - 1));
	if (first_page_len > remaining)
		first_page_len = remaining;
	remaining -= first_page_len;
	iova += first_page_len;

	if (remaining == 0) {
		cmd->prp2 = 0;
	} else if (remaining <= PAGE_SIZE) {
		if (!nvme_use_iommu(data)) {
			void *vaddr_page2 = (void *)(((__u64)io_buf + first_page_len) & ~(PAGE_SIZE - 1));
			uint64_t paddr2 = dma_buf_pool_virt_to_phys(&data->dma_pool, vaddr_page2);
			if (paddr2 == DMA_BUF_PHYS_ERROR) {
				ublk_err("Failed to get paddr for 2nd page\n");
				return -EINVAL;
			}
			cmd->prp2 = htole64(paddr2);
		} else {
			cmd->prp2 = htole64(iova);
		}
	} else {
		int max_prps = PAGE_SIZE / sizeof(__le64);
		int prp_idx = 0;
		__u64 prp_addr = iova;
		size_t left = remaining;

		cmd->prp2 = htole64(priv->prp_mapping.iova);

		/*
		 * Build PRP list with sequential page-aligned addresses.
		 * With IOMMU (including zero-copy), iommu_map_sg() creates
		 * a contiguous IOVA range, so PRP entries are just
		 * sequential pages from the starting IOVA.
		 */
		while (left > 0 && prp_idx < max_prps) {
			priv->prp_list[prp_idx++] = htole64(prp_addr);
			prp_addr += PAGE_SIZE;
			left = (left > PAGE_SIZE) ? (left - PAGE_SIZE) : 0;
		}
		if (left > 0) {
			ublk_err("PRP list overflow\n");
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * Setup SGL descriptor for a command.
 *
 * In noiommu mode, I/O buffers may span hugepage boundaries where physical
 * addresses are not contiguous. This function detects such cases and builds
 * a 2-entry SGL list to handle the discontinuity.
 *
 * For single-segment I/O (within one hugepage or with IOMMU), uses a single
 * DATA_BLOCK descriptor embedded in command dptr.
 */
static inline int nvme_setup_sgl(struct nvme_rw_command *cmd,
				 struct nvme_vfio_tgt_data *data,
				 struct nvme_io_priv *priv,
				 void *io_buf, __u64 iova, size_t len)
{
	struct nvme_sgl_desc *sgl;
	size_t hps = data->hugepage_size;
	__u64 buf_start = (__u64)io_buf;
	__u64 buf_end = buf_start + len - 1;
	int need_two_segments = 0;

	/* Set SGL flag in command */
	cmd->flags |= NVME_CMD_SGL_METABUF;

	/*
	 * In noiommu mode, check if buffer crosses hugepage boundary.
	 * Different hugepages have non-contiguous physical addresses.
	 */
	if (!nvme_use_iommu(data) && hps > 0) {
		__u64 start_page = buf_start / hps;
		__u64 end_page = buf_end / hps;
		need_two_segments = (start_page != end_page);
	}

	if (!need_two_segments) {
		/* Single segment - use DATA_BLOCK in command dptr */
		sgl = (struct nvme_sgl_desc *)&cmd->prp1;

		sgl->addr = htole64(iova);
		sgl->length = htole32((__u32)len);
		sgl->rsvd[0] = 0;
		sgl->rsvd[1] = 0;
		sgl->rsvd[2] = 0;
		sgl->type = (NVME_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_ADDRESS;
	} else {
		/*
		 * Two segments - build SGL list in prp_list buffer.
		 * Segment 1: from buffer start to hugepage boundary
		 * Segment 2: from hugepage boundary to buffer end
		 */
		struct nvme_sgl_desc *sgl_list = (struct nvme_sgl_desc *)priv->prp_list;
		__u64 hp_boundary = ((buf_start / hps) + 1) * hps;
		size_t seg1_len = hp_boundary - buf_start;
		size_t seg2_len = len - seg1_len;
		void *seg2_vaddr = (void *)hp_boundary;
		__u64 seg2_phys;

		/* Get physical address for second segment */
		seg2_phys = dma_buf_pool_virt_to_phys(&data->dma_pool, seg2_vaddr);
		if (seg2_phys == DMA_BUF_PHYS_ERROR) {
			ublk_err("SGL: failed to get phys for segment 2\n");
			return -EFAULT;
		}

		/* Build SGL entry 0: first segment */
		sgl_list[0].addr = htole64(iova);
		sgl_list[0].length = htole32((__u32)seg1_len);
		sgl_list[0].rsvd[0] = 0;
		sgl_list[0].rsvd[1] = 0;
		sgl_list[0].rsvd[2] = 0;
		sgl_list[0].type = (NVME_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_ADDRESS;

		/* Build SGL entry 1: second segment */
		sgl_list[1].addr = htole64(seg2_phys);
		sgl_list[1].length = htole32((__u32)seg2_len);
		sgl_list[1].rsvd[0] = 0;
		sgl_list[1].rsvd[1] = 0;
		sgl_list[1].rsvd[2] = 0;
		sgl_list[1].type = (NVME_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_ADDRESS;

		/* Point command dptr to SGL list (LAST_SEGMENT descriptor) */
		sgl = (struct nvme_sgl_desc *)&cmd->prp1;
		sgl->addr = htole64(priv->prp_mapping.iova);
		sgl->length = htole32(2 * sizeof(struct nvme_sgl_desc));
		sgl->rsvd[0] = 0;
		sgl->rsvd[1] = 0;
		sgl->rsvd[2] = 0;
		sgl->type = (NVME_SGL_FMT_LAST_SEG_DESC << 4) | NVME_SGL_FMT_ADDRESS;
	}

	return 0;
}

/* Queue read/write I/O */
static int nvme_queue_rw_io(const struct ublksrv_queue *q,
			    struct nvme_queue *nvmeq,
			    const struct ublksrv_io_desc *iod, int tag,
			    struct nvme_vfio_tgt_data *data)
{
	struct nvme_io_priv *priv;
	__u64 slba, iova;
	__u32 nlb;
	size_t len;
	unsigned int op;
	void *io_buf;

	slba = iod->start_sector >> (data->lba_shift - 9);
	nlb = (iod->nr_sectors >> (data->lba_shift - 9)) - 1;
	len = iod->nr_sectors << 9;

	priv = nvme_get_io_priv(q, tag);
	op = ublksrv_get_op(iod);

	if (data->zero_copy) {
		/*
		 * DMA zero-copy: the kernel has already mapped bio pages
		 * into our device's IOAS and placed the IOVA in iod->addr.
		 * No data copy or userspace DMA mapping needed.
		 */
		iova = iod->addr;
		io_buf = NULL;
	} else {
		io_buf = nvme_pool_get_io_buf(data, q->q_id, tag);

		/* Get or create DMA mapping */
		iova = priv->data_mapping.iova;
		if (!iova) {
			size_t buf_size = data->max_io_buf_bytes;

			iova = nvme_map_dma(data, io_buf, buf_size,
					    &priv->data_mapping);
			if (!iova) {
				ublk_err("Failed to map I/O buffer tag %d\n",
					 tag);
				return -ENOMEM;
			}
		}

		/* For WRITE with user_copy, copy data first */
		if (data->user_copy && op == UBLK_IO_OP_WRITE) {
			int ret = nvme_user_copy_sync(q, tag, io_buf, len,
						      false);
			if (ret < 0)
				return ret;
		}
	}

	/* Build command on stack (L1 cache), then copy to SQ (DMA memory) */
	struct nvme_rw_command stack_cmd = {};

	stack_cmd.opcode = (op == UBLK_IO_OP_WRITE) ? NVME_CMD_WRITE : NVME_CMD_READ;
	stack_cmd.cid = tag;
	stack_cmd.nsid = data->nsid;
	stack_cmd.slba = htole64(slba);
	stack_cmd.length = htole16(nlb);
	stack_cmd.control = (ublksrv_get_flags(iod) & UBLK_IO_F_FUA) ? htole16(NVME_RW_FUA) : 0;

	/* Setup data pointers - use SGL if supported, otherwise PRP */
	if (nvme_sgl_supported(data)) {
		if (nvme_setup_sgl(&stack_cmd, data, priv, io_buf, iova, len) < 0)
			return -EINVAL;
	} else {
		if (nvme_setup_prps(&stack_cmd, data, priv, io_buf, iova, len) < 0)
			return -EINVAL;
	}

	memcpy((struct nvme_rw_command *)nvmeq->sq_buffer + nvmeq->sq_tail,
	       &stack_cmd, sizeof(stack_cmd));
	nvme_sq_submit_cmd(nvmeq);

	return 0;
}

/* Queue flush I/O */
static int nvme_queue_flush_io(const struct ublksrv_queue *q,
			       struct nvme_queue *nvmeq,
			       const struct ublksrv_io_desc *iod, int tag,
			       struct nvme_vfio_tgt_data *data)
{
	struct nvme_common_command stack_cmd = {};

	stack_cmd.opcode = NVME_CMD_FLUSH;
	stack_cmd.cid = tag;
	stack_cmd.nsid = data->nsid;

	memcpy((struct nvme_common_command *)nvmeq->sq_buffer + nvmeq->sq_tail,
	       &stack_cmd, sizeof(stack_cmd));
	nvme_sq_submit_cmd(nvmeq);

	return 0;
}

/* Queue discard I/O (Dataset Management command) */
static int nvme_queue_discard_io(const struct ublksrv_queue *q,
				 struct nvme_queue *nvmeq,
				 const struct ublksrv_io_desc *iod, int tag,
				 struct nvme_vfio_tgt_data *data)
{
	struct nvme_io_priv *priv;
	struct nvme_dsm_range *range;
	__u64 slba;
	__u32 nlb;

	slba = iod->start_sector >> (data->lba_shift - 9);
	nlb = iod->nr_sectors >> (data->lba_shift - 9);

	priv = nvme_get_io_priv(q, tag);

	/* Use PRP list buffer for DSM range (already mapped for DMA) */
	range = (struct nvme_dsm_range *)priv->prp_list;
	/* Zero entire page - some devices read beyond specified range count */
	memset(range, 0, PAGE_SIZE);
	range->cattr = htole32(0);
	range->nlb = htole32(nlb);
	range->slba = htole64(slba);

	struct nvme_common_command stack_cmd = {};

	stack_cmd.opcode = NVME_CMD_DSM;
	stack_cmd.cid = tag;
	stack_cmd.nsid = htole32(data->nsid);
	stack_cmd.prp1 = htole64(priv->prp_mapping.iova);
	stack_cmd.cdw10 = htole32(0);  /* Number of ranges - 1 (single range) */
	stack_cmd.cdw11 = htole32(NVME_DSMGMT_AD);  /* Deallocate attribute */

	memcpy((struct nvme_common_command *)nvmeq->sq_buffer + nvmeq->sq_tail,
	       &stack_cmd, sizeof(stack_cmd));
	nvme_sq_submit_cmd(nvmeq);

	return 0;
}

/* Enable PCI Bus Mastering */
static int nvme_enable_pci_bus_master(int device_fd)
{
	struct vfio_region_info config_region = { .argsz = sizeof(config_region) };
	__u16 cmd_reg;

	config_region.index = 7;  /* VFIO_PCI_CONFIG_REGION_INDEX */
	if (ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &config_region) < 0) {
		ublk_err("VFIO_DEVICE_GET_REGION_INFO (config): %s\n", strerror(errno));
		return -1;
	}

	if (pread(device_fd, &cmd_reg, sizeof(cmd_reg),
		  config_region.offset + 0x04) != sizeof(cmd_reg)) {
		ublk_err("pread PCI command register: %s\n", strerror(errno));
		return -1;
	}

	cmd_reg |= 0x0404;

	if (pwrite(device_fd, &cmd_reg, sizeof(cmd_reg),
		   config_region.offset + 0x04) != sizeof(cmd_reg)) {
		ublk_err("pwrite PCI command register: %s\n", strerror(errno));
		return -1;
	}

	if (pread(device_fd, &cmd_reg, sizeof(cmd_reg),
		  config_region.offset + 0x04) != sizeof(cmd_reg)) {
		ublk_err("pread PCI command register (verify): %s\n", strerror(errno));
		return -1;
	}

	if (!(cmd_reg & 0x04)) {
		ublk_err("Failed to enable Bus Mastering\n");
		return -1;
	}

	return 0;
}

/*
 * Open VFIO group and attach to container
 */
static int nvme_open_vfio_group(int iommu_group, int container_fd,
				int *use_noiommu)
{
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	char group_path[256];
	int group_fd;

	snprintf(group_path, sizeof(group_path), "/dev/vfio/%d", iommu_group);

	if (access(group_path, F_OK) != 0) {
		snprintf(group_path, sizeof(group_path),
			 "/dev/vfio/noiommu-%d", iommu_group);

		if (access(group_path, F_OK) != 0) {
			ublk_err("No VFIO or noiommu group found for group %d\n", iommu_group);
			return -1;
		}
		*use_noiommu = 1;
	}

	group_fd = open(group_path, O_RDWR);
	if (group_fd < 0) {
		ublk_err("open vfio group: %s\n", strerror(errno));
		return -1;
	}

	if (ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status) < 0) {
		ublk_err("VFIO_GROUP_GET_STATUS: %s\n", strerror(errno));
		goto err_close;
	}

	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		ublk_err("VFIO group not viable\n");
		goto err_close;
	}

	if (ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &container_fd) < 0) {
		ublk_err("VFIO_GROUP_SET_CONTAINER: %s\n", strerror(errno));
		goto err_close;
	}

	if (*use_noiommu) {
		if (ioctl(container_fd, VFIO_SET_IOMMU, VFIO_NOIOMMU_IOMMU) < 0) {
			ublk_err("VFIO_SET_IOMMU (no-IOMMU): %s\n", strerror(errno));
			goto err_close;
		}
	} else {
		if (ioctl(container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) < 0) {
			ublk_err("VFIO_SET_IOMMU: %s\n", strerror(errno));
			goto err_close;
		}
	}

	return group_fd;

err_close:
	close(group_fd);
	return -1;
}

/*
 * Open VFIO cdev for a PCI device.
 * Scans /sys/bus/pci/devices/{pci}/vfio-dev/ to find the vfioN name,
 * then opens /dev/vfio/devices/vfioN.
 */
static int nvme_open_vfio_cdev(const char *pci_addr)
{
	char sysfs_path[256];
	DIR *dir;
	struct dirent *entry;
	char dev_path[256];
	int fd = -1;

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/bus/pci/devices/%s/vfio-dev", pci_addr);

	dir = opendir(sysfs_path);
	if (!dir) {
		ublk_err("opendir %s: %s\n", sysfs_path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;
		snprintf(dev_path, sizeof(dev_path),
			 "/dev/vfio/devices/%s", entry->d_name);
		fd = open(dev_path, O_RDWR);
		if (fd < 0)
			ublk_err("open %s: %s\n", dev_path, strerror(errno));
		break;
	}

	closedir(dir);

	if (fd < 0)
		ublk_err("No VFIO cdev found for %s\n", pci_addr);

	return fd;
}

/*
 * Setup iommufd-based VFIO device access.
 * Opens /dev/iommu, the VFIO cdev, binds the device to iommufd,
 * allocates an IOAS, and attaches the device to it.
 */
static int nvme_vfio_setup_iommufd(struct nvme_vfio_tgt_data *data)
{
	struct vfio_device_bind_iommufd bind = {};
	struct iommu_ioas_alloc ioas_alloc = {};
	struct vfio_device_attach_iommufd_pt attach = {};

	/* Open /dev/iommu */
	data->iommufd = open("/dev/iommu", O_RDWR);
	if (data->iommufd < 0) {
		ublk_err("open /dev/iommu: %s\n", strerror(errno));
		return -1;
	}

	/* Open VFIO cdev */
	data->device_fd = nvme_open_vfio_cdev(data->pci_addr);
	if (data->device_fd < 0)
		goto err_close_iommufd;

	/* Bind device to iommufd */
	bind.argsz = sizeof(bind);
	bind.flags = 0;
	bind.iommufd = data->iommufd;
	if (ioctl(data->device_fd, VFIO_DEVICE_BIND_IOMMUFD, &bind) < 0) {
		ublk_err("VFIO_DEVICE_BIND_IOMMUFD: %s\n", strerror(errno));
		goto err_close_device;
	}
	data->dev_id = bind.out_devid;

	/* Allocate IOAS */
	ioas_alloc.size = sizeof(ioas_alloc);
	ioas_alloc.flags = 0;
	if (ioctl(data->iommufd, IOMMU_IOAS_ALLOC, &ioas_alloc) < 0) {
		ublk_err("IOMMU_IOAS_ALLOC: %s\n", strerror(errno));
		goto err_close_device;
	}
	data->ioas_id = ioas_alloc.out_ioas_id;

	/* Attach device to IOAS */
	attach.argsz = sizeof(attach);
	attach.flags = 0;
	attach.pt_id = data->ioas_id;
	if (ioctl(data->device_fd, VFIO_DEVICE_ATTACH_IOMMUFD_PT, &attach) < 0) {
		ublk_err("VFIO_DEVICE_ATTACH_IOMMUFD_PT: %s\n", strerror(errno));
		goto err_destroy_ioas;
	}

	return 0;

err_destroy_ioas:
	{
		struct iommu_destroy destroy = {};
		destroy.size = sizeof(destroy);
		destroy.id = data->ioas_id;
		ioctl(data->iommufd, IOMMU_DESTROY, &destroy);
	}
err_close_device:
	close(data->device_fd);
	data->device_fd = -1;
err_close_iommufd:
	close(data->iommufd);
	data->iommufd = -1;
	return -1;
}

/* Per-queue private data */
struct nvme_vfio_queue_data {
	struct nvme_vfio_tgt_data *tgt_data;
	int qid;
};

static int nvme_vfio_setup_tgt(struct ublksrv_dev *dev)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(cdev);
	struct ublk_params p;
	int ret;

	ret = ublk_json_read_params(&p, cdev);
	if (ret) {
		ublk_err("%s: read ublk params failed %d\n", __func__, ret);
		return ret;
	}

	tgt->dev_size = p.basic.dev_sectors << 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;

	tgt->io_data_size = sizeof(struct ublk_io_tgt) + sizeof(struct nvme_io_priv);

	return 0;
}

/*
 * Setup VFIO device and map BAR0.
 * Called after data->pci_addr is set.
 *
 * IOMMU mode:   uses iommufd + VFIO cdev (/dev/iommu + /dev/vfio/devices/vfioN)
 * NoIOMMU mode: uses legacy VFIO container/group (/dev/vfio/vfio + /dev/vfio/{group})
 */
static int nvme_vfio_setup(struct nvme_vfio_tgt_data *data)
{
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	struct vfio_region_info region_info = { .argsz = sizeof(region_info) };

	/* Setup VFIO binding */
	if (setup_vfio_binding(data->pci_addr) < 0) {
		ublk_err("Failed to bind device to vfio-pci\n");
		return -1;
	}

	/* Get IOMMU group (needed to detect noiommu) */
	data->iommu_group = get_iommu_group(data->pci_addr, &data->use_noiommu);
	if (data->iommu_group < 0) {
		ublk_err("Failed to get IOMMU group\n");
		return -1;
	}

	if (nvme_use_iommu(data)) {
		/* IOMMU mode: use iommufd + VFIO cdev */
		if (nvme_vfio_setup_iommufd(data) < 0)
			return -1;
	} else {
		/* NoIOMMU mode: use legacy VFIO container/group */
		int version;

		data->container_fd = open("/dev/vfio/vfio", O_RDWR);
		if (data->container_fd < 0) {
			ublk_err("open /dev/vfio/vfio: %s\n", strerror(errno));
			return -1;
		}

		version = ioctl(data->container_fd, VFIO_GET_API_VERSION);
		if (version != VFIO_API_VERSION) {
			ublk_err("VFIO API version mismatch\n");
			return -1;
		}

		if (!ioctl(data->container_fd, VFIO_CHECK_EXTENSION, VFIO_NOIOMMU_IOMMU)) {
			ublk_err("VFIO no-IOMMU not supported\n");
			return -1;
		}

		data->group_fd = nvme_open_vfio_group(data->iommu_group,
						      data->container_fd,
						      &data->use_noiommu);
		if (data->group_fd < 0)
			return -1;

		data->device_fd = ioctl(data->group_fd, VFIO_GROUP_GET_DEVICE_FD,
					data->pci_addr);
		if (data->device_fd < 0) {
			ublk_err("VFIO_GROUP_GET_DEVICE_FD: %s\n", strerror(errno));
			return -1;
		}
	}

	/* Common post-setup: device info, bus mastering, BAR0 mmap */
	if (ioctl(data->device_fd, VFIO_DEVICE_GET_INFO, &device_info) < 0) {
		ublk_err("VFIO_DEVICE_GET_INFO: %s\n", strerror(errno));
		return -1;
	}

	if (nvme_enable_pci_bus_master(data->device_fd) < 0)
		return -1;

	region_info.index = 0;
	if (ioctl(data->device_fd, VFIO_DEVICE_GET_REGION_INFO, &region_info) < 0) {
		ublk_err("VFIO_DEVICE_GET_REGION_INFO: %s\n", strerror(errno));
		return -1;
	}

	data->bar0_size = region_info.size;
	data->bar0 = mmap(NULL, region_info.size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, data->device_fd, region_info.offset);
	if (data->bar0 == MAP_FAILED) {
		ublk_err("mmap BAR0: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int nvme_vfio_recover_tgt(struct ublksrv_dev *dev, int type)
{
	return nvme_vfio_setup_tgt(dev);
}

static int nvme_vfio_init_tgt(struct ublksrv_dev *dev, int type, int argc, char *argv[])
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(cdev);
	struct nvme_vfio_tgt_data *data;
	char *pci_addr = NULL;
	__u64 cap;
	int opt;
	int force_noiommu = 0;
	struct ublksrv_tgt_base_json tgt_json = { 0 };
	struct ublk_params p = {};
	enum {
		OPT_PCI = 256,
		OPT_NOIOMMU,
	};
	static const struct option longopts[] = {
		{ "pci",		required_argument, NULL, OPT_PCI },
		{ "noiommu",		no_argument, NULL, OPT_NOIOMMU },
		{ NULL }
	};
	int use_bpf = 0;
	size_t hps = nvme_get_hugepage_size();

	if (hps == 0) {
		ublk_err("Failed to get hugepage size from /proc/meminfo\n");
		return -EINVAL;
	}

	/* Check for unsupported zero copy modes */
	if (info->flags & UBLK_F_AUTO_BUF_REG) {
		ublk_err("auto zero copy not supported (page copy only)\n");
		return -EINVAL;
	}

	if (info->flags & UBLK_F_SUPPORT_ZERO_COPY) {
		ublk_err("zero copy not supported (page copy only)\n");
		return -EINVAL;
	}

	/* Validate ublk parameters */
	if (info->nr_hw_queues < 1 || info->nr_hw_queues > 64) {
		ublk_err("nr_hw_queues %u out of range (1-64)\n", info->nr_hw_queues);
		return -EINVAL;
	}

	if (info->queue_depth < 1 || info->queue_depth > 4096) {
		ublk_err("queue_depth %u out of range (1-4096)\n", info->queue_depth);
		return -EINVAL;
	}

	if (info->max_io_buf_bytes < PAGE_SIZE ||
	    info->max_io_buf_bytes > (2 << 20) ||
	    info->max_io_buf_bytes > hps ||
	    (info->max_io_buf_bytes & (info->max_io_buf_bytes - 1))) {
		ublk_err("max_io_buf_bytes %u invalid (must be power of 2, %u-%u)\n",
			 info->max_io_buf_bytes, PAGE_SIZE, 32 << 20);
		return -EINVAL;
	}

	if (ublksrv_is_recovering(cdev))
		return nvme_vfio_recover_tgt(dev, 0);

	/* Parse options */
	optind = 0;
	while ((opt = getopt_long(argc, argv, "-:", longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_PCI:
			pci_addr = strdup(optarg);
			break;
		case OPT_NOIOMMU:
			force_noiommu = 1;
			break;
		}
	}

	if (!pci_addr) {
		ublk_err("PCI address required (--pci)\n");
		return -EINVAL;
	}

	/* Allocate private data */
	data = (struct nvme_vfio_tgt_data *)calloc(1, sizeof(*data));
	if (!data) {
		ublk_err("calloc: %s\n", strerror(errno));
		free(pci_addr);
		return -1;
	}

	dev->tgt.tgt_data = data;
	data->force_noiommu = force_noiommu;
	data->user_copy = info->flags & UBLK_F_USER_COPY;

	/* Enable noiommu mode if requested */
	if (force_noiommu) {
		if (nvme_enable_noiommu_mode() < 0)
			goto err;
	}

	if ((info->flags & UBLK_F_BPF_DMA) && force_noiommu) {
		ublk_err("BPF_DMA requires IOMMU (incompatible with --noiommu)\n");
		goto err;
	}

	use_bpf = !!(info->flags & UBLK_F_BPF);
	nvme_log("flags=0x%llx use_bpf=%d bpf_dma=%d\n",
		 (unsigned long long)info->flags, use_bpf,
		 !!(info->flags & UBLK_F_BPF_DMA));

	if (use_bpf && !(info->flags & UBLK_F_BPF_DMA)) {
		ublk_err("BPF mode requires BPF_DMA (--bpf)\n");
		goto err;
	}

	if (use_bpf && force_noiommu) {
		ublk_err("BPF mode requires IOMMU (incompatible with --noiommu)\n");
		goto err;
	}

	data->zero_copy = !!(info->flags & UBLK_F_BPF_DMA);

	data->container_fd = -1;
	data->group_fd = -1;
	data->device_fd = -1;
	data->iommufd = -1;
	data->next_iova = 0x100000000ULL;
	data->nr_io_queues = info->nr_hw_queues;
	data->queue_depth = info->queue_depth;
	data->max_io_buf_bytes = info->max_io_buf_bytes;
	data->max_transfer_shift = 31 - __builtin_clz(info->max_io_buf_bytes);
	data->hugepage_size = hps;
	pthread_spin_init(&data->iova_lock, PTHREAD_PROCESS_PRIVATE);

	if (strlen(pci_addr) >= sizeof(data->pci_addr)) {
		ublk_err("PCI address too long\n");
		goto err;
	}
	data->numa_node = get_pci_numa_node(pci_addr);
	strcpy(data->pci_addr, pci_addr);
	free(pci_addr);
	pci_addr = NULL;

	if (nvme_vfio_setup(data) < 0)
		goto err;

	/* Read capabilities */
	cap = nvme_readq(data->bar0, NVME_REG_CAP);
	data->db_stride = (1 << ((cap >> 32) & 0xF)) * 4;

	if (nvme_validate_params(data, cap) < 0)
		goto err;

	if (use_bpf)
		data->bpf_mode = true;

	/*
	 * Two-phase pool init:
	 *
	 * Phase 1 (early_init): Allocate pool backing + admin-only layout.
	 *   - Hugepage: full pool sized from CLI args (max), pagemap read.
	 *   - Arena: BPF skeleton load, admin pages faulted, IOMMU map.
	 */
	if (data->bpf_mode) {
		if (nvme_arena_pool_early_init(data) < 0)
			goto err;
	} else {
		if (nvme_hugepage_pool_early_init(data) < 0)
			goto err;
	}

	/* Initialize controller (admin queue from pool head) */
	if (nvme_init_controller(data) < 0)
		goto err;

	/* Negotiate I/O queue count with controller */
	if (nvme_set_num_queues(data) < 0)
		goto err;

	/* Get controller capabilities */
	if (nvme_identify_controller(data) < 0)
		goto err;

	if (nvme_identify_namespace(data, &p) < 0)
		goto err;

	/*
	 * Phase 2 (finish_init): Finalize layout with actual params.
	 *   - Hugepage: recompute layout (nop for memory — pool is big enough).
	 *   - Arena: fault remaining pages, update pool size, validate fit.
	 */
	if (data->bpf_mode) {
		if (nvme_arena_pool_finish_init(data) < 0)
			goto err;
	} else {
		if (nvme_hugepage_pool_finish_init(data) < 0)
			goto err;
	}

	/* Allocate IO queue array */
	data->io_queues = (struct nvme_queue *)calloc(data->nr_io_queues,
						      sizeof(struct nvme_queue));
	if (!data->io_queues) {
		ublk_err("calloc io_queues: %s\n", strerror(errno));
		goto err;
	}

	/* Create IO queues using unified layout */
	if (data->bpf_mode) {
		if (nvme_bpf_create_io_queues(data) < 0)
			goto err;
		if (nvme_bpf_attach(data) < 0)
			goto err;
	} else {
		for (int i = 0; i < data->nr_io_queues; i++) {
			int qsize = data->queue_depth + 1;

			if (nvme_create_io_queue(data, i + 1, qsize) < 0)
				goto err;
		}
	}

	/*
	 * DMA zero-copy: pass iommufd context to the kernel so it can map
	 * bio pages directly into the device's IOAS. The kernel-provided
	 * IOVA will appear in iod->addr for each dispatched request.
	 *
	 * base_iova is set above userspace's DMA allocation range
	 * (0x100000000) to avoid conflicts. The kernel will reserve this
	 * range in the IOAS.
	 */
	if (data->zero_copy) {
		/*
		 * Total kernel IOVA space:
		 * nr_queues * queue_depth * max_io_buf_bytes
		 */
		__u64 kernel_iova_base = 0x200000000ULL;

		p.types |= UBLK_PARAM_TYPE_DMA_DEV;
		p.dma_dev.base_iova = kernel_iova_base;
		p.dma_dev.iommufd = data->iommufd;
		p.dma_dev.ioas_id = data->ioas_id;
		p.dma_dev.vfio_dev_fd = -1;
		if (data->bpf_mode)
			p.dma_dev.vfio_dev_fd = data->device_fd;

		/*
		 * DMA alignment and segment constraints reduce sub-page
		 * SG entries at the block layer level, complementing the
		 * kernel-side page-alignment in ublk_fill_dma_addrs().
		 */
		p.types |= UBLK_PARAM_TYPE_DMA_ALIGN;
		p.dma.alignment = PAGE_SIZE - 1;

		p.types |= UBLK_PARAM_TYPE_SEGMENT;
		p.basic.virt_boundary_mask = PAGE_SIZE - 1;
		p.seg.seg_boundary_mask = PAGE_SIZE - 1;
		p.seg.max_segment_size = data->max_io_buf_bytes;
		p.seg.max_segments = 64;
	}

	/* Setup JSON data */
	strcpy(tgt_json.name, "nvme_vfio");
	tgt_json.dev_size = data->dev_size;

	ublk_json_write_dev_info(cdev);
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_tgt_str(cdev, "pci_addr", data->pci_addr);
	ublk_json_write_params(cdev, &p);

	nvme_log_numa_info(data);

	return nvme_vfio_setup_tgt(dev);

err:
	free(pci_addr);
	nvme_vfio_cleanup(data, false);
	dev->tgt.tgt_data = NULL;
	return -1;
}

static void nvme_vfio_deinit_tgt(const struct ublksrv_dev *dev)
{
	struct nvme_vfio_tgt_data *data = (struct nvme_vfio_tgt_data *)dev->tgt.tgt_data;

	nvme_vfio_cleanup(data, true);
	nvme_log("VFIO NVMe target cleaned up\n");
}

static int nvme_vfio_init_queue(const struct ublksrv_queue *q, void **queue_data_ptr)
{
	struct nvme_vfio_tgt_data *data = (struct nvme_vfio_tgt_data *)q->dev->tgt.tgt_data;
	int depth = data->queue_depth;

	/* Pre-allocate and pre-map DMA buffers */
	for (int tag = 0; tag < depth; tag++) {
		struct nvme_io_priv *priv = nvme_get_io_priv(q, tag);

		memset(priv, 0, sizeof(*priv));

		/* Get PRP list buffer from pool */
		priv->prp_list = (__le64 *)nvme_pool_get_prp(data, q->q_id, tag);
		if (!priv->prp_list) {
			ublk_err("Failed to get PRP buffer for tag %d\n", tag);
			return -1;
		}
		memset(priv->prp_list, 0, PAGE_SIZE);

		/* Map PRP list for DMA */
		priv->prp_mapping.iova = nvme_map_dma(data, priv->prp_list,
						      PAGE_SIZE, &priv->prp_mapping);
		if (!priv->prp_mapping.iova) {
			ublk_err("Failed to map PRP list for tag %d\n", tag);
			return -1;
		}
	}

	return 0;
}

static void nvme_vfio_deinit_queue(const struct ublksrv_queue *q)
{
	struct nvme_vfio_tgt_data *data = (struct nvme_vfio_tgt_data *)q->dev->tgt.tgt_data;
	int depth = data->queue_depth;

	for (int tag = 0; tag < depth; tag++) {
		struct nvme_io_priv *priv = nvme_get_io_priv(q, tag);

		if (priv->data_mapping.iova)
			nvme_unmap_dma(data, &priv->data_mapping);
		if (priv->prp_mapping.iova)
			nvme_unmap_dma(data, &priv->prp_mapping);
	}
}

static int nvme_vfio_queue_io(const struct ublksrv_queue *q,
			      const struct ublk_io_data *io_data, int tag)
{
	struct nvme_vfio_tgt_data *data = (struct nvme_vfio_tgt_data *)q->dev->tgt.tgt_data;
	const struct ublksrv_io_desc *iod = io_data->iod;
	struct nvme_queue *nvmeq = &data->io_queues[q->q_id];
	unsigned int op = ublksrv_get_op(iod);
	int ret;

	/*
	 * In BPF mode, the BPF queue_io_cmd already built the NVMe
	 * command in the arena SQ and rang the doorbell. Userspace
	 * only needs to track inflight count for CQ polling.
	 */
	/*
	 * In BPF mode, READ/WRITE was already submitted by BPF
	 * queue_io_cmd (SQ entry + doorbell). Just track inflight.
	 * Other ops (FLUSH, DISCARD) go through the normal path
	 * since BPF returns 0 (forward to userspace) for them.
	 */
	/*
	 * In BPF mode, all NVMe commands (READ/WRITE/FLUSH/DISCARD) are
	 * submitted by BPF queue_io_cmd. Userspace only tracks inflight
	 * count and handles deferred CQ completions.
	 */
	if (data->bpf_mode) {
		struct nvme_io_priv *priv = nvme_get_io_priv(q, tag);

		ublksrv_queue_inc_tgt_io_inflight(q);
		priv->fetch_done = true;

		/*
		 * Check if the NVMe CQE arrived before this FETCH was
		 * consumed. If so, complete the IO now (deferred from
		 * nvme_poll_cq which couldn't call ublksrv_complete_io
		 * because the FETCH hadn't been consumed yet).
		 */
		if (priv->cqe_early) {
			priv->cqe_early = false;
			priv->fetch_done = false;
			ublksrv_queue_dec_tgt_io_inflight(q);
			ublksrv_complete_io(q, tag, priv->cqe_result);
		}
		return 0;
	}

	switch (op) {
	case UBLK_IO_OP_READ:
	case UBLK_IO_OP_WRITE:
		ret = nvme_queue_rw_io(q, nvmeq, iod, tag, data);
		break;
	case UBLK_IO_OP_FLUSH:
		ret = nvme_queue_flush_io(q, nvmeq, iod, tag, data);
		break;
	case UBLK_IO_OP_DISCARD:
		ret = nvme_queue_discard_io(q, nvmeq, iod, tag, data);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret < 0)
		ublksrv_complete_io(q, tag, ret);
	else
		ublksrv_queue_inc_tgt_io_inflight(q);

	return ret;
}

static void nvme_vfio_handle_io_background(const struct ublksrv_queue *q,
					    int nr_queued_io)
{
	struct nvme_vfio_tgt_data *data = (struct nvme_vfio_tgt_data *)q->dev->tgt.tgt_data;
	struct nvme_queue *nvmeq = &data->io_queues[q->q_id];
	int total_completed = 0;
	int nr;

	/* Flush any pending SQ submissions (skip in BPF mode —
	 * BPF handles doorbell writes directly) */
	if (!data->bpf_mode)
		nvme_sq_flush(nvmeq);

	/* Poll NVMe CQ for completions */
	while ((nr = nvme_poll_cq(q, nvmeq, data)) > 0)
		total_completed += nr;

	/*
	 * If NVMe pipeline is busy but we only drained a tiny batch,
	 * completions are arriving imminently. Spin-wait on CQ to
	 * accumulate more before returning to io_uring event loop.
	 * This reduces io_uring_enter syscall frequency.
	 *
	 * tgt_io_inflight: IOs submitted to NVMe hardware, awaiting CQE.
	 * When high, device is actively producing completions.
	 *
	 * Skip in BPF mode: BPF submits NVMe commands from kernel
	 * dispatch context, so tgt_io_inflight can be high before
	 * CQEs arrive. Spinning here blocks io_uring_enter, preventing
	 * COMMIT processing and causing deadlock.
	 */
	if (!data->bpf_mode &&
	    ublksrv_queue_get_tgt_io_inflight(q) >= 32 &&
	    total_completed <= 2) {
		while (total_completed < 4 && !ublksrv_queue_is_done(q)) {
			while ((nr = nvme_poll_cq(q, nvmeq, data)) > 0)
				total_completed += nr;
		}
	}
}

static int nvme_vfio_handle_io_async(const struct ublksrv_queue *q,
				     const struct ublk_io_data *data)
{
	int ret = nvme_vfio_queue_io(q, data, data->tag);
	return ret >= 0 ? 0 : ret;
}

static void *nvme_vfio_alloc_io_buf(const struct ublksrv_queue *q, int tag, int size)
{
	struct nvme_vfio_tgt_data *data = (struct nvme_vfio_tgt_data *)q->dev->tgt.tgt_data;
	return nvme_pool_get_io_buf(data, q->q_id, tag);
}

static void nvme_vfio_free_io_buf(const struct ublksrv_queue *q, void *buf, int tag)
{
	/* Pool memory freed when pool is destroyed */
}

static void nvme_vfio_cmd_usage(void)
{
	printf("\tnvme_vfio: --pci PCI_ADDR [--noiommu]\n");
	printf("\t  --pci: PCI address of NVMe device (e.g., 0000:01:00.0)\n");
	printf("\t  --noiommu: Force noiommu mode (use virtual addresses as IOVAs)\n");
	printf("\t  BPF SQ submission: --bpf\n");
}

static const struct ublksrv_tgt_type nvme_vfio_tgt_type = {
	.handle_io_async = nvme_vfio_handle_io_async,
	.handle_io_background = nvme_vfio_handle_io_background,
	.usage_for_add = nvme_vfio_cmd_usage,
	.init_tgt = nvme_vfio_init_tgt,
	.deinit_tgt = nvme_vfio_deinit_tgt,
	.alloc_io_buf = nvme_vfio_alloc_io_buf,
	.free_io_buf = nvme_vfio_free_io_buf,
	.ublksrv_flags = UBLKSRV_F_NEED_POLL,
	.name = "nvme_vfio",
	.init_queue = nvme_vfio_init_queue,
	.deinit_queue = nvme_vfio_deinit_queue,
};

int main(int argc, char *argv[])
{
	return ublksrv_main(&nvme_vfio_tgt_type, argc, argv);
}
