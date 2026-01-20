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
 *   Standard mode:
 *     - IOMMU enabled (intel_iommu=on or amd_iommu=on)
 *     - vfio-pci module loaded
 *
 *   NoIOMMU mode:
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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <endian.h>
#include <fcntl.h>

#include "ublksrv_tgt.h"
#include "nvme.h"

#define PAGE_SIZE 4096
#define ADMIN_Q_SIZE 64

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
};

/* Target Private Data */
struct nvme_vfio_tgt_data {
	char pci_addr[16];
	__u32 nsid;
	__u32 lba_shift;
	__u64 dev_size;

	/* VFIO handles */
	int container_fd;
	int group_fd;
	int device_fd;
	int iommu_group;
	int use_noiommu;

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

	/* DMA IOVA allocation */
	__u64 next_iova;
	pthread_spinlock_t iova_lock;	/* Protects next_iova allocation */

	/* dma_buf pool for pinned DMA memory */
	void *dmabuf_base;		/* mmap'd base address */
	size_t dmabuf_size;		/* total allocated size */

	/* Region layout (offsets from dmabuf_base) */
	size_t queue_region_off;	/* end of queue region (= prp_region_off) */
	size_t prp_region_off;		/* offset to PRP list region */
	size_t io_buf_region_off;	/* offset to I/O buffer region */
	size_t identify_buf_off;	/* offset to identify buffer */

	/* Queue buffer allocation state (bump allocator) */
	size_t queue_alloc_off;

	/* Pagemap cache for noiommu mode */
	uint64_t *pagemap_cache;		/* Pre-read pagemap entries */
	__u64 pagemap_base_vaddr;		/* Base virtual address of cached region */
	size_t pagemap_nr_pages;		/* Number of pages in cache */
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

	if (data->queue_depth > mqes) {
		ublk_err("queue_depth %u exceeds NVMe MQES %u\n",
			 data->queue_depth, mqes);
		return -EINVAL;
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

/*
 * Pre-read pagemap entries for the dmabuf region into a cache.
 */
static int nvme_read_pagemap(struct nvme_vfio_tgt_data *data)
{
	size_t nr_pages = data->dmabuf_size / PAGE_SIZE;
	__u64 base_vaddr = (__u64)data->dmabuf_base;
	off_t offset;
	ssize_t ret;
	int pagemap_fd;

	data->pagemap_cache = (uint64_t *)malloc(nr_pages * sizeof(uint64_t));
	if (!data->pagemap_cache) {
		ublk_err("Failed to allocate pagemap cache\n");
		return -ENOMEM;
	}

	pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	if (pagemap_fd < 0) {
		ublk_err("Failed to open /proc/self/pagemap: %s\n", strerror(errno));
		free(data->pagemap_cache);
		data->pagemap_cache = NULL;
		return -errno;
	}

	offset = (base_vaddr / PAGE_SIZE) * sizeof(uint64_t);
	ret = pread(pagemap_fd, data->pagemap_cache,
		    nr_pages * sizeof(uint64_t), offset);
	close(pagemap_fd);

	if (ret != (ssize_t)(nr_pages * sizeof(uint64_t))) {
		ublk_err("pread pagemap failed: expected %zu, got %zd\n",
			nr_pages * sizeof(uint64_t), ret);
		free(data->pagemap_cache);
		data->pagemap_cache = NULL;
		return -EIO;
	}

	data->pagemap_base_vaddr = base_vaddr;
	data->pagemap_nr_pages = nr_pages;

	return 0;
}

/*
 * Query physical address from pre-read pagemap cache
 */
static __u64 nvme_virt_to_phys(struct nvme_vfio_tgt_data *data, __u64 vaddr)
{
	uint64_t entry;
	unsigned long pfn;
	size_t page_idx;

	if (!data->pagemap_cache) {
		ublk_err("pagemap cache not initialized\n");
		return 0;
	}

	/* Check if vaddr is within cached region */
	if (vaddr < data->pagemap_base_vaddr ||
	    vaddr >= data->pagemap_base_vaddr + data->pagemap_nr_pages * PAGE_SIZE) {
		ublk_err("vaddr 0x%llx outside cached region\n", (unsigned long long)vaddr);
		return 0;
	}

	page_idx = (vaddr - data->pagemap_base_vaddr) / PAGE_SIZE;
	entry = data->pagemap_cache[page_idx];

	/* Check page present bit */
	if (!(entry & (1ULL << 63))) {
		ublk_err("Page not present for vaddr 0x%llx\n", (unsigned long long)vaddr);
		return 0;
	}

	/* Extract PFN (bits 0-54) */
	pfn = entry & 0x007fffffffffffffULL;

	return (pfn * PAGE_SIZE) + (vaddr & (PAGE_SIZE - 1));
}

static inline bool nvme_use_iommu(struct nvme_vfio_tgt_data *data)
{
	return !data->use_noiommu && !data->force_noiommu;
}

/*
 * Get IOVA for buffer based on current mode
 */
static __u64 nvme_get_iova(struct nvme_vfio_tgt_data *data, void *vaddr, size_t size)
{
	__u64 iova;

	/* NoIOMMU mode: use physical address from /proc/self/pagemap */
	if (!nvme_use_iommu(data)) {
		return nvme_virt_to_phys(data, (__u64)vaddr);
	}

	/* Standard IOMMU mode: allocate sequential IOVA */
	pthread_spin_lock(&data->iova_lock);
	iova = data->next_iova;
	data->next_iova += (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	pthread_spin_unlock(&data->iova_lock);
	return iova;
}

/*
 * Build PRP list with individual page addresses
 */
static int nvme_build_prp_list(struct nvme_vfio_tgt_data *data,
			       void *vaddr, size_t len, __u64 first_iova,
			       __le64 *prp_list, int max_entries)
{
	__u64 vaddr_page = (__u64)vaddr;
	__u64 iova;
	size_t offset = 0;
	size_t remaining = len;
	int prp_index = 0;

	/* Skip first page (already in PRP1) */
	offset = PAGE_SIZE - (vaddr_page & (PAGE_SIZE - 1));
	vaddr_page = ((__u64)vaddr + offset) & ~(PAGE_SIZE - 1);
	remaining = (len > offset) ? (len - offset) : 0;

	while (remaining > 0) {
		if (prp_index >= max_entries) {
			ublk_err("PRP list overflow\n");
			return -1;
		}

		/* Get IOVA for this page */
		if (!nvme_use_iommu(data)) {
			iova = nvme_virt_to_phys(data, vaddr_page);
			if (!iova) {
				ublk_err("Failed to get physical address for page\n");
				return -1;
			}
		} else {
			iova = first_iova + offset;
		}

		prp_list[prp_index++] = htole64(iova);

		vaddr_page += PAGE_SIZE;
		offset += PAGE_SIZE;
		remaining = (remaining > PAGE_SIZE) ? (remaining - PAGE_SIZE) : 0;
	}

	return prp_index;
}

/*
 * Perform VFIO DMA mapping if needed
 */
static int nvme_do_vfio_map(struct nvme_vfio_tgt_data *data,
			    void *vaddr, __u64 iova, size_t size)
{
	struct vfio_iommu_type1_dma_map dma_map = { .argsz = sizeof(dma_map) };

	if (!nvme_use_iommu(data))
		return 0;

	dma_map.vaddr = (__u64)vaddr;
	dma_map.size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	dma_map.iova = iova;
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	if (ioctl(data->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map) < 0) {
		ublk_err("VFIO_IOMMU_MAP_DMA: %s\n", strerror(errno));
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

/* Bind device to vfio-pci driver */
static int bind_vfio_pci(const char *pci_addr)
{
	char path[256], vendor[16], device[16];
	char vendor_device[32];
	int fd;

	/* Read vendor:device ID */
	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/vendor", pci_addr);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ublk_err("open vendor: %s\n", strerror(errno));
		return -1;
	}
	if (read(fd, vendor, sizeof(vendor)) < 0) {
		ublk_err("read vendor: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	vendor[strcspn(vendor, "\n")] = 0;

	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/device", pci_addr);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ublk_err("open device: %s\n", strerror(errno));
		return -1;
	}
	if (read(fd, device, sizeof(device)) < 0) {
		ublk_err("read device: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	device[strcspn(device, "\n")] = 0;

	/* Remove 0x prefix and format as "vendor device" */
	snprintf(vendor_device, sizeof(vendor_device), "%s %s",
		vendor + 2, device + 2);

	/* Add device ID to vfio-pci */
	fd = open("/sys/bus/pci/drivers/vfio-pci/new_id", O_WRONLY);
	if (fd < 0) {
		ublk_err("open new_id: %s\n", strerror(errno));
		return -1;
	}

	if (write(fd, vendor_device, strlen(vendor_device)) < 0) {
		if (errno != EEXIST) {
			ublk_err("write new_id: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
	}
	close(fd);

	/* Explicitly bind the device */
	fd = open("/sys/bus/pci/drivers/vfio-pci/bind", O_WRONLY);
	if (fd < 0) {
		ublk_err("open vfio-pci bind: %s\n", strerror(errno));
		return -1;
	}

	if (write(fd, pci_addr, strlen(pci_addr)) < 0) {
		if (errno != EEXIST) {
			ublk_err("bind to vfio-pci: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
	}
	close(fd);

	usleep(200000);  /* 200ms delay */

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
#define HUGE_PAGE_SIZE (2 * 1024 * 1024)  /* 2MB hugepages */

static int nvme_ensure_hugepages(size_t needed_bytes)
{
	size_t needed_pages = (needed_bytes + HUGE_PAGE_SIZE - 1) / HUGE_PAGE_SIZE;
	unsigned long current_pages = 0, free_pages = 0;
	FILE *fp;
	char buf[64];

	fp = fopen("/proc/sys/vm/nr_hugepages", "r");
	if (!fp)
		return -errno;
	if (fgets(buf, sizeof(buf), fp))
		current_pages = strtoul(buf, NULL, 10);
	fclose(fp);

	fp = fopen("/proc/meminfo", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp)) {
			if (sscanf(buf, "HugePages_Free: %lu", &free_pages) == 1)
				break;
		}
		fclose(fp);
	}

	if (free_pages >= needed_pages)
		return 0;

	fp = fopen("/proc/sys/vm/nr_hugepages", "w");
	if (!fp)
		return -errno;

	fprintf(fp, "%lu\n", current_pages + needed_pages - free_pages);
	fclose(fp);

	/* Verify allocation succeeded */
	fp = fopen("/proc/meminfo", "r");
	if (fp) {
		free_pages = 0;
		while (fgets(buf, sizeof(buf), fp)) {
			if (sscanf(buf, "HugePages_Free: %lu", &free_pages) == 1)
				break;
		}
		fclose(fp);
	}

	if (free_pages < needed_pages) {
		ublk_err("Failed to allocate %zu hugepages (only %lu free)\n",
			needed_pages, free_pages);
		return -ENOMEM;
	}

	return 0;
}

static int nvme_dmabuf_pool_init(struct nvme_vfio_tgt_data *data)
{
	size_t queue_region, prp_region, io_buf_region, total_size;
	size_t admin_sq_size, admin_cq_size, io_sq_size, io_cq_size;
	int nr_queues = data->nr_io_queues;
	int depth = data->queue_depth;
	size_t io_buf_size = data->max_io_buf_bytes;
	int ret;

	/* Calculate region sizes */
	admin_sq_size = (ADMIN_Q_SIZE * 64 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	admin_cq_size = (ADMIN_Q_SIZE * 16 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	io_sq_size = ((depth + 1) * 64 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	io_cq_size = ((depth + 1) * 16 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

	queue_region = (admin_sq_size + admin_cq_size) +
		       nr_queues * (io_sq_size + io_cq_size);
	prp_region = nr_queues * depth * PAGE_SIZE;
	io_buf_region = nr_queues * depth * io_buf_size;

	data->queue_region_off = queue_region;
	data->prp_region_off = queue_region;
	data->io_buf_region_off = queue_region + prp_region;
	data->identify_buf_off = queue_region + prp_region + io_buf_region;

	total_size = data->identify_buf_off + PAGE_SIZE;

	/* Round up to hugepage size */
	total_size = (total_size + HUGE_PAGE_SIZE - 1) & ~(HUGE_PAGE_SIZE - 1);

	ret = nvme_ensure_hugepages(total_size);
	if (ret < 0)
		return ret;

	data->dmabuf_base = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB |
				 MAP_POPULATE, -1, 0);
	if (data->dmabuf_base == MAP_FAILED) {
		ublk_err("Failed to mmap hugepages: %s\n", strerror(errno));
		return -errno;
	}

	data->dmabuf_size = total_size;

	memset(data->dmabuf_base, 0, total_size);

	data->queue_alloc_off = 0;

	return 0;
}

static void nvme_dmabuf_pool_deinit(struct nvme_vfio_tgt_data *data)
{
	if (data->pagemap_cache) {
		free(data->pagemap_cache);
		data->pagemap_cache = NULL;
	}
	if (data->dmabuf_base && data->dmabuf_base != MAP_FAILED) {
		munmap(data->dmabuf_base, data->dmabuf_size);
		data->dmabuf_base = NULL;
	}
}

/* Allocate from queue region */
static void *nvme_pool_alloc_queue_buf(struct nvme_vfio_tgt_data *data, size_t size)
{
	size_t aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	void *ptr;

	if (data->queue_alloc_off + aligned_size > data->queue_region_off) {
		ublk_err("Queue region exhausted\n");
		return NULL;
	}

	ptr = (char *)data->dmabuf_base + data->queue_alloc_off;
	data->queue_alloc_off += aligned_size;
	return ptr;
}

/* Get PRP list buffer for given queue/tag */
static void *nvme_pool_get_prp(struct nvme_vfio_tgt_data *data, int qid, int tag)
{
	int depth = data->queue_depth;
	size_t offset = data->prp_region_off + (qid * depth + tag) * PAGE_SIZE;

	return (char *)data->dmabuf_base + offset;
}

/* Get I/O buffer for given queue/tag */
static inline void *nvme_pool_get_io_buf(struct nvme_vfio_tgt_data *data, int qid, int tag)
{
	int depth = data->queue_depth;
	size_t io_buf_size = data->max_io_buf_bytes;
	size_t offset = data->io_buf_region_off + (qid * depth + tag) * io_buf_size;

	return (char *)data->dmabuf_base + offset;
}

/* Get identify buffer */
static void *nvme_pool_get_identify_buf(struct nvme_vfio_tgt_data *data)
{
	return (char *)data->dmabuf_base + data->identify_buf_off;
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
	struct vfio_iommu_type1_dma_unmap dma_unmap = { .argsz = sizeof(dma_unmap) };

	if (!mapping || !mapping->iova)
		return;

	if (nvme_use_iommu(data)) {
		dma_unmap.iova = mapping->iova;
		dma_unmap.size = mapping->size;
		ioctl(data->container_fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
	}

	mapping->vaddr = 0;
	mapping->iova = 0;
	mapping->size = 0;
}

/*
 * Initialize NVMe queue pair
 */
static int nvme_queue_init(struct nvme_vfio_tgt_data *data,
			   struct nvme_queue *q, __u16 qid, __u16 depth)
{
	volatile void *bar = data->bar0;
	size_t sq_buf_size, cq_buf_size;

	sq_buf_size = (depth * 64 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	cq_buf_size = (depth * 16 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

	q->sq_buffer = nvme_pool_alloc_queue_buf(data, sq_buf_size);
	if (!q->sq_buffer) {
		ublk_err("Failed to allocate SQ buffer from pool\n");
		return -ENOMEM;
	}
	memset(q->sq_buffer, 0, sq_buf_size);

	q->cq_buffer = nvme_pool_alloc_queue_buf(data, cq_buf_size);
	if (!q->cq_buffer) {
		ublk_err("Failed to allocate CQ buffer from pool\n");
		return -ENOMEM;
	}
	memset(q->cq_buffer, 0, cq_buf_size);

	q->sq_iova = nvme_map_dma(data, q->sq_buffer, sq_buf_size, &q->sq_mapping);
	q->cq_iova = nvme_map_dma(data, q->cq_buffer, cq_buf_size, &q->cq_mapping);

	if (!q->sq_iova || !q->cq_iova) {
		ublk_err("Failed to map queue %d for DMA\n", qid);
		nvme_unmap_dma(data, &q->sq_mapping);
		nvme_unmap_dma(data, &q->cq_mapping);
		return -ENOMEM;
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

	nvme_log("NVMe controller initialized successfully\n");
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

	nvme_log("Controller: VWC=%s, MDTS=%u (%uKB)\n",
			(data->vwc & NVME_CTRL_VWC_PRESENT) ? "yes" : "no",
			data->mdts, data->mdts ? (1U << data->mdts) * 4 : 0);

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
	params->types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_SEGMENT |
			UBLK_PARAM_TYPE_DISCARD;
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

	params->basic.virt_boundary_mask = 4095;

	/* Set write cache attributes if VWC is present */
	if (data->vwc & NVME_CTRL_VWC_PRESENT)
		params->basic.attrs = UBLK_ATTR_VOLATILE_CACHE | UBLK_ATTR_FUA;

	params->seg.seg_boundary_mask = 4095;
	params->seg.max_segment_size = 32 << 20;
	params->seg.max_segments = 127;

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

	nvme_log("Created I/O queue %d (depth %d)\n", qid, qsize);
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

	/* Delete I/O queues */
	if (data->io_queues) {
		for (i = 0; i < data->nr_io_queues; i++) {
			nvme_delete_io_queue(data, i + 1);
			nvme_queue_deinit(data, &data->io_queues[i]);
		}
		free(data->io_queues);
	}

	if (shutdown_ctrl)
		nvme_shutdown_controller(data);

	nvme_queue_deinit(data, &data->admin_queue);

	if (data->bar0 && data->bar0 != MAP_FAILED)
		munmap((void *)data->bar0, data->bar0_size);

	if (data->device_fd >= 0)
		close(data->device_fd);
	if (data->group_fd >= 0)
		close(data->group_fd);
	if (data->container_fd >= 0)
		close(data->container_fd);

	pthread_spin_destroy(&data->iova_lock);
	nvme_dmabuf_pool_deinit(data);

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
	__u16 next_tail;

	if (++nvmeq->sq_tail == nvmeq->qsize)
		nvmeq->sq_tail = 0;

	next_tail = nvmeq->sq_tail + 1;
	if (next_tail == nvmeq->qsize)
		next_tail = 0;
	if (next_tail != nvmeq->last_sq_tail)
		return;

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
	nvmeq->cq_head = (nvmeq->cq_head + 1) % nvmeq->qsize;
	if (nvmeq->cq_head == 0)
		nvmeq->cq_phase = !nvmeq->cq_phase;
}

/* Poll completion queue */
static inline void nvme_poll_cq(const struct ublksrv_queue *q,
				struct nvme_queue *nvmeq,
				struct nvme_vfio_tgt_data *data)
{
	bool found = false;

	nvme_sq_flush(nvmeq);

	while (nvme_cqe_pending(nvmeq)) {
		struct nvme_completion *cqe = &((struct nvme_completion *)nvmeq->cq_buffer)[nvmeq->cq_head];
		__u16 status_field, status, cid;
		int tag, result;
		const struct ublk_io_data *io_data;
		const struct ublksrv_io_desc *iod;

		found = true;

		ublk_rmb();

		status_field = READ_ONCE(cqe->status);
		cid = READ_ONCE(cqe->command_id);
		status = status_field >> 1;
		tag = cid;

		io_data = ublksrv_queue_get_io_data(q, tag);
		iod = io_data->iod;

		if (status == 0) {
			/* Discard returns 0 on success, read/write returns bytes */
			if (ublksrv_get_op(iod) == UBLK_IO_OP_DISCARD)
				result = 0;
			else
				result = iod->nr_sectors << 9;
		} else {
			fprintf(stderr, "NVMe error: op=%d tag=%d status=0x%x\n",
				 ublksrv_get_op(iod), tag, status);
			result = -EIO;
		}

		ublksrv_queue_dec_tgt_io_inflight(q);
		ublksrv_complete_io(q, tag, result);

		nvme_update_cq_head(nvmeq);
	}

	if (found)
		nvme_writel_mmio(nvmeq->cq_head, nvmeq->cq_doorbell);
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
			__u64 vaddr_page2 = ((__u64)io_buf + first_page_len) & ~(PAGE_SIZE - 1);
			__u64 paddr2 = nvme_virt_to_phys(data, vaddr_page2);
			if (!paddr2) {
				ublk_err("Failed to get paddr for 2nd page\n");
				return -EINVAL;
			}
			cmd->prp2 = htole64(paddr2);
		} else {
			cmd->prp2 = htole64(iova);
		}
	} else {
		cmd->prp2 = htole64(priv->prp_mapping.iova);

		if (nvme_build_prp_list(data, io_buf, len,
					priv->data_mapping.iova,
					priv->prp_list,
					PAGE_SIZE / sizeof(__le64)) < 0) {
			return -EINVAL;
		}
	}

	return 0;
}

/* Queue read/write I/O */
static int nvme_queue_rw_io(const struct ublksrv_queue *q,
			    struct nvme_queue *nvmeq,
			    const struct ublksrv_io_desc *iod, int tag,
			    struct nvme_vfio_tgt_data *data)
{
	struct nvme_rw_command *cmd;
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
	io_buf = nvme_pool_get_io_buf(data, q->q_id, tag);

	/* Get or create DMA mapping */
	iova = priv->data_mapping.iova;
	if (!iova) {
		size_t buf_size = data->max_io_buf_bytes;

		iova = nvme_map_dma(data, io_buf, buf_size, &priv->data_mapping);
		if (!iova) {
			ublk_err("Failed to map I/O buffer tag %d\n", tag);
			return -ENOMEM;
		}
	}

	op = ublksrv_get_op(iod);

	/* Get SQ entry */
	cmd = (struct nvme_rw_command *)nvmeq->sq_buffer + nvmeq->sq_tail;

	cmd->opcode = (op == UBLK_IO_OP_WRITE) ? NVME_CMD_WRITE : NVME_CMD_READ;
	cmd->flags = 0;
	cmd->cid = tag;
	cmd->nsid = data->nsid;
	cmd->rsvd2 = 0;
	cmd->metadata = 0;
	cmd->slba = htole64(slba);
	cmd->length = htole16(nlb);
	cmd->control = (ublksrv_get_flags(iod) & UBLK_IO_F_FUA) ? htole16(NVME_RW_FUA) : 0;
	cmd->dsmgmt = 0;
	cmd->reftag = 0;
	cmd->apptag = 0;
	cmd->appmask = 0;

	/* Setup PRP entries */
	if (nvme_setup_prps(cmd, data, priv, io_buf, iova, len) < 0)
		return -EINVAL;

	nvme_sq_submit_cmd(nvmeq);

	return 0;
}

/* Queue flush I/O */
static int nvme_queue_flush_io(const struct ublksrv_queue *q,
			       struct nvme_queue *nvmeq,
			       const struct ublksrv_io_desc *iod, int tag,
			       struct nvme_vfio_tgt_data *data)
{
	struct nvme_common_command *cmd;

	cmd = (struct nvme_common_command *)nvmeq->sq_buffer + nvmeq->sq_tail;

	cmd->opcode = NVME_CMD_FLUSH;
	cmd->flags = 0;
	cmd->cid = tag;
	cmd->nsid = data->nsid;
	cmd->cdw2[0] = 0;
	cmd->cdw2[1] = 0;
	cmd->metadata = 0;
	cmd->prp1 = 0;
	cmd->prp2 = 0;
	cmd->cdw10 = 0;
	cmd->cdw11 = 0;
	cmd->cdw12 = 0;
	cmd->cdw13 = 0;
	cmd->cdw14 = 0;
	cmd->cdw15 = 0;

	nvme_sq_submit_cmd(nvmeq);

	return 0;
}

/* Queue discard I/O (Dataset Management command) */
static int nvme_queue_discard_io(const struct ublksrv_queue *q,
				 struct nvme_queue *nvmeq,
				 const struct ublksrv_io_desc *iod, int tag,
				 struct nvme_vfio_tgt_data *data)
{
	struct nvme_common_command *cmd;
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

	cmd = (struct nvme_common_command *)nvmeq->sq_buffer + nvmeq->sq_tail;
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = NVME_CMD_DSM;
	cmd->flags = 0;
	cmd->cid = tag;
	cmd->nsid = htole32(data->nsid);
	cmd->prp1 = htole64(priv->prp_mapping.iova);
	cmd->cdw10 = htole32(0);  /* Number of ranges - 1 (single range) */
	cmd->cdw11 = htole32(NVME_DSMGMT_AD);  /* Deallocate attribute */

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
 */
static int nvme_vfio_setup(struct nvme_vfio_tgt_data *data)
{
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	struct vfio_region_info region_info = { .argsz = sizeof(region_info) };
	int version;

	/* Setup VFIO binding */
	if (setup_vfio_binding(data->pci_addr) < 0) {
		ublk_err("Failed to bind device to vfio-pci\n");
		return -1;
	}

	/* Get IOMMU group */
	data->iommu_group = get_iommu_group(data->pci_addr, &data->use_noiommu);
	if (data->iommu_group < 0) {
		ublk_err("Failed to get IOMMU group\n");
		return -1;
	}

	/* Open container */
	data->container_fd = open("/dev/vfio/vfio", O_RDWR);
	if (data->container_fd < 0) {
		ublk_err("open /dev/vfio/vfio: %s\n", strerror(errno));
		return -1;
	}

	/* Check API version */
	version = ioctl(data->container_fd, VFIO_GET_API_VERSION);
	if (version != VFIO_API_VERSION) {
		ublk_err("VFIO API version mismatch\n");
		return -1;
	}

	/* Check IOMMU support */
	if (data->use_noiommu) {
		if (!ioctl(data->container_fd, VFIO_CHECK_EXTENSION, VFIO_NOIOMMU_IOMMU)) {
			ublk_err("VFIO no-IOMMU not supported\n");
			return -1;
		}
	} else {
		if (!ioctl(data->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
			ublk_err("VFIO Type1 IOMMU not supported\n");
			return -1;
		}
	}

	/* Open VFIO group */
	data->group_fd = nvme_open_vfio_group(data->iommu_group,
					      data->container_fd,
					      &data->use_noiommu);
	if (data->group_fd < 0)
		return -1;

	/* Get device */
	data->device_fd = ioctl(data->group_fd, VFIO_GROUP_GET_DEVICE_FD, data->pci_addr);
	if (data->device_fd < 0) {
		ublk_err("VFIO_GROUP_GET_DEVICE_FD: %s\n", strerror(errno));
		return -1;
	}

	/* Get device info */
	if (ioctl(data->device_fd, VFIO_DEVICE_GET_INFO, &device_info) < 0) {
		ublk_err("VFIO_DEVICE_GET_INFO: %s\n", strerror(errno));
		return -1;
	}

	/* Enable PCI Bus Mastering */
	if (nvme_enable_pci_bus_master(data->device_fd) < 0)
		return -1;

	/* Map BAR0 */
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
	    info->max_io_buf_bytes > (32 << 20) ||
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

	/* Enable noiommu mode if requested */
	if (force_noiommu) {
		if (nvme_enable_noiommu_mode() < 0)
			goto err;
	}

	data->container_fd = -1;
	data->group_fd = -1;
	data->device_fd = -1;
	data->next_iova = 0x100000000ULL;
	data->nr_io_queues = info->nr_hw_queues;
	data->queue_depth = info->queue_depth;
	data->max_io_buf_bytes = info->max_io_buf_bytes;
	data->max_transfer_shift = 31 - __builtin_clz(info->max_io_buf_bytes);
	pthread_spin_init(&data->iova_lock, PTHREAD_PROCESS_PRIVATE);

	if (strlen(pci_addr) >= sizeof(data->pci_addr)) {
		ublk_err("PCI address too long\n");
		goto err;
	}
	strcpy(data->pci_addr, pci_addr);
	free(pci_addr);
	pci_addr = NULL;

	nvme_log("Initializing VFIO NVMe target for %s\n", data->pci_addr);

	if (nvme_vfio_setup(data) < 0)
		goto err;

	/* Read capabilities */
	cap = nvme_readq(data->bar0, NVME_REG_CAP);
	data->db_stride = (1 << ((cap >> 32) & 0xF)) * 4;

	if (nvme_validate_params(data, cap) < 0)
		goto err;

	/* Initialize dma_buf pool */
	if (nvme_dmabuf_pool_init(data) < 0) {
		ublk_err("Failed to initialize dma_buf pool\n");
		goto err;
	}

	/* Pre-read pagemap for noiommu mode */
	if (!nvme_use_iommu(data)) {
		if (nvme_read_pagemap(data) < 0) {
			ublk_err("Failed to read pagemap\n");
			goto err;
		}
	}

	/* Initialize controller */
	if (nvme_init_controller(data) < 0)
		goto err;

	/* Get controller capabilities */
	if (nvme_identify_controller(data) < 0)
		goto err;

	if (nvme_identify_namespace(data, &p) < 0)
		goto err;

	/* Setup I/O queues */
	data->io_queues = (struct nvme_queue *)calloc(data->nr_io_queues, sizeof(struct nvme_queue));
	if (!data->io_queues) {
		ublk_err("calloc io_queues: %s\n", strerror(errno));
		goto err;
	}

	for (int i = 0; i < data->nr_io_queues; i++) {
		int qsize = data->queue_depth + 1;
		if (nvme_create_io_queue(data, i + 1, qsize) < 0) {
			goto err;
		}
	}

	/* Setup JSON data */
	strcpy(tgt_json.name, "nvme_vfio");
	tgt_json.dev_size = data->dev_size;

	ublk_json_write_dev_info(cdev);
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_tgt_str(cdev, "pci_addr", data->pci_addr);
	ublk_json_write_params(cdev, &p);

	nvme_log("VFIO NVMe target initialized successfully\n");

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

	/* Poll NVMe CQ for completions */
	nvme_poll_cq(q, nvmeq, data);
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
