// SPDX-License-Identifier: MIT or GPL-2.0-only
/*
 * VFIO iommufd cdev support for nvme_vfio target.
 *
 * This file is only compiled when HAVE_VFIO_IOMMUFD is defined.
 * It provides setup, cleanup, and DMA mapping operations using
 * the iommufd + VFIO cdev interface.
 */
#include <config.h>

#include <linux/vfio.h>
#include <linux/iommufd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>

#include <sched.h>
#include "ublksrv_utils.h"
#include "vfio_iommufd.h"

#define PAGE_SIZE 4096

/*
 * Open VFIO cdev for a PCI device.
 * Scans /sys/bus/pci/devices/{pci}/vfio-dev/ to find the vfioN name,
 * then opens /dev/vfio/devices/vfioN.
 */
static int vfio_open_cdev(const char *pci_addr)
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
		ublk_err( "opendir %s: %s\n", sysfs_path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;
		snprintf(dev_path, sizeof(dev_path),
			 "/dev/vfio/devices/%s", entry->d_name);
		fd = open(dev_path, O_RDWR);
		if (fd < 0)
			ublk_err( "open %s: %s\n", dev_path, strerror(errno));
		break;
	}

	closedir(dir);

	if (fd < 0)
		ublk_err( "No VFIO cdev found for %s\n", pci_addr);

	return fd;
}

/*
 * Setup iommufd-based VFIO device access.
 * Opens /dev/iommu, the VFIO cdev, binds the device to iommufd,
 * allocates an IOAS, and attaches the device to it.
 */
int vfio_iommufd_setup(const char *pci_addr, int *iommufd, int *device_fd,
		       __u32 *ioas_id, __u32 *dev_id)
{
	struct vfio_device_bind_iommufd bind = {};
	struct iommu_ioas_alloc ioas_alloc = {};
	struct vfio_device_attach_iommufd_pt attach = {};

	/* Open /dev/iommu */
	*iommufd = open("/dev/iommu", O_RDWR);
	if (*iommufd < 0) {
		ublk_err( "open /dev/iommu: %s\n", strerror(errno));
		return -1;
	}

	/* Open VFIO cdev */
	*device_fd = vfio_open_cdev(pci_addr);
	if (*device_fd < 0)
		goto err_close_iommufd;

	/* Bind device to iommufd */
	bind.argsz = sizeof(bind);
	bind.flags = 0;
	bind.iommufd = *iommufd;
	if (ioctl(*device_fd, VFIO_DEVICE_BIND_IOMMUFD, &bind) < 0) {
		ublk_err( "VFIO_DEVICE_BIND_IOMMUFD: %s\n", strerror(errno));
		goto err_close_device;
	}
	*dev_id = bind.out_devid;

	/* Allocate IOAS */
	ioas_alloc.size = sizeof(ioas_alloc);
	ioas_alloc.flags = 0;
	if (ioctl(*iommufd, IOMMU_IOAS_ALLOC, &ioas_alloc) < 0) {
		ublk_err( "IOMMU_IOAS_ALLOC: %s\n", strerror(errno));
		goto err_close_device;
	}
	*ioas_id = ioas_alloc.out_ioas_id;

	/* Attach device to IOAS */
	attach.argsz = sizeof(attach);
	attach.flags = 0;
	attach.pt_id = *ioas_id;
	if (ioctl(*device_fd, VFIO_DEVICE_ATTACH_IOMMUFD_PT, &attach) < 0) {
		ublk_err( "VFIO_DEVICE_ATTACH_IOMMUFD_PT: %s\n", strerror(errno));
		goto err_destroy_ioas;
	}

	return 0;

err_destroy_ioas:
	{
		struct iommu_destroy destroy = {};
		destroy.size = sizeof(destroy);
		destroy.id = *ioas_id;
		ioctl(*iommufd, IOMMU_DESTROY, &destroy);
	}
err_close_device:
	close(*device_fd);
	*device_fd = -1;
err_close_iommufd:
	close(*iommufd);
	*iommufd = -1;
	return -1;
}

void vfio_iommufd_cleanup(int iommufd, int device_fd, __u32 ioas_id)
{
	struct vfio_device_detach_iommufd_pt detach = {};
	struct iommu_destroy destroy = {};

	detach.argsz = sizeof(detach);
	ioctl(device_fd, VFIO_DEVICE_DETACH_IOMMUFD_PT, &detach);

	destroy.size = sizeof(destroy);
	destroy.id = ioas_id;
	ioctl(iommufd, IOMMU_DESTROY, &destroy);

	if (device_fd >= 0)
		close(device_fd);
	close(iommufd);
}

int vfio_iommufd_map_dma(int iommufd, __u32 ioas_id,
			 void *vaddr, __u64 iova, size_t size)
{
	struct iommu_ioas_map map = {};

	map.size = sizeof(map);
	map.flags = IOMMU_IOAS_MAP_FIXED_IOVA |
		    IOMMU_IOAS_MAP_WRITEABLE |
		    IOMMU_IOAS_MAP_READABLE;
	map.ioas_id = ioas_id;
	map.user_va = (__u64)vaddr;
	map.length = (size + PAGE_SIZE - 1) & ~((__u64)PAGE_SIZE - 1);
	map.iova = iova;

	if (ioctl(iommufd, IOMMU_IOAS_MAP, &map) < 0) {
		ublk_err( "IOMMU_IOAS_MAP: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

void vfio_iommufd_unmap_dma(int iommufd, __u32 ioas_id,
			    __u64 iova, size_t size)
{
	struct iommu_ioas_unmap unmap = {};

	unmap.size = sizeof(unmap);
	unmap.ioas_id = ioas_id;
	unmap.iova = iova;
	unmap.length = size;
	ioctl(iommufd, IOMMU_IOAS_UNMAP, &unmap);
}
