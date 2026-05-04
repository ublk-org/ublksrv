/* SPDX-License-Identifier: MIT or GPL-2.0-only */
#ifndef VFIO_IOMMUFD_H
#define VFIO_IOMMUFD_H

#include <config.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_VFIO_IOMMUFD

int vfio_iommufd_setup(const char *pci_addr, int *iommufd, int *device_fd,
		       __u32 *ioas_id, __u32 *dev_id);
void vfio_iommufd_cleanup(int iommufd, int device_fd, __u32 ioas_id);
int vfio_iommufd_map_dma(int iommufd, __u32 ioas_id,
			 void *vaddr, __u64 iova, size_t size);
void vfio_iommufd_unmap_dma(int iommufd, __u32 ioas_id,
			    __u64 iova, size_t size);

#else /* !HAVE_VFIO_IOMMUFD */

static inline int vfio_iommufd_setup(const char *pci_addr, int *iommufd,
				     int *device_fd, __u32 *ioas_id,
				     __u32 *dev_id)
{
	return -1;
}

static inline void vfio_iommufd_cleanup(int iommufd, int device_fd,
					__u32 ioas_id)
{
}

static inline int vfio_iommufd_map_dma(int iommufd, __u32 ioas_id,
				       void *vaddr, __u64 iova, size_t size)
{
	return -1;
}

static inline void vfio_iommufd_unmap_dma(int iommufd, __u32 ioas_id,
					  __u64 iova, size_t size)
{
}

#endif /* HAVE_VFIO_IOMMUFD */

static inline bool vfio_iommufd_enabled(void)
{
#ifdef HAVE_VFIO_IOMMUFD
	return true;
#else
	return false;
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* VFIO_IOMMUFD_H */
