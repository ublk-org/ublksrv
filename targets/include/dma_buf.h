/* SPDX-License-Identifier: MIT or GPL-2.0-only */
#ifndef UBLKSRV_DMA_BUF_H
#define UBLKSRV_DMA_BUF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generic DMA Buffer Pool
 *
 * A reusable hugepage-backed DMA buffer pool that can be used by any target.
 * The pool handles memory allocation (mmap with MAP_HUGETLB) and physical
 * address lookup (pagemap) for NUMA-affine DMA memory.
 *
 * Usage pattern:
 *   1. Call dma_buf_pool_init() to allocate the pool
 *   2. For noiommu mode, call dma_buf_pool_read_pagemap() after init
 *   3. Use dma_buf_pool_virt_to_phys() for physical address lookup
 *   4. Call dma_buf_pool_deinit() to free the pool
 */
struct dma_buf_pool {
	void *base;			/* mmap'd base address */
	size_t size;			/* total allocated size */

	/* Pagemap cache for physical address lookup (noiommu mode) */
	uint64_t *pagemap_cache;
	size_t pagemap_nr_pages;
};

/**
 * Initialize a DMA buffer pool with hugepage-backed memory
 *
 * @param pool Pool structure to initialize
 * @param size Size of the pool in bytes
 * @return 0 on success, negative errno on failure
 */
int dma_buf_pool_init(struct dma_buf_pool *pool, size_t size);

/**
 * Read pagemap entries for physical address lookup (for noiommu mode)
 *
 * Must be called after dma_buf_pool_init() and before using
 * dma_buf_pool_virt_to_phys().
 *
 * @param pool Initialized pool
 * @return 0 on success, negative errno on failure
 */
int dma_buf_pool_read_pagemap(struct dma_buf_pool *pool);

/* Error return value for dma_buf_pool_virt_to_phys() */
#define DMA_BUF_PHYS_ERROR	((uint64_t)-1)

/**
 * Get physical address for a virtual address within the pool
 *
 * Only works if dma_buf_pool_read_pagemap() was called first.
 *
 * @param pool Pool with pagemap cache
 * @param vaddr Virtual address within the pool
 * @return Physical address, or DMA_BUF_PHYS_ERROR on error
 */
uint64_t dma_buf_pool_virt_to_phys(struct dma_buf_pool *pool, void *vaddr);

/**
 * Deinitialize a DMA buffer pool
 *
 * Frees all resources including the mmap'd memory and pagemap cache.
 *
 * @param pool Pool to deinitialize
 */
void dma_buf_pool_deinit(struct dma_buf_pool *pool);

#ifdef __cplusplus
}
#endif

#endif /* UBLKSRV_DMA_BUF_H */
