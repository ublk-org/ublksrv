// SPDX-License-Identifier: MIT or GPL-2.0-only

/*
 * Generic DMA Buffer Pool
 *
 * Provides hugepage-backed memory pools with physical address lookup
 * for targets that need DMA-capable buffers (e.g., nvme_vfio).
 */

#define _GNU_SOURCE
#include <sched.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ublksrv_utils.h"
#include "dma_buf.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

int dma_buf_pool_init(struct dma_buf_pool *pool, size_t size)
{
	pool->base = mmap(NULL, size, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB |
			  MAP_POPULATE, -1, 0);
	if (pool->base == MAP_FAILED) {
		ublk_err("dma_buf_pool: mmap failed: %s\n", strerror(errno));
		pool->base = NULL;
		return -errno;
	}

	pool->size = size;
	pool->pagemap_cache = NULL;
	pool->pagemap_nr_pages = 0;

	memset(pool->base, 0, size);
	return 0;
}

int dma_buf_pool_read_pagemap(struct dma_buf_pool *pool)
{
	size_t nr_pages = pool->size / PAGE_SIZE;
	uint64_t base_vaddr = (uint64_t)pool->base;
	off_t offset;
	ssize_t ret;
	int pagemap_fd;

	pool->pagemap_cache = (uint64_t *)malloc(nr_pages * sizeof(uint64_t));
	if (!pool->pagemap_cache) {
		ublk_err("dma_buf_pool: pagemap cache alloc failed\n");
		return -ENOMEM;
	}

	pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	if (pagemap_fd < 0) {
		ublk_err("dma_buf_pool: open pagemap failed: %s\n", strerror(errno));
		free(pool->pagemap_cache);
		pool->pagemap_cache = NULL;
		return -errno;
	}

	offset = (base_vaddr / PAGE_SIZE) * sizeof(uint64_t);
	ret = pread(pagemap_fd, pool->pagemap_cache,
		    nr_pages * sizeof(uint64_t), offset);
	if (ret != (ssize_t)(nr_pages * sizeof(uint64_t))) {
		int saved_errno = errno;

		close(pagemap_fd);
		if (ret < 0)
			ublk_err("dma_buf_pool: pread pagemap failed: %s\n",
				 strerror(saved_errno));
		else
			ublk_err("dma_buf_pool: pread pagemap short read: %zd/%zu\n",
				 ret, nr_pages * sizeof(uint64_t));
		free(pool->pagemap_cache);
		pool->pagemap_cache = NULL;
		return ret < 0 ? -saved_errno : -EIO;
	}
	close(pagemap_fd);

	pool->pagemap_nr_pages = nr_pages;
	return 0;
}

uint64_t dma_buf_pool_virt_to_phys(struct dma_buf_pool *pool, void *vaddr)
{
	uint64_t va = (uint64_t)vaddr;
	uint64_t base = (uint64_t)pool->base;
	uint64_t entry;
	unsigned long pfn;
	size_t page_idx;

	if (!pool->pagemap_cache) {
		ublk_err("dma_buf_pool: pagemap cache not initialized\n");
		return DMA_BUF_PHYS_ERROR;
	}

	/* Check if vaddr is within this pool */
	if (va < base || va >= base + pool->size) {
		ublk_err("dma_buf_pool: vaddr 0x%llx outside pool\n",
			 (unsigned long long)va);
		return DMA_BUF_PHYS_ERROR;
	}

	page_idx = (va - base) / PAGE_SIZE;
	entry = pool->pagemap_cache[page_idx];

	/* Check page present bit (bit 63) */
	if (!(entry & (1ULL << 63))) {
		ublk_err("dma_buf_pool: page not present for vaddr 0x%llx\n",
			 (unsigned long long)va);
		return DMA_BUF_PHYS_ERROR;
	}

	/* Extract PFN (bits 0-54) per /proc/pid/pagemap documentation */
	pfn = entry & 0x007fffffffffffffULL;
	return (pfn * PAGE_SIZE) + (va & (PAGE_SIZE - 1));
}

void dma_buf_pool_deinit(struct dma_buf_pool *pool)
{
	if (pool->pagemap_cache) {
		free(pool->pagemap_cache);
		pool->pagemap_cache = NULL;
	}
	if (pool->base && pool->base != MAP_FAILED) {
		if (munmap(pool->base, pool->size) < 0)
			ublk_err("dma_buf_pool: munmap failed: %s\n",
				 strerror(errno));
		pool->base = NULL;
	}
	pool->size = 0;
	pool->pagemap_nr_pages = 0;
}
