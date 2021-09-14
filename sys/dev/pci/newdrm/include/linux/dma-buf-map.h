/* Public domain. */

#ifndef _LINUX_DMA_BUF_MAP_H
#define _LINUX_DMA_BUF_MAP_H

#include <linux/io.h>
#include <linux/string.h>

struct dma_buf_map {
	union {
		void *vaddr_iomem;
		void *vaddr;
	};
	bool is_iomem;
};

static inline void
dma_buf_map_incr(struct dma_buf_map *dbm, size_t n)
{
	if (dbm->is_iomem)
		dbm->vaddr_iomem += n;
	else
		dbm->vaddr += n;
}

static inline void
dma_buf_map_memcpy_to(struct dma_buf_map *dbm, const void *src, size_t len)
{
	if (dbm->is_iomem)
		memcpy_toio(dbm->vaddr_iomem, src, len);
	else
		memcpy(dbm->vaddr, src, len);
}

#endif
