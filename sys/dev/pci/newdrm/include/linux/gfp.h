/* Public domain. */

#ifndef _LINUX_GFP_H
#define _LINUX_GFP_H

#include <sys/types.h>
#include <sys/malloc.h>
#include <uvm/uvm_extern.h>

#include <linux/mmzone.h>

#define __GFP_ZERO		M_ZERO
#define __GFP_DMA32		0x00010000
#define __GFP_NOWARN		0
#define __GFP_NORETRY		0
#define __GFP_RETRY_MAYFAIL	0
#define __GFP_MOVABLE		0
#define __GFP_COMP		0
#define __GFP_KSWAPD_RECLAIM	0
#define __GFP_HIGHMEM		0
#define __GFP_RECLAIMABLE	0
#define __GFP_NOMEMALLOC	0

#define GFP_ATOMIC		M_NOWAIT
#define GFP_NOWAIT		M_NOWAIT
#define GFP_KERNEL		(M_WAITOK | M_CANFAIL)
#define GFP_USER		(M_WAITOK | M_CANFAIL)
#define GFP_HIGHUSER		0
#define GFP_DMA32		__GFP_DMA32
#define GFP_TRANSHUGE_LIGHT	0

static inline bool
gfpflags_allow_blocking(const unsigned int flags)
{
	return (flags & M_WAITOK) != 0;
}

struct vm_page *alloc_pages(unsigned int, unsigned int);
void	__free_pages(struct vm_page *, unsigned int);

/*
 * XXX Kludge alert!
 * The TAILQ element links of pages allocated by the above API are free to
 * reuse.  As an ugly hack we map Linux' page's "private" field to vm_page's
 * TAILQ_ENTRY space.
 */
static inline void
page_set_private(struct vm_page *pg, unsigned long private)
{
	*((unsigned long *)&pg->pageq) = private;
}

static inline unsigned long
page_get_private(struct vm_page *pg)
{
	return *((unsigned long *)&pg->pageq);
}

static inline struct vm_page *
alloc_page(unsigned int gfp_mask)
{
	return alloc_pages(gfp_mask, 0);
}

static inline void
__free_page(struct vm_page *page)
{
	__free_pages(page, 0);
}

static inline unsigned long
__get_free_page(unsigned int gfp_mask)
{
	void *addr = km_alloc(PAGE_SIZE, &kv_page, &kp_dirty, &kd_nowait);
	return (unsigned long)addr;
}

static inline void
free_page(unsigned long addr)
{
	km_free((void *)addr, PAGE_SIZE, &kv_page, &kp_dirty);
}

#endif
