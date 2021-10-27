/* Public domain. */

#ifndef _LINUX_DMA_FENCE_CHAIN_H
#define _LINUX_DMA_FENCE_CHAIN_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/pool.h>
#include <linux/dma-fence.h>
#include <linux/irq_work.h>

struct dma_fence_chain {
	struct dma_fence base;
	struct dma_fence *fence;
	struct dma_fence *prev;
	uint64_t prev_seqno;
	union {
		struct dma_fence_cb cb;
		struct irq_work work;
	};
	struct mutex lock;
};

extern struct pool dma_fence_chain_pool;

int dma_fence_chain_find_seqno(struct dma_fence **, uint64_t);
void dma_fence_chain_init(struct dma_fence_chain *, struct dma_fence *,
    struct dma_fence *, uint64_t);

extern const struct dma_fence_ops dma_fence_chain_ops;

static inline struct dma_fence_chain *
to_dma_fence_chain(struct dma_fence *fence)
{
	return fence != NULL && fence->ops == &dma_fence_chain_ops ?
	    container_of(fence, struct dma_fence_chain, base) : NULL;
}

static bool dma_fence_chain_enable_signaling(struct dma_fence *);
struct dma_fence *dma_fence_chain_walk(struct dma_fence *);

#define dma_fence_chain_for_each(f, h) \
	for (f = dma_fence_get(h); f != NULL; f = dma_fence_chain_walk(f))

static inline struct dma_fence_chain *
dma_fence_chain_alloc(void)
{
	return pool_get(&dma_fence_chain_pool, PR_WAITOK);
}

static inline void
dma_fence_chain_free(struct dma_fence_chain *dfc)
{
	pool_put(&dma_fence_chain_pool, dfc);
}

#endif
