/* Public domain. */

#include <sys/types.h>
#include <sys/param.h>
#include <uvm/uvm.h>

#include <linux/kernel.h>
#include <linux/dma-buf-map.h>
#include <drm/drm_gem.h>

int
drm_gem_ttm_mmap(struct drm_gem_object *obj,
    vm_prot_t accessprot, voff_t off, vsize_t size)
{
	STUB();
	return -ENOSYS;
}

int
drm_gem_ttm_vmap(struct drm_gem_object *obj, struct dma_buf_map *dbm)
{
	STUB();
	return -ENOSYS;
}

void
drm_gem_ttm_vunmap(struct drm_gem_object *obj, struct dma_buf_map *dbm)
{
	STUB();
}
