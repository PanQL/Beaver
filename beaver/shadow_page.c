#include "shadow_entry.h"

struct kmem_cache *shadow_page_cachep = NULL;

int shadow_page_init()
{
	shadow_page_cachep = kmem_cache_create("shadow_page_cachep",
						sizeof(struct shadow_page),
						0,
						(SLAB_RECLAIM_ACCOUNT|
						 SLAB_MEM_SPREAD),
						NULL);
	if (!shadow_page_cachep)
		return -ENOMEM;

	return 0;
}

void shadow_page_exit()
{
	if (shadow_page_cachep)
		kmem_cache_destroy(shadow_page_cachep);
}

struct shadow_page* alloc_shadow_page(void)
{
	return kmem_cache_alloc(shadow_page_cachep, GFP_KERNEL);
}

void dealloc_shadow_page(struct shadow_page *shadow)
{
	return kmem_cache_free(shadow_page_cachep, shadow);
}

void create_shadow_page(struct page *page, enum ShadowType type)
{
	struct address_space *mapping = page_mapping(page);
	struct shadow_sb_info *sb_info = mapping->host->i_sb->s_fs_info;
	struct shadow_page *shadow = alloc_shadow_page();
	struct page *pmem_page = pmem_page_alloc(sb_info->mgr);
	void *pmem_addr = page_address(pmem_page);

	pmem_page->mapping = mapping;
	pmem_page->index = page->index;

	shadow->p_data = pmem_addr;
	shadow->type = type;
	shadow->entry_tail = 0UL;

	spin_lock(&mapping->private_lock);
	attach_page_private(page, shadow);
	spin_unlock(&mapping->private_lock);
}

void create_page_log(struct page *page, unsigned offset, size_t bytes)
{
	struct shadow_page *shadow = page_shadow_buffer(page);
	char *data = page_address(page);
	char *p = shadow->p_data;
	struct page_log_entry *entry = NULL;

	if (bytes < PAGE_SIZE / 2) {
		entry = (struct page_log_entry *)p;
		p += sizeof(struct shadow_log_entry);
	}
	memcpy(p, data, bytes);
	shadow_barrier();
	if (entry) {
		entry->bytes = bytes;
		entry->offset = offset;
		shadow->entry_tail += sizeof(struct shadow_log_entry) + bytes;
	}
}
