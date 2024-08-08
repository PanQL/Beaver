#include <linux/dax.h>
#include <linux/blkdev.h>
#include <linux/pfn_t.h>
#include "shadow_entry.h"
#include "log.h"

extern struct kmem_cache *shadow_mgr_cachep;
struct kmem_cache *range_node_cachep = NULL;

int rng_cache_init(void)
{
	range_node_cachep = kmem_cache_create("shadow_rng_node_cachep",
						sizeof(struct range_node),
						0,
						(SLAB_RECLAIM_ACCOUNT|
						 SLAB_MEM_SPREAD),
						NULL);

	if (!range_node_cachep)
		return -ENOMEM;

	return 0;
}

void rng_cache_exit(void)
{
	if (range_node_cachep)
		kmem_cache_destroy(range_node_cachep);
}

static int
shadow_dax_notify_failure(struct dax_device *dax_dev, u64 offset,
			u64 len, int mf_flags)
{
	pr_warn("memory failure notifying in shadowfs not implemented!\n");
	pr_info("%s: dax_dev=0x%px, offset=0x%llx, len=0x%llx, mf_flags=0x%x\n",
		__func__, dax_dev, offset, len, mf_flags);
	return -EIO;
}

const struct dax_holder_operations shadow_dax_holder_operations = {
	.notify_failure		= shadow_dax_notify_failure,
};

static void print_pmem_mgr(struct shadow_pm_manager *mgr)
{
	pr_info("num_blocks: %lu\n", mgr->num_blocks);
	pr_info("virt_addr: [%px, %px]\n", mgr->virt_addr,
			mgr->virt_addr + mgr->num_blocks * PAGE_SIZE);
	for (int i = 0; i < mgr->cores; ++i)
		pr_info("cpu %d get %ld pm pages\n", i,
				mgr->free_lists[i].capacity);
}

void pmem_mgr_release(struct shadow_pm_manager *mgr, struct shadow_sb_info *sbi)
{
	struct dax_device *dax_dev = mgr->dax_dev;
	struct pm_free_list *free_list;
	struct range_node *node, *next;
	int i;

	for (i = 0; i < mgr->cores; ++i) {
		free_list = &mgr->free_lists[i];
		list_for_each_entry_safe(node, next, &free_list->nodes, list) {
			list_del_init(&node->list);
			kmem_cache_free(range_node_cachep, node);
		}
	}

	if (dax_dev)
		fs_put_dax(dax_dev, sbi);

	kvfree(mgr->free_lists);
	kmem_cache_free(shadow_mgr_cachep, mgr);
}

inline void pm_free_list_init(struct pm_free_list *list)
{
	spin_lock_init(&list->lock);
	list->capacity = 0UL;
	INIT_LIST_HEAD(&list->nodes);
}

/*
 * create a pmem manager holding dev
 *
 * @dev: block device with dax supported
 * @cpus: cpu core numbers for concurrent alloc/free
 * @log_page_nr: pages reserves for log region
 *
 * return valid reference if success, else NULL.
 */
int pmem_mgr_create(struct shadow_sb_info *sbi, const char *dev,
		    struct shadow_pm_manager *mgr, unsigned long log_page_nr)
{
	int err = 0;
	struct dax_device *dax_dev;
	struct block_device *bdev;
	u64 startoff;
	unsigned long num_blocks;
	void* virt_addr = NULL;
	pfn_t pfn_t;
	unsigned long pfn;
	unsigned int i;
	struct page *pmem_pages;
	fmode_t blkdev_mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;
	unsigned long pcp_log_blocks;
	struct page *low, *high;

	bdev = blkdev_get_by_path(dev, blkdev_mode, sbi);
	if (!bdev) {
		pr_err("No bdev\n");
		err = -EINVAL;
		goto failed;
	}
	pr_info("Get blkdev %s successfully\n", dev);

	dax_dev = fs_dax_get_by_bdev(bdev, &startoff,
				     sbi, &shadow_dax_holder_operations);
	blkdev_put(bdev, blkdev_mode);
	if (!dax_dev) {
		pr_err("No dax dev\n");
		err = -EINVAL;
		goto failed;
	}

	num_blocks = dax_direct_access(dax_dev, 0,
			LONG_MAX/PAGE_SIZE, DAX_ACCESS, &virt_addr, &pfn_t);

	if (!pfn_t_valid(pfn_t)) {
		pr_err("pmem pfn is not valid!\n");
		fs_put_dax(dax_dev, sbi);
		err = -EIO;
		goto failed;
	}
	pfn = pfn_t_to_pfn(pfn_t);
	pr_info("pfn=0x%lx, pfn_to_kaddr=0x%px\n", pfn, pfn_to_kaddr(pfn));

	mgr->startoff = startoff;
	mgr->pfn = pfn;
	mgr->virt_addr = virt_addr;
	mgr->dax_dev = dax_dev;
	mgr->cores = sbi->cpus;
	mgr->num_blocks = num_blocks;
	mgr->free_lists = kvmalloc_array(sbi->cpus,
					sizeof(struct pm_free_list), GFP_KERNEL);
	pr_info("%s: mgr->free_lists=0x%px\n", __func__, mgr->free_lists);
	for (i = 0; i < sbi->cpus; ++i)
		pm_free_list_init(&mgr->free_lists[i]);

	/*log_page_nr = shadow_raw_log_check(virt_addr, log_page_nr);
	mgr->log_page_nr = log_page_nr;
	BUG_ON(log_page_nr >= num_blocks);*/

	pmem_pages = pfn_to_page(pfn);
	pr_info("%s: pmem_page structs in [%px, %px]\n",
			__func__, pmem_pages, pmem_pages + num_blocks);
	pr_info("%s: 0x%lx pmem data pages, each with 0x%lx\n", __func__,
		num_blocks - HEAD_RESERVED_BLOCKS, sizeof(struct pm_page_desc));

	/*pm_descs = vzalloc((num_blocks - log_page_nr) * sizeof(struct pm_page_desc));
	BUG_ON(!pm_descs);
	for (i = HEAD_RESERVED_BLOCKS; i < num_blocks; ++i) {
		struct pm_page_desc *desc = &pm_descs[i - log_page_nr];
		INIT_LIST_HEAD(&desc->list);
		desc->pm_page = &pmem_pages[i];
		attach_page_private(&pmem_pages[i], desc);
		list_add(&desc->list, &mgr->free_lists[i % sbi->cpus].pages);
		mgr->free_lists[i % sbi->cpus].capacity += 1;
	}*/

	pcp_log_blocks =
		(num_blocks - HEAD_RESERVED_BLOCKS) / sbi->cpus;
	low = pmem_pages + HEAD_RESERVED_BLOCKS + 1;
	high = low + pcp_log_blocks;
	for (i = 0; i < sbi->cpus; ++i) {
		struct range_node *rng = kmem_cache_alloc(range_node_cachep,
								GFP_KERNEL);
		pr_info("%s: cpu=%d low=0x%px, high=0x%px\n",
			__func__, i, low, high);
		INIT_LIST_HEAD(&rng->list);
		rng->low = low;
		rng->high = high;
		mgr->free_lists[i].capacity = high - low;
		list_add(&rng->list, &mgr->free_lists[i].nodes);

		low = high + 1;
		high += pcp_log_blocks;
		if (high >= pmem_pages + num_blocks)
			high = pmem_pages + num_blocks - 1;
	}

	print_pmem_mgr(mgr);
	return 0;

failed:
	return err;
}

struct page *pmem_page_alloc(struct shadow_pm_manager *mgr, unsigned int num)
{
	struct list_head *entry;
	unsigned int cpuid;
	struct pm_free_list *free_list;
	struct range_node *node;
	struct page *ret = NULL;
	unsigned int retry_times = 0;

	cpuid = smp_processor_id();
retry:
	retry_times += 1;
	if (retry_times > mgr->cores)
		return NULL;

	free_list = &mgr->free_lists[cpuid];
	spin_lock(&free_list->lock);
	if (!free_list->capacity) {
		spin_unlock(&free_list->lock);
		cpuid = (cpuid + 1) % mgr->cores;
		goto retry;
	}

	if (num == 1)
		entry = free_list->nodes.prev;
	else
		entry = free_list->nodes.next;
	BUG_ON(entry == &free_list->nodes);
	node = container_of(entry, struct range_node, list);
	if (node->low + num - 1 < node->high) {
		ret = node->low;
		node->low += num;
	} else if (node->low + num - 1 == node->high) {
		ret = node->low;
		list_del_init(entry);
		kmem_cache_free(range_node_cachep, node);
	} else {
		spin_unlock(&free_list->lock);
		cpuid = (cpuid + 1) % mgr->cores;
		goto retry;
	}

	spin_unlock(&free_list->lock);
	SHADOW_STATS_ADD(pmem_allocated, num);

	return ret;
}

struct page *pmem_page_alloc_one(struct shadow_pm_manager *mgr)
{
	/*struct pm_page_desc *pm_page_desc;
	struct list_head *entry;
	unsigned int cpuid;
	struct pm_free_list *free_list;*/

	return pmem_page_alloc(mgr, 1);

	/*cpuid = smp_processor_id();
	free_list = &mgr->free_lists[cpuid];
	if (!free_list->capacity)
		BUG();

	list_del_init(entry);
	free_list->capacity -= 1;

	SHADOW_STATS_ADD(pmem_allocated, 1);

	pm_page_desc = list_entry(entry, struct pm_page_desc, list);

	return pm_page_desc->pm_page;*/
}

void pmem_page_free(struct page *page, struct shadow_pm_manager *mgr)
{
	struct range_node *node;
	unsigned int cpuid;
	struct pm_free_list *free_list;

	node = kmem_cache_alloc(range_node_cachep, GFP_KERNEL);
	INIT_LIST_HEAD(&node->list);
	node->low = page;
	node->high = page;

	cpuid = smp_processor_id();
	free_list = &mgr->free_lists[cpuid];
	list_add_tail(&node->list, &free_list->nodes);
	free_list->capacity += 1;
	SHADOW_STATS_ADD(pmem_released, 1);
}

/*void pmem_page_free(struct page *page, struct shadow_pm_manager *mgr)
{
	unsigned int cpuid;
	struct pm_free_list *free_list;
	struct pm_page_desc *desc;

	page->mapping = NULL;
	page->index = LONG_MAX;
	desc = (struct pm_page_desc*)page_private(page);

	cpuid = smp_processor_id();
	free_list = &mgr->free_lists[cpuid];

	list_add_tail(&desc->list, &free_list->pages);
	free_list->capacity += 1;

	SHADOW_STATS_ADD(pmem_released, 1);
}*/

unsigned int get_pmem_page_num(struct shadow_pm_manager *mgr,
				struct page *page)
{
	return (unsigned int)(page_to_pfn(page) - mgr->pfn);
}
