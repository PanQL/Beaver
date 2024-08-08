#include <linux/uio.h>
#include "shadow_entry.h"

struct page* pp_log_init_locked(struct shadow_page_holder *holder,
			struct pp_args *args, void **dram_addr)
{
	struct page *pp_log = NULL;
	bool latest_dram = false;

	pr_debug("%s: begin\n", __func__);

	// make sure that latest DRAM replica exists
	if (!holder->dram_page) {//no DRAM page
		holder->dram_page = alloc_pages(GFP_KERNEL, 0);
		*dram_addr = page_address(holder->dram_page);
	} else {
		*dram_addr = page_address(holder->dram_page);
		rcu_read_lock();
		if ((unsigned long)rcu_dereference(holder->read_ptr) & 1)
			latest_dram = true;
		rcu_read_unlock();
	}
	if (!latest_dram) {
		unsigned long read_ptr_val = (unsigned long)*dram_addr | 1UL;

		memcpy(*dram_addr,
			page_address(holder->pmem_pages[holder->cur]), PAGE_SIZE);
		rcu_assign_pointer(holder->read_ptr, (void*)read_ptr_val);
	}

	holder->pmem_pages[2] = pmem_page_alloc(args->mgr);
	pp_log = holder->pmem_pages[2];
	pp_log->index = 0;
	*(int*)page_address(pp_log) = 0;

	return pp_log;
}

void pp_log_flush_locked(struct shadow_page_holder *holder,
				struct pp_args *args)
{
	struct page *invalid_page = holder->pmem_pages[(holder->cur+1)%2];
	struct page *pp_log = holder->pmem_pages[2];

	pr_debug("%s: begin\n", __func__);
	//copy DRAM replica into invalide NVM page
	memcpy_flushcache(page_address(invalid_page),
			page_address(holder->dram_page), PAGE_SIZE);
	//flip this holder
	shadow_log_range_flush(args->log_mgr, args->ino,
			       args->mask_addr, args->mask_addr + PAGE_SIZE);
	holder->cur = holder->cur + 1;
	//clean pp_log
	pp_log->index = 0;
	*(int*)page_address(pp_log) = 0;
}

static inline void* pp_log_next_pos(struct page *pp_log)
{
	pp_log->index = 0;//TEMP;DELETE ME

	return page_address(pp_log) + pp_log->index + sizeof(int);
}

static inline loff_t pp_log_space(struct page *pp_log)
{
	loff_t space = PAGE_SIZE - pp_log->index;

	return space < sizeof(int) ? 0 : space - sizeof(int);
}

static void pp_append(struct shadow_page_holder *holder,
	       struct iov_iter *iov, struct pp_args *args)
{
	void *dram_addr = NULL, *pmem_addr;
	struct page *pp_log;
	unsigned int head = 0;

	// lock holder;
	spin_lock(&holder->lock);
	// make sure that pp_log exist
	pp_log = holder->pmem_pages[2];
	if (!pp_log)
		pp_log = pp_log_init_locked(holder, args, &dram_addr);
	else if (pp_log_space(pp_log) < args->bytes)// check if pp_log space enough
		pp_log_flush_locked(holder, args);// flush the DRAM replica to NVM
					    // invalid page
	BUG_ON(!pp_log);
	// write data to pp_log and 'double write' update DRAM replica
	pmem_addr = pp_log_next_pos(pp_log);
	if (!dram_addr) {
		dram_addr = page_address(holder->dram_page) + args->pos;
		pr_debug("%s:use old dram_addr 0x%px\n", __func__, dram_addr);
	}
	pr_debug("pmem_addr=0x%px, dram_addr=0x%px\n", pmem_addr, dram_addr);
	_copy_from_iter_flushcache(dram_addr, args->bytes, iov);
	memcpy_flushcache(pmem_addr, dram_addr, args->bytes);
	head = ((unsigned long)dram_addr & ~PAGE_MASK) << 16 | args->bytes;
	*(unsigned int*)(pmem_addr - sizeof(int)) = head;
	pp_log->index += sizeof(unsigned int) + args->bytes;
	pp_log->index = (pp_log->index + 3) & 0xffc;
	// unlock holder;
	spin_unlock(&holder->lock);
}

void ppl_append(struct address_space *mapping, loff_t rng_start,
			loff_t rng_end, struct iov_iter *iov)
{
	struct shadow_page_holder *holder;
	struct shadow_sb_info *sb_info = mapping->host->i_sb->s_fs_info;
	pgoff_t index = rng_start >> PAGE_SHIFT;
	XA_STATE(xas, &mapping->i_pages, index);
	struct pp_args args = {
		.ino = mapping->host->i_ino,
		.mgr = sb_info->mgr,
		.log_mgr = &sb_info->log_mgr,
		.pos = rng_start & ~PAGE_MASK,
		.bytes = rng_end - rng_start,
		.mask_addr = rng_start & PAGE_MASK,
	};

	rcu_read_lock();
	holder = xas_load(&xas);
	rcu_read_unlock();

	pr_debug("%s:idx=%ld,pos=%lld,bytes=%lld,mask_addr=%lld\n",
		__func__, index, args.pos, args.bytes, args.mask_addr);

	pp_append(holder, iov, &args);
}

