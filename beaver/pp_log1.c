#include <linux/uio.h>
#include "shadow_entry.h"

#define DEBUG 1

static inline void* pp_log_next_pos(struct page *pp_log)
{
	return page_address(pp_log) + pp_log->index + sizeof(int);
}

static inline loff_t pp_log_space(struct page *pp_log)
{
	loff_t space = PAGE_SIZE - pp_log->index;

	return space < sizeof(int) ? 0 : space - sizeof(int);
}

static void pp_log_commit(struct page *pp_log, loff_t pos, loff_t bytes)
{
	unsigned int *head_ptr = page_address(pp_log) + pp_log->index;
	unsigned int high = (pos & ~PAGE_MASK) << 16;
	unsigned int low = bytes;
	unsigned int head = high | low;

	WRITE_ONCE(*head_ptr, head);
	pp_log->index += sizeof(unsigned int) + roundup(bytes, sizeof(int));

	pr_debug("head_ptr=0x%px, pos=0x%llx, bytes=0x%llx, head=0x%x\n",
		head_ptr, pos, bytes, head);
}

static void pp_log_init(struct page *pp_log)
{
	unsigned int *head_ptr = page_address(pp_log);

	pp_log->mapping = NULL;
	pp_log->index = 0;
	*head_ptr = 0;
}

bool holder_partial_modifying(struct shadow_page_holder *holder)
{
	return holder->cur & ~1UL;
}

void holder_trans_partial_mode(struct shadow_page_holder *holder)
{
	unsigned int valid_idx = holder->cur & 1UL;
	unsigned int invalid_idx = 1UL - valid_idx;
	unsigned int new_cur = holder->cur | 2UL;
	void *old_read_ptr;
	loff_t new_read_ptr;

	holder->cur = new_cur;
	holder->pmem_pages[2] = holder->pmem_pages[invalid_idx];
	pp_log_init(holder->pmem_pages[2]);

	rcu_read_lock();
	old_read_ptr = rcu_dereference(holder->read_ptr);
	rcu_read_unlock();

	new_read_ptr = (loff_t)page_address(holder->pmem_pages[valid_idx]) | 1UL;
	rcu_assign_pointer(holder->read_ptr, new_read_ptr);
}

struct page *holder_new_pp_log(struct shadow_page_holder *holder,
				struct pp_args *args)
{
	struct page *new_log_page;
	struct page *old_log_page = holder->pmem_pages[2];

	BUG_ON(!old_log_page);

	new_log_page = pmem_page_alloc(args->mgr);
	//TODO need appending a log entry for new pp_log attaching
	pp_log_init(new_log_page);
	old_log_page->mapping = (struct address_space*)new_log_page;
	holder->pmem_pages[2] = new_log_page;

	return new_log_page;
}

static void pp_append(struct shadow_page_holder *holder,
	       struct iov_iter *iov, struct pp_args *args)
{
	struct page *pp_log;
	void *pmem_addr;

	if (!holder_partial_modifying(holder))
		holder_trans_partial_mode(holder);

	pp_log = holder->pmem_pages[2];

	if (unlikely(pp_log_space(pp_log) < args->bytes))
		pp_log = holder_new_pp_log(holder, args);

	pmem_addr = pp_log_next_pos(pp_log);
	_copy_from_iter_flushcache(pmem_addr, args->bytes, iov);
	pp_log_commit(pp_log, args->pos, args->bytes);
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
