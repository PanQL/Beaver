#include "shadow_entry.h"
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/bvec.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/memcontrol.h>
#include <linux/pfn_t.h>
#include <linux/dax.h>
#include <linux/swap.h>
#include <linux/falloc.h>

#define DAX_SHIFT	(1)
#define DAX_LOCKED	(1UL << 0)

static inline void shadow_iov_save_state(struct iov_iter *iter,
				       struct iov_iter_state *state)
{
	state->iov_offset = iter->iov_offset;
	state->count = iter->count;
	state->nr_segs = iter->nr_segs;
}

static inline void shadow_iov_restore(struct iov_iter *i,
				      struct iov_iter_state *state)
{
	BUG_ON(!iter_is_ubuf(i) && !iter_is_iovec(i));

	i->iov_offset = state->iov_offset;
	i->count = state->count;
	if (iter_is_ubuf(i))
		return;
	i->iov -= state->nr_segs - i->nr_segs;
	i->nr_segs = state->nr_segs;
}

static unsigned long dax_to_pfn(void *entry)
{
	return xa_to_value(entry) >> DAX_SHIFT;
}

static void *dax_make_entry(unsigned long pfn, unsigned long flags)
{
	return xa_mk_value(flags | (pfn << DAX_SHIFT));
}

static bool dax_is_locked(void *entry)
{
	return xa_to_value(entry) & DAX_LOCKED;
}

static void *dax_lock_entry(struct xa_state *xas, void *entry)
{
	unsigned long v = xa_to_value(entry);
	return xas_store(xas, xa_mk_value(v | DAX_LOCKED));
}

static void dax_unlock_entry(struct xa_state *xas, void *entry)
{
	void *old;

	BUG_ON(dax_is_locked(entry));
	xas_reset(xas);
	xas_lock_irq(xas);
	old = xas_store(xas, entry);
	xas_unlock_irq(xas);
	BUG_ON(!dax_is_locked(old));
}

inline void shadow_barrier(void)
{
	asm volatile ("sfence\n" : : );
}

extern int shadow_setattr(struct user_namespace *mnt_userns,
			  struct dentry *dentry, struct iattr *iattr);

static void holder_read_slow(struct shadow_page_holder *holder, struct shadow_sb_info *sb_info,
				size_t length, struct iov_iter *to)
{
	struct page *new_pmem_page;
	void *new_pmem_addr;
	struct page *valid_pm, *invalid_pm;
	unsigned int cur, iv_cur;

	spin_lock(&holder->lock);
	cur = holder->cur & 1UL;
	iv_cur = 1UL - cur;
	valid_pm = holder->pmem_pages[cur];
	invalid_pm = holder->pmem_pages[iv_cur];
	new_pmem_page = pmem_page_alloc(sb_info->mgr);
	new_pmem_addr = page_address(new_pmem_page);
	pr_debug("%s: new_pmem_page=0x%px, new_pmem_addr=0x%px\n", __func__,
		new_pmem_page, new_pmem_addr);

	memcpy_flushcache(new_pmem_addr,
			page_address(valid_pm), PAGE_SIZE);
	while (invalid_pm) {
		unsigned int index = 0;
		unsigned int head, pos, bytes;
		unsigned int *ptr;

		pr_debug("%s: invalid_pm=0x%px, index=0x%x, invalid_pm->index=0x%lx\n",
			__func__, invalid_pm, index, invalid_pm->index);

		while (index < invalid_pm->index) {
			ptr = page_address(invalid_pm) + index;
			head = *ptr;
			ptr++;
			pos = head >> 16;
			bytes = head & ~PAGE_MASK;

			pr_debug("    addr=0x%px, pos=0x%x, bytes=0x%x\n", ptr, pos, bytes);

			memcpy_flushcache(new_pmem_addr + pos,
					ptr, bytes);
			index += sizeof(int) + roundup(bytes, sizeof(int));
		}

		invalid_pm = (struct page *)invalid_pm->mapping;
	}
	holder->pmem_pages[iv_cur] = new_pmem_page;
	rcu_assign_pointer(holder->read_ptr, new_pmem_addr);
	//TODO append flip log entry
	spin_unlock(&holder->lock);
}

static ssize_t shadow_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *filp = iocb->ki_filp;
	struct inode *inode = file_inode(filp);
	struct address_space *mapping = filp->f_mapping;
	pgoff_t index = iocb->ki_pos >> PAGE_SHIFT;
	void *entry;
	char *kaddr;
	ssize_t already_read = 0;
	XA_STATE(xas, &mapping->i_pages, index);

	pr_debug("%s: inode=0x%px, pos=0x%llx, bytes=0x%lx\n",
			__func__, inode, iocb->ki_pos, iov_iter_count(to));

	if (!iov_iter_count(to))
		return 0;
	if (unlikely(iocb->ki_pos >= i_size_read(inode)))
		return 0;

	inode_lock_shared(inode);
	rcu_read_lock();
	for (entry = xas_load(&xas); iov_iter_count(to); entry = xas_next(&xas)) {
		loff_t isize = i_size_read(inode);
		//size_t length = min(iov_iter_count(to), PAGE_SIZE);
		size_t offset = iocb->ki_pos & (PAGE_SIZE - 1UL);
		size_t length = min3(iov_iter_count(to),
				(size_t)(isize - iocb->ki_pos),
				PAGE_SIZE - offset);

		if (xas_retry(&xas, entry))
			continue;
		if (entry) {
			struct shadow_page_holder *holder = entry;
retry:
			loff_t read_ptr_val = (loff_t)rcu_dereference(holder->read_ptr);
			kaddr = (void*)(read_ptr_val & ~1ULL);
			pr_debug("  kaddr=0x%px\n", kaddr);
			/*if (virt_to_page(kaddr) == holder->pmem_pages[0] ||
			    virt_to_page(kaddr) == holder->pmem_pages[1]) {
				SHADOW_STATS_ADD(pmem_read, 1);
			} else {
				SHADOW_STATS_ADD(dram_read, 1);
			}*/
			if (read_ptr_val & 1ULL) {
				rcu_read_unlock();
				holder_read_slow(holder, inode->i_sb->s_fs_info, length, to);
				rcu_read_lock();
				goto retry;
			}
			_copy_to_iter(kaddr + offset, length, to);
		} else
			iov_iter_zero(length, to);

		iocb->ki_pos += length;
		already_read += length;
		if (isize <= iocb->ki_pos)
			break;
	}
	rcu_read_unlock();
	inode_unlock_shared(inode);

	return already_read;
}

static int shadow_open(struct inode *inode, struct file *file)
{
	const char *name = file->f_path.dentry->d_name.name;

	pr_debug("%s: inode=0x%px, file=%s\n", __func__, inode, name);
	return 0;
}

static int shadow_release(struct inode *inode, struct file *file)
{
	const char *name = file->f_path.dentry->d_name.name;

	pr_debug("%s: inode=0x%px, file=%s\n", __func__, inode, name);
	return 0;
}

static vm_fault_t shadow_filemap_read_fault(struct vm_fault *vmf)
{
	vm_fault_t ret = VM_FAULT_LOCKED;
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	XA_STATE(xas, &mapping->i_pages, vmf->pgoff);
	void *entry;
	struct folio *dram_folio = filemap_alloc_folio(GFP_KERNEL, 0);

	xas_lock_irq(&xas);
	entry = xas_load(&xas);
	if (xa_is_value(entry)) {
		struct page* page = folio_page(dram_folio, 0);
		folio_lock(dram_folio);
		page->private = dax_to_pfn(entry);
		vmf->page = page;
		xas_store(&xas, page);
	}
	xas_unlock_irq(&xas);

	return ret;
}

static vm_fault_t shadow_filemap_fault(struct vm_fault *vmf)
{
	bool write = (vmf->flags & FAULT_FLAG_WRITE) && !vmf->cow_page;
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	struct shadow_sb_info *sb_info = mapping->host->i_sb->s_fs_info;
	XA_STATE(xas, &mapping->i_pages, vmf->pgoff);
	void *entry, *new_entry;
	vm_fault_t ret;
	pfn_t pfn_t;
	struct page *latest, *older;
	unsigned long latest_pfn, older_pfn;

	if (!write)
		return shadow_filemap_read_fault(vmf);

	latest = NULL;
	older = NULL;
	xas_lock_irq(&xas);
	entry = xas_load(&xas);
	if (xa_is_value(entry)) {
		latest_pfn = dax_to_pfn(entry);
		latest = pfn_to_page(latest_pfn);
	}
	if (latest && latest->private) {
		older_pfn = latest->private;
		latest->private = 0;
		older = pfn_to_page(older_pfn);
	}
	if (!older) {
		older = pmem_page_alloc(sb_info->mgr);
		SHADOW_STATS_ADD(sync_persisted, 1);
	}
	BUG_ON(entry && !xa_is_value(entry));
	older->private = latest_pfn;
	older_pfn = page_to_pfn(older);
	new_entry = dax_make_entry(older_pfn, 0);
	dax_lock_entry(&xas, new_entry);
	pfn_t = pfn_to_pfn_t(older_pfn);

	xas_set_mark(&xas, PAGECACHE_TAG_DIRTY);
	xas_unlock_irq(&xas);

	ret = vmf_insert_mixed_mkwrite(vmf->vma, vmf->address, pfn_t);
	dax_unlock_entry(&xas, new_entry);

	return ret;
}

static const struct vm_operations_struct shadow_file_vm_ops = {
	.fault		= shadow_filemap_fault,
	.page_mkwrite	= shadow_page_mkwrite,
};

/*static int shadow_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_flags |= VM_MIXEDMAP;
	vma->vm_ops = &shadow_file_vm_ops;

	return 0;
}*/

/*
 * Get holders during [index, max)
 */
static unsigned int _get_holder_batch(struct address_space *mapping, pgoff_t index,
				pgoff_t max, struct shadow_page_holder **batch)
{
	XA_STATE(xas, &mapping->i_pages, index);
	struct shadow_page_holder *holder;
	unsigned int i = 0;

	rcu_read_lock();
	for (holder = xas_load(&xas); holder; holder = xas_next(&xas)) {
		if (xas.xa_index == max)
			break;

		batch[i++] = holder;
		if (i == 16) break;
	}
	rcu_read_unlock();

	return i;
}

struct commit_args {
	loff_t range_start, range_end;
	struct iov_iter *iov;
	struct iov_iter_state l_state;
	struct iov_iter_state r_state;
	struct journal_handle j_handle;
};

static int shadow_commit_range(struct address_space *mapping,
				struct commit_args *args)
{
	loff_t rng_start = args->range_start;
	loff_t rng_end = args->range_end;
	pgoff_t index = roundup(rng_start, PAGE_SIZE) >> PAGE_SHIFT;
	pgoff_t end = rounddown(rng_end, PAGE_SIZE) >> PAGE_SHIFT;
	int ret = 0;
	unsigned int next_cur;
	struct shadow_page_holder *holders[16];
	struct list_head holder_lists[SYNCUP_LIST_NUM];
	//struct shadow_sb_info *sb_info = mapping->host->i_sb->s_fs_info;
	unsigned int num, i;

	pr_debug("%s: rng_start=0x%llx, rng_end=0x%llx\n", __func__, args->range_start, args->range_end);

	if (args->r_state.count) {
		shadow_iov_restore(args->iov, &args->r_state);
		ppl_append(mapping,
			   rng_end & PAGE_MASK, rng_end, args->iov);
	}
	if (args->l_state.count) {
		shadow_iov_restore(args->iov, &args->l_state);
		ppl_append(mapping, rng_start,
			   min_t(loff_t, rng_end, (rng_start + (PAGE_SIZE-1)) & PAGE_MASK), args->iov);
	}

	if (index >= end)
		return ret;

	shadow_log_range_flush(&args->j_handle, mapping->host->i_ino, rng_start, rng_end);

	for (i = 0; i < SYNCUP_LIST_NUM; ++i)
		INIT_LIST_HEAD(&holder_lists[i]);

	do {
		num = _get_holder_batch(mapping, index, end, holders);

		for (i = 0; i < num; ++i) {
			struct shadow_page_holder *holder = holders[i];
			void *new_read_ptr;
			struct page *cur_page;

			next_cur = (holder->cur + 1) % 2;
			cur_page = holder->pmem_pages[next_cur];
			spin_lock(&holder->lock);
			holder->cur = next_cur;
			new_read_ptr = page_address(cur_page);
			rcu_assign_pointer(holder->read_ptr, new_read_ptr);

			/*if (holder->state == INIT) {
				holder->state = SYNCING;
				list_add(&holder->syncup,
					&holder_lists[(index+i) % SYNCUP_LIST_NUM]);
			}*/
			spin_unlock(&holder->lock);
		}

		index += num;
	} while (index < end);

	/*for (i = 0; i < SYNCUP_LIST_NUM; ++i) {
		struct syncup_list *s_list = &sb_info->syncup_args[i].s_list;

		if (list_empty(&holder_lists[i]))
			continue;

		spin_lock(&s_list->lock);
		list_splice_tail_init(&holder_lists[i], &s_list->head);
		spin_unlock(&s_list->lock);
	}*/

	return ret;
}

int shadow_fsync(struct file *file, loff_t start,
			loff_t end, int datasync)
{
	return 0;
}

int shadow_setattr(struct user_namespace *mnt_userns, struct dentry *dentry,
		   struct iattr *iattr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(mnt_userns, dentry, iattr);
	if (error)
		return error;

	if (iattr->ia_valid & ATTR_SIZE) {
		//truncate_setsize(inode, iattr->ia_size);
		i_size_write(inode, iattr->ia_size);
		inode->i_ctime = current_time(inode);
	}
	setattr_copy(mnt_userns, inode, iattr);
	mark_inode_dirty(inode);
	return 0;
}

static int shadow_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	return 0;
}

const struct inode_operations shadow_file_inode_ops = {
	.getattr	= simple_getattr,
	.setattr	= shadow_setattr,
};

static void restore_shadow_page(const struct page *shadow_page,
				struct address_space *mapping)
{
	struct page *dram_page = xa_load(&mapping->i_pages, shadow_page->index);
	void *pmem_addr = page_address(shadow_page);
	void *dram_addr;

	BUG_ON(!dram_page);
	BUG_ON(!PageLocked(dram_page));
	dram_addr = page_address(dram_page);

	memcpy(dram_addr, pmem_addr, PAGE_SIZE);
}

static void shadow_readahead(struct readahead_control *ractl)
{
	pgoff_t index = readahead_index(ractl);
	unsigned int page_nr = readahead_count(ractl);
	unsigned int max = index + page_nr;
	struct address_space *mapping = ractl->mapping;
	struct xarray *shadow_mapping = mapping->private_data;

	const struct file_operations *real_fops;
	struct iov_iter i;
	struct kiocb kiocb;
	struct page *page, *shadow_page;
	struct shadow_inode *s_inode = SHADOW_I(mapping->host);
	struct file *real_filp = s_inode->file_handle;

	XA_STATE(xas, shadow_mapping, index);
	if (!real_filp)
		goto out;
	BUG_ON(!real_filp);
	real_fops = real_filp->f_op;
	iov_iter_xarray(&i, READ, &ractl->mapping->i_pages, 0, 0);
	while (index <= max && (shadow_page = xas_find(&xas, max))) {
		// copy content of shadow_page into corresponding dram page
		restore_shadow_page(shadow_page, mapping);
		if (shadow_page->index == index)
			goto skip;
		// submit consecutive dram page into bio
		i.xarray_start = index << PAGE_SHIFT;
		i.count = (shadow_page->index - index) << PAGE_SHIFT;
		init_sync_kiocb(&kiocb, real_filp);
		kiocb.ki_pos = i.xarray_start;
		real_fops->read_iter(&kiocb, &i);

skip:
		index = shadow_page->index + 1;
	}

	if (index <= max) {
		i.xarray_start = index << PAGE_SHIFT;
		i.count = (max - index + 1) << PAGE_SHIFT;
		init_sync_kiocb(&kiocb, real_filp);
		kiocb.ki_pos = i.xarray_start;
		real_fops->read_iter(&kiocb, &i);
	}

	/*pr_warn("%s: pos=%lld, len=%ld\n", __func__, pos, len);*/
	/*BUG_ON(!real_filp);*/
	/*real_fops = real_filp->f_op;*/

	/*iov_iter_xarray(i, READ, &ractl->mapping->i_pages, pos, len);*/
	/*init_sync_kiocb(&kiocb, real_filp);*/
	/*kiocb.ki_pos = pos;*/

	/*real_fops->read_iter(&kiocb, i);*/

out:
	/*now we have [pos, pos + len) updated, set update bit and unlock.*/
	while((page = readahead_page(ractl))) {
		SetPageUptodate(page);
		unlock_page(page);
	}
}

static int shadow_read_folio(struct file *file, struct folio *folio)
{
	struct address_space *mapping = file->f_mapping;
	struct xarray *shadow_mapping = mapping->private_data;
	struct shadow_inode *s_inode = SHADOW_I(file->f_mapping->host);
	const loff_t real_pos = folio_pos(folio);
	pgoff_t index = folio_index(folio);
	struct file *real_filp = s_inode->file_handle;
	loff_t real_f_len;
	unsigned int real_block_size;
	size_t real_block_mask;

	size_t len = folio_size(folio);
	struct bio_vec bvec = {
		.bv_page = folio_page(folio, 0),
		.bv_offset = 0,
	};
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t size;
	struct page *shadow_page;

retry_find:
	shadow_page = xa_load(shadow_mapping, index);
	if (shadow_page) {
		lock_page(shadow_page);
		/*
		 * if shadow_page is not in the same pos as folio,
		 * it had been truncated from shadow mapping.
		 * Retry to get the newer entry until it is empitied.
		 */
		if (shadow_page->index != index &&
		    shadow_page->mapping != mapping) {
			unlock_page(shadow_page);
			goto retry_find;
		}
		unlock_page(shadow_page);
		memcpy(folio_address(folio),
		       page_address(shadow_page), PAGE_SIZE);

		goto out;
	}

	if (!real_filp) {
		zero_user(folio_page(folio, 0), 0, PAGE_SIZE);
		goto out;
	}

	real_f_len = i_size_read(real_filp->f_inode);
	real_block_size = i_blocksize(real_filp->f_inode);
	real_block_mask = real_block_size - 1UL;

	/*WARN(real_f_len <= real_pos, "%s: real_f_len=%llx, real_pos=%llx\n",*/
			/*__func__, real_f_len, real_pos);*/
	if (real_f_len > real_pos && real_f_len - real_pos < len)
		len = (size_t)(real_f_len - real_pos);
	if (len & real_block_mask)
		len = (len & ~real_block_mask) + real_block_size;
	bvec.bv_len = len;

	/*pr_warn("%s: to read bvec={.bv_page=0x%px, .bv_len=%d} from realpos=0x%llx\n",*/
		/*__func__, bvec.bv_page, bvec.bv_len, real_pos);*/

	init_sync_kiocb(&kiocb, real_filp);
	kiocb.ki_pos = real_pos;
	iov_iter_bvec(&iter, READ, &bvec, 1, bvec.bv_len);

	size = real_filp->f_op->read_iter(&kiocb, &iter);

	/*pr_warn("%s: size=%ld, len=%ld\n", __func__, size, len);*/
	/*BUG_ON(size != len && size != (real_f_len - real_pos));*/

out:
	folio_mark_uptodate(folio);
	folio_unlock(folio);

	return 0;
}

static int shadow_write_begin(struct journal_handle *j_handle,
			      struct address_space *mapping, loff_t pos,
			      unsigned len, struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_SHIFT;
	struct inode *inode = mapping->host;
	struct shadow_sb_info *sb_info = inode->i_sb->s_fs_info;
	struct shadow_page_holder *holder;
	XA_STATE(xas, &mapping->i_pages, index);

	rcu_read_lock();
	holder = xas_load(&xas);
	rcu_read_unlock();

	if (unlikely(!holder)) {
		struct shadow_page_holder *temp;
		struct page *p_page0, *p_page1;
		bool page_used = false;

		holder = holder_alloc();//alloc holder
		p_page0 = pmem_page_alloc(sb_info->mgr);
		p_page1 = pmem_page_alloc(sb_info->mgr);

		xas_lock_irq(&xas);
		xas_reset(&xas);
		if ((temp = xas_load(&xas))) {
			holder_free(holder);
			holder = temp;
		} else {
			page_used = true;
			holder->pmem_pages[0] = p_page0;
			holder->pmem_pages[1] = p_page1;
			xas_store(&xas, holder);
		}
		xas_unlock_irq(&xas);

		if (likely(page_used))
			shadow_log_pmem_alloc(j_handle,
					(unsigned int)inode->i_ino,
					index,
					get_pmem_page_num(sb_info->mgr, p_page0),
					get_pmem_page_num(sb_info->mgr, p_page1));
		else {
			pmem_page_free(p_page0, sb_info->mgr);
			pmem_page_free(p_page1, sb_info->mgr);
		}
	}

	*pagep = holder->pmem_pages[(holder->cur + 1) % 2];
	if (holder->cur == -1)
		*fsdata = NULL;
	else
		*fsdata = page_address(holder->pmem_pages[holder->cur]);

	return 0;
}

static int shadow_write_end(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned copied,
			    struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	loff_t old_size = inode->i_size;
	loff_t new_size = pos + copied;

	if (new_size > old_size)
		i_size_write(inode, new_size);

	return copied;
}

static void shadow_invalidate_folio(struct folio *folio,
					size_t offset, size_t len)
{
	struct address_space *mapping = folio_mapping(folio);
	struct shadow_sb_info *sb_info = mapping->host->i_sb->s_fs_info;
	struct page *pmem_page = folio_detach_private(folio);

	BUG_ON(len != PAGE_SIZE);
	pmem_page_free(pmem_page, sb_info->mgr);
}

/*
 * We remove DRAM replica from mapping by this interface.
 */
static bool shadow_release_folio(struct folio *folio, gfp_t gfp)
{
	/*struct address_space *mapping = folio_mapping(folio);*/
	struct shadow_page_holder *holder;
	struct page *page = folio_page(folio, 0);

	BUG_ON(!folio_test_locked(folio));
	//pr_info("%s: Page=0x%px(%d)\n", __func__, folio, folio_ref_count(folio));

	holder = folio_get_private(folio);
	spin_lock(&holder->lock);
	if (page == holder->dram_page) {
		struct page *cur_pmem_page = holder->pmem_pages[holder->cur];
		void *new_read_ptr = page_address(cur_pmem_page);

		folio->mapping = NULL;
		folio_detach_private(folio);
		holder->dram_page = NULL;
		rcu_assign_pointer(holder->read_ptr, new_read_ptr);
		__mod_lruvec_page_state(page, NR_FILE_PAGES, -1);
	}
	spin_unlock(&holder->lock);

	return true;
}

int flush_pmem_pages(struct address_space *mapping)
{
	struct pagevec pvec;
	struct list_head to_free;
	struct list_head *lru;
	struct page *pm_page;
	struct list_head *wb_list = &mapping->private_list;
	/*struct inode *inode = mapping->host;*/
	/*struct shadow_inode *s_inode = SHADOW_I(inode);*/
	/*struct file *real_filp = READ_ONCE(s_inode->file_handle);*/
	struct shadow_sb_info *sb_info = mapping->host->i_sb->s_fs_info;
	struct shadow_pm_manager *mgr = sb_info->mgr;
	unsigned int i;
	/*ssize_t size;*/
	struct bio_vec bvec;
	struct iov_iter iter;
	struct kiocb kiocb;
	// count write out pmem pages and released pmem pages
	unsigned int written_out = 0;
	unsigned int released = 0;

	/*pr_warn("%s: now we begin to write for kupdate\n", __func__);*/
	/*if (!real_filp) {*/
		/*spin_lock(&mapping->private_lock);*/
		/*lru = wb_list->prev;*/
		/*while (lru != wb_list) {*/
			/*pm_page = list_entry(lru, struct page, lru);*/
			/*lru = lru->prev;*/
			/*list_del_init(&pm_page->lru);*/
			/*pmem_page_free(pm_page, mgr);*/
		/*}*/
		/*spin_unlock(&mapping->private_lock);*/
		/*return 0;*/
	/*}*/

	/*init_sync_kiocb(&kiocb, real_filp);*/
	INIT_LIST_HEAD(&to_free);
again:
	pagevec_init(&pvec);
	spin_lock(&mapping->private_lock);
	if (list_empty(wb_list)) {
		spin_unlock(&mapping->private_lock);
		/*if (written_out || released)*/
			/*pr_warn("%s: flushed %d pages, released %d pages",*/
				/*__func__, written_out, released);*/
		return 0;
	}
	lru = wb_list->prev;
	while (lru != wb_list && pagevec_space(&pvec)) {
		pm_page = list_entry(lru, struct page, lru);
		lru = lru->prev;
		lock_page(pm_page);
		if (pm_page->mapping != mapping->private_data) {
			/*
			 * free invalid pmem pages.
			 */
			list_move(&pm_page->lru, &to_free);
			released += 1;
		} else {
			list_del_init(&pm_page->lru);
			pagevec_add(&pvec, pm_page);
		}
		unlock_page(pm_page);
	}
	spin_unlock(&mapping->private_lock);
	written_out += pagevec_count(&pvec);
	/*pr_warn("%s: flushed %d pages, released %d pages",*/
		/*__func__, written_out, released);*/

	// free all unused pmem pages
	while (!list_empty(&to_free)) {
		struct page *it = list_entry(to_free.prev, struct page, lru);
		list_del_init(&it->lru);
		pmem_page_free(it, mgr);
	}

	//write out committed pm pages.
	for (i = 0; i < pagevec_count(&pvec); ++i) {
		pm_page = pvec.pages[i];
		bvec.bv_page = pm_page;
		bvec.bv_offset = 0;
		bvec.bv_len = PAGE_SIZE;
		kiocb.ki_pos = page_offset(pm_page);
		iov_iter_bvec(&iter, WRITE, &bvec, 1, bvec.bv_len);
		/*size = real_filp->f_op->write_iter(&kiocb, &iter);*/
		/*BUG_ON(size != PAGE_SIZE);*/

		lock_page(pm_page);
		if (pm_page->mapping != mapping->private_data) {
			pmem_page_free(pm_page, mgr);
			released += 1;
		}
		unlock_page(pm_page);
	}

	//do it again
	goto again;
}

static bool shadow_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	unsigned long flags;

	if (folio_test_set_dirty(folio))
		return false;

	xa_lock_irqsave(&mapping->i_pages, flags);
	if (folio->mapping) {	/* Race with truncate? */
		WARN_ON_ONCE(!folio_test_uptodate(folio));
		__xa_set_mark(&mapping->i_pages, folio_index(folio),
				PAGECACHE_TAG_DIRTY);
	}
	xa_unlock_irqrestore(&mapping->i_pages, flags);

	if (mapping->host) {
		/* !PageAnon && !swapper_space */
		__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
	}

	return true;
}

static int shadow_flush_thread(void *arg)
{
	struct address_space *mapping = arg;
	unsigned long next_wakeup, cur;

	while (true) {
		flush_pmem_pages(mapping);

		next_wakeup = jiffies + prandom_u32_max(1 * HZ);
		cur = jiffies;
		schedule_timeout_interruptible(next_wakeup - cur);

		if (kthread_should_stop())
			break;
	}

	return 0;
}

int shadow_run_flush_thread(struct shadow_inode *s_inode)
{
	BUG_ON(s_inode->flush_task);
	s_inode->flush_task = kthread_run(shadow_flush_thread,
					  s_inode->vfs_node.i_mapping,
					  "shadow_flush_thread");
	if (IS_ERR(s_inode->flush_task))
		return PTR_ERR(s_inode->flush_task);

	return 0;
}

void shadow_destroy_flush_thread(struct shadow_inode *s_inode)
{
	if (!s_inode->flush_task)
		return;

	kthread_stop(s_inode->flush_task);
}

static inline bool iov_iter_is_aligned_ubuf(const struct iov_iter *i,
					unsigned addr_mask, unsigned len_mask)
{
	if (unlikely(!iter_is_ubuf(i)))
		return false;
	if (i->count & len_mask)
		return false;
	if ((unsigned long)(i->ubuf + i->iov_offset) & addr_mask)
		return false;
	return true;
}

inline void* holder_old_addr(struct shadow_page_holder *holder)
{
	return page_address(holder->pmem_pages[(holder->cur + 1) % 2]);
}

static void __page_holder_append_batch(struct journal_handle *j_handle,
				       struct address_space *mapping,
				       unsigned int index, unsigned int num)
{
	struct inode *inode = mapping->host;
	struct shadow_sb_info *sb_info = inode->i_sb->s_fs_info;
	struct shadow_page_holder *new;
	struct page *p_page0, *p_page1;
	unsigned int i;
	XA_STATE(xas, &mapping->i_pages, index);

	xas_lock(&xas);
	for (i = index; i < index + num; ++i) {
		new = holder_alloc();
		BUG_ON(new->dram_page);

		p_page0 = pmem_page_alloc(sb_info->mgr);
		p_page1 = pmem_page_alloc(sb_info->mgr);
		p_page0->mapping = mapping;
		p_page1->mapping = mapping;
		shadow_log_pmem_alloc(j_handle,
				(unsigned int)inode->i_ino,
				i,
				get_pmem_page_num(sb_info->mgr, p_page0),
				get_pmem_page_num(sb_info->mgr, p_page1));
		if (i & 1) {
			new->pmem_pages[0] = p_page0;
			new->pmem_pages[1] = p_page1;
		} else {
			new->pmem_pages[0] = p_page1;
			new->pmem_pages[1] = p_page0;
		}

		xas_set(&xas, i);
		BUG_ON(xas_store(&xas, new));
	}
	xas_unlock(&xas);
}

static ssize_t __aligned_ubuf_write(struct journal_handle *j_handle,
				    struct address_space *mapping,
				    unsigned int index,
				    void *src_addr, unsigned long src_len)
{
	struct inode *inode = mapping->host;
	loff_t old_size = i_size_read(inode);
	bool is_append = old_size == (index << PAGE_SHIFT);
	ssize_t written = 0;
	void *entry;
	struct shadow_page_holder *holder;
	XA_STATE(xas, &mapping->i_pages, index);

	if (is_append)
		__page_holder_append_batch(j_handle, mapping,
						index, src_len >> PAGE_SHIFT);

	stac();
	while (src_len) {
		rcu_read_lock();
		entry = xas_next(&xas);
		rcu_read_unlock();
		holder = entry;
		avx_copy(holder_old_addr(holder), src_addr, PAGE_SIZE);
		src_len -= PAGE_SIZE;
		src_addr += PAGE_SIZE;
		written += PAGE_SIZE;
	}
	clac();

	if (is_append && holder)
		i_size_write(inode, old_size + written);

	SHADOW_STATS_ADD(simd_written, written);

	return written;
}

static ssize_t __shadow_file_write_iter(struct kiocb *iocb, struct iov_iter *from,
					struct commit_args *args)
{
	struct iov_iter_state *l_state = &args->l_state;
	struct iov_iter_state *r_state = &args->r_state;
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	loff_t pos = iocb->ki_pos;
	ssize_t		written = 0;
	ssize_t		err;
	ssize_t		status;

	err = file_update_time(file);
	if (err)
		goto out;

	// only for overwrite/append now, and hole is not allowed
	if (PAGE_ALIGNED(pos) &&
			iov_iter_is_aligned_ubuf(from, 63UL, ~PAGE_MASK)) {
		unsigned long count = iov_iter_count(from);
		void *addr = from->ubuf + from->iov_offset;
		written = __aligned_ubuf_write(&args->j_handle, mapping,
						pos >> PAGE_SHIFT, addr, count);
		iov_iter_advance(from, written);
		goto out;
	}

	do {
		struct page *page;
		unsigned long offset;	/* Offset into pagecache page */
		unsigned long bytes;	/* Bytes to write to page */
		size_t copied;		/* Bytes copied from user */
		void *invalid_page_addr = NULL;
		void *addr;

		offset = (pos & (PAGE_SIZE - 1));
		bytes = min_t(unsigned long, PAGE_SIZE - offset,
				iov_iter_count(from));

		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}

		status = shadow_write_begin(&args->j_handle, mapping, pos,
						bytes, &page, &invalid_page_addr);
		if (unlikely(status < 0))
			break;
		if (bytes < PAGE_SIZE / 2) {
			loff_t old_size, new_size;

			if (!offset)
				shadow_iov_save_state(from, r_state);
			else
				shadow_iov_save_state(from, l_state);
			iov_iter_advance(from ,bytes);
			old_size = inode->i_size;
			new_size = pos + bytes;
			if (new_size > old_size)
				i_size_write(inode, new_size);

			pos += bytes;
			written += bytes;
			goto skip;
		} else if (bytes < PAGE_SIZE) {
			if (offset) {
				if (invalid_page_addr)
					memcpy_flushcache(page_address(page),
							invalid_page_addr, offset);
				args->range_start = args->range_start & ~PAGE_MASK;
			}
			if (offset + bytes < PAGE_SIZE) {
				if (invalid_page_addr)
					memcpy_flushcache(page_address(page) + offset + bytes,
							invalid_page_addr + offset + bytes,
							PAGE_SIZE - offset - bytes);
				args->range_end = roundup(args->range_end, PAGE_SIZE);
			}
		}

		addr = page_address(page) + offset;
		copied = _copy_from_iter_flushcache(addr, bytes, from);

		status = shadow_write_end(file, mapping, pos, bytes, copied,
						page, invalid_page_addr);
		if (unlikely(status != copied)) {
			iov_iter_revert(from, copied - max(status, 0L));
			if (unlikely(status < 0))
				break;
		}
		pos += status;
		written += status;
skip:
	} while (iov_iter_count(from));
	SHADOW_STATS_ADD(normal_written, written);

out:
	if (likely(written > 0))
		iocb->ki_pos += written;

	return written ? written : err;
}

#define pr_iov_state(name, state) pr_debug("%s={.iov_offset=%ld, .count=%ld, .nr_segs=%ld}", \
		#name, \
		state.iov_offset, \
		state.count, \
		state.nr_segs)

ssize_t shadow_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct shadow_inode *s_inode = SHADOW_I(inode);
	struct commit_args args = {
		.iov = from,
		.l_state={.count=0},
		.r_state={.count=0},
		.range_start = iocb->ki_pos,
		.range_end = iocb->ki_pos + iov_iter_count(from),
	};
	ssize_t ret;

	shadow_init_journal_handle(inode->i_sb, &args.j_handle);

	pr_debug("%s: inode=0x%px, pos=0x%llx, length=0x%lx\n", __func__,
			inode, iocb->ki_pos, iov_iter_count(from));
	spin_lock(&s_inode->lock);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __shadow_file_write_iter(iocb, from, &args);
	if (ret > 0) {
		if (args.l_state.count)
			pr_iov_state(l_state, args.l_state);
		if (args.r_state.count)
			pr_iov_state(r_state, args.r_state);
		inode_lock(inode);
		shadow_commit_range(file->f_mapping, &args);
		inode_unlock(inode);
	}
	shadow_destroy_journal_handle(inode->i_sb, &args.j_handle);
	spin_unlock(&s_inode->lock);

	return ret;
}

long shadow_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file_inode(file);
	loff_t old_isize = inode->i_size;
	unsigned long index = offset >> PAGE_SHIFT;
	unsigned long end = (offset + len) >> PAGE_SHIFT;
	struct journal_handle j_handle;
	bool extend;
	long ret;

	if (mode != (mode & FALLOC_FL_KEEP_SIZE)) {
		ret = -EOPNOTSUPP;
		goto finish;
	}

	extend = !(mode & FALLOC_FL_KEEP_SIZE);

	shadow_init_journal_handle(inode->i_sb, &j_handle);
	__page_holder_append_batch(&j_handle, mapping, index, end - index);
	shadow_destroy_journal_handle(inode->i_sb, &j_handle);

	if ((offset + len) > old_isize && extend)
		i_size_write(inode, offset + len);

finish:
	pr_info("%s: %s mode=%d, index=0x%lx, end=0x%lx\n",
		__func__, file->f_path.dentry->d_name.name, mode, index, end);
	return ret;
}

const struct address_space_operations shadow_aops = {
	.readahead = shadow_readahead,
	.read_folio = shadow_read_folio,
	.dirty_folio = shadow_dirty_folio,
	.release_folio = shadow_release_folio,
	.invalidate_folio = shadow_invalidate_folio,
	.direct_IO = noop_direct_IO,
};

const struct file_operations shadow_file_ops = {
	.owner		= THIS_MODULE,
	.read_iter	= shadow_read_iter,
	.write_iter	= shadow_file_write_iter,
	/*.mmap		= shadow_file_mmap,*/
	/*.mmap_supported_flags = MAP_SYNC,*/
	.open		= shadow_open,
	.release	= shadow_release,
	.fsync		= shadow_fsync,
	.fadvise	= shadow_fadvise,
	.fallocate	= shadow_fallocate,
};

