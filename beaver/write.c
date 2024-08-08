#include "log.h"
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
#include <linux/timekeeping.h>
#include <uapi/linux/fadvise.h>

extern long __shadow_cp(void *dst, const void __user *src,
				unsigned size, int zerorest);

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

int shadow_fsync(struct file *file, loff_t start,
			loff_t end, int datasync)
{
	return 0;
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
		size_t offset = iocb->ki_pos & ~PAGE_MASK;
		size_t length = min3(iov_iter_count(to),
				(size_t)(isize - iocb->ki_pos),
				PAGE_SIZE - offset);

		if (xas_retry(&xas, entry))
			continue;
		if (entry) {
			struct shadow_page_holder *holder = entry;
			u64 read_ptr_val;

			read_ptr_val = (u64)rcu_dereference(holder->read_ptr);
			kaddr = (char *)(read_ptr_val & PAGE_MASK);
			pr_debug("  kaddr=0x%px\n", kaddr);
			if (read_ptr_val & 1ULL) {
				SHADOW_STATS_ADD(dram_read, 1);
			} else {
				SHADOW_STATS_ADD(pmem_read, 1);
				if (holder->state == INIT)
					SHADOW_STATS_ADD(unsubmitted_read, 1);
			}
			/*if (virt_to_page(kaddr) == holder->pmem_pages[0] ||
			    virt_to_page(kaddr) == holder->pmem_pages[1]) {
				SHADOW_STATS_ADD(pmem_read, 1);
			} else {
				SHADOW_STATS_ADD(dram_read, 1);
			}*/
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

void split_buffer(size_t pos, size_t len, size_t boundary[3][2])
{
	int i;
	
	for(i = 0; i < 3 && len; i++) {
		size_t off = pos & ~PAGE_MASK;

		boundary[i][0] = pos;
		if (!off) { // start at an aligned pos
			// because this segment starts at an aligned pos,
			// it can have two cases
			boundary[i][1] = len < PAGE_SIZE ?
						len : // tail
						len & PAGE_MASK; // multiple aligend blocks
		} else { // start at an unaligned pos
			boundary[i][1] = off + len <= PAGE_SIZE ?
						len : (PAGE_SIZE - off);
		}
		len -= boundary[i][1];
		pos += boundary[i][1];
	}
}

#define HOLDER_BULK_SIZE 64

// install p_pages into mapping
void install_p_pages(struct address_space *mapping, unsigned int index,
		     struct page *p_pages, size_t num)
{
	void *batch[HOLDER_BULK_SIZE];
	size_t batch_size;
	struct page *p = p_pages;
	unsigned int i;
	struct shadow_page_holder *holder;

	do {
		batch_size = num > HOLDER_BULK_SIZE ? HOLDER_BULK_SIZE : num;
		holder_alloc_bulk(batch_size, batch);

		for (i = 0; i < batch_size; ++i) {
			holder = batch[i];

			holder->cur = -1;
			holder->pmem_pages[0] = p;
			holder->pmem_pages[1] = NULL;
			holder->dram_page = NULL;
			WRITE_ONCE(holder->read_ptr, NULL);//FIXME, should be
							   //zero page address
			if (xa_store(&mapping->i_pages, index, holder, GFP_KERNEL)) {
				pr_debug("%s: here!!!", __func__);
				BUG();
			}
			index++;
			p++;
		}

		num -= batch_size;
	} while (num);
}

static inline void* holder_next_addr(struct shadow_page_holder *holder)
{
	unsigned int next_cur = (holder->cur + 1) % 2;
	struct page *pmem_page = holder->pmem_pages[next_cur];

	return pmem_page ? page_address(pmem_page) : NULL;
}

enum SegState {
	NoPage,
	Exist,
};

struct seg {
	u8 state;
	unsigned int start;
	unsigned int len;
	void *ptr;
};

#define SEG_VEC_SIZE 16

struct segs_info {
	struct seg segs[SEG_VEC_SIZE];
};

static int __collect_segs(struct xarray *xa, unsigned int *index,
				unsigned int max, struct segs_info *info)
{
	int seg_pos = -1, expect_idx = *index;
	struct shadow_page_holder *holder;
	struct seg *segs = info->segs;
	XA_STATE(xas, xa, *index);

	rcu_read_lock();
	xas_for_each(&xas, holder, max) {
		void *next_addr = holder_next_addr(holder);

		if (!next_addr)
			continue;

		if (seg_pos < 0) {//segs empty, we are the first holder!
			if (xas.xa_index != expect_idx) {//a gap is befor us==
				seg_pos += 1;
				segs[seg_pos].state = NoPage;
				segs[seg_pos].start = expect_idx;
				segs[seg_pos].len = xas.xa_index - expect_idx;
			}
			seg_pos += 1;
			segs[seg_pos].state = Exist;
			segs[seg_pos].start = xas.xa_index;
			segs[seg_pos].len = 1;
			segs[seg_pos].ptr = next_addr;
			expect_idx = xas.xa_index + 1;

			continue;
		}

		if (expect_idx != xas.xa_index) {//unadjacent!
			if (seg_pos == SEG_VEC_SIZE - 1)
				break;

			seg_pos += 1;
			segs[seg_pos].start = expect_idx;
			segs[seg_pos].len = xas.xa_index - expect_idx;
			segs[seg_pos].state = NoPage;
			expect_idx = xas.xa_index;
		}

		if (segs[seg_pos].ptr + (segs[seg_pos].len << PAGE_SHIFT) != next_addr){
			if (seg_pos == SEG_VEC_SIZE - 1)
				break;

			seg_pos += 1;
			segs[seg_pos].start = xas.xa_index;
			segs[seg_pos].len = 1;
			segs[seg_pos].state = Exist;
		} else {
			segs[seg_pos].len += 1;
		}
		expect_idx = xas.xa_index + 1;
	}
	rcu_read_unlock();

	if (expect_idx <= max && seg_pos != SEG_VEC_SIZE - 1) {
		seg_pos += 1;
		segs[seg_pos].start = expect_idx;
		segs[seg_pos].len = max - expect_idx + 1;
		segs[seg_pos].state = NoPage;
		expect_idx = max + 1;
	}

	*index = expect_idx;

	return seg_pos;
}

static void holder_attach_pmem_page(struct shadow_page_holder *holder,
					struct page *pmem_page)
{
	unsigned int next_cur = (holder->cur + 1) % 2;

	BUG_ON(holder->pmem_pages[next_cur]);
	holder->pmem_pages[next_cur] = pmem_page;
}

static void __install_segs(struct xarray *xa, struct segs_info *info, unsigned int num)
{
	struct seg *segs = info->segs;
	unsigned int i, j;

	// insert segs
	for (i = 0; i <= num; ++i) {
		unsigned int index;
		struct page *p_pages;
		struct shadow_page_holder *holder;

		if (segs[i].state == Exist)
			continue;

		p_pages = virt_to_page(segs[i].ptr);
		index = segs[i].start;

		for (j = 0; j < segs[i].len; ++j) {
			holder = xa_load(xa, index + j);
			if (holder)
				holder_attach_pmem_page(holder, p_pages + j);
			else {
				holder = holder_alloc();
				holder->cur = -1;
				holder->pmem_pages[0] = p_pages + j;
				holder->pmem_pages[1] = NULL;
				holder->dram_page = NULL;
				xa_store(xa, index + j, holder, GFP_KERNEL);
			}
		}
	}
}

static inline void holder_flip_locked(struct shadow_page_holder *holder)
{
	unsigned int next_cur = (holder->cur + 1) % 2;
	struct page *pmem_page = holder->pmem_pages[next_cur];
	void *new_read_ptr;

	BUG_ON(!pmem_page);
	holder->cur = next_cur;
	new_read_ptr = page_address(pmem_page);
	rcu_assign_pointer(holder->read_ptr, new_read_ptr);
}

#define GET_HOLDER_BATCH_SIZE 16

static unsigned int _get_holder_batch(struct xarray *xa, pgoff_t index,
				pgoff_t max, struct shadow_page_holder **batch)
{
	XA_STATE(xas, xa, index);
	struct shadow_page_holder *holder;
	unsigned int i = 0;

	rcu_read_lock();
	xas_for_each(&xas, holder, max) {
		batch[i++] = holder;
		if (i == GET_HOLDER_BATCH_SIZE) break;
	}
	rcu_read_unlock();

	return i;
}

static void flip_holders(struct shadow_sb_info *sbi, struct address_space *mapping,
			 unsigned int index, unsigned int max, bool is_direct)
{
	struct shadow_page_holder *holder;
	struct list_head holder_list;
	unsigned int i, num, submitted = 0;
	struct xarray *xa = &mapping->i_pages;
	struct shadow_inode *s_inode = SHADOW_I(mapping->host);
	struct shadow_page_holder *holders[GET_HOLDER_BATCH_SIZE];

	pr_debug("%s: flip [0x%x, 0x%x]\n", __func__, index, max);

	if (!is_direct)
		INIT_LIST_HEAD(&holder_list);
	/*for (i = 0; i < SYNCUP_LIST_NUM && !is_direct; ++i)
		INIT_LIST_HEAD(&holder_lists[i]);*/

	do {
		num = _get_holder_batch(xa, index, max, holders);

		for (i = 0; i < num; ++i) {
			holder = holders[i];

			spin_lock(&holder->lock);
			holder_flip_locked(holder);
			if (!is_direct && holder->state == INIT) {
				holder->state = SYNCING;
				list_add(&holder->syncup, &holder_list);
				submitted += 1;
			}
			spin_unlock(&holder->lock);
		}

		index += num;
	} while (index <= max);

	if (!is_direct) {
		struct syncup_list *s_list;

		i = s_inode->write_count % SYNCUP_LIST_NUM;
		s_inode->write_count += 1;
		s_list = &sbi->syncup_args[i].s_list;

		spin_lock(&s_list->lock);
		list_splice_tail_init(&holder_list, &s_list->head);
		if (s_list->sleeping) {
			s_list->sleeping = 0;
			wake_up_process(s_list->task);
		}
		spin_unlock(&s_list->lock);
		SHADOW_STATS_ADD(fadvise_submitted, submitted);
	}

	/*for (i = 0; i < SYNCUP_LIST_NUM; ++i) {
		struct syncup_list *s_list = &sbi->syncup_args[i].s_list;

		if (list_empty(&holder_lists[i]))
			continue;

		spin_lock(&s_list->lock);
		list_splice_tail_init(&holder_lists[i], &s_list->head);
		spin_unlock(&s_list->lock);
	}*/
}

#define AVX_THRESHOLD_BYTES 16384UL

static ssize_t __shadow_file_write(struct file *file, size_t *boundary, char __user *buf,
				   struct journal_handle *j_handle, loff_t *ki_pos, bool is_direct)
{
	struct inode *inode = file_inode(file);
	struct shadow_sb_info *sbi = inode->i_sb->s_fs_info;
	struct address_space *mapping = file->f_mapping;
	struct xarray *xa = &mapping->i_pages;
	size_t pos = boundary[0], len = boundary[1];
	unsigned int index = pos >> PAGE_SHIFT;
	size_t offset = pos & ~PAGE_MASK;
	size_t i_size = i_size_read(inode);
	size_t written = 0;
	void *p_kaddr;
	u64 s_cpy_time, e_cpy_time, s_flip_time, e_flip_time;

	pr_debug("file_write: pos=0x%lx,len=0x%lx,buf=0x%px\n", pos, len, buf);

	// ideal case, multiple aligned blocks
	if(!(len & ~PAGE_MASK)) {
		struct page *p_pages;
		unsigned int max = index + (len >> PAGE_SHIFT) - 1;
		struct segs_info info;
		unsigned int i, idx = index;
		/*bool use_avx = len >= AVX_THRESHOLD_BYTES &&
				IS_ALIGNED((unsigned long)buf, 64);*/
		bool use_avx = false;

		s_cpy_time = ktime_get_boottime_ns();
		do {//collect, copy and install all segs
			struct seg *seg;
			size_t bytes;
			int num;

			pr_debug("idx=0x%x\n", idx);
			num = __collect_segs(xa, &idx, max, &info);

			for (i = 0; i <= num; ++i) {//write, alloc if necessary
				seg = &info.segs[i];
				bytes = seg->len << PAGE_SHIFT;

				pr_debug("segs[%d]: {.state=%d, .start=0x%x, .len=0x%x, .ptr=0x%px}",
					i, seg->state, seg->start, seg->len, seg->ptr);

				if (seg->state == Exist) {
					p_kaddr = seg->ptr;
				} else {
					p_pages = pmem_page_alloc(sbi->mgr,
								seg->len);
					p_kaddr = page_address(p_pages);
					seg->ptr = p_kaddr;
					log_blocks_alloc(j_handle, inode->i_ino,
							get_pmem_page_num(sbi->mgr, p_pages),
							seg->start, seg->len);
				}
				atomic64_add(seg->len, &sbi->pending_wr);
				if (use_avx)
					avx_copy(p_kaddr, buf, bytes);
				else
					__copy_user_nocache(p_kaddr, buf, bytes, 0);
				atomic64_add(seg->len, &sbi->finished_wr);
				buf += bytes;
			}

			__install_segs(xa, &info, num);
		} while (idx <= max);
		e_cpy_time = ktime_get_boottime_ns();

		log_aligned_update(j_handle, inode->i_ino, index, max);

		//flip all holders
		s_flip_time = ktime_get_boottime_ns();
		flip_holders(sbi, mapping, index, max, is_direct);
		e_flip_time = ktime_get_boottime_ns();
		SHADOW_STATS_ADD(wtime_copy, e_cpy_time - s_cpy_time);
		SHADOW_STATS_ADD(wtime_flip, e_flip_time - s_flip_time);
		written += len;
	} else {//unaligned
		struct shadow_page_holder *holder;

		holder = xa_load(&mapping->i_pages, index);
		if (pos >= i_size) { // unaligned append
			struct page *p_page;
			void *p_kaddr;
			bool new_holder = false;

			// 0. prepare new holder with pmem page
			if (!holder) {
				holder = holder_alloc();
				p_page = pmem_page_alloc_one(sbi->mgr);
				holder->pmem_pages[0] = p_page;
				holder->dram_page = NULL;
				holder->cur = 0;
				WRITE_ONCE(holder->read_ptr,
						page_address(p_page));
				log_blocks_alloc(j_handle, inode->i_ino,
						get_pmem_page_num(sbi->mgr, p_page),
						index, 1);
				new_holder = true;
			} else if (holder->cur < 0) {
				holder->cur = 0;
				p_page = holder->pmem_pages[holder->cur];
				//WRITE_ONCE(holder->read_ptr, page_address(p_page));
				rcu_assign_pointer(holder->read_ptr,
							page_address(p_page));
			} else
				p_page = holder->pmem_pages[holder->cur];
			p_kaddr = page_address(p_page);
			// 2. copy into pmem_addr
			//s_cpy_time = ktime_get_boottime_ns();
			__shadow_cp(p_kaddr + offset, buf, len, 0);
			//e_cpy_time = ktime_get_boottime_ns();
			//SHADOW_STATS_ADD(wtime_copy, e_cpy_time - s_cpy_time);

			written += len;
			if (new_holder)
				xa_store(&mapping->i_pages, index, holder, GFP_KERNEL);

			log_unaligned_append(j_handle, inode->i_ino, pos, len);
		} else { // unaligned overwrite
			bool new_holder = false;
			void *d_kaddr, *p_kaddr;
			struct page *pp_page;

			if (!holder) {
				holder = holder_alloc();
				holder->cur = -1;
				holder->pmem_pages[0] = NULL;
				holder->pmem_pages[1] = NULL;
				holder->dram_page = alloc_pages(GFP_KERNEL, 0);
				WRITE_ONCE(holder->read_ptr,
					page_address(holder->dram_page));
				pp_page = pmem_page_alloc_one(sbi->mgr);
				pp_page->index = 0;
				pp_page->mapping = NULL;
				holder->pmem_pages[2] = pp_page;

				log_pplog_alloc(j_handle, inode->i_ino,
						get_pmem_page_num(sbi->mgr, holder->pmem_pages[2]),
						index);
				new_holder = true;
			} else if (!holder->pmem_pages[2] ||
					holder->pmem_pages[2]->index + len > PAGE_SIZE){

				pp_page = pmem_page_alloc_one(sbi->mgr);
				log_pplog_alloc(j_handle, inode->i_ino,
						get_pmem_page_num(sbi->mgr, holder->pmem_pages[2]),
						index);

				spin_lock(&holder->lock);
				pp_page->index = 0;
				pp_page->mapping = (struct address_space*)holder->pmem_pages[2];
				holder->pmem_pages[2] = pp_page;
				if (!holder->dram_page) {
					holder->dram_page = alloc_pages(GFP_KERNEL, 0);
					if (holder->cur > -1)
						copy_page(page_address(holder->dram_page),
							  page_address(holder->pmem_pages[holder->cur]));
					else
						memset64(page_address(holder->dram_page),
							0, PAGE_SIZE / sizeof(u64));
				}
				rcu_assign_pointer(holder->read_ptr, page_address(holder->dram_page));
				spin_unlock(&holder->lock);
			} else
				pp_page = holder->pmem_pages[2];

			d_kaddr = page_address(holder->dram_page);
			p_kaddr = page_address(pp_page) + pp_page->index;

			__shadow_cp(d_kaddr + offset, buf, len, 0);
			__shadow_cp(p_kaddr, buf, len, 0);

			log_unaligned_overwrite(j_handle, inode->i_ino, pos, len);

			written += len;
			if (new_holder)
				xa_store(&mapping->i_pages, index, holder, GFP_KERNEL);
		}
	}

	pos += written;
	*ki_pos = pos;
	if (i_size < pos)
		i_size_write(inode, pos);

	return written;
}

ssize_t shadow_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = iocb->ki_filp->f_inode;
	char __user *buf;
	unsigned long len;
	size_t boundary[3][2] = {{0, 0}, {0, 0}, {0, 0}};
	struct journal_handle j_handle;
	unsigned int i;
	size_t written, ret = 0;
	bool is_direct = iocb->ki_flags & IOCB_DIRECT;
	/*bool is_direct = true;*/
	u64 s_time, e_time;
	/*u64 s_time, e_time, s_log_flush_time,
	    e_log_flush_time, s_log_init_time, e_log_init_time;*/

	s_time = ktime_get_boottime_ns();

	BUG_ON(!iter_is_ubuf(from));
	buf = from->ubuf + from->iov_offset;
	len = iov_iter_count(from);
	split_buffer(iocb->ki_pos, len, boundary);

	pr_debug("write_iter: inode=0x%px, pos=0x%llx, length=0x%lx, buf=0x%px\n",
			inode, iocb->ki_pos, len, buf);

	//s_log_init_time = ktime_get_boottime_ns();
	shadow_init_journal_handle(inode->i_sb, &j_handle);
	inode_lock(inode);
	for (i = 0; i < 3; ++i) {
		if (!boundary[i][1])
			break;
		written = __shadow_file_write(iocb->ki_filp, boundary[i], buf,
						&j_handle, &iocb->ki_pos, is_direct);
		buf += boundary[i][1];
		ret += written;
	}
	//e_log_init_time = ktime_get_boottime_ns();
	//SHADOW_STATS_ADD(wtime_log_flush, e_log_init_time - s_log_init_time);
	inode_unlock(inode);
	//s_log_flush_time = ktime_get_boottime_ns();
	shadow_destroy_journal_handle(inode->i_sb, &j_handle);
	//e_log_flush_time = ktime_get_boottime_ns();
	e_time = ktime_get_boottime_ns();

	SHADOW_STATS_ADD(wtime_total, e_time - s_time);
	//SHADOW_STATS_ADD(wtime_log_flush, e_log_flush_time - s_log_flush_time);

	return ret;
}

long shadow_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file_inode(file);
	struct shadow_sb_info *sbi = inode->i_sb->s_fs_info;
	loff_t old_isize = inode->i_size;
	unsigned long index = roundup(offset, PAGE_SIZE) >> PAGE_SHIFT;
	unsigned long end = roundup(offset + len, PAGE_SIZE) >> PAGE_SHIFT;
	struct journal_handle j_handle;
	bool extend;
	size_t num_blocks_need = end - index;
	struct page *p_pages;
	long ret = 0;

	if (offset < i_size_read(inode)) {
		ret = -EOPNOTSUPP;
		goto finish;
	}

	if (mode & ~FALLOC_FL_KEEP_SIZE) {
		ret = -EOPNOTSUPP;
		goto finish;
	}

	extend = !(mode & FALLOC_FL_KEEP_SIZE);

	shadow_init_journal_handle(inode->i_sb, &j_handle);
	p_pages = pmem_page_alloc(sbi->mgr, num_blocks_need);
	install_p_pages(mapping, index, p_pages, num_blocks_need);
	log_blocks_alloc(&j_handle, inode->i_ino,
			get_pmem_page_num(sbi->mgr, p_pages),
			index, num_blocks_need);
	shadow_destroy_journal_handle(inode->i_sb, &j_handle);

	if ((offset + len) > old_isize && extend)
		i_size_write(inode, offset + len);

finish:
	pr_debug("%s: %s mode=%d, index=0x%lx, end=0x%lx\n",
		__func__, file->f_path.dentry->d_name.name, mode, index, end);
	return ret;
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

static int shadow_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	struct inode *inode = file_inode(file);
	loff_t i_size = i_size_read(inode);
	unsigned int i, num, submitted = 0;
	struct shadow_page_holder *holder;
	struct list_head holder_list;
	struct syncup_list *s_list;
	unsigned int index, max;
	loff_t endbyte;
	struct xarray *xa = &file->f_mapping->i_pages;
	struct shadow_page_holder *holders[GET_HOLDER_BATCH_SIZE];
	struct shadow_inode *s_inode = SHADOW_I(inode);
	struct shadow_sb_info *sbi = inode->i_sb->s_fs_info;
	return 0;

	pr_debug("%s: %s, file_len=0x%llx, offset=0x%llx, len=0x%llx, advice=%d\n",
		__func__, file->f_path.dentry->d_name.name,
		i_size_read(inode), offset, len, advice);

	if (advice & ~(POSIX_FADV_WILLNEED | POSIX_FADV_RANDOM | POSIX_FADV_SEQUENTIAL))
		return 0;
	if (i_size < PAGE_SIZE)
		return 0;
	if ((offset & PAGE_MASK) == (i_size & PAGE_MASK))
		return 0;

	endbyte = (u64)offset + (u64)len;
	if ((endbyte & PAGE_MASK) == (i_size & PAGE_MASK))
		endbyte = endbyte & PAGE_MASK;
	if (!len || endbyte < len)
		endbyte = (i_size & PAGE_MASK) - 1;
	else
		endbyte--;
	index = offset >> PAGE_SHIFT;
	max = endbyte >> PAGE_SHIFT;

	pr_debug("%s: index=0x%x, max=0x%x\n", __func__, index, max);
	inode_lock(inode);
	INIT_LIST_HEAD(&holder_list);
	do {
		num = _get_holder_batch(xa, index, max, holders);
		if (!num)
			break;

		for (i = 0; i < num; ++i) {
			holder = holders[i];

			spin_lock(&holder->lock);
			if (holder->state == INIT) {
				holder->state = SYNCING;
				list_add(&holder->syncup, &holder_list);
				submitted += 1;
			}
			spin_unlock(&holder->lock);
		}

		index += num;
	} while (index <= max);
	SHADOW_STATS_ADD(fadvise_submitted, submitted);

	i = s_inode->write_count % SYNCUP_LIST_NUM;
	s_inode->write_count += 1;
	s_list = &sbi->syncup_args[i].s_list;

	spin_lock(&s_list->lock);
	list_splice_tail_init(&holder_list, &s_list->head);
	spin_unlock(&s_list->lock);

	inode_unlock(inode);

	return 0;
}

static loff_t beaver_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes = inode->i_sb->s_maxbytes;

	pr_err("%s: name=%s, offset=%lld, whence=%d\n", __func__,
			file->f_path.dentry->d_name.name, offset, whence);

	return generic_file_llseek_size(file, offset, whence,
					maxbytes, i_size_read(inode));
}

const struct inode_operations shadow_file_inode_ops = {
	.getattr	= simple_getattr,
	.setattr	= shadow_setattr,
};

const struct address_space_operations shadow_aops = {
	.release_folio = shadow_release_folio,
	.direct_IO = noop_direct_IO,
};

const struct file_operations shadow_file_ops = {
	.owner		= THIS_MODULE,
	.read_iter	= shadow_read_iter,
	.write_iter	= shadow_file_write_iter,
	.open		= shadow_open,
	.release	= shadow_release,
	.fsync		= shadow_fsync,
	.fadvise	= shadow_fadvise,
	.fallocate	= shadow_fallocate,
	.llseek		= beaver_llseek,
};

