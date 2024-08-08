#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include <linux/xarray.h>
#include <linux/pagemap.h>
#include "overlayfs.h"
// #include "log-index.h"
#include <linux/sort.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/smap.h>
#include "cp.h"


extern unsigned long avx_copy(void* dst1, void* dst2, void* src, size_t sz);
/*
"movnti %%r8, 0*8(%[waddr1]) \n"
			"movnti %%r9, 1*8(%[waddr1]) \n"
			"movnti %%r10, 2*8(%[waddr1]) \n"
			"movnti %%r11, 3*8(%[waddr1]) \n"
"movnti %%r8, 4*8(%[waddr1]) \n"
			"movnti %%r9, 5*8(%[waddr1]) \n"
			"movnti %%r10, 6*8(%[waddr1]) \n"
			"movnti %%r11, 7*8(%[waddr1]) \n"
*/

/*static inline unsigned long regular_copy(void* dst1, void* dst2, void* src, size_t sz)
{
	unsigned long iters = sz / 64;
    unsigned long i;
    void *dram_src, *dram_dst, *pmem_dst;
	for(i = 0; i < iters; i++) {
		dram_src = src + (i << 6);
		pmem_dst = dst1 + (i << 6);
		dram_dst = dst2 + (i << 6);
		asm volatile(
			"movq 0*8(%[addr]),	%%r8 \n"
			"movq 1*8(%[addr]),	%%r9 \n"
			"movq 2*8(%[addr]),	%%r10 \n"
			"movq 3*8(%[addr]),	%%r11 \n"
			"movnti %%r8, 0*8(%[waddr]) \n"
			"movnti %%r9, 1*8(%[waddr]) \n"
			"movnti %%r10, 2*8(%[waddr]) \n"
			"movnti %%r11, 3*8(%[waddr]) \n"
			"movnti %%r8, 0*8(%[waddr1]) \n"
			"movnti %%r9, 1*8(%[waddr1]) \n"
			"movnti %%r10, 2*8(%[waddr1]) \n"
			"movnti %%r11, 3*8(%[waddr1]) \n"
			"movq 4*8(%[addr]),	%%r8 \n"
			"movq 5*8(%[addr]),	%%r9 \n"
			"movq 6*8(%[addr]),	%%r10 \n"
			"movq 7*8(%[addr]),	%%r11 \n"
			"movnti %%r8, 4*8(%[waddr]) \n"
			"movnti %%r9, 5*8(%[waddr]) \n"
			"movnti %%r10, 6*8(%[waddr]) \n"
			"movnti %%r11, 7*8(%[waddr]) \n"
			"movnti %%r8, 4*8(%[waddr1]) \n"
			"movnti %%r9, 5*8(%[waddr1]) \n"
			"movnti %%r10, 6*8(%[waddr1]) \n"
			"movnti %%r11, 7*8(%[waddr1]) \n"
			: [addr] "+r" (dram_src), [waddr] "+r" (pmem_dst), [waddr1] "+r" (dram_dst)
			: 
			: "%r8", "%r9", "%r10", "%r11"
		);
	}
	return 0;
}*/


#define size_t unsigned long

#define NO_PAGE 0xFFFF000000000000

unsigned long previous_blocknr;

struct address_space dram_cache;

void *ovl_get_page_addr(struct xarray *pages, pgoff_t offset)
{
	// return NULL;
	// XA_STATE(xas, pages, offset);
	// return (void*)((unsigned long)xas_load(&xas) | NO_PAGE);
	
	return (void*)((unsigned long)xa_load(pages, offset) | NO_PAGE);
}

int ovl_store_page_addr(struct xarray *pages, pgoff_t offset, void* addr) {
	// pr_info("%s: offset: %lu, addr: %lx\n", __func__, offset, addr);
	__xa_store(pages, offset, addr, GFP_KERNEL);
	return 0;
}

// void ovl_get_page(struct address_space *mapping, pgoff_t offset)
// {
// 	// cmpxchg
// 	// pr_info("%s, %lu\n", __func__, offset);
// 	void *old_entry, *new_entry;
// 	unsigned long value;
// 	do {
// 		old_entry = xa_load(&mapping->i_pages, offset);
// 		// value = xa_to_value(old_entry);
// 		// new_entry = xa_mk_value(value + 1);
// 		new_entry = (unsigned long)old_entry - 0x0001000000000000; 
// 	} while(xa_cmpxchg(&mapping->i_pages, offset, old_entry, new_entry, GFP_KERNEL) != old_entry);
// }

// void ovl_put_page(struct address_space *mapping, pgoff_t offset)
// {
// 	// cmpxchg
// 	// pr_info("%s, %lu\n", __func__, offset);
// 	void *old_entry, *new_entry;
// 	unsigned long value;
// 	do {
// 		old_entry = xa_load(&mapping->i_pages, offset);
// 		// value = xa_to_value(old_entry);
// 		// new_entry = xa_mk_value(value - 1);
// 		new_entry = (unsigned long)old_entry + 0x0001000000000000;
// 	} while(xa_cmpxchg(&mapping->i_pages, offset, old_entry, new_entry, GFP_KERNEL) != old_entry);
// }

int ovl_page_readable(struct address_space *mapping, pgoff_t offset)
{
	// return true;
	// return false;
	// pr_info("query page %lu, %lx\n", offset, (unsigned long)xa_load(&mapping->i_pages, offset) & NO_PAGE);
	return ((unsigned long)xa_load(&mapping->i_pages, offset) & NO_PAGE) == NO_PAGE;
}



void wait_on_page(struct address_space *mapping, pgoff_t offset)
{
	// pr_info("offset: %lu, entry: %lx\n", offset, xa_load(&mapping->i_pages, offset));
	while(!ovl_page_readable(mapping, offset));
}

static int ovl_append_file_write_entry(struct super_block *sb, struct ovl_inode_info_header *sih, unsigned long ino,
										int write_type, loff_t pos, unsigned long blocknr, void *buf, size_t len)
{
	// struct journal_ptr_pair *pair;
	size_t size = sizeof(struct ovl_file_write_entry), ret;
	struct ovl_file_write_entry *entry;

	// pair = ovl_get_journal_pointers(sb, 0);
	
	entry = ovl_get_block(sb, sih->log_tail);

	entry->entry_type = 0;
	entry->write_type = write_type;
	entry->mtime = rrdtsc();
	entry->ino = ino;
	entry->pos = pos;
	entry->blocknr = blocknr;
	entry->len = len;

	// pr_info("append log tail: %lu, write_type: %d\n", sih->log_tail, write_type);

	sih->log_tail += (size + 63) & ~63;

	if(write_type == 4) {
		// pr_info("copy data to %lu\n", ovl_get_block(sb, sih->log_tail));
		// ret = copy_from_user(ovl_get_block(sb, sih->log_tail), buf, len);
		ret = __cp(ovl_get_block(sb, sih->log_tail), buf, len, 0);
		BUG_ON(ret);
		sih->log_tail += (len + 63) & ~63;
	}

	// __iget
	

	return 0;
}

static int ovl_persist_log(struct super_block *sb, struct ovl_inode_info_header *sih)
{
	struct journal_ptr_pair *pair;
	int cpuid = smp_processor_id();

	PERSISTENT_BARRIER();

	pair = ovl_get_journal_pointers(sb, cpuid);

	pair->journal_tail = sih->log_tail;

	// pr_info("%s: cpuid %d, %lx\n", __func__, cpuid, pair->journal_tail);

	// ovl_flush_buffer(pair, CACHELINE_SIZE, 1);
	PERSISTENT_BARRIER();
	return 0;
}

// static void wakeup_bg(struct ovl_sb_info *sbi)
// {
// 	atomic_set(&sbi->bg_signal, 1);
// 	if (!waitqueue_active(&sbi->bg_wait))
// 		return;


// 	// nova_dbg("Wakeup snapshot cleaner thread\n");
// 	wake_up_interruptible(&sbi->bg_wait);
// }

// static struct page *ovl_pagecache_get_page(struct address_space *mapping, pgoff_t offset)
// {
// 	struct page *page;


// 	page = find_get_entry(mapping, offset);
// 	if (xa_is_value(page))
// 		page = NULL;

// 	if (!page) {
// 		int err;
		
// 		page = __page_cache_alloc(GFP_HIGHUSER);
// 		if (!page)
// 			return NULL;

// 		add_to_page_cache_locked(page, &dram_cache, offset, GFP_HIGHUSER);
// 		/*
// 		 * add_to_page_cache_lru locks the page, and for mmap we expect
// 		 * an unlocked page.
// 		 */
// 		// if (page && (fgp_flags & FGP_FOR_MMAP))
// 		// 	unlock_page(page);
// 	}

// 	return page;
// }


/*
 * Generally, we can split a userspace buffer into 3 segments
 * A head segment, a body segment(multiple aligned blocks), a tail segment
 */

int split_buffer(size_t pos, size_t len, size_t boundary[3][2])
{
	int i;
	
	for(i = 0; i < 3 && len; i++) {
		// the start pos
		boundary[i][0] = pos;
		if (!(pos & ~PAGE_MASK)) { // start at an aligned pos
			// because this segment starts at an aligned pos,
			// it can have two cases
			boundary[i][1] = len < PAGE_SIZE ?
								len : // tail
								len & PAGE_MASK; // multiple aligend blocks
		} else { // start at an unaligned pos
			boundary[i][1] = (pos & ~PAGE_MASK) + len <= PAGE_SIZE ? len : (PAGE_SIZE - (pos & ~PAGE_MASK));
		}
		len -= boundary[i][1];
		pos += boundary[i][1];
	}
	return 0;
}

static ssize_t do_ovl_cow_file_write0(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode	*inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	struct ovl_inode_info_header *sih = OVL_IH(inode);
	struct ovl_sb_info *sbi = sb->s_fs_info;

	unsigned long blocksize_mask = sb->s_blocksize - 1;
	unsigned long num_blocks, num_blocks_need;

	loff_t pos = *ppos, curr_pos = *ppos;
	
	void *kmem, *kmem_dram;
	int allocated;
	unsigned long blocknr, i;
	int cpuid = smp_processor_id();
	
	loff_t s, offset;
	size_t l, ret;

	void *addr;

	size_t written = 0;
	char __user *curr_buf = buf;

	struct page *dram_page;

	size_t boundary[3][2] = {{0,0},{0,0},{0,0}};

	unsigned long write_back[3][3] = {{0,0,0},{0,0,0},{0,0,0}};

	// struct xa_state *xas;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	split_buffer(pos, len, boundary);

	// if(boundary[0][0] % 256 == 0)
	// 	pr_info("%s, {%lu, %lu}, {%lu, %lu}, {%lu, %lu}\n", filp->f_path.dentry->d_name.name, boundary[0][0], boundary[0][1], boundary[1][0], boundary[1][1], boundary[2][0], boundary[2][1]);

	// ASM_STAC
	
	sih->log_tail = sih->log_head = ovl_get_journal_pointers(sb, cpuid)->journal_tail;

	for(i = 0; i < 3; i++) {
		
		s = boundary[i][0]; // start pos
		l = boundary[i][1]; // len

		offset = ~PAGE_MASK & s;

		// BUG_ON(s && !l);
		// BUG_ON(offset && offset + l > PAGE_SIZE);
		// BUG_ON(!offset && (l > PAGE_SIZE) && (~PAGE_MASK & l));

		// pr_info("start: %lu, len: %lu\n", s, l);

		if(!s && !l)
			break;
		
		// ideal case, multiple aligned blocks
		if(!(s & ~PAGE_MASK) && (l & PAGE_MASK)) {
			unsigned long m = 0;
			// pr_info("aligned start: %lu, len: %lu\n", s, l);
			// BUG_ON(s >= 8589934592UL);
			num_blocks_need = l >> PAGE_SHIFT;
			allocated = ovl_new_data_blocks(sb, NULL, &blocknr, 0,
				 num_blocks_need, ALLOC_NO_INIT, ANY_CPU,
				 ALLOC_FROM_HEAD);

			BUG_ON(allocated != num_blocks_need);

			// if()

			kmem = ovl_get_block(inode->i_sb,
					ovl_get_block_off(sb, blocknr, 0));

			while (m < allocated) {
				bool new_dram_page = false;
				void *kmem_addr = kmem + (m << PAGE_SHIFT);

				kmem_dram = ovl_get_page_addr(&sih->dram_pages, (s >> PAGE_SHIFT) + m);
				if (!kmem_dram || kmem_dram == NO_PAGE) {
					struct page *dram_page = alloc_pages(GFP_KERNEL, 0);

					kmem_dram = page_address(dram_page);
					new_dram_page = true;
				}
				ret = __cp(kmem_addr, curr_buf, PAGE_SIZE, 0);
				if (kmem_dram)
					ret = __cp(kmem_dram, curr_buf, PAGE_SIZE, 0);
				BUG_ON(ret);

				if (new_dram_page)
					ovl_store_page_addr(&sih->dram_pages, (s >> PAGE_SHIFT) + m, kmem_dram);
				ovl_store_page_addr(&sih->pmem_pages, (s >> PAGE_SHIFT) + m, kmem_addr);
				curr_buf += PAGE_SIZE;
				m++;
			}
			
			if(!sbi->write_back_sync)
				xa_store_range(&sih->log_index, s, (s + l - 1), NULL, GFP_KERNEL);


			
			ovl_append_file_write_entry(sb, sih, inode->i_ino, 1, s, blocknr, NULL, l);

			//curr_buf += l;
			written += l;
			
		} else {
			// pr_info("unaligned, start: %lu, len: %lu\n", s, l);
			if (s >= i_size_read(inode)) { // append
				
				kmem = ovl_get_page_addr(&sih->pmem_pages, s >> PAGE_SHIFT);

				if(kmem != NO_PAGE) { // page exists, append right after the end of the file
					// pr_info("append 1, start: %lu, len: %lu\n", s, l);
					// ret = copy_from_user(kmem + offset, curr_buf, l);
					ret = __cp(kmem + offset, curr_buf, l, 0);
					BUG_ON(ret);
					
					if(sbi->enable_dram_page) {
						kmem_dram = ovl_get_page_addr(&sih->dram_pages, s >> PAGE_SHIFT);
						if(kmem_dram != NO_PAGE) {
							ret = copy_from_user(kmem_dram + offset, curr_buf, l);
							BUG_ON(ret);
						}
					}


					ovl_append_file_write_entry(sb, sih, inode->i_ino, 2, s, 0, NULL, l);

					curr_buf += l;
					written += l;
				} else { // append, "aligned start" or "hole"
					// pr_info("append 2, start: %lu, len: %lu\n", s, l);
					num_blocks_need = 1;
					allocated = ovl_new_data_blocks(sb, NULL, &blocknr, 0,
									num_blocks_need, ALLOC_NO_INIT, ANY_CPU,
									ALLOC_FROM_HEAD);

					BUG_ON(allocated != num_blocks_need);

					kmem = ovl_get_block(inode->i_sb,
						ovl_get_block_off(sb, blocknr, 0));

					ret = __cp(kmem + offset, curr_buf, l, 0);
					BUG_ON(ret);

					if(sbi->enable_dram_page) {
						kmem_dram = ovl_get_page_addr(&sih->dram_pages, s >> PAGE_SHIFT);
						if(kmem_dram != NO_PAGE) {
							ret = copy_from_user(kmem_dram + offset, curr_buf, l);
							BUG_ON(ret);
						//} else {
						} else {
							struct page *dram_page = alloc_pages(GFP_KERNEL, 0);

							kmem_dram = page_address(dram_page);
							BUG_ON(!kmem_dram);
							ret = copy_from_user(kmem_dram + offset, curr_buf, l);
							BUG_ON(ret);
							ovl_store_page_addr(&sih->dram_pages, s >> PAGE_SHIFT, kmem_dram);
						}
					}

					ovl_store_page_addr(&sih->pmem_pages, s >> PAGE_SHIFT, kmem);

					ovl_append_file_write_entry(sb, sih, inode->i_ino, 3, s, blocknr, NULL, l);

					curr_buf += l;
					written += l;
				}
			} else { // overwrite
				kmem = ovl_get_page_addr(&sih->pmem_pages, s >> PAGE_SHIFT);
				if(kmem != NO_PAGE) {
					addr = sih->log_tail;
					ovl_append_file_write_entry(sb, sih, inode->i_ino, 4, s, 0, curr_buf, l);

					if(sbi->enable_dram_page) {
						kmem_dram = ovl_get_page_addr(&sih->dram_pages, s >> PAGE_SHIFT);
						if(kmem_dram != NO_PAGE) {
							ret = copy_from_user(kmem_dram + offset, curr_buf, l);
							BUG_ON(ret);
						} else {
							struct page *dram_page = alloc_pages(GFP_KERNEL, 0);
							kmem_dram = page_address(dram_page);
							BUG_ON(!kmem_dram);
							copy_page(kmem_dram, kmem);
							ret = copy_from_user(kmem_dram + offset, curr_buf, l);
							BUG_ON(ret);
							ovl_store_page_addr(&sih->dram_pages, s >> PAGE_SHIFT, kmem_dram);
						}
					}

					if(sbi->write_back_sync) {
					
						write_back[i][0] = s;
						write_back[i][1] = l;
						write_back[i][2] = curr_buf;
					} else {
						xa_store(&sih->log_index, (s << PAGE_SHIFT) | l, addr, GFP_KERNEL);
					}

				} else { // overwriting a hole
					num_blocks_need = 1;
					allocated = ovl_new_data_blocks(sb, NULL, &blocknr, 0,
									num_blocks_need, ALLOC_INIT_ZERO, ANY_CPU,
									ALLOC_FROM_HEAD);

					BUG_ON(allocated != num_blocks_need);

					kmem = ovl_get_block(inode->i_sb,
						ovl_get_block_off(sb, blocknr, 0));


					BUG_ON((curr_buf - buf) + l > len);
					ret = __cp(kmem + offset, curr_buf, l, 0);
					BUG_ON(ret);

					ovl_store_page_addr(&sih->pmem_pages, s >> PAGE_SHIFT, kmem);
					

					if(sbi->enable_dram_page) {
						kmem_dram = ovl_get_page_addr(&sih->dram_pages, s >> PAGE_SHIFT);
						if(kmem_dram != NO_PAGE) {
							BUG();
						} else {
							struct page *dram_page = alloc_pages(GFP_KERNEL, 0);
							kmem_dram = page_address(dram_page);
							BUG_ON(!kmem_dram);
							ret = copy_from_user(kmem_dram + offset, curr_buf, l);
							BUG_ON(ret);
							ovl_store_page_addr(&sih->dram_pages, s >> PAGE_SHIFT, kmem_dram);
						}
					}

					addr = sih->log_tail;
					ovl_append_file_write_entry(sb, sih, inode->i_ino, 5, s, blocknr, NULL, l);
				}

				

				curr_buf += l;
				written += l;
			}
		}
		
	}

	BUG_ON(written != len);


	ovl_persist_log(sb, sih);
	pos += written;
	
	*ppos = pos;

	if(pos > i_size_read(inode)){
		i_size_write(inode, pos);
	}

	return written;

}

static ssize_t do_ovl_dax_file_write(struct file *filp, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	// struct address_space *mapping = filp->f_mapping;
	// struct inode *inode = mapping->host;

	return do_ovl_cow_file_write0(filp, buf, len, ppos);

	// if (test_opt(inode->i_sb, DATA_COW))
	// 	return do_ovl_cow_file_write(filp, buf, len, ppos);
	// else
	// 	return do_ovl_inplace_file_write(filp, buf, len, ppos);
}

static int compare(const void *lhs, const void *rhs) {
	struct ovl_file_write_entry *lentry = *(struct ovl_file_write_entry **)lhs;
	struct ovl_file_write_entry *rentry = *(struct ovl_file_write_entry **)rhs;

	// pr_info("%lu, %lu", lentry, rentry);

	// if(lentry->pos < rentry->pos)
	// 	return -1;
	// else if(lentry->pos > rentry->pos)
	// 	return 1;

	// return 0;
	
	if(lentry->mtime > rentry->mtime)
		return -1;
	else if(lentry->mtime < rentry->mtime)
		return 1;
	else {
		BUG();
		return 0;
	}
}

static ssize_t
do_dax_mapping_read(struct file *filp, char __user *buf,
	size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	struct ovl_inode_info *si = OVL_I(inode);
	struct ovl_inode_info_header *sih = &si->header;
	struct ovl_file_write_entry *e;
	// struct ovl_file_write_entry *entry, *e;
	// struct ovl_file_write_entry *entryc, entry_copy;
	// pgoff_t index, end_index;
	pgoff_t index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0, ret;
	int cpuid = smp_processor_id();
	// unsigned long blocknr, blocknr_start;

	struct ovl_sb_info *sbi = sb->s_fs_info;

	struct dlist_node* tmp_list = sbi->dlist[cpuid];

	unsigned long *tmp_addr = sbi->tmp_addr[cpuid];

	loff_t bio_pos;

	

	// struct ovl_file_write_entry 

	// pr_info("%s\n", __func__);

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	// pr_info("%s, %lu, %lu, %lu, %lu, a1\n", filp->f_path.dentry->d_name.name, pos, index, offset, len);

	if (!access_ok(buf, len)) {
		error = -EFAULT;
		goto out;
	}
	// pr_info("buf: %lu\n", buf);
	// pr_info("%s, a2\n", filp->f_path.dentry->d_name.name);


	isize = i_size_read(inode);
	if (!isize)
		goto out;

	// pr_info("%s, a2\n", filp->f_path.dentry->d_name.name);


	if (len > isize - pos)
		len = isize - pos;

	if (len <= 0)
		goto out;

	// wakeup_bg(OVL_SB(sb));


	do {
		// pr_info("read loop\n");
		unsigned long nr;
		// unsigned long nvmm;
		void *dax_mem = NULL;
		void *dax_pmem = NULL;
		// int zero = 0;
		int i, j, k;

		// char map[512];
		unsigned long curr_offset, idx;

		unsigned pstart, pend;


		struct dlist_node *dlist_head, *curr_node, *new_node, *next_node;



// memcpy:
		nr = 4096 - offset;
		if(nr > len - copied)
			nr = len - copied;

		// dax_mem = ovl_get_block(inode->i_sb,
		// 				ovl_get_block_off(sb, blocknr_start + (index * 8 + (cpuid % 8)), 0));

		// while(!ovl_page_readable(inode->i_mapping, index));
		// wait_on_page(inode->i_mapping, index);


		// if(ovl_get_page_addr())

		dax_mem = ovl_get_page_addr(&sih->dram_pages, index);
		if(dax_mem == NO_PAGE) {
			dax_mem = ovl_get_page_addr(&sih->pmem_pages, index);
		}
		
		// dax_mem = ovl_get_page_addr(&sih->pmem_pages, index);
		if(dax_mem == NO_PAGE) { // hole
			dax_mem = sbi->zeroed_page;
		}
		
		// e = xa_load(&sih->partial_writes, index);
		e = NULL;
		if(e) {
			
			// pr_info("calling underlying read\n");
			
			// ret = vfs_read(sbi->underlying_file, (void __user *)(buf + copied), nr, offset);
			// bio_pos = 0;
			// ret = kernel_read(sbi->underlying_file, sbi->bio_buffer, nr, &bio_pos);
			// __copy_to_user(buf + copied, sbi->bio_buffer, nr);
			// // BUG_ON(ret != nr);
			// copied += nr;

		} else if(!sbi->write_back_sync) {
			i = 0; 

			xa_for_each_start(&sih->log_index, idx, e, index << (PAGE_SHIFT << 1)) {

			

				if(!e)
					BUG();
				
				if(idx >> (PAGE_SHIFT << 1) > index)
					break;

				e = (struct ovl_file_write_entry*) ovl_get_block(inode->i_sb, e);

				// pr_info("%lu, %lu, %lu, %lu", e->pos, e->len, offset, ((e->pos + e->len) & ~PAGE_MASK));

				if((e->pos + e->len) > ((index << PAGE_SHIFT) + offset))
					tmp_addr[i++] = (unsigned long)e;
					// continue;

				// if(offset + nr <= e->pos & ~PAGE_MASK)
				// 	continue;

				

				// if(e->len) {
					
				// 	__copy_to_user(buf + copied + (e->pos & ~PAGE_MASK), )
				// }
				
			}

			sort(tmp_addr, i, sizeof(unsigned long), &compare, NULL);



			dlist_head = NULL;
			curr_node = NULL;
			next_node = NULL;
			k = 0;
			curr_offset = offset;

			for(j = 0; j < i; j++) {
				e = (struct ovl_file_write_entry *)tmp_addr[j];
				pstart = (unsigned int)(e->pos & ~PAGE_MASK);
				pend = pstart + (unsigned int)e->len;

				
				if(dlist_head) {
					curr_node = dlist_head;
					if(pstart < curr_node->start) { // insert before the head
						new_node = &tmp_list[k++];
						new_node->start = offset > pstart ? offset : pstart;
						// new_node->end = pend <= curr_node->start ? pend : curr_node->start;
						new_node->end = min(pend, curr_node->start);
						new_node->ptr = e;
						new_node->next = curr_node;
						new_node->prev = NULL;
						dlist_head = new_node;
						
					} else if(pstart == curr_node->start) {
						BUG();
					}

					

					while(curr_node && pend > curr_node->end) {
						next_node = curr_node->next;
						if(next_node && curr_node->end == next_node->start) {
							curr_node = next_node;
							continue;
						}
						
						new_node = &tmp_list[k++];
						new_node->start = pstart > curr_node->end ? pstart : curr_node->end;
						// new_node->end = next_node ? (pend < next_node->start ? pend : next_node->start) : pend;
						new_node->end = next_node ? min(pend, next_node->start) : pend;
						
						new_node->ptr = e;
						new_node->next = next_node;
						new_node->prev = curr_node;
						curr_node->next = new_node;
						if(next_node)
							next_node->prev = new_node;
						
						curr_node = next_node;
						if (new_node->end > offset + nr) {
							new_node->end = offset + nr;
							break;
						}
					}
				} else {
					new_node = &tmp_list[k++];
					new_node->start = max(pstart, offset);
					new_node->end = min(pend, offset + nr);
					new_node->ptr = e;
					new_node->next = NULL;
					new_node->prev = NULL;
					dlist_head = new_node;
				}
			}


			// do the real copy
			curr_node = dlist_head;
			curr_offset = offset;
			while(curr_offset < offset + nr) {
				
				if(curr_node && curr_offset < curr_node->start) {
					// copy from page
					ret = __copy_to_user(buf + copied, dax_mem + curr_offset, curr_node->start - curr_offset);
					BUG_ON(ret);
					
					copied += curr_node->start - curr_offset;
					curr_offset = curr_node->start;
					// continue;
				} else if(curr_node && curr_offset == curr_node->start) {
					// copy from log entry
					// pr_info("%lu, %lu, %lu, %lu, %lu, %lu, %lu", curr_node, curr_node->ptr, curr_node->start, buf, copied, ((struct ovl_file_write_entry*)(curr_node->ptr))->pos, (curr_node->ptr + 64) + (curr_node->start - ((struct ovl_file_write_entry*)(curr_node->ptr))->pos & ~PAGE_MASK));
					ret = __copy_to_user(buf + copied, (curr_node->ptr + 64) + (curr_node->start - ((struct ovl_file_write_entry*)(curr_node->ptr))->pos & ~PAGE_MASK), curr_node->end - curr_node->start);
					BUG_ON(ret);
					
					copied += curr_node->end - curr_node->start;
					curr_offset = curr_node->end;

					curr_node = curr_node->next;
					
					// continue;
				} else { 
					// copy the remaining
					
					ret = __copy_to_user(buf + copied, dax_mem + curr_offset, offset + nr - curr_offset);
					// pr_info("%lu, %lu, %lu, %lu, %lu, %lu", buf, copied, dax_mem, curr_offset, ret, offset + nr);
					// BUG_ON(ret);
					if(ret) {
						pr_info("%lu, %lu, %lu, %lu, %lu, %lu", buf, copied, dax_mem, curr_offset, ret, offset + nr);
						BUG();
					}

					copied += offset + nr - curr_offset;
					curr_offset = offset + nr;
					
					// continue;
				}
			}
		
		} else {
			
			BUG_ON(copied + nr > len);
			// pr_info("%lx, %lu, %lx, %lu, %lu\n", buf, copied, dax_mem, offset, nr);

			ret = __copy_to_user(buf + copied, dax_mem + offset, nr);
			// dax_pmem = ovl_get_page_addr(&sih->pmem_pages, index);
			// __copy_to_user(buf + copied, dax_pmem, 2048);
			// __copy_to_user(buf + copied + 2048, dax_mem, 2048);
			
			BUG_ON(ret);

			copied += nr;

			// ============================

			// pr_info("calling underlying read\n");
			
			// ret = vfs_read(sbi->underlying_file, (void __user *)(buf + copied), nr, offset);
			// BUG_ON(ret != nr);

			// copied += nr;
			
		}
		
		offset += nr;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;	
		
	} while(copied < len);

	BUG_ON(copied > len);

	// pr_info("copied: %lu\n", copied);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	// pr_info("accessed");
	
	return copied;
}

// [1,4095][4096,8191]
//

static ssize_t ovl_wrap_rw_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *filp = iocb->ki_filp;
	struct inode *inode = filp->f_mapping->host;
	ssize_t ret = -EIO;
	ssize_t written = 0;
	unsigned long seg;
	unsigned long nr_segs = iter->nr_segs;
	const struct iovec *iv = iter->iov;

	unsigned long flags;

	// pr_info("rw begin\n");
	// pr_info("name: %s\n", filp->f_path.dentry->d_name.name);

	// ovl_dbgv("%s %s: %lu segs\n", __func__,
	// 		iov_iter_rw(iter) == READ ? "read" : "write",
	// 		nr_segs);

	if (iov_iter_rw(iter) == WRITE)  {
		sb_start_write(inode->i_sb);
		// local_irq_save(flags);
		// preempt_disable();
		inode_lock(inode);
	} else {
		// pr_info("begin read");
		// inode_lock_shared(inode);
	}

	if (iter_is_ubuf(iter)) {
		if (iov_iter_rw(iter) == READ) {
			ret = do_dax_mapping_read(filp, iter->ubuf + iter->iov_offset,
						iter->count, &iocb->ki_pos);
		} else if (iov_iter_rw(iter) == WRITE) {
			ret = do_ovl_dax_file_write(filp, iter->ubuf + iter->iov_offset,
						iter->count, &iocb->ki_pos);
		} else {
			BUG();
		}
		if (ret < 0)
			goto err;

		iter->iov_offset += ret;
		iter->count -= ret;
	} else {
		iv = iter->iov;
		for (seg = 0; seg < nr_segs; seg++) {
			if (iov_iter_rw(iter) == READ) {
				// pr_info("read");
				// pr_info("name: %s\n", filp->f_path.dentry->d_name.name);
				ret = do_dax_mapping_read(filp, iv->iov_base,
							iv->iov_len, &iocb->ki_pos);
			} else if (iov_iter_rw(iter) == WRITE) {
				ret = do_ovl_dax_file_write(filp, iv->iov_base,
							iv->iov_len, &iocb->ki_pos);
			} else {
				BUG();
			}
			if (ret < 0)
				goto err;

			if (iter->count > iv->iov_len)
				iter->count -= iv->iov_len;
			else
				iter->count = 0;

			written += ret;
			iter->nr_segs--;
			iv++;
		}
		ret = written;
	}
err:
	if (iov_iter_rw(iter) == WRITE)  {
		// preempt_enable();
		// local_irq_restore(flags);
		inode_unlock(inode);
		sb_end_write(inode->i_sb);
	} else {
		// inode_unlock_shared(inode);
	}

	// pr_info("rw end\n");

	// ovl_END_TIMING(wrap_iter_t, wrap_iter_time);
	return ret;
}

// static int ovl_fsync(struct file *file, loff_t start, loff_t end, int datasync)
// {
// 	// struct fd real;
// 	// const struct cred *old_cred;
// 	// int ret;

// 	// ret = ovl_real_fdget_meta(file, &real, !datasync);
// 	// if (ret)
// 	// 	return ret;

// 	// /* Don't sync lower file for fear of receiving EROFS error */
// 	// if (file_inode(real.file) == ovl_inode_upper(file_inode(file))) {
// 	// 	old_cred = ovl_override_creds(file_inode(file)->i_sb);
// 	// 	ret = vfs_fsync_range(real.file, start, end, datasync);
// 	// 	revert_creds(old_cred);
// 	// }

// 	// fdput(real);

// 	return 0;
// }

static loff_t ovl_llseek(struct file *file, loff_t offset, int origin)
{
	// pr_info("%s", __func__);
	// struct inode *inode = file->f_path.dentry->d_inode;
	// int retval;

	// if (origin != SEEK_DATA && origin != SEEK_HOLE)
	// 	return generic_file_llseek(file, offset, origin);
	
	// inode_lock(inode);
	// // switch(origin) {

	// // }
	if(offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}

	// inode_unlock(inode);
	return offset;

}

int ovl_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	return 0;
}

int ovl_file_open(struct inode * inode, struct file * filp)
{
	// pr_info ("Caller name: %pS\n", __builtin_return_address(0));
	// pr_info("%s, %s, pos %lu\n", __func__, filp->f_path.dentry->d_name.name, filp->f_pos);
	return generic_file_open(inode, filp);
}

long ovl_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	return 0;
}

const struct file_operations ovl_file_operations = {
	.open		= ovl_file_open,
	// .release	= ovl_release,
	.llseek		= ovl_llseek,
	// .llseek = generic_file_llseek,
	.read_iter	= ovl_wrap_rw_iter,
	.write_iter	= ovl_wrap_rw_iter,
    // .write_iter = generic_file_write_iter,
	// .write = ovl_dax_file_write,
	// generic_file_write_iter
	.fsync		= noop_fsync,
	// .mmap		= ovl_mmap,
	.fallocate	= ovl_fallocate,
	//TODO BUG generic_fadvise has bug at invalidate_mapping_pages
	.fadvise	= ovl_fadvise,
	// .flush		= ovl_flush,
	// .splice_read    = generic_file_splice_read,
	// .splice_write   = ovl_splice_write,

	// .copy_file_range	= ovl_copy_file_range,
	// .remap_file_range	= ovl_remap_file_range,
};

// void ovl_tidy_log(struct ovl_sb_info *sbi)
// {
// 	// struct journal_ptr_pair *pair;
// 	struct ovl_file_write_entry *entry;
// 	int cpuid;
// 	struct inode *inode;
// 	struct super_block *sb = sbi->sb;
// 	void *kmem;

// 	// pr_info("ovl_tidy_log\n");

// 	atomic_set(&sbi->bg_signal, 0);
	
// 	// do {

// 	// 	entry = ovl_get_block(sbi->sb, pair->journal_head);
// 	// 	if(entry->write_type == 2) { // async copy on write
// 	// 		memcpy_to_pmem_nocache(NULL, (pair->journal_head + 64), entry->len);
// 	// 		pair->journal_head += 64 + ((entry->len + 63) & ~63) ;
// 	// 	} else {
// 	// 		pair->journal_head += 64;
// 	// 	}

// 	// 	PERSISTENT_BARRIER();

// 	// } while(pair->journal_head != pair->journal_tail);
// 	// pr_info("%llx, %llx\n", pair->journal_head, pair->journal_tail);
// 	// for(cpuid = 1; cpuid <=8; cpuid++) {
// 	// 	pair = ovl_get_journal_pointers(sbi->sb, cpuid);
// 	// 	// pr_info("%llx, %llx\n", pair->journal_head, pair->journal_tail);
// 	// 	while(pair->journal_head < pair->journal_tail) {
// 	// 		// pr_info("journal_head: %llx\n", pair->journal_head);
// 	// 		entry = ovl_get_block(sbi->sb, pair->journal_head);
// 	// 		// pr_info("entry type: %d\n", entry->write_type);
// 	// 		if(entry->write_type == 2) { // async copy on write
// 	// 			inode = ovl_iget(sb, entry->ino, );
// 	// 			kmem = ovl_get_page_addr(inode->i_mapping, entry->pos >> sb->s_blocksize_bits);
// 	// 			// pr_info("copy back to %llx\n", kmem);
// 	// 			memcpy_to_pmem_nocache(kmem + (entry->pos & (sb->s_blocksize - 1)), (pair->journal_head + 64), entry->len);
// 	// 			ovl_put_page(inode->i_mapping, entry->pos >> sb->s_blocksize_bits);
// 	// 			pair->journal_head += 64 + ((entry->len + 63) & ~63) ;
// 	// 		} else {
// 	// 			pair->journal_head += 64;
// 	// 		}
// 	// 	}
// 	// }
// }

