#include <linux/mm.h>
#include <linux/fs.h>
#include "shadow_entry.h"
#include "log.h"

#define _mm_clflush(addr)\
	asm volatile("clflush %0" : "+m" (*(volatile char *)(addr)))
#define _mm_clflushopt(addr)\
	asm volatile(".byte 0x66; clflush %0" : "+m" \
		     (*(volatile char *)(addr)))
#define _mm_clwb(addr)\
	asm volatile(".byte 0x66; xsaveopt %0" : "+m" \
		     (*(volatile char *)(addr)))
static inline void PERSISTENT_BARRIER(void)
{
	asm volatile ("sfence\n" : : );
}


struct kmem_cache *page_holder_cachep = NULL;

static void shadow_page_holder_init_once(void *foo)
{
	struct shadow_page_holder *holder = foo;

	spin_lock_init(&holder->lock);
	holder->cur = 0;
	holder->pmem_pages[0] = NULL;
	holder->pmem_pages[1] = NULL;
	holder->pmem_pages[2] = NULL;
	holder->dram_page = NULL;
	WRITE_ONCE(holder->read_ptr, NULL);
	INIT_LIST_HEAD(&holder->syncup);
	holder->state = INIT;
}

int ph_cache_init(void)
{
	page_holder_cachep = kmem_cache_create("shadow_page_holder_cachep",
						sizeof(struct shadow_page_holder),
						0,
						(SLAB_RECLAIM_ACCOUNT|
						 SLAB_MEM_SPREAD),
						shadow_page_holder_init_once);
	if (!page_holder_cachep)
		return -ENOMEM;

	return 0;
}

void ph_cache_exit(void)
{
	if (page_holder_cachep)
		kmem_cache_destroy(page_holder_cachep);
}

struct shadow_page_holder *holder_alloc(void)
{
	SHADOW_STATS_ADD(holder_allocated, 1);
	return kmem_cache_alloc(page_holder_cachep, GFP_KERNEL);
}

int holder_alloc_bulk(size_t size, void **p)
{
	SHADOW_STATS_ADD(holder_allocated, size);
	return kmem_cache_alloc_bulk(page_holder_cachep, GFP_KERNEL, size, p);
}

void holder_free(struct shadow_page_holder *holder)
{
	BUG_ON(holder->pmem_pages[0] || holder->pmem_pages[1]);
	shadow_page_holder_init_once(holder);
	kmem_cache_free(page_holder_cachep, holder);
	SHADOW_STATS_ADD(holder_freed, 1);
}

/*unsigned long shadow_raw_log_check(struct raw_shadow_log *raw,
				   unsigned long log_page_nr)
{
	unsigned long log_cap = log_page_nr * PAGE_SIZE
					/ sizeof(struct shadow_log_entry);

	if (raw->magic_num != SHADOW_LOG_MAGIC) {
		pr_warn("log space has not been initialized ever!\n");
		raw->counter = 0;
		raw->magic_num = SHADOW_LOG_MAGIC;
	}

	if (raw->counter > log_cap) {
		log_cap = raw->counter;
		roundup(log_cap, PAGE_SIZE / sizeof(struct shadow_log_entry));
	}
	raw->capacity = log_cap;
	shadow_barrier();

	pr_info("Shadow log: counter=%ld, capacity=%ld\n",
		 raw->counter, raw->capacity);

	log_page_nr = (log_cap * sizeof(struct shadow_log_entry)) >> PAGE_SHIFT;
	return log_page_nr;
}*/

int shadow_log_restore(struct shadow_log *log_mgr, struct raw_shadow_log *raw_mgr)
{
	log_mgr->capacity = raw_mgr->capacity;
	log_mgr->counter = raw_mgr->counter;
	log_mgr->raw_mgr = raw_mgr;
	log_mgr->tail = raw_mgr->entry_space + raw_mgr->counter;
	spin_lock_init(&log_mgr->lock);

	return 0;
}

static inline int write_log_entry(struct shadow_log *log_mgr,
				struct shadow_log_entry *entry)
{
	struct raw_shadow_log *raw_log = log_mgr->raw_mgr;

	spin_lock(&log_mgr->lock);
	memcpy_flushcache(log_mgr->tail, entry, sizeof(struct shadow_log_entry));
	log_mgr->counter += 1;
	if (log_mgr->counter > log_mgr->capacity) {
		spin_unlock(&log_mgr->lock);
		BUG();
	}
	raw_log->counter = log_mgr->counter;
	log_mgr->tail++;
	spin_unlock(&log_mgr->lock);

	return 0;
}

/*int shadow_log_pmem_alloc(struct journal_handle *handle, unsigned int ino,
		unsigned int index, unsigned int p_page0, unsigned int p_page1)
{
	struct shadow_log_entry *entry = handle->tail;
	
	entry->ino = ino;
	entry->page_index = index;
	entry->p_page_num0 = p_page0;
	entry->p_page_num1 = p_page1;

	handle->tail ++;

	return 0;
}*/

/*int shadow_log_range_flush(struct journal_handle *handle, unsigned int ino,
				loff_t start, loff_t end)
{
	struct shadow_log_entry *entry = handle->tail;

	entry->ino = ino;
	entry->range_start = (unsigned int)(start >> PAGE_SHIFT);
	entry->range_end = (unsigned int)(end >> PAGE_SHIFT);
	entry->page_offsets = (unsigned int)(start & ~PAGE_MASK) << 16
				| (unsigned int)(end & ~PAGE_MASK);

	handle->tail ++;

	return 0;
}*/

/*int shadow_log_partial_update(struct journal_handle *handle, unsigned int ino,
				unsigned int block_nr, loff_t pos, loff_t len)
{
	struct shadow_log_entry *entry = handle->tail;

	entry->ino = ino;
	entry->block_nr = block_nr;
	entry->pos = pos;
	entry->len = len;

	handle->tail ++;

	return 0;
}*/

static inline
void shadow_flush_buffer(void *buf, uint32_t len, bool fence)
{
	uint32_t i;

	len = roundup(len, CACHELINE_SIZE);
	for (i = 0; i < len; i += CACHELINE_SIZE)
		_mm_clflush(buf + i);

	if (fence)
		PERSISTENT_BARRIER();
}

static inline
struct journal_ptr_pair *shadow_get_journal_ptr(struct super_block *sb,
						unsigned int cpu)
{
	struct shadow_sb_info *sb_info = sb->s_fs_info;

	BUG_ON(cpu > sb_info->cpus);

	return (struct journal_ptr_pair*)(sb_info->mgr->virt_addr + PAGE_SIZE
			+ cpu * CACHELINE_SIZE);
}

void shadow_init_journal_handle(struct super_block *sb,
				struct journal_handle *handle)
{
	struct journal_ptr_pair *pair;
	struct shadow_sb_info *si = sb->s_fs_info;

	pair = shadow_get_journal_ptr(sb, smp_processor_id());
	handle->old_tail = handle->tail = si->mgr->virt_addr + pair->tail;
}

static inline u64 shadow_pmem_v2p(struct super_block *sb, void *vaddr)
{
	return vaddr - ((struct shadow_sb_info*)sb->s_fs_info)->mgr->virt_addr;
}

void shadow_destroy_journal_handle(struct super_block *sb,
				   struct journal_handle *handle)
{
	u64 new_tail, entry_num;
	struct journal_ptr_pair *pair;

	pair = shadow_get_journal_ptr(sb, smp_processor_id());
	new_tail = shadow_pmem_v2p(sb, handle->tail);

	entry_num = handle->tail - handle->old_tail;
	if (entry_num)
		shadow_flush_buffer(handle->old_tail,
				entry_num * sizeof(struct shadow_log_entry), 0);

	pair->tail = new_tail;
	PERSISTENT_BARRIER();
}

int shadow_init_journal_hart(struct super_block *sb)
{
	struct shadow_sb_info *sbi = sb->s_fs_info;
	struct journal_ptr_pair *pair;
	unsigned int i;
	u64 block = HEAD_BLOCKS;

	unsigned long pcp_log_blocks =
		(HEAD_RESERVED_BLOCKS - HEAD_BLOCKS) / sbi->cpus;
	for(i = 0; i < sbi->cpus; ++i) {
		pair = shadow_get_journal_ptr(sb, i);
		pair->head = block << PAGE_SHIFT;
		pair->tail = block << PAGE_SHIFT;
		pr_info("%s: cpu %d start log at block %lld\n", __func__,
				i, block);
		block += pcp_log_blocks;
		shadow_flush_buffer(pair, sizeof(struct journal_ptr_pair), 0);
	}

	PERSISTENT_BARRIER();
	return 0;
}
