#ifndef SHADOW_ENTRY_H
#define SHADOW_ENTRY_H

#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/mman.h>
//#include "log.h"

#define SYNCUP_LIST_NUM 2

struct shadow_config {
	char *realfs;
	char *nvm;
};

struct syncup_list {
	struct task_struct *task;
	struct list_head head;
	int sleeping;
	spinlock_t lock;
};

struct shadow_sb_info;
struct syncup_task_arg {
	struct shadow_sb_info *sbi;
	struct syncup_list s_list;
	struct syncup_list *freeing;
};

struct shadow_sb_info {
	unsigned int cpus;
	struct vfsmount *real_mnt;
	/* creds for process who forced instantiation of super block */
	const struct cred *creator_cred;
	struct shadow_pm_manager *mgr;
	//struct shadow_log log_mgr;
	struct proc_dir_entry *s_proc;
	struct shadow_config config;
	struct task_struct *syncup_task[SYNCUP_LIST_NUM];
	struct syncup_task_arg syncup_args[SYNCUP_LIST_NUM];
	struct syncup_list freeing;
	atomic64_t pending_wr, finished_wr;
};

extern void shadow_sb_info_destroy(struct shadow_sb_info *sb_info);

const struct cred *shadow_override_creds(struct super_block *sb);

struct shadow_inode {
	spinlock_t lock;//guarantee one writter once only
	struct inode vfs_node;
	struct xarray shadow_mapping;
	struct inode *real_inode;
	struct file *file_handle;
	struct task_struct *flush_task;
	u64 write_count;
};
struct dentry *d_real_dentry(struct dentry *dentry);
struct inode *i_real_inode(struct inode *inode);

static inline struct shadow_inode *SHADOW_I(struct inode *inode)
{
	return container_of(inode, struct shadow_inode, vfs_node);
}

struct pm_page {
	struct list_head list;
	bool allocated;
	void *kaddr;
};
struct page *pmem_page_alloc_one(struct shadow_pm_manager *mgr);
struct page *pmem_page_alloc(struct shadow_pm_manager *mgr, unsigned int num);
void pmem_page_free(struct page *page, struct shadow_pm_manager *mgr);
unsigned int get_pmem_page_num(struct shadow_pm_manager *mgr, struct page *page);

struct pm_page_desc {
	struct list_head list;
	struct page *pm_page;
};

struct range_node {
	struct list_head list;
	struct page *low, *high;
};

struct pm_free_list {
	spinlock_t lock;
	struct list_head nodes;
	unsigned long capacity;
};

/*
 * PMem manager for shadow page cache
 *
 * @dax_dev: dax device instance
 * @virt_addr: virtual base address of PMem pages
 * @pfn: page frame number of first page entry
 * @num_blocks: number of PMem pages
 * @startoff: byte offset into the dax_device
 * @cores: cpu cores number
 * @free_lists: lists of free pm pages, per core a list
 */
struct shadow_pm_manager {
	struct dax_device *dax_dev;
	void *virt_addr;
	unsigned long pfn;
	unsigned long num_blocks;
	unsigned long log_page_nr;
	u64 startoff;
	unsigned int cores;
	struct pm_free_list *free_lists;
	spinlock_t lock;
};

int pmem_mgr_create(struct shadow_sb_info *sbi, const char *dev,
		    struct shadow_pm_manager *mgr, unsigned long log_page_nr);
void pmem_mgr_release(struct shadow_pm_manager *mgr, struct shadow_sb_info *sbi);

struct shadow_inode_param {
	struct inode *real_inode;
	struct inode *dir;
	struct user_namespace *userns;
};

/*struct inode* pcache_get_inode(struct super_block *sb,
			       struct shadow_inode_param *sip);*/
struct inode *shadow_new_inode(struct user_namespace *userns,
				struct super_block *sb, const struct inode *dir,
				umode_t mode, dev_t dev, unsigned long ino);
//struct inode *shadow_new_inode(struct super_block *sb,
				      //umode_t mode, dev_t rdev);

extern const struct file_operations shadow_file_ops;
extern const struct inode_operations shadow_dir_inode_ops;
extern const struct address_space_operations shadow_aops;
extern const struct inode_operations shadow_file_inode_ops;
extern const struct file_operations shadow_dir_ops;

vm_fault_t shadow_page_mkwrite(struct vm_fault *vmf);

/* If we *know* page->private refers to shadow_buffer */
#define page_shadow_buffer(page)				\
	({							\
		BUG_ON(!PagePrivate(page));			\
		((struct shadow_page *)page_private(page));	\
	})
#define page_shadowed(page)	PagePrivate(page)
#define folio_shadow_buffer(folio)	folio_get_private(folio)

#define SHADOW_TAG_COMMITTED	XA_MARK_0
#define SHADOW_TAG_NEW		XA_MARK_1

enum ShadowType {
	PageLog,
	PageSnapshot,
};

struct shadow_page {
	void *p_data; /* persistent data; points to a persistent page*/
	enum ShadowType type; /* what is the shadow page used for?
				 log of data page or page snapshot*/
	unsigned int entry_tail; /* point to head of free space for log*/
};
struct shadow_page* alloc_shadow_page(void);
void dealloc_shadow_page(struct shadow_page *shadow);

struct page_log_entry {
	unsigned offset;
	unsigned bytes;
};

int shadow_page_init(void);
void shadow_page_exit(void);
void create_shadow_page(struct page*, enum ShadowType);
void create_page_log(struct page *page, unsigned offset, size_t bytes);

/* For statfs */
enum stats_type {
	sync_persisted,
	async_persisted,
	simd_written,
	normal_written,
	pmem_allocated,
	pmem_released,
	dram_read,
	pmem_read,
	unsubmitted_read,
	synced_up,
	holder_allocated,
	holder_freed,
	fadvise_submitted,
	wtime_total,
	wtime_copy,
	wtime_flip,
	wtime_log_flush,
	wtime_log_init,
	STATS_NUM,
};

extern u64 IOstats[STATS_NUM];
DECLARE_PER_CPU(u64[STATS_NUM], IOstats_percpu);

void shadow_sysfs_init(void);
void shadow_sysfs_exit(void);
void shadow_register_sysfs(struct super_block *sb);
void shadow_unregister_sysfs(struct super_block *sb);

#define SHADOW_STATS_ADD(name, value) \
	{__this_cpu_add(IOstats_percpu[name], value); }

int flush_pmem_pages(struct address_space *mapping);
int shadow_run_flush_thread(struct shadow_inode *s_inode);
void shadow_destroy_flush_thread(struct shadow_inode *s_inode);

struct shadow_page_holder {
	spinlock_t lock;
	void *__rcu read_ptr;
	int cur;
	unsigned int state;
	struct page *pmem_pages[3];
	struct page *dram_page;
	struct list_head syncup;
};
static_assert(sizeof(struct shadow_page_holder) == 72,
		"size of shadow_log_entry is not 72 bytes");
int ph_cache_init(void);
void ph_cache_exit(void);
struct shadow_page_holder *holder_alloc(void);
int holder_alloc_bulk(size_t size, void **p);
void holder_free(struct shadow_page_holder *holder);

unsigned long avx_copy(void* dst, void* src, size_t sz);
unsigned long avx_copy_iter4(void** dst_iter, void* src);

int _run_syncup_threads(struct shadow_inode *s_inode);
void _stop_syncup_threads(struct shadow_inode *s_inode);

enum holder_state {
	INIT = 0,
	SYNCING = 1,
	FREEING = 2,
};

int init_sb_info_syncup(struct shadow_sb_info *sb_info);
void destroy_sb_info_syncup(struct shadow_sb_info *sb_info);
void clean_freeing_holders(struct syncup_list *freeing, struct shadow_pm_manager *mgr);

struct pp_args {
	unsigned long ino;
	struct shadow_pm_manager *mgr;
	struct shadow_log *log_mgr;
	loff_t pos, bytes;
	loff_t mask_addr;
};

void ppl_append(struct address_space *mapping, loff_t rng_start,
			loff_t rng_end, struct iov_iter *iov);

int shadow_fsync(struct file *file, loff_t start,
			loff_t end, int datasync);

void rng_cache_exit(void);
int rng_cache_init(void);

#endif
