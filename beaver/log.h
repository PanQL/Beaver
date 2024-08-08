#ifndef _SHADOW_LOG_H
#define _SHADOW_LOG_H
#include <linux/module.h>
#include <asm/msr.h>

enum ShadowLogType {
	/* alloc nvm pages for a file content range */
	AllocBlocks,
	/* alloc a nvm page as per-page log for one file page */
	AllocPageLog,
	/* alignedly update file content range */
	UpdateAligned,
	/* unalignedly update a file data page by append */
	UpdateUnalignedAppend,
	/* append a per-page entry for an unaligned overwrite*/
	UpdateUnalignedOverwrite,
};

/*
 * Shadow log entry
 *
 * @log_type: type of this entry
 * @ino: associated page's inode number
 * @page_index: associated page's index in inode mapping
 * @p_page_number: two associated persistent pages' pfn
 */
struct shadow_log_entry {
	u8 entry_type;
	__le32 ino;
	__le64 time;
	union {
		struct { //for AllocBlocks and AllocPageLog
			__le64 block_nr;
			__le32 page_index;
			__le32 len;//in page/block granularity
		};
		struct { //for UpdateXxx
			union {
				struct {// [s_page, e_page) for UpdateAligned
					__le32 s_page;
					__le32 e_page;
				};
				struct {// for UpdateUnalignedXxx
					// high 48bits for pos(in bytes),
					// low 12bits for len(in bytes)
					__le64 pos_len;
				};
			};
		};
	};
	u8 __pad[32];
};
static_assert(sizeof(struct shadow_log_entry) == 64,
		"size of shadow_log_entry is not 64 bytes");

enum ShadowDirLogType {
	/* mkdir */
	MkDir,
	/* mknod */
	MkNode,
	/* link */
	Link,
	/* unlink */
	UnLink,
	/* rename */
	Rename,
	/* rmdir */
	RmDir,
};

#define DIR_LOG_NAME_LEN 255
struct shadow_dir_log_entry {
	__le32 p_ino; // parent inode number
	__le32 c_ino; // child inode number
	__le64 time;
	u8 entry_type; // dir operation type
	u8 name_len; // child name size
	u8 padding[14];
	char	name[255 + 1]; // child name
};
static_assert(sizeof(struct shadow_dir_log_entry) == 288,
		"size of shadow_log_entry is not 288 bytes");

struct journal_handle {
	struct shadow_log_entry *old_tail, *tail;
};

static inline void log_mkdir(struct journal_handle *handle, unsigned int p_ino,
			unsigned int c_ino, unsigned int name_len, const char *name)
{
	struct shadow_dir_log_entry *entry =
		(struct shadow_dir_log_entry *)handle->tail;

	entry->entry_type = MkDir;
	entry->time = rdtsc();
	entry->p_ino = p_ino;
	entry->c_ino = c_ino;
	entry->name_len = name_len;
	memcpy(entry->name, name, name_len);

	handle->tail += sizeof(struct shadow_dir_log_entry) / sizeof(struct shadow_log_entry);
}

static inline void log_mknod(struct journal_handle *handle, unsigned int p_ino,
			unsigned int c_ino, unsigned int name_len, const char *name)
{
	struct shadow_dir_log_entry *entry =
		(struct shadow_dir_log_entry *)handle->tail;

	entry->entry_type = MkNode;
	entry->time = rdtsc();
	entry->p_ino = p_ino;
	entry->c_ino = c_ino;
	entry->name_len = name_len;
	memcpy(entry->name, name, name_len);

	handle->tail += sizeof(struct shadow_dir_log_entry) / sizeof(struct shadow_log_entry);
}

static inline void log_link(struct journal_handle *handle, unsigned int p_ino,
			unsigned int c_ino, unsigned int name_len, const char *name)
{
	struct shadow_dir_log_entry *entry =
		(struct shadow_dir_log_entry *)handle->tail;

	entry->entry_type = Link;
	entry->time = rdtsc();
	entry->p_ino = p_ino;
	entry->c_ino = c_ino;
	entry->name_len = name_len;
	memcpy(entry->name, name, name_len);

	handle->tail += sizeof(struct shadow_dir_log_entry) / sizeof(struct shadow_log_entry);
}

static inline void log_unlink(struct journal_handle *handle,
			unsigned int p_ino, unsigned int c_ino)
{
	struct shadow_dir_log_entry *entry =
		(struct shadow_dir_log_entry *)handle->tail;

	entry->entry_type = UnLink;
	entry->time = rdtsc();
	entry->p_ino = p_ino;
	entry->c_ino = c_ino;
	entry->name_len = 0;

	handle->tail ++;
}

static inline void log_rename(struct journal_handle *handle, unsigned int p_ino,
			unsigned int c_ino, unsigned int name_len, const char *name)
{
	struct shadow_dir_log_entry *entry =
		(struct shadow_dir_log_entry *)handle->tail;

	entry->entry_type = Rename;
	entry->time = rdtsc();
	entry->p_ino = p_ino;
	entry->c_ino = c_ino;
	entry->name_len = name_len;
	memcpy(entry->name, name, name_len);

	handle->tail += sizeof(struct shadow_dir_log_entry) / sizeof(struct shadow_log_entry);
}

static inline void log_rmdir(struct journal_handle *handle,
			unsigned int p_ino, unsigned int c_ino)
{
	struct shadow_dir_log_entry *entry =
		(struct shadow_dir_log_entry *)handle->tail;

	entry->entry_type = RmDir;
	entry->time = rdtsc();
	entry->p_ino = p_ino;
	entry->c_ino = c_ino;
	entry->name_len = 0;

	handle->tail ++;
}

static inline void log_blocks_alloc(struct journal_handle *handle, unsigned int ino,
		u64 block_nr, unsigned int index, unsigned int len)
{
	struct shadow_log_entry *entry = handle->tail;

	entry->entry_type = AllocBlocks;
	entry->ino = ino;
	entry->time = rdtsc();
	entry->block_nr = block_nr;
	entry->page_index = index;
	entry->len = len;

	handle->tail ++;
}

static inline void log_pplog_alloc(struct journal_handle *handle, unsigned int ino,
		u64 block_nr, unsigned int index)
{
	struct shadow_log_entry *entry = handle->tail;

	entry->entry_type = AllocPageLog;
	entry->ino = ino;
	entry->time = rdtsc();
	entry->block_nr = block_nr;
	entry->page_index = index;

	handle->tail ++;
}

static inline void log_aligned_update(struct journal_handle *handle, unsigned int ino,
					u32 s_page, u32 e_page)
{
	struct shadow_log_entry *entry = handle->tail;

	entry->entry_type = UpdateAligned;
	entry->ino = ino;
	entry->time = rdtsc();
	entry->s_page = s_page;
	entry->e_page = e_page;

	handle->tail ++;
}

static inline void log_unaligned_append(struct journal_handle *handle, unsigned int ino,
					u64 pos, u32 len)
{
	struct shadow_log_entry *entry = handle->tail;

	entry->entry_type = UpdateUnalignedAppend;
	entry->ino = ino;
	entry->time = rdtsc();
	entry->pos_len = (pos << PAGE_SHIFT) | (len & ~PAGE_MASK);

	handle->tail ++;
}

static inline void log_unaligned_overwrite(struct journal_handle *handle,
					unsigned int ino, u64 pos, u32 len)
{
	struct shadow_log_entry *entry = handle->tail;

	entry->entry_type = UpdateUnalignedOverwrite;
	entry->ino = ino;
	entry->time = rdtsc();
	entry->pos_len = (pos << PAGE_SHIFT) | (len & ~PAGE_MASK);

	handle->tail ++;
}

/*
 * Shadow log meta data (residing in PMem)
 *
 * @magic_num: magic number to identify if this log is initialized
 * @counter: number of exist log entries
 * @capacity: capacity for maximal log entry quantity
 * @entry_space: space of log enties
 */
struct raw_shadow_log {
	u64 magic_num;
	size_t counter;
	size_t capacity;
	struct shadow_log_entry entry_space[];
};

#define SHADOW_LOG_MAGIC 0xabcddeadULL
#define CACHELINE_SIZE 64
#define HEAD_RESERVED_BLOCKS 16777216UL
#define HEAD_BLOCKS 4UL

struct journal_ptr_pair {
	__le64 head;
	__le64 tail;
};

/*
 * Shadow log meta data (residing in DRAM)
 *
 * @lock: guard for concurrent access
 * @raw: pointer to raw log data in PMem
 */
struct shadow_log {
	spinlock_t lock;
	size_t counter;
	size_t capacity;
	struct shadow_log_entry *tail;
	struct raw_shadow_log *raw_mgr;
};

//unsigned long txid_create(struct shadow_log *log_mgr);
//int txid_submit(struct shadow_log *log_mgr, unsigned long txid);
//int shadow_log_commit(struct shadow_log *log_mgr, unsigned long txid,
		//unsigned long ino, struct page *pmem_page);
//int shadow_log_commit1(struct shadow_log *log_mgr, unsigned long txid,
		//unsigned long ino, unsigned long index, unsigned long pfn);
/*int shadow_log_pmem_alloc(struct journal_handle *handle, unsigned int ino,
		unsigned int index, unsigned int p_page0, unsigned int p_page1);
int shadow_log_range_flush(struct journal_handle *handle, unsigned int ino,
				loff_t start, loff_t end);
int shadow_log_partial_update(struct journal_handle *handle, unsigned int ino,
				unsigned int block_nr, loff_t pos, loff_t len);*/
void shadow_init_journal_handle(struct super_block *sb, struct journal_handle *handle);
void shadow_destroy_journal_handle(struct super_block *sb,
					struct journal_handle *handle);
int shadow_init_journal_hart(struct super_block *sb);

unsigned long shadow_raw_log_check(struct raw_shadow_log *raw,
				   unsigned long log_page_nr);
int shadow_log_restore(struct shadow_log *log_mgr, struct raw_shadow_log *raw);

#endif
