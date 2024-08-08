#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include "shadow_entry.h"

u64 IOstats[STATS_NUM];
DEFINE_PER_CPU(u64[STATS_NUM], IOstats_percpu);
const char *proc_dirname = "fs/shadow";
struct proc_dir_entry *shadow_proc_root;

static void shadow_get_IO_stats(void)
{
	int i, cpu;

	for (i = 0; i < STATS_NUM; i++) {
		IOstats[i] = 0;
		for_each_possible_cpu(cpu)
			IOstats[i] += per_cpu(IOstats_percpu[i], cpu);
	}
}

static void shadow_clear_IO_stats(struct super_block* sb)
{
	int i, cpu;

	for (i = 0; i < STATS_NUM; i++) {
		IOstats[i] = 0;
		if (i == pmem_allocated || i == pmem_released)
			continue;
		for_each_possible_cpu(cpu)
			per_cpu(IOstats_percpu[i], cpu) = 0;
	}
}

static int shadow_seq_IO_show(struct seq_file *seq, void *v)
{
	shadow_get_IO_stats();

	seq_puts(seq,
		"================ shadow I/O stats ================\n\n");
	seq_printf(seq, "sync_persisted %llu, async_persisted %llu\n",
		   IOstats[sync_persisted], IOstats[async_persisted]);
	seq_printf(seq, "simd_written 0x%llx(Bytes) normal_written 0x%llx(Bytes)\n",
		   IOstats[simd_written], IOstats[normal_written]);
	seq_printf(seq, "pmem_allocated 0x%llx(Pages) pmem_released 0x%llx(Pages)\n",
		   IOstats[pmem_allocated], IOstats[pmem_released]);
	seq_printf(seq, "read_dram 0x%llx(Pages) read_pmem 0x%llx(Pages) unsubmitted_read 0x%llx(Pages)\n",
		   IOstats[dram_read], IOstats[pmem_read], IOstats[unsubmitted_read]);
	seq_printf(seq, "holder allocated 0x%llx, freed 0x%llx\n",
		   IOstats[holder_allocated], IOstats[holder_freed]);
	seq_printf(seq, "synced up 0x%llx(Bytes)\n", IOstats[synced_up]);
	seq_printf(seq, "wtime_total=%lld, wtime_copy=%lld, wtime_flip=%lld, wtime_log_init=%lld, wtime_log_flush=%lld\n",
		   IOstats[wtime_total], IOstats[wtime_copy],
		   IOstats[wtime_flip], IOstats[wtime_log_init], IOstats[wtime_log_flush]);
	seq_printf(seq, "fadvise_submitted=%lld\n", IOstats[fadvise_submitted]);
	seq_puts(seq, "\n");

	return 0;
}

static int shadow_seq_IO_open(struct inode *inode, struct file *file)
{
	return single_open(file, shadow_seq_IO_show, pde_data(inode));
}

static ssize_t shadow_seq_clear_stats(struct file *filp, const char __user *buf,
				size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = pde_data(inode);

	shadow_clear_IO_stats(sb);

	return len;
}

static const struct proc_ops shadow_seq_IO_fops = {
	.proc_open	= shadow_seq_IO_open,
	.proc_read	= seq_read,
	.proc_write	= shadow_seq_clear_stats,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int show_written_data(struct seq_file *seq, void *v)
{
	int i, cpu;
	unsigned int stats_type[3] = {simd_written, normal_written, synced_up};

	for (i = 0; i < 3; ++i) {
		IOstats[stats_type[i]] = 0;
		for_each_possible_cpu(cpu)
			IOstats[stats_type[i]] += 
					per_cpu(IOstats_percpu[stats_type[i]], cpu);
	}

	// simd_written normal_written synced_up
	seq_put_decimal_ull(seq, NULL, IOstats[simd_written]);
	seq_put_decimal_ull(seq, " ", IOstats[normal_written]);
	seq_put_decimal_ull(seq, " ", IOstats[synced_up]);
	seq_putc(seq, '\n');

	return 0;
}

static int shadow_written_data_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_written_data, pde_data(inode));
}

static const struct proc_ops written_data_fops = {
	.proc_open	= shadow_written_data_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

void shadow_sysfs_init(void)
{
	shadow_proc_root = proc_mkdir(proc_dirname, NULL);
}

void shadow_sysfs_exit(void)
{
	remove_proc_entry(proc_dirname, NULL);
	shadow_proc_root = NULL;
}

void shadow_register_sysfs(struct super_block *sb)
{
	struct shadow_sb_info *sbi = sb->s_fs_info;

	if(shadow_proc_root)
		sbi->s_proc = proc_mkdir("test", shadow_proc_root);

	if(sbi->s_proc) {
		proc_create_data("IO_stats", 0444, sbi->s_proc,
				&shadow_seq_IO_fops, sb);
		proc_create_data("written_data", 0444, sbi->s_proc,
				&written_data_fops, sb);
	}
}

void shadow_unregister_sysfs(struct super_block *sb)
{
	struct shadow_sb_info *sbi = sb->s_fs_info;

	if (sbi->s_proc)
		remove_proc_subtree("test", shadow_proc_root);
}
