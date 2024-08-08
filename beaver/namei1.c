#include <linux/namei.h>
#include <linux/dcache.h>
#include "log.h"
#include "shadow_entry.h"

static int shadow_mknod(struct user_namespace *ns, struct inode *dir,
			struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct inode *inode;
	struct journal_handle j_handle;
	struct super_block *sb = dir->i_sb;

	inode = shadow_new_inode(ns, sb, dir, mode, dev, 0);
	if (!inode)
		return -ENOSPC;

	d_instantiate(dentry, inode);
	dget(dentry);
	dir->i_mtime = dir->i_ctime = current_time(dir);

	shadow_init_journal_handle(inode->i_sb, &j_handle);
	log_mknod(&j_handle, dir->i_ino,
		inode->i_ino, dentry->d_name.len, dentry->d_name.name);
	shadow_destroy_journal_handle(inode->i_sb, &j_handle);

	return 0;
}

static int shadow_create(struct user_namespace *ns, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	pr_debug("%s: dir=0x%px, dentry=%.20s, mode=%d, excl=%d\n",
		__func__, dir, dentry->d_name.name, mode, excl);

	return shadow_mknod(ns, dir, dentry, mode | S_IFREG, 0);
}

static int shadow_mkdir(struct user_namespace *userns, struct inode *dir,
			struct dentry *dentry, umode_t mode)
{
	int ret;
	struct journal_handle j_handle;
	struct inode *inode;

	ret = shadow_mknod(userns, dir, dentry, mode | S_IFDIR, 0);
	if (!ret) {
		inc_nlink(dir);
		inc_nlink(d_inode(dentry));
	}

	inode = dentry->d_inode;
	pr_debug("%s: dir=0x%px, dentry=%.20s, inode=0x%px\n",
		__func__, dir, dentry->d_name.name, inode);

	shadow_init_journal_handle(inode->i_sb, &j_handle);
	log_mkdir(&j_handle, dir->i_ino,
		inode->i_ino, dentry->d_name.len, dentry->d_name.name);
	shadow_destroy_journal_handle(inode->i_sb, &j_handle);

	return ret;
}

static int shadow_symlink(struct user_namespace *userns, struct inode *dir,
			  struct dentry *dentry, const char *symname)
{
	struct inode *inode;
	int ret = 0, len;

	inode = shadow_new_inode(userns,
				dir->i_sb, dir, S_IFLNK|S_IRWXUGO, 0, 0);
	if (!inode)
		return -ENOSPC;

	len = strlen(symname) + 1;
	ret = page_symlink(inode, symname, len);
	if (ret) {
		iput(inode);
		return ret;
	}

	d_instantiate(dentry, inode);
	dget(dentry);
	dir->i_mtime = dir->i_ctime = current_time(dir);

	return ret;
}

static int shadow_unlink(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	unsigned long c_ino = d_inode(dentry)->i_ino;
	struct journal_handle j_handle;
	int ret;

	pr_debug("%s: dir=0x%px, dentry=%.20s, inode=0x%px\n",
		__func__, dir, dentry->d_name.name, d_inode(dentry));
	ret = simple_unlink(dir, dentry);
	if (ret)
		return ret;

	shadow_init_journal_handle(sb, &j_handle);
	log_unlink(&j_handle, dir->i_ino, c_ino);
	shadow_destroy_journal_handle(sb, &j_handle);

	return 0;
}

static int shadow_link(struct dentry *old_dentry,
			struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);
	struct journal_handle j_handle;
	int ret;

	ret = simple_link(old_dentry, dir, dentry);
	if (ret)
		return ret;

	shadow_init_journal_handle(inode->i_sb, &j_handle);
	log_link(&j_handle, dir->i_ino,
		inode->i_ino, dentry->d_name.len, dentry->d_name.name);
	shadow_destroy_journal_handle(inode->i_sb, &j_handle);

	return 0;
}

static int shadow_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *c_inode = d_inode(dentry);
	struct journal_handle j_handle;
	int ret;

	ret = simple_rmdir(dir, dentry);
	if (ret)
		return ret;

	shadow_init_journal_handle(c_inode->i_sb, &j_handle);
	log_rmdir(&j_handle, dir->i_ino, c_inode->i_ino);
	shadow_destroy_journal_handle(c_inode->i_sb, &j_handle);

	return 0;
}

static int shadow_rename(struct user_namespace *mnt_userns, struct inode *old_dir,
		  struct dentry *old_dentry, struct inode *new_dir,
		  struct dentry *new_dentry, unsigned int flags)
{
	struct super_block *sb = d_inode(old_dentry)->i_sb;
	struct journal_handle j_handle;
	int ret;

	ret = simple_rename(mnt_userns, old_dir,
			old_dentry, new_dir, new_dentry, flags);
	if (ret)
		return ret;

	shadow_init_journal_handle(sb, &j_handle);
	log_rename(&j_handle, new_dir->i_ino, d_inode(old_dentry)->i_ino,
			new_dentry->d_name.len, new_dentry->d_name.name);
	shadow_destroy_journal_handle(sb, &j_handle);

	return 0;
}

struct dentry *shadow_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	pr_debug("%s: dir=0x%px, dentry=%.20s, flags=%d\n",
		__func__, dir, dentry->d_name.name, flags);

	return simple_lookup(dir, dentry, flags);
}

const struct inode_operations shadow_dir_inode_ops = {
	.lookup	= shadow_lookup,
	.create = shadow_create,
	.mknod	= shadow_mknod,
	.link	= shadow_link,
	.unlink	= shadow_unlink,
	.mkdir	= shadow_mkdir,
	.rmdir	= shadow_rmdir,
	.symlink= shadow_symlink,
	.rename	= shadow_rename,
	.getattr= simple_getattr,
	.setattr= simple_setattr,
};

