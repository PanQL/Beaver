#include <linux/fs.h>
#include <linux/pagemap.h>
#include "shadow_entry.h"

static int ovl_inode_test(struct inode *inode, void *data)
{
	return inode->i_private == data;
}

static int ovl_inode_set(struct inode *inode, void *data)
{
	inode->i_private = data;
	return 0;
}

static struct inode *shadow_iget(struct super_block *sb,
			         unsigned long key, struct inode *real_inode)
{
	return iget5_locked(sb, key,
			    ovl_inode_test, ovl_inode_set, (void *)real_inode);
}

/* No atime modification nor notify on underlying */
/*#define SHADOW_OPEN_FLAGS (O_DIRECT | O_RDWR | O_NOATIME | FMODE_NONOTIFY)*/
/*#define SHADOW_INODE_PERM (MAY_OPEN | MAY_READ | MAY_WRITE)*/

/*static struct file *shadow_open_realfile(const struct inode *inode,*/
					 /*const struct path *realpath)*/
/*{*/
	/*const struct cred *old_cred;*/
	/*struct inode *realinode = d_inode(realpath->dentry);*/
	/*struct user_namespace *real_mnt_userns;*/
	/*int flags = SHADOW_OPEN_FLAGS;*/
	/*struct file *realfile;*/
	/*int err;*/

	/*old_cred = shadow_override_creds(inode->i_sb);*/
	/*real_mnt_userns = mnt_user_ns(realpath->mnt);*/
	/*err = inode_permission(real_mnt_userns, realinode,*/
			       /*SHADOW_INODE_PERM);*/
	/*if (err) {*/
		/*realfile = ERR_PTR(err);*/
	/*} else {*/
		/*[>if (!inode_owner_or_capable(real_mnt_userns, realinode))<]*/
			/*[>flags &= ~O_NOATIME;<]*/

		/*realfile = open_with_fake_path(realpath, flags, realinode,*/
					       /*current_cred());*/
	/*}*/
	/*revert_creds(old_cred);*/

	/*return realfile;*/
/*}*/

/*void real_inode_copy_up(struct shadow_inode *s_inode,*/
			/*const struct file *real_file)*/
/*{*/
	/*struct inode *real_inode = file_inode(real_file);*/

	/*s_inode->vfs_node.i_size = real_inode->i_size;*/
	/*// TODO: complete this function, may need lock on real_inode*/
/*}*/

vm_fault_t shadow_page_mkwrite(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct page *page = vmf->page;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	vm_fault_t ret = VM_FAULT_LOCKED;

	sb_start_pagefault(inode->i_sb);

	filemap_invalidate_lock_shared(mapping);

	lock_page(page);
	set_page_dirty(page);
	/*if (!page_shadowed(page)) {*/
		/*create_shadow_page(page, PageSnapshot);*/
		/*ret = VM_FAULT_LOCKED;*/
		/*goto out;*/
	/*}*/

/*out:*/
	filemap_invalidate_unlock_shared(mapping);
	sb_end_pagefault(inode->i_sb);
	return ret;
}

/*void shadow_inode_init(struct inode *inode, struct dentry *real_dentry,*/
		       /*unsigned long ino)*/
/*{*/
	/*struct shadow_inode *s_inode = SHADOW_I(inode);*/
	/*struct shadow_sb_info *info = inode->i_sb->s_fs_info;*/
	/*struct inode *real_inode = d_inode(real_dentry);*/
	/*struct path real_path;*/
	/*struct file *real_file;*/

	/*pr_warn("%s: inode=0x%px, real_dentry=0x%px, ino=%ld\n", __func__,*/
		/*inode, real_dentry, ino);*/

	/*inode->i_ino = ino;*/
	/*s_inode->real_dentry = real_dentry;*/

	/*if ((real_inode->i_mode & S_IFMT) == S_IFREG) {*/
		/*real_path.mnt = info->real_mnt;*/
		/*real_path.dentry = real_dentry;*/
		/*real_file = shadow_open_realfile(inode, &real_path);*/
		/*BUG_ON(IS_ERR(real_file));*/

		/*real_inode_copy_up(s_inode, real_file);*/
		/*s_inode->file_handle = real_file;*/
	/*} else {*/
		/*s_inode->file_handle = NULL;*/
	/*}*/

/*}*/

const char *shadow_get_link(struct dentry *dentry,
			    struct inode *inode, struct delayed_call *callback)
{
	struct inode *real_inode = i_real_inode(inode);
	const struct inode_operations *real_iops = real_inode->i_op;

	return real_iops->get_link(dentry, real_inode, callback);
}

const struct inode_operations shadow_symlink_inode_operations = {
	.get_link	= shadow_get_link,
};

static void shadow_fill_inode(struct inode *inode, struct inode *real_inode)
{
	struct shadow_inode *shadow_inode = SHADOW_I(inode);

	inode->i_mode = real_inode->i_mode;
	inode->i_ino  = real_inode->i_ino;
	inode->__i_nlink = real_inode->i_nlink;
	inode->i_size = real_inode->i_size;
	shadow_inode->real_inode = real_inode;

	switch (real_inode->i_mode & S_IFMT) {
	case S_IFREG:
		struct xarray *shadow_mapping;

		inode->i_op = &shadow_file_inode_ops;
		inode->i_fop = &shadow_file_ops;
		inode->i_mapping->a_ops = &shadow_aops;
		shadow_mapping = &shadow_inode->shadow_mapping;
		inode->i_mapping->private_data = shadow_mapping;
		spin_lock_init(&shadow_inode->lock);
		/*shadow_run_flush_thread(shadow_inode);*/
		break;
	case S_IFDIR:
		inode->i_op = &shadow_dir_inode_ops;
		inode->i_fop = &shadow_dir_ops;
		break;
	case S_IFLNK:
		inode->i_op = &shadow_symlink_inode_operations;
		inode_nohighmem(inode);
		break;
	default:
		init_special_inode(inode,
				   real_inode->i_mode, real_inode->i_rdev);
	}
}

struct inode *pcache_get_inode(struct super_block *sb,
			       struct shadow_inode_param *sip)
{
	struct inode *real_inode = sip->real_inode;
	struct inode *inode;
	int err = -ENOMEM;

	BUG_ON(!real_inode);
	inode = shadow_iget(sb, real_inode->i_ino, real_inode);
	if (!inode)
		goto err_out;
	if (!(inode->i_state & I_NEW))
		goto out;

	// we get a new inode, init it with real_inode
	inode_init_owner(sip->userns, inode, sip->dir, real_inode->i_mode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	shadow_fill_inode(inode, real_inode);

	// unlock for using this new inode
	unlock_new_inode(inode);

out:
	return inode;
err_out:
	pr_err("%s: failed to get inode (%i)\n", __func__, err);
	return ERR_PTR(err);
}

struct inode *shadow_new_inode(struct user_namespace *userns,
				struct super_bloc *sb, const struct inode *dir,
				umode_t mode, dev_t dev, unsigned long ino)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		if (ino)
			inode->i_ino = ino;
		else
			inode->i_ino = get_next_ino() + 2;

		inode_init_owner(userns, inode, dir, mode);
		inode->i_mode = real_inode->i_mode;
		inode->i_ino  = real_inode->i_ino;
		inode->__i_nlink = real_inode->i_nlink;
		inode->i_size = real_inode->i_size;
		shadow_inode->real_inode = real_inode;

		switch (mode & S_IFMT) {
			case S_IFREG:
				struct xarray *shadow_mapping;

				inode->i_op = &shadow_file_inode_ops;
				inode->i_fop = &shadow_file_ops;
				inode->i_mapping->a_ops = &shadow_aops;
				shadow_mapping = &shadow_inode->shadow_mapping;
				inode->i_mapping->private_data = shadow_mapping;
				spin_lock_init(&shadow_inode->lock);
				break;
			case S_IFDIR:
				inode->i_op = &shadow_dir_inode_ops;
				inode->i_fop = &shadow_dir_ops;
				break;
			case S_IFLNK:
				inode->i_op = &shadow_symlink_inode_operations;
				inode_nohighmem(inode);
				break;
			default:
				init_special_inode(inode, i_mode, dev);
		}
	}

	return inode;
}

/*struct inode *shadow_new_inode(struct super_block *sb, umode_t mode, dev_t rdev)*/
/*{*/
	/*struct inode *inode;*/

	/*inode = new_inode(sb);*/
	/*if (inode) {*/
		/*inode->i_state |= I_NEW;*/
		/*shadow_fill_inode(inode, mode, rdev);*/
	/*}*/

	/*return inode;*/
/*}*/
