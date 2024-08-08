#include <linux/fs.h>
#include <linux/fsnotify.h>
#include "shadow_entry.h"

#define SHADOW_DIR_FLAGS (O_RDONLY | O_NOATIME | FMODE_NONOTIFY)
#define SHADOW_INODE_PERM (MAY_OPEN | MAY_READ)

/*static int shadow_iterate(struct file *file, struct dir_context *ctx)*/
/*{*/
	/*int ret = 0;*/
	/*const struct cred *old_cred;*/
	/*struct user_namespace *real_mnt_userns;*/
	/*struct file *realfile;*/
	/*struct path real_path;*/
	/*struct inode *inode = file_inode(file);*/
	/*struct shadow_inode *shadow_f_inode = SHADOW_I(inode);*/
	/*struct inode *real_inode = d_inode(shadow_f_inode->real_dentry);*/
	/*struct shadow_sb_info *sb_info = inode->i_sb->s_fs_info;*/
	/*int flags = SHADOW_DIR_FLAGS;*/

	/*pr_warn("%s: %.10s, ctx->pos=%lld\n", __func__,*/
		/*file->f_path.dentry->d_name.name, ctx->pos);*/
	/*realfile = shadow_f_inode->file_handle;*/
	/*if (realfile)*/
		/*goto opened;*/

	/*real_path.dentry = SHADOW_I(inode)->real_dentry;*/
	/*real_path.mnt = sb_info->real_mnt;*/

	/*old_cred = shadow_override_creds(inode->i_sb);*/
	/*real_mnt_userns = mnt_user_ns(real_path.mnt);*/
	/*ret = inode_permission(real_mnt_userns, real_inode,*/
			       /*SHADOW_INODE_PERM);*/
	/*if (ret)*/
		/*return ret;*/
	/*else {*/
		/*[>if (!inode_owner_or_capable(real_mnt_userns, real_inode))<]*/
			/*[>flags &= ~O_NOATIME;<]*/

		/*realfile = open_with_fake_path(&real_path,*/
					    /*flags, real_inode, current_cred());*/
		/*shadow_f_inode->file_handle = realfile;*/
	/*}*/
	/*revert_creds(old_cred);*/

/*opened:*/
	/*realfile->f_pos = file->f_pos;*/
	/*ret = iterate_dir(realfile, ctx);*/
	/*[>ret = realfile->f_op->iterate_shared(realfile, ctx);<]*/
	/*[>realfile->f_pos = ctx->pos;<]*/
	/*[>fsnotify_access(realfile);<]*/
	/*[>file_accessed(realfile);<]*/
	/*return ret;*/
/*}*/

/*loff_t shadow_dir_llseek(struct file *file, loff_t offset, int whence) {*/
	/*BUG();*/
	/*return 0;*/
/*}*/

/*static int shadow_dir_open(struct inode *inode, struct file *file)*/
/*{*/
	/*struct inode *real_inode = i_real_inode(inode);*/

	/*fops_put(file->f_op);*/
	/*file->f_op = real_inode->i_fop;*/
	/*file->f_inode = real_inode;*/
	/*fops_get(file->f_op);*/
	/*i_readcount_inc(real_inode);*/

	/*return 0;*/
/*}*/

const struct file_operations shadow_dir_ops = {
	.owner = THIS_MODULE,
	.open	= dcache_dir_open,
	.release= dcache_dir_close,
	.iterate_shared = dcache_readdir,
	.fsync		= shadow_fsync,
};

