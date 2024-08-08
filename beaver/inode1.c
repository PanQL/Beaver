#include <linux/fs.h>
#include <linux/pagemap.h>
#include "shadow_entry.h"

struct inode *shadow_new_inode(struct user_namespace *userns,
				struct super_block *sb, const struct inode *dir,
				umode_t mode, dev_t dev, unsigned long ino)
{
	struct inode *inode = new_inode(sb);
	struct shadow_inode *s_inode = SHADOW_I(inode);

	if (inode) {
		if (ino) {
			inode->i_ino = ino;
			inode->i_size = PAGE_SIZE;
		} else {
			inode->i_ino = get_next_ino() + 2;
			inode->i_size = 0;
		}

		inode_init_owner(userns, inode, dir, mode);
		inode->i_mode = mode;
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

		switch (mode & S_IFMT) {
			case S_IFREG:
				inode->i_op = &shadow_file_inode_ops;
				inode->i_fop = &shadow_file_ops;
				inode->i_mapping->a_ops = &shadow_aops;
				spin_lock_init(&s_inode->lock);
				break;
			case S_IFDIR:
				inode->i_op = &shadow_dir_inode_ops;
				inode->i_fop = &shadow_dir_ops;
				break;
			case S_IFLNK:
				inode->i_op = &page_symlink_inode_operations;
				inode_nohighmem(inode);
				break;
			default:
				init_special_inode(inode, mode, dev);
		}
	}

	return inode;
}
