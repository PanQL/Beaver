#include <linux/namei.h>
#include <linux/dcache.h>
#include "shadow_entry.h"

struct dentry *d_real_dentry(struct dentry *dentry)
{
	BUG_ON(!dentry->d_fsdata);
	return (struct dentry*)dentry->d_fsdata;
}

struct inode *i_real_inode(struct inode *inode)
{
	return SHADOW_I(inode)->real_inode;
}

static struct dentry *__lookup_hash(const struct qstr *name,
		struct dentry *base, unsigned int flags)
{
	struct dentry *dentry = d_lookup(base, name);
	struct dentry *old;
	struct inode *dir = base->d_inode;

	if (dentry)
		return dentry;

	/* Don't create child dentry for a dead directory. */
	if (unlikely(IS_DEADDIR(dir)))
		return ERR_PTR(-ENOENT);

	dentry = d_alloc(base, name);
	if (unlikely(!dentry))
		return ERR_PTR(-ENOMEM);

	old = dir->i_op->lookup(dir, dentry, flags);
	if (unlikely(old)) {
		dput(dentry);
		dentry = old;
	}
	return dentry;
}

static struct dentry *shadow_lookup(struct inode *dir,
				    struct dentry *dentry, unsigned int flags)
{
	struct dentry *real_dir_dentry = d_real_dentry(dentry->d_parent);
	struct inode *real_dir_inode = d_inode(real_dir_dentry);
	struct dentry *real_dentry;
	struct shadow_inode_param sip = {
		.userns = dentry->d_sb->s_user_ns,
		.dir = dir,
	};
	struct inode *inode = NULL;

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	pr_info("%s: dir=%.20s, dentry=%.20s, flags=%d\n",
		__func__, real_dir_dentry->d_name.name,
		dentry->d_name.name, flags);
	BUG_ON(dentry->d_fsdata);

	inode_lock(real_dir_inode);
	// lookup in lower dcache
	real_dentry = __lookup_hash(&dentry->d_name, real_dir_dentry, 0);
	if (IS_ERR(real_dentry))
		return real_dentry;
	/*real_dentry = d_lookup(real_dir_dentry, &dentry->d_name);*/
	/*if (!real_dentry) {//lower dcache miss, lookup in lower dir inode*/
		/*real_dentry = d_alloc(real_dir_dentry, &dentry->d_name);//unhashed*/
		/*res = real_dir_iop->lookup(real_dir_inode, real_dentry, flags);*/
		/*pr_warn("%s: lower dcache miss, lower lookup res=%px,real_dentry.count=%d\n",*/
			/*__func__, res, d_count(real_dentry));*/
		/*if (unlikely(res)) {*/
			/*dput(real_dentry);*/
			/*real_dentry = res;*/
		/*}*/
	/*}*/
	inode_unlock(real_dir_inode);
	sip.real_inode = d_inode(real_dentry);
	if (d_is_negative(real_dentry)) {
		dput(real_dentry);
		pr_info("%s: real_dentry is negative, return\n", __func__);
		goto out;
	}

	// build shadow inode for found lower inode
	inode = pcache_get_inode(dir->i_sb, &sip);
	dentry->d_fsdata = real_dentry;
	dir->i_mtime = dir->i_ctime = current_time(dir);

out:
	pr_info("%s: dentry.count=%d\n", __func__, d_count(dentry));
	return d_splice_alias(inode, dentry);
}

static int shadow_inode_create(struct user_namespace *ns, struct inode *dir,
			       struct dentry *dentry, umode_t mode, bool excl)
{
	struct shadow_sb_info *sb_info = dir->i_sb->s_fs_info;
	struct user_namespace *real_ns = mnt_user_ns(sb_info->real_mnt);
	struct dentry *real_dir_dentry = d_real_dentry(dentry->d_parent);
	struct inode *real_dir_inode = d_inode(real_dir_dentry);
	/*struct dentry *real_dentry = d_real_dentry(dentry);*/
	struct dentry *real_dentry;
	const struct inode_operations *real_iop = real_dir_inode->i_op;
	struct shadow_inode_param sip = {
		.userns = dir->i_sb->s_user_ns,
		.dir = dir,
	};
	struct inode *inode;
	int err;

	BUG_ON(dentry->d_fsdata);

	// lookup in lower dcache
	/*real_dentry = d_lookup(real_dir_dentry, &dentry->d_name);*/
	real_dentry = __lookup_hash(&dentry->d_name, real_dir_dentry, 0);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);
	BUG_ON(!real_dentry);
	BUG_ON(d_is_positive(real_dentry));
	// we find a dentry, now create a node for it
	err = real_iop->create(real_ns, real_dir_inode, real_dentry, mode, excl);
	if (err) {
		dput(real_dentry);
		return err;
	}

	sip.real_inode = d_inode(real_dentry);
	inode = pcache_get_inode(dir->i_sb, &sip);
	dentry->d_fsdata = real_dentry;
	dget(dentry);
	d_instantiate(dentry, inode);
	dir->i_mtime = dir->i_ctime = current_time(dir);

	return err;
}

static int shadow_mknod(struct user_namespace *ns, struct inode *dir,
			struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct shadow_sb_info *sb_info = dir->i_sb->s_fs_info;
	struct user_namespace *real_ns = mnt_user_ns(sb_info->real_mnt);
	struct dentry *real_dir_dentry = d_real_dentry(dentry->d_parent);
	struct inode *real_dir_inode = d_inode(real_dir_dentry);
	/*struct dentry *real_dentry = d_real_dentry(dentry);*/
	struct dentry *real_dentry;
	const struct inode_operations *real_iop = real_dir_inode->i_op;
	struct shadow_inode_param sip = {
		.userns = dir->i_sb->s_user_ns,
		.dir = dir,
	};
	struct inode *inode;
	int err;

	// lookup in lower dcache
	/*real_dentry = d_lookup(real_dir_dentry, &dentry->d_name);*/
	BUG_ON(dentry->d_fsdata);
	real_dentry = __lookup_hash(&dentry->d_name, real_dir_dentry, 0);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);
	BUG_ON(!real_dentry);
	if (d_is_positive(real_dentry)) {
		BUG();
		pr_warn("error!\n");
	}
	// we find a dentry, now make a node for it
	err = real_iop->mknod(real_ns, real_dir_inode, real_dentry, mode, dev);
	if (err) {
		dput(real_dentry);
		return err;
	}

	sip.real_inode = d_inode(real_dentry);
	inode = pcache_get_inode(dir->i_sb, &sip);
	dentry->d_fsdata = real_dentry;
	dget(dentry);
	d_instantiate(dentry, inode);
	dir->i_mtime = dir->i_ctime = current_time(dir);

	return err;
}

static int shadow_link(struct dentry *old_dentry,
		       struct inode *dir,struct dentry *dentry)
{
	/*struct dentry *real_dir_dentry = d_real_dentry(dentry->d_parent);*/
	struct dentry *real_dentry;
	struct dentry *real_dir_dentry = d_real_dentry(dentry->d_parent);
	struct dentry *real_old_dentry = d_real_dentry(old_dentry);
	struct inode *real_dir_inode = i_real_inode(dir);
	const struct inode_operations *real_iop = real_dir_inode->i_op;
	int err;

	// lookup in lower dcache
	/*real_dentry = d_lookup(real_dir_dentry, &dentry->d_name);*/
	real_dentry = __lookup_hash(&dentry->d_name, real_dir_dentry, 0);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);
	BUG_ON(!real_dentry);
	// we find a dentry, now do link operation
	err = real_iop->link(real_old_dentry, real_dir_inode, real_dentry);
	if (err) {
		dput(real_dentry);
		return err;
	}

	dentry->d_fsdata = real_dentry;
	err = simple_link(old_dentry, dir, dentry);

	return err;
}

static int shadow_unlink(struct inode *dir, struct dentry *dentry)
{
	struct dentry *real_dentry = d_real_dentry(dentry);
	struct inode *real_inode = d_inode(real_dentry);
	struct inode *real_dir_inode = i_real_inode(dir);
	const struct inode_operations *real_iop = real_dir_inode->i_op;
	int err;

	inode_lock(real_inode);
	err = real_iop->unlink(real_dir_inode, real_dentry);
	inode_unlock(real_inode);
	if (err)
		goto out;
	d_delete(real_dentry);
	dput(real_dentry);
	dentry->d_fsdata = NULL;

	err = simple_unlink(dir, dentry);

out:
	return err;
}

static int shadow_mkdir(struct user_namespace *userns, struct inode *dir,
			struct dentry *dentry, umode_t mode)
{
	struct shadow_sb_info *sb_info = dir->i_sb->s_fs_info;
	struct user_namespace *real_ns = mnt_user_ns(sb_info->real_mnt);
	struct dentry *real_dir_dentry = d_real_dentry(dentry->d_parent);
	struct inode *real_dir_inode = d_inode(real_dir_dentry);
	struct dentry *real_dentry;
	const struct inode_operations *real_iop = real_dir_inode->i_op;
	struct shadow_inode_param sip = {
		.userns = dir->i_sb->s_user_ns,
		.dir = dir,
	};
	struct inode *inode;
	int err;

	BUG_ON(dentry->d_fsdata);

	// lookup in lower dcache
	/*real_dentry = d_lookup(real_dir_dentry, &dentry->d_name);*/
	real_dentry = __lookup_hash(&dentry->d_name, real_dir_dentry, 0);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);
	BUG_ON(!real_dentry);
	pr_info("%s: real_dentry=%px with count %d\n",
		__func__, real_dentry, d_count(real_dentry));
	// we find a dentry, create a dir inode for it to connect with
	err = real_iop->mkdir(real_ns, real_dir_inode, real_dentry, mode);
	if (err) {
		dput(real_dentry);
		goto out;
	}

	sip.real_inode = d_inode(real_dentry);
	inode = pcache_get_inode(dir->i_sb, &sip);
	dget(dentry);
	dentry->d_fsdata = real_dentry;
	d_instantiate(dentry, inode);
	dir->i_mtime = dir->i_ctime = current_time(dir);
	inc_nlink(dir);

	pr_info("%s finish: real_dentry count=%d, dentry count=%d\n",
		__func__, d_count(real_dentry), d_count(dentry));
out:
	return err;
}

static int shadow_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *real_dentry = d_real_dentry(dentry);
	struct inode *real_inode = d_inode(real_dentry);
	struct inode *real_dir_inode = i_real_inode(dir);
	const struct inode_operations *real_iop = real_dir_inode->i_op;
	int err;

	if (!simple_empty(dentry))
		return -ENOTEMPTY;

	inode_lock(real_inode);
	err = real_iop->rmdir(real_dir_inode, real_dentry);
	inode_unlock(real_inode);
	if (err)
		goto out;
	d_delete(real_dentry);

	drop_nlink(d_inode(dentry));
	simple_unlink(dir, dentry);
	drop_nlink(dir);
out:
	return err;
}

static int shadow_symlink(struct user_namespace *userns, struct inode *dir,
			  struct dentry *dentry, const char *symname)
{
	struct shadow_sb_info *sb_info = dir->i_sb->s_fs_info;
	struct user_namespace *real_ns = mnt_user_ns(sb_info->real_mnt);
	struct dentry *real_dir_dentry = d_real_dentry(dentry->d_parent);
	struct inode *real_dir_inode = d_inode(real_dir_dentry);
	struct dentry *real_dentry;
	const struct inode_operations *real_iop = real_dir_inode->i_op;
	struct shadow_inode_param sip = {
		.userns = dir->i_sb->s_user_ns,
		.dir = dir,
	};
	struct inode *inode;
	int err;

	BUG_ON(dentry->d_fsdata);
	real_dentry = __lookup_hash(&dentry->d_name, real_dir_dentry, 0);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);

	err = real_iop->symlink(real_ns, real_dir_inode, real_dentry, symname);
	if (err) {
		dput(real_dentry);
		goto out;
	}

	sip.real_inode = d_inode(real_dentry);
	inode = pcache_get_inode(dir->i_sb, &sip);
	dentry->d_fsdata = real_dentry;
	dget(dentry);
	d_instantiate(dentry, inode);
	dir->i_mtime = dir->i_ctime = current_time(dir);
out:
	return err;
}

static int shadow_rename(struct user_namespace *mnt_userns,
			 struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	int err;
	struct inode *real_old_dir = i_real_inode(old_dir);
	struct inode *real_new_dir = i_real_inode(new_dir);
	struct dentry *real_old_dentry = d_real_dentry(old_dentry);
	struct dentry *real_new_dir_dentry = d_real_dentry(new_dentry->d_parent);
	struct dentry *real_new_dentry = new_dentry->d_fsdata;
	/*struct inode *real_inode = d_inode(real_old_dentry);*/
	struct inode *real_target;
	bool is_dir = d_is_dir(real_old_dentry);
	const struct inode_operations *iops = real_old_dir->i_op;
	bool put_real_new_dentry = false;

	/*pr_info("%s: old=%.20s, new=%.20s, flags=%d\n",
		__func__, old_dentry->d_name.name,
		new_dentry->d_name.name, flags);*/

	if (!iops->rename)
		return -EPERM;
	BUG_ON(flags & RENAME_WHITEOUT);

	if (!(flags & RENAME_EXCHANGE) && !real_new_dentry) {
		inode_lock(real_new_dir);
		real_new_dentry = __lookup_hash(&new_dentry->d_name,
						real_new_dir_dentry, 0);
		inode_unlock(real_new_dir);
		put_real_new_dentry = true;
		new_dentry->d_fsdata = NULL;
	}

	/*real_target = d_inode(real_new_dentry);*/
	/*inode_lock(real_inode);*/
	if (real_target)
		inode_lock(real_target);
	err = iops->rename(NULL, real_old_dir,
			real_old_dentry, real_new_dir, real_new_dentry, flags);
	if (err)
		return err;
	if (!(flags & RENAME_EXCHANGE) && real_target) {
		if (is_dir) {
			shrink_dcache_parent(real_new_dentry);
			real_target->i_flags |= S_DEAD;
		}
	}
	if (!(real_old_dir->i_sb->s_type->fs_flags & FS_RENAME_DOES_D_MOVE)) {
		if (!(flags & RENAME_EXCHANGE))
			d_move(real_old_dentry, real_new_dentry);
		else
			BUG();
			/*d_exchange(real_old_dentry, real_new_dentry);*/
	}
	/*inode_unlock(real_inode);*/
	/*if (real_target)*/
		/*inode_unlock(real_target);*/
	if (put_real_new_dentry)
		dput(real_new_dentry);

	err = simple_rename(mnt_userns, old_dir,
				old_dentry, new_dir, new_dentry, flags);

	return err;
}

const struct inode_operations shadow_dir_inode_ops = {
	.lookup	= shadow_lookup,
	.create = shadow_inode_create,
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
