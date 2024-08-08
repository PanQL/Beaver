#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/parser.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/swap.h>
#include <linux/list.h>

#include "log.h"
#include "shadow_entry.h"

MODULE_AUTHOR("Qinglin Pan");
MODULE_DESCRIPTION("Shadow filesystem");
MODULE_LICENSE("GPL");

struct kmem_cache *shadow_inode_cachep = NULL;
struct kmem_cache *shadow_mgr_cachep = NULL;

enum {
	OPT_REALFS,
	OPT_NVM,
};

static const match_table_t shadow_tokens = {
	{OPT_REALFS,			"realfs=%s"},
	{OPT_NVM,			"nvm=%s"},
};

static char *shadow_next_opt(char **s)
{
	char *sbegin = *s;
	char *p;

	if (sbegin == NULL)
		return NULL;

	for (p = sbegin; *p; p++) {
		if (*p == '\\') {
			p++;
			if (!*p)
				break;
		} else if (*p == ',') {
			*p = '\0';
			*s = p + 1;
			return sbegin;
		}
	}
	*s = NULL;
	return sbegin;
}

static int shadow_parse_opt(char *opt, struct shadow_config *config)
{
	char *p;

	while ((p = shadow_next_opt(&opt)) != NULL) {
		int token;
		substring_t args[MAX_OPT_ARGS];

		if (!*p)
			continue;

		token = match_token(p, shadow_tokens, args);
		switch (token) {
		case OPT_REALFS:
			kfree(config->realfs);
			config->realfs = match_strdup(&args[0]);
			break;
		case OPT_NVM:
			kfree(config->nvm);
			config->nvm = match_strdup(&args[0]);
			break;
		}
	}

	return 0;
}

static struct inode* shadow_alloc_inode(struct super_block *sb)
{
	struct shadow_inode *s_inode;

	s_inode = alloc_inode_sb(sb, shadow_inode_cachep, GFP_KERNEL);
	xa_init(&s_inode->shadow_mapping);
	s_inode->real_inode = NULL;
	s_inode->file_handle = NULL;
	s_inode->flush_task = NULL;

	return &s_inode->vfs_node;
}

void destroy_shadow_mapping(struct xarray *shadow_mapping,
				struct shadow_pm_manager *mgr)
{
	void *entry;
	XA_STATE(xas, shadow_mapping, 0);

	rcu_read_lock();
	xas_for_each(&xas, entry, LONG_MAX) {
		if (xas_retry(&xas, entry))
			continue;

		pmem_page_free(entry, mgr);
	}
	rcu_read_unlock();

	xa_destroy(shadow_mapping);
}

static void release_inode_holders(struct inode *inode)
{
	struct shadow_sb_info *sb_info = inode->i_sb->s_fs_info;
	struct syncup_list *freeing = &sb_info->freeing;
	struct list_head temp;
	struct shadow_page_holder *holder;
	XA_STATE(xas, &inode->i_data.i_pages, 0);
	INIT_LIST_HEAD(&temp);

	xas_for_each(&xas, holder, LONG_MAX) {
		spin_lock(&holder->lock);
		// if holder is syncing, skip.
		if (holder->state == INIT) {
			holder->state = FREEING;
			list_add(&holder->syncup, &temp);
		} else if (holder->state == SYNCING)
			holder->state = FREEING;
		else
			BUG();
		spin_unlock(&holder->lock);
	}

	spin_lock(&freeing->lock);
	list_splice_tail_init(&temp, &freeing->head);
	spin_unlock(&freeing->lock);

	clean_freeing_holders(freeing, sb_info->mgr);
	xa_destroy(&inode->i_data.i_pages);
}

static void shadow_destroy_inode(struct inode *inode)
{
	struct shadow_inode *s_inode = SHADOW_I(inode);

	kmem_cache_free(shadow_inode_cachep, s_inode);
}

static void shadow_evict_inode(struct inode *inode)
{
	pr_debug("%s: inodex=0x%px\n", __func__, inode);

	// we should be the only one accessing this xarray
	// so rcu_read_lock is unnecessary
	release_inode_holders(inode);
	clear_inode(inode);
}

static int shadow_drop_inode(struct inode *inode)
{
	bool res;

	res = !inode->i_nlink || inode_unhashed(inode);
	pr_debug("%s: inode=0x%px, i_nlink=%d, res=%d\n",
		__func__, inode, inode->i_nlink, res);
	BUG_ON(inode->i_nlink && !inode_unhashed(inode));

	return res;
}

const struct super_operations shadow_super_ops = {
	.alloc_inode = shadow_alloc_inode,
	.destroy_inode = shadow_destroy_inode,
	//.dirty_inode = shadow_dirty_inode,
	.evict_inode = shadow_evict_inode,
	.drop_inode  = shadow_drop_inode,
	.statfs = simple_statfs,
};

void shadow_d_iput(struct dentry *dentry, struct inode *inode)
{
	struct dentry *real_dentry = dentry->d_fsdata;
	dentry->d_fsdata = NULL;

	if (real_dentry && !IS_ROOT(real_dentry))
		dput(real_dentry);
	iput(inode);
}

static void shadow_d_release(struct dentry *dentry)
{
	struct dentry *real_dentry = dentry->d_fsdata;
	dentry->d_fsdata = NULL;

	if (real_dentry && !IS_ROOT(real_dentry))
		dput(real_dentry);
}

const struct dentry_operations shadow_dentry_ops = {
	.d_release = shadow_d_release,
	.d_iput = shadow_d_iput,
};

static int shadow_fill_super(struct super_block *sb, void *data, int silent)
{
	struct shadow_sb_info *sb_info = data;
	struct inode *root_inode;
	struct shadow_inode_param sip;
	struct dentry *real_root = sb_info->real_mnt->mnt_root;
	int ret;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_op = &shadow_super_ops;
	sb->s_fs_info = sb_info;
	sb->s_d_op = &shadow_dentry_ops;
	sb->s_time_gran = 1;

	sb->s_bdev = NULL;
	ret = super_setup_bdi(sb);
	if (ret)
		return ret;

	sip.real_inode = d_inode(real_root);
	sip.userns = sb->s_user_ns;
	root_inode = shadow_new_inode(sb->s_user_ns, sb,
					NULL, S_IFDIR | 0755, 0, 1);
	if (!root_inode)
		return -ENOMEM;
	sb->s_root = d_make_root(root_inode);
	sb->s_root->d_fsdata = real_root;

	shadow_init_journal_hart(sb);
	shadow_register_sysfs(sb);

	ret = init_sb_info_syncup(sb_info);

	return ret;
}

struct dentry *shadow_mount_nodev(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int))
{
	int error;
	struct super_block *s = sget(fs_type, NULL, set_anon_super, flags, NULL);

	if (IS_ERR(s))
		return ERR_CAST(s);

	pr_debug("fill_super enter\n");
	error = fill_super(s, data, flags & SB_SILENT ? 1 : 0);
	if (error) {
		deactivate_locked_super(s);
		return ERR_PTR(error);
	}
	s->s_flags |= SB_ACTIVE;
	return dget(s->s_root);
}

/*
 * @fs_type: must be `shadow`
 * @flags: mount flags we will push to real fs
 * @dev_name: the block dev we are mounting for
 * @raw_data: still not use
 */
static struct dentry* shadowfs_mount(struct file_system_type *fs_type, int flags,
				     const char *dev_name, void *raw_data)
{
	struct file_system_type *real_fs_type = NULL;
	struct dentry *dentry = NULL;
	struct shadow_sb_info *sb_info;
	struct vfsmount *realmnt;
	struct shadow_config *config;
	int err;

	sb_info = kzalloc(sizeof(struct shadow_sb_info), GFP_KERNEL);
	sb_info->cpus = 8;
	config = &sb_info->config;
	sb_info->creator_cred = prepare_creds();
	err = shadow_parse_opt(raw_data, config);
	if (err || !config->realfs || !config->nvm) {
		err = -EINVAL;
		goto err_out;
	}

	pr_info("size of struct shadow_page_holder is %ld bytes\n",
			sizeof(struct shadow_page_holder));
	pr_err("%s: fs_type=%s, flags=%d, dev_name=%s, realfs=%s, nvm=%s\n",
	       __func__, fs_type->name, flags,
	       dev_name, config->realfs, config->nvm);

	real_fs_type = get_fs_type(config->realfs);
	if (!real_fs_type) {
		pr_err("can not find a fs type named %s\n", config->realfs);
		err = -EINVAL;
		goto err_out;
	}
	realmnt = vfs_kern_mount(real_fs_type, flags, dev_name, NULL);
	if (IS_ERR_OR_NULL(realmnt)) {
		pr_err("can not mount %s with %s type\n",
				dev_name, config->realfs);
		err = -EINVAL;
		goto err_out;
	}
	sb_info->real_mnt = realmnt;

	sb_info->mgr = kmem_cache_alloc(shadow_mgr_cachep, GFP_KERNEL);
	err = pmem_mgr_create(sb_info, config->nvm, sb_info->mgr, 1UL << 22);
	if (err)
		goto err_out;
	//err = shadow_log_restore(&sb_info->log_mgr, sb_info->mgr->virt_addr);
	//BUG_ON(err);

	dentry = shadow_mount_nodev(fs_type, flags, sb_info, shadow_fill_super);
	if (IS_ERR(dentry))
		shadow_sb_info_destroy(sb_info);

	atomic64_set(&sb_info->pending_wr, 0);
	atomic64_set(&sb_info->finished_wr, 0);

	return dentry;
err_out:
	if (config->nvm)
		kfree(config->nvm);
	if (config->realfs)
		kfree(config->realfs);
	if (sb_info->mgr)
		kmem_cache_free(shadow_mgr_cachep, sb_info->mgr);

	kvfree(sb_info);
	return ERR_PTR(err);
}

static void shadow_kill_sb(struct super_block *sb)
{
	struct shadow_sb_info *sb_info = sb->s_fs_info;

	destroy_sb_info_syncup(sb_info);
	shadow_unregister_sysfs(sb);
	kill_litter_super(sb);
	shadow_sb_info_destroy(sb_info);
}

static struct file_system_type shadow_fs_type = {
	.owner = THIS_MODULE,
	.name = "shadow",
	.fs_flags = FS_USERNS_MOUNT,
	.mount = shadowfs_mount,
	.kill_sb = shadow_kill_sb,
};
MODULE_ALIAS_FS("shadow");

static void shadow_inode_init_once(void *foo)
{
	struct shadow_inode *si = foo;

	inode_init_once(&si->vfs_node);
	si->real_inode = NULL;
	si->flush_task = NULL;
}

static void shadow_mgr_ctor(void *ptr)
{
	struct shadow_pm_manager *mgr = ptr;

	spin_lock_init(&mgr->lock);
}

static int __init shadow_fs_init(void)
{
	int err = 0;

	pr_warn("shadow_fs_init\n");

	shadow_inode_cachep = kmem_cache_create("shadow_inode_cache",
						sizeof(struct shadow_inode),
						0,
						(SLAB_RECLAIM_ACCOUNT|
						 SLAB_MEM_SPREAD),
						shadow_inode_init_once);
	if (!shadow_inode_cachep)
		return -ENOMEM;

	shadow_mgr_cachep = kmem_cache_create("shadow_mgr_cache",
						sizeof(struct shadow_pm_manager),
						0,
						(SLAB_RECLAIM_ACCOUNT|
						 SLAB_MEM_SPREAD),
						shadow_mgr_ctor);
	if (!shadow_mgr_cachep)
		return -ENOMEM;

	err = ph_cache_init();
	if (err)
		return err;

	err = rng_cache_init();
	if (err)
		return err;

	/*err = shadow_page_init();
	if (err)
		return err;*/

	shadow_sysfs_init();
	register_filesystem(&shadow_fs_type);

	return err;
}

static void __exit shadow_fs_exit(void)
{
	shadow_sysfs_exit();
	//shadow_page_exit();
	ph_cache_exit();
	rng_cache_exit();
	kmem_cache_destroy(shadow_inode_cachep);
	kmem_cache_destroy(shadow_mgr_cachep);
	unregister_filesystem(&shadow_fs_type);
	pr_info("shadowfs exited\n");
}

module_init(shadow_fs_init);
module_exit(shadow_fs_exit);
