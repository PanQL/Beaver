#include "shadow_entry.h"

const struct cred *shadow_override_creds(struct super_block *sb)
{
	struct shadow_sb_info *info = sb->s_fs_info;

	return override_creds(info->creator_cred);
}

void shadow_sb_info_destroy(struct shadow_sb_info *sb_info)
{
	if (!sb_info)
		return;

	if (sb_info->mgr)
		pmem_mgr_release(sb_info->mgr, sb_info);

	if (sb_info->real_mnt)
		kern_unmount(sb_info->real_mnt);

	/*if (sb_info->real_fs_type)*/
		/*module_put(sb_info->real_fs_type->owner);*/

	if (sb_info->creator_cred)
		put_cred(sb_info->creator_cred);

	kfree(sb_info);
}


