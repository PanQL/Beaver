#include <linux/pagevec.h>
#include <linux/swap.h>
#include <linux/list.h>

#include "shadow_entry.h"

static bool syncup_holder(struct shadow_sb_info *sbi,
				struct shadow_page_holder *holder,
				struct list_head *freeing)
{
	struct page *dram_page, *cur_page;
	void *new_read_ptr;
	u64 new_read_ptr_val;
	uint64_t l_pending_wr=0, l_finished_wr=0;

	spin_lock(&holder->lock);
	if (holder->state == FREEING) {
		list_move(&holder->syncup, freeing);
		goto skip;
	}

	cur_page = holder->pmem_pages[holder->cur];
	if (holder->read_ptr != page_address(cur_page))
		goto skip;

	if (holder->dram_page)
		new_read_ptr = page_address(holder->dram_page);
	else {
		dram_page = alloc_pages(GFP_KERNEL, 0);
		dram_page->mapping = cur_page->mapping;

		attach_page_private(dram_page, holder);
		put_page(dram_page);
		folio_add_lru(page_folio(dram_page));
		__mod_lruvec_page_state(dram_page, NR_FILE_PAGES, 1);

		holder->dram_page = dram_page;
		new_read_ptr = page_address(dram_page);
	}

	/*l_pending_wr = atomic64_read(&sbi->pending_wr);
	l_finished_wr = atomic64_read(&sbi->finished_wr);
	if (l_pending_wr > l_finished_wr)
		goto accomedated;*/

	mark_page_accessed(holder->dram_page);
	memcpy_flushcache(new_read_ptr, page_address(cur_page), PAGE_SIZE);
	new_read_ptr_val = (u64)new_read_ptr | 1ULL;
	rcu_assign_pointer(holder->read_ptr, new_read_ptr_val);
	holder->state = INIT;
	SHADOW_STATS_ADD(synced_up, 4096);

skip:
	spin_unlock(&holder->lock);
	return true;
accomedated:
	spin_unlock(&holder->lock);
	return false;
}

static int shadow_syncup_thread(void *arg)
{
	struct syncup_task_arg *s_arg = arg;
	struct shadow_sb_info *sbi = s_arg->sbi;
	struct syncup_list *s_list = &s_arg->s_list;
	struct syncup_list *freeing = s_arg->freeing;
	unsigned long next_wakeup, cur;
	struct list_head head, to_free, accomedated;
	struct shadow_page_holder *holder;
	struct list_head *tmp;

	INIT_LIST_HEAD(&head);
	INIT_LIST_HEAD(&to_free);
	INIT_LIST_HEAD(&accomedated);
	pr_info("%s: started\n", __func__);

	while (true) {
		spin_lock(&s_list->lock);
		list_splice_tail_init(&s_list->head, &head);
		if (list_empty(&head))
			s_list->sleeping = 1;
		spin_unlock(&s_list->lock);

		if (list_empty(&head))
			goto sleep;

		tmp = head.next;
		do {
			holder = container_of(tmp, struct shadow_page_holder, syncup);
			tmp = tmp->next;
			list_del_init(&holder->syncup);
			if (!syncup_holder(sbi, holder, &to_free))
				list_add_tail(&holder->syncup, &accomedated);
		} while (tmp != &head);

		continue;
sleep:
		spin_lock(&freeing->lock);
		list_splice_tail_init(&to_free, &freeing->head);
		spin_unlock(&freeing->lock);
		/*pr_info("%s: fall sleep\n", __func__);*/
		next_wakeup = jiffies + prandom_u32_max(1 * HZ);
		cur = jiffies;
		schedule_timeout_interruptible(next_wakeup - cur);

		if (kthread_should_stop())
			break;
	}

	pr_info("%s: end\n", __func__);

	return 0;
}

int init_sb_info_syncup(struct shadow_sb_info *sb_info)
{
	unsigned int i;
	struct task_struct *task;
	int err = 0;

	INIT_LIST_HEAD(&sb_info->freeing.head);
	spin_lock_init(&sb_info->freeing.lock);

	for (i = 0; i < SYNCUP_LIST_NUM; ++i) {
		sb_info->syncup_args[i].sbi = sb_info;
		INIT_LIST_HEAD(&sb_info->syncup_args[i].s_list.head);
		spin_lock_init(&sb_info->syncup_args[i].s_list.lock);
		sb_info->syncup_args[i].s_list.sleeping = 0;
		sb_info->syncup_args[i].freeing = &sb_info->freeing;
	}

	for (i = 0; i < SYNCUP_LIST_NUM; ++i) {
//#ifdef CONFIG_SHADOW_FS_MODULE
		task = kthread_run_on_cpu(shadow_syncup_thread,
					  &sb_info->syncup_args[i],
					  23 - i,
					  "sdw_syncup");
/*#else
		task = kthread_run(shadow_syncup_thread,
					  &sb_info->syncup_args[i],
					  "sdw_syncup");
#endif*/
		if (IS_ERR(task)) {
			err = PTR_ERR(task);
			break;
		}
		sb_info->syncup_task[i] = task;
		sb_info->syncup_args[i].s_list.task = task;
	}

	if (err)
		for (--i; i >= 0; --i)
			kthread_stop(sb_info->syncup_task[i]);

	return err;
}

void destroy_sb_info_syncup(struct shadow_sb_info *sb_info)
{
	unsigned int i;
	struct syncup_list *freeing = &sb_info->freeing;
	struct pagevec pvec;

	pagevec_init(&pvec);

	for (i = 0; i < SYNCUP_LIST_NUM; ++i) {
		if (!sb_info->syncup_task[i])
			continue;

		kthread_stop(sb_info->syncup_task[i]);
	}

	//splice all syncup_lists into freeing list
	for (i = 0; i < SYNCUP_LIST_NUM; ++i) {
		struct syncup_task_arg *args = &sb_info->syncup_args[i];

		list_splice_init(&args->s_list.head, &freeing->head);
	}
	
	clean_freeing_holders(freeing, sb_info->mgr);
}

inline void shadow_release_pagevec(struct pagevec *pvec)
{
	unsigned int i;

	for (i = 0; i < pagevec_count(pvec); ++i) {
		struct page *page = pvec->pages[i];

		lock_page(page);
		if (PagePrivate(page))
			detach_page_private(page);
		page->mapping = NULL;
		unlock_page(page);
	}
	__mod_lruvec_page_state(pvec->pages[0],
			NR_FILE_PAGES, -pagevec_count(pvec));
	release_pages(pvec->pages, pagevec_count(pvec));
}

static void release_pmem_pages(struct shadow_page_holder *holder,
				struct shadow_pm_manager *mgr)
{
	if (holder->pmem_pages[0])
		pmem_page_free(holder->pmem_pages[0], mgr);
	holder->pmem_pages[0] = NULL;
	if (holder->pmem_pages[1])
		pmem_page_free(holder->pmem_pages[1], mgr);
	holder->pmem_pages[1] = NULL;
}

void clean_freeing_holders(struct syncup_list *freeing, struct shadow_pm_manager *mgr)
{
	struct shadow_page_holder *holder, *next;
	struct list_head temp;
	struct pagevec pvec;
	INIT_LIST_HEAD(&temp);
	pagevec_init(&pvec);

	spin_lock(&freeing->lock);
	list_splice_tail_init(&freeing->head, &temp);
	spin_unlock(&freeing->lock);

	if (list_empty(&temp))
		return;

	list_for_each_entry_safe(holder, next, &temp, syncup) {
		// lock holder
		spin_lock(&holder->lock);
		// if dram_page == NULL or has not added into lru list, release holder directly.
		if (!holder->dram_page || !PagePrivate(holder->dram_page)) {
			if (holder->dram_page) {
				__free_pages(holder->dram_page, 0);
				holder->dram_page = NULL;
			}
			list_del_init(&holder->syncup);
			spin_unlock(&holder->lock);
			release_pmem_pages(holder, mgr);
			holder_free(holder);
			continue;
		}

		get_page(holder->dram_page);
		spin_unlock(&holder->lock);
		if (!pagevec_add(&pvec, holder->dram_page)) {
			shadow_release_pagevec(&pvec);
			pagevec_reinit(&pvec);
		}
	}

	if (pagevec_count(&pvec)) {
		shadow_release_pagevec(&pvec);
		pagevec_reinit(&pvec);
	}

	list_for_each_entry_safe(holder, next, &temp, syncup) {
		list_del_init(&holder->syncup);
		release_pmem_pages(holder, mgr);
		holder_free(holder);
	}
}

