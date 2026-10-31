// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/topology.h>
#include <linux/version.h>
#include <linux/cred.h>		/* current_uid */
#include <linux/mutex.h>
#include <linux/sched/task.h>	/* get_task_struct / put_task_struct */
#include <linux/pid.h>		/* find_vpid / pid_task */
#include <trace/hooks/sched.h>


#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) || defined(APPOPT_SETAFF_BOOL)
typedef bool appopt_skip_t;
#else
typedef int appopt_skip_t;
#endif

/* available_idle_cpu 在 GKI KMI 里导出(OPLUS sched_assist 亦用之),但无公共头声明,自行 extern。 */
extern int available_idle_cpu(int cpu);

#define APPOPT_PROC_DIR   "sched_opt"
#define MAX_TASKS         32
#define MAX_CLUSTERS      8

static int skip_self_setaffinity;

/*
 * 管理进程 tgid(AppOpt 守护进程,经 /proc/sched_opt/manager_pid 登记)。
 * skip_self 拦截时【放行】tgid 命中它的调用 —— AppOpt 才是设核的人,开 bit2(拦全部)
 * 也不能把它自己的 sched_setaffinity 一起拦掉。0=未登记(不豁免任何人)。
 */
static int manager_tgid;

/*
 * 各 vendor hook 的注册结果,供 /proc/sched_opt/hooks 显示(web 端读取):
 *   0  = 成功
 *   <0 = 注册失败的 errno(如 -16=-EBUSY:该 RVH 已被 OEM 调度器占用,单注册被拒 -> 降级)
 *   1  = 编译期跳过(仅 check_preempt:该 KMI 无此 hook,由 -DAPPOPT_NO_PREEMPT_HOOK 关掉)
 */
static int hook_select;
static int hook_migrate;
static int hook_preempt = 1;	/* 默认"编译期跳过";#ifndef 块内会覆写为实际 ret */
static int hook_setaff;

/*
 * per-task 偏好表。tid==-1 为空槽。热路径(RVH)无锁读各标量字段(READ_ONCE),写侧持 tbl_lock。
 * 竞态最坏是一次放置用到旧值,可接受。
 */
struct appopt_slot {
	int tid;		/* -1 空槽 */
	int tgid;		/* 所属进程 tgid(登记时解析;整进程守护 bit4 用,0=未知) */
	int pipeline_cpu;	/* :p 单核贴核;-1 未设 */
	unsigned int prefer_cpu;	/* :pf 偏好核位掩码;0 未设 */
	unsigned int prefer_cluster;	/* :pcl 偏好簇位掩码;0 未设 */
	int prefer_idle;	/* :pi 0/1 */
	int prefer_preempt;	/* :pp 0/1 */
};
static struct appopt_slot tbl[MAX_TASKS];
static DEFINE_SPINLOCK(tbl_lock);

/* bit5 内核级锁:已置 PF_NO_SETAFFINITY 的 tid(-1=空);对账用。改标志有睡眠(put_task_struct)
 * 故只在进程上下文、持 pf_lock_mutex 下操作,绝不在 tbl_lock(自旋)内碰。 */
static int pf_locked[MAX_TASKS];
static DEFINE_MUTEX(pf_lock_mutex);

/* 簇 -> 核位掩码(init 时按拓扑构建),供 prefer_cluster 展开。 */
static unsigned int cluster_cpumask[MAX_CLUSTERS];
static int ncluster;

static struct proc_dir_entry *appopt_dir;

/*
 * 硬亲和(:ph):直接把 cpus_allowed 锁到目标核集(set_cpus_allowed_ptr),不挂任何 hook——
 * 所有调度类(CFS 与 sched_ext/风驰)都必须遵守,任何机型都钉得住,不受 RVH 单注册约束。
 * 仅进程上下文操作(set_cpus_allowed_ptr 会睡),用 hard_mutex;与上面的软偏好表独立。
 * 写新掩码/清除时先恢复原亲和再释放 ref。app 若自己 set_affinity 会覆盖 -> 配 skip_self_setaffinity。
 */
static int hard_tid[MAX_TASKS];
static unsigned int hard_mask[MAX_TASKS];	/* 已施加的核掩码(供回显);0=未用 */
static struct task_struct *hard_task[MAX_TASKS];
static struct cpumask hard_orig[MAX_TASKS];	/* 钉前原亲和,解除时恢复 */
static DEFINE_MUTEX(hard_mutex);

/* ---- 表操作(均须持 tbl_lock) ---- */

static inline unsigned int cpu_mask_lim(void)
{
	return nr_cpu_ids >= 32 ? ~0u : ((1u << nr_cpu_ids) - 1);
}

static struct appopt_slot *slot_find(int tid)
{
	int i;

	for (i = 0; i < MAX_TASKS; i++)
		if (READ_ONCE(tbl[i].tid) == tid)	/* 热路径无锁读 */
			return &tbl[i];
	return NULL;
}

/* 整进程守护:tgid 是否属于"含任一已登记线程"的进程(无锁读)。 */
static bool tgid_is_guarded(int tgid)
{
	int i;

	if (tgid <= 0)
		return false;
	for (i = 0; i < MAX_TASKS; i++)
		if (READ_ONCE(tbl[i].tid) != -1 && READ_ONCE(tbl[i].tgid) == tgid)
			return true;
	return false;
}

/* bit5:给单个 tid 置/清 PF_NO_SETAFFINITY(进程上下文;get/put 引用防 UAF)。 */
static void pf_set_tid(int tid, bool on)
{
	struct task_struct *t;

	if (tid <= 0)
		return;
	rcu_read_lock();
	t = pid_task(find_vpid(tid), PIDTYPE_PID);
	if (t)
		get_task_struct(t);
	rcu_read_unlock();
	if (!t)
		return;
	if (on)
		t->flags |= PF_NO_SETAFFINITY;
	else
		t->flags &= ~PF_NO_SETAFFINITY;
	put_task_struct(t);
}

/*
 * 对账 PF_NO_SETAFFINITY(bit5):开→已登记(tbl)线程全置;关→已置的全清;线程注销→清。
 * 在每次表变动 / 模式变动(pipeline_write / prop_write / skipaff_write)后于进程上下文调用。
 * 只管 tbl(软偏好)登记的线程;:ph 线程在 hard 表、靠 cpus_allowed 硬锁,不重复置标志。
 */
static void reconcile_pf_lock(void)
{
	int want[MAX_TASKS], nwant = 0, i, j;
	unsigned long flags;
	bool lock_on = (READ_ONCE(skip_self_setaffinity) & 32) != 0;

	mutex_lock(&pf_lock_mutex);

	if (lock_on) {
		spin_lock_irqsave(&tbl_lock, flags);
		for (i = 0; i < MAX_TASKS; i++)
			if (tbl[i].tid != -1)
				want[nwant++] = tbl[i].tid;
		spin_unlock_irqrestore(&tbl_lock, flags);
	}

	/* 清除:已锁但不再需要(bit5 关,或线程已注销) */
	for (i = 0; i < MAX_TASKS; i++) {
		bool keep = false;

		if (pf_locked[i] == -1)
			continue;
		for (j = 0; j < nwant; j++)
			if (want[j] == pf_locked[i]) {
				keep = true;
				break;
			}
		if (!keep) {
			pf_set_tid(pf_locked[i], false);
			pf_locked[i] = -1;
		}
	}

	/* 施加:需要但尚未锁 */
	for (j = 0; j < nwant; j++) {
		bool have = false;

		for (i = 0; i < MAX_TASKS; i++)
			if (pf_locked[i] == want[j]) {
				have = true;
				break;
			}
		if (have)
			continue;
		pf_set_tid(want[j], true);
		for (i = 0; i < MAX_TASKS; i++)
			if (pf_locked[i] == -1) {
				pf_locked[i] = want[j];
				break;
			}
	}

	mutex_unlock(&pf_lock_mutex);
}

/* 找到 tid 的槽;没有则占一个空槽并初始化。表满返回 NULL。 */
static struct appopt_slot *slot_get(int tid)
{
	struct appopt_slot *s = slot_find(tid);
	int i;

	if (s)
		return s;
	for (i = 0; i < MAX_TASKS; i++) {
		if (tbl[i].tid == -1) {
			tbl[i].pipeline_cpu = -1;
			tbl[i].prefer_cpu = 0;
			tbl[i].prefer_cluster = 0;
			tbl[i].prefer_idle = 0;
			tbl[i].prefer_preempt = 0;
			/* 解析 tgid(供整进程守护):tid 为 AppOpt(root ns)写入的全局 pid */
			{
				struct task_struct *t;
				int tg = 0;

				rcu_read_lock();
				t = pid_task(find_vpid(tid), PIDTYPE_PID);
				if (t)
					tg = t->tgid;
				rcu_read_unlock();
				tbl[i].tgid = tg;
			}
			WRITE_ONCE(tbl[i].tid, tid);
			return &tbl[i];
		}
	}
	return NULL;
}

/* 若一个槽所有偏好都为空,则释放(tid=-1)。 */
static void slot_gc(struct appopt_slot *s)
{
	if (s->pipeline_cpu < 0 && !s->prefer_cpu && !s->prefer_cluster &&
	    !s->prefer_idle && !s->prefer_preempt)
		WRITE_ONCE(s->tid, -1);
}

/* prefer_cluster 位掩码 -> 核位掩码 */
static unsigned int expand_cluster(unsigned int clmask)
{
	unsigned int m = 0;
	int cl;

	for (cl = 0; cl < ncluster; cl++)
		if (clmask & (1u << cl))
			m |= cluster_cpumask[cl];
	return m;
}

/* 计算某槽的"偏好核集"(cpu 位掩码);无任何核偏好则返回 0。优先级 prefer_cpu > prefer_cluster > pipeline_cpu。 */
static unsigned int slot_pref_mask(struct appopt_slot *s)
{
	unsigned int pc = READ_ONCE(s->prefer_cpu);
	unsigned int pcl = READ_ONCE(s->prefer_cluster);
	int pcpu = READ_ONCE(s->pipeline_cpu);

	if (pc)
		return pc;
	if (pcl)
		return expand_cluster(pcl);
	if (pcpu >= 0 && pcpu < nr_cpu_ids)
		return 1u << pcpu;
	return 0;
}

/* ---- RVH 回调 ---- */

/* 选核:在(偏好集 & 允许集 & 在线)里挑核;prefer_idle 优先空闲,否则取最高核(贴大核)。 */
static void appopt_rvh_select_task_rq_fair(void *unused, struct task_struct *p,
					   int prev_cpu, int sd_flag,
					   int wake_flags, int *new_cpu)
{
	struct appopt_slot *s;
	unsigned int pref;
	int cpu, best = -1, idle = 0;

	if (unlikely(!p) || p->pid <= 0)
		return;
	s = slot_find(p->pid);
	if (!s)
		return;

	pref = slot_pref_mask(s);
	idle = READ_ONCE(s->prefer_idle);
	if (!pref && !idle)
		return;		/* 没核偏好也不要空闲核 -> 不干预 */

	/* prefer_idle:在候选集里找空闲核 */
	if (idle) {
		for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
			if (pref && !(pref & (1u << cpu)))
				continue;
			if (!cpu_online(cpu) || !cpumask_test_cpu(cpu, p->cpus_ptr))
				continue;
			if (available_idle_cpu(cpu)) {
				best = cpu;
				break;
			}
		}
	}
	/* 没找到空闲核(或不要空闲):有核偏好则取候选集里最高核 */
	if (best < 0 && pref) {
		for (cpu = nr_cpu_ids - 1; cpu >= 0; cpu--) {
			if (!(pref & (1u << cpu)))
				continue;
			if (cpu_online(cpu) && cpumask_test_cpu(cpu, p->cpus_ptr)) {
				best = cpu;
				break;
			}
		}
	}
	if (best >= 0)
		*new_cpu = best;
}

/* 挡迁移:有核偏好时,不许把任务迁到偏好集之外的核。 */
static void appopt_rvh_can_migrate_task(void *unused, struct task_struct *p,
					int dst_cpu, int *can_migrate)
{
	struct appopt_slot *s;
	unsigned int pref;

	if (unlikely(!p) || p->pid <= 0)
		return;
	s = slot_find(p->pid);
	if (!s)
		return;
	pref = slot_pref_mask(s);
	if (pref && dst_cpu >= 0 && dst_cpu < nr_cpu_ids && !(pref & (1u << dst_cpu)))
		*can_migrate = 0;
}

/*
 * 抢占:prefer_preempt 任务唤醒时抢占当前。
 * 注意:android_rvh_check_preempt_wakeup 在 6.12 起被【整个删除】——由 workflow 对该 KMI 传
 * -DAPPOPT_NO_PREEMPT_HOOK 跳过本 hook(此时 :pp 在该机 ko 上 no-op;HMBIRD II 机型走原生)。
 */
#ifndef APPOPT_NO_PREEMPT_HOOK
/*
 * android_rvh_check_preempt_wakeup 末参 `unsigned int granularity` 跨版本被删:
 *   有(10参):5.10 / android13-5.15 / android14-6.1;
 *   无(9参):6.6+(EEVDF)、以及 android14-5.15(回退,同 5.15 但去了 gran)。
 * 6.6+ 按 LINUX_VERSION_CODE 自动判;android14-5.15 这种 <6.6 却已删的,由 workflow 传
 * -DAPPOPT_PREEMPT_NO_GRAN 指定。body 不使用 granularity/next_buddy_marked,两种签名共用。
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) || defined(APPOPT_PREEMPT_NO_GRAN)
static void appopt_rvh_check_preempt_wakeup(void *unused, struct rq *rq,
					    struct task_struct *p, bool *preempt,
					    bool *nopreempt, int wake_flags,
					    struct sched_entity *se,
					    struct sched_entity *pse,
					    int next_buddy_marked)
#else
static void appopt_rvh_check_preempt_wakeup(void *unused, struct rq *rq,
					    struct task_struct *p, bool *preempt,
					    bool *nopreempt, int wake_flags,
					    struct sched_entity *se,
					    struct sched_entity *pse,
					    int next_buddy_marked,
					    unsigned int granularity)
#endif
{
	struct appopt_slot *s;

	if (unlikely(!p) || p->pid <= 0)
		return;
	s = slot_find(p->pid);
	if (s && READ_ONCE(s->prefer_preempt))
		*preempt = true;
}
#endif /* APPOPT_NO_PREEMPT_HOOK */

/*
 * skip_self_setaffinity:app 自己改自己(已登记线程)的亲和时跳过,防止覆盖我们的偏好。
 * 只拦"同进程自改"(current->tgid == p->tgid);外部 root/appopt 改亲和照常生效。
 */
/* Android 应用 uid 区间(每用户偏移 PER_USER_RANGE) */
#define APPOPT_PER_USER_RANGE   100000
#define APPOPT_FIRST_APP_UID    10000
#define APPOPT_LAST_APP_UID     19999

static bool caller_is_app(void)
{
	int uid = current_uid().val % APPOPT_PER_USER_RANGE;

	return uid >= APPOPT_FIRST_APP_UID && uid <= APPOPT_LAST_APP_UID;
}

static void appopt_vh_sched_setaffinity_early(void *unused, struct task_struct *p,
					      const struct cpumask *new_mask,
					      appopt_skip_t *retval)
{
	int mode = READ_ONCE(skip_self_setaffinity);
	bool block = false;

	if (!mode)			/* 全 0 才完全不管;仅 debug(bit1) 也要进来打印 */
		return;
	if (unlikely(!p) || p->pid <= 0)
		return;
	/* 保护范围:已登记线程;开 bit4(整进程守护)时扩到"含任一已登记线程的整个进程"
	 * (未单独登记的兄弟线程也保护) */
	if (!slot_find(p->pid) &&
	    !((mode & 16) && tgid_is_guarded(p->tgid)))
		return;

	/* 放行管理进程(AppOpt)自身:它就是设核的人,开 bit2 也不能把它一起拦了 */
	if (READ_ONCE(manager_tgid) > 0 && current->tgid == READ_ONCE(manager_tgid)) {
		if (mode & 2)
			pr_info("appopt_sched: setaffinity tid=%d(%s) by MANAGER pid=%d allow\n",
				p->pid, p->comm, current->pid);
		return;
	}

	if (mode & 4)			/* bit2:拦任何调用者(含官方/appopt) */
		block = true;
	else if ((mode & 8) && caller_is_app())	/* bit3:只拦 app-uid,放行系统/官方 */
		block = true;
	else if ((mode & 1) && current->tgid == p->tgid)  /* bit0:只拦 app 自己改自己 */
		block = true;

	if (block)
		*retval = 1;		/* 置非 0 -> sched_setaffinity 提前返回,亲和不变 */

	if (mode & 2)
		pr_info("appopt_sched: setaffinity tid=%d(%s) by pid=%d(%s,tgid=%d,uid=%d) %s\n",
			p->pid, p->comm, current->pid, current->comm, current->tgid,
			current_uid().val, block ? "BLOCKED" : "allow");
}

/* ---- proc:pipeline_pids_cpus(整表重写,:p) ---- */

static ssize_t pipeline_write(struct file *file, const char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	char buf[512] = {0};
	int np[MAX_TASKS], nc[MAX_TASKS], i;
	unsigned long flags;

	if (count >= sizeof(buf))
		count = sizeof(buf) - 1;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';

	for (i = 0; i < MAX_TASKS; i++) {
		np[i] = -1;
		nc[i] = -1;
	}
	sscanf(buf,
	       "%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d "
	       "%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
	       &np[0], &nc[0], &np[1], &nc[1], &np[2], &nc[2], &np[3], &nc[3],
	       &np[4], &nc[4], &np[5], &nc[5], &np[6], &nc[6], &np[7], &nc[7],
	       &np[8], &nc[8], &np[9], &nc[9], &np[10], &nc[10], &np[11], &nc[11],
	       &np[12], &nc[12], &np[13], &nc[13], &np[14], &nc[14], &np[15], &nc[15]);

	spin_lock_irqsave(&tbl_lock, flags);
	/* 先清掉所有旧的 pipeline_cpu(整表重写语义),保留其它偏好 */
	for (i = 0; i < MAX_TASKS; i++) {
		if (tbl[i].tid != -1 && tbl[i].pipeline_cpu >= 0) {
			tbl[i].pipeline_cpu = -1;
			slot_gc(&tbl[i]);
		}
	}
	/* 再写新表 */
	for (i = 0; i < MAX_TASKS; i++) {
		struct appopt_slot *s;

		if (np[i] <= 0)
			continue;
		s = slot_get(np[i]);
		if (!s)
			continue;
		/* 对齐 OPLUS:cpu 须 >0(拒 0);越界忽略 */
		if (nc[i] > 0 && nc[i] < nr_cpu_ids)
			WRITE_ONCE(s->pipeline_cpu, nc[i]);
	}
	spin_unlock_irqrestore(&tbl_lock, flags);
	reconcile_pf_lock();	/* bit5:整表重写后同步 PF_NO_SETAFFINITY */
	return count;
}

static int pipeline_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < MAX_TASKS; i++)
		if (tbl[i].tid != -1 && tbl[i].pipeline_cpu >= 0)
			seq_printf(m, "%d %d ", tbl[i].tid, tbl[i].pipeline_cpu);
	seq_putc(m, '\n');
	return 0;
}

/* ---- proc:通用 "tid val" 单条写入(prefer_*) ---- */

enum prop_kind { P_CPU, P_CLUSTER, P_IDLE, P_PREEMPT };

static int prop_apply(enum prop_kind kind, int tid, unsigned int val)
{
	struct appopt_slot *s;
	unsigned long flags;

	spin_lock_irqsave(&tbl_lock, flags);
	/* val==0 一律视作"清除"该偏好:不新建槽,只在已存在时清。 */
	s = (val == 0) ? slot_find(tid) : slot_get(tid);
	if (!s) {
		spin_unlock_irqrestore(&tbl_lock, flags);
		return 0;	/* 清除一个不存在的,视为成功 no-op */
	}
	switch (kind) {
	case P_CPU:
		WRITE_ONCE(s->prefer_cpu, val & cpu_mask_lim());
		break;
	case P_CLUSTER:
		WRITE_ONCE(s->prefer_cluster, val & ((1u << MAX_CLUSTERS) - 1));
		break;
	case P_IDLE:
		WRITE_ONCE(s->prefer_idle, val ? 1 : 0);
		break;
	case P_PREEMPT:
		WRITE_ONCE(s->prefer_preempt, val ? 1 : 0);
		break;
	}
	slot_gc(s);
	spin_unlock_irqrestore(&tbl_lock, flags);
	return 0;
}

static ssize_t prop_write(enum prop_kind kind, int hex,
			  const char __user *ubuf, size_t count)
{
	char buf[64] = {0};
	int tid;
	unsigned int val = 0;
	int n;

	if (count >= sizeof(buf))
		count = sizeof(buf) - 1;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';

	n = sscanf(buf, hex ? "%d %x" : "%d %u", &tid, &val);
	if (n < 1 || tid <= 0)
		return -EINVAL;
	prop_apply(kind, tid, val);
	reconcile_pf_lock();	/* bit5:表变动后同步 PF_NO_SETAFFINITY */
	return count;
}

static ssize_t prefer_cpu_write(struct file *f, const char __user *b, size_t c, loff_t *p)
{ return prop_write(P_CPU, 1, b, c); }
static ssize_t prefer_cluster_write(struct file *f, const char __user *b, size_t c, loff_t *p)
{ return prop_write(P_CLUSTER, 1, b, c); }
static ssize_t prefer_idle_write(struct file *f, const char __user *b, size_t c, loff_t *p)
{ return prop_write(P_IDLE, 0, b, c); }
static ssize_t prefer_preempt_write(struct file *f, const char __user *b, size_t c, loff_t *p)
{ return prop_write(P_PREEMPT, 0, b, c); }

static int prefer_show(struct seq_file *m, void *v)
{
	enum prop_kind kind = (enum prop_kind)(long)m->private;
	int i;

	for (i = 0; i < MAX_TASKS; i++) {
		if (tbl[i].tid == -1)
			continue;
		switch (kind) {
		case P_CPU:
			if (tbl[i].prefer_cpu)
				seq_printf(m, "%d 0x%x\n", tbl[i].tid, tbl[i].prefer_cpu);
			break;
		case P_CLUSTER:
			if (tbl[i].prefer_cluster)
				seq_printf(m, "%d 0x%x\n", tbl[i].tid, tbl[i].prefer_cluster);
			break;
		case P_IDLE:
			if (tbl[i].prefer_idle)
				seq_printf(m, "%d 1\n", tbl[i].tid);
			break;
		case P_PREEMPT:
			if (tbl[i].prefer_preempt)
				seq_printf(m, "%d 1\n", tbl[i].tid);
			break;
		}
	}
	return 0;
}

static int prefer_cpu_open(struct inode *i, struct file *f)
{ return single_open(f, prefer_show, (void *)(long)P_CPU); }
static int prefer_cluster_open(struct inode *i, struct file *f)
{ return single_open(f, prefer_show, (void *)(long)P_CLUSTER); }
static int prefer_idle_open(struct inode *i, struct file *f)
{ return single_open(f, prefer_show, (void *)(long)P_IDLE); }
static int prefer_preempt_open(struct inode *i, struct file *f)
{ return single_open(f, prefer_show, (void *)(long)P_PREEMPT); }

static int pipeline_open(struct inode *inode, struct file *file)
{ return single_open(file, pipeline_show, NULL); }

static const struct proc_ops pipeline_ops = {
	.proc_open = pipeline_open, .proc_read = seq_read,
	.proc_write = pipeline_write, .proc_lseek = seq_lseek, .proc_release = single_release,
};
static const struct proc_ops prefer_cpu_ops = {
	.proc_open = prefer_cpu_open, .proc_read = seq_read,
	.proc_write = prefer_cpu_write, .proc_lseek = seq_lseek, .proc_release = single_release,
};
static const struct proc_ops prefer_cluster_ops = {
	.proc_open = prefer_cluster_open, .proc_read = seq_read,
	.proc_write = prefer_cluster_write, .proc_lseek = seq_lseek, .proc_release = single_release,
};
static const struct proc_ops prefer_idle_ops = {
	.proc_open = prefer_idle_open, .proc_read = seq_read,
	.proc_write = prefer_idle_write, .proc_lseek = seq_lseek, .proc_release = single_release,
};
static const struct proc_ops prefer_preempt_ops = {
	.proc_open = prefer_preempt_open, .proc_read = seq_read,
	.proc_write = prefer_preempt_write, .proc_lseek = seq_lseek, .proc_release = single_release,
};

/* /proc/sched_opt/skip_self_setaffinity —— 位掩码:bit0=拦自己 bit1=debug bit2=拦所有 bit3=只拦app */
static ssize_t skipaff_write(struct file *f, const char __user *ubuf, size_t count, loff_t *ppos)
{
	char b[16] = {0};
	size_t n = count;
	int v = 0;

	if (n >= sizeof(b))
		n = sizeof(b) - 1;
	if (copy_from_user(b, ubuf, n))
		return -EFAULT;
	b[n] = '\0';
	if (sscanf(b, "%d", &v) != 1)
		return -EINVAL;
	WRITE_ONCE(skip_self_setaffinity, v);
	reconcile_pf_lock();	/* bit5:模式变动后置/清 PF_NO_SETAFFINITY */
	return count;
}
static int skipaff_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", READ_ONCE(skip_self_setaffinity));
	return 0;
}
static int skipaff_open(struct inode *i, struct file *f)
{ return single_open(f, skipaff_show, NULL); }
static const struct proc_ops skipaff_ops = {
	.proc_open = skipaff_open, .proc_read = seq_read,
	.proc_write = skipaff_write, .proc_lseek = seq_lseek, .proc_release = single_release,
};

/* ---- proc:manager_pid(AppOpt 写自己 pid,skip_self 拦截时放行它自己的 setaffinity) ---- */
static ssize_t manager_write(struct file *f, const char __user *ubuf, size_t count, loff_t *ppos)
{
	char b[16] = {0};
	size_t n = count;
	int v = 0;

	if (n >= sizeof(b))
		n = sizeof(b) - 1;
	if (copy_from_user(b, ubuf, n))
		return -EFAULT;
	b[n] = '\0';
	if (sscanf(b, "%d", &v) != 1)
		return -EINVAL;
	WRITE_ONCE(manager_tgid, v);
	return count;
}
static int manager_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", READ_ONCE(manager_tgid));
	return 0;
}
static int manager_open(struct inode *i, struct file *f)
{ return single_open(f, manager_show, NULL); }
static const struct proc_ops manager_ops = {
	.proc_open = manager_open, .proc_read = seq_read,
	.proc_write = manager_write, .proc_lseek = seq_lseek, .proc_release = single_release,
};

/* ---- proc:hooks(只读,各 vendor hook 注册状态,供 web 显示 ok/off/err) ---- */
static void hooks_print(struct seq_file *m, const char *name, int val)
{
	if (val == 1)
		seq_printf(m, "%s=off\n", name);	/* 编译期跳过 */
	else if (val == 0)
		seq_printf(m, "%s=ok\n", name);
	else
		seq_printf(m, "%s=err:%d\n", name, val);
}
static int hooks_show(struct seq_file *m, void *v)
{
	hooks_print(m, "select_task_rq_fair", hook_select);
	hooks_print(m, "can_migrate_task", hook_migrate);
	hooks_print(m, "check_preempt_wakeup", hook_preempt);
	hooks_print(m, "sched_setaffinity_early", hook_setaff);
	return 0;
}
static int hooks_open(struct inode *i, struct file *f)
{ return single_open(f, hooks_show, NULL); }
static const struct proc_ops hooks_ops = {
	.proc_open = hooks_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
};

/* ---- proc:hard_affinity(:ph 硬亲和,set_cpus_allowed_ptr) ---- */

static void hard_unpin_idx(int i)	/* 持 hard_mutex */
{
	if (hard_task[i]) {
		set_cpus_allowed_ptr(hard_task[i], &hard_orig[i]);	/* 恢复原亲和 */
		put_task_struct(hard_task[i]);
		hard_task[i] = NULL;
	}
	hard_mask[i] = 0;
	hard_tid[i] = -1;
}

static int hard_apply(int tid, unsigned int mask)
{
	int i, slot = -1, free = -1, ret = 0, cpu;
	struct task_struct *p;
	struct cpumask want;

	mutex_lock(&hard_mutex);
	for (i = 0; i < MAX_TASKS; i++) {
		if (hard_tid[i] == tid) { slot = i; break; }
		if (free < 0 && hard_tid[i] == -1)
			free = i;
	}

	if (mask == 0) {		/* 解除 */
		if (slot >= 0)
			hard_unpin_idx(slot);
		goto out;
	}
	if (slot < 0)
		slot = free;
	if (slot < 0) { ret = -ENOSPC; goto out; }	/* 表满 */

	/* 目标掩码里在线的核 */
	cpumask_clear(&want);
	for (cpu = 0; cpu < nr_cpu_ids; cpu++)
		if ((mask & (1u << cpu)) && cpu_online(cpu))
			cpumask_set_cpu(cpu, &want);
	if (cpumask_empty(&want)) { ret = -EINVAL; goto out; }

	if (hard_tid[slot] != tid) {		/* 新占槽:取任务、存原亲和 */
		rcu_read_lock();
		p = pid_task(find_vpid(tid), PIDTYPE_PID);
		if (p)
			get_task_struct(p);
		rcu_read_unlock();
		if (!p) { ret = -ESRCH; goto out; }
		hard_task[slot] = p;
		cpumask_copy(&hard_orig[slot], p->cpus_ptr);
		hard_tid[slot] = tid;
	}
	ret = set_cpus_allowed_ptr(hard_task[slot], &want);
	if (ret) {
		pr_warn("sched_opt: hard pin tid %d mask 0x%x failed: %d\n", tid, mask, ret);
		if (hard_tid[slot] == tid && hard_mask[slot] == 0)	/* 首次就失败 -> 回收槽 */
			hard_unpin_idx(slot);
	} else {
		hard_mask[slot] = mask;
	}
out:
	mutex_unlock(&hard_mutex);
	return ret;
}

static ssize_t hard_write(struct file *f, const char __user *ubuf, size_t count, loff_t *ppos)
{
	char b[64] = {0};
	unsigned int mask = 0;
	int tid, n;
	size_t k = count;

	if (k >= sizeof(b))
		k = sizeof(b) - 1;
	if (copy_from_user(b, ubuf, k))
		return -EFAULT;
	b[k] = '\0';
	n = sscanf(b, "%d %x", &tid, &mask);	/* 掩码 hex;缺省=0=解除 */
	if (n < 1 || tid <= 0)
		return -EINVAL;
	hard_apply(tid, mask);
	return count;
}

static int hard_show(struct seq_file *m, void *v)
{
	int i;

	mutex_lock(&hard_mutex);
	for (i = 0; i < MAX_TASKS; i++)
		if (hard_tid[i] != -1)
			seq_printf(m, "%d 0x%x\n", hard_tid[i], hard_mask[i]);
	mutex_unlock(&hard_mutex);
	return 0;
}

static int hard_open(struct inode *i, struct file *f)
{ return single_open(f, hard_show, NULL); }
static const struct proc_ops hard_ops = {
	.proc_open = hard_open, .proc_read = seq_read,
	.proc_write = hard_write, .proc_lseek = seq_lseek, .proc_release = single_release,
};

static void build_clusters(void)
{
	int cpu, cl;

	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		cl = topology_physical_package_id(cpu);
		if (cl < 0 || cl >= MAX_CLUSTERS)
			continue;
		cluster_cpumask[cl] |= 1u << cpu;
		if (cl + 1 > ncluster)
			ncluster = cl + 1;
	}
}

static int __init appopt_sched_init(void)
{
	int i, ret;

	for (i = 0; i < MAX_TASKS; i++) {
		tbl[i].tid = -1;
		hard_tid[i] = -1;
		pf_locked[i] = -1;
	}
	build_clusters();

	appopt_dir = proc_mkdir(APPOPT_PROC_DIR, NULL);
	if (!appopt_dir)
		return -ENOMEM;

	if (!proc_create("pipeline_pids_cpus", 0664, appopt_dir, &pipeline_ops)) {
		remove_proc_entry(APPOPT_PROC_DIR, NULL);
		return -ENOMEM;
	}
	proc_create("prefer_cpu", 0664, appopt_dir, &prefer_cpu_ops);
	proc_create("prefer_cluster", 0664, appopt_dir, &prefer_cluster_ops);
	proc_create("prefer_idle", 0664, appopt_dir, &prefer_idle_ops);
	proc_create("prefer_preempt", 0664, appopt_dir, &prefer_preempt_ops);
	proc_create("skip_self_setaffinity", 0664, appopt_dir, &skipaff_ops);
	proc_create("manager_pid", 0664, appopt_dir, &manager_ops);
	proc_create("hard_affinity", 0664, appopt_dir, &hard_ops);
	proc_create("hooks", 0444, appopt_dir, &hooks_ops);

	ret = register_trace_android_rvh_select_task_rq_fair(
			appopt_rvh_select_task_rq_fair, NULL);
	hook_select = ret;
	if (ret) {
		pr_err("appopt_sched: reg select_task_rq_fair failed: %d\n", ret);
		remove_proc_subtree(APPOPT_PROC_DIR, NULL);	/* 连子节点一起删 */
		return ret;
	}
	ret = register_trace_android_rvh_can_migrate_task(
			appopt_rvh_can_migrate_task, NULL);
	hook_migrate = ret;
	if (ret)
		pr_warn("appopt_sched: reg can_migrate_task failed: %d (挡迁移失效)\n", ret);
#ifndef APPOPT_NO_PREEMPT_HOOK
	ret = register_trace_android_rvh_check_preempt_wakeup(
			appopt_rvh_check_preempt_wakeup, NULL);
	hook_preempt = ret;
	if (ret)
		pr_warn("appopt_sched: reg check_preempt_wakeup failed: %d (prefer_preempt 失效)\n", ret);
#endif
	/* VH 可多注册,不会 EBUSY,即便 OEM 也占了 setaffinity_early 也能共存 */
	ret = register_trace_android_vh_sched_setaffinity_early(
			appopt_vh_sched_setaffinity_early, NULL);
	hook_setaff = ret;
	if (ret)
		pr_warn("appopt_sched: reg sched_setaffinity_early failed: %d (skip_self_setaffinity 失效)\n", ret);

	/* RVH 不可注销 -> 钉住模块防 rmmod 后回调跳进已释放内存。停用=清空各表。 */
	__module_get(THIS_MODULE);

	pr_info("appopt_sched: loaded, %d clusters, per-task prefer(cpu/cluster/idle/preempt)+pipeline\n",
		ncluster);
	return 0;
}
module_init(appopt_sched_init);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("AppOpt generic per-task sched preferences (pipeline/prefer_cpu/cluster/idle/preempt) via GKI vendor hooks");
MODULE_AUTHOR("AppOpt");
