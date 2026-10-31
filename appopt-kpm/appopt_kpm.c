/* SPDX-License-Identifier: GPL-2.0-only */
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <common.h>
#include <asm/current.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

KPM_NAME("appopt_sched");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("AppOpt");
KPM_DESCRIPTION("AppOpt per-task sched preferences via GKI vendor hooks, KPM build");

#define logkm(fmt, ...) printk("appopt_kpm: " fmt, ##__VA_ARGS__)
#define APPOPT_MAX_TASKS 32

struct task_struct;
struct proc_dir_entry;
struct inode;
struct file;
struct tracepoint;

/* 5.6+ proc_ops(仅用 read/write)。umode_t=unsigned short。 */
struct proc_ops {
	unsigned int proc_flags;
	int (*proc_open)(struct inode *, struct file *);
	long (*proc_read)(struct file *, char __user *, unsigned long, long long *);
	long (*proc_read_iter)(void *, void *);
	long (*proc_write)(struct file *, const char __user *, unsigned long, long long *);
	long long (*proc_lseek)(struct file *, long long, int);
	int (*proc_release)(struct inode *, struct file *);
	unsigned int (*proc_poll)(struct file *, void *);
	long (*proc_ioctl)(struct file *, unsigned int, unsigned long);
	int (*proc_mmap)(struct file *, void *);
	unsigned long (*proc_get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
};

/* cpumask:超配到 1024 位;set_cpus_allowed/sched_setaffinity 只读 nr_cpu_ids 位 */
struct cpumask { unsigned long bits[16]; };

/* ---- 内核符号(kallsyms 解析)---- */
int kfunc_def(__task_pid_nr_ns)(struct task_struct *task, int type, void *ns);
int kfunc_def(available_idle_cpu)(int cpu);
long kfunc_def(sched_setaffinity)(int pid, const struct cpumask *in_mask);	/* :ph */
struct proc_dir_entry *kfunc_def(proc_mkdir)(const char *name, struct proc_dir_entry *parent);
struct proc_dir_entry *kfunc_def(proc_create_data)(const char *name, unsigned short mode,
						   struct proc_dir_entry *parent, const struct proc_ops *ops, void *data);
void kfunc_def(proc_remove)(struct proc_dir_entry *de);
struct tracepoint kvar_def(__tracepoint_android_rvh_select_task_rq_fair);
struct tracepoint kvar_def(__tracepoint_android_rvh_can_migrate_task);
struct tracepoint kvar_def(__tracepoint_android_rvh_check_preempt_wakeup);
struct tracepoint kvar_def(__tracepoint_android_vh_sched_setaffinity_early);
int kfunc_def(tracepoint_probe_register)(struct tracepoint *tp, void *probe, void *data);
int kfunc_def(tracepoint_probe_unregister)(struct tracepoint *tp, void *probe, void *data);
int kvar_def(nr_cpu_ids);
uid_t current_uid(void);

/* ---- 可调用包装 ---- */
static inline int _task_pid(struct task_struct *p)
{
	kfunc_call(__task_pid_nr_ns, p, 0 /*PIDTYPE_PID*/, 0);
	kfunc_not_found();
	return 0;
}
static inline int _task_tgid(struct task_struct *p)
{
	kfunc_call(__task_pid_nr_ns, p, 1 /*PIDTYPE_TGID*/, 0);
	kfunc_not_found();
	return 0;
}
static inline long _sched_setaffinity(int pid, const struct cpumask *m)
{
	kfunc_call(sched_setaffinity, pid, m);
	kfunc_not_found();
	return -EFAULT;
}
static inline int _idle_cpu(int cpu)
{
	kfunc_call(available_idle_cpu, cpu);
	kfunc_not_found();
	return 0;
}
static inline struct proc_dir_entry *_proc_mkdir(const char *name, struct proc_dir_entry *parent)
{
	kfunc_call(proc_mkdir, name, parent);
	kfunc_not_found();
	return 0;
}
static inline struct proc_dir_entry *_proc_create(const char *name, unsigned short mode,
						  struct proc_dir_entry *parent, const struct proc_ops *ops)
{
	kfunc_call(proc_create_data, name, mode, parent, ops, 0);
	kfunc_not_found();
	return 0;
}
static inline void _proc_remove(struct proc_dir_entry *de) { kfunc_call_void(proc_remove, de); }
static inline int _tp_register(struct tracepoint *tp, void *probe)
{
	kfunc_call(tracepoint_probe_register, tp, probe, 0);
	kfunc_not_found();
	return -EFAULT;
}
static inline int _tp_unregister(struct tracepoint *tp, void *probe)
{
	kfunc_call(tracepoint_probe_unregister, tp, probe, 0);
	kfunc_not_found();
	return -EFAULT;
}
static inline int nr_cpus(void)
{
	int n = *(int *)kvar(nr_cpu_ids);
	return n > 0 ? n : 8;
}

/* ---- per-tid 偏好表(单写者 AppOpt,探针无锁读)---- */
struct appopt_slot {
	int tid;			/* 0 空 */
	int tgid;			/* 所属进程(hook 首次命中时回填;bit4 整进程守护用;0 未知) */
	int pipeline_cpu;		/* :p;-1 未设 */
	unsigned int prefer_cpu;	/* :pf 位掩码;0 未设 */
	int prefer_idle;		/* :pi 0/1 */
	int prefer_preempt;		/* :pp 0/1 */
};
static struct appopt_slot tbl[APPOPT_MAX_TASKS];
static struct proc_dir_entry *appopt_dir;
static bool reg_select, reg_migrate, reg_preempt, reg_setaff;
/* skip_self_setaffinity 位掩码(KPM v1 支持:bit1 debug / bit2 拦全部 / bit3 仅app-uid;
 * root 恒放行→AppOpt 自身不受影响。bit0/bit4/bit5 待 v2)。 */
static int skip_self_mode;
#define APPOPT_PER_USER 100000
#define APPOPT_APP_UID_LO 10000
#define APPOPT_APP_UID_HI 19999

static struct appopt_slot *slot_find(int tid)
{
	int i;

	for (i = 0; i < APPOPT_MAX_TASKS; i++)
		if (tbl[i].tid == tid)
			return &tbl[i];
	return 0;
}
static struct appopt_slot *slot_add(int tid)
{
	int i;
	struct appopt_slot *s = slot_find(tid);

	if (s)
		return s;
	for (i = 0; i < APPOPT_MAX_TASKS; i++)
		if (tbl[i].tid == 0) {
			tbl[i].tgid = 0;
			tbl[i].pipeline_cpu = -1;
			tbl[i].prefer_cpu = 0;
			tbl[i].prefer_idle = 0;
			tbl[i].prefer_preempt = 0;
			tbl[i].tid = tid;
			return &tbl[i];
		}
	return 0;
}
static void slot_gc(struct appopt_slot *s)
{
	if (s->pipeline_cpu < 0 && !s->prefer_cpu && !s->prefer_idle && !s->prefer_preempt)
		s->tid = 0;
}
/* bit4:tgid 是否属于"含任一已登记线程"的进程(tgid 由 hook 首次命中回填)。 */
static bool tgid_is_managed(int tgid)
{
	int i;

	if (tgid <= 0)
		return false;
	for (i = 0; i < APPOPT_MAX_TASKS; i++)
		if (tbl[i].tid && tbl[i].tgid == tgid)
			return true;
	return false;
}

/* 偏好核集(位掩码):prefer_cpu 优先,回落 pipeline 单核。(:pcl 待 v2) */
static unsigned int slot_pref_mask(struct appopt_slot *s)
{
	if (s->prefer_cpu)
		return s->prefer_cpu;
	if (s->pipeline_cpu >= 0 && s->pipeline_cpu < nr_cpus())
		return 1u << s->pipeline_cpu;
	return 0;
}

/* ---- RVH 探针 ---- */
static void appopt_rvh_select(void *data, struct task_struct *p, int prev_cpu, int sd_flag, int wake_flags, int *new_cpu)
{
	struct appopt_slot *s;
	unsigned int pref;
	int cpu, best = -1, maxc = nr_cpus();

	if (!p || !new_cpu)
		return;
	s = slot_find(_task_pid(p));
	if (!s)
		return;
	if (!s->tgid)
		s->tgid = _task_tgid(p);
	pref = slot_pref_mask(s);
	if (!pref && !s->prefer_idle)
		return;
	if (s->prefer_idle) {
		for (cpu = 0; cpu < maxc; cpu++) {
			if (pref && !(pref & (1u << cpu)))
				continue;
			if (_idle_cpu(cpu)) {
				best = cpu;
				break;
			}
		}
	}
	if (best < 0 && pref) {
		for (cpu = maxc - 1; cpu >= 0; cpu--)
			if (pref & (1u << cpu)) {
				best = cpu;
				break;
			}
	}
	if (best >= 0)
		*new_cpu = best;
}

static void appopt_rvh_can_migrate(void *data, struct task_struct *p, int dst_cpu, int *can_migrate)
{
	struct appopt_slot *s;
	unsigned int pref;

	if (!p || !can_migrate)
		return;
	s = slot_find(_task_pid(p));
	if (!s)
		return;
	if (!s->tgid)
		s->tgid = _task_tgid(p);
	pref = slot_pref_mask(s);
	if (pref && dst_cpu >= 0 && dst_cpu < nr_cpus() && !(pref & (1u << dst_cpu)))
		*can_migrate = 0;
}

/* check_preempt_wakeup:preempt 恒为第 4 参(x3),跨版本尾参差异不影响其位置;用 char* 单字节写。 */
static void appopt_rvh_check_preempt(void *data, void *rq, struct task_struct *p, unsigned char *preempt)
{
	struct appopt_slot *s;

	if (!p || !preempt)
		return;
	s = slot_find(_task_pid(p));
	if (!s)
		return;
	if (!s->tgid)
		s->tgid = _task_tgid(p);
	if (s->prefer_preempt)
		*preempt = 1;
}

/*
 * skip_self_setaffinity VH:拦对已登记线程的 sched_setaffinity。retval 跨版本是 int 指针
 * 或 bool 指针,用单字节写(小端下二者低字节都置 1)兼容。root 恒放行(= AppOpt 自身豁免)。
 */
static void appopt_vh_setaffinity_early(void *data, struct task_struct *p, const void *new_mask, void *retval)
{
	int mode = skip_self_mode, uid, ptid, ptgid = 0;
	struct appopt_slot *s;
	bool managed, block = false;

	if (!mode || !p || !retval)
		return;
	ptid = _task_pid(p);
	s = slot_find(ptid);
	if (s && !s->tgid)
		s->tgid = _task_tgid(p);
	managed = (s != 0);
	if (!managed && (mode & 16)) {		/* bit4 整进程守护:同进程兄弟线程 */
		ptgid = _task_tgid(p);
		if (tgid_is_managed(ptgid))
			managed = true;
	}
	if (!managed)
		return;
	uid = (int)current_uid();
	if (uid == 0)		/* 放行 root(含 AppOpt 自身) */
		return;
	if (mode & 4)		/* bit2:拦所有非 root 调用者 */
		block = true;
	else if ((mode & 8) && (uid % APPOPT_PER_USER) >= APPOPT_APP_UID_LO &&
		 (uid % APPOPT_PER_USER) <= APPOPT_APP_UID_HI)	/* bit3:仅 app-uid */
		block = true;
	else if (mode & 1) {	/* bit0:同进程自改(current tgid == p tgid) */
		if (!ptgid)
			ptgid = _task_tgid(p);
		if (_task_tgid(current) == ptgid)
			block = true;
	}
	if (block)
		*(volatile unsigned char *)retval = 1;
	if (mode & 2)
		logkm("setaffinity tid=%d uid=%d %s\n", ptid, uid, block ? "BLOCKED" : "allow");
}

/* ---- proc 读写 ---- */
static int parse_int(const char **s, bool *ok, int hex)
{
	const char *p = *s;
	int neg = 0;
	unsigned int val = 0;

	*ok = false;
	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	if (*p == '-') { neg = 1; p++; }
	if (hex && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		p += 2;
	if (!hex) {
		if (*p < '0' || *p > '9') { *s = p; return 0; }
		while (*p >= '0' && *p <= '9') { val = val * 10u + (*p - '0'); p++; }
	} else {
		int d = -1;
		if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))) { *s = p; return 0; }
		while (1) {
			char c = *p;
			if (c >= '0' && c <= '9') d = c - '0';
			else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
			else break;
			val = val * 16u + d; p++;
		}
	}
	*s = p;
	*ok = true;
	return neg ? -(int)val : (int)val;
}

static long read_buf_from_user(char *buf, int bufsz, const char __user *ubuf, unsigned long count)
{
	long lim = count < (unsigned long)bufsz ? (long)count : (long)bufsz - 1;
	long got = compat_strncpy_from_user(buf, ubuf, lim);

	if (got < 0)
		return -EFAULT;
	buf[got] = '\0';
	return got;
}

/* pipeline_pids_cpus:整表重写(只动 pipeline_cpu,保留其它偏好) */
static long pipeline_write(struct file *file, const char __user *ubuf, unsigned long count, long long *ppos)
{
	char buf[512];
	const char *sp;
	int i, np, nc, maxc = nr_cpus();
	bool ok;
	struct appopt_slot *s;

	if (read_buf_from_user(buf, sizeof(buf), ubuf, count) < 0)
		return -EFAULT;
	for (i = 0; i < APPOPT_MAX_TASKS; i++)
		if (tbl[i].tid && tbl[i].pipeline_cpu >= 0) {
			tbl[i].pipeline_cpu = -1;
			slot_gc(&tbl[i]);
		}
	sp = buf;
	while (1) {
		np = parse_int(&sp, &ok, 0);
		if (!ok) break;
		nc = parse_int(&sp, &ok, 0);
		if (!ok) break;
		if (np <= 0) continue;
		s = slot_add(np);
		if (s && nc > 0 && nc < maxc)
			s->pipeline_cpu = nc;
	}
	return count;
}

/* 单条 "tid val" 写:kind 0=prefer_cpu(hex) 1=prefer_idle 2=prefer_preempt */
static long prop_write(int kind, int hex, const char __user *ubuf, unsigned long count)
{
	char buf[64];
	const char *sp;
	int tid, val;
	bool ok;
	struct appopt_slot *s;

	if (read_buf_from_user(buf, sizeof(buf), ubuf, count) < 0)
		return -EFAULT;
	sp = buf;
	tid = parse_int(&sp, &ok, 0);
	if (!ok || tid <= 0)
		return count;
	val = parse_int(&sp, &ok, hex);
	if (!ok)
		val = 0;
	s = (val == 0) ? slot_find(tid) : slot_add(tid);
	if (!s)
		return count;
	if (kind == 0)
		s->prefer_cpu = (unsigned int)val;
	else if (kind == 1)
		s->prefer_idle = val ? 1 : 0;
	else
		s->prefer_preempt = val ? 1 : 0;
	slot_gc(s);
	return count;
}
static long prefer_cpu_write(struct file *f, const char __user *b, unsigned long c, long long *p) { return prop_write(0, 1, b, c); }
static long prefer_idle_write(struct file *f, const char __user *b, unsigned long c, long long *p) { return prop_write(1, 0, b, c); }
static long prefer_preempt_write(struct file *f, const char __user *b, unsigned long c, long long *p) { return prop_write(2, 0, b, c); }

/* :ph 硬亲和:写 "<tid> <maskhex>";mask=0 释放(设全核)。经 sched_setaffinity(内部 find+ref+设)。 */
static long hard_write(struct file *f, const char __user *b, unsigned long c, long long *p)
{
	char buf[64];
	const char *sp = buf;
	int tid, i, n;
	unsigned int mask;
	bool ok;
	struct cpumask cm;

	if (read_buf_from_user(buf, sizeof(buf), b, c) < 0)
		return -EFAULT;
	tid = parse_int(&sp, &ok, 0);
	if (!ok || tid <= 0)
		return c;
	mask = (unsigned int)parse_int(&sp, &ok, 1);
	if (!ok)
		mask = 0;
	for (i = 0; i < 16; i++)
		cm.bits[i] = 0;
	if (mask) {
		cm.bits[0] = mask;
	} else {
		n = nr_cpus();
		cm.bits[0] = (n >= 64) ? ~0UL : ((1UL << n) - 1);	/* 释放=全核 */
	}
	_sched_setaffinity(tid, &cm);
	return c;
}

static long pipeline_read(struct file *file, char __user *ubuf, unsigned long count, long long *ppos)
{
	char buf[512];
	int len = 0, i;

	if (*ppos > 0)
		return 0;
	for (i = 0; i < APPOPT_MAX_TASKS && len < (int)sizeof(buf) - 24; i++)
		if (tbl[i].tid > 0 && tbl[i].pipeline_cpu >= 0)
			len += snprintf(buf + len, sizeof(buf) - len, "%d %d ", tbl[i].tid, tbl[i].pipeline_cpu);
	if (len < (int)sizeof(buf))
		buf[len++] = '\n';
	if ((unsigned long)len > count)
		len = count;
	if (compat_copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

static long skipself_write(struct file *f, const char __user *b, unsigned long c, long long *p)
{
	char buf[32];
	const char *sp = buf;
	int v;
	bool ok;

	if (read_buf_from_user(buf, sizeof(buf), b, c) < 0)
		return -EFAULT;
	v = parse_int(&sp, &ok, 0);
	skip_self_mode = ok ? (v & 0x1f) : 0;	/* bit0..bit4(bit5 PF_NO_SETAFFINITY 待 .ko) */
	return c;
}
static long skipself_read(struct file *f, char __user *ubuf, unsigned long count, long long *ppos)
{
	char buf[16];
	int len;

	if (*ppos > 0)
		return 0;
	len = snprintf(buf, sizeof(buf), "%d\n", skip_self_mode);
	if ((unsigned long)len > count)
		len = count;
	if (compat_copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos += len;
	return len;
}
static long hooks_read(struct file *f, char __user *ubuf, unsigned long count, long long *ppos)
{
	char buf[256];
	int len;

	if (*ppos > 0)
		return 0;
	len = snprintf(buf, sizeof(buf),
		       "select_task_rq_fair=%s\ncan_migrate_task=%s\ncheck_preempt_wakeup=%s\nsched_setaffinity_early=%s\n",
		       reg_select ? "ok" : "off", reg_migrate ? "ok" : "off",
		       reg_preempt ? "ok" : "off", reg_setaff ? "ok" : "off");
	if ((unsigned long)len > count)
		len = count;
	if (compat_copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

static const struct proc_ops pipeline_ops = { .proc_read = pipeline_read, .proc_write = pipeline_write };
static const struct proc_ops prefer_cpu_ops = { .proc_write = prefer_cpu_write };
static const struct proc_ops prefer_idle_ops = { .proc_write = prefer_idle_write };
static const struct proc_ops prefer_preempt_ops = { .proc_write = prefer_preempt_write };
static const struct proc_ops hard_ops = { .proc_write = hard_write };
static const struct proc_ops skipself_ops = { .proc_read = skipself_read, .proc_write = skipself_write };
static const struct proc_ops hooks_ops = { .proc_read = hooks_read };

static long appopt_kpm_init(const char *args, const char *event, void *__user reserved)
{
	int i;

	logkm("init(M3), event: %s, args: %s\n", event, args);

	kfunc_lookup_name(__task_pid_nr_ns);
	kfunc_lookup_name(available_idle_cpu);
	kfunc_lookup_name(sched_setaffinity);
	kvar_lookup_name(nr_cpu_ids);
	kfunc_lookup_name(proc_mkdir);
	kfunc_lookup_name(proc_create_data);
	kfunc_lookup_name(proc_remove);
	kfunc_lookup_name(tracepoint_probe_register);
	kfunc_lookup_name(tracepoint_probe_unregister);
	kvar_lookup_name(__tracepoint_android_rvh_select_task_rq_fair);
	kvar_lookup_name(__tracepoint_android_rvh_can_migrate_task);
	kvar_lookup_name(__tracepoint_android_rvh_check_preempt_wakeup);
	kvar_lookup_name(__tracepoint_android_vh_sched_setaffinity_early);

	for (i = 0; i < APPOPT_MAX_TASKS; i++)
		tbl[i].tid = 0;

	appopt_dir = _proc_mkdir("sched_opt", 0);
	if (!appopt_dir) {
		logkm("proc_mkdir sched_opt failed\n");
		return -ENOMEM;
	}
	_proc_create("pipeline_pids_cpus", 0664, appopt_dir, &pipeline_ops);
	_proc_create("prefer_cpu", 0664, appopt_dir, &prefer_cpu_ops);
	_proc_create("prefer_idle", 0664, appopt_dir, &prefer_idle_ops);
	_proc_create("prefer_preempt", 0664, appopt_dir, &prefer_preempt_ops);
	_proc_create("hard_affinity", 0664, appopt_dir, &hard_ops);
	_proc_create("skip_self_setaffinity", 0664, appopt_dir, &skipself_ops);
	_proc_create("hooks", 0444, appopt_dir, &hooks_ops);

	if (kvar(__tracepoint_android_rvh_select_task_rq_fair))
		reg_select = (_tp_register(kvar(__tracepoint_android_rvh_select_task_rq_fair), appopt_rvh_select) == 0);
	if (kvar(__tracepoint_android_rvh_can_migrate_task))
		reg_migrate = (_tp_register(kvar(__tracepoint_android_rvh_can_migrate_task), appopt_rvh_can_migrate) == 0);
	if (kvar(__tracepoint_android_rvh_check_preempt_wakeup))
		reg_preempt = (_tp_register(kvar(__tracepoint_android_rvh_check_preempt_wakeup), appopt_rvh_check_preempt) == 0);
	if (kvar(__tracepoint_android_vh_sched_setaffinity_early))
		reg_setaff = (_tp_register(kvar(__tracepoint_android_vh_sched_setaffinity_early), appopt_vh_setaffinity_early) == 0);

	logkm("loaded: select=%d migrate=%d preempt=%d setaff=%d, %d cpus\n",
	      reg_select, reg_migrate, reg_preempt, reg_setaff, nr_cpus());
	return 0;
}

static long appopt_kpm_control0(const char *args, char *__user out_msg, int outlen) { return 0; }

static long appopt_kpm_exit(void *__user reserved)
{
	if (reg_select)
		_tp_unregister(kvar(__tracepoint_android_rvh_select_task_rq_fair), appopt_rvh_select);
	if (reg_migrate)
		_tp_unregister(kvar(__tracepoint_android_rvh_can_migrate_task), appopt_rvh_can_migrate);
	if (reg_preempt)
		_tp_unregister(kvar(__tracepoint_android_rvh_check_preempt_wakeup), appopt_rvh_check_preempt);
	if (reg_setaff)
		_tp_unregister(kvar(__tracepoint_android_vh_sched_setaffinity_early), appopt_vh_setaffinity_early);
	if (appopt_dir)
		_proc_remove(appopt_dir);
	logkm("exit\n");
	return 0;
}

KPM_INIT(appopt_kpm_init);
KPM_CTL0(appopt_kpm_control0);
KPM_EXIT(appopt_kpm_exit);
