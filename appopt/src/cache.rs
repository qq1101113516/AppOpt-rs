use std::collections::HashMap;

use crate::apply_affinity::affinity_set;
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::rule_match::thread_affinity;

/// 线程条目，对应 /proc/[pid]/task/[tid]
pub struct TaskEntry {
    pub pid: i32,
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
    pub sched: Option<crate::sched::SchedPolicy>,
    /// 生效的厂商 boost level，用于 affinity_sync 周期重刷
    pub boost: Option<u32>,
    /// 生效的 WALT reduce-affinity 掩码，用于 affinity_sync 周期重刷
    pub reduce: Option<u64>,
    /// 是否标记低延迟(:ll)，用于 affinity_sync 周期重刷
    pub low_latency: bool,
    /// 生效的 task_load_boost 值(:loadboost)，用于 affinity_sync 周期重刷
    pub load_boost: Option<u32>,
    /// 生效的 per-task WALT 提示(:p/:w/:g)，用于 affinity_sync 周期重刷
    pub walt: Vec<(&'static str, u32)>,
    /// 生效的 per-task uclamp 地板/顶(:umin/:umax)，用于 affinity_sync 周期重刷
    pub uclamp_min: Option<u32>,
    pub uclamp_max: Option<u32>,
    /// 生效的 per-task 定时器松弛度(:slack)，用于 affinity_sync 周期重刷
    pub timerslack: Option<u64>,
    /// 是否标记为 pipeline 线程(:p)，OPLUS 机型据此重排到大核，用于 affinity_sync 周期重刷
    pub pipeline: bool,
    /// :p:<cpu> 显式目标核(None=取掩码最高核)，用于 affinity_sync 周期重刷
    pub pipeline_cpu: Option<u32>,
    /// :pf HMBIRD prefer_cpu 偏好核掩码，用于 affinity_sync 周期重刷
    pub prefer_cpu: Option<u64>,
    /// :ph 硬亲和核掩码(ko hard_affinity)，用于 affinity_sync 周期重刷
    pub hard_cpu: Option<u64>,
    /// :pcl HMBIRD prefer_cluster 偏好簇掩码，用于 affinity_sync 周期重刷
    pub prefer_cluster: Option<u64>,
    /// :pi HMBIRD prefer_idle，用于 affinity_sync 周期重刷
    pub prefer_idle: bool,
    /// :pp HMBIRD prefer_preempt，用于 affinity_sync 周期重刷
    pub prefer_preempt: bool,
}

/// :p 的 OPLUS pipeline 目标核：取绑定集合内最高编号核(≈prime)，集合空则用大核簇/在线核最高核。
fn pipeline_target(cpus: &CpuSet, topo: &CpuTopology) -> u32 {
    cpus.highest()
        .or_else(|| topo.hp_core.highest())
        .or_else(|| topo.present_cpus.highest())
        .unwrap_or(0) as u32
}

/// 解析 :p 的最终目标核。显式 :p:<cpu> 优先，但必须满足内核 pipeline_pids_cpus 的约束
/// (cpu>0 且为在线核；cpu 0 会令整表写入 -EINVAL)；不满足则回落到绑定掩码最高核。
/// 掩码最高核若为 0(如 =0:p 之类反常规则)，再退化到最高在线核，避免写 0 使整表失败。
fn resolve_pipeline_cpu(explicit: Option<u32>, cpus: &CpuSet, topo: &CpuTopology) -> u32 {
    if let Some(c) = explicit
        && c > 0
        && topo.present_cpus.is_set(c as usize)
    {
        return c;
    }
    let t = pipeline_target(cpus, topo);
    if t == 0 {
        topo.present_cpus.highest().unwrap_or(0) as u32
    } else {
        t
    }
}

/// 双模式共用进程缓存，eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub pkgs: HashMap<i32, (String, bool)>,
    pub tasks: HashMap<i32, TaskEntry>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            pkgs: HashMap::new(),
            tasks: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.pkgs.clear();
        self.tasks.clear();
    }

    /// 删除 tid，若该 pid 下无线程则清理 pkgs[pid]；同时还原被改过的调度策略
    pub fn task_del(&mut self, tid: i32) {
        crate::sched::sched_restore(tid);
        crate::vendor_boost::boost_restore(tid);
        crate::vendor_boost::reduce_restore(tid);
        crate::vendor_boost::ll_restore(tid);
        crate::vendor_boost::loadboost_restore(tid);
        crate::vendor_boost::hints_restore(tid);
        crate::uclamp::uclamp_restore(tid);
        crate::timerslack::timerslack_restore(tid);
        crate::oplus::pipeline_restore(tid);
        crate::hmbird::prefer_cpu_restore(tid);
        crate::hard::hard_restore(tid);
        crate::hmbird::prefer_cluster_restore(tid);
        crate::hmbird::prefer_idle_restore(tid);
        crate::hmbird::prefer_preempt_restore(tid);
        let pid = self.tasks.remove(&tid).map(|t| t.pid);
        if let Some(pid) = pid {
            self.pkgs_purge(pid);
        }
    }

    /// 取【配了 :p 流水线】的包 pid（供 OPLUS skip_gameself 锁注册 game_pid）。
    /// OPLUS 锁仅对这类包生效——没配 :p 就不动 game_pid/skip，返回 None 表示应解锁。
    /// 多进程/多同名取任一，够用。
    pub fn pipeline_pkg_pid(
        &self,
        pipeline_pkgs: &std::collections::HashSet<String>,
    ) -> Option<i32> {
        self.pkgs
            .iter()
            .find(|(_, (pkg, _))| pipeline_pkgs.contains(pkg))
            .map(|(pid, _)| *pid)
    }

    /// pid 无残留 task 时清理 pkgs[pid] 避免孤立缓存泄漏
    fn pkgs_purge(&mut self, pid: i32) {
        if !self.tasks.values().any(|t| t.pid == pid) {
            self.pkgs.remove(&pid);
        }
    }

    /// eBPF 专用，pkgs 缓存命中优先否则 comm_to_pkg 匹配后缓存
    pub fn pkg_lookup_comm(
        &mut self,
        pid: i32,
        comm: &str,
        cfg: &AppConfig,
    ) -> Option<(String, bool)> {
        if let Some(&(ref pkg, htr)) = self.pkgs.get(&pid) {
            return Some((pkg.clone(), htr));
        }
        let pkg = comm_to_pkg(comm, cfg)?;
        let htr = cfg.has_thread_rules.contains(&pkg);
        self.pkgs.insert(pid, (pkg.clone(), htr));
        Some((pkg, htr))
    }

    /// 计算并应用线程亲和性，trust_comm=false 时忽略 comm 走 fallback（FORK 继承场景）
    /// 新结果走 fallback 时保护已有线程规则绑定，防止临时改名降级
    // 参数按 (tid,pid,pkg,comm,trust/bind 标志,cfg,apply_fn) 直传避免每线程构造临时上下文结构，是热路径上的
    // 有意设计，故豁免 too_many_arguments。
    #[allow(clippy::too_many_arguments)]
    pub fn task_apply<F>(
        &mut self,
        tid: i32,
        pid: i32,
        pkg: &str,
        comm: &str,
        has_thread_rules: bool,
        cfg: &AppConfig,
        trust_comm: bool,
        bind_only: bool,
        apply_fn: F,
    ) -> bool
    where
        F: FnOnce(i32, &CpuSet, &str) -> bool,
    {
        let thread_name = if has_thread_rules && trust_comm { comm } else { "" };
        let Some(mut result) = thread_affinity(pkg, thread_name, cfg) else {
            return false;
        };

        // bind_only：`:m` 因「继承父名」而认出的 fork 子线程走此路——只复制【绑核/cpuset】，
        // 清掉所有 per-task 强度 hint(sched/boost/reduce/ll/loadboost/:p:w:g/uclamp/slack)，
        // 使这些 hint 只作用于按自己真实线程名命中的线程(EXEC/RENAME/全量扫描)，不灌到整个同名池。
        if bind_only {
            result.sched = None;
            result.boost = None;
            result.reduce = None;
            result.low_latency = false;
            result.load_boost = None;
            result.walt.clear();
            result.uclamp_min = None;
            result.uclamp_max = None;
            result.timerslack = None;
            result.pipeline = false;
            result.pipeline_cpu = None;
            result.prefer_cpu = None;
            result.hard_cpu = None;
            result.prefer_cluster = None;
            result.prefer_idle = false;
            result.prefer_preempt = false;
        }

        if !result.is_thread_rule
            && self.tasks.get(&tid).is_some_and(|old| old.is_thread_rule)
        {
            // 绑核/cpuset 维持旧线程规则,防【不可信/临时改名】(fork 继承父名的瞬时事件)把核降级。
            // 全部 per-task 提示(:p/:pf/:pcl/:pi/:pp/:ph/:boost/:sched/:uclamp …)一律【保留、不解除】,
            // 继续被 affinity_sync 6 秒重刷,直到线程【真正死亡】才由 task_del 清理。
            // 注::p 走的内核 pipeline_pids_cpus 只有 6 槽、flush 按 tid 升序取前 6,理论上改名存活的
            // 旧线程(tid 更小)可能占坑;但实践中 :p 目标线程(如 UnityMain)基本不改名,故不再特殊
            // 解除,与其它后缀统一(flush 截断到 6 对,不会溢出)。
            return true;
        }

        self.tasks.remove(&tid);
        let dead = apply_fn(tid, &result.cpus, &result.cpuset_dir);
        if dead {
            return false;
        }

        // 仅对配置了调度策略的规则应用；否则还原（应对线程改名后不再匹配 FIFO 规则）
        match result.sched {
            Some(p) => {
                crate::sched::sched_apply(tid, p);
            }
            None => crate::sched::sched_restore(tid),
        }

        // 厂商 boost：命中带 :boost 的规则则应用，否则撤销（改名后不再匹配）
        match result.boost {
            Some(v) => crate::vendor_boost::boost_apply(tid, v),
            None => crate::vendor_boost::boost_restore(tid),
        }

        // WALT reduce-affinity 同理：命中带 :reduce 的规则则应用，否则撤销
        match result.reduce {
            Some(m) => crate::vendor_boost::reduce_apply(tid, m),
            None => crate::vendor_boost::reduce_restore(tid),
        }

        // 低延迟标记 / task_load_boost 同理
        if result.low_latency {
            crate::vendor_boost::ll_apply(tid);
        } else {
            crate::vendor_boost::ll_restore(tid);
        }
        match result.load_boost {
            Some(v) => crate::vendor_boost::loadboost_apply(tid, v),
            None => crate::vendor_boost::loadboost_restore(tid),
        }

        // per-task WALT 提示(:p/:w/:g)：命中则统一施加，否则撤销(改名后不再匹配)
        if result.walt.is_empty() {
            crate::vendor_boost::hints_restore(tid);
        } else {
            crate::vendor_boost::hints_apply(tid, &result.walt);
        }

        // per-task uclamp(:umin/:umax)：命中则施加，否则还原
        if result.uclamp_min.is_some() || result.uclamp_max.is_some() {
            crate::uclamp::uclamp_apply(tid, result.uclamp_min, result.uclamp_max);
        } else {
            crate::uclamp::uclamp_restore(tid);
        }

        // per-task 定时器松弛度(:slack)：命中则施加，否则还原
        match result.timerslack {
            Some(ns) => crate::timerslack::timerslack_apply(tid, ns),
            None => crate::timerslack::timerslack_restore(tid),
        }

        // :p pipeline(仅 OPLUS 生效，非 OPLUS no-op)：命中则注册进 pipeline_pids_cpus 贴大核，否则撤销
        if result.pipeline {
            let target = resolve_pipeline_cpu(result.pipeline_cpu, &result.cpus, &cfg.topo);
            crate::oplus::pipeline_apply(tid, pid, target);
        } else {
            crate::oplus::pipeline_restore(tid);
        }

        // HMBIRD(_II) prefer_cpu / prefer_cluster：命中带 :pf/:pcl 则施加，否则撤销(改名后不再匹配)
        match result.prefer_cpu {
            Some(m) => crate::hmbird::prefer_cpu_apply(tid, m),
            None => crate::hmbird::prefer_cpu_restore(tid),
        }
        // :ph 硬亲和(ko hard_affinity)：命中则锁死,否则撤销恢复原亲和
        match result.hard_cpu {
            Some(m) => crate::hard::hard_apply(tid, m),
            None => crate::hard::hard_restore(tid),
        }
        match result.prefer_cluster {
            Some(m) => crate::hmbird::prefer_cluster_apply(tid, m),
            None => crate::hmbird::prefer_cluster_restore(tid),
        }
        if result.prefer_idle {
            crate::hmbird::prefer_idle_apply(tid);
        } else {
            crate::hmbird::prefer_idle_restore(tid);
        }
        if result.prefer_preempt {
            crate::hmbird::prefer_preempt_apply(tid);
        } else {
            crate::hmbird::prefer_preempt_restore(tid);
        }

        self.tasks.insert(
            tid,
            TaskEntry {
                pid,
                cpus: result.cpus,
                cpuset_dir: result.cpuset_dir,
                is_thread_rule: result.is_thread_rule,
                sched: result.sched,
                boost: result.boost,
                reduce: result.reduce,
                low_latency: result.low_latency,
                load_boost: result.load_boost,
                walt: result.walt,
                uclamp_min: result.uclamp_min,
                uclamp_max: result.uclamp_max,
                timerslack: result.timerslack,
                pipeline: result.pipeline,
                pipeline_cpu: result.pipeline_cpu,
                prefer_cpu: result.prefer_cpu,
                hard_cpu: result.hard_cpu,
                prefer_cluster: result.prefer_cluster,
                prefer_idle: result.prefer_idle,
                prefer_preempt: result.prefer_preempt,
            },
        );
        true
    }

    /// 遍历 tasks 重刷亲和性与调度策略（Android 会在前后台切换时重置，需周期性纠正），
    /// 返回 dead_tids 供 eBPF 调用方清理 APPLIED_MAP
    pub fn affinity_sync(&mut self, topo: &CpuTopology) -> Vec<i32> {
        let dead_tids: Vec<i32> = self
            .tasks
            .iter()
            .filter_map(|(tid, e)| {
                let dead = affinity_set(*tid, &e.cpus, &e.cpuset_dir, topo);
                if let Some(p) = e.sched.filter(|_| !dead) {
                    crate::sched::sched_apply(*tid, p);
                }
                // 周期重刷厂商 boost 与 reduce，抵消前后台切换导致的重置
                if let Some(v) = e.boost.filter(|_| !dead) {
                    crate::vendor_boost::boost_apply(*tid, v);
                }
                if let Some(m) = e.reduce.filter(|_| !dead) {
                    crate::vendor_boost::reduce_apply(*tid, m);
                }
                if e.low_latency && !dead {
                    crate::vendor_boost::ll_apply(*tid);
                }
                if let Some(v) = e.load_boost.filter(|_| !dead) {
                    crate::vendor_boost::loadboost_apply(*tid, v);
                }
                if !e.walt.is_empty() && !dead {
                    crate::vendor_boost::hints_apply(*tid, &e.walt);
                }
                if (e.uclamp_min.is_some() || e.uclamp_max.is_some()) && !dead {
                    crate::uclamp::uclamp_apply(*tid, e.uclamp_min, e.uclamp_max);
                }
                if let Some(ns) = e.timerslack.filter(|_| !dead) {
                    crate::timerslack::timerslack_apply(*tid, ns);
                }
                // pipeline(:p, 仅 OPLUS)周期重刷，抵消前后台切换/场景变化对 pipeline_pids_cpus 的重置
                if e.pipeline && !dead {
                    let target = resolve_pipeline_cpu(e.pipeline_cpu, &e.cpus, topo);
                    crate::oplus::pipeline_apply(*tid, e.pid, target);
                }
                // HMBIRD prefer_cpu/cluster 周期重刷，抵消前后台切换/场景变化的重置
                if let Some(m) = e.prefer_cpu.filter(|_| !dead) {
                    crate::hmbird::prefer_cpu_apply(*tid, m);
                }
                if let Some(m) = e.hard_cpu.filter(|_| !dead) {
                    crate::hard::hard_apply(*tid, m);
                }
                if let Some(m) = e.prefer_cluster.filter(|_| !dead) {
                    crate::hmbird::prefer_cluster_apply(*tid, m);
                }
                if e.prefer_idle && !dead {
                    crate::hmbird::prefer_idle_apply(*tid);
                }
                if e.prefer_preempt && !dead {
                    crate::hmbird::prefer_preempt_apply(*tid);
                }
                dead.then_some(*tid)
            })
            .collect();
        for tid in &dead_tids {
            self.task_del(*tid);
        }
        // pipeline_pids_cpus 是全局单表，会被内核场景切换/OEM HAL 清空或覆盖；上面的 pipeline_apply
        // 按 MEMBERS 去重不会重写已在册的 tid，故每周期在此无条件强制重刷整表，使 :p 像 affinity 一样自愈。
        crate::oplus::pipeline_resync();
        dead_tids
    }
}

/// 将内核 comm 截断于首个 NUL 并 trim 尾部空白
pub fn comm_str(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&comm[..end])
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 通过内核 comm 匹配配置包名，精确优先其次前缀后缀，与 BPF 双键逻辑一致
pub fn comm_to_pkg(comm: &str, cfg: &AppConfig) -> Option<String> {
    // 精确匹配；多进程子进程名形如 "pkg:suffix"，取冒号前归主包(冒号定界，精确不误扩)
    let base = comm.split(':').next().unwrap_or(comm);
    if cfg.pkgs.contains(base) {
        return Some(base.to_string());
    }
    if comm.len() >= 15 {
        // 截断名(comm 上限 15B)：前缀命中优先于后缀。单趟扫描——命中前缀立即返回，
        // 后缀仅记首个作兜底，扫完无前缀命中才用它（等价原两趟，少扫一遍）。
        let mut suffix_hit: Option<&String> = None;
        for pkg in &cfg.pkgs {
            if pkg.starts_with(comm) {
                return Some(pkg.clone());
            }
            if suffix_hit.is_none() && pkg.ends_with(comm) {
                suffix_hit = Some(pkg);
            }
        }
        if let Some(pkg) = suffix_hit {
            return Some(pkg.clone());
        }
    }
    None
}


