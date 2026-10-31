use std::ffi::CString;

use crate::config::{AffinityRule, AppConfig};
use crate::cpuset::{ensure_cpuset_dir, CpuSet};

/// POSIX fnmatch 封装，需预转换为 CString
pub fn fnmatch_c(pattern: &CString, string: &str) -> bool {
    const BUF_LEN: usize = 32;
    if string.len() >= BUF_LEN {
        return false;
    }
    let mut buf = [0u8; BUF_LEN];
    buf[..string.len()].copy_from_slice(string.as_bytes());
    unsafe { libc::fnmatch(pattern.as_ptr(), buf.as_ptr() as *const _, libc::FNM_NOESCAPE) == 0 }
}

/// 线程亲和性计算结果
pub struct AffinityResult {
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
    pub sched: Option<crate::sched::SchedPolicy>,
    /// 合并后生效的厂商 boost level(取最后一条命中的带 boost 规则)
    pub boost: Option<u32>,
    /// 合并后生效的 WALT reduce-affinity 掩码(取最后一条命中的带 reduce 规则)
    pub reduce: Option<u64>,
    /// 是否标记低延迟(任一命中规则带 :ll 即为 true)
    pub low_latency: bool,
    /// 合并后生效的 task_load_boost 值(取最后一条命中的带 loadboost 规则)
    pub load_boost: Option<u32>,
    /// 合并后生效的 per-task WALT 提示(取最后一条命中的带 :p/:w/:g 规则)
    pub walt: Vec<(&'static str, u32)>,
    /// 合并后生效的 per-task uclamp 地板/顶(取最后一条命中的带 :umin/:umax 规则)
    pub uclamp_min: Option<u32>,
    pub uclamp_max: Option<u32>,
    /// 合并后生效的 per-task 定时器松弛度(取最后一条命中的带 :slack 规则)
    pub timerslack: Option<u64>,
    /// 任一命中规则带 :p 即为 true —— OPLUS 机型据此把线程注册进 pipeline_pids_cpus 贴大核。
    pub pipeline: bool,
    /// :p:<cpu> 显式目标核(取最后一条命中的带显式核的规则)；None=由绑定掩码最高核决定。
    pub pipeline_cpu: Option<u32>,
    /// :pf HMBIRD prefer_cpu 偏好核掩码(取最后一条命中)。
    pub prefer_cpu: Option<u64>,
    /// :ph 硬亲和核掩码(取最后一条命中)。
    pub hard_cpu: Option<u64>,
    /// :pcl HMBIRD prefer_cluster 偏好簇掩码(取最后一条命中)。
    pub prefer_cluster: Option<u64>,
    /// :pi HMBIRD prefer_idle(任一命中即真)。
    pub prefer_idle: bool,
    /// :pp HMBIRD prefer_preempt(任一命中即真)。
    pub prefer_preempt: bool,
}

/// 是否存在命中 `comm` 的带 `:m` 线程规则。供 eBPF FORK 路径判断:子线程继承到的正好是某条
/// `:m` 线程名时,直接按线程名绑(不等 task_rename),从而纯事件覆盖"后出现的同名线程"、不扫 /proc。
pub fn same_name_match(pkg: &str, comm: &str, cfg: &AppConfig) -> bool {
    cfg.rules.iter().any(|r| {
        r.same_name && r.pkg == pkg && !r.thread.is_empty() && fnmatch_c(&r.thread_pattern, comm)
    })
}

/// thread_affinity 的字段合并累加器：把命中规则的 CPU 与各 per-task 提示按
/// 「boost/reduce/… 取最后一条命中、ll/pipeline 任一命中即真」合并。线程分支与包级
/// fallback 分支共用同一套合并逻辑，避免两处逐字段重复。
#[derive(Default)]
struct Merged {
    cpus: CpuSet,
    sched: Option<crate::sched::SchedPolicy>,
    boost: Option<u32>,
    reduce: Option<u64>,
    low_latency: bool,
    load_boost: Option<u32>,
    walt: Vec<(&'static str, u32)>,
    uclamp_min: Option<u32>,
    uclamp_max: Option<u32>,
    timerslack: Option<u64>,
    pipeline: bool,
    pipeline_cpu: Option<u32>,
    prefer_cpu: Option<u64>,
    hard_cpu: Option<u64>,
    prefer_cluster: Option<u64>,
    prefer_idle: bool,
    prefer_preempt: bool,
}

impl Merged {
    fn merge(&mut self, rule: &AffinityRule) {
        self.cpus.or(&rule.cpus);
        if rule.sched.is_some() {
            self.sched = rule.sched;
        }
        if rule.boost.is_some() {
            self.boost = rule.boost;
        }
        if rule.reduce.is_some() {
            self.reduce = rule.reduce;
        }
        if rule.low_latency {
            self.low_latency = true;
        }
        if rule.load_boost.is_some() {
            self.load_boost = rule.load_boost;
        }
        if !rule.walt.is_empty() {
            self.walt = rule.walt.clone();
        }
        if rule.uclamp_min.is_some() {
            self.uclamp_min = rule.uclamp_min;
        }
        if rule.uclamp_max.is_some() {
            self.uclamp_max = rule.uclamp_max;
        }
        if rule.timerslack.is_some() {
            self.timerslack = rule.timerslack;
        }
        if rule.pipeline {
            self.pipeline = true;
        }
        if rule.pipeline_cpu.is_some() {
            self.pipeline_cpu = rule.pipeline_cpu;
        }
        if rule.prefer_cpu.is_some() {
            self.prefer_cpu = rule.prefer_cpu;
        }
        if rule.hard_cpu.is_some() {
            self.hard_cpu = rule.hard_cpu;
        }
        if rule.prefer_cluster.is_some() {
            self.prefer_cluster = rule.prefer_cluster;
        }
        if rule.prefer_idle {
            self.prefer_idle = true;
        }
        if rule.prefer_preempt {
            self.prefer_preempt = true;
        }
    }

    /// 是否带任何 per-task 提示（决定"无核规则"是否仍值得下发）。
    fn has_hint(&self) -> bool {
        self.sched.is_some()
            || self.boost.is_some()
            || self.reduce.is_some()
            || self.low_latency
            || self.load_boost.is_some()
            || !self.walt.is_empty()
            || self.uclamp_min.is_some()
            || self.uclamp_max.is_some()
            || self.timerslack.is_some()
            || self.pipeline
            || self.prefer_cpu.is_some()
            || self.hard_cpu.is_some()
            || self.prefer_cluster.is_some()
            || self.prefer_idle
            || self.prefer_preempt
    }

    /// 以累加的提示 + 给定 cpus/cpuset_dir/is_thread_rule 组装结果（消费 self）。
    fn into_result(self, cpus: CpuSet, cpuset_dir: String, is_thread_rule: bool) -> AffinityResult {
        AffinityResult {
            cpus,
            cpuset_dir,
            is_thread_rule,
            sched: self.sched,
            boost: self.boost,
            reduce: self.reduce,
            low_latency: self.low_latency,
            load_boost: self.load_boost,
            walt: self.walt,
            uclamp_min: self.uclamp_min,
            uclamp_max: self.uclamp_max,
            timerslack: self.timerslack,
            pipeline: self.pipeline,
            pipeline_cpu: self.pipeline_cpu,
            prefer_cpu: self.prefer_cpu,
            hard_cpu: self.hard_cpu,
            prefer_cluster: self.prefer_cluster,
            prefer_idle: self.prefer_idle,
            prefer_preempt: self.prefer_preempt,
        }
    }
}

/// 线程规则 CPU 累加，无线程匹配走包级 fallback，仍无则返回 None。
pub fn thread_affinity(pkg: &str, thread: &str, cfg: &AppConfig) -> Option<AffinityResult> {
    let mut m = Merged::default();
    let mut cpuset_dir = String::new();
    let mut matched = false;

    if !thread.is_empty() {
        for rule in &cfg.rules {
            if rule.pkg == pkg && !rule.thread.is_empty() && fnmatch_c(&rule.thread_pattern, thread) {
                m.merge(rule);
                matched = true;
            }
        }
        // 按合并后的 CPU 集合重算 cpuset 目录，确保与亲和性一致
        if matched {
            cpuset_dir = ensure_cpuset_dir(&m.cpus, &cfg.topo);
        }
    }

    if !matched {
        let mut fallback_seen = false;
        for rule in &cfg.rules {
            if rule.pkg != pkg || !rule.thread.is_empty() {
                continue;
            }
            m.merge(rule);
            // 单条包级规则用其自身 cpuset 目录；多条合并后目录不再对应单一集合，清空、只按亲和绑定。
            if !fallback_seen {
                cpuset_dir = rule.cpuset_dir.clone();
                fallback_seen = true;
            } else {
                cpuset_dir.clear();
            }
        }
    }

    // 有核：直接按合并集合绑定。
    if m.cpus.count() != 0 {
        let cpus = m.cpus;
        return Some(m.into_result(cpus, cpuset_dir, matched));
    }
    // 无核但带提示（如 =:p / =:boost:2 / =:pf:7）：【只施加 per-task 提示，不建也不移 cpuset、不动亲和】。
    // 旧版把 boost/:p 等“抢大核”提示移进全核 cpuset 解封大核，但那会把线程强拉进 /dev/cpuset/AppOpt/*
    // (affinity_set 对非空 cpus + 空 dir 会写进 base cpuset 的 tasks)。按“不配核=纯提示”：大核放置交给
    // :p(pipeline)/:pf(prefer_cpu)/:boost(WALT/uclamp) 等调度器机制自己完成，appopt 不再动 cpuset/亲和。
    // 返回空 cpus，下游 affinity_set 据 count()==0 直接跳过，绝不写任何 cpuset 或 setaffinity。
    if m.has_hint() {
        return Some(m.into_result(CpuSet::new(), String::new(), matched));
    }
    // 该包有线程规则、但当前线程没命中任何规则：仍返回 Some 使其【被纳管】——防降级 guard 据此
    // 保护已改名线程的旧绑定(见 cache::task_apply)；但返回【空 cpus + 空 dir → 完全不动亲和/cpuset】。
    // 不再返回 present_cpus(那会把每个未命中线程都强拉进 base AppOpt cpuset)。未命中的线程保持系统
    // 原样，放置只由各自命中规则的绑核/提示完成。
    if cfg.has_thread_rules.contains(pkg) {
        return Some(Merged::default().into_result(CpuSet::new(), String::new(), false));
    }
    None
}
