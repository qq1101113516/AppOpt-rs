use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::sync::{LazyLock, Mutex, OnceLock};

use crate::lock_ignore_poison;


/// WALT per-task boost 节点（level 0..=3，旧二进制非 rt 路径写此）
const WALT_BOOST: &str = "/proc/sys/walt/sched_per_task_boost";
/// WALT reduce-affinity 节点（cpumask，旧二进制 rt 路径写此）
const WALT_REDUCE: &str = "/proc/sys/walt/task_reduce_affinity";
/// WALT 低延迟任务标记节点（"tid 1" 开 / "tid 0" 关；唤醒优先塞空闲核、少被迁走，仅高通）
const WALT_LOW_LATENCY: &str = "/proc/sys/walt/sched_low_latency";
/// WALT 任务负载 boost 节点（"tid <val>" 抬高任务负载读数→占大核+拉频，仅高通）
const WALT_LOAD_BOOST: &str = "/proc/sys/walt/task_load_boost";
/// WALT pipeline special 开关（旧二进制 mode=2 一并写 "0" 关闭它；亦作旧内核流水线节点回落）
const WALT_PIPELINE: &str = "/proc/sys/walt/sched_pipeline_special";
/// WALT 流水线任务标记（新内核 per-task "tid 1"；旧内核回落到 WALT_PIPELINE，:p 后缀）
const WALT_PIPELINE_NEW: &str = "/proc/sys/walt/sched_pipeline";
/// WALT 唤醒选空闲核标记（per-task "tid 1"，砍唤醒延迟；:w 后缀）
const WALT_WAKE_IDLE: &str = "/proc/sys/walt/sched_wake_up_idle";
/// WALT 共置组(RTG)标记（per-task "tid <gid>"，整组协同放置+boost；:g 后缀）
const WALT_GROUP_ID: &str = "/proc/sys/walt/sched_group_id";
/// 联发科 FPSGO fbt 按 pid 调参节点
const FPSGO_FBT: &str = "/sys/kernel/fpsgo/fbt/fbt_attr_by_pid";
/// EAS schedtune cgroup 根（老内核 4.4~4.19，uclamp/WALT boost 前身；新内核一般无此目录）
const STUNE_ROOT: &str = "/dev/stune";

/// boost 后端：高通 WALT / 联发科 FPSGO / 老内核 EAS schedtune / 无
enum BoostBackend {
    Walt,
    Fpsgo,
    /// schedtune：把 tid 移进带 boost 的子组(见 schedtune_boost)。WALT/FPSGO 都没有时的老内核兜底。
    Schedtune,
    None,
}

/// boost 后端探测结果，首次使用时探测并缓存
static BOOST_BACKEND: OnceLock<BoostBackend> = OnceLock::new();
/// WALT reduce 节点是否可用，首次使用时探测并缓存
static REDUCE_OK: OnceLock<bool> = OnceLock::new();
/// WALT 低延迟/负载 boost 节点是否可用
static LL_OK: OnceLock<bool> = OnceLock::new();
static LOADBOOST_OK: OnceLock<bool> = OnceLock::new();
/// pipeline special 只需在首次用到 WALT 时写一次 "0"
static PIPELINE_INIT: OnceLock<()> = OnceLock::new();

/// 已 boost 的 tid → level；已 reduce 的 tid → cpumask。用于退出/配置变更时写 0 撤销。
static BOOSTED: LazyLock<Mutex<HashMap<i32, u32>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static REDUCED: LazyLock<Mutex<HashMap<i32, u64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// 已标记低延迟的 tid；已 load_boost 的 tid→值。同样只撤登记在册的。
static LOW_LATENCY: LazyLock<Mutex<HashSet<i32>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static LOAD_BOOSTED: LazyLock<Mutex<HashMap<i32, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// 已作用的 per-task WALT 提示：tid → 写入成功的节点列表，供退出/线程消失写 "tid 0" 撤销。
static WALT_HINTED: LazyLock<Mutex<HashMap<i32, Vec<&'static str>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 从 CPU 规格里剥离出的厂商后缀
#[derive(Default)]
pub struct VendorSuffix {
    /// :boost:<level> 的 level（0..=3；FPSGO 平台按其自身语义）
    pub boost: Option<u32>,
    /// :reduce:<cpuspec> 的原始 CPU 规格串（留待上层用 parse_cpu_spec 解析为掩码）
    pub reduce_spec: Option<String>,
    /// :ll —— 标记低延迟任务(sched_low_latency)
    pub low_latency: bool,
    /// :loadboost:<val> —— 任务负载 boost 值(task_load_boost)
    pub load_boost: Option<u32>,
    /// 追加的 per-task WALT 提示：(节点路径, 值)，统一 "tid val" 写入、"tid 0" 撤销。
    /// 来自 :p(流水线) / :w(唤醒选空闲核) / :g(共置组)。节点不存在时写入自然失败并跳过。
    pub walt: Vec<(&'static str, u32)>,
    /// :m —— 同名线程全绑(匹配作用域标记，非厂商提示)。命中此线程规则时，把本进程内
    /// 与触发线程同 comm 的兄弟线程一并绑定(见 ebpf_mode 事件路径)。
    pub same_name: bool,
    /// :umin:<0..1024> —— per-task uclamp 性能地板(主线机制,非厂商;经 sched_setattr 施加)
    pub uclamp_min: Option<u32>,
    /// :umax:<0..1024> —— per-task uclamp 频率封顶
    pub uclamp_max: Option<u32>,
    /// :slack:<ns> —— per-task 定时器松弛度(/proc/<tid>/timerslack_ns，主线;非厂商)。需带值。
    pub timerslack: Option<u64>,
    /// :p —— 流水线任务标记(跨厂商)。WALT 机型写 /proc/sys/walt/sched_pipeline(见上 walt 向量)；
    /// OPLUS 机型该 walt 节点不存在，转而经 oplus 子系统把线程注册进 pipeline_pids_cpus 贴大核。
    pub pipeline: bool,
    /// :p:<cpu> —— OPLUS pipeline 的显式目标核(该线程钉到哪个核)。None=不指定，由上层取绑定
    /// 掩码内最高核。仅影响 OPLUS pipeline_pids_cpus 的 cpu 字段；WALT sched_pipeline 只标记、忽略它。
    /// 内核要求 cpu 为 1..在线核数-1(0 非法)，越界/非在线由上层校验后回落最高核。
    pub pipeline_cpu: Option<u32>,
    /// :pf:<cpuspec> —— HMBIRD(_II) prefer_cpu 偏好核的原始 CPU 规格(上层用 parse_cpu_spec 解析成掩码)。
    pub prefer_cpu_spec: Option<String>,
    /// :ph:<cpuspec> —— 硬亲和(hard affinity)的原始 CPU 规格(上层解析成掩码,写 ko hard_affinity)。
    pub hard_cpu_spec: Option<String>,
    /// :pcl:<cpuspec> —— HMBIRD(_II) prefer_cluster 偏好簇的原始 CPU 规格(上层换算成簇掩码)。
    pub prefer_cluster_spec: Option<String>,
    /// :pi —— HMBIRD(_II) prefer_idle(唤醒优先空闲核)无值标记。
    pub prefer_idle: bool,
    /// :pp —— HMBIRD(_II) prefer_preempt(抢占倾向)无值标记。
    pub prefer_preempt: bool,
}

/// 向 proc/sysfs 节点写一次字符串（每次写都是一条完整命令，不能用 append）
fn write_node(path: &str, content: &str) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;
    f.write_all(content.as_bytes())
}

/// 首次用到 WALT 时关闭 pipeline special（忠实复刻旧二进制 mode=2 写 "0" 的行为）。
/// 若旧内核把 sched_pipeline_special 当作 :p 的 per-task 标记节点(pipeline_node 回落到它)，
/// 则跳过这次全局写 "0"，避免与逐线程标记("tid 1")语义冲突。
fn walt_pipeline_off() {
    PIPELINE_INIT.get_or_init(|| {
        if pipeline_node() == Some(WALT_PIPELINE) {
            return;
        }
        let _ = write_node(WALT_PIPELINE, "0");
    });
}

/// 探测 boost 后端：WALT boost 节点存在即判为高通（等价旧二进制 boost_fd>0）；
/// 否则尝试联发科 FPSGO；都没有则 boost 为无操作。
fn detect_boost() -> BoostBackend {
    if Path::new(WALT_BOOST).exists() {
        return BoostBackend::Walt;
    }
    if Path::new(FPSGO_FBT).exists() {
        return BoostBackend::Fpsgo;
    }
    // 老内核 EAS：无 WALT/FPSGO 但有 schedtune → 用它兜底 :boost
    if Path::new(STUNE_ROOT).exists() {
        return BoostBackend::Schedtune;
    }
    BoostBackend::None
}

/// schedtune 兜底：把 tid 移进 `/dev/stune/AppOpt_b<margin>` 子组(带 schedtune.boost=margin)。
/// WALT 档(0..=3)映射到 boost margin(近似)：level*20 → 1=20 / 2=40 / 3=60。建组幂等,失败即 no-op。
fn schedtune_boost(tid: i32, level: u32) -> bool {
    let margin = (level.min(3) * 20) as i32;
    let grp = format!("{}/AppOpt_b{}", STUNE_ROOT, margin);
    let _ = std::fs::create_dir(&grp);
    let _ = write_node(&format!("{}/schedtune.boost", grp), &margin.to_string());
    write_node(&format!("{}/tasks", grp), &tid.to_string()).is_ok()
}

/// 撤销 schedtune boost：把 tid 移回根组(boost 0)。
fn schedtune_unboost(tid: i32) {
    let _ = write_node(&format!("{}/tasks", STUNE_ROOT), &tid.to_string());
}

/// 解析流水线任务节点：优先新内核 sched_pipeline，回落旧内核 sched_pipeline_special，都无则 None。
/// 首次使用时探测并缓存（"那个存在那个生效"）。
fn pipeline_node() -> Option<&'static str> {
    static NODE: OnceLock<Option<&'static str>> = OnceLock::new();
    *NODE.get_or_init(|| {
        if Path::new(WALT_PIPELINE_NEW).exists() {
            Some(WALT_PIPELINE_NEW)
        } else if Path::new(WALT_PIPELINE).exists() {
            Some(WALT_PIPELINE)
        } else {
            None
        }
    })
}

/// 从 CPU 规格里剥离 `:boost:<level>` 与 `:reduce:<cpuspec>` 后缀，返回 (剩余规格, 厂商后缀)。
///
/// 与 `:FIFO:n / :RR:n / :nice:n` 并存且顺序无关：先在此剥离厂商后缀，剩余部分再交给
/// `sched::split_sched`。关键字大小写不敏感。例：
/// - `3-7:boost:2`             → ("3-7",       boost=2)
/// - `0-7:reduce:6-7`          → ("0-7",       reduce_spec="6-7")
/// - `6-7:FIFO:2:boost:3`      → ("6-7:FIFO:2", boost=3)
///
/// `boost` 缺省或非法值按 0 处理；`reduce` 缺省则忽略。
pub fn split_vendor(spec: &str) -> (String, VendorSuffix) {
    let parts: Vec<&str> = spec.split(':').collect();
    let mut kept: Vec<&str> = Vec::with_capacity(parts.len());
    let mut out = VendorSuffix::default();
    let mut i = 0;
    while i < parts.len() {
        let tok = parts[i].trim();
        // :boost:<0..3> / 短名 :b:<..>。裸 :boost / :b(不带数值)默认档 2(=偏置大核簇)。
        // 仅当紧邻是纯数字时才消费它，避免把后续后缀误当档位(如 :b:FIFO:2 里的 FIFO)。
        if tok.eq_ignore_ascii_case("boost") || tok.eq_ignore_ascii_case("b") {
            let val = parts.get(i + 1).and_then(|s| s.trim().parse::<u32>().ok());
            out.boost = Some(val.unwrap_or(2));
            i += if val.is_some() { 2 } else { 1 };
            continue;
        }
        if tok.eq_ignore_ascii_case("reduce") {
            // reduce 的值是 CPU 规格(非数字)：仅当紧邻 token 形如 CPU 规格才消费它；
            // 缺值 / 紧邻是别的后缀时不设 reduce、也不吞掉下一后缀(与 :boost/:umin 的"仅消费合法值"一致)。
            let next = parts.get(i + 1).map(|s| s.trim()).unwrap_or("");
            if crate::config::spec_like(next) {
                out.reduce_spec = Some(next.to_string());
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if tok.eq_ignore_ascii_case("ll") {
            out.low_latency = true;
            i += 1; // :ll 是无值标记
            continue;
        }
        if tok.eq_ignore_ascii_case("m") {
            out.same_name = true;
            i += 1; // :m 是无值标记（同名线程全绑）
            continue;
        }
        // :slack:<ns> —— 定时器松弛度纳秒。必须带值；无数值则忽略此标记(bare :slack 不生效)。
        // 注意：内核拒绝写入 0(timerslack_ns=0 会失败)，最紧请写 1；此处按原值透传，不做钳制。
        if tok.eq_ignore_ascii_case("slack") {
            match parts.get(i + 1).and_then(|s| s.trim().parse::<u64>().ok()) {
                Some(ns) => {
                    out.timerslack = Some(ns);
                    i += 2;
                }
                None => i += 1,
            }
            continue;
        }
        // :umin:<v> / 短名 :u:<v> —— per-task uclamp 性能地板（0..=1024，越界钳到 1024）。
        // 裸 :umin / :u(不带数值)默认 812。仅当紧邻是纯数字时才消费它。
        if tok.eq_ignore_ascii_case("umin") || tok.eq_ignore_ascii_case("u") {
            let val = parts.get(i + 1).and_then(|s| s.trim().parse::<u32>().ok());
            out.uclamp_min = Some(val.unwrap_or(812).min(crate::uclamp::UCLAMP_MAX));
            i += if val.is_some() { 2 } else { 1 };
            continue;
        }
        // :umax:<v> / 短名 :x:<v> —— per-task uclamp 频率封顶。裸 :umax / :x 默认 1024(=不封顶)。
        if tok.eq_ignore_ascii_case("umax") || tok.eq_ignore_ascii_case("x") {
            let val = parts.get(i + 1).and_then(|s| s.trim().parse::<u32>().ok());
            out.uclamp_max = Some(val.unwrap_or(crate::uclamp::UCLAMP_MAX).min(crate::uclamp::UCLAMP_MAX));
            i += if val.is_some() { 2 } else { 1 };
            continue;
        }
        if tok.eq_ignore_ascii_case("loadboost") {
            // 仅当紧邻是纯数字才消费它(与 :boost/:umin 一致)，避免把后续后缀误当值吞掉。
            let val = parts.get(i + 1).and_then(|s| s.trim().parse::<u32>().ok());
            out.load_boost = Some(val.unwrap_or(0));
            i += if val.is_some() { 2 } else { 1 };
            continue;
        }
        if tok.eq_ignore_ascii_case("p") {
            // 线路选择(0=auto 1=walt 2=oplus 3=ko):
            //   · WALT sched_pipeline 仅在 auto/walt 线路写(节点存在才入向量);
            //   · OPLUS/ko 由 out.pipeline + oplus::pipeline_node()(route-aware)决定,
            //     walt 线路下 pipeline_node()=None 自动 no-op。两条互补,由同一 :p 触发。
            let r = crate::oplus::route();
            if (r == 0 || r == 1)
                && let Some(node) = pipeline_node()
            {
                out.walt.push((node, 1));
            }
            out.pipeline = true;
            // :p:<cpu> —— 可选显式目标核(仅 OPLUS pipeline_pids_cpus 用)。仅当紧邻是纯数字时消费,
            // 否则 :p 仍是无值标记(避免把后续后缀误当核号,如 :p:FIFO:2 里的 FIFO)。
            let val = parts.get(i + 1).and_then(|s| s.trim().parse::<u32>().ok());
            out.pipeline_cpu = val;
            i += if val.is_some() { 2 } else { 1 };
            continue;
        }
        // :pf:<cpuspec> —— HMBIRD prefer_cpu(偏好核)。值是 CPU 规格(非纯数字标记)，仅当紧邻
        // 形如 CPU 规格时消费；缺值不设、也不吞下一后缀(与 :reduce 一致)。
        if tok.eq_ignore_ascii_case("pf") {
            let next = parts.get(i + 1).map(|s| s.trim()).unwrap_or("");
            if crate::config::spec_like(next) {
                out.prefer_cpu_spec = Some(next.to_string());
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        // :ph:<cpuspec> —— 硬亲和(hard affinity),写 ko 的 /proc/sched_opt/hard_affinity 锁死到该核集。
        // 值是 CPU 规格(同 :pf),仅当形如 CPU 规格时消费;缺值不设、也不吞下一后缀。
        if tok.eq_ignore_ascii_case("ph") {
            let next = parts.get(i + 1).map(|s| s.trim()).unwrap_or("");
            if crate::config::spec_like(next) {
                out.hard_cpu_spec = Some(next.to_string());
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        // :pcl:<cpuspec> —— HMBIRD prefer_cluster(偏好簇)。同上，值是 CPU 规格，上层换算成簇掩码。
        if tok.eq_ignore_ascii_case("pcl") {
            let next = parts.get(i + 1).map(|s| s.trim()).unwrap_or("");
            if crate::config::spec_like(next) {
                out.prefer_cluster_spec = Some(next.to_string());
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        // :pi —— HMBIRD prefer_idle(唤醒优先空闲核)，无值标记。
        if tok.eq_ignore_ascii_case("pi") {
            out.prefer_idle = true;
            i += 1;
            continue;
        }
        // :pp —— HMBIRD prefer_preempt(抢占倾向)，无值标记。
        if tok.eq_ignore_ascii_case("pp") {
            out.prefer_preempt = true;
            i += 1;
            continue;
        }
        // :w / :g 的值可选(缺省 1)：仅当紧邻 token 是纯数字时才消费它，避免误吞后续调度后缀
        if tok.eq_ignore_ascii_case("w") || tok.eq_ignore_ascii_case("g") {
            let node = if tok.eq_ignore_ascii_case("w") {
                WALT_WAKE_IDLE
            } else {
                WALT_GROUP_ID
            };
            let val = parts.get(i + 1).and_then(|s| s.trim().parse::<u32>().ok());
            out.walt.push((node, val.unwrap_or(1)));
            i += if val.is_some() { 2 } else { 1 };
            continue;
        }
        kept.push(parts[i]);
        i += 1;
    }
    (kept.join(":"), out)
}

/// 对线程施加厂商 boost 并登记。首次调用时探测后端。会在每次 affinity_sync 周期被重刷，
/// 抵消 Android 前后台切换的重置（与 sched_apply 一致）。
pub fn boost_apply(tid: i32, level: u32) {
    let ok = match BOOST_BACKEND.get_or_init(detect_boost) {
        BoostBackend::Walt => {
            walt_pipeline_off();
            write_node(WALT_BOOST, &format!("{} {}", tid, level)).is_ok()
        }
        BoostBackend::Fpsgo => {
            write_node(FPSGO_FBT, &format!("boost_affinity s {} {}", tid, level)).is_ok()
        }
        BoostBackend::Schedtune => schedtune_boost(tid, level),
        BoostBackend::None => false,
    };
    if ok {
        lock_ignore_poison(&BOOSTED).insert(tid, level);
    }
}

/// 撤销单个 tid 的 boost（未登记则无操作）：向对应节点写 level 0 清除。
pub fn boost_restore(tid: i32) {
    if lock_ignore_poison(&BOOSTED).remove(&tid).is_none() {
        return;
    }
    match BOOST_BACKEND.get_or_init(detect_boost) {
        BoostBackend::Walt => {
            let _ = write_node(WALT_BOOST, &format!("{} 0", tid));
        }
        BoostBackend::Fpsgo => {
            let _ = write_node(FPSGO_FBT, &format!("boost_affinity s {} 0", tid));
        }
        BoostBackend::Schedtune => schedtune_unboost(tid),
        BoostBackend::None => {}
    }
}

/// 对线程施加 WALT reduce-affinity（软性收窄到 mask）并登记；仅高通 WALT 有此节点。
pub fn reduce_apply(tid: i32, mask: u64) {
    if !*REDUCE_OK.get_or_init(|| Path::new(WALT_REDUCE).exists()) {
        return;
    }
    walt_pipeline_off();
    if write_node(WALT_REDUCE, &format!("{} {}", tid, mask)).is_ok() {
        lock_ignore_poison(&REDUCED).insert(tid, mask);
    }
}

/// 撤销单个 tid 的 reduce-affinity（未登记则无操作）：写 mask 0 解除软约束。
pub fn reduce_restore(tid: i32) {
    if lock_ignore_poison(&REDUCED).remove(&tid).is_none() {
        return;
    }
    if *REDUCE_OK.get_or_init(|| Path::new(WALT_REDUCE).exists()) {
        let _ = write_node(WALT_REDUCE, &format!("{} 0", tid));
    }
}

/// 标记线程为低延迟任务并登记；仅高通 WALT 有此节点。
pub fn ll_apply(tid: i32) {
    if !*LL_OK.get_or_init(|| Path::new(WALT_LOW_LATENCY).exists()) {
        return;
    }
    if write_node(WALT_LOW_LATENCY, &format!("{} 1", tid)).is_ok() {
        lock_ignore_poison(&LOW_LATENCY).insert(tid);
    }
}

/// 撤销低延迟标记（未登记则无操作）：写 "tid 0"。
pub fn ll_restore(tid: i32) {
    if lock_ignore_poison(&LOW_LATENCY).remove(&tid) {
        let _ = write_node(WALT_LOW_LATENCY, &format!("{} 0", tid));
    }
}

/// 对线程施加 task_load_boost（抬高负载读数→占大核+拉频）并登记；仅高通 WALT。
pub fn loadboost_apply(tid: i32, val: u32) {
    if !*LOADBOOST_OK.get_or_init(|| Path::new(WALT_LOAD_BOOST).exists()) {
        return;
    }
    if write_node(WALT_LOAD_BOOST, &format!("{} {}", tid, val)).is_ok() {
        lock_ignore_poison(&LOAD_BOOSTED).insert(tid, val);
    }
}

/// 撤销 task_load_boost（未登记则无操作）：写 "tid 0"。
pub fn loadboost_restore(tid: i32) {
    if lock_ignore_poison(&LOAD_BOOSTED).remove(&tid).is_some() {
        let _ = write_node(WALT_LOAD_BOOST, &format!("{} 0", tid));
    }
}

/// 施加一组 per-task WALT 提示并登记（仅登记写入成功的节点，节点不存在则自然跳过）。
/// 与其它厂商提示一样在每个 affinity_sync 周期被重刷，抵消前后台切换的重置。
pub fn hints_apply(tid: i32, hints: &[(&'static str, u32)]) {
    let mut applied: Vec<&'static str> = Vec::new();
    for &(node, val) in hints {
        if write_node(node, &format!("{} {}", tid, val)).is_ok() {
            applied.push(node);
        }
    }
    if applied.is_empty() {
        lock_ignore_poison(&WALT_HINTED).remove(&tid);
    } else {
        lock_ignore_poison(&WALT_HINTED).insert(tid, applied);
    }
}

/// 撤销某 tid 的全部 WALT 提示（未登记则无操作）：向每个已登记节点写 "tid 0"。
pub fn hints_restore(tid: i32) {
    if let Some(nodes) = lock_ignore_poison(&WALT_HINTED).remove(&tid) {
        for node in nodes {
            let _ = write_node(node, &format!("{} 0", tid));
        }
    }
}

/// fork 子线程去继承：把【配置里实际用到的】厂商提示写默认/0(不登记)，抹掉可能从父线程内核级
/// 继承来的残留。仅在 FORK 事件、对已管理进程的子线程调用，且只写配置用到的项，故开销受规则集
/// 约束。uclamp 由 sched_setattr 的 RESET_ON_FORK 免疫、不在此列；sched(FIFO/RR/nice)亦然。
pub fn scrub_fork_child(tid: i32, pkg: &str, cfg: &crate::config::AppConfig) {
    // 只按【本包】规则决定抹哪些继承项：子线程只会从同包父线程继承到我方设过的提示。若用全量
    // rules，则"任一包用了某后缀"就会波及其它受管包的 fork 子线程——尤以 :g(sched_group_id)写
    // "tid 0" 为甚，会把非 :g 包的子线程踢出系统 colocation 组。故按 pkg 过滤后再判。
    let rules: Vec<&crate::config::AffinityRule> =
        cfg.rules.iter().filter(|r| r.pkg.as_str() == pkg).collect();
    if rules.iter().any(|r| r.boost.is_some()) {
        match BOOST_BACKEND.get_or_init(detect_boost) {
            BoostBackend::Walt => {
                let _ = write_node(WALT_BOOST, &format!("{} 0", tid));
            }
            BoostBackend::Fpsgo => {
                let _ = write_node(FPSGO_FBT, &format!("boost_affinity s {} 0", tid));
            }
            BoostBackend::Schedtune => schedtune_unboost(tid),
            BoostBackend::None => {}
        }
    }
    if rules.iter().any(|r| r.reduce.is_some())
        && *REDUCE_OK.get_or_init(|| Path::new(WALT_REDUCE).exists())
    {
        let _ = write_node(WALT_REDUCE, &format!("{} 0", tid));
    }
    if rules.iter().any(|r| r.low_latency)
        && *LL_OK.get_or_init(|| Path::new(WALT_LOW_LATENCY).exists())
    {
        let _ = write_node(WALT_LOW_LATENCY, &format!("{} 0", tid));
    }
    if rules.iter().any(|r| r.load_boost.is_some())
        && *LOADBOOST_OK.get_or_init(|| Path::new(WALT_LOAD_BOOST).exists())
    {
        let _ = write_node(WALT_LOAD_BOOST, &format!("{} 0", tid));
    }
    // :p/:w/:g —— 对配置用到的每个 WALT 节点写 "tid 0"（去重）
    let mut seen: Vec<&'static str> = Vec::new();
    for r in rules {
        for &(nodepath, _) in &r.walt {
            if !seen.contains(&nodepath) {
                seen.push(nodepath);
                let _ = write_node(nodepath, &format!("{} 0", tid));
            }
        }
    }
}

/// 撤销全部厂商提示（boost + reduce + 低延迟 + load_boost + WALT 提示），配置变更、退出时调用
pub fn restore_all() {
    let boosted: Vec<i32> = lock_ignore_poison(&BOOSTED).keys().copied().collect();
    for tid in boosted {
        boost_restore(tid);
    }
    let reduced: Vec<i32> = lock_ignore_poison(&REDUCED).keys().copied().collect();
    for tid in reduced {
        reduce_restore(tid);
    }
    let ll: Vec<i32> = lock_ignore_poison(&LOW_LATENCY).iter().copied().collect();
    for tid in ll {
        ll_restore(tid);
    }
    let lb: Vec<i32> = lock_ignore_poison(&LOAD_BOOSTED).keys().copied().collect();
    for tid in lb {
        loadboost_restore(tid);
    }
    let hinted: Vec<i32> = lock_ignore_poison(&WALT_HINTED).keys().copied().collect();
    for tid in hinted {
        hints_restore(tid);
    }
}
