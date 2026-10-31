use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicU8, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};

use crate::lock_ignore_poison;

const GAME_PID: &str = "/proc/game_opt/game_pid";
const SKIP: &str = "/proc/game_opt/skip_gameself_setaffinity";
/// pipeline_pids_cpus 候选节点（按优先级探测第一个存在者）：
///   [0] OPLUS 官方(sched_assist)——一加/OPPO/真我原生；
///   [1] appopt 自带通用 .ko(appopt-ko/appopt_sched.c)提供的同格式节点——
///       让【非 OPLUS】机型加载 appopt_sched.ko 后 :p / :p:<cpu> 也能贴核。
/// 二者写格式一致("<tid> <cpu> ..."，空格分隔，-1 清空)，故 :p 写入逻辑无需分叉。
/// 注意：RT 避核/白名单/args/换 prime 等 companion 旋钮仍是 OPLUS 专属节点，通用 .ko 无，
/// 在非 OPLUS 上各自 available() 探测失败 → no-op，只保留核心的 pipeline 贴核。
const PIPELINE_NODES: [&str; 2] = [
    "/proc/oplus_scheduler/sched_assist/pipeline_pids_cpus",
    "/proc/sched_opt/pipeline_pids_cpus",
];
/// pipeline_rt_cpumask —— RT 任务应【避开】的核掩码(sa_pipeline.c 的 oplus_pipeline_rt_skip_prime_cpu 用)。
/// 把音频/中断等 RT 线程从 pipeline/prime 核赶走，减少对渲染流水线的抢占抖动。写处理按【十进制】
/// 解析掩码(kstrtoint base10)，读回却是 "0x<hex>"(故还原时须把读回值解析成数值再以十进制写回)；
/// 内核 sanity：掩码内核数 >4 直接作废(清 0)。仅 pipeline 生效(prime_task!=NULL)时起作用。
const PIPELINE_RT_CPUMASK: &str = "/proc/oplus_scheduler/sched_assist/pipeline_rt_cpumask";
/// pipeline_immuned_thread —— 动态白名单：即使非 pipeline 任务，只要 comm 含这些子串也允许上 prime 核。
/// 格式 "name1;name2"(各 ≤15 字节，内核 sscanf "%15[^;];%15[^;]" 截断)。内核另有静态白名单
/// (Loading.Preload / GC Marker / mali-compiler / RBX Worker)，此节点是额外动态追加两个。
const PIPELINE_IMMUNED: &str = "/proc/oplus_scheduler/sched_assist/pipeline_immuned_thread";
/// pipeline_args —— prime 核对 RT/非 pipeline 线程的容忍度(sa_pipeline.c 的 pipeline_args_proc_write)。
/// 格式 "<low_latency_util> <no_pipeline_util> <dislike>"，内核默认 30 / 400 / 1：
///   · low_latency_util(0..1024)：prime 上 RT/音频任务 util ≥ 此值才算“够忙、留下”；
///   · no_pipeline_util(0..1024)：游戏自身【非 pipeline】线程 util < 此值才允许上 prime 核；
///   · dislike(0/1)：是否【排斥非 pipeline 线程占用 prime 核】(=1 时把它们赶下 prime)。
/// 调低 no_pipeline_util、保持 dislike=1，可压制“uclamp/其它把杂线程 pack 上 prime”。
const PIPELINE_ARGS: &str = "/proc/oplus_scheduler/sched_assist/pipeline_args";
/// pipeline 动态换 prime 旋钮，格式 "<mode> <amp_coef> <cnt>"(sa_pipeline.c 确证)。
/// mode 1=开(按 util 把最忙 pipeline 线程动态换到 prime)/>1=只调试打点/0=关；
/// amp_coef=换核阈值(max_util≥prime_util*amp/100)；cnt=累积 WALT 窗口数。仅 ≥2 个 pipeline 线程时生效。
const PRIME_REARRANGE: &str = "/proc/oplus_scheduler/sched_assist/pipeline_prime_rearrange";
/// opt-in(-P) 开启时写入的值 "<mode> <amp> <cnt>"，可调，默认 1 51 10（web 端调、AppOpt.json 持久化）。
/// mode 0关/1开/>1只调试；amp 换核阈值放大系数(%)；cnt 累积 WALT 窗口数。
static REARRANGE_MODE: AtomicI32 = AtomicI32::new(1);
static REARRANGE_AMP: AtomicI32 = AtomicI32::new(51);
static REARRANGE_CNT: AtomicI32 = AtomicI32::new(10);

/// pipeline 元素分隔符（空格，sa_pipeline.c 确证）
const SEP: char = ' ';
/// 清空 pipeline 列表写 "-1"（内核 pids/cpus 数组默认 -1，匹配 pids[0]=-1 即清空全部）
const CLEAR: &str = "-1";
/// 内核 MAX_PIPELINE_TASK_NUM = 6：最多 6 对 pid/cpu，超出被 sscanf 忽略，故截断
const MAX_PIPELINE_TASKS: usize = 6;

/// pipeline 线路选择:0=auto(自动探测) 1=walt 2=oplus(一加官方) 3=ko(通用模块)。
/// web 在线可切、AppOpt.json 持久化。auto=先 OPLUS 官方后 ko;walt=不走 oplus/ko(交 WALT);
/// oplus/ko=强制只用对应节点(不存在则该路 no-op)。
pub static PIPELINE_ROUTE: AtomicU8 = AtomicU8::new(0);
pub fn set_route(r: u8) {
    PIPELINE_ROUTE.store(r, Ordering::Release);
}
pub fn route() -> u8 {
    PIPELINE_ROUTE.load(Ordering::Acquire)
}
/// skip 锁是否可用（需 game_pid 与 skip 两个节点都在；否则锁路径 no-op）
static LOCK_OK: OnceLock<bool> = OnceLock::new();
/// pipeline_prime_rearrange 节点是否可用
static REARRANGE_OK: OnceLock<bool> = OnceLock::new();
/// 是否 opt-in 启用动态换 prime（由 CLI -P 设置，默认关）
static REARRANGE_OPT: AtomicBool = AtomicBool::new(false);
/// 是否 opt-in 启用 skip_gameself 锁（由 CLI -S 设置，默认关）。
/// 该锁是【进程级】的：内核会丢弃游戏对自己【任意】线程的 sched_setaffinity，
/// 会波及游戏对其它线程的放置，而配了 cpuset 的 :p 线程本就被 cpus_mask 硬限，
/// 故默认关；仅需要这层进程级保护时显式开启。
static SKIP_OPT: AtomicBool = AtomicBool::new(false);

/// 已纳入 pipeline 的 tid → (所属进程 pid, 目标核)
static MEMBERS: LazyLock<Mutex<HashMap<i32, (i32, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// 当前 skip 锁定的游戏 pid（None=未锁）。owns /proc/game_opt/game_pid 的写入。
static LOCKED_PID: LazyLock<Mutex<Option<i32>>> = LazyLock::new(|| Mutex::new(None));
/// pipeline_prime_rearrange 原值存档（Some=已被我们改过，退出/清空时写回；None=未启用）。
static REARRANGE_SAVED: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// 是否 opt-in 启用 pipeline_rt_cpumask（RT 避核）。默认关。web 端切换、AppOpt.json 持久化。
static RT_CPUMASK_OPT: AtomicBool = AtomicBool::new(false);
/// 要写入 pipeline_rt_cpumask 的掩码值（0=清空→回落内核默认启发式）。
static RT_CPUMASK_VAL: AtomicU64 = AtomicU64::new(0);
/// pipeline_rt_cpumask 节点是否可用（非 OPLUS/无节点 → 全程 no-op）。
static RT_CPUMASK_OK: OnceLock<bool> = OnceLock::new();
/// pipeline_rt_cpumask 原值存档（十进制串；Some=已启用，清空/关闭时写回）。
static RT_CPUMASK_SAVED: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// 是否 opt-in 启用 pipeline_immuned_thread（白名单线程可上 prime）。默认关。
static IMMUNED_OPT: AtomicBool = AtomicBool::new(false);
/// 要写入 pipeline_immuned_thread 的名单串（形如 "name1;name2"，各 ≤15 字节由内核截断）。
static IMMUNED_NAMES: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(String::new()));
/// pipeline_immuned_thread 节点是否可用。
static IMMUNED_OK: OnceLock<bool> = OnceLock::new();
/// pipeline_immuned_thread 原值存档（Some=已启用，清空/关闭时写回；空名单写 ";" 清空）。
static IMMUNED_SAVED: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// 是否 opt-in 启用 pipeline_args。默认关。web 端切换、AppOpt.json 持久化。
static ARGS_OPT: AtomicBool = AtomicBool::new(false);
/// pipeline_args 三参(内核默认 30/400/1)。
static ARGS_LOWLAT: AtomicI32 = AtomicI32::new(30);
static ARGS_NOPIPE: AtomicI32 = AtomicI32::new(400);
static ARGS_DISLIKE: AtomicI32 = AtomicI32::new(1);
/// pipeline_args 节点是否可用。
static ARGS_OK: OnceLock<bool> = OnceLock::new();
/// pipeline_args 原值存档("<low> <nopipe> <dislike>"；Some=已启用，清空/关闭时写回)。
static ARGS_SAVED: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

// -------------------------- pipeline (:p) ----------------------------------

/// 解析 pipeline 写入节点（OPLUS 官方优先，回落 appopt 通用 .ko）；首次调用探测并缓存。
fn pipeline_node() -> Option<&'static str> {
    // 实时探测(不缓存):OPLUS 官方节点内核常驻,但通用 ko 的 /proc/sched_opt/pipeline_pids_cpus
    // 可能在守护进程启动后才 insmod。缓存首次结果会让 ko 后加载时 :p 永久 no-op(auto/ko 线路)。
    let ex = [Path::new(PIPELINE_NODES[0]).exists(), Path::new(PIPELINE_NODES[1]).exists()];
    match route() {
        1 => None,                                 // walt 线路:pipeline 交 WALT sched_pipeline,这里不走
        2 => ex[0].then_some(PIPELINE_NODES[0]),    // oplus 一加官方
        3 => ex[1].then_some(PIPELINE_NODES[1]),    // ko 通用模块
        _ => {
            // auto:先 OPLUS 官方,回落 ko
            if ex[0] {
                Some(PIPELINE_NODES[0])
            } else if ex[1] {
                Some(PIPELINE_NODES[1])
            } else {
                None
            }
        }
    }
}

/// pipeline 落地是否可用（OPLUS 官方节点，或已加载通用 appopt_sched.ko）
pub fn available() -> bool {
    pipeline_node().is_some()
}

/// 按当前 MEMBERS 重写 pipeline_pids_cpus 整表（空表写 CLEAR 清空）。
fn flush(members: &HashMap<i32, (i32, u32)>) {
    if members.is_empty() {
        if let Some(node) = pipeline_node() {
            let _ = fs::write(node, CLEAR);
        }
        rearrange_restore(); // pipeline 清空 → 还原各 opt-in 旋钮
        rt_cpumask_restore();
        immuned_restore();
        args_restore();
        return;
    }
    // HashMap 迭代序不确定，成员数 > MAX_PIPELINE_TASKS 时每次 flush 选中的子集会漂移；
    // 按 tid 升序取前 N，保证选择稳定、不来回换（换核会抖动，得不偿失）。
    let mut entries: Vec<(&i32, &(i32, u32))> = members.iter().collect();
    entries.sort_unstable_by_key(|(tid, _)| **tid);
    let mut s = String::new();
    for (tid, (_pid, cpu)) in entries.into_iter().take(MAX_PIPELINE_TASKS) {
        if !s.is_empty() {
            s.push(SEP);
        }
        s.push_str(&tid.to_string());
        s.push(SEP);
        s.push_str(&cpu.to_string());
    }
    if let Some(node) = pipeline_node() {
        let _ = fs::write(node, &s);
    }
    rearrange_enable(); // pipeline 有成员 + -P 开启 → 开动态换 prime(仅 ≥2 线程内核才真换)
    rt_cpumask_enable(); // pipeline 有成员 + opt 开启 → 施加 RT 避核掩码
    immuned_enable(); // pipeline 有成员 + opt 开启 → 施加白名单线程
    args_enable(); // pipeline 有成员 + opt 开启 → 施加 pipeline_args(prime 容忍度/dislike)
}

/// 把线程纳入 pipeline 并重排到目标核（tid→cpu）。pipeline_pids_cpus 不依赖 game_pid（内核源确认），
/// 故此处不注册 game_pid（game_pid 由 skip 锁按运行中的 :p 包统一管理）。非 OPLUS 为 no-op。
pub fn pipeline_apply(tid: i32, pid: i32, cpu: u32) {
    if !available() {
        return;
    }
    let mut m = lock_ignore_poison(&MEMBERS);
    if m.get(&tid) == Some(&(pid, cpu)) {
        return; // 未变化，避免每周期重写整表
    }
    m.insert(tid, (pid, cpu));
    flush(&m);
}

/// 把线程移出 pipeline（未登记则 no-op）；表空时清空节点。
pub fn pipeline_restore(tid: i32) {
    if !available() {
        return;
    }
    let mut m = lock_ignore_poison(&MEMBERS);
    if m.remove(&tid).is_none() {
        return;
    }
    flush(&m);
}

/// 周期性强制重写 pipeline_pids_cpus 整表（供 affinity_sync 每周期调用）。
/// pipeline_pids_cpus 是【全局单表】，会被内核场景切换 / OEM 游戏 HAL / 其它写者清空或覆盖；
/// 而 pipeline_apply 按 MEMBERS 去重、不重写"已在册未变"的 tid，于是表被外部清掉后我方不再补写，
/// 表现为切后台再切回 :p 失效。故每周期无条件重刷（仅在有成员时），使 :p 像 affinity 一样自愈。
pub fn pipeline_resync() {
    if !available() {
        return;
    }
    let m = lock_ignore_poison(&MEMBERS);
    if !m.is_empty() {
        flush(&m);
    }
}

/// 清空全部 pipeline 成员（配置变更、退出、暂停时调用）。
pub fn pipeline_restore_all() {
    if !available() {
        return;
    }
    {
        let mut m = lock_ignore_poison(&MEMBERS);
        if !m.is_empty() {
            m.clear();
            if let Some(node) = pipeline_node() {
                let _ = fs::write(node, CLEAR);
            }
        }
    }
    rearrange_restore();
    rt_cpumask_restore();
    immuned_restore();
    args_restore();
}

// -------------------- pipeline_prime_rearrange(opt-in) ----------------------

/// CLI `-P` / web 端「OPLUS 动态换 prime」：启用“动态换 prime”。默认关。
/// 关闭时立即还原 pipeline_prime_rearrange 原值（若曾被我们改过；否则 no-op）。
pub fn set_rearrange_opt(on: bool) {
    REARRANGE_OPT.store(on, Ordering::Release);
    if !on {
        rearrange_restore();
    }
}

/// CLI `-S` / web 端「OPLUS skip 锁」：启用 skip_gameself 进程级锁。默认关。
/// 关闭时先 game_lock_reset() 清锁（此时 SKIP_OPT 仍为 true，门控放行 → 写 skip=0/game_pid=-1），
/// 再存 false；顺序要紧：先清后存。开启时直接存 true。
pub fn set_skip_opt(on: bool) {
    if on {
        SKIP_OPT.store(true, Ordering::Release);
    } else {
        game_lock_reset();
        SKIP_OPT.store(false, Ordering::Release);
    }
}

/// 当前是否已启用 pipeline 动态换 prime（-P）。
pub fn rearrange_opt_enabled() -> bool {
    REARRANGE_OPT.load(Ordering::Acquire)
}

/// 组装 pipeline_prime_rearrange 写入串 "<mode> <amp> <cnt>"。
fn rearrange_value() -> String {
    format!(
        "{} {} {}",
        REARRANGE_MODE.load(Ordering::Acquire),
        REARRANGE_AMP.load(Ordering::Acquire),
        REARRANGE_CNT.load(Ordering::Acquire)
    )
}

/// 设置 pipeline_prime_rearrange 的 mode/amp/cnt（web 端 / 启动持久值）。仅暂存到原子量；
/// 若当前已启用（-P 开 + 节点在 + 已有存档=正在生效）则立即用新值重写，使调整即时生效。
pub fn set_rearrange_value(mode: i32, amp: i32, cnt: i32) {
    REARRANGE_MODE.store(mode, Ordering::Release);
    REARRANGE_AMP.store(amp, Ordering::Release);
    REARRANGE_CNT.store(cnt, Ordering::Release);
    if REARRANGE_OPT.load(Ordering::Acquire)
        && rearrange_available()
        && lock_ignore_poison(&REARRANGE_SAVED).is_some()
    {
        let _ = fs::write(PRIME_REARRANGE, rearrange_value());
    }
}

pub fn rearrange_mode() -> i32 {
    REARRANGE_MODE.load(Ordering::Acquire)
}
pub fn rearrange_amp() -> i32 {
    REARRANGE_AMP.load(Ordering::Acquire)
}
pub fn rearrange_cnt() -> i32 {
    REARRANGE_CNT.load(Ordering::Acquire)
}

/// pipeline_prime_rearrange 节点在本机是否存在（供 web 端提示是否可用）。
pub fn rearrange_node_available() -> bool {
    rearrange_available()
}

/// 当前是否已启用 skip_gameself 进程级锁（-S）。
pub fn skip_opt_enabled() -> bool {
    SKIP_OPT.load(Ordering::Acquire)
}

fn rearrange_available() -> bool {
    *REARRANGE_OK.get_or_init(|| Path::new(PRIME_REARRANGE).exists())
}

/// 开启动态换 prime：读原值存档后写当前可调值(默认 "1 51 10")。仅 -P 开启 + 节点在 + 尚未启用时执行；
/// 读不到原值则不启用（无法安全还原）。幂等。
fn rearrange_enable() {
    if !REARRANGE_OPT.load(Ordering::Acquire) || !rearrange_available() {
        return;
    }
    let mut saved = lock_ignore_poison(&REARRANGE_SAVED);
    if saved.is_some() {
        return; // 已启用
    }
    let Ok(orig) = fs::read_to_string(PRIME_REARRANGE) else {
        return;
    };
    if fs::write(PRIME_REARRANGE, rearrange_value()).is_ok() {
        *saved = Some(orig.trim().to_string());
    }
}

/// 还原 pipeline_prime_rearrange 到原值（未启用则 no-op）。
fn rearrange_restore() {
    if !rearrange_available() {
        return;
    }
    let mut saved = lock_ignore_poison(&REARRANGE_SAVED);
    if let Some(orig) = saved.take() {
        let _ = fs::write(PRIME_REARRANGE, &orig);
    }
}

// -------------------- pipeline_rt_cpumask(opt-in) --------------------------

fn rt_cpumask_available() -> bool {
    *RT_CPUMASK_OK.get_or_init(|| Path::new(PIPELINE_RT_CPUMASK).exists())
}

/// web 端 / 启动持久值：设置 RT 避核开关与掩码。关闭时立即还原；开启且当前正在生效(有 pipeline
/// 成员=已存档)时立即用新掩码重写。真正的“首次施加”由 flush(有成员) 调 rt_cpumask_enable 完成。
pub fn set_rt_cpumask(on: bool, mask: u64) {
    RT_CPUMASK_OPT.store(on, Ordering::Release);
    RT_CPUMASK_VAL.store(mask, Ordering::Release);
    if !on {
        rt_cpumask_restore();
    } else if rt_cpumask_available() && lock_ignore_poison(&RT_CPUMASK_SAVED).is_some() {
        let _ = fs::write(PIPELINE_RT_CPUMASK, mask.to_string());
    }
}

pub fn rt_cpumask_opt_enabled() -> bool {
    RT_CPUMASK_OPT.load(Ordering::Acquire)
}
pub fn rt_cpumask_val() -> u64 {
    RT_CPUMASK_VAL.load(Ordering::Acquire)
}
pub fn rt_cpumask_node_available() -> bool {
    rt_cpumask_available()
}

/// 施加 RT 避核掩码：读原值存档后写当前掩码。仅 opt 开 + 节点在 + 尚未施加时执行；幂等。
/// 原值读回是 "0x<hex>"，而写处理按十进制解析，故把原值解析成数值、以十进制存，还原时以十进制写回，
/// 避免把 "0x.." 直接写回被内核 kstrtoint(base10) 拒绝导致还原失败。
fn rt_cpumask_enable() {
    if !RT_CPUMASK_OPT.load(Ordering::Acquire) || !rt_cpumask_available() {
        return;
    }
    let mut saved = lock_ignore_poison(&RT_CPUMASK_SAVED);
    if saved.is_some() {
        return; // 已施加
    }
    let orig_dec = fs::read_to_string(PIPELINE_RT_CPUMASK)
        .ok()
        .map(|s| {
            let t = s.trim();
            let v = t
                .strip_prefix("0x")
                .or_else(|| t.strip_prefix("0X"))
                .and_then(|h| u64::from_str_radix(h, 16).ok())
                .or_else(|| t.parse::<u64>().ok())
                .unwrap_or(0);
            v.to_string()
        })
        .unwrap_or_else(|| "0".to_string());
    let mask = RT_CPUMASK_VAL.load(Ordering::Acquire);
    if fs::write(PIPELINE_RT_CPUMASK, mask.to_string()).is_ok() {
        *saved = Some(orig_dec);
    }
}

/// 还原 pipeline_rt_cpumask 到原值（未施加则 no-op）。
fn rt_cpumask_restore() {
    if !rt_cpumask_available() {
        return;
    }
    let mut saved = lock_ignore_poison(&RT_CPUMASK_SAVED);
    if let Some(orig) = saved.take() {
        let _ = fs::write(PIPELINE_RT_CPUMASK, &orig);
    }
}

// -------------------- pipeline_immuned_thread(opt-in) ----------------------

fn immuned_available() -> bool {
    *IMMUNED_OK.get_or_init(|| Path::new(PIPELINE_IMMUNED).exists())
}

/// web 端 / 启动持久值：设置白名单开关与名单串("name1;name2")。关闭立即还原；开启且已生效时立即重写。
pub fn set_immuned(on: bool, names: String) {
    IMMUNED_OPT.store(on, Ordering::Release);
    *lock_ignore_poison(&IMMUNED_NAMES) = names.clone();
    if !on {
        immuned_restore();
    } else if immuned_available() && lock_ignore_poison(&IMMUNED_SAVED).is_some() {
        let _ = fs::write(PIPELINE_IMMUNED, immuned_write_str(&names));
    }
}

pub fn immuned_opt_enabled() -> bool {
    IMMUNED_OPT.load(Ordering::Acquire)
}
pub fn immuned_names() -> String {
    lock_ignore_poison(&IMMUNED_NAMES).clone()
}
pub fn immuned_node_available() -> bool {
    immuned_available()
}

/// 空名单写 ";" 以清空(内核 sscanf 对空段解析为清空)；非空原样写。
fn immuned_write_str(names: &str) -> String {
    if names.trim().is_empty() {
        ";".to_string()
    } else {
        names.to_string()
    }
}

/// 施加白名单线程：读原值存档后写当前名单。仅 opt 开 + 节点在 + 尚未施加时执行；幂等。
fn immuned_enable() {
    if !IMMUNED_OPT.load(Ordering::Acquire) || !immuned_available() {
        return;
    }
    let mut saved = lock_ignore_poison(&IMMUNED_SAVED);
    if saved.is_some() {
        return;
    }
    let orig = fs::read_to_string(PIPELINE_IMMUNED)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let names = lock_ignore_poison(&IMMUNED_NAMES).clone();
    if fs::write(PIPELINE_IMMUNED, immuned_write_str(&names)).is_ok() {
        *saved = Some(orig);
    }
}

/// 还原 pipeline_immuned_thread 到原值（未施加则 no-op）；原名单为空则写 ";" 清空。
fn immuned_restore() {
    if !immuned_available() {
        return;
    }
    let mut saved = lock_ignore_poison(&IMMUNED_SAVED);
    if let Some(orig) = saved.take() {
        let w = if orig.trim().is_empty() { ";".to_string() } else { orig };
        let _ = fs::write(PIPELINE_IMMUNED, &w);
    }
}

// -------------------- pipeline_args(opt-in) --------------------------------

fn args_available() -> bool {
    *ARGS_OK.get_or_init(|| Path::new(PIPELINE_ARGS).exists())
}

/// 组装 pipeline_args 写入串 "<low> <nopipe> <dislike>"。
fn args_value() -> String {
    format!(
        "{} {} {}",
        ARGS_LOWLAT.load(Ordering::Acquire),
        ARGS_NOPIPE.load(Ordering::Acquire),
        ARGS_DISLIKE.load(Ordering::Acquire)
    )
}

/// web 端 / 启动持久值：设置 pipeline_args 开关与三参。关闭立即还原；开启且已生效时立即重写。
pub fn set_pipeline_args(on: bool, lowlat: i32, nopipe: i32, dislike: i32) {
    ARGS_OPT.store(on, Ordering::Release);
    ARGS_LOWLAT.store(lowlat, Ordering::Release);
    ARGS_NOPIPE.store(nopipe, Ordering::Release);
    ARGS_DISLIKE.store(if dislike != 0 { 1 } else { 0 }, Ordering::Release);
    if !on {
        args_restore();
    } else if args_available() && lock_ignore_poison(&ARGS_SAVED).is_some() {
        let _ = fs::write(PIPELINE_ARGS, args_value());
    }
}

pub fn pipeline_args_opt_enabled() -> bool {
    ARGS_OPT.load(Ordering::Acquire)
}
pub fn pipeline_args_lowlat() -> i32 {
    ARGS_LOWLAT.load(Ordering::Acquire)
}
pub fn pipeline_args_nopipe() -> i32 {
    ARGS_NOPIPE.load(Ordering::Acquire)
}
pub fn pipeline_args_dislike() -> i32 {
    ARGS_DISLIKE.load(Ordering::Acquire)
}
pub fn pipeline_args_node_available() -> bool {
    args_available()
}

/// 施加 pipeline_args：读原值存档后写当前三参。仅 opt 开 + 节点在 + 尚未施加时执行；幂等。
/// 原值读回形如 "30 400 1, prime_cpu_num=1"，故只解析前 3 个整数以便还原时按十进制写回。
fn args_enable() {
    if !ARGS_OPT.load(Ordering::Acquire) || !args_available() {
        return;
    }
    let mut saved = lock_ignore_poison(&ARGS_SAVED);
    if saved.is_some() {
        return;
    }
    let orig = fs::read_to_string(PIPELINE_ARGS)
        .ok()
        .map(|s| {
            let nums: Vec<&str> = s
                .split(|c: char| !c.is_ascii_digit())
                .filter(|t| !t.is_empty())
                .take(3)
                .collect();
            if nums.len() == 3 {
                nums.join(" ")
            } else {
                "30 400 1".to_string()
            }
        })
        .unwrap_or_else(|| "30 400 1".to_string());
    if fs::write(PIPELINE_ARGS, args_value()).is_ok() {
        *saved = Some(orig);
    }
}

/// 还原 pipeline_args 到原值（未施加则 no-op）。
fn args_restore() {
    if !args_available() {
        return;
    }
    let mut saved = lock_ignore_poison(&ARGS_SAVED);
    if let Some(orig) = saved.take() {
        let _ = fs::write(PIPELINE_ARGS, &orig);
    }
}

// ----------------------- skip_gameself 锁 ----------------------------------

/// skip 锁是否可用（game_pid + skip 两节点都在）。自动探测，非 OPLUS/无节点 → false → 全程 no-op。
fn lock_available() -> bool {
    *LOCK_OK.get_or_init(|| Path::new(SKIP).exists() && Path::new(GAME_PID).exists())
}

/// 按当前运行中的 :p 包 pid 同步锁状态（幂等，仅在变化时写）：
///   Some(pid) → 注册 game_pid=pid + skip=1（内核忽略该游戏对自己线程的 sched_setaffinity）
///   None      → skip=0 + game_pid=-1（解锁）
/// 内核钩子按 tgid==game_pid 门控，故必须先写 game_pid 再写 skip。主循环每周期调用。
pub fn game_lock_sync(fg_game_pid: Option<i32>) {
    if !SKIP_OPT.load(Ordering::Acquire) || !lock_available() {
        return;
    }
    let mut locked = lock_ignore_poison(&LOCKED_PID);
    if *locked == fg_game_pid {
        return;
    }
    match fg_game_pid {
        Some(pid) => {
            let _ = fs::write(GAME_PID, pid.to_string());
            let _ = fs::write(SKIP, "1");
        }
        None => {
            let _ = fs::write(SKIP, "0");
            let _ = fs::write(GAME_PID, "-1");
        }
    }
    *locked = fg_game_pid;
}

/// 无条件清空一加锁节点到干净状态（skip=0、game_pid=-1），并重置内部锁记录。
/// 不受 game_lock_sync 门控影响：用于【启动时】清除上次非正常退出(SIGKILL/崩溃/强杀)
/// 残留的 game_pid/skip——否则残留的旧 game_pid 会让 skip 锁与实际运行的 :p 包错位。
/// 内核 game_pid 写处理对任何值都先释放旧注册，故写 -1 即安全解除。非 OPLUS/无节点为 no-op。
pub fn game_lock_reset() {
    // 未开启 -S 时完全不碰 game_pid/skip（不干扰 OEM HAL）。
    if !SKIP_OPT.load(Ordering::Acquire) || !lock_available() {
        return;
    }
    let _ = fs::write(SKIP, "0");
    let _ = fs::write(GAME_PID, "-1");
    *lock_ignore_poison(&LOCKED_PID) = None;
}

/// 解锁并注销 game_pid（退出时调用）。等价于无条件清空。
pub fn game_lock_restore_all() {
    game_lock_reset();
}
