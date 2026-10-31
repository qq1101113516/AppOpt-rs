use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

use crate::lock_ignore_poison;

/// 是否已放宽 RT 带宽限流（-r / web 端「RT 带宽放宽」旋钮，默认关）。
/// 系统级旋钮，可运行期切换：置位并 program_rt_knobs，复位并 restore_rt_knobs。
pub static RT_RELAX: AtomicBool = AtomicBool::new(false);

/// RT 旋钮原值存档（None=从未启用过；Some=已捕获原值，可安全还原）。
/// 首次 program_rt_knobs 前捕获 rr_timeslice_ms / rt_period_us / rt_runtime_us 的原值。
#[allow(clippy::type_complexity)]
static RT_SAVED: LazyLock<Mutex<Option<Vec<(&'static str, String)>>>> =
    LazyLock::new(|| Mutex::new(None));

/// 调度策略，来自配置 CPU 规格后缀 :FIFO:n / :RR:n / :nice:n
#[derive(Clone, Copy)]
pub enum SchedPolicy {
    Fifo(i32), // SCHED_FIFO，rtprio 1..99
    Rr(i32),   // SCHED_RR，rtprio 1..99
    Nice(i32), // SCHED_OTHER，nice -20..19
}

/// 被改动线程的原始调度状态。SCHED_SAVED 即“安全标识”：只有登记在册的 tid 才会被还原，
/// 退出/配置变更时全部还原，绝不触碰我们没设置过的线程。
#[derive(Clone, Copy)]
struct Saved {
    policy: i32,
    priority: i32,
    nice: i32,
}

static SCHED_SAVED: LazyLock<Mutex<HashMap<i32, Saved>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 从配置值拆出 (cpus 规格, 可选调度策略)。无后缀则策略为 None
pub fn split_sched(spec: &str) -> (&str, Option<SchedPolicy>) {
    // 用 split 而非 splitn(3)：取 cpus / kind / 值 三段，忽略多余尾段。否则 splitn 会把
    // "nice:-5:垃圾" 的 "-5:垃圾" 整体当值 → 解析失败回落成 0，把合法的 -5 丢掉。
    let mut it = spec.split(':');
    let cpus = it.next().unwrap_or(spec).trim();
    let Some(kind) = it.next() else {
        return (cpus, None);
    };
    let param: i32 = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let policy = match kind.trim().to_ascii_uppercase().as_str() {
        "FIFO" => Some(SchedPolicy::Fifo(param.clamp(1, 99))),
        "RR" => Some(SchedPolicy::Rr(param.clamp(1, 99))),
        "NICE" => Some(SchedPolicy::Nice(param.clamp(-20, 19))),
        _ => None,
    };
    (cpus, policy)
}

/// 放宽 RT 带宽限流，配合 :RR/:FIFO 使用：内核默认 RT 组限流会掐住实时线程导致卡顿。
/// 旋钮——rr_timeslice=3ms；先解开 runtime(-1)以规避 runtime<=period 约束，
/// 再设 period=31000us、runtime=30200us。全局旋钮、有一定风险，仅在 -r 显式开启时调用。
/// 首次写入前捕获原值到 RT_SAVED（供关闭时 restore_rt_knobs 还原）。
pub fn program_rt_knobs() {
    // 首次启用前捕获原值：读 /proc/sys/kernel/sched_<k> 去空白后存档
    {
        let mut saved = lock_ignore_poison(&RT_SAVED);
        if saved.is_none() {
            let mut orig: Vec<(&'static str, String)> = Vec::with_capacity(3);
            for knob in ["rr_timeslice_ms", "rt_period_us", "rt_runtime_us"] {
                let path = format!("/proc/sys/kernel/sched_{}", knob);
                let val = std::fs::read_to_string(&path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                orig.push((knob, val));
            }
            *saved = Some(orig);
        }
    }

    let steps: [(&str, &str); 4] = [
        ("rr_timeslice_ms", "3"),
        ("rt_runtime_us", "-1"),
        ("rt_period_us", "31000"),
        ("rt_runtime_us", "30200"),
    ];
    for (knob, val) in steps {
        let path = format!("/proc/sys/kernel/sched_{}", knob);
        if std::fs::write(&path, val).is_ok() {
            println!("设置 RT 旋钮 {} = {}", knob, val);
        }
    }
}

/// 还原 RT 旋钮到启用前的原值（未启用过则 no-op）。为规避 runtime<=period 约束，
/// 先写 rt_runtime_us=-1 解开限流，再依次写回 rt_period_us、rt_runtime_us、rr_timeslice_ms 的原值
/// （空值跳过）。还原后清空 RT_SAVED，下次启用会重新捕获。
pub fn restore_rt_knobs() {
    let saved = lock_ignore_poison(&RT_SAVED).take();
    let Some(orig) = saved else {
        return;
    };
    // 先解开 runtime 限制以避开 runtime<=period 约束
    let _ = std::fs::write("/proc/sys/kernel/sched_rt_runtime_us", "-1");
    // 按 period → runtime → rr_timeslice 的顺序写回原值，跳过空捕获值
    let order = ["rt_period_us", "rt_runtime_us", "rr_timeslice_ms"];
    for knob in order {
        if let Some((_, val)) = orig.iter().find(|(k, _)| *k == knob) {
            if val.is_empty() {
                continue;
            }
            let path = format!("/proc/sys/kernel/sched_{}", knob);
            if std::fs::write(&path, val).is_ok() {
                println!("还原 RT 旋钮 {} = {}", knob, val);
            }
        }
    }
}

/// 运行期切换 RT 带宽放宽：on → program_rt_knobs()；off → restore_rt_knobs()。
pub fn set_rt_relax(on: bool) {
    RT_RELAX.store(on, Ordering::Release);
    if on {
        program_rt_knobs();
    } else {
        restore_rt_knobs();
    }
}

/// 读取 tid 当前调度状态，线程已退出返回 None
fn capture(tid: i32) -> Option<Saved> {
    // musl 把 sched_getscheduler/sched_getparam 桩为 ENOSYS，必须走裸 syscall
    let policy = unsafe { libc::syscall(libc::SYS_sched_getscheduler, tid as libc::c_long) };
    if policy < 0 {
        return None;
    }
    let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
    unsafe {
        libc::syscall(
            libc::SYS_sched_getparam,
            tid as libc::c_long,
            &mut param as *mut libc::sched_param,
        );
    }
    // getpriority 返回 -1 既可能是合法 nice(-1) 也可能是出错(errno 置位)：先清 errno，
    // 调用后按 errno 区分。出错(如线程刚退出)则用默认 nice 0 兜底，避免把错误的 -1 当原值存下、
    // 退出还原时反倒把线程 nice 设成 -1。
    unsafe {
        *libc::__errno_location() = 0;
    }
    let raw_nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, tid as libc::id_t) };
    let nice = if raw_nice == -1 && std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != 0
    {
        0
    } else {
        raw_nice
    };
    Some(Saved {
        policy: policy as i32,
        priority: param.sched_priority,
        nice,
    })
}

/// 设置调度策略，返回 true 表示线程已退出(ESRCH)。
/// 一律带 SCHED_RESET_ON_FORK：fork 出的子线程不继承本策略（不续承到同名/子线程）。
fn set_policy(tid: i32, p: SchedPolicy) -> bool {
    let (pol, prio, nice) = match p {
        SchedPolicy::Fifo(n) => (libc::SCHED_FIFO, n, None),
        SchedPolicy::Rr(n) => (libc::SCHED_RR, n, None),
        SchedPolicy::Nice(n) => (libc::SCHED_OTHER, 0, Some(n)),
    };
    // musl 的 sched_param 含额外 sched_ss_* 字段，用 zeroed 再赋值以跨 libc 通用
    let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
    param.sched_priority = prio;
    // musl 把 sched_setscheduler 桩为 ENOSYS，必须走裸 syscall
    let rc = unsafe {
        libc::syscall(
            libc::SYS_sched_setscheduler,
            tid as libc::c_long,
            (pol | libc::SCHED_RESET_ON_FORK) as libc::c_long,
            &param as *const libc::sched_param,
        )
    };
    if rc < 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    }
    if let Some(n) = nice {
        unsafe { libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, n) };
    }
    false
}

/// 还原一个 tid 的原始调度（对已退出线程为无害的 no-op）
fn restore_one(tid: i32, s: Saved) {
    let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
    param.sched_priority = s.priority;
    unsafe {
        libc::syscall(
            libc::SYS_sched_setscheduler,
            tid as libc::c_long,
            s.policy as libc::c_long,
            &param as *const libc::sched_param,
        );
        libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, s.nice);
    }
}

/// 应用调度策略，首次改动前登记原始状态（供退出/配置变更时还原）
pub fn sched_apply(tid: i32, p: SchedPolicy) {
    use std::collections::hash_map::Entry;
    let mut map = lock_ignore_poison(&SCHED_SAVED);
    // 读不到原始调度也不阻止设置：用默认（还原为 SCHED_OTHER）兜底
    if let Entry::Vacant(e) = map.entry(tid) {
        e.insert(capture(tid).unwrap_or(Saved {
            policy: libc::SCHED_OTHER,
            priority: 0,
            nice: 0,
        }));
    }
    // set 返回线程已退出(ESRCH)时撤销登记
    if set_policy(tid, p) {
        map.remove(&tid);
    }
}

/// 还原并注销单个 tid（未登记则无操作）
pub fn sched_restore(tid: i32) {
    let saved = lock_ignore_poison(&SCHED_SAVED).remove(&tid);
    if let Some(s) = saved {
        restore_one(tid, s);
    }
}

/// 还原全部被改动线程（配置变更、退出时调用）
pub fn sched_restore_all() {
    let saved: Vec<(i32, Saved)> = lock_ignore_poison(&SCHED_SAVED).drain().collect();
    for (tid, s) in saved {
        restore_one(tid, s);
    }
}
