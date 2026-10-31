use std::collections::HashMap;
use std::fs;
use std::sync::{LazyLock, Mutex};

use crate::lock_ignore_poison;

// =============================================================================
//  timerslack.rs —— per-task 定时器松弛度(/proc/<tid>/timerslack_ns)
// -----------------------------------------------------------------------------
//  主线内核、全平台通吃(不挑高通/联发科)：内核把该线程的定时器/轮询唤醒在这个时间窗内
//  【合并】(coalescing)，单位纳秒。默认 50000(50µs)。
//     - 小值(如 0 / 1万ns) → 唤醒更准、砍掉批处理延迟 → 更跟手(适合主线程/渲染/输入线程)
//     - 大值(如 5千万ns=50ms) → 唤醒被大量合并 → 省电(适合后台/杂线程；Android 息屏即此招)
//
//  存档还原：与 uclamp.rs 的 UCLAMP_SAVED 同理——首次改动前读原值登记，只还原登记在册的
//  tid，退出/配置变更/暂停时全部还原，绝不碰未设置过的线程。
// =============================================================================

/// 内核默认 timerslack(读不到原值时的还原兜底)
const DEFAULT_SLACK_NS: u64 = 50_000;

/// 被改动 tid 的原始 timerslack_ns；只还原登记在册的。
static SAVED: LazyLock<Mutex<HashMap<i32, u64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn node(tid: i32) -> String {
    format!("/proc/{}/timerslack_ns", tid)
}

/// 读取 tid 当前 timerslack_ns，失败返回 None
fn capture(tid: i32) -> Option<u64> {
    fs::read_to_string(node(tid)).ok()?.trim().parse::<u64>().ok()
}

/// 施加 timerslack。首次改动前登记原值供还原(读不到用内核默认兜底)。
/// 会在每个 affinity_sync 周期被重刷，抵消前后台切换的重置(与其它 per-task 提示一致)。
pub fn timerslack_apply(tid: i32, ns: u64) {
    use std::collections::hash_map::Entry;
    {
        let mut map = lock_ignore_poison(&SAVED);
        if let Entry::Vacant(e) = map.entry(tid) {
            e.insert(capture(tid).unwrap_or(DEFAULT_SLACK_NS));
        }
    }
    // 写失败：仅当线程确已消失(ENOENT/ESRCH)才撤销登记，避免残留；其它瞬时错误(如写 0 触发 EINVAL)
    // 保留已存原值——否则下轮 Vacant 会把【当前(可能已是我方值)】误当原值重新捕获，退出还原时丢真原值。
    let gone = fs::write(node(tid), ns.to_string())
        .err()
        .and_then(|e| e.raw_os_error())
        .is_some_and(|c| c == libc::ENOENT || c == libc::ESRCH);
    if gone {
        lock_ignore_poison(&SAVED).remove(&tid);
    }
}

/// 还原并注销单个 tid 的 timerslack(未登记则无操作)
pub fn timerslack_restore(tid: i32) {
    if let Some(ns) = lock_ignore_poison(&SAVED).remove(&tid) {
        let _ = fs::write(node(tid), ns.to_string());
    }
}

/// fork 子线程去继承：把 timerslack 写回默认(不登记)。内核 copy_process 会把父线程的
/// timer_slack_ns 整块拷给子线程、且无 reset-on-fork 语义可挡，故只能在子线程的 FORK 事件里
/// 主动写回默认，抹掉从父继承的值。仅当配置用到 :slack 时由调用方触发。
pub fn timerslack_scrub(tid: i32) {
    let _ = fs::write(node(tid), DEFAULT_SLACK_NS.to_string());
}

/// 还原全部被改动线程的 timerslack(配置变更、退出时调用)
pub fn timerslack_restore_all() {
    let tids: Vec<i32> = lock_ignore_poison(&SAVED).keys().copied().collect();
    for tid in tids {
        timerslack_restore(tid);
    }
}
