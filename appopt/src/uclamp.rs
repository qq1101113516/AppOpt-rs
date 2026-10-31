use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::lock_ignore_poison;

// =============================================================================
//  uclamp.rs —— per-task 利用率钳制(utilization clamping)
// -----------------------------------------------------------------------------
//  与写 /proc/sys/walt/* 的厂商提示(vendor_boost.rs)不同，uclamp 是【主线内核原生】
//  机制，通过 sched_setattr(2) 系统调用直接改线程的 uclamp 字段，【不写任何文件】：
//     - util_min 抬"性能地板"(0..=1024) → 线程一跑就把 CPU util 顶到至少该值 → 占大核+拉频
//     - util_max 封"频率顶"(0..=1024)   → 限制线程能拉起的算力 → 省电
//  高通(WALT)与联发科都遵循 uclamp；受系统级封顶 /proc/sys/kernel/sched_util_clamp_min[/max]
//  约束(默认 1024，即不限)。root 有 CAP_SYS_NICE，抬高 util_min 无权限问题。
//
//  存档还原：与 sched.rs 的 SCHED_SAVED 同理——首次改动前用 sched_getattr 读原值登记，
//  只有登记在册的 tid 才会被还原，退出/配置变更/暂停时全部还原，绝不碰未设置过的线程。
// =============================================================================

// uapi sched_attr.sched_flags 位（内核 include/uapi/linux/sched.h）
const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;

/// uclamp 合法上限
pub const UCLAMP_MAX: u32 = 1024;

/// uapi `struct sched_attr`。内核按 size 字段校验版本，务必置 size。
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
    sched_util_min: u32,
    sched_util_max: u32,
}

/// 被改动 tid 的原始 uclamp (util_min, util_max)；只还原登记在册的。
static UCLAMP_SAVED: LazyLock<Mutex<HashMap<i32, (u32, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 读取 tid 当前 uclamp，失败返回 None。musl 无 sched_getattr 封装，走裸 syscall。
fn capture(tid: i32) -> Option<(u32, u32)> {
    let mut attr = SchedAttr::default();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_sched_getattr,
            tid as libc::c_long,
            &mut attr as *mut SchedAttr,
            std::mem::size_of::<SchedAttr>() as libc::c_uint,
            0u32,
        )
    };
    if rc < 0 {
        None
    } else {
        Some((attr.sched_util_min, attr.sched_util_max))
    }
}

/// 施加 uclamp（min/max 各自可选，只改指定的那个）。首次改动前登记原值供还原。
/// 会在每个 affinity_sync 周期被重刷，抵消前后台切换的重置（与 sched_apply 一致）。
pub fn uclamp_apply(tid: i32, min: Option<u32>, max: Option<u32>) {
    use std::collections::hash_map::Entry;
    if min.is_none() && max.is_none() {
        return;
    }
    // 读不到原始 uclamp 也不阻止设置：用内核默认 (0, 1024) 兜底
    {
        let mut map = lock_ignore_poison(&UCLAMP_SAVED);
        if let Entry::Vacant(e) = map.entry(tid) {
            e.insert(capture(tid).unwrap_or((0, UCLAMP_MAX)));
        }
    }

    // RESET_ON_FORK：本线程 fork 出的子线程【不继承】uclamp——内核 uclamp_fork() 见此标志即把
    // 子线程的 uclamp 清回默认，否则 dup_task_struct 会把父的 uclamp_req 整块拷给子线程，导致
    // 我们抬了 util 的线程一 fork，worker 子线程就带着同样的 util 地板占大核。与 sched.rs 对
    // FIFO/RR/nice 用 SCHED_RESET_ON_FORK 一致。
    let mut flags = SCHED_FLAG_RESET_ON_FORK | SCHED_FLAG_KEEP_POLICY | SCHED_FLAG_KEEP_PARAMS;
    if min.is_some() {
        flags |= SCHED_FLAG_UTIL_CLAMP_MIN;
    }
    if max.is_some() {
        flags |= SCHED_FLAG_UTIL_CLAMP_MAX;
    }
    let attr = SchedAttr {
        size: std::mem::size_of::<SchedAttr>() as u32,
        sched_flags: flags,
        sched_util_min: min.unwrap_or(0),
        sched_util_max: max.unwrap_or(UCLAMP_MAX),
        ..Default::default()
    };
    // musl 无 sched_setattr 封装，走裸 syscall；第 3 参 flags 目前必须为 0
    let rc = unsafe {
        libc::syscall(
            libc::SYS_sched_setattr,
            tid as libc::c_long,
            &attr as *const SchedAttr,
            0u32,
        )
    };
    // 线程已退出(ESRCH)时撤销登记，避免残留
    if rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        lock_ignore_poison(&UCLAMP_SAVED).remove(&tid);
    }
}

/// 还原并注销单个 tid 的 uclamp（未登记则无操作）
pub fn uclamp_restore(tid: i32) {
    let saved = lock_ignore_poison(&UCLAMP_SAVED).remove(&tid);
    if let Some((min, max)) = saved {
        let attr = SchedAttr {
            size: std::mem::size_of::<SchedAttr>() as u32,
            sched_flags: SCHED_FLAG_KEEP_POLICY
                | SCHED_FLAG_KEEP_PARAMS
                | SCHED_FLAG_UTIL_CLAMP_MIN
                | SCHED_FLAG_UTIL_CLAMP_MAX,
            sched_util_min: min,
            sched_util_max: max,
            ..Default::default()
        };
        unsafe {
            libc::syscall(
                libc::SYS_sched_setattr,
                tid as libc::c_long,
                &attr as *const SchedAttr,
                0u32,
            );
        }
    }
}

/// 还原全部被改动线程的 uclamp（配置变更、退出时调用）
pub fn uclamp_restore_all() {
    let tids: Vec<i32> = lock_ignore_poison(&UCLAMP_SAVED).keys().copied().collect();
    for tid in tids {
        uclamp_restore(tid);
    }
}
