use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

use crate::lock_ignore_poison;
pub const PREFER_CPU_MASK_MAX: u64 = 0xff;
const PREFER_CPU_KO_MASK_MAX: u64 = 0xffff_ffff;
const PREFER_CPU_NODES: [&str; 2] = ["/proc/sys/hmbird_II/prefer_cpu", "/proc/sched_opt/prefer_cpu"];
const PREFER_CLUSTER_NODES: [&str; 2] = ["/proc/sys/hmbird_II/prefer_cluster", "/proc/sched_opt/prefer_cluster"];
const PREFER_IDLE_NODES: [&str; 2] = ["/proc/sys/hmbird_II/prefer_idle", "/proc/sched_opt/prefer_idle"];
const PREFER_PREEMPT_NODES: [&str; 2] = ["/proc/sys/hmbird_II/prefer_preempt", "/proc/sched_opt/prefer_preempt"];

/// 已设 prefer_cpu 的 tid → 掩码；已设 prefer_cluster 的 tid → 掩码。只还原登记在册的。
static PREFER_CPU_SET: LazyLock<Mutex<HashMap<i32, u64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static PREFER_CLUSTER_SET: LazyLock<Mutex<HashMap<i32, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// 已设 prefer_idle / prefer_preempt 的 tid 集合(0/1 标记，只记开启的)。
static PREFER_IDLE_SET: LazyLock<Mutex<HashSet<i32>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static PREFER_PREEMPT_SET: LazyLock<Mutex<HashSet<i32>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn first_existing(cands: &[&'static str]) -> Option<&'static str> {
    cands.iter().copied().find(|p| Path::new(p).exists())
}

fn prefer_cpu_node() -> Option<&'static str> {
    first_existing(&PREFER_CPU_NODES)
}
fn prefer_cluster_node() -> Option<&'static str> {
    first_existing(&PREFER_CLUSTER_NODES)
}
fn prefer_idle_node() -> Option<&'static str> {
    first_existing(&PREFER_IDLE_NODES)
}
fn prefer_preempt_node() -> Option<&'static str> {
    first_existing(&PREFER_PREEMPT_NODES)
}
/// prefer_idle 节点在本机是否存在。
pub fn prefer_idle_available() -> bool {
    prefer_idle_node().is_some()
}
/// prefer_preempt 节点在本机是否存在。
pub fn prefer_preempt_available() -> bool {
    prefer_preempt_node().is_some()
}

/// prefer_cpu 节点在本机是否存在(供 web 端提示是否可用)。
pub fn prefer_cpu_available() -> bool {
    prefer_cpu_node().is_some()
}
/// prefer_cluster 节点在本机是否存在。
pub fn prefer_cluster_available() -> bool {
    prefer_cluster_node().is_some()
}

/// 对线程施加 prefer_cpu(偏好核掩码)并登记。掩码按 %x 写(内核 sscanf "%d %x")。
/// mask=0 无意义(等于清除)，直接忽略。会被 affinity_sync 周期重刷，抵消前后台切换的重置。
pub fn prefer_cpu_apply(tid: i32, mask: u64) {
    let Some(node) = prefer_cpu_node() else {
        return;
    };
    // 按目标节点定上限:HMBIRD II 官方节点内核限 0xff(且该机型均 8 核);KO 回落节点按 32 位透传
    // (KO 内部再按在线核裁剪)→ >8 核设备走 KO 也能用到 cpu8+。
    let cap = if node == PREFER_CPU_NODES[0] {
        PREFER_CPU_MASK_MAX
    } else {
        PREFER_CPU_KO_MASK_MAX
    };
    let mask = mask & cap;
    if mask == 0 {
        return;
    }
    if fs::write(node, format!("{} {:x}", tid, mask)).is_ok() {
        lock_ignore_poison(&PREFER_CPU_SET).insert(tid, mask);
    }
}

/// 撤销单个 tid 的 prefer_cpu(未登记则 no-op)：写 "<tid> 0" 清除内核偏好。
pub fn prefer_cpu_restore(tid: i32) {
    if lock_ignore_poison(&PREFER_CPU_SET).remove(&tid).is_none() {
        return;
    }
    if let Some(node) = prefer_cpu_node() {
        let _ = fs::write(node, format!("{} 0", tid));
    }
}

/// 对线程施加 prefer_cluster(偏好簇掩码)并登记。掩码按 %x 写。mask=0 忽略。
pub fn prefer_cluster_apply(tid: i32, mask: u64) {
    let Some(node) = prefer_cluster_node() else {
        return;
    };
    if mask == 0 {
        return;
    }
    if fs::write(node, format!("{} {:x}", tid, mask)).is_ok() {
        lock_ignore_poison(&PREFER_CLUSTER_SET).insert(tid, mask);
    }
}

/// 撤销单个 tid 的 prefer_cluster(未登记则 no-op)。
pub fn prefer_cluster_restore(tid: i32) {
    if lock_ignore_poison(&PREFER_CLUSTER_SET).remove(&tid).is_none() {
        return;
    }
    if let Some(node) = prefer_cluster_node() {
        let _ = fs::write(node, format!("{} 0", tid));
    }
}

/// 对线程施加 prefer_idle(唤醒优先空闲核)并登记；写 "<tid> 1"(十进制)。
pub fn prefer_idle_apply(tid: i32) {
    let Some(node) = prefer_idle_node() else {
        return;
    };
    if fs::write(node, format!("{} 1", tid)).is_ok() {
        lock_ignore_poison(&PREFER_IDLE_SET).insert(tid);
    }
}

/// 撤销单个 tid 的 prefer_idle(未登记则 no-op)：写 "<tid> 0"。
pub fn prefer_idle_restore(tid: i32) {
    if !lock_ignore_poison(&PREFER_IDLE_SET).remove(&tid) {
        return;
    }
    if let Some(node) = prefer_idle_node() {
        let _ = fs::write(node, format!("{} 0", tid));
    }
}

/// 对线程施加 prefer_preempt(抢占倾向)并登记；写 "<tid> 1"。
pub fn prefer_preempt_apply(tid: i32) {
    let Some(node) = prefer_preempt_node() else {
        return;
    };
    if fs::write(node, format!("{} 1", tid)).is_ok() {
        lock_ignore_poison(&PREFER_PREEMPT_SET).insert(tid);
    }
}

/// 撤销单个 tid 的 prefer_preempt(未登记则 no-op)。
pub fn prefer_preempt_restore(tid: i32) {
    if !lock_ignore_poison(&PREFER_PREEMPT_SET).remove(&tid) {
        return;
    }
    if let Some(node) = prefer_preempt_node() {
        let _ = fs::write(node, format!("{} 0", tid));
    }
}

/// 还原全部被改动线程的 prefer_cpu/prefer_cluster/prefer_idle/prefer_preempt(配置变更、退出、暂停时调用)。
pub fn prefer_restore_all() {
    let cpu_tids: Vec<i32> = lock_ignore_poison(&PREFER_CPU_SET).keys().copied().collect();
    for tid in cpu_tids {
        prefer_cpu_restore(tid);
    }
    let cl_tids: Vec<i32> = lock_ignore_poison(&PREFER_CLUSTER_SET).keys().copied().collect();
    for tid in cl_tids {
        prefer_cluster_restore(tid);
    }
    let idle_tids: Vec<i32> = lock_ignore_poison(&PREFER_IDLE_SET).iter().copied().collect();
    for tid in idle_tids {
        prefer_idle_restore(tid);
    }
    let pre_tids: Vec<i32> = lock_ignore_poison(&PREFER_PREEMPT_SET).iter().copied().collect();
    for tid in pre_tids {
        prefer_preempt_restore(tid);
    }
}
