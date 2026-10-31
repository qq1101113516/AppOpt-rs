use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

use crate::lock_ignore_poison;

// =============================================================================
//  hard.rs —— :ph 硬亲和(hard affinity)。写 appopt 通用 ko 的
//  /proc/sched_opt/hard_affinity(内核 set_cpus_allowed_ptr 把 cpus_allowed 锁死到目标核集)。
//
//  与 :pf(hmbird prefer_cpu 软偏好)的区别：:ph 是【硬锁】——所有调度类(CFS/sched_ext风驰)都
//  必须遵守,任何机型都钉得住,不受 RVH 单注册被 OEM 占用的影响。代价:改任务 cpumask(taskset 可见)。
//
//  仅本 ko 提供该节点(OPLUS/风驰原生无);节点不存在(未装 ko)则全程 no-op。
//  写 "<tid> <掩码hex>";0=解除并恢复原亲和。只还原【被我们设过】的 tid。
//  app 自己 set_affinity 会覆盖 → 配 ko 的 skip_self_setaffinity 使用。
// =============================================================================

const HARD_NODES: [&str; 1] = ["/proc/sched_opt/hard_affinity"];
/// 已施加硬亲和的 tid → 掩码。只还原登记在册的。
static HARD_SET: LazyLock<Mutex<HashMap<i32, u64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

// 实时探测(不缓存):KO 可能在守护进程启动后才 insmod;若缓存会把它永久记成不存在,
// 导致 :ph 永不写入。非热路径(仅规则应用 / affinity_sync 周期调用),stat 开销可忽略。
fn hard_node() -> Option<&'static str> {
    HARD_NODES.iter().copied().find(|p| Path::new(p).exists())
}

/// hard_affinity 节点是否存在(供 web 端提示是否可用)。
#[allow(dead_code)] // web 端集成时使用
pub fn available() -> bool {
    hard_node().is_some()
}

/// 对线程施加硬亲和(锁到掩码核集)并登记。掩码按 %x 写(ko sscanf "%d %x")。mask=0 视作解除。
/// 会被 affinity_sync 周期重刷,抵消前后台切换的重置。
pub fn hard_apply(tid: i32, mask: u64) {
    let Some(node) = hard_node() else {
        return;
    };
    if mask == 0 {
        hard_restore(tid);
        return;
    }
    if fs::write(node, format!("{} {:x}", tid, mask)).is_ok() {
        lock_ignore_poison(&HARD_SET).insert(tid, mask);
    }
}

/// 撤销单个 tid 的硬亲和(未登记则 no-op):写 "<tid> 0" 让 ko 恢复其原亲和。
pub fn hard_restore(tid: i32) {
    if lock_ignore_poison(&HARD_SET).remove(&tid).is_none() {
        return;
    }
    if let Some(node) = hard_node() {
        let _ = fs::write(node, format!("{} 0", tid));
    }
}

/// 还原全部被硬钉的线程(配置变更、退出、暂停时调用)。
pub fn hard_restore_all() {
    let tids: Vec<i32> = lock_ignore_poison(&HARD_SET).keys().copied().collect();
    for tid in tids {
        hard_restore(tid);
    }
}
