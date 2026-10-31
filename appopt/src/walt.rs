use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;

use crate::lock_ignore_poison;

// =============================================================================
//  walt.rs —— 高通 WALT(Window Assisted Load Tracking) 全局调度 sysctl 旋钮。
//  两个 opt-in 数值旋钮（web 端调，AppOpt.json 持久化）：
//    · /proc/sys/walt/sched_min_task_util_for_boost   任务 util ≥ 此值才够格触发 boost
//    · /proc/sys/walt/sched_min_task_util_for_uclamp  任务 util ≥ 此值才够格吃 uclamp
//  兄弟节点 sched_min_task_util_for_colocation 已由 reverse/ 的 OEM gameopt 确证在同目录。
//  内核默认约 51(util 0-1024)，调低 => 更多任务够格 => 更激进。
//
//  这是【全局】旋钮（影响整机所有任务，非单游戏），故与 sched.rs 的 RT 旋钮同款处理：
//  opt-in、首次写入前存原值、关闭/退出还原、节点缺失(非 WALT 机型)全程 no-op。
// =============================================================================

struct WaltKnob {
    path: &'static str,
    /// 是否启用（opt-in，默认关）
    on: AtomicBool,
    /// 启用时写入的目标值（util，0-1024）
    val: AtomicI32,
    /// 原值存档：Some=已改过(可安全还原)；None=从未启用/已还原
    saved: Mutex<Option<String>>,
}

impl WaltKnob {
    const fn new(path: &'static str) -> Self {
        Self {
            path,
            on: AtomicBool::new(false),
            val: AtomicI32::new(51),
            saved: Mutex::new(None),
        }
    }

    fn available(&self) -> bool {
        Path::new(self.path).exists()
    }

    /// 应用当前值：首次前捕获原值到 saved，再写入目标值（值变化时也走这里重写）。
    /// 未启用 / 节点缺失 / 读不到原值(无法安全还原) 时不动。
    fn apply(&self) {
        if !self.on.load(Ordering::Acquire) || !self.available() {
            return;
        }
        let mut saved = lock_ignore_poison(&self.saved);
        if saved.is_none() {
            let Ok(orig) = std::fs::read_to_string(self.path) else {
                return;
            };
            *saved = Some(orig.trim().to_string());
        }
        let _ = std::fs::write(self.path, self.val.load(Ordering::Acquire).to_string());
    }

    /// 还原到启用前的原值（未启用过则 no-op）。还原后清空存档，下次启用重新捕获。
    fn restore(&self) {
        if !self.available() {
            return;
        }
        let mut saved = lock_ignore_poison(&self.saved);
        if let Some(orig) = saved.take()
            && !orig.is_empty()
        {
            let _ = std::fs::write(self.path, &orig);
        }
    }

    /// 运行期设置：on → 存值并 apply；off → restore。值先钳到 0-1024。
    fn set(&self, on: bool, val: i32) {
        self.val.store(val.clamp(0, 1024), Ordering::Release);
        self.on.store(on, Ordering::Release);
        if on {
            self.apply();
        } else {
            self.restore();
        }
    }
}

static BOOST: WaltKnob = WaltKnob::new("/proc/sys/walt/sched_min_task_util_for_boost");
static UCLAMP: WaltKnob = WaltKnob::new("/proc/sys/walt/sched_min_task_util_for_uclamp");

pub fn set_boost(on: bool, val: i32) {
    BOOST.set(on, val);
}
pub fn set_uclamp(on: bool, val: i32) {
    UCLAMP.set(on, val);
}

pub fn boost_enabled() -> bool {
    BOOST.on.load(Ordering::Acquire)
}
pub fn uclamp_enabled() -> bool {
    UCLAMP.on.load(Ordering::Acquire)
}
pub fn boost_val() -> i32 {
    BOOST.val.load(Ordering::Acquire)
}
pub fn uclamp_val() -> i32 {
    UCLAMP.val.load(Ordering::Acquire)
}

pub fn boost_available() -> bool {
    BOOST.available()
}
pub fn uclamp_available() -> bool {
    UCLAMP.available()
}

/// 还原全部 WALT 旋钮到原值（退出清理调用）。
pub fn restore_all() {
    BOOST.restore();
    UCLAMP.restore();
}
