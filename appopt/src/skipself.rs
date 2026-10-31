use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

// =============================================================================
//  skipself.rs —— skip_self_setaffinity 全局开关(仅 appopt 通用 ko 提供)。
//
//  写 /proc/sched_opt/skip_self_setaffinity 的位掩码,让内核在 sched_setaffinity
//  【系统调用】路径上丢弃对【已被 appopt 登记(:p/:pf/:pcl/:pi/:pp 软偏好 或 :ph 硬亲和)
//  线程】的亲和修改,防止 app / 官方 HAL 用 sched_setaffinity 把我们贴好的核弹回去。
//
//    bit0(1)=拦 app 自己改自己已登记线程(current->tgid==p->tgid)
//    bit1(2)=debug:每次 setaffinity 打印拦/放(dmesg)
//    bit2(4)=拦【所有】外部调用者(含三方 / 官方 / appopt 自身)
//    bit3(8)=只拦【app-uid】调用者(10000..19999),放行系统 / 官方 —— 8750 做法
//  内核优先级 bit2 > bit3 > bit0。
//
//  仅本 ko 有此节点(OPLUS / 风驰原生无)。节点不存在(未装 ko)→ 全程 no-op,
//  内部仍记值供 web 回显。此为全局模块状态,写一次常驻,无需像 per-task 那样周期重刷。
//
//  注意:开 bit2(拦所有)会连 appopt 经 sched_setaffinity 的绑核一起拦掉;而 :pf/:pcl/:pi/:pp
//  软偏好走 prefer_* 节点、:ph 走 set_cpus_allowed_ptr —— 都不经 sched_setaffinity,故不受影响。
//  因此推荐 bit0(拦自己)或 bit3(仅三方 app),bit2 慎用。
// =============================================================================

const NODE: &str = "/proc/sched_opt/skip_self_setaffinity";
// 管理进程登记节点:把 AppOpt 自己的 pid 写进去, ko 便在 skip_self 拦截时放行它自己的
// sched_setaffinity —— 否则 bit2(拦全部)会把 AppOpt 设基础核范围的调用也一起拦掉。
const MANAGER_NODE: &str = "/proc/sched_opt/manager_pid";
static MODE: AtomicU8 = AtomicU8::new(0);

// 实时探测(不缓存):KO 可能在 AppOpt 守护进程启动【之后】才 insmod。若用 OnceLock 缓存,
// 会把"启动瞬间尚不存在"永久记成不可用 —— web 端一直显示"无此节点",set() 也永远 no-op。
// 一次 stat 开销极小,这里只在启动应用 / web GET / web 保存时调用,非热路径。
fn node_ok() -> bool {
    Path::new(NODE).exists()
}

/// 节点是否存在(供 web 端提示是否可用)。
pub fn available() -> bool {
    node_ok()
}

/// 设置位掩码并写节点(0=关闭)。节点不存在则只记内部值(no-op 写)。
/// 每次都顺带把本进程 pid 登记为管理进程(见 register_self),确保 bit2 下 AppOpt 自身被放行。
pub fn set(mode: u8) {
    MODE.store(mode, Ordering::Release);
    if node_ok() {
        register_self();
        let _ = fs::write(NODE, mode.to_string());
    }
}

/// 把本进程 pid(=tgid,主线程)登记为管理进程,让 ko 放行 AppOpt 自己的 sched_setaffinity。
/// 节点不存在(未装 ko / KO 后加载)则 no-op;实时探测,不缓存。
pub fn register_self() {
    if Path::new(MANAGER_NODE).exists() {
        let _ = fs::write(MANAGER_NODE, std::process::id().to_string());
    }
}

/// 当前位掩码(web 回显 / 持久化用)。
pub fn current() -> u8 {
    MODE.load(Ordering::Acquire)
}
