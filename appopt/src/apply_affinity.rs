use std::fs;
use std::io::Write as _;
use std::os::unix::fs::FileExt;

use crate::{MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::cpuset::{base_cpuset, CpuSet, CpuTopology};

/// 栈上构建 /proc/{pid}/{suffix} 路径读取文件
fn read_proc_file<'a>(pid: i32, suffix: &str, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    let mut path = [0u8; 32];
    let mut cur = std::io::Cursor::new(&mut path[..]);
    write!(cur, "/proc/{}/{}", pid, suffix).ok()?;
    let len = cur.position() as usize;
    let path_str = std::str::from_utf8(&path[..len]).ok()?;
    let file = fs::File::open(path_str).ok()?;
    let n = file.read_at(buf, 0).ok()?;
    (n > 0).then_some(&buf[..n])
}

pub(crate) fn read_cmdline(pid: i32) -> Option<String> {
    let mut buf = [0u8; MAX_PKG_LEN];
    let bytes = read_proc_file(pid, "cmdline", &mut buf)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let cmdline = std::str::from_utf8(&bytes[..end]).ok()?;
    let name = cmdline.rsplit('/').next().unwrap_or(cmdline);
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

pub(crate) fn tid_comm(tid: i32) -> Option<String> {
    let mut buf = [0u8; MAX_THREAD_LEN];
    let bytes = read_proc_file(tid, "comm", &mut buf)?;
    let end = bytes
        .iter()
        .position(|&b| b == 0 || b == b'\n')
        .unwrap_or(bytes.len());
    let name = std::str::from_utf8(&bytes[..end]).ok()?;
    Some(name.trim().to_string())
}

/// 读 /proc/{pid}/task 下全部 tid 栈上路径零堆分配
pub(crate) fn task_tids(pid: i32) -> Option<Vec<i32>> {
    let mut path_buf = [0u8; 32];
    let mut cur = std::io::Cursor::new(&mut path_buf[..]);
    write!(cur, "/proc/{}/task", pid).ok()?;
    let len = cur.position() as usize;
    let task_path = std::str::from_utf8(&path_buf[..len]).unwrap();
    let task_dir = fs::read_dir(task_path).ok()?;
    Some(
        task_dir
            .flatten()
            .filter_map(|tent| tent.file_name().to_string_lossy().parse::<i32>().ok())
            .collect(),
    )
}

/// 线程是否已在目标 cpuset：读 /proc/<tid>/cpuset(相对 cpuset 控制器根的路径)，比对末段是否等于
/// 期望目录名(cpuset_dir 非空取它，否则取 base cpuset 名)。读不到(无 cpuset 控制器/线程已退出)保守
/// 判否 → 走完整迁移路径(幂等，无害)。
fn in_target_cpuset(tid: i32, cpuset_dir: &str) -> bool {
    let base = base_cpuset();
    let want = if cpuset_dir.is_empty() {
        base.rsplit('/').next().unwrap_or("")
    } else {
        cpuset_dir
    };
    match fs::read_to_string(format!("/proc/{}/cpuset", tid)) {
        Ok(s) => s.trim().rsplit('/').next() == Some(want),
        Err(_) => false,
    }
}

/// 对单线程应用亲和性，返回 true 表示 ESRCH 线程已退出
pub fn affinity_set(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: &str,
    topo: &CpuTopology,
) -> bool {
    // 空 cpus = "不绑核"规则(如 =:boost，仅施加 per-task 提示)：不动线程亲和/cpuset。
    if cpus.count() == 0 {
        return false;
    }

    // 零开销返回需【掩码相等 且 已在目标 cpuset】。仅比掩码不够：线程掩码可能是我方掩码⊂某受限
    // cpuset(如 top-app 全核)的情形——此时被系统迁进 top-app 后有效掩码不变(交集仍是我方掩码)，
    // 只比掩码会漏掉 cpuset 迁移、丢失 cpuset 硬边界(游戏可 setaffinity 逃逸)。故掩码相等时再核
    // /proc/<tid>/cpuset 末段是否为目标目录名；不一致则继续走下面的 cpuset 迁移。get_affinity 先算、
    // 短路 &&：掩码不等时不读 cpuset，稳态多一次小读、修好归属后仍回到零写路径。
    if CpuSet::get_affinity(tid).is_some_and(|curr| curr.bits == cpus.bits)
        && (!topo.cpuset_enabled || in_target_cpuset(tid, cpuset_dir))
    {
        return false;
    }

    if topo.cpuset_enabled {
        let tasks_path = if cpuset_dir.is_empty() {
            format!("{}/tasks", base_cpuset())
        } else {
            format!("{}/{}/tasks", base_cpuset(), cpuset_dir)
        };
        let _ = fs::OpenOptions::new()
            .append(true)
            .open(&tasks_path)
            .and_then(|mut f| writeln!(f, "{}", tid));
    }

    if let Err(e) = cpus.set_affinity(tid) {
        return e.raw_os_error() == Some(libc::ESRCH);
    }

    false
}
