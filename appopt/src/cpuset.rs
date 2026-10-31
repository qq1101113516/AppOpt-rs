use std::ffi::CString;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::sync::RwLock;

pub const CPU_SETSIZE: usize = 1024;
pub const CPU_WORD_BITS: usize = 64;
pub const CPU_WORDS: usize = CPU_SETSIZE / CPU_WORD_BITS;

pub const DEFAULT_CPUSET_NAME: &str = "AppOpt";

/// BASE_CPUSET 运行时路径，web 端可热更新，未设置时默认 /dev/cpuset/AppOpt
static BASE_CPUSET_PATH: RwLock<Option<String>> = RwLock::new(None);

/// 校验 cpuset 目录名：仅允许 `[A-Za-z0-9_-]` 单段、非空、长度 < 64。
/// 借此排除 `/`(路径分隔)、`.`/`..`(目录穿越——如 `..` 会让 `/dev/cpuset/..` 逃逸到 `/dev`，
/// 随后 create_cpuset_dir 对逃逸目标 chmod/chown/写文件，root 运行下危害严重)、空白与控制字符。
pub fn valid_cpuset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// 设置 BASE_CPUSET 目录名；非法名(空 / 含 `/` `.` `..` / 非安全字符)一律忽略、保持默认，绝不据此拼路径。
pub fn set_base_cpuset(name: &str) {
    if !valid_cpuset_name(name) {
        return;
    }
    *BASE_CPUSET_PATH.write().unwrap() = Some(format!("/dev/cpuset/{}", name));
}

/// 获取 BASE_CPUSET 路径，未设置返回默认值
pub fn base_cpuset() -> String {
    BASE_CPUSET_PATH
        .read()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "/dev/cpuset/AppOpt".to_string())
}

/// 把守护进程自身丢进 background cpuset(通常只含小核)+降低普通调度优先级(nice +10)，避免优化器
/// 自己去抢大核、跟被优化的游戏争算力。尽力而为：无 /dev/cpuset/background 或非 Android 时静默跳过。
pub fn demote_self() {
    let pid = unsafe { libc::getpid() };
    let _ = fs::write("/dev/cpuset/background/tasks", pid.to_string());
    unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, 10) };
}

// CpuSet 直接以 *const libc::cpu_set_t 传给 sched_[gs]etaffinity，二者字节大小必须一致
const _: () = assert!(std::mem::size_of::<CpuSet>() == std::mem::size_of::<libc::cpu_set_t>());

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct CpuSet {
    pub bits: [u64; CPU_WORDS],
}

impl CpuSet {
    pub fn new() -> Self {
        CpuSet::default()
    }

    pub fn set(&mut self, cpu: usize) {
        if cpu < CPU_SETSIZE {
            self.bits[cpu / CPU_WORD_BITS] |= 1u64 << (cpu % CPU_WORD_BITS);
        }
    }

    pub fn is_set(&self, cpu: usize) -> bool {
        cpu < CPU_SETSIZE && self.bits[cpu / CPU_WORD_BITS] & (1u64 << (cpu % CPU_WORD_BITS)) != 0
    }

    pub fn count(&self) -> usize {
        self.bits.iter().map(|&b| b.count_ones() as usize).sum()
    }

    /// 集合内最高编号的核（空集返回 None）。OPLUS pipeline 选“目标大核/超大核”用：
    /// 手机拓扑里核号越高频率簇越高，故最高位≈prime。
    pub fn highest(&self) -> Option<usize> {
        for (word_idx, &word) in self.bits.iter().enumerate().rev() {
            if word != 0 {
                let top = CPU_WORD_BITS - 1 - word.leading_zeros() as usize;
                return Some(word_idx * CPU_WORD_BITS + top);
            }
        }
        None
    }

    pub fn or(&mut self, other: &CpuSet) {
        for (d, &s) in self.bits.iter_mut().zip(other.bits.iter()) {
            *d |= s;
        }
    }

    /// 转换为范围字符串
    pub fn to_range_string(self) -> String {
        let mut result = String::new();
        let mut start: Option<usize> = None;
        let mut end: Option<usize> = None;
        let mut first = true;

        for (word_idx, &word) in self.bits.iter().enumerate() {
            if word == 0 {
                if start.is_some() {
                    push_range(&mut result, start, end, &mut first);
                    start = None;
                    end = None;
                }
                continue;
            }
            let base = word_idx * CPU_WORD_BITS;
            for bit in 0..CPU_WORD_BITS {
                if word & (1u64 << bit) != 0 {
                    let cpu = base + bit;
                    if start.is_none() {
                        start = Some(cpu);
                        end = Some(cpu);
                    } else if end.is_some_and(|e| cpu == e + 1) {
                        end = Some(cpu);
                    } else {
                        push_range(&mut result, start, end, &mut first);
                        start = Some(cpu);
                        end = Some(cpu);
                    }
                }
            }
        }
        push_range(&mut result, start, end, &mut first);
        result
    }

    pub fn get_affinity(tid: i32) -> Option<CpuSet> {
        let mut curr = CpuSet::new();
        let ret = unsafe {
            libc::sched_getaffinity(
                tid,
                std::mem::size_of::<CpuSet>(),
                &mut curr as *mut CpuSet as *mut libc::cpu_set_t,
            )
        };
        if ret == -1 {
            None
        } else {
            Some(curr)
        }
    }

    pub fn set_affinity(&self, tid: i32) -> io::Result<()> {
        let ret = unsafe {
            libc::sched_setaffinity(
                tid,
                std::mem::size_of::<CpuSet>(),
                self as *const CpuSet as *const libc::cpu_set_t,
            )
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn push_range(s: &mut String, start: Option<usize>, end: Option<usize>, first: &mut bool) {
    if let (Some(lo), Some(hi)) = (start, end) {
        if !*first {
            s.push(',');
        }
        if lo == hi {
            let _ = write!(s, "{}", lo);
        } else {
            let _ = write!(s, "{}-{}", lo, hi);
        }
        *first = false;
    }
}

/// 解析 CPU 范围字符串
pub fn parse_cpu_ranges(spec: &str, present: Option<&CpuSet>) -> CpuSet {
    let mut set = CpuSet::new();
    if spec.is_empty() {
        return set;
    }
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (lo, hi) = if let Some(pos) = part.find('-') {
            // 区间两端都必须是合法数字；任一端解析失败就整段跳过——不再把失败端静默回落成
            // 另一端（否则 "0-x" 会被悄悄当成 "0-0" 绑错核）。
            let (Ok(a), Ok(b)) = (
                part[..pos].parse::<usize>(),
                part[pos + 1..].parse::<usize>(),
            ) else {
                continue;
            };
            if a > b {
                (b, a)
            } else {
                (a, b)
            }
        } else {
            let Ok(a) = part.parse::<usize>() else {
                continue;
            };
            (a, a)
        };
        for i in lo..=hi.min(CPU_SETSIZE - 1) {
            if present.is_some_and(|p| !p.is_set(i)) {
                continue;
            }
            set.set(i);
        }
    }
    set
}

/// 解析 CPU 规格，支持语义核心名(e-core/p-core/hp-core)与数字范围混合
pub fn parse_cpu_spec(spec: &str, topo: &CpuTopology) -> CpuSet {
    let mut set = CpuSet::new();
    if spec.is_empty() {
        return set;
    }
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // 语义名展开为对应核心层，其余按数字范围解析
        let seg = match part {
            "e-core" => &topo.e_core,
            "p-core" => &topo.p_core,
            "hp-core" => &topo.hp_core,
            "all-core" => &topo.present_cpus,
            _ => {
                set.or(&parse_cpu_ranges(part, Some(&topo.present_cpus)));
                continue;
            }
        };
        set.or(seg);
    }
    set
}

/// 创建 cpuset 子目录并写入 cpus 与 mems
pub(crate) fn create_cpuset_dir(path: &str, cpus: &str, mems: &str) -> bool {
    let c_path = CString::new(path).expect("cpuset path 受控输入，无 NUL");
    let ret = unsafe { libc::mkdir(c_path.as_ptr(), 0o755) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return false;
        }
    }
    // 纵深防御：目标必须是【真实目录且非符号链接】，否则后续 chmod/chown/写会作用到意外目标
    // (chmod/chown 会跟随软链)。lstat 不跟随软链——是软链则 st_mode=S_IFLNK≠S_IFDIR → 拒绝；
    // 普通文件等非目录同样拒绝。名字已限制为 [A-Za-z0-9_-] 单段、路径固定在 /dev/cpuset 之下，
    // 此处再挡软链/非目录，双保险。
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c_path.as_ptr(), &mut st) } != 0 {
        return false;
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return false;
    }
    if unsafe { libc::chmod(c_path.as_ptr(), 0o755) } != 0 {
        return false;
    }
    if unsafe { libc::chown(c_path.as_ptr(), 0, 0) } != 0 {
        return false;
    }
    let cpus_path = format!("{}/cpus", path);
    if fs::write(&cpus_path, cpus).is_err() {
        return false;
    }
    let mems_path = format!("{}/mems", path);
    fs::write(&mems_path, mems).is_ok()
}

/// 按合并后的 CPU 集合确保 cpuset 子目录存在，返回目录名（cpuset 未启用或创建失败返回空串）
pub fn ensure_cpuset_dir(cpus: &CpuSet, topo: &CpuTopology) -> String {
    if !topo.cpuset_enabled {
        return String::new();
    }
    let dir_name = cpus.to_range_string();
    let path = format!("{}/{}", base_cpuset(), dir_name);
    // create_cpuset_dir 已处理 EEXIST，重复调用幂等
    if create_cpuset_dir(&path, &dir_name, &topo.mems_str) {
        dir_name
    } else {
        String::new()
    }
}

#[derive(Clone)]
pub struct CpuTopology {
    pub present_cpus: CpuSet,
    pub present_str: String,
    pub mems_str: String,
    pub cpuset_enabled: bool,
    /// 语义核心分层：最低频为 e-core，最高频为 hp-core，中间为 p-core
    pub e_core: CpuSet,
    pub p_core: CpuSet,
    pub hp_core: CpuSet,
    /// 按 cpufreq 策略分出的【全部簇】，按频率升序(簇 0=最小核簇 … 末簇=超大核簇)。
    /// 与内核 cpu_topology.cluster_id 顺序一致，供 HMBIRD prefer_cluster 的簇掩码换算。
    pub clusters: Vec<CpuSet>,
}

impl CpuTopology {
    /// 把 CPU 集合换算成【簇掩码】：cpus 命中哪个簇就置该簇的位。供 :pcl(prefer_cluster)用。
    pub fn cluster_mask_for(&self, cpus: &CpuSet) -> u64 {
        let mut mask = 0u64;
        for (i, cl) in self.clusters.iter().enumerate() {
            if i >= 64 {
                break;
            }
            // 簇与目标集合有交集即置位(任一 word 相与非零)
            if cl.bits.iter().zip(cpus.bits.iter()).any(|(&a, &b)| a & b != 0) {
                mask |= 1u64 << i;
            }
        }
        mask
    }
}

/// 按 cpufreq 策略检测核心分层，按最高频率升序分组：首组为 e-core，末组为 hp-core，中间为 p-core。
/// 同时返回按频率升序的【全部簇】(每个 cpufreq 策略一簇)，供 prefer_cluster 簇掩码换算。
fn detect_core_types() -> (CpuSet, CpuSet, CpuSet, Vec<CpuSet>) {
    let mut groups: Vec<(u64, Vec<usize>)> = Vec::new();
    // 读取每个 policy 的 related_cpus 与 cpuinfo_max_freq，按频率合并同组
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu/cpufreq") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("policy"))
            {
                continue;
            }
            let freq: u64 = fs::read_to_string(path.join("cpuinfo_max_freq"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            if freq == 0 {
                continue;
            }
            let cpus: Vec<usize> = fs::read_to_string(path.join("related_cpus"))
                .ok()
                .map(|s| s.split_whitespace().filter_map(|c| c.parse().ok()).collect())
                .unwrap_or_default();
            if cpus.is_empty() {
                continue;
            }
            if let Some(g) = groups.iter_mut().find(|(f, _)| *f == freq) {
                g.1.extend(cpus);
            } else {
                groups.push((freq, cpus));
            }
        }
    }
    groups.sort_by_key(|(f, _)| *f);
    let mut e = CpuSet::new();
    let mut p = CpuSet::new();
    let mut h = CpuSet::new();
    let n = groups.len();
    for (i, (_, cpus)) in groups.iter().enumerate() {
        // 首组入 e-core，末组入 hp-core，其余入 p-core
        let target = if i == 0 {
            &mut e
        } else if i == n - 1 {
            &mut h
        } else {
            &mut p
        };
        for &cpu in cpus {
            target.set(cpu);
        }
    }
    // 全部簇按频率升序，每簇一个 CpuSet（簇 0=最小核簇 … 末簇=超大核簇）
    let clusters: Vec<CpuSet> = groups
        .iter()
        .map(|(_, cpus)| {
            let mut s = CpuSet::new();
            for &c in cpus {
                s.set(c);
            }
            s
        })
        .collect();
    (e, p, h, clusters)
}

/// 初始化 CPU 拓扑，检测 cpuset 可用性并创建 BASE_CPUSET 目录
pub fn init_cpu_topo() -> CpuTopology {
    let mut topo = CpuTopology {
        present_cpus: CpuSet::new(),
        present_str: String::new(),
        mems_str: String::new(),
        cpuset_enabled: false,
        e_core: CpuSet::new(),
        p_core: CpuSet::new(),
        hp_core: CpuSet::new(),
        clusters: Vec::new(),
    };

    if let Ok(content) = fs::read_to_string("/sys/devices/system/cpu/present") {
        topo.present_str = content.trim().to_string();
    }
    topo.present_cpus = parse_cpu_ranges(&topo.present_str, None);
    let (e, p, h, clusters) = detect_core_types();
    topo.e_core = e;
    topo.p_core = p;
    topo.hp_core = h;
    topo.clusters = clusters;

    let cpuset_path = CString::new("/dev/cpuset").expect("常量字符串无 NUL");
    if unsafe { libc::access(cpuset_path.as_ptr(), libc::F_OK) } != 0 {
        return topo;
    }

    // mems 继承父 cpuset /dev/cpuset/mems（旧代码从新建的子目录回读，恒为写入的 "0"，
    // 在多 NUMA/多内存节点设备上是错的）；读不到再兜底 "0"
    topo.mems_str = fs::read_to_string("/dev/cpuset/mems")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "0".to_string());

    if create_cpuset_dir(&base_cpuset(), &topo.present_str, &topo.mems_str) {
        topo.cpuset_enabled = true;
    }

    topo
}


#[cfg(test)]
mod tests {
    use super::valid_cpuset_name;

    #[test]
    fn test_valid_cpuset_name_rejects_traversal_and_unsafe() {
        // 合法：仅 [A-Za-z0-9_-]
        assert!(valid_cpuset_name("AppOpt"));
        assert!(valid_cpuset_name("my_set-1"));
        // 非法：空 / 目录穿越 / 路径分隔 / 点 / 空白 / 控制字符 / 超长
        assert!(!valid_cpuset_name(""));
        assert!(!valid_cpuset_name("."));
        assert!(!valid_cpuset_name(".."), "..(会逃逸到 /dev)必须被拒绝");
        assert!(!valid_cpuset_name("a/b"));
        assert!(!valid_cpuset_name("../evil"));
        assert!(!valid_cpuset_name("a.b"));
        assert!(!valid_cpuset_name("a b"));
        assert!(!valid_cpuset_name("a\tb"));
        assert!(!valid_cpuset_name(&"x".repeat(64)));
    }
}
