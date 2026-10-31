use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use crate::{lock_ignore_poison, CONFIG_UPDATED, MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::cpuset::{base_cpuset, create_cpuset_dir, parse_cpu_spec, CpuSet, CpuTopology};

pub static INOTIFY_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static INOTIFY_FD: AtomicI32 = AtomicI32::new(-1);
pub static INOTIFY_WD: AtomicI32 = AtomicI32::new(-1);

/// 运行时可调参数，web 端热更新
pub static CHECK_INTERVAL: AtomicU64 = AtomicU64::new(2);
pub static FORCE_RELOAD: AtomicBool = AtomicBool::new(false);
/// 当前生效的配置文件路径，web 端可热切换；main 启动时写入初始值
pub static CONFIG_FILE: Mutex<String> = Mutex::new(String::new());
/// 上次解析被跳过的规则条数，供 web /api/status 展示
pub static PARSE_FAILS: AtomicUsize = AtomicUsize::new(0);

/// 校验 CPU 规格形态(供 web 端提交规则前做形态校验)
pub fn spec_like(s: &str) -> bool {
    let mut any = false;
    for part in s.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        any = true;
        let ok = matches!(t, "e-core" | "p-core" | "hp-core" | "all-core")
            || t.bytes().all(|b| b.is_ascii_digit())
            || t.split_once('-').is_some_and(|(a, b)| {
                !a.is_empty()
                    && !b.is_empty()
                    && a.bytes().all(|b| b.is_ascii_digit())
                    && b.bytes().all(|b| b.is_ascii_digit())
            });
        if !ok {
            return false;
        }
    }
    any
}

pub fn comment_at(s: &str) -> Option<usize> {
    let mut prev_ws = false;
    for (i, c) in s.char_indices() {
        if prev_ws && (c == '#' || (c == '/' && s[i..].starts_with("//"))) {
            return Some(s[..i].trim_end().len());
        }
        prev_ws = c.is_whitespace();
    }
    None
}

pub fn strip_comment(s: &str) -> &str {
    &s[..comment_at(s).unwrap_or(s.len())]
}

pub fn split_rule_line(p: &str) -> Option<(&str, &str, bool)> {
    let p = strip_comment(p);
    fn kv(s: &str) -> Option<(&str, &str)> {
        s.rfind('=')
            .map(|eq| (s[..eq].trim(), s[eq + 1..].trim()))
            .filter(|(k, _)| !k.is_empty())
    }
    p.match_indices('}')
        .find_map(|(cb, _)| kv(&p[..cb]).map(|(k, v)| (k, v, true)))
        .or_else(|| kv(p).map(|(k, v)| (k, v, false)))
}

pub fn close_like(p: &str) -> bool {
    p.strip_prefix('}').is_some_and(|r| {
        r.is_empty() || r.starts_with(char::is_whitespace) || r.starts_with('#') || r.starts_with("//")
    })
}

pub fn split_single_line(body: &str) -> Option<(&str, &str, &str)> {
    let eq = body.rfind('=')?;
    let cpus = body[eq + 1..].trim();
    let left = body[..eq].trim_end().strip_suffix('}')?.trim_end();
    let ob = left.find('{')?;
    let (pkg, thread) = (left[..ob].trim(), left[ob + 1..].trim());
    (!pkg.is_empty() && !thread.is_empty()).then_some((pkg, thread, cpus))
}

pub enum OuterLine<'a> {
    // 本仓 load_config 沿用自有内联解析器(而非 parse_outer)，rule_edit 只读 pkg/thread/open；
    // 保留 cpus 字段与上游 parse_outer 形态一致(便于对照/后续复用)，此处显式允许其未被读取。
    Rule { pkg: &'a str, #[allow(dead_code)] cpus: &'a str, open: bool },
    BareOpen { pkg: &'a str },
    Pending { pkg: &'a str },
    Single { pkg: &'a str, thread: &'a str, #[allow(dead_code)] cpus: &'a str, open: bool },
    Junk,
}

pub fn parse_outer(p: &str) -> OuterLine<'_> {
    let p = strip_comment(p);
    let (open, body) = match p.strip_suffix('{') {
        Some(b) => (true, b.trim_end()),
        None => (false, p),
    };
    if let Some((pkg, thread, cpus)) = split_single_line(body) {
        return OuterLine::Single { pkg, thread, cpus, open };
    }
    if !open && close_like(body) {
        return OuterLine::Junk;
    }
    match body.rfind('=') {
        Some(eq) => {
            let (pkg, cpus) = (body[..eq].trim(), body[eq + 1..].trim());
            if cpus.is_empty() {
                return if open {
                    OuterLine::BareOpen { pkg }
                } else {
                    OuterLine::Pending { pkg }
                };
            }
            OuterLine::Rule { pkg, cpus, open }
        }
        None => {
            if open {
                OuterLine::BareOpen { pkg: body }
            } else {
                OuterLine::Pending { pkg: body }
            }
        }
    }
}

pub struct AffinityRule {
    pub pkg: String,
    pub thread: String,
    pub thread_pattern: CString,
    pub cpuset_dir: String,
    pub cpus: CpuSet,
    pub sched: Option<crate::sched::SchedPolicy>,
    /// 厂商 per-task boost level(来自 :boost:<level> 后缀)，None 表示不加 boost
    pub boost: Option<u32>,
    /// WALT reduce-affinity 掩码(来自 :reduce:<cpuspec> 后缀)，None 表示不施加
    pub reduce: Option<u64>,
    /// 低延迟标记(来自 :ll 后缀，sched_low_latency)
    pub low_latency: bool,
    /// 任务负载 boost 值(来自 :loadboost:<val> 后缀，task_load_boost)
    pub load_boost: Option<u32>,
    /// 追加的 per-task WALT 提示：(节点, 值)，来自 :p / :w / :g 后缀
    pub walt: Vec<(&'static str, u32)>,
    /// :m —— 同名线程全绑(仅线程规则有意义)
    pub same_name: bool,
    /// per-task uclamp 地板/顶(来自 :umin:<v> / :umax:<v>)
    pub uclamp_min: Option<u32>,
    pub uclamp_max: Option<u32>,
    /// :slack:<ns> —— per-task 定时器松弛度(timerslack_ns)
    pub timerslack: Option<u64>,
    /// :p —— 流水线任务标记。OPLUS 机型据此把线程注册进 pipeline_pids_cpus 贴大核(见 oplus.rs)。
    pub pipeline: bool,
    /// :p:<cpu> —— OPLUS pipeline 的显式目标核。None 表示由绑定掩码最高核决定(见 cache::resolve_pipeline_cpu)。
    pub pipeline_cpu: Option<u32>,
    /// :pf:<cpuspec> —— HMBIRD(_II) prefer_cpu 偏好核掩码(& 0xff)。None 表示不施加。
    pub prefer_cpu: Option<u64>,
    /// :ph:<cpuspec> —— 硬亲和核掩码(写 ko hard_affinity 锁死)。None 表示不施加。
    pub hard_cpu: Option<u64>,
    /// :pcl:<cpuspec> —— HMBIRD(_II) prefer_cluster 偏好簇掩码。None 表示不施加。
    pub prefer_cluster: Option<u64>,
    /// :pi —— HMBIRD(_II) prefer_idle(唤醒优先空闲核)。
    pub prefer_idle: bool,
    /// :pp —— HMBIRD(_II) prefer_preempt(抢占倾向)。
    pub prefer_preempt: bool,
    /// 规则 `=` 后的原始 spec 文本(含全部后缀，如 "3-7:boost:2:p")。供 WebUI 编辑时原样回填，
    /// 避免只拿到解析后的 CPU 而丢后缀。
    pub raw_spec: String,
    /// 该规则在配置文件里的 0 基行号。供 WebUI「临时启停」按行号加/去注释(见 web.rs rule_toggle)。
    pub line: usize,
}

pub struct AppConfig {
    pub rules: Vec<AffinityRule>,
    pub pkgs: HashSet<String>,
    pub has_thread_rules: HashSet<String>,
    /// 含 :p 流水线规则的包。OPLUS skip_gameself 锁仅对这些包生效(见 main 主循环)。
    pub pipeline_pkgs: HashSet<String>,
    pub topo: CpuTopology,
}

/// 当前生效配置，主循环与配置加载线程共享
pub static CURRENT_CONFIG: Mutex<Option<Arc<AppConfig>>> = Mutex::new(None);

/// 添加规则，包级规则创建 cpuset 子目录，线程规则目录由匹配时按合并集合创建
fn add_rule(
    rules: &mut Vec<AffinityRule>,
    topo: &CpuTopology,
    pkg: &str,
    thread: &str,
    cpus_spec: &str,
    line: usize,
) -> bool {
    if pkg.len() >= MAX_PKG_LEN || thread.len() >= MAX_THREAD_LEN {
        return false;
    }
    // 保存 `=` 后的原始 spec 全文(含后缀)供 WebUI 回填；下面 cpus_spec 会被重绑为 CPU-only 部分。
    let raw_spec = cpus_spec.trim().to_string();
    // 先剥离厂商 :boost:<level> / :reduce:<cpuspec>(与调度后缀顺序无关)，再剥离
    // :FIFO:n / :RR:n / :nice:n，剩下的才是 CPU 规格
    let (rest, vendor) = crate::vendor_boost::split_vendor(cpus_spec);
    let (cpus_spec, sched) = crate::sched::split_sched(&rest);
    let set = parse_cpu_spec(cpus_spec, topo);
    // 允许"省略 CPU 规格、只带后缀"的规则(如 com.x{T}=:boost:2 / =:umin:512 / =:slack:1)：
    // 不绑核、只施加 per-task 提示。仅当【既没核也没任何提示】才判为空规则拒绝。
    // (:m 是匹配作用域标记、非可施加提示，故不算数——单独 =:m 无意义，按空规则拒绝。)
    let has_hint = sched.is_some()
        || vendor.boost.is_some()
        || vendor.reduce_spec.is_some()
        || vendor.low_latency
        || vendor.load_boost.is_some()
        || !vendor.walt.is_empty()
        || vendor.uclamp_min.is_some()
        || vendor.uclamp_max.is_some()
        || vendor.timerslack.is_some()
        || vendor.pipeline
        || vendor.prefer_cpu_spec.is_some()
        || vendor.hard_cpu_spec.is_some()
        || vendor.prefer_cluster_spec.is_some()
        || vendor.prefer_idle
        || vendor.prefer_preempt;
    if set.count() == 0 && !has_hint {
        return false;
    }
    // reduce 的 cpuspec 复用亲和解析(支持 e/p/hp-core 与数字范围)，取低 64 位作为掩码值
    let reduce = vendor
        .reduce_spec
        .map(|s| parse_cpu_spec(&s, topo).bits[0]);
    // :pf 偏好核：解析成 CPU 掩码低位；掩码为 0 视作无效丢弃。
    // 上限【不在此处截】——由 hmbird.rs 按目标节点定(HMBIRD II 内核限 0xff；KO 按在线核自裁),
    // 故这里保留完整掩码,以支持 >8 核设备走 KO 时用到 cpu8+。
    let prefer_cpu = vendor
        .prefer_cpu_spec
        .as_ref()
        .map(|s| parse_cpu_spec(s, topo).bits[0])
        .filter(|&m| m != 0);
    // :ph 硬亲和：解析成 CPU 掩码低 64 位(不 &0xff,ko 侧自会按在线核裁剪)；0 丢弃
    let hard_cpu = vendor
        .hard_cpu_spec
        .as_ref()
        .map(|s| parse_cpu_spec(s, topo).bits[0])
        .filter(|&m| m != 0);
    // :pcl 偏好簇：解析成 CPU 集合后按拓扑换算成簇掩码；为 0(没命中任何簇)则丢弃
    let prefer_cluster = vendor
        .prefer_cluster_spec
        .as_ref()
        .map(|s| topo.cluster_mask_for(&parse_cpu_spec(s, topo)))
        .filter(|&m| m != 0);
    // 线程规则目录延迟到 thread_affinity 合并后创建，避免冗余空目录
    let cpuset_dir = if thread.is_empty() {
        let dir_name = set.to_range_string();
        if topo.cpuset_enabled {
            let path = format!("{}/{}", base_cpuset(), dir_name);
            if create_cpuset_dir(&path, &dir_name, &topo.mems_str) {
                dir_name
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    // 内核 comm 上限 15 字节(TASK_COMM_LEN-1)，超长线程名会被截断。把匹配用的 pattern 截到
    // 15 字节(取 char 边界，避免切断多字节)，使规则里写全名(如 Unity 的 "UnityGfxDeviceWorker"，
    // 实际 comm 为 "UnityGfxDeviceW")也能命中；≤15 的名字与 glob 前缀不受影响。
    let mut cut = thread.len().min(15);
    while cut > 0 && !thread.is_char_boundary(cut) {
        cut -= 1;
    }
    rules.push(AffinityRule {
        pkg: pkg.to_string(),
        thread: thread.to_string(),
        thread_pattern: CString::new(&thread[..cut]).unwrap_or_default(),
        cpuset_dir,
        cpus: set,
        sched,
        boost: vendor.boost,
        reduce,
        low_latency: vendor.low_latency,
        load_boost: vendor.load_boost,
        walt: vendor.walt,
        same_name: vendor.same_name,
        uclamp_min: vendor.uclamp_min,
        uclamp_max: vendor.uclamp_max,
        timerslack: vendor.timerslack,
        pipeline: vendor.pipeline,
        pipeline_cpu: vendor.pipeline_cpu,
        prefer_cpu,
        hard_cpu,
        prefer_cluster,
        prefer_idle: vendor.prefer_idle,
        prefer_preempt: vendor.prefer_preempt,
        raw_spec,
        line,
    });
    true
}

/// 加载配置文件，返回 None 表示未变化或解析失败
pub fn load_config(
    config_file: &str,
    topo: &CpuTopology,
    last_mtime: &mut i64,
) -> Option<AppConfig> {
    let metadata = fs::metadata(config_file).ok()?;
    let mtime = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos() as i64;

    if *last_mtime == mtime && *last_mtime != -1 {
        return None;
    }

    let content = fs::read_to_string(config_file).ok()?;

    let mut rules: Vec<AffinityRule> = Vec::new();
    let mut fail_cnt: usize = 0;
    let mut cur_pkg = String::new();
    let mut pending_pkg = String::new();
    let mut in_block = false;

    for (lineno, line) in content.lines().enumerate() {
        let p = line.trim();
        if p.is_empty() || p.starts_with('#') || p.starts_with("//") {
            continue;
        }
        // 剥离行尾注释后再解析（与 rule_edit / parse_outer 的 strip_comment 语义一致：#、// 需前置空白）。
        // 否则 `=0-3 # 注释` 会把 "0-3 # 注释" 整体喂给 parse_cpu_spec，被 parse_cpu_ranges 的
        // unwrap_or 静默回落成错核（如只绑 CPU 0），且 PARSE_FAILS 不计——运行时与 WebUI 解析器语义分叉。
        // strip_comment 已 trim_end 到注释前、无注释时返回本就 trim 过的原串，无需再 trim/判空。
        let p = strip_comment(p);

        if in_block {
            let mut block_end = false;
            let content_part = if let Some(close_br) = p.find('}') {
                block_end = true;
                p[..close_br].trim()
            } else {
                p
            };

            if !content_part.is_empty() {
                if let Some(eq) = content_part.find('=') {
                    let thread = content_part[..eq].trim();
                    let cpus = content_part[eq + 1..].trim();
                    if !add_rule(&mut rules, topo, &cur_pkg, thread, cpus, lineno) {
                        fail_cnt += 1;
                    }
                } else {
                    fail_cnt += 1;
                }
            }

            if block_end {
                in_block = false;
                cur_pkg.clear();
            }
            continue;
        }

        let sep_pos = match p.find(['=', '{']) {
            Some(pos) => pos,
            None => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pending_pkg.clear();
                continue;
            }
        };

        let sep_char = p.as_bytes()[sep_pos] as char;
        let before = p[..sep_pos].trim();
        let after = p[sep_pos + 1..].trim();

        if sep_char == '{' {
            let pkg = before;
            if let Some(eb) = after.find('}') {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                    pending_pkg.clear();
                }
                let thread = after[..eb].trim();
                let rest = after[eb + 1..].trim();
                if let Some(eq) = rest.find('=') {
                    let cpus = rest[eq + 1..].trim();
                    let tail_br = cpus.find('{');
                    if let Some(tb) = tail_br {
                        let cpus_only = cpus[..tb].trim();
                        if !cpus_only.is_empty()
                            && !add_rule(&mut rules, topo, pkg, thread, cpus_only, lineno)
                        {
                            fail_cnt += 1;
                        }
                        cur_pkg = pkg.to_string();
                        in_block = true;
                        continue;
                    }
                    if !add_rule(&mut rules, topo, pkg, thread, cpus, lineno) {
                        fail_cnt += 1;
                    }
                } else {
                    fail_cnt += 1;
                }
                continue;
            }

            let blk_pkg = if !pkg.is_empty() {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pkg
            } else {
                &pending_pkg
            };
            if blk_pkg.is_empty() {
                fail_cnt += 1;
                continue;
            }
            cur_pkg = blk_pkg.to_string();
            pending_pkg.clear();
            in_block = true;
            continue;
        }

        if !pending_pkg.is_empty() {
            fail_cnt += 1;
        }

        let pkg = before;
        if let Some(br) = after.find('{') {
            let cpus = after[..br].trim();
            cur_pkg = pkg.to_string();
            in_block = true;
            if !cpus.is_empty() && !add_rule(&mut rules, topo, pkg, "", cpus, lineno) {
                fail_cnt += 1;
            }
            pending_pkg.clear();
            continue;
        }

        let cpus = after.trim();
        if cpus.is_empty() {
            pending_pkg = pkg.to_string();
            continue;
        }
        if !add_rule(&mut rules, topo, pkg, "", cpus, lineno) {
            fail_cnt += 1;
        }
        pending_pkg.clear();
    }

    if in_block || !pending_pkg.is_empty() {
        fail_cnt += 1;
    }

    // 无条件落定 last_mtime：畸形行本就被跳过，对【未变化】的文件重解析毫无意义。原先仅在
    // fail_cnt==0 时更新，会使【轮询降级模式】下"配置含任何永久畸形行"→每周期重解析并全量
    // 还原+重应用(thrash)。文件真正变化(用户修好)时 mtime 变、自然重读；inotify 模式仍靠事件
    // 置 last_mtime=-1 强制重读，不受影响。
    *last_mtime = mtime;
    PARSE_FAILS.store(fail_cnt, Ordering::Relaxed);

    let pkgs: HashSet<String> = rules.iter().map(|r| r.pkg.clone()).collect();
    let has_thread_rules: HashSet<String> = rules
        .iter()
        .filter(|r| !r.thread.is_empty())
        .map(|r| r.pkg.clone())
        .collect();
    let pipeline_pkgs: HashSet<String> = rules
        .iter()
        .filter(|r| r.pipeline)
        .map(|r| r.pkg.clone())
        .collect();
    let num_rules = rules.len();

    println!("配置文件解析完成，共加载 {} 条规则", num_rules);
    if fail_cnt > 0 {
        eprintln!("警告: {} 条规则因格式无效被跳过", fail_cnt);
    }

    Some(AppConfig {
        rules,
        pkgs,
        has_thread_rules,
        pipeline_pkgs,
        topo: topo.clone(),
    })
}

/// 配置加载线程，优先 inotify 失败降级为定时轮询；间隔取运行时可调的 CHECK_INTERVAL
pub fn config_loader() {
    let name = CString::new("ConfigLoader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    let mut last_mtime: i64 = -1;

    loop {
        let interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        // web 端切换配置文件/cpuset 目录后置位 FORCE_RELOAD，这里强制重读并重挂 inotify
        if FORCE_RELOAD.swap(false, Ordering::AcqRel) {
            last_mtime = -1;
            if INOTIFY_SUPPORTED.load(Ordering::Acquire) {
                let fd = INOTIFY_FD.load(Ordering::Acquire);
                inotify_rewatch(fd);
            }
            config_reload(&mut last_mtime);
        }
        if INOTIFY_SUPPORTED.load(Ordering::Acquire) {
            inotify_handle(interval, &mut last_mtime);
        } else {
            config_reload(&mut last_mtime);
            thread::sleep(Duration::from_secs(interval));
        }
    }
}

/// 关闭 inotify 并降级为轮询模式
fn disable_inotify(inotify_fd: i32) {
    INOTIFY_SUPPORTED.store(false, Ordering::Release);
    unsafe {
        libc::close(inotify_fd);
    }
    INOTIFY_FD.store(-1, Ordering::Release);
    INOTIFY_WD.store(-1, Ordering::Release);
}

/// 重新加载配置，成功则更新 CURRENT_CONFIG 并置位 CONFIG_UPDATED
fn config_reload(last_mtime: &mut i64) {
    let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
        return;
    };
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    let Some(new_cfg) = load_config(&file, &cfg.topo, last_mtime) else {
        return;
    };
    {
        let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(new_cfg));
    }
    CONFIG_UPDATED.store(true, Ordering::Release);
}

/// 立即强制重载一次配置(忽略 mtime 缓存)，供 web 端改规则后即时生效
pub fn config_reload_now() {
    let mut mtime: i64 = -1;
    config_reload(&mut mtime);
}

/// 处理 inotify 事件，循环 read 直到 EAGAIN 避免事件丢失
fn inotify_handle(interval: u64, last_mtime: &mut i64) {
    let inotify_fd = INOTIFY_FD.load(Ordering::Acquire);

    let mut pfd = libc::pollfd {
        fd: inotify_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, (interval as libc::c_int) * 1000) };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            return;
        }
        disable_inotify(inotify_fd);
        return;
    } else if ret == 0 {
        return;
    }

    #[repr(align(8))]
    struct InotifyBuf([u8; 4096]);
    let mut buf = InotifyBuf([0u8; 4096]);
    let mut reload_needed = false;
    let mut needs_rewatch = false;
    let hdr = std::mem::size_of::<libc::inotify_event>();

    loop {
        let len = unsafe {
            libc::read(
                inotify_fd,
                buf.0.as_mut_ptr() as *mut libc::c_void,
                buf.0.len(),
            )
        };
        if len <= 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error();
            // EAGAIN 或 EINTR 退出循环
            if errno == Some(libc::EAGAIN)
                || errno == Some(libc::EWOULDBLOCK)
                || errno == Some(libc::EINTR)
            {
                break;
            }
            disable_inotify(inotify_fd);
            return;
        }

        let mut offset = 0;
        while offset + hdr <= len as usize {
            let event = unsafe { &*(buf.0.as_ptr().add(offset) as *const libc::inotify_event) };
            if event.mask & (libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0
            {
                reload_needed = true;
                *last_mtime = -1;
                if event.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                    needs_rewatch = true;
                }
            }
            offset += hdr + event.len as usize;
        }
    }

    // rewatch 在 read 循环结束后统一处理避免中途 sleep 丢事件
    if needs_rewatch {
        thread::sleep(Duration::from_secs(interval));
        if !inotify_rewatch(inotify_fd) {
            return;
        }
    }

    if reload_needed {
        config_reload(last_mtime);
    }
}

/// 重装 inotify 监听，失败则降级为轮询
fn inotify_rewatch(inotify_fd: i32) -> bool {
    let inotify_wd = INOTIFY_WD.load(Ordering::Acquire);
    unsafe {
        libc::inotify_rm_watch(inotify_fd, inotify_wd);
    }
    let cfg_cstr = match CString::new(lock_ignore_poison(&CONFIG_FILE).clone()) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("错误: 配置文件路径包含非法字符，降级为轮询模式");
            disable_inotify(inotify_fd);
            return false;
        }
    };
    let new_wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };

    if new_wd < 0 {
        disable_inotify(inotify_fd);
        return false;
    }
    INOTIFY_WD.store(new_wd, Ordering::Release);
    true
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpuset::{parse_cpu_ranges, parse_cpu_spec, CpuSet, CpuTopology};
    use crate::sched::{split_sched, SchedPolicy};
    use crate::vendor_boost::split_vendor;

    fn cs(cpus: &[usize]) -> CpuSet {
        let mut s = CpuSet::new();
        for &c in cpus {
            s.set(c);
        }
        s
    }

    fn test_topo() -> CpuTopology {
        CpuTopology {
            present_cpus: cs(&[0, 1, 2, 3, 4, 5, 6, 7]),
            present_str: "0-7".into(),
            mems_str: "0".into(),
            cpuset_enabled: false, // 不碰 /dev/cpuset 文件系统
            e_core: cs(&[0, 1, 2, 3]),
            p_core: cs(&[4, 5]),
            hp_core: cs(&[6, 7]),
            clusters: vec![cs(&[0, 1, 2, 3]), cs(&[4, 5]), cs(&[6, 7])],
        }
    }

    /// 把一段配置文本写进临时文件、解析、返回 AppConfig（供端到端解析测试）。
    fn load_str(name: &str, content: &str) -> AppConfig {
        let topo = test_topo();
        let path = std::env::temp_dir().join(format!("appopt_test_{}.conf", name));
        std::fs::write(&path, content).unwrap();
        let mut mtime = -1i64;
        let cfg = load_config(path.to_str().unwrap(), &topo, &mut mtime).expect("load_config");
        let _ = std::fs::remove_file(&path);
        cfg
    }

    fn rule_cpus<'a>(cfg: &'a AppConfig, pkg: &str, thread: &str) -> &'a CpuSet {
        &cfg.rules
            .iter()
            .find(|r| r.pkg == pkg && r.thread == thread)
            .unwrap_or_else(|| panic!("rule not found: pkg={pkg} thread={thread}"))
            .cpus
    }

    // ---------- comment_at / strip_comment ----------
    #[test]
    fn test_strip_comment() {
        assert_eq!(strip_comment("0-3 # note"), "0-3"); // 注释前的尾随空白一并去掉
        assert_eq!(strip_comment("0-3 // note"), "0-3");
        assert_eq!(strip_comment("0-3"), "0-3");
        // # / // 不带前置空白不算注释（与既有约定一致）
        assert_eq!(strip_comment("a#b"), "a#b");
        assert_eq!(strip_comment("a//b"), "a//b");
        // 整行注释里首字符 # 无前置空白 → 不剥（load_config 另有整行跳过逻辑）
        assert_eq!(strip_comment("# whole"), "# whole");
    }

    // ---------- parse_cpu_ranges / parse_cpu_spec ----------
    #[test]
    fn test_parse_cpu_ranges() {
        assert_eq!(parse_cpu_ranges("0-3", None), cs(&[0, 1, 2, 3]));
        assert_eq!(parse_cpu_ranges("0,2,4", None), cs(&[0, 2, 4]));
        assert_eq!(parse_cpu_ranges("3-1", None), cs(&[1, 2, 3])); // 反向区间归一
        assert_eq!(parse_cpu_ranges("7", None), cs(&[7]));
        // present 过滤：超出在线核的部分被裁掉
        let present = cs(&[0, 1, 2, 3]);
        assert_eq!(parse_cpu_ranges("0-7", Some(&present)), cs(&[0, 1, 2, 3]));
    }

    #[test]
    fn test_parse_cpu_ranges_malformed() {
        // 端点非法 → 整段跳过，不再静默回落成 "0-0"
        assert_eq!(parse_cpu_ranges("0-x", None), cs(&[]));
        assert_eq!(parse_cpu_ranges("2-", None), cs(&[]));
        assert_eq!(parse_cpu_ranges("-3", None), cs(&[]));
        assert_eq!(parse_cpu_ranges("z", None), cs(&[]));
        // 合法段保留、非法段丢弃
        assert_eq!(parse_cpu_ranges("1,3-y,5", None), cs(&[1, 5]));
    }

    #[test]
    fn test_load_config_malformed_range_rejected() {
        // 整条规格非法(无核无提示) → 规则被拒、不产生"只绑 CPU0"的错规则
        let cfg = load_str("bad_range", "com.bad=0-z\ncom.ok=2-3\n");
        assert!(cfg.rules.iter().all(|r| r.pkg != "com.bad"), "非法区间规则不应被接受");
        assert_eq!(rule_cpus(&cfg, "com.ok", ""), &cs(&[2, 3]));
    }

    #[test]
    fn test_parse_cpu_spec_semantic() {
        let t = test_topo();
        assert_eq!(parse_cpu_spec("e-core", &t), cs(&[0, 1, 2, 3]));
        assert_eq!(parse_cpu_spec("p-core", &t), cs(&[4, 5]));
        assert_eq!(parse_cpu_spec("hp-core", &t), cs(&[6, 7]));
        assert_eq!(parse_cpu_spec("all-core", &t), cs(&[0, 1, 2, 3, 4, 5, 6, 7]));
        assert_eq!(parse_cpu_spec("0-1,hp-core", &t), cs(&[0, 1, 6, 7]));
    }

    // ---------- spec_like ----------
    #[test]
    fn test_spec_like() {
        assert!(spec_like("0-3"));
        assert!(spec_like("0,2,4"));
        assert!(spec_like("hp-core"));
        assert!(spec_like("e-core,p-core"));
        assert!(!spec_like("boost"));
        assert!(!spec_like(""));
        assert!(!spec_like("0-")); // 半区间无效
    }

    // ---------- split_sched ----------
    #[test]
    fn test_split_sched() {
        let (cpus, p) = split_sched("0-7:FIFO:2");
        assert_eq!(cpus, "0-7");
        assert!(matches!(p, Some(SchedPolicy::Fifo(2))));
        let (cpus, p) = split_sched("hp-core:RR:1");
        assert_eq!(cpus, "hp-core");
        assert!(matches!(p, Some(SchedPolicy::Rr(1))));
        let (cpus, p) = split_sched(":nice:-5");
        assert_eq!(cpus, "");
        assert!(matches!(p, Some(SchedPolicy::Nice(-5))));
        let (cpus, p) = split_sched("0-3");
        assert_eq!(cpus, "0-3");
        assert!(p.is_none());
        // rtprio 越界钳制
        assert!(matches!(split_sched("0:FIFO:200").1, Some(SchedPolicy::Fifo(99))));
        // 尾部多余段不再吞掉合法值：nice 仍取 -5（而非回落 0）
        assert!(matches!(split_sched("0-7:nice:-5:junk").1, Some(SchedPolicy::Nice(-5))));
        assert!(matches!(split_sched("0-7:FIFO:2:x").1, Some(SchedPolicy::Fifo(2))));
    }

    // ---------- split_vendor（含近期健壮性修复）----------
    #[test]
    fn test_split_vendor_basic() {
        let (rest, v) = split_vendor("3-7:boost:2");
        assert_eq!(rest, "3-7");
        assert_eq!(v.boost, Some(2));

        let (_, v) = split_vendor("0-7:b"); // 裸 :b 默认 2
        assert_eq!(v.boost, Some(2));

        let (_, v) = split_vendor("0-7:u"); // 裸 :u 默认 812
        assert_eq!(v.uclamp_min, Some(812));

        let (_, v) = split_vendor("0-7:x"); // 裸 :x 默认 1024
        assert_eq!(v.uclamp_max, Some(1024));

        let (rest, v) = split_vendor("0-7:reduce:6-7");
        assert_eq!(rest, "0-7");
        assert_eq!(v.reduce_spec.as_deref(), Some("6-7"));
    }

    #[test]
    fn test_split_vendor_order_independent() {
        // 厂商后缀与调度后缀顺序无关：boost 在 FIFO 之后仍被正确剥离
        let (rest, v) = split_vendor("6-7:FIFO:2:boost:3");
        assert_eq!(rest, "6-7:FIFO:2");
        assert_eq!(v.boost, Some(3));
    }

    #[test]
    fn test_split_vendor_no_token_swallow() {
        // :reduce 后紧邻不是 CPU 规格(是别的后缀) → 不消费它、不设 reduce
        let (_, v) = split_vendor("0-7:reduce:boost:2");
        assert!(v.reduce_spec.is_none(), "reduce 不应吞掉 boost");
        assert_eq!(v.boost, Some(2), "boost 应被正常识别");

        // :loadboost 后紧邻不是数字(是别的后缀) → 不消费它
        let (_, v) = split_vendor("0-7:loadboost:ll");
        assert!(v.low_latency, "ll 应被正常识别，不被 loadboost 吞掉");
    }

    // ---------- load_config 端到端：行尾注释必须被剥离（回归测试）----------
    #[test]
    fn test_load_config_inline_comment_pkg_rule() {
        let cfg = load_str(
            "inline_pkg",
            "com.a=0-3 # 渲染绑小核\ncom.b=hp-core // 大核\ncom.c=4-7\n",
        );
        assert_eq!(rule_cpus(&cfg, "com.a", ""), &cs(&[0, 1, 2, 3]), "行尾 # 注释未剥离 → 绑错核");
        assert_eq!(rule_cpus(&cfg, "com.b", ""), &cs(&[6, 7]), "行尾 // 注释未剥离 → 绑错核");
        assert_eq!(rule_cpus(&cfg, "com.c", ""), &cs(&[4, 5, 6, 7]));
    }

    #[test]
    fn test_load_config_inline_comment_block_and_single() {
        let cfg = load_str(
            "inline_block",
            "com.x {\n    RenderThread=6-7 # 渲染\n    Worker=0-3\n}\ncom.y{Main}=hp-core  // 主线程\n",
        );
        assert_eq!(rule_cpus(&cfg, "com.x", "RenderThread"), &cs(&[6, 7]));
        assert_eq!(rule_cpus(&cfg, "com.x", "Worker"), &cs(&[0, 1, 2, 3]));
        assert_eq!(rule_cpus(&cfg, "com.y", "Main"), &cs(&[6, 7]));
    }

    #[test]
    fn test_load_config_suffix_with_comment() {
        // 带后缀 + 行尾注释：CPU 部分与后缀都应正确，注释被剥离
        let cfg = load_str("suffix_cmt", "com.z=3-7:boost:2 # 贴大核\n");
        let r = cfg.rules.iter().find(|r| r.pkg == "com.z").unwrap();
        assert_eq!(r.cpus, cs(&[3, 4, 5, 6, 7]));
        assert_eq!(r.boost, Some(2));
        assert!(!r.raw_spec.contains('#'), "raw_spec 不应含注释: {}", r.raw_spec);
    }

    // ---------- thread_affinity（重构后行为回归）----------
    #[test]
    fn test_thread_affinity_thread_rule() {
        // 线程规则命中：绑核 + 提示，is_thread_rule=true
        let cfg = load_str("ta_thread", "com.g {\n  RenderThread=6-7:boost:2\n}\n");
        let r = crate::rule_match::thread_affinity("com.g", "RenderThread", &cfg).unwrap();
        assert_eq!(r.cpus, cs(&[6, 7]));
        assert_eq!(r.boost, Some(2));
        assert!(r.is_thread_rule);
    }

    #[test]
    fn test_thread_affinity_package_fallback() {
        // 无匹配线程规则 → 回落包级规则，is_thread_rule=false
        let cfg = load_str("ta_pkg", "com.h=0-3\n");
        let r = crate::rule_match::thread_affinity("com.h", "Whatever", &cfg).unwrap();
        assert_eq!(r.cpus, cs(&[0, 1, 2, 3]));
        assert!(!r.is_thread_rule);
    }

    #[test]
    fn test_thread_affinity_hint_only_boost_no_cpuset() {
        // 只带 boost、不写核 → 纯提示：不建/不移 cpuset(空 cpus、空 dir)，仍带 boost
        let cfg = load_str("ta_boost", "com.i=:boost:2\n");
        let r = crate::rule_match::thread_affinity("com.i", "T", &cfg).unwrap();
        assert_eq!(r.cpus.count(), 0); // 不再提升进全核 cpuset
        assert_eq!(r.cpuset_dir, "");
        assert_eq!(r.boost, Some(2));
    }

    #[test]
    fn test_thread_affinity_hint_only_pipeline_no_cpuset() {
        // 只带 :p、不写核 → 纯提示：空 cpus + 空 dir，pipeline 标记保留(放置交给 OPLUS 调度器)
        let cfg = load_str("ta_pipe", "com.p=:p\n");
        let r = crate::rule_match::thread_affinity("com.p", "T", &cfg).unwrap();
        assert_eq!(r.cpus.count(), 0);
        assert_eq!(r.cpuset_dir, "");
        assert!(r.pipeline);
    }

    #[test]
    fn test_thread_affinity_hint_only_no_promote() {
        // 只带 umax → 空 cpus + 提示保留
        let cfg = load_str("ta_nopromote", "com.j=:umax:300\n");
        let r = crate::rule_match::thread_affinity("com.j", "T", &cfg).unwrap();
        assert_eq!(r.cpus.count(), 0);
        assert_eq!(r.uclamp_max, Some(300));
    }

    #[test]
    fn test_thread_affinity_managed_pkg_fallback_untouched() {
        // 有线程规则的包、但线程没命中且无包级规则 → present_cpus 兜底，is_thread_rule=false
        let cfg = load_str("ta_managed", "com.k {\n  Main=0-3\n}\n");
        let r = crate::rule_match::thread_affinity("com.k", "Other", &cfg).unwrap();
        // 未命中线程：被纳管(Some)但【不动亲和/cpuset】——空 cpus/空 dir，不再强拉进 AppOpt 全核 cpuset
        assert_eq!(r.cpus.count(), 0);
        assert_eq!(r.cpuset_dir, "");
        assert!(!r.is_thread_rule);
        assert!(r.boost.is_none());
        // 未配置的包 → None
        assert!(crate::rule_match::thread_affinity("com.none", "T", &cfg).is_none());
    }

    // ---------- comm_to_pkg（截断名前缀优先于后缀）----------
    #[test]
    fn test_comm_to_pkg_prefix_suffix() {
        use crate::cache::comm_to_pkg;
        let cfg = load_str("c2p", "com.tencent.tmgp.sgame=0-3\n");
        // 精确
        assert_eq!(
            comm_to_pkg("com.tencent.tmgp.sgame", &cfg).as_deref(),
            Some("com.tencent.tmgp.sgame")
        );
        // 截断到 15B 的 comm → 前缀命中
        assert_eq!(
            comm_to_pkg("com.tencent.tmg", &cfg).as_deref(),
            Some("com.tencent.tmgp.sgame")
        );
        // "pkg:proc" 子进程 → 冒号前归主包(精确)
        assert_eq!(
            comm_to_pkg("com.tencent.tmgp.sgame:push", &cfg).as_deref(),
            Some("com.tencent.tmgp.sgame")
        );
        assert!(comm_to_pkg("com.unrelated", &cfg).is_none());
    }

    #[test]
    fn test_load_config_whole_line_comment_skipped() {
        let cfg = load_str("whole_cmt", "# 整行注释\n// 另一行\ncom.only=0-1\n");
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(rule_cpus(&cfg, "com.only", ""), &cs(&[0, 1]));
    }
}
