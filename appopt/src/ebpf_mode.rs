use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::mpsc;
use std::thread;

use aya::maps::{Array as AyaArray, HashMap as AyaHashMap};
use aya::programs::BtfTracePoint as AyaBtfTracePoint;
use aya::{Btf, Ebpf, EbpfLoader, Pod};

use crate::apply_affinity::{affinity_set, read_cmdline, task_tids, tid_comm};
use crate::cache::{comm_str, comm_to_pkg, ProcCache};
use crate::config::{AppConfig, CURRENT_CONFIG};
use crate::cpuset::CpuSet;

/// eBPF 进程事件，布局需与内核态 ProcEvent 一致
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfProcEvent {
    pub pid: i32,
    pub tid: i32,
    pub comm: [u8; 16],
    pub event_type: u32,
}

/// 编译期内嵌的 eBPF 对象，由 build.rs 经 APPOPT_EBPF_OBJ 提供。
/// 用 aya 的对齐宏：ELF64 头需 8 字节对齐，普通 include_bytes! 对齐为 1。
static EBPF_OBJ: &[u8] = aya::include_bytes_aligned!(env!("APPOPT_EBPF_OBJ"));

pub const EBPF_EVENT_FORK: u32 = 1;
pub const EBPF_EVENT_EXEC: u32 = 2;
pub const EBPF_EVENT_RENAME: u32 = 3;
pub const EBPF_EVENT_EXIT: u32 = 4;

/// 用户态注入内核的 task_struct 成员偏移，布局需与内核态 TracepointOffsets 一致，
/// tp_btf 各 tracepoint 共用。
#[repr(C)]
#[derive(Clone, Copy)]
struct EbpfOffsets {
    task_pid: u32,
    task_tgid: u32,
    task_comm: u32,
}

unsafe impl Pod for EbpfOffsets {}

pub struct EbpfState {
    pub event_rx: mpsc::Receiver<EbpfProcEvent>,
    pub reader_thread: Option<thread::JoinHandle<()>>,
    pub bpf: Ebpf,
    pub cache: ProcCache,
    pub wakeup_fd: RawFd,
    pub comm_capacity: u32,
    /// task_rename tracepoint 是否挂载成功(启动后新建线程按线程名匹配的关键路径)；供 web 状态展示
    pub rename_ok: bool,
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // 写 eventfd 唤醒 reader 线程的 epoll_wait 后 join 等待退出
        if self.wakeup_fd >= 0 {
            let val: u64 = 1;
            unsafe {
                libc::write(self.wakeup_fd, &val as *const u64 as *const _, 8);
            }
        }
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
        if self.wakeup_fd >= 0 {
            unsafe { libc::close(self.wakeup_fd); }
        }
    }
}

/// 检测 eBPF 支持，内核存在 BTF 即可（eBPF 对象已内嵌）
pub fn ebpf_probe() -> bool {
    fs::metadata("/sys/kernel/btf/vmlinux").is_ok()
}

fn attach_btf_tp(bpf: &mut Ebpf, btf: &Btf, name: &str, required: bool) -> bool {
    let Some(prog) = bpf.program_mut(name) else {
        if required {
            eprintln!("eBPF: 未找到 {} 程序", name);
        }
        return false;
    };
    let Ok(tp): Result<&mut AyaBtfTracePoint, _> = prog.try_into() else {
        if required {
            eprintln!("eBPF: {} 类型转换失败", name);
        }
        return false;
    };
    // tp_btf 加载即绑定到 tracepoint 的 BTF ID，需内核 BTF；随后 attach 无参
    if let Err(e) = tp.load(name, btf) {
        if required {
            eprintln!("eBPF: {} 加载失败 ({})", name, e);
        }
        return false;
    }
    if let Err(e) = tp.attach() {
        if required {
            eprintln!("eBPF: {} 附加失败 ({})", name, e);
        }
        return false;
    }
    true
}

/// 构建白名单键，每个包名生成前 8 字节与末 8 字节键
fn comm_keys_build<'a, I: IntoIterator<Item = &'a String>>(pkgs: I) -> Vec<[u8; 8]> {
    let mut entries: Vec<[u8; 8]> = Vec::new();
    for pkg in pkgs {
        let bytes = pkg.as_bytes();
        if bytes.is_empty() {
            continue;
        }

        let mut prefix_key = [0u8; 8];
        let prefix_len = bytes.len().min(8);
        prefix_key[..prefix_len].copy_from_slice(&bytes[..prefix_len]);
        entries.push(prefix_key);

        if bytes.len() > 8 {
            let mut suffix_key = [0u8; 8];
            let start = bytes.len() - 8;
            suffix_key.copy_from_slice(&bytes[start..]);
            entries.push(suffix_key);
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

/// 初始化 TARGET_COMM_MAP，返回 true 表示需重载内核端（容量不足或插入部分失败）
pub fn comm_map_init(bpf: &mut Ebpf, pkgs: &HashSet<String>, comm_capacity: u32) -> bool {
    let entries = comm_keys_build(pkgs.iter());

    if entries.len() > comm_capacity as usize {
        eprintln!(
            "eBPF: 白名单容量不足（需 {} > 现 {}），触发内核端重载",
            entries.len(),
            comm_capacity
        );
        return true;
    }

    let Some(map) = bpf.map_mut("TARGET_COMM_MAP") else {
        eprintln!("eBPF: 未找到 TARGET_COMM_MAP");
        return false;
    };
    let mut target_map = match AyaHashMap::<_, [u8; 8], u32>::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("eBPF: TARGET_COMM_MAP 类型转换失败 ({})", e);
            return false;
        }
    };

    let old_keys: Vec<[u8; 8]> = target_map.keys().filter_map(|r| r.ok()).collect();
    for key in &old_keys {
        let _ = target_map.remove(key);
    }

    let mut count = 0;
    for key in &entries {
        if target_map.insert(key, 1, 0).is_ok() {
            count += 1;
        }
    }

    // 部分键写入失败（map 满/竞态）时白名单不完整，触发重载重建而非带病运行
    if count < entries.len() {
        eprintln!(
            "eBPF: 白名单插入部分失败（{}/{}），触发重载",
            count,
            entries.len()
        );
        return true;
    }

    println!(
        "eBPF: FORK/EXEC 白名单已配置，{} 个包名 > {} 条匹配规则",
        pkgs.len(),
        count
    );
    false
}

/// 读小端 u32
#[inline]
fn rd_u32(d: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]])
}

/// 解析 /sys/kernel/btf/vmlinux，返回 task_struct 的 (pid, tgid, comm) 字节偏移。
/// 手写 BTF 遍历：aya::Btf 不公开成员偏移，故直接扫类型表定位 task_struct 结构体。
fn task_offsets_from_btf() -> Option<(u32, u32, u32)> {
    let data = fs::read("/sys/kernel/btf/vmlinux").ok()?;
    // btf_header: magic(u16) version(u8) flags(u8) hdr_len type_off type_len str_off str_len
    if data.len() < 24 || u16::from_le_bytes([data[0], data[1]]) != 0xeb9f {
        return None;
    }
    let hdr_len = rd_u32(&data, 4) as usize;
    let type_start = hdr_len + rd_u32(&data, 8) as usize;
    let type_end = type_start.checked_add(rd_u32(&data, 12) as usize)?;
    let str_start = hdr_len + rd_u32(&data, 16) as usize;
    if type_end > data.len() || str_start > data.len() {
        return None;
    }

    // 字符串区某偏移处的以 NUL 结尾名字
    let name_at = |off: u32| -> &[u8] {
        let s = str_start + off as usize;
        if s >= data.len() {
            return &[];
        }
        let end = data[s..]
            .iter()
            .position(|&b| b == 0)
            .map_or(data.len(), |e| s + e);
        &data[s..end]
    };

    let mut pos = type_start;
    while pos + 12 <= type_end {
        let name_off = rd_u32(&data, pos);
        let info = rd_u32(&data, pos + 4);
        let vlen = (info & 0xffff) as usize;
        let kind = (info >> 24) & 0x1f;
        let kind_flag = (info >> 31) & 1;
        pos += 12;

        // 各 kind 的尾随数据字节数，用于跳到下一个类型
        let trailing = match kind {
            1 => 4,             // INT
            3 => 12,            // ARRAY
            4 | 5 => vlen * 12, // STRUCT/UNION: btf_member[]
            6 => vlen * 8,      // ENUM
            13 => vlen * 8,     // FUNC_PROTO: btf_param[]
            14 => 4,            // VAR
            15 => vlen * 12,    // DATASEC
            17 => 4,            // DECL_TAG
            19 => vlen * 12,    // ENUM64
            _ => 0,             // PTR/FWD/TYPEDEF/VOLATILE/CONST/RESTRICT/FUNC/FLOAT/TYPE_TAG
        };

        if kind == 4 && name_at(name_off) == b"task_struct" {
            let (mut pid, mut tgid, mut comm) = (0u32, 0u32, 0u32);
            for i in 0..vlen {
                let m = pos + i * 12;
                if m + 12 > type_end {
                    return None;
                }
                let raw = rd_u32(&data, m + 8);
                let byte_off = (if kind_flag == 1 { raw & 0xff_ffff } else { raw }) / 8;
                match name_at(rd_u32(&data, m)) {
                    b"pid" => pid = byte_off,
                    b"tgid" => tgid = byte_off,
                    b"comm" => comm = byte_off,
                    _ => {}
                }
            }
            return (pid != 0 && tgid != 0 && comm != 0).then_some((pid, tgid, comm));
        }
        pos += trailing;
    }
    None
}

/// 注入 OFFSETS_MAP 索引 0 的 task_struct 偏移（tp_btf 各 tracepoint 共用）。
/// 解析或注入失败返回 false，调用方回退 /proc 轮询。
fn offsets_inject(bpf: &mut Ebpf) -> bool {
    let Some((pid, tgid, comm)) = task_offsets_from_btf() else {
        eprintln!("eBPF: task_struct 偏移解析失败，回退到 /proc 轮询");
        return false;
    };
    let offsets = EbpfOffsets {
        task_pid: pid,
        task_tgid: tgid,
        task_comm: comm,
    };

    let Some(map) = bpf.map_mut("OFFSETS_MAP") else {
        eprintln!("eBPF: 未找到 OFFSETS_MAP，回退到 /proc 轮询");
        return false;
    };
    let Ok(mut offsets_map) = AyaArray::<_, EbpfOffsets>::try_from(map) else {
        eprintln!("eBPF: OFFSETS_MAP 类型转换失败，回退到 /proc 轮询");
        return false;
    };
    if offsets_map.set(0, offsets, 0).is_err() {
        eprintln!("eBPF: OFFSETS_MAP 注入失败，回退到 /proc 轮询");
        return false;
    }

    println!("eBPF: 偏移注入 task[pid={}, tgid={}, comm={}]", pid, tgid, comm);
    true
}

/// 初始化 eBPF，加载程序 attach tracepoint 创建 RingBuf 线程，失败回退 /proc
pub fn ebpf_init() -> Option<EbpfState> {
    if !ebpf_probe() {
        eprintln!("eBPF: 内核不支持（缺少 BTF），回退到 /proc 轮询");
        return None;
    }

    println!("eBPF: 加载内嵌程序 ({} bytes)", EBPF_OBJ.len());

    // 按包名数动态设置容量（每包最多 2 个键），最小 512 覆盖常见场景，不足时重载自然倍增。
    // 只取长度、不再克隆整个 pkgs 集合与重建键数组
    let pkgs_len = crate::lock_ignore_poison(&CURRENT_CONFIG)
        .as_ref()
        .map(|cfg| cfg.pkgs.len())
        .unwrap_or(0);
    let capacity = (pkgs_len * 2).max(512).next_power_of_two() as u32;

    let mut loader = EbpfLoader::new();
    loader.map_max_entries("TARGET_COMM_MAP", capacity);
    let mut bpf = match loader.load(EBPF_OBJ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("eBPF: 加载失败 ({})，回退到 /proc 轮询", e);
            return None;
        }
    };

    // attach 前注入 task 偏移避免首批事件读到空 map；失败即回退 /proc
    if !offsets_inject(&mut bpf) {
        return None;
    }

    // tp_btf 加载需内核 BTF，读一次供四个 tracepoint 共用
    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("eBPF: BTF 读取失败 ({})，回退到 /proc 轮询", e);
            return None;
        }
    };

    if !attach_btf_tp(&mut bpf, &btf, "sched_process_fork", true) {
        return None;
    }
    if !attach_btf_tp(&mut bpf, &btf, "sched_process_exec", true) {
        return None;
    }
    if !attach_btf_tp(&mut bpf, &btf, "sched_process_exit", true) {
        return None;
    }

    // task_rename 捕获线程改名，是启动后新建线程按线程名匹配（含 FIFO/RR/nice）的关键路径
    let rename_ok = attach_btf_tp(&mut bpf, &btf, "task_rename", false);
    println!(
        "eBPF: task_rename 挂载{}",
        if rename_ok { "成功" } else { "失败（启动后新建线程的线程名规则将失效）" }
    );

    let ring_buf = match bpf.take_map("EVENTS") {
        Some(map) => match aya::maps::RingBuf::try_from(map) {
            Ok(rb) => rb,
            Err(e) => {
                eprintln!("eBPF: EVENTS map 类型转换失败 ({})，回退到 /proc 轮询", e);
                return None;
            }
        },
        None => {
            eprintln!("eBPF: 未找到 EVENTS map，回退到 /proc 轮询");
            return None;
        }
    };

    let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
    let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wakeup_fd < 0 {
        eprintln!("eBPF: eventfd 创建失败，回退到 /proc 轮询");
        return None;
    }
    let reader_thread = thread::spawn(move || {
        ebpf_reader(ring_buf, tx, wakeup_fd);
    });

    println!("eBPF: 初始化成功，纯事件驱动（启动后零 /proc 读），全量扫描走 /proc");

    let state = EbpfState {
        event_rx: rx,
        reader_thread: Some(reader_thread),
        bpf,
        cache: ProcCache::new(),
        wakeup_fd,
        comm_capacity: capacity,
        rename_ok,
    };
    Some(state)
}

/// RingBuf 读取线程，epoll 阻塞等待事件 wakeup_fd 用于 Drop 唤醒退出
fn ebpf_reader(
    mut ring_buf: aya::maps::RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<EbpfProcEvent>,
    wakeup_fd: RawFd,
) {
    let name = CString::new("EbpfReader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        eprintln!("eBPF: epoll_create1 失败");
        return;
    }

    let ring_fd = ring_buf.as_raw_fd();
    let mut ring_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ring_ev.events = libc::EPOLLIN as u32;
    ring_ev.u64 = 0;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ring_fd, &mut ring_ev) } < 0 {
        eprintln!("eBPF: epoll_ctl ADD ring_fd 失败");
        unsafe { libc::close(epfd) };
        return;
    }

    let mut wake_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    wake_ev.events = libc::EPOLLIN as u32;
    wake_ev.u64 = 1;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut wake_ev) } < 0 {
        eprintln!("eBPF: epoll_ctl ADD wakeup_fd 失败");
        unsafe { libc::close(epfd) };
        return;
    }

    let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };
    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, -1) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        // wakeup 事件优先退出
        let mut wakeup = false;
        for ev in events.iter().take(n as usize) {
            if ev.u64 == 1 {
                wakeup = true;
                break;
            }
        }
        if wakeup {
            break;
        }

        while let Some(item) = ring_buf.next() {
            let bytes: &[u8] = &item;
            if bytes.len() >= std::mem::size_of::<EbpfProcEvent>() {
                let event: EbpfProcEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfProcEvent) };
                if tx.send(event).is_err() {
                    unsafe { libc::close(epfd) };
                    return;
                }
            }
        }
    }
    unsafe { libc::close(epfd) };
}

/// 取 APPLIED_MAP 的可写句柄，未找到或类型不符返回 None
fn applied_get(bpf: &mut Ebpf) -> Option<AyaHashMap<&mut aya::maps::MapData, u32, u64>> {
    AyaHashMap::<_, u32, u64>::try_from(bpf.map_mut("APPLIED_MAP")?).ok()
}

/// 写入 APPLIED_MAP tid 到 CPU mask
fn applied_set(bpf: &mut Ebpf, tid: i32, cpus: &CpuSet) {
    let Some(mut applied) = applied_get(bpf) else { return };
    if let Err(e) = applied.insert(tid as u32, cpus.bits[0], 0) {
        eprintln!("eBPF: APPLIED_MAP 插入失败 tid={} ({})，map 可能已满", tid, e);
    }
}

/// 从 APPLIED_MAP 删除 tid
fn applied_del(bpf: &mut Ebpf, tid: i32) {
    let Some(mut applied) = applied_get(bpf) else { return };
    let _ = applied.remove(&(tid as u32));
}

/// 清空 APPLIED_MAP 所有条目
fn applied_clear(bpf: &mut Ebpf) {
    let Some(mut m) = applied_get(bpf) else { return };
    let keys: Vec<u32> = m.keys().filter_map(|r| r.ok()).collect();
    for k in &keys {
        let _ = m.remove(k);
    }
}

/// 应用亲和性并写 APPLIED_MAP，返回 true 表示 tid 已退出
fn affinity_apply(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: &str,
    cfg: &AppConfig,
    bpf: &mut Ebpf,
) -> bool {
    let dead = affinity_set(tid, cpus, cpuset_dir, &cfg.topo);
    if !dead {
        applied_set(bpf, tid, cpus);
    }
    dead
}

/// 事件派发，按 event_type 增量处理 FORK/RENAME/EXEC/EXIT
pub fn event_dispatch(event: &EbpfProcEvent, cfg: &AppConfig, state: &mut EbpfState) {
    let tid = event.tid;
    let pid = event.pid;
    let comm = comm_str(&event.comm);

    match event.event_type {
        EBPF_EVENT_EXIT => {
            if tid == pid {
                state.cache.pkgs.remove(&pid);
            }
            state.cache.task_del(tid);
            applied_del(&mut state.bpf, tid);
        }

        EBPF_EVENT_EXEC => {
            state.cache.pkgs.remove(&pid);
            if !event_apply(&mut state.cache, &mut state.bpf, tid, pid, &comm, cfg, true, false) {
                state.cache.task_del(tid);
                applied_del(&mut state.bpf, tid);
            }
        }

        EBPF_EVENT_FORK => {
            // FORK 子线程继承父 comm 不可信，主线程 tid==pid comm 为自身
            event_apply(&mut state.cache, &mut state.bpf, tid, pid, &comm, cfg, tid == pid, true);
        }

        EBPF_EVENT_RENAME => {
            event_apply(&mut state.cache, &mut state.bpf, tid, pid, &comm, cfg, true, false);
        }

        _ => {}
    }
}

/// 统一事件处理 pkg_lookup_comm 到 task_apply
// 参数直传避免每事件构造临时上下文结构，热路径有意设计，豁免 too_many_arguments。
#[allow(clippy::too_many_arguments)]
fn event_apply(
    cache: &mut ProcCache,
    bpf: &mut Ebpf,
    tid: i32,
    pid: i32,
    comm: &str,
    cfg: &AppConfig,
    mut trust_comm: bool,
    is_fork: bool,
) -> bool {
    let Some((pkg, has_thread_rules)) = cache.pkg_lookup_comm(pid, comm, cfg) else {
        return false;
    };

    // fork 子线程【去继承】：内核会把父线程的 uclamp/timerslack(及可能的 WALT 提示)带给子线程。
    // uclamp 已靠 sched_setattr 的 RESET_ON_FORK 源头免疫；这里把 WALT 提示 + timerslack 写默认
    // 抹掉，随后 task_apply 按子线程【自己】规则重设(命中才设)。只在 FORK、对已管理进程的子线程
    // 做，且只清配置实际用到的项，开销受规则集约束。
    if is_fork {
        crate::vendor_boost::scrub_fork_child(tid, &pkg, cfg);
        // 仅当【本包】有 :slack 规则才抹 timerslack：否则会把非 :slack 受管包的 fork 子线程
        // 强写成默认 50000，改掉它本该继承的(可能非默认)系统 timerslack。
        if cfg.rules.iter().any(|r| r.pkg == pkg && r.timerslack.is_some()) {
            crate::timerslack::timerslack_scrub(tid);
        }
    }

    // :m —— 同名线程全绑(纯事件、不扫 /proc)。fork 子线程的 comm 默认不可信(可能是待改名的
    // 继承父名);但若它继承到的正好是某条带 :m 线程规则的名字,就直接按线程名绑,不等 task_rename。
    // 于是"clone 继承同名、自身不再改名"的后生线程也能被自己的 FORK 事件绑上;会改名的线程仍由
    // RENAME 纠正。每个线程都由它自己的事件(FORK/RENAME)绑定,无需扫兄弟、零额外 /proc。
    // 但此路只复制【绑核/cpuset】(bind_only)：per-task 强度 hint(sched/boost/uclamp/slack/:p:w:g
    // 等)不灌到继承名的子线程,只作用于按自己真实名字命中的线程。
    let mut bind_only = false;
    if !trust_comm && has_thread_rules && crate::rule_match::same_name_match(&pkg, comm, cfg) {
        trust_comm = true;
        bind_only = true;
    }

    cache.task_apply(tid, pid, &pkg, comm, has_thread_rules, cfg, trust_comm, bind_only, |t, c, d| {
        affinity_apply(t, c, d, cfg, bpf)
    });

    true
}

/// 定期纠正：affinity_sync 重刷亲和/调度并清死亡 tid，同步 APPLIED_MAP。
pub fn affinity_check(state: &mut EbpfState, cfg: &AppConfig) {
    let dead_tids = state.cache.affinity_sync(&cfg.topo);
    for tid in dead_tids {
        applied_del(&mut state.bpf, tid);
    }
}

/// 启动或配置更新时的全量 /proc 扫描：每进程先按 cmdline 全名、再按 comm 匹配包名，
/// 命中即绑定其全部线程并缓存 pkg。仅此一次读 /proc，纳管后靠 APPLIED_MAP + 事件维持，
/// 稳态零 /proc 读。cmdline 覆盖 comm≠配置名的原生服务（如 HAL：comm 截断、全名只在 cmdline）。
pub fn full_scan(cfg: &AppConfig, state: &mut EbpfState) {
    state.cache.clear();
    applied_clear(&mut state.bpf);

    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return;
    };
    let targets: Vec<(i32, String, bool)> = proc_dir
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_string_lossy().parse::<i32>().ok()?;
            let pkg = read_cmdline(pid)
                .and_then(|n| comm_to_pkg(&n, cfg))
                .or_else(|| comm_to_pkg(&tid_comm(pid)?, cfg))?;
            let htr = cfg.has_thread_rules.contains(&pkg);
            Some((pid, pkg, htr))
        })
        .collect();

    for (pid, pkg, htr) in targets {
        let Some(tids) = task_tids(pid) else {
            continue;
        };
        for tid in tids {
            let t_name = if htr {
                tid_comm(tid).unwrap_or_default()
            } else {
                String::new()
            };
            state.cache.task_apply(tid, pid, &pkg, &t_name, htr, cfg, true, false, |t, c, d| {
                affinity_apply(t, c, d, cfg, &mut state.bpf)
            });
        }
        state.cache.pkgs.insert(pid, (pkg, htr));
    }
}



