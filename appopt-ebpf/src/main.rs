#![no_std]
#![no_main]
#![allow(linker_messages)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf,
    },
    macros::{btf_tracepoint, map},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::BtfTracePointContext,
};

const EVENT_FORK: u32 = 1;
const EVENT_EXEC: u32 = 2;
const EVENT_RENAME: u32 = 3;
const EVENT_EXIT: u32 = 4;

/// task_struct 成员偏移，取自 /sys/kernel/btf/vmlinux 由用户态注入（因内核/设备而异禁止硬编码）。
/// tp_btf 拿到 task_struct 指针后按这些偏移读 pid/tgid/comm。全 0（task_pid==0）表示未注入。
#[repr(C)]
#[derive(Clone, Copy)]
struct TracepointOffsets {
    task_pid: u32,
    task_tgid: u32,
    task_comm: u32,
}

/// 进程事件，布局需与用户态 EbpfProcEvent 一致
#[repr(C)]
struct ProcEvent {
    pid: i32,
    tid: i32,
    comm: [u8; 16],
    event_type: u32,
}

const MAP_CAPACITY: u32 = 16 << 5;
const APPLIED_CAPACITY: u32 = 8192;

/// 白名单键为包名前 8 字节或末 8 字节
#[map]
static TARGET_COMM_MAP: HashMap<[u8; 8], u32> = HashMap::with_max_entries(MAP_CAPACITY, 0);

/// 已应用亲和性表 tid 到 CPU mask，LruHashMap 配合 ESRCH 兜底
#[map]
static APPLIED_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(APPLIED_CAPACITY, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// 用户态注入的 tracepoint 字段偏移单条 Array 索引 0
#[map]
static OFFSETS_MAP: Array<TracepointOffsets> = Array::with_max_entries(1, 0);

/// 读取偏移，task_pid 为 0 视为未注入返回 None
#[inline(always)]
fn offsets_load() -> Option<TracepointOffsets> {
    OFFSETS_MAP.get(0).and_then(|o| {
        if o.task_pid != 0 {
            Some(*o)
        } else {
            None
        }
    })
}

#[inline(always)]
fn applied_lookup(key: u32) -> bool {
    unsafe { APPLIED_MAP.get(&key) }.is_some()
}

/// 在 comm 16 字节上以 8 字节窗口滑动匹配白名单
#[inline(always)]
fn whitelist_matched(comm: &[u8; 16]) -> bool {
    for pos in 0..=8usize {
        // comm[pos..pos+8] 恒为 8 字节, try_from 必成功。不用 .unwrap_or([0u8;8]):
        // 那个 [0u8;8] 默认在 opt-level=s 下会被拆成 BPF-to-BPF 数组填充调用。
        if let Ok(key) = <[u8; 8]>::try_from(&comm[pos..pos + 8]) {
            if unsafe { TARGET_COMM_MAP.get(&key) }.is_some() {
                return true;
            }
        }
    }
    false
}

#[inline(always)]
fn submit_event(event: ProcEvent) {
    if let Some(mut entry) = EVENTS.reserve(0) {
        entry.write(event);
        entry.submit(0);
    }
}

/// FORK: tp_btf 参数 (parent, child) 两个 task_struct 指针。读 child->pid/comm，
/// 父被管理或子 comm 命中白名单即相关；通过后立即占位 APPLIED_MAP[child_tid]=0，
/// 防子线程随后改名（如 RenderThread）时因尚未跟踪、新名不在白名单而被 RENAME 丢弃。
/// pid 沿用父 tgid（clone 共享 TGID），进程 fork 场景由随后的 EXEC 纠正。
#[btf_tracepoint(function = "sched_process_fork")]
fn sched_process_fork(ctx: BtfTracePointContext) -> i32 {
    let Some(off) = offsets_load() else {
        return 0;
    };
    let child = ctx.arg::<*const u8>(1);
    let child_tid = unsafe { kread::<i32>(child, off.task_pid) }.unwrap_or(0);
    let child_comm = read_comm(child, off.task_comm);

    let pid_tgid = bpf_get_current_pid_tgid();
    let parent_tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let parent_tgid = (pid_tgid >> 32) as i32;

    if !applied_lookup(parent_tid) && !whitelist_matched(&child_comm) {
        return 0;
    }

    let _ = APPLIED_MAP.insert(&(child_tid as u32), &0, 0);

    submit_event(ProcEvent {
        pid: parent_tgid,
        tid: child_tid,
        comm: child_comm,
        event_type: EVENT_FORK,
    });
    0
}

/// EXEC: 用当前上下文即可，不需要 tp_btf 参数。已管理线程或自身 comm 命中白名单才上报
#[btf_tracepoint(function = "sched_process_exec")]
fn sched_process_exec(_ctx: BtfTracePointContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = (pid_tgid & 0xFFFFFFFF) as i32;
    let comm = bpf_get_current_comm().unwrap_or_default();

    if !applied_lookup(tid as u32) && !whitelist_matched(&comm) {
        return 0;
    }

    submit_event(ProcEvent {
        pid: (pid_tgid >> 32) as i32,
        tid,
        comm,
        event_type: EVENT_EXEC,
    });
    0
}

/// RENAME: tp_btf 参数 (task, comm)。tid/tgid 取自被改名的 task 本身（比当前上下文更准，
/// 覆盖 pthread_setname_np 改他人线程的场景），新名取自 comm 指针
#[btf_tracepoint(function = "task_rename")]
fn task_rename(ctx: BtfTracePointContext) -> i32 {
    let Some(off) = offsets_load() else {
        return 0;
    };
    let task = ctx.arg::<*const u8>(0);
    let tid = unsafe { kread::<i32>(task, off.task_pid) }.unwrap_or(0);
    if tid == 0 {
        return 0;
    }
    let tgid = unsafe { kread::<i32>(task, off.task_tgid) }.unwrap_or(0);

    let comm_ptr = ctx.arg::<*const u8>(1);
    let new_comm = read_comm(comm_ptr, 0);

    if !applied_lookup(tid as u32) && !whitelist_matched(&new_comm) {
        return 0;
    }

    submit_event(ProcEvent {
        pid: tgid,
        tid,
        comm: new_comm,
        event_type: EVENT_RENAME,
    });
    0
}

/// EXIT: 已管理线程清理 APPLIED_MAP。用当前上下文即可，不需要 tp_btf 参数
#[btf_tracepoint(function = "sched_process_exit")]
fn sched_process_exit(_ctx: BtfTracePointContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;

    if !applied_lookup(tid) {
        return 0;
    }

    let _ = APPLIED_MAP.remove(&tid);

    submit_event(ProcEvent {
        pid: tgid as i32,
        tid: tid as i32,
        comm: [0u8; 16],
        event_type: EVENT_EXIT,
    });
    0
}

/// 从内核指针 base + off 处读取 T，失败返回 None
#[inline(always)]
unsafe fn kread<T>(base: *const u8, off: u32) -> Option<T> {
    unsafe { bpf_probe_read_kernel(base.add(off as usize) as *const T).ok() }
}

/// 读 base+off 处 16 字节 comm 到【预清零】缓冲：base 为空或读失败都保持全 0。
/// 关键在于缓冲无条件初始化、用 bpf_probe_read_kernel_buf 就地写入，避开
/// `kread::<[u8;16]>().unwrap_or([0u8;16])` 那种 Option 合并 + [0u8;16] 数组填充——
/// 后者在 opt-level=s 下被拆成 BPF-to-BPF 调用，verifier 跨调用证不出栈已初始化，
/// 报 "invalid read from stack"。
#[inline(always)]
fn read_comm(base: *const u8, off: u32) -> [u8; 16] {
    let mut buf = [0u8; 16];
    if !base.is_null() {
        let _ = unsafe { bpf_probe_read_kernel_buf(base.add(off as usize), &mut buf) };
    }
    buf
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
