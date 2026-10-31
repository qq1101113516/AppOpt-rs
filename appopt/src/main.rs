#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_endian = "big")]
compile_error!("AppOpt assumes a little-endian target for its cpu_set_t bitmask layout");

mod apply_affinity;
mod cache;
mod config;
mod cpuset;
mod ebpf_mode;
mod hard;
mod hmbird;
mod oplus;
mod proc_mode;
mod rule_edit;
mod rule_match;
mod sched;
mod skipself;
mod timerslack;
mod uclamp;
mod vendor_boost;
mod walt;
mod web;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::env;
use std::ffi::CString;
use std::fs;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{
    config_loader, load_config, CHECK_INTERVAL, CONFIG_FILE, CURRENT_CONFIG,
    INOTIFY_FD, INOTIFY_SUPPORTED, INOTIFY_WD,
};
use crate::cpuset::{init_cpu_topo, set_base_cpuset};
use crate::ebpf_mode::{
    affinity_check, full_scan, event_dispatch, comm_map_init,
    ebpf_init, EbpfState,
};
use crate::proc_mode::{cache_sync, ProcScanState};
use crate::web::{
    cache_hits, cache_stats, settings_load, settings_save, web_start, WebStats,
    MODE_FORCE, PAUSED, SETTINGS_FILE, WEB_ENABLED, WEB_STATS,
};

pub const MAX_PKG_LEN: usize = 128;
pub const MAX_THREAD_LEN: usize = 32;

pub static CONFIG_UPDATED: AtomicBool = AtomicBool::new(false);

/// 自动模式下 eBPF 初始化失败后的放弃标记，用户经 web 强制切换时清除以允许重试
pub static EBPF_GAVE_UP: AtomicBool = AtomicBool::new(false);

pub(crate) fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| {
        eprintln!("警告: 互斥锁中毒，尝试恢复...");
        e.into_inner()
    })
}

fn print_help(prog_name: &str) {
    println!("Usage: {} [OPTIONS]", prog_name);
    println!("Options:");
    println!("  -c <config_file>   指定配置文件 (默认: ./applist.conf)");
    println!("  -s <interval>      设置检查间隔(秒) (必须>=1, 默认: 2)");
    println!("  -b <cpuset_name>   指定 BASE_CPUSET 目录名 (默认: AppOpt)");
    println!("  -w                 启用网页前端 (仅本机 127.0.0.1:8889)");
    println!("  -r                 放宽 RT 带宽限流(配合 :RR/:FIFO，全局旋钮，默认关)");
    println!("  -P                 启用 OPLUS pipeline 动态换 prime(pipeline_prime_rearrange,默认1 51 10,值可网页前端调);");
    println!("                     仅 :p 多线程 + OPLUS 生效，退出还原，默认关");
    println!("  -S                 启用 OPLUS skip_gameself 锁(进程级:内核丢弃游戏对自己所有线程的");
    println!("                     setaffinity);仅对配置了 :p 的包生效，默认关。cpuset 已硬限时通常不需要");
    println!("  -v                 显示程序版本");
    println!("  -h                 显示帮助信息");
    println!();
    println!("示例:");
    println!("  {} -c /data/applist.conf -s 3", prog_name);
    println!("  {} -b MyAppOpt", prog_name);
    println!();
    println!("应用设置保存于 ./AppOpt.json，首次运行自动创建；");
    println!("命令行参数优先于设置文件，web 端修改会写回该文件。");
    println!();
    println!("规则格式:");
    println!("  # 注释以 # 或 // 开头");
    println!("  com.example=0-3           包级规则，绑定到 CPU 0-3");
    println!("  com.example=e-core        语义核心，绑定到全部小核");
    println!("  com.example=p-core        语义核心，绑定到全部中核");
    println!("  com.example=hp-core       语义核心，绑定到全部大核");
    println!();
    println!("  块语法，包级规则 + 线程规则");
    println!("  com.example {{");
    println!("    RenderThread=6-7");
    println!("    Thread-1=0-5");
    println!("  }}");
    println!("  线程 RenderThread 绑定到 CPU 6-7");
    println!("  线程 Thread-1 绑定到 CPU 0-5");
    println!();
    println!("  可选后缀（可组合，顺序无关）:");
    println!("  :FIFO:n / :RR:n     实时调度，rtprio 1..99");
    println!("  :nice:n             普通调度 nice 值 -20..19");
    println!("  :boost[:n] / :b[:n] 厂商 per-task boost，软贴大核(高通 WALT / 联发科 FPSGO)；不带 n 默认 2");
    println!("                      WALT level: 0=不boost 1=中核簇 2=大核簇 3=强制大核");
    println!("                      (联发科 FPSGO 按其自身语义，旧版惯用 2)");
    println!("  :umin[:n] / :u[:n]  per-task uclamp 性能地板 0..1024；不带 n 默认 812");
    println!("  :umax[:n] / :x[:n]  per-task uclamp 频率封顶 0..1024；不带 n 默认 1024(不封顶)");
    println!("  :reduce:<cpuspec>   WALT task_reduce_affinity，把线程软性收窄到指定核(仅高通)");
    println!("  :ll                 WALT 低延迟标记(sched_low_latency)，唤醒优先塞空闲核(仅高通)");
    println!("  :loadboost:<val>    WALT task_load_boost，抬高任务负载读数→占大核+拉频(仅高通)");
    println!("  :p[:cpu]            流水线任务(跨厂商)。OPLUS 写 pipeline_pids_cpus 钉到大核；");
    println!("                      带 :cpu 指定该线程的目标核(1..在线核数-1，0/越界回落掩码最高核)，");
    println!("                      不带则取绑定掩码最高核。多线程各配不同核=官方分核用法(WALT 忽略 cpu)");
    println!("  :pf:<cpuspec>       HMBIRD II prefer_cpu，软偏好指定核(如 :pf:hp-core / :pf:7 贴超大核);");
    println!("                      仅 /proc/sys/hmbird_II(如 sm8850);HMBIRD v1(sm8750)/非 HMBIRD 跳过，v1 贴核用 :p");
    println!("  :pcl:<cpuspec>      HMBIRD II prefer_cluster，软偏好指定簇(按 cpuspec 命中的簇)");
    println!("  :pi                 HMBIRD II prefer_idle，唤醒优先空闲核(降延迟，per-task 不外溢)");
    println!("  :pp                 HMBIRD II prefer_preempt，抢占倾向(关键线程更快上核)");
    println!("  例: RenderThread=3-7:boost:2       绑定 3-7 并 boost 到大核簇");
    println!("  例: UnityMain=0-7:boost:2          不限核，仅软贴大核(不困死)");
    println!("  例: UnityMain=0-7:reduce:hp-core   不限核，WALT 软性收窄到大核");
    println!("  例: UnityMain=3-7:p:7  UnityGfxDeviceW=3-7:p:6  Job.worker*=3-7:p:5");
    println!("      (OPLUS pipeline 把三条线程分别钉 7/6/5 核，最高核 7=prime)");
    println!();
    println!("生效范围: 命中配置包即绑定并施加优化，常驻生效(不区分前后台)。");
}

fn init_inotify(config_file: &str) {
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if inotify_fd < 0 {
        println!("inotify初始化失败，使用轮询模式");
        return;
    }
    // 路径含 NUL 时无法构造 CString，降级到轮询模式
    let cfg_cstr = match CString::new(config_file) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("错误: 配置文件路径包含非法字符，使用轮询模式");
            unsafe { libc::close(inotify_fd); }
            return;
        }
    };
    let wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };
    if wd >= 0 {
        INOTIFY_SUPPORTED.store(true, Ordering::Release);
        INOTIFY_FD.store(inotify_fd, Ordering::Release);
        INOTIFY_WD.store(wd, Ordering::Release);
        println!("启用inotify监控配置文件变更");
    } else {
        unsafe {
            libc::close(inotify_fd);
        }
        println!("inotify初始化失败，使用轮询模式");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog_name = &args[0];

    // 参数解析先行，-v/-h/错误用法在设置加载前退出，不产生文件副作用；
    // -c/-s/-b/-w 可覆盖 AppOpt.json 里的持久化设置(命令行优先)
    let (mut cli_cfg, mut cli_interval, mut cli_cpuset, mut cli_web) =
        (None, None, None, false);
    // 全局旋钮 CLI 标志：出现即“要求开启”，与 AppOpt.json 持久值取或(命令行优先强制为真)。
    let (mut cli_rt_relax, mut cli_pipe_rearrange, mut cli_skip_gameself) = (false, false, false);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                if i < args.len() {
                    cli_cfg = Some(args[i].clone());
                    println!("配置文件: {}", args[i]);
                } else {
                    eprintln!("错误: -c 需要指定配置文件路径");
                    process::exit(1);
                }
            }
            "-s" => {
                i += 1;
                if i < args.len() {
                    let val: u64 = match args[i].parse() {
                        Ok(v) if v >= 1 => v,
                        _ => {
                            eprintln!("无效的时间间隔: {}", args[i]);
                            eprintln!("间隔必须是 >=1 的整数");
                            process::exit(1);
                        }
                    };
                    cli_interval = Some(val);
                    println!("检查间隔: {} 秒", val);
                } else {
                    eprintln!("错误: -s 需要指定时间间隔");
                    process::exit(1);
                }
            }
            "-b" => {
                i += 1;
                if i < args.len() {
                    if !crate::cpuset::valid_cpuset_name(&args[i]) {
                        eprintln!("无效的 cpuset 目录名: {}", args[i]);
                        eprintln!("只允许字母/数字/下划线/连字符，且不能为空或含 / . ..");
                        process::exit(1);
                    }
                    cli_cpuset = Some(args[i].clone());
                    println!("cpuset 目录名: {}", args[i]);
                } else {
                    eprintln!("错误: -b 需要指定 cpuset 目录名");
                    process::exit(1);
                }
            }
            "-w" => {
                cli_web = true;
            }
            "-r" => {
                cli_rt_relax = true;
            }
            "-P" => {
                cli_pipe_rearrange = true;
            }
            "-S" => {
                cli_skip_gameself = true;
            }
            "-v" => {
                if crate::ebpf_mode::ebpf_probe() {
                    println!("AppOpt 版本 {} eBPF", env!("CARGO_PKG_VERSION"));
                } else {
                    println!("AppOpt 版本 {}", env!("CARGO_PKG_VERSION"));
                }
                process::exit(0);
            }
            "-h" => {
                print_help(prog_name);
                process::exit(0);
            }
            other => {
                eprintln!("未知选项: {}", other);
                print_help(prog_name);
                process::exit(1);
            }
        }
        i += 1;
    }

    // 应用设置持久化于 AppOpt.json，命令行参数优先覆盖
    let st = settings_load(SETTINGS_FILE);
    let config_file = cli_cfg.unwrap_or(st.config_file);
    let sleep_interval = cli_interval.unwrap_or(st.check_interval);
    let cpuset_name = cli_cpuset.unwrap_or(st.cpuset_name);
    let web_enable = cli_web || st.web_enable;
    // 全局旋钮生效值：命令行标志出现即强制为真，否则沿用 AppOpt.json 持久值(命令行优先)。
    let rt_relax = cli_rt_relax || st.rt_relax;
    let pipe_rearrange = cli_pipe_rearrange || st.pipe_rearrange;
    let skip_gameself = cli_skip_gameself || st.skip_gameself;

    // 先设置 cpuset 路径再初始化拓扑，init_cpu_topo 会创建 BASE_CPUSET 目录
    set_base_cpuset(&cpuset_name);
    let topo = init_cpu_topo();

    // 自我降级：把优化器自身丢进 background cpuset(小核)+降优先级，别跟被优化的游戏抢大核
    cpuset::demote_self();

    // 全局旋钮启动即应用一次（CLI 标志 或 AppOpt.json 持久值）：
    //   -r 放宽 RT 带宽限流(系统级)；-P OPLUS 动态换 prime；-S OPLUS skip_gameself 进程级锁。
    // 之后 web 端可运行期热切换(开启即应用、关闭即还原)，并写回 AppOpt.json。
    sched::set_rt_relax(rt_relax);
    // rearrange 可调值须在开关之前设，确保开启用的是持久化的新值
    oplus::set_rearrange_value(st.rearrange_mode, st.rearrange_amp, st.rearrange_cnt);
    oplus::set_rearrange_opt(pipe_rearrange);
    oplus::set_skip_opt(skip_gameself);
    oplus::set_route(st.pipeline_route);
    // skip_self_setaffinity 全局位掩码(仅 appopt 通用 ko 有此节点;防 app 用 sched_setaffinity
    // 覆盖我们贴好的核)。启动即应用一次;web 端可热改并写回 AppOpt.json。非本 ko 机型 no-op。
    skipself::set(st.skip_self);
    // WALT util 阈值旋钮（全局 sysctl，opt-in，退出还原；非 WALT 机型 no-op）
    walt::set_boost(st.walt_boost, st.walt_boost_val);
    walt::set_uclamp(st.walt_uclamp, st.walt_uclamp_val);
    // OPLUS pipeline 伴随旋钮（opt-in，pipeline 生效时施加、清空/关闭时还原；非 OPLUS/无节点 no-op）
    oplus::set_rt_cpumask(st.rt_skip, st.rt_skip_mask);
    oplus::set_immuned(st.immuned, st.immuned_names.clone());
    oplus::set_pipeline_args(
        st.pipe_args,
        st.pipe_args_lowlat,
        st.pipe_args_nopipe,
        st.pipe_args_dislike as i32,
    );
    // 全局暂停持久值：启动即恢复上次的暂停状态
    PAUSED.store(st.paused, Ordering::Relaxed);
    if rt_relax {
        println!("已启用 RT 带宽放宽(配合 :RR/:FIFO)");
    }
    if pipe_rearrange {
        println!("已启用 OPLUS pipeline 动态换 prime(仅 :p 多线程 + OPLUS 生效)");
    }
    if skip_gameself {
        println!("已启用 OPLUS skip_gameself 进程级锁(仅对配置了 :p 的包生效)");
    }

    if fs::metadata(&config_file).is_err() {
        let initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";
        if fs::write(&config_file, initial_content).is_ok() {
            println!("配置文件不存在，重建一个空的配置文件: {}", config_file);
        }
    }

    // 运行期可调参数落入全局：config_loader / 主循环读 CHECK_INTERVAL；web 端热切换配置文件读 CONFIG_FILE
    {
        let mut guard = lock_ignore_poison(&CONFIG_FILE);
        *guard = config_file.clone();
    }
    CHECK_INTERVAL.store(sleep_interval, Ordering::Release);
    MODE_FORCE.store(st.mode, Ordering::Release);

    let mut tmp_mtime: i64 = -1;
    let initial_config = match load_config(&config_file, &topo, &mut tmp_mtime) {
        Some(cfg) => cfg,
        None => {
            eprintln!("初始配置加载失败");
            process::exit(1);
        }
    };

    {
        let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(initial_config));
    }
    CONFIG_UPDATED.store(true, Ordering::Release);

    init_inotify(&config_file);

    // 守护进程模式，保留 JoinHandle 以便检测线程 panic 后重启
    let mut config_handle = thread::spawn(config_loader);

    // 仅在真正回退到 /proc 轮询时才分配（eBPF 模式下始终为 None，省去两张 HashMap）
    let mut proc_state: Option<ProcScanState> = None;
    let mut affinity_deadline = Instant::now();
    let prog_start = Instant::now();
    let mut web_stats_deadline = Instant::now();
    // 预支 60 秒使首次 eBPF 重试立即到期
    let mut ebpf_retry_at = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);
    // 跟踪上轮工作模式：切到 auto/eBPF 时让下一轮 eBPF 重试立即触发（免等 30s 周期）
    let mut last_mode = MODE_FORCE.load(Ordering::Relaxed);
    // 全局暂停状态跟踪：进入暂停时还原一次，退出暂停时触发全量重扫
    let mut was_paused = false;

    println!("启动AppOpt服务 v{}", env!("CARGO_PKG_VERSION"));

    // Web 前端启停状态与 eBPF 初始化同阶段输出（横幅之后），成功/失败/未启用一律明示，风格对齐 eBPF。
    if web_enable {
        web_start(); // 成功打印 "Web: 前端已启用 http://..."；绑定失败打印 "Web: 监听 ... 失败 (...)"
        // -w 或设置恢复启用后落盘，重启保持开启
        settings_save();
    } else {
        println!("Web: 前端未启用（-w 启用，或在网页设置里持久开启）");
    }

    // 恢复的强制 /proc 模式无需 eBPF 初始化
    let mut ebpf_state: Option<EbpfState> =
        if MODE_FORCE.load(Ordering::Relaxed) == 2 { None } else { ebpf_init() };
    // 仅自动模式失败一次即放弃；强制 eBPF 需持续重试，强制 /proc 无需 eBPF
    if ebpf_state.is_none() && MODE_FORCE.load(Ordering::Relaxed) == 0 {
        EBPF_GAVE_UP.store(true, Ordering::Relaxed);
    }

    // SIGTERM/SIGINT 时置位，主循环据此还原全部调度策略后退出（退出清理还原）
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        let _ = signal_hook::flag::register(sig, shutdown.clone());
    }

    // 启动即无条件清空一加锁节点，清除上次非正常退出(SIGKILL/强杀/崩溃)残留的
    // game_pid/skip；否则脏残留会让 skip 锁状态与实际运行的 :p 包错位、规则应用异常。
    oplus::game_lock_reset();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            sched::sched_restore_all();
            vendor_boost::restore_all();
            uclamp::uclamp_restore_all();
            timerslack::timerslack_restore_all();
            oplus::pipeline_restore_all();
            hmbird::prefer_restore_all();
            hard::hard_restore_all();
            oplus::game_lock_restore_all();
            walt::restore_all();
            // 全局 RT 带宽旋钮(-r)退出还原，与 walt/rearrange/skip 等其它全局旋钮对称——
            // 否则带 -r 启动后被 kill，rt_runtime_us/rt_period_us/rr_timeslice_ms 会残留在改过的值。
            sched::restore_rt_knobs();
            process::exit(0);
        }

        // 全局暂停：还原全部 per-task 优化并停止绑定；恢复时触发全量重扫重绑。全局旋钮(-r/-P/-S/WALT)不受影响。
        if PAUSED.load(Ordering::Relaxed) {
            if !was_paused {
                sched::sched_restore_all();
                vendor_boost::restore_all();
                uclamp::uclamp_restore_all();
                timerslack::timerslack_restore_all();
                oplus::pipeline_restore_all();
                hmbird::prefer_restore_all();
                hard::hard_restore_all();
                oplus::game_lock_restore_all();
                if let Some(es) = &mut ebpf_state {
                    es.cache.clear();
                }
                if let Some(ps) = &mut proc_state {
                    ps.cache.clear();
                }
                was_paused = true;
                println!("已暂停优化：还原全部线程优化并停止绑定");
            }
            // 排空 eBPF 事件通道，避免暂停期间事件积压涨内存
            if let Some(es) = &ebpf_state {
                while es.event_rx.try_recv().is_ok() {}
            }
            thread::sleep(Duration::from_secs(1));
            continue;
        }
        if was_paused {
            was_paused = false;
            CONFIG_UPDATED.store(true, Ordering::Release);
            if let Some(ps) = &mut proc_state {
                ps.scan_all_proc = true;
                ps.last_proc_count = 0;
                ps.force_affinity = true;
            }
            affinity_deadline = Instant::now();
            println!("已恢复优化：触发全量重扫重绑");
        }

        // 先 swap CONFIG_UPDATED 再获取 cfg 防止漏更新
        let config_changed = CONFIG_UPDATED.swap(false, Ordering::AcqRel);
        let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
            thread::sleep(Duration::from_millis(100));
            continue;
        };

        // 配置变更先还原旧调度策略与厂商 boost，再由下面的全量扫描按新配置重新应用
        if config_changed {
            sched::sched_restore_all();
            vendor_boost::restore_all();
            uclamp::uclamp_restore_all();
            timerslack::timerslack_restore_all();
            oplus::pipeline_restore_all();
            hmbird::prefer_restore_all();
            hard::hard_restore_all();
        }

        // 配置加载线程若 panic 退出则重启，避免此后配置变更失效
        if config_handle.is_finished() {
            eprintln!("警告: 配置加载线程异常退出，尝试重启...");
            config_handle = thread::spawn(config_loader);
        }

        // 运行期可调间隔与工作模式(web 端热更新)
        let sleep_interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        let mode = MODE_FORCE.load(Ordering::Relaxed);
        // 模式切换（如网页从 Proc 切回 auto/eBPF）当轮即刻尝试 eBPF，不等 30s 重试周期。
        let mode_changed = mode != last_mode;
        last_mode = mode;

        // 强制 /proc 时卸载 eBPF 并触发全量扫描
        if mode == 2 && ebpf_state.is_some() {
            println!("工作模式切换: /proc 轮询");
            ebpf_state = None;
            let cache = proc_state.get_or_insert_with(ProcScanState::new);
            cache.scan_all_proc = true;
            cache.last_proc_count = 0;
            cache.force_affinity = true;
            affinity_deadline = Instant::now();
        }

        // eBPF 缺失时周期重试：自动模式失败一次后放弃(EBPF_GAVE_UP)，强制 eBPF 持续重试
        if mode != 2
            && ebpf_state.is_none()
            && (mode == 1 || !EBPF_GAVE_UP.load(Ordering::Relaxed))
            && (mode_changed || ebpf_retry_at.elapsed() >= Duration::from_secs(30))
        {
            ebpf_retry_at = Instant::now();
            if let Some(mut new_es) = ebpf_init() {
                if comm_map_init(&mut new_es.bpf, &cfg.pkgs, new_es.comm_capacity) {
                    eprintln!("eBPF: 白名单容量不足，保持 /proc 轮询");
                    if mode == 0 {
                        EBPF_GAVE_UP.store(true, Ordering::Relaxed);
                    }
                } else {
                    println!("工作模式切换: eBPF 事件驱动");
                    full_scan(&cfg, &mut new_es);
                    ebpf_state = Some(new_es);
                    affinity_deadline = Instant::now();
                }
            } else if mode == 0 {
                EBPF_GAVE_UP.store(true, Ordering::Relaxed);
            }
        }

        let mut ebpf_dead = false;
        let mut need_ebpf_reload = false;
        match &mut ebpf_state {
            Some(es) => {
                if config_changed {
                    need_ebpf_reload = comm_map_init(&mut es.bpf, &cfg.pkgs, es.comm_capacity);
                    if !need_ebpf_reload {
                        full_scan(&cfg, es);
                    }
                }

                if !need_ebpf_reload {
                    match es.event_rx.recv_timeout(Duration::from_secs(1)) {
                        Ok(event) => {
                            event_dispatch(&event, &cfg, es);
                            while let Ok(event) = es.event_rx.try_recv() {
                                event_dispatch(&event, &cfg, es);
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            ebpf_dead = true;
                        }
                    }

                    // 每 3*sleep_interval 秒定期纠正，纯事件驱动零 /proc 读
                    if affinity_deadline.elapsed() >= Duration::from_secs(3 * sleep_interval) {
                        affinity_check(es, &cfg);
                        affinity_deadline = Instant::now();
                    }
                }
            }
            None => {
                let cache = proc_state.get_or_insert_with(ProcScanState::new);
                if config_changed {
                    cache.scan_all_proc = true;
                    cache.last_proc_count = 0;
                }

                cache_sync(cache, &cfg);
                if affinity_deadline.elapsed() >= Duration::from_secs(5 * sleep_interval) || cache.force_affinity {
                    cache.cache.affinity_sync(&cfg.topo);
                    affinity_deadline = Instant::now();
                    cache.force_affinity = false;
                }

                // 分 1 秒段睡眠并检查 shutdown：thread::sleep 遇信号会补足、不会被 SIGTERM 提前唤醒，
                // 若整段睡 sleep_interval(可大到 3600) 秒，关停会被拖到整个间隔后才响应。分段后关停延迟 ≤1s，
                // 与 eBPF 分支的 recv_timeout(1s) 对齐。
                for _ in 0..sleep_interval {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }

        // OPLUS skip_gameself 锁：当有【配了 :p 流水线】的配置包在运行时注册 game_pid + skip=1，
        // 让内核忽略游戏对自己 pipeline 线程的 sched_setaffinity（防它把贴好的线程弹回小核）；
        // 无 :p 包在运行则解锁。仅 -S 开启且探测到节点才生效，非 OPLUS no-op。
        let fg_game_pid = match &ebpf_state {
            Some(es) => es.cache.pipeline_pkg_pid(&cfg.pipeline_pkgs),
            None => proc_state
                .as_ref()
                .and_then(|ps| ps.cache.pipeline_pkg_pid(&cfg.pipeline_pkgs)),
        };
        oplus::game_lock_sync(fg_game_pid);

        if ebpf_dead {
            eprintln!("eBPF: 事件通道断开，回退到 /proc 轮询");
            ebpf_state = None;
            let cache = proc_state.get_or_insert_with(ProcScanState::new);
            cache.scan_all_proc = true;
            cache.last_proc_count = 0;
            cache.force_affinity = true;
            affinity_deadline = Instant::now();
        }

        // 容量不足先释放旧 BPF 程序再重载，置位 CONFIG_UPDATED 触发重建
        if need_ebpf_reload {
            ebpf_state.take();
            ebpf_state = ebpf_init();
            CONFIG_UPDATED.store(true, Ordering::Release);
            affinity_deadline = Instant::now();
        }

        // web 状态统计，低频更新避免高频事件循环下的额外开销
        if WEB_ENABLED.load(Ordering::Relaxed)
            && web_stats_deadline.elapsed() >= Duration::from_secs(2)
        {
            web_stats_deadline = Instant::now();
            let (threads, hit_pkgs, hits) = match (&ebpf_state, &proc_state) {
                (Some(es), _) => {
                    let (t, h) = cache_stats(&es.cache);
                    (t, h, cache_hits(&es.cache))
                }
                (None, Some(ps)) => {
                    let (t, h) = cache_stats(&ps.cache);
                    (t, h, cache_hits(&ps.cache))
                }
                _ => (0, 0, Vec::new()),
            };
            let ebpf_rename = ebpf_state.as_ref().map(|es| es.rename_ok).unwrap_or(false);
            *lock_ignore_poison(&WEB_STATS) = Some(WebStats {
                rules: cfg.rules.len(),
                pkgs: cfg.pkgs.len(),
                hit_pkgs,
                threads,
                ebpf: ebpf_state.is_some(),
                uptime: prog_start.elapsed().as_secs(),
                hits,
                ebpf_rename,
            });
        }
    }
}
