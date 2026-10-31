use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::apply_affinity::{read_cmdline, task_tids};
use crate::cache::ProcCache;
use crate::config::{
    config_reload_now, spec_like,
    CHECK_INTERVAL, CONFIG_FILE, CURRENT_CONFIG, FORCE_RELOAD, PARSE_FAILS,
};
use crate::cpuset::{base_cpuset, create_cpuset_dir, parse_cpu_spec, CpuSet, CpuTopology, DEFAULT_CPUSET_NAME};
use crate::ebpf_mode::ebpf_probe;
use crate::rule_edit::{rule_delete, rule_delete_pkg, rule_rename, rule_toggle_line, rule_upsert, RuleEdit};
use crate::{lock_ignore_poison, EBPF_GAVE_UP, MAX_PKG_LEN, MAX_THREAD_LEN};

pub const WEB_PORT: u16 = 8889;
/// 完整前端 UI，编译期内嵌进二进制，由本机 :8889 服务器提供。
/// (模块 webroot/index.html 只是给管理器 WebUI 入口用的跳转页，不在此处提供。)
const INDEX_HTML: &str = include_str!("../web/index.html");

pub static MODE_FORCE: AtomicU8 = AtomicU8::new(0);
pub static WEB_ENABLED: AtomicBool = AtomicBool::new(false);
/// 全局暂停优化：置位后主循环还原全部已应用的 per-task 优化并停止绑定，清零后重扫重绑。
/// 全局旋钮(-r/-P/-S/WALT)不受其影响。由 web 端切换、AppOpt.json 持久化。
pub static PAUSED: AtomicBool = AtomicBool::new(false);

pub static WEB_STATS: Mutex<Option<WebStats>> = Mutex::new(None);

#[derive(Clone)]
pub struct WebStats {
    pub rules: usize,
    pub pkgs: usize,
    pub hit_pkgs: usize,
    pub threads: usize,
    pub ebpf: bool,
    pub uptime: u64,
    /// 当前生效一览：(包名, 已绑定线程 tid 列表)，按线程数降序。数据源为内存缓存，零额外 /proc 读。
    pub hits: Vec<(String, Vec<i32>)>,
    /// eBPF 挂载点状态(供状态页展示)：task_rename(改名跟踪)
    pub ebpf_rename: bool,
}

/// 缓存统计。适配本仓 ProcCache：包名存于 `pkgs`(pid→(pkg,htr))，TaskEntry 不含 pkg 字段，
/// 故命中包数取 `pkgs` 里去重后的包名数，线程数取 `tasks` 条目数。
pub fn cache_stats(cache: &ProcCache) -> (usize, usize) {
    let pkgs: HashSet<&str> = cache.pkgs.values().map(|(pkg, _)| pkg.as_str()).collect();
    (cache.tasks.len(), pkgs.len())
}

/// 当前生效一览：按包名聚合已绑定线程的 tid 列表(所有已绑定的包)，按线程数降序。全用内存缓存，
/// 零额外 /proc 读；线程名(comm)不在此读，由前端展开时按需经 /api/tidcomm 拉取(非常驻)。
pub fn cache_hits(cache: &ProcCache) -> Vec<(String, Vec<i32>)> {
    let mut m: HashMap<&str, Vec<i32>> = HashMap::new();
    for (tid, t) in cache.tasks.iter() {
        if let Some((pkg, _)) = cache.pkgs.get(&t.pid) {
            m.entry(pkg.as_str()).or_default().push(*tid);
        }
    }
    let mut v: Vec<(String, Vec<i32>)> = m
        .into_iter()
        .map(|(k, tids)| (k.to_string(), tids))
        .collect();
    v.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    v
}

/// 启动 web 前端
pub fn web_start() {
    let listener = match TcpListener::bind(("127.0.0.1", WEB_PORT)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Web: 监听 127.0.0.1:{} 失败 ({})", WEB_PORT, e);
            return;
        }
    };
    WEB_ENABLED.store(true, Ordering::Release);
    println!("Web: 前端已启用 http://127.0.0.1:{}/", WEB_PORT);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || conn_handle(stream));
        }
    });
}

struct Request {
    method: String,
    path: String,
    host: String,
    origin: String,
    fetch_site: String,
    content_type: String,
    body: Vec<u8>,
    keep_alive: bool,
}

fn conn_handle(stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_nodelay(true);
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    while let Some(req) = request_read(&mut reader) {
        dispatch(&mut writer, &req);
        if !req.keep_alive {
            return;
        }
    }
}

fn request_read(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut head = Vec::with_capacity(512);
    let mut line = Vec::with_capacity(128);
    loop {
        line.clear();
        reader.read_until(b'\n', &mut line).ok()?;
        if line.is_empty() {
            return None;
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        head.extend_from_slice(&line);
        if head.len() > 8192 {
            return None;
        }
    }

    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.lines();
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.split('?').next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let (mut host, mut origin, mut site, mut ctype, mut len) =
        (String::new(), String::new(), String::new(), String::new(), 0usize);
    let mut conn = String::new();
    for h in lines {
        let Some((k, v)) = h.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "host" => host = v.to_ascii_lowercase(),
            "origin" => origin = v.to_ascii_lowercase(),
            "sec-fetch-site" => site = v.to_ascii_lowercase(),
            "content-type" => ctype = v.to_ascii_lowercase(),
            "content-length" => len = v.parse().unwrap_or(usize::MAX),
            "connection" => conn = v.to_ascii_lowercase(),
            "transfer-encoding" => return None, // 拒绝 chunked
            _ => {}
        }
    }
    // 常规请求体上限 16 KiB；原始配置编辑(/api/rawconfig)放宽——256 KiB 文本经 JSON 转义后可翻倍。
    let len_cap = if path == "/api/rawconfig" { 640 * 1024 } else { 16384 };
    if len > len_cap {
        return None;
    }

    let mut body = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    let keep_alive = if version == "HTTP/1.0" {
        conn.contains("keep-alive")
    } else {
        !conn.contains("close")
    };
    Some(Request {
        method,
        path,
        host,
        origin,
        fetch_site: site,
        content_type: ctype,
        body,
        keep_alive,
    })
}

fn resp_send(out: &mut TcpStream, status: u16, ctype: &str, body: &[u8], close: bool) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: {}\r\n\r\n",
        status,
        reason,
        ctype,
        body.len(),
        if close { "close" } else { "keep-alive" }
    );
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(body);
    let _ = out.flush();
}

fn dispatch(out: &mut TcpStream, req: &Request) {
    let port_str = format!(":{}", WEB_PORT);
    let host = req.host.strip_suffix(&port_str).unwrap_or(req.host.as_str());
    let origin_ok = matches!(host, "127.0.0.1" | "localhost")
        && (req.origin.is_empty()
            || req.origin == "null"
            || matches!(req.fetch_site.as_str(), "" | "none" | "same-origin"))
        && (req.method != "POST" || req.content_type.starts_with("application/json"));
    if !origin_ok {
        resp_send(out, 403, "application/json", b"{\"ok\":false,\"err\":\"forbidden\"}", true);
        return;
    }

    if req.method == "GET" && matches!(req.path.as_str(), "/" | "/index.html") {
        resp_send(out, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes(), !req.keep_alive);
        return;
    }

    let (status, body) = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/status") => (200, status_json()),
        ("GET", "/api/rules") => (200, rules_json()),
        ("GET", "/api/config") => (200, config_json()),
        ("GET", "/api/rawconfig") => (200, rawconfig_json()),
        ("POST", "/api/rawconfig") => rawconfig_set_api(req),
        ("POST", "/api/rule") => rule_api(req),
        ("POST", "/api/rule/del") => rule_del_api(req),
        ("POST", "/api/rule/rename") => rule_rename_api(req),
        ("POST", "/api/rule/toggle") => rule_toggle_api(req),
        ("POST", "/api/config") => config_set_api(req),
        ("POST", "/api/suggest") => suggest_api(req),
        ("GET", "/api/snapshots") => (200, snapshots_json()),
        ("POST", "/api/snapshot/save") => {
            snapshot_save();
            (200, json!({ "ok": true }).to_string())
        }
        ("POST", "/api/snapshot/restore") => snapshot_restore_api(req),
        ("POST", "/api/tidcomm") => tidcomm_api(req),
        _ => err_json(404, "not found"),
    };
    resp_send(out, status, "application/json", body.as_bytes(), !req.keep_alive);
}

fn err_json(code: u16, msg: &str) -> (u16, String) {
    (code, json!({ "ok": false, "err": msg }).to_string())
}

fn current_cfg() -> Option<std::sync::Arc<crate::config::AppConfig>> {
    lock_ignore_poison(&CURRENT_CONFIG).clone()
}

fn sys_procs() -> u16 {
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } == 0 {
        info.procs
    } else {
        0
    }
}

/// CPU 集合转语义名
fn spec_name(cpus: &CpuSet, topo: &CpuTopology) -> String {
    if cpus.count() > 0 {
        if *cpus == topo.e_core {
            return "e-core".into();
        }
        if *cpus == topo.p_core {
            return "p-core".into();
        }
        if *cpus == topo.hp_core {
            return "hp-core".into();
        }
        if *cpus == topo.present_cpus {
            return "all-core".into();
        }
    }
    cpus.to_range_string()
}

fn status_json() -> String {
    let stats = lock_ignore_poison(&WEB_STATS).clone();
    let cfg = current_cfg();
    let topo = cfg.as_ref().map(|c| &c.topo);
    let s = stats.unwrap_or(WebStats {
        rules: 0,
        pkgs: 0,
        hit_pkgs: 0,
        threads: 0,
        ebpf: false,
        uptime: 0,
        hits: Vec::new(),
        ebpf_rename: false,
    });
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if s.ebpf { "ebpf" } else { "proc" },
        "paused": PAUSED.load(Ordering::Relaxed),
        "ebpf_rename": s.ebpf_rename,
        "hits": s.hits.iter().map(|(p, tids)| json!({ "pkg": p, "n": tids.len(), "tids": tids })).collect::<Vec<_>>(),
        "uptime": s.uptime,
        "rules": s.rules,
        "pkgs": s.pkgs,
        "parse_fail": PARSE_FAILS.load(Ordering::Relaxed),
        "hit_pkgs": s.hit_pkgs,
        "threads": s.threads,
        "total_procs": sys_procs(),
        "interval": CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        "e_core": topo.map(|t| t.e_core.to_range_string()).unwrap_or_default(),
        "p_core": topo.map(|t| t.p_core.to_range_string()).unwrap_or_default(),
        "hp_core": topo.map(|t| t.hp_core.to_range_string()).unwrap_or_default(),
        "all_core": topo.map(|t| t.present_str.clone()).unwrap_or_default(),
        "cores": topo.map(|t| t.present_cpus.count()).unwrap_or(0),
        "cpuset_enabled": topo.is_some_and(|t| t.cpuset_enabled),
        // HMBIRD prefer_cpu/cluster/idle/preempt(:pf/:pcl/:pi/:pp)本机是否可用，供规则编辑器提示
        "hmbird_pf": crate::hmbird::prefer_cpu_available(),
        "hmbird_pcl": crate::hmbird::prefer_cluster_available(),
        "hmbird_pi": crate::hmbird::prefer_idle_available(),
        "hmbird_pp": crate::hmbird::prefer_preempt_available(),
    })
    .to_string()
}

fn rules_json() -> String {
    let Some(cfg) = current_cfg() else {
        return json!({ "rules": [], "disabled": [] }).to_string();
    };
    let mut groups: Vec<serde_json::Value> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for r in &cfg.rules {
        let gi = *index.entry(r.pkg.as_str()).or_insert_with(|| {
            groups.push(json!({ "pkg": r.pkg, "items": [] }));
            groups.len() - 1
        });
        // 优先发原始 spec 全文(含后缀)供编辑回填；万一为空(理论不会)回落解析后的 CPU 名。
        let spec = if r.raw_spec.is_empty() {
            spec_name(&r.cpus, &cfg.topo)
        } else {
            r.raw_spec.clone()
        };
        // line/enabled 供 WebUI 临时启停(按行号加/去注释)；enabled 恒 true(能解析出的都是生效规则)。
        groups[gi]["items"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "thread": r.thread, "spec": spec, "line": r.line, "enabled": true }));
    }
    json!({ "rules": groups, "disabled": disabled_rules() }).to_string()
}

/// 扫描配置文件找【被注释掉的规则行】(以 # 或 // 开头、去标记后形如 `token=spec`)，返回
/// [{raw, line}]，供 WebUI「已停用」列表展示 + 按行号重新启用。块开/闭等非 `=` 行不计。
fn disabled_rules() -> Vec<serde_json::Value> {
    let path = lock_ignore_poison(&CONFIG_FILE).clone();
    let Ok(content) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    if content.len() > RAWCONFIG_MAX {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let t = line.trim();
        let rest = match t.strip_prefix('#').or_else(|| t.strip_prefix("//")) {
            Some(r) => r.trim(),
            None => continue,
        };
        let Some(eq) = rest.find('=') else { continue };
        let left = rest[..eq].trim_end();
        let right = rest[eq + 1..].trim();
        // 左侧是包/线程/单行 token(无空白)、右侧非空 → 认作被注释的规则；prose 注释(含空格)被滤掉。
        if left.is_empty() || right.is_empty() || left.bytes().any(|b| b == b' ' || b == b'\t') {
            continue;
        }
        out.push(json!({ "raw": rest, "line": idx }));
    }
    out
}

/// 名称校验
fn token_ok(s: &str, max: usize) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() < max
        && !t.bytes().any(|b| b < 0x20 || b == 0x7f)
        && !t.contains('#')
        && !t.contains("//")
        // '=' 是规则的键值分隔符：包名/线程名含 '=' 会让编辑器(按末个 '=' 切)与运行时 load_config
        // (按首个 '=' 切)对同一行解析出不同 pkg/thread，Web 报成功但热重载绑错或失败。禁掉。
        && !t.contains('=')
}

fn pkg_shape_ok(pkg: &str) -> bool {
    !(pkg.contains('{') && pkg.ends_with('}'))
}

fn rule_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(pkg), Some(cpus)) = (
        v["pkg"].as_str().map(str::trim),
        v["cpus"].as_str().map(str::trim),
    ) else {
        return err_json(400, "缺少 pkg 或 cpus 字段");
    };
    let thread = v["thread"].as_str().map(str::trim).unwrap_or("");
    let Some(cfg) = current_cfg() else {
        return err_json(500, "配置未就绪");
    };
    if !token_ok(pkg, MAX_PKG_LEN) || (!thread.is_empty() && !token_ok(thread, MAX_THREAD_LEN)) {
        return err_json(400, "名称含有非法字符");
    }
    if thread.is_empty() && !pkg_shape_ok(pkg) {
        return err_json(400, "包名含 { 且以 } 结尾时不支持包级规则，可改用线程规则");
    }
    // cpus 可携带扩展后缀(:FIFO/:RR/:nice/:p/:b/:u 等)。仅校验首个 ':' 之前的 CPU 部分，
    // 后缀部分按不透明处理，原样透传写入配置(见 rule_edit::spec_swap)。允许"仅后缀"规格——
    // 即以 ':' 开头、CPU 部分为空(如 =:b:2)，此类不绑核只施加 per-task 提示。
    if cpus.is_empty() || cpus.len() >= 128 {
        return err_json(400, "无效的 CPU 规格");
    }
    let cpu_part = cpus.split(':').next().unwrap_or("").trim();
    if !cpu_part.is_empty()
        && (!spec_like(cpu_part) || parse_cpu_spec(cpu_part, &cfg.topo).count() == 0)
    {
        return err_json(400, "无效的 CPU 规格");
    }

    snapshot_save();
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_upsert(&file, pkg, thread, cpus) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

fn rule_del_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(pkg) = v["pkg"].as_str().map(str::trim) else {
        return err_json(400, "缺少 pkg 字段");
    };
    let thread = v["thread"].as_str().map(str::trim).unwrap_or("");

    snapshot_save();
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    let result = if v["all"].as_bool().unwrap_or(false) {
        rule_delete_pkg(&file, pkg)
    } else {
        rule_delete(&file, pkg, thread)
    };
    match result {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::NotFound => err_json(404, "规则不存在"),
        RuleEdit::Conflict => err_json(409, "状态冲突"),
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        RuleEdit::IoErr => err_json(500, "配置文件写入失败"),
    }
}

fn rule_rename_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(old), Some(new)) =
        (v["old"].as_str().map(str::trim), v["new"].as_str().map(str::trim))
    else {
        return err_json(400, "缺少 old 或 new 字段");
    };
    if !token_ok(old, MAX_PKG_LEN) || !token_ok(new, MAX_PKG_LEN) {
        return err_json(400, "名称含有非法字符");
    }
    if !pkg_shape_ok(new) {
        return err_json(400, "包名含 { 且以 } 结尾时不可作为重命名目标");
    }
    if old == new {
        return (200, json!({ "ok": true }).to_string());
    }

    snapshot_save();
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_rename(&file, old, new) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::NotFound => err_json(404, "原包名不存在"),
        RuleEdit::Conflict => err_json(409, "目标包名已存在规则"),
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        RuleEdit::IoErr => err_json(500, "配置文件写入失败"),
    }
}

/// POST /api/rule/toggle {line, enable} —— 按行号加/去行首注释，临时停用/启用一条规则。
fn rule_toggle_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(line) = v["line"].as_u64() else {
        return err_json(400, "缺少 line 字段");
    };
    let enable = v["enable"].as_bool().unwrap_or(false);
    snapshot_save();
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_toggle_line(&file, line as usize, enable) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::NotFound => err_json(404, "行号越界(配置已变化，请刷新)"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

/// 配置快照保留数
const SNAP_KEEP: usize = 15;

/// 快照目录：配置文件同级的 .appopt_snap/
fn snap_dir() -> String {
    let cfg = lock_ignore_poison(&CONFIG_FILE).clone();
    let parent = std::path::Path::new(&cfg)
        .parent()
        .and_then(|x| x.to_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| ".".to_string());
    format!("{}/.appopt_snap", parent)
}

/// 保存当前配置为快照(毫秒时间戳命名)，保留最近 SNAP_KEEP 份。文件缺失/建目录失败则跳过。
fn snapshot_save() {
    let cfg = lock_ignore_poison(&CONFIG_FILE).clone();
    let Ok(content) = fs::read_to_string(&cfg) else {
        return;
    };
    let dir = snap_dir();
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let _ = fs::write(format!("{}/{}.conf", dir, ms), &content);
    // 剪枝：按文件名(时间戳)升序，超出保留数的最旧者删除
    if let Ok(rd) = fs::read_dir(&dir) {
        let mut snaps: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| n.ends_with(".conf"))
            .collect();
        snaps.sort();
        if snaps.len() > SNAP_KEEP {
            for name in &snaps[..snaps.len() - SNAP_KEEP] {
                let _ = fs::remove_file(format!("{}/{}", dir, name));
            }
        }
    }
}

/// GET /api/snapshots —— 列出快照 [{id, ms, size}]，按时间倒序。
fn snapshots_json() -> String {
    let dir = snap_dir();
    let mut items: Vec<(u64, u64)> = Vec::new();
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".conf") else {
                continue;
            };
            let Ok(ms) = stem.parse::<u64>() else {
                continue;
            };
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            items.push((ms, size));
        }
    }
    items.sort_by(|a, b| b.0.cmp(&a.0));
    let arr: Vec<Value> = items
        .iter()
        .map(|(ms, size)| json!({ "id": ms.to_string(), "ms": ms, "size": size }))
        .collect();
    json!({ "snapshots": arr }).to_string()
}

/// POST /api/snapshot/restore {id} —— 回滚到指定快照(先把当前内容也存一份便于反悔)。
fn snapshot_restore_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(id) = v["id"].as_str() else {
        return err_json(400, "缺少 id 字段");
    };
    // id 必须是纯数字(时间戳)，防目录穿越
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return err_json(400, "无效的快照 id");
    }
    let snap_path = format!("{}/{}.conf", snap_dir(), id);
    let Ok(content) = fs::read_to_string(&snap_path) else {
        return err_json(404, "快照不存在");
    };
    if content.len() > RAWCONFIG_MAX {
        return err_json(400, "快照过大");
    }
    // 回滚前把当前内容也存一份快照，便于反悔
    snapshot_save();
    let path = lock_ignore_poison(&CONFIG_FILE).clone();
    let tmp = format!("{}.tmp", path);
    let res = fs::File::create(&tmp)
        .and_then(|mut f| {
            f.write_all(content.as_bytes())?;
            f.sync_all()
        })
        .and_then(|_| fs::rename(&tmp, &path));
    if res.is_err() {
        return err_json(500, "配置文件写入失败");
    }
    config_reload_now();
    (200, json!({ "ok": true }).to_string())
}

/// POST /api/tidcomm {tids:[..]} —— 按需读一批 tid 的线程名(/proc/<tid>/comm)，供「当前生效」展开
/// 显示线程名用。仅在用户点开时调用(非常驻)，最多读 100 个。
fn tidcomm_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(arr) = v["tids"].as_array() else {
        return err_json(400, "缺少 tids 字段");
    };
    let mut list: Vec<Value> = Vec::new();
    for t in arr.iter().take(100) {
        let Some(tid) = t.as_i64() else { continue };
        if tid <= 0 {
            continue;
        }
        let comm = fs::read_to_string(format!("/proc/{}/comm", tid))
            .ok()
            .map(|s| s.trim_end_matches(['\0', '\n']).trim().to_string())
            .unwrap_or_default();
        list.push(json!({ "tid": tid, "comm": comm }));
    }
    (200, json!({ "ok": true, "list": list }).to_string())
}

/// 输入建议
fn suggest_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let q = v["q"].as_str().map(str::trim).unwrap_or("");
    if q.len() > 64 {
        return err_json(400, "q 过长");
    }
    let list: Vec<String> = match v["pkg"].as_str().map(str::trim).filter(|p| !p.is_empty()) {
        None => suggest_pkgs(q).into_iter().map(|(n, _)| n).collect(),
        Some(pkg) => {
            if !token_ok(pkg, MAX_PKG_LEN) {
                return err_json(400, "名称含有非法字符");
            }
            suggest_threads(pkg, q).into_iter().map(|(n, _)| n).collect()
        }
    };
    (200, json!({ "ok": true, "list": list }).to_string())
}

/// 枚举包名
fn installed_pkgs() -> Vec<String> {
    fs::read_dir("/data/data")
        .map(|dirs| {
            dirs.flatten()
                .map(|d| d.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains('.') && !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default()
}

fn for_each_pid(mut f: impl FnMut(i32)) {
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                f(pid);
            }
        }
    }
}

/// 排序键
fn rank_top(counts: BTreeMap<String, usize>, lq: &str) -> Vec<(String, usize)> {
    let mut ranked: Vec<(u8, Reverse<usize>, String)> = counts
        .into_iter()
        .filter_map(|(n, c)| {
            let ln = n.to_ascii_lowercase();
            let r = if ln.starts_with(lq) { 0 } else if ln.contains(lq) { 1 } else { 2 };
            (r < 2).then_some((r, Reverse(c), n))
        })
        .collect();
    ranked.sort_unstable();
    ranked.truncate(20);
    ranked.into_iter().map(|(_, Reverse(c), n)| (n, c)).collect()
}

fn suggest_pkgs(q: &str) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> =
        installed_pkgs().into_iter().map(|p| (p, 0)).collect();
    for_each_pid(|pid| {
        if let Some(name) = read_cmdline(pid).filter(|n| n.contains('.')) {
            *counts.entry(name).or_insert(0) += 1;
        }
    });
    rank_top(counts, &q.to_ascii_lowercase())
}

fn thread_comm(pid: i32, tid: i32) -> Option<String> {
    let s = fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, tid)).ok()?;
    let name = s.trim_end_matches(['\0', '\n']).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn suggest_threads(pkg: &str, q: &str) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for_each_pid(|pid| {
        if read_cmdline(pid).as_deref() == Some(pkg) {
            for tid in task_tids(pid).unwrap_or_default() {
                if let Some(comm) = thread_comm(pid, tid) {
                    *counts.entry(comm).or_insert(0) += 1;
                }
            }
        }
    });
    rank_top(counts, &q.to_ascii_lowercase())
}

/// 原始配置文本上限（字节）。仅约束落盘文本本身；JSON 传输放大由 request_read 的 len_cap 兜住。
const RAWCONFIG_MAX: usize = 256 * 1024;

/// GET /api/rawconfig —— 读取 CONFIG_FILE 全文（文件缺失时返回空文本，不视为错误）。
fn rawconfig_json() -> String {
    let path = lock_ignore_poison(&CONFIG_FILE).clone();
    let text = fs::read_to_string(&path).unwrap_or_default();
    json!({ "ok": true, "text": text, "path": path }).to_string()
}

/// POST /api/rawconfig —— 原子写入 CONFIG_FILE 后热加载。不深校验内容(解析失败经 PARSE_FAILS/状态反馈)。
fn rawconfig_set_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(text) = v["text"].as_str() else {
        return err_json(400, "缺少 text 字段");
    };
    if text.len() > RAWCONFIG_MAX {
        return err_json(400, "配置内容过大（上限 256 KiB）");
    }
    snapshot_save();
    // 原子写：先写 <path>.tmp，sync 落盘后 rename 覆盖，避免半截文件（与 rule_edit::file_write 一致）。
    let path = lock_ignore_poison(&CONFIG_FILE).clone();
    let tmp = format!("{}.tmp", path);
    let res = fs::File::create(&tmp)
        .and_then(|mut f| {
            f.write_all(text.as_bytes())?;
            f.sync_all()
        })
        .and_then(|_| fs::rename(&tmp, &path));
    if res.is_err() {
        return err_json(500, "配置文件写入失败");
    }
    config_reload_now();
    (200, json!({ "ok": true }).to_string())
}

/// 读取 appopt 通用 ko 的 /proc/sched_opt/hooks(各 vendor hook 注册状态)。
/// 返回如 {"select_task_rq_fair":"ok","can_migrate_task":"ok","check_preempt_wakeup":"off",
/// "sched_setaffinity_early":"ok"};值 ok=成功 / off=编译期跳过 / err:-N=注册失败(errno)。
/// 节点不存在(未装 ko,或旧版 ko 无此状态节点)返回 null。
fn ko_hooks_value() -> Value {
    match fs::read_to_string("/proc/sched_opt/hooks") {
        Ok(s) => {
            let mut m = serde_json::Map::new();
            for line in s.lines() {
                if let Some((k, val)) = line.split_once('=') {
                    let k = k.trim();
                    if !k.is_empty() {
                        m.insert(k.to_string(), Value::String(val.trim().to_string()));
                    }
                }
            }
            if m.is_empty() {
                Value::Null
            } else {
                Value::Object(m)
            }
        }
        Err(_) => Value::Null,
    }
}

fn config_json() -> String {
    let stats = lock_ignore_poison(&WEB_STATS).clone();
    let cfg = current_cfg();
    json!({
        "mode": MODE_FORCE.load(Ordering::Relaxed),
        "pipeline_route": crate::oplus::route(),
        // 各线路节点在本机是否存在(供 web 端下拉禁用不可用项)
        "route_oplus_avail": std::path::Path::new("/proc/oplus_scheduler/sched_assist/pipeline_pids_cpus").exists(),
        "route_ko_avail": std::path::Path::new("/proc/sched_opt/pipeline_pids_cpus").exists(),
        "route_walt_avail": std::path::Path::new("/proc/sys/walt/sched_pipeline").exists()
            || std::path::Path::new("/proc/sys/walt/sched_pipeline_special").exists(),
        // skip_self_setaffinity 位掩码 + 节点是否可用(仅 appopt 通用 ko 提供)
        "skip_self": crate::skipself::current(),
        "skip_self_avail": crate::skipself::available(),
        // appopt 通用 ko 是否加载 + 各 vendor hook 注册状态(供 web 显示成功/失败/未启用)
        "ko_loaded": std::path::Path::new("/proc/sched_opt/pipeline_pids_cpus").exists(),
        "ko_hooks": ko_hooks_value(),
        "mode_active": if stats.is_some_and(|s| s.ebpf) { "ebpf" } else { "proc" },
        "ebpf_available": ebpf_probe(),
        "interval": CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        "cpuset_name": base_cpuset().rsplit('/').next().unwrap_or_default(),
        "config_file": lock_ignore_poison(&CONFIG_FILE).clone(),
        "cpuset_enabled": cfg.is_some_and(|c| c.topo.cpuset_enabled),
        "rt_relax": crate::sched::RT_RELAX.load(Ordering::Relaxed),
        "pipe_rearrange": crate::oplus::rearrange_opt_enabled(),
        "skip_gameself": crate::oplus::skip_opt_enabled(),
        // pipeline_prime_rearrange 可调值 <mode amp cnt>
        "rearrange_mode": crate::oplus::rearrange_mode(),
        "rearrange_amp": crate::oplus::rearrange_amp(),
        "rearrange_cnt": crate::oplus::rearrange_cnt(),
        "rearrange_avail": crate::oplus::rearrange_node_available(),
        // WALT util 阈值旋钮（全局 sysctl，opt-in）
        "walt_boost": crate::walt::boost_enabled(),
        "walt_boost_val": crate::walt::boost_val(),
        "walt_boost_avail": crate::walt::boost_available(),
        "walt_uclamp": crate::walt::uclamp_enabled(),
        "walt_uclamp_val": crate::walt::uclamp_val(),
        "walt_uclamp_avail": crate::walt::uclamp_available(),
        // OPLUS pipeline RT 避核掩码（opt-in）
        "rt_skip": crate::oplus::rt_cpumask_opt_enabled(),
        "rt_skip_mask": crate::oplus::rt_cpumask_val(),
        "rt_skip_avail": crate::oplus::rt_cpumask_node_available(),
        // OPLUS pipeline 白名单线程（opt-in）
        "immuned": crate::oplus::immuned_opt_enabled(),
        "immuned_names": crate::oplus::immuned_names(),
        "immuned_avail": crate::oplus::immuned_node_available(),
        // OPLUS pipeline_args（opt-in：prime 容忍度 + dislike）
        "pipe_args": crate::oplus::pipeline_args_opt_enabled(),
        "pipe_args_lowlat": crate::oplus::pipeline_args_lowlat(),
        "pipe_args_nopipe": crate::oplus::pipeline_args_nopipe(),
        "pipe_args_dislike": crate::oplus::pipeline_args_dislike() != 0,
        "pipe_args_avail": crate::oplus::pipeline_args_node_available(),
        "paused": PAUSED.load(Ordering::Relaxed),
    })
    .to_string()
}

/// 校验白名单线程名单串：形如 "name1;name2"，最多两段、各非空段 ≤15 字节(内核 %15 截断)，
/// 拒绝控制字符/换行、总长 <64。空串合法(=清空名单)。
fn valid_immuned_names(s: &str) -> bool {
    if s.len() >= 64 || s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    let segs: Vec<&str> = s.split(';').map(str::trim).filter(|x| !x.is_empty()).collect();
    segs.len() <= 2 && segs.iter().all(|x| x.len() <= 15)
}

fn config_set_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let mode = v["mode"].as_u64();
    let interval = v["interval"].as_u64();
    let name = v["cpuset_name"].as_str();
    let path = v["config_file"].as_str();

    if mode.is_some_and(|m| m > 2) {
        return err_json(400, "无效的工作模式");
    }
    if interval.is_some_and(|n| !(1..=3600).contains(&n)) {
        return err_json(400, "间隔需在 1-3600 秒之间");
    }
    if name.is_some_and(|n| !valid_name(n)) {
        return err_json(400, "无效的 cpuset 目录名");
    }
    if path.is_some_and(|p| !valid_path(p)) {
        return err_json(400, "无效的配置文件路径");
    }

    if let Some(m) = mode {
        MODE_FORCE.store(m as u8, Ordering::Relaxed);
        // 用户主动切回 eBPF 方向时清除放弃标记允许重试
        if m != 2 {
            EBPF_GAVE_UP.store(false, Ordering::Relaxed);
        }
    }
    if let Some(n) = interval {
        CHECK_INTERVAL.store(n, Ordering::Relaxed);
    }
    if let Some(n) = name {
        crate::cpuset::set_base_cpuset(n);
        if let Some(cfg) = current_cfg()
            && cfg.topo.cpuset_enabled {
                create_cpuset_dir(&base_cpuset(), &cfg.topo.present_str, &cfg.topo.mems_str);
            }
        FORCE_RELOAD.store(true, Ordering::Release);
    }
    if let Some(p) = path {
        // 安全：仅允许把配置文件切到【当前配置同目录】的文件，防经 rawconfig 覆盖 root 任意文件。
        let cur = lock_ignore_poison(&CONFIG_FILE).clone();
        if !config_path_in_cur_dir(p, &cur) {
            return err_json(400, "配置文件路径受限：仅允许与当前配置同一目录内的文件");
        }
        if std::fs::metadata(p).is_err() {
            let _ = std::fs::write(p, "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n");
        }
        *lock_ignore_poison(&CONFIG_FILE) = p.to_string();
        FORCE_RELOAD.store(true, Ordering::Release);
    }

    // pipeline_prime_rearrange 可调值：mode/amp/cnt（任一存在即读取，缺失字段沿用当前值）。
    // 须在 pipe_rearrange 开关之前设，确保随后开启用的是新值。
    if v.get("rearrange_mode").is_some()
        || v.get("rearrange_amp").is_some()
        || v.get("rearrange_cnt").is_some()
    {
        let mode = v["rearrange_mode"]
            .as_i64()
            .unwrap_or(crate::oplus::rearrange_mode() as i64);
        let amp = v["rearrange_amp"]
            .as_i64()
            .unwrap_or(crate::oplus::rearrange_amp() as i64);
        let cnt = v["rearrange_cnt"]
            .as_i64()
            .unwrap_or(crate::oplus::rearrange_cnt() as i64);
        if !(0..=2).contains(&mode) {
            return err_json(400, "rearrange 模式需为 0/1/2");
        }
        if !(1..=1000).contains(&amp) {
            return err_json(400, "rearrange 放大系数需在 1-1000");
        }
        if !(0..=3000).contains(&cnt) {
            return err_json(400, "rearrange 窗口数需在 0-3000");
        }
        crate::oplus::set_rearrange_value(mode as i32, amp as i32, cnt as i32);
    }

    // WALT util 阈值旋钮：开关 + 值一起下发（缺失字段沿用当前状态）。util 范围 0-1024。
    if v.get("walt_boost").is_some() || v.get("walt_boost_val").is_some() {
        let on = v["walt_boost"].as_bool().unwrap_or(crate::walt::boost_enabled());
        let val = v["walt_boost_val"]
            .as_i64()
            .unwrap_or(crate::walt::boost_val() as i64);
        if !(0..=1024).contains(&val) {
            return err_json(400, "boost util 值需在 0-1024 之间");
        }
        crate::walt::set_boost(on, val as i32);
    }
    if v.get("walt_uclamp").is_some() || v.get("walt_uclamp_val").is_some() {
        let on = v["walt_uclamp"]
            .as_bool()
            .unwrap_or(crate::walt::uclamp_enabled());
        let val = v["walt_uclamp_val"]
            .as_i64()
            .unwrap_or(crate::walt::uclamp_val() as i64);
        if !(0..=1024).contains(&val) {
            return err_json(400, "uclamp util 值需在 0-1024 之间");
        }
        crate::walt::set_uclamp(on, val as i32);
    }

    // OPLUS pipeline RT 避核掩码：开关 + 掩码值一起下发（缺失字段沿用当前状态）。掩码内核数须 ≤4。
    if v.get("rt_skip").is_some() || v.get("rt_skip_mask").is_some() {
        let on = v["rt_skip"].as_bool().unwrap_or(crate::oplus::rt_cpumask_opt_enabled());
        let mask = v["rt_skip_mask"]
            .as_u64()
            .unwrap_or(crate::oplus::rt_cpumask_val());
        if mask.count_ones() > 4 {
            return err_json(400, "RT 避核掩码最多 4 个核");
        }
        crate::oplus::set_rt_cpumask(on, mask);
    }
    // OPLUS pipeline 白名单线程：开关 + 名单串一起下发。
    if v.get("immuned").is_some() || v.get("immuned_names").is_some() {
        let on = v["immuned"].as_bool().unwrap_or(crate::oplus::immuned_opt_enabled());
        let names = v["immuned_names"]
            .as_str()
            .map(str::trim)
            .map(String::from)
            .unwrap_or_else(crate::oplus::immuned_names);
        if !valid_immuned_names(&names) {
            return err_json(400, "白名单线程名非法：最多两段(分号隔)、各 ≤15 字符、无控制字符");
        }
        crate::oplus::set_immuned(on, names);
    }
    // OPLUS pipeline_args：开关 + 三参(低延迟util/非pipelineutil ∈ 0-1024，dislike 0/1)一起下发。
    if v.get("pipe_args").is_some()
        || v.get("pipe_args_lowlat").is_some()
        || v.get("pipe_args_nopipe").is_some()
        || v.get("pipe_args_dislike").is_some()
    {
        let on = v["pipe_args"].as_bool().unwrap_or(crate::oplus::pipeline_args_opt_enabled());
        let lowlat = v["pipe_args_lowlat"]
            .as_i64()
            .unwrap_or(crate::oplus::pipeline_args_lowlat() as i64);
        let nopipe = v["pipe_args_nopipe"]
            .as_i64()
            .unwrap_or(crate::oplus::pipeline_args_nopipe() as i64);
        let dislike = v["pipe_args_dislike"]
            .as_bool()
            .unwrap_or(crate::oplus::pipeline_args_dislike() != 0);
        if !(0..=1024).contains(&lowlat) || !(0..=1024).contains(&nopipe) {
            return err_json(400, "pipeline_args util 值需在 0-1024 之间");
        }
        crate::oplus::set_pipeline_args(on, lowlat as i32, nopipe as i32, dislike as i32);
    }
    // 全局旋钮：运行期切换并即时生效（开启即应用、关闭即还原）
    if let Some(b) = v["rt_relax"].as_bool() {
        crate::sched::set_rt_relax(b);
    }
    if let Some(b) = v["pipe_rearrange"].as_bool() {
        crate::oplus::set_rearrange_opt(b);
    }
    if let Some(b) = v["skip_gameself"].as_bool() {
        crate::oplus::set_skip_opt(b);
    }
    // skip_self_setaffinity 位掩码(低 6 位:bit0 拦自己/bit1 debug/bit2 拦全部/bit3 仅app-uid/
    // bit4 整进程守护/bit5 内核级锁定 PF_NO_SETAFFINITY)
    if let Some(m) = v["skip_self"].as_u64() {
        crate::skipself::set((m & 0x3f) as u8);
    }
    // pipeline 线路选择:0=auto 1=walt 2=oplus(一加官方) 3=ko(通用模块)。切换后重解析配置,
    // 让 :p 的 WALT 门控随线路生效(oplus/ko 由 route-aware pipeline_node 即时决定,无需重解析)。
    if let Some(r) = v["pipeline_route"].as_u64() {
        if r > 3 {
            return err_json(400, "无效的 pipeline 线路(0=auto/1=walt/2=oplus/3=ko)");
        }
        let changed = crate::oplus::route() != r as u8;
        crate::oplus::set_route(r as u8);
        if changed {
            config_reload_now();
        }
    }
    // 全局暂停：主循环据 PAUSED 门控(暂停即还原并停绑，恢复自动重扫重绑)
    if let Some(b) = v["paused"].as_bool() {
        PAUSED.store(b, Ordering::Relaxed);
    }

    settings_save();
    (200, json!({ "ok": true }).to_string())
}

pub const SETTINGS_FILE: &str = "./AppOpt.json";

static SAVE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub struct Settings {
    pub web_enable: bool,
    pub mode: u8,
    /// pipeline 线路:0=auto 1=walt 2=oplus(一加官方) 3=ko(通用模块)
    pub pipeline_route: u8,
    pub check_interval: u64,
    pub cpuset_name: String,
    pub config_file: String,
    /// 全局旋钮：RT 带宽放宽(-r)
    pub rt_relax: bool,
    /// 全局旋钮：OPLUS pipeline 动态换 prime(-P)
    pub pipe_rearrange: bool,
    /// 全局旋钮：OPLUS skip_gameself 进程级锁(-S)
    pub skip_gameself: bool,
    /// skip_self_setaffinity 位掩码(仅 appopt ko)：0=关 / bit0 拦自己 / bit1 debug / bit2 拦全部 /
    /// bit3 仅app-uid / bit4 整进程守护 / bit5 内核级锁定(PF_NO_SETAFFINITY)
    pub skip_self: u8,
    /// pipeline_prime_rearrange 可调值 <mode amp cnt>，默认 1/51/10
    pub rearrange_mode: i32,
    pub rearrange_amp: i32,
    pub rearrange_cnt: i32,
    /// WALT sched_min_task_util_for_boost 旋钮（开关 + 值，默认关/51）
    pub walt_boost: bool,
    pub walt_boost_val: i32,
    /// WALT sched_min_task_util_for_uclamp 旋钮（开关 + 值，默认关/51）
    pub walt_uclamp: bool,
    pub walt_uclamp_val: i32,
    /// OPLUS pipeline_rt_cpumask 旋钮（开关 + 掩码，默认关/0）
    pub rt_skip: bool,
    pub rt_skip_mask: u64,
    /// OPLUS pipeline_immuned_thread 旋钮（开关 + 名单串，默认关/空）
    pub immuned: bool,
    pub immuned_names: String,
    /// OPLUS pipeline_args 旋钮（开关 + 低延迟util/非pipelineutil/dislike，默认关/30/400/1）
    pub pipe_args: bool,
    pub pipe_args_lowlat: i32,
    pub pipe_args_nopipe: i32,
    pub pipe_args_dislike: bool,
    /// 全局暂停优化（默认关）
    pub paused: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            web_enable: false,
            mode: 0,
            pipeline_route: 0,
            check_interval: 2,
            cpuset_name: DEFAULT_CPUSET_NAME.to_string(),
            config_file: "./applist.conf".to_string(),
            rt_relax: false,
            pipe_rearrange: false,
            skip_gameself: false,
            skip_self: 0,
            rearrange_mode: 1,
            rearrange_amp: 51,
            rearrange_cnt: 10,
            walt_boost: false,
            walt_boost_val: 51,
            walt_uclamp: false,
            walt_uclamp_val: 51,
            rt_skip: false,
            rt_skip_mask: 0,
            immuned: false,
            immuned_names: String::new(),
            pipe_args: false,
            pipe_args_lowlat: 30,
            pipe_args_nopipe: 400,
            pipe_args_dislike: true,
            paused: false,
        }
    }
}

fn valid_name(s: &str) -> bool {
    // cpuset 目录名安全校验(与 cpuset::set_base_cpuset 同源)：拒绝 / . .. 及非 [A-Za-z0-9_-]，
    // 防目录穿越(如 ".." 逃逸到 /dev 后被 chmod/chown/写文件)。
    crate::cpuset::valid_cpuset_name(s)
}

fn valid_path(s: &str) -> bool {
    !s.is_empty() && s.len() < 256 && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// web 改配置文件路径的安全约束：新路径必须与【当前配置文件】位于同一目录，防止被经
/// /api/rawconfig 变成 root 任意文件覆盖(web 启用时的本地提权面)。CLI `-c` 由本机管理员在启动时
/// 设定、不经此路径，不受限。目录用 canonicalize 比较(消解 ./ 与符号链接，且父目录不存在即拒绝)。
fn config_path_in_cur_dir(new: &str, cur: &str) -> bool {
    let canon_parent = |s: &str| -> Option<std::path::PathBuf> {
        let p = std::path::Path::new(s);
        let dir = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        std::fs::canonicalize(dir).ok()
    };
    match (canon_parent(new), canon_parent(cur)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

impl Settings {
    fn from_json(v: &Value) -> Self {
        let d = Settings::default();
        Self {
            web_enable: v["web_enable"].as_bool().unwrap_or(d.web_enable),
            mode: v["mode"].as_u64().unwrap_or(d.mode as u64).min(2) as u8,
            pipeline_route: v["pipeline_route"]
                .as_u64()
                .unwrap_or(d.pipeline_route as u64)
                .min(3) as u8,
            check_interval: v["check_interval"]
                .as_u64()
                .unwrap_or(d.check_interval)
                .clamp(1, 3600),
            cpuset_name: v["cpuset_name"]
                .as_str()
                .filter(|s| valid_name(s))
                .unwrap_or(&d.cpuset_name)
                .to_string(),
            config_file: v["config_file"]
                .as_str()
                .filter(|s| valid_path(s))
                .unwrap_or(&d.config_file)
                .to_string(),
            rt_relax: v["rt_relax"].as_bool().unwrap_or(d.rt_relax),
            pipe_rearrange: v["pipe_rearrange"].as_bool().unwrap_or(d.pipe_rearrange),
            skip_gameself: v["skip_gameself"].as_bool().unwrap_or(d.skip_gameself),
            skip_self: v["skip_self"].as_u64().unwrap_or(d.skip_self as u64).min(63) as u8,
            rearrange_mode: v["rearrange_mode"]
                .as_i64()
                .unwrap_or(d.rearrange_mode as i64)
                .clamp(0, 2) as i32,
            rearrange_amp: v["rearrange_amp"]
                .as_i64()
                .unwrap_or(d.rearrange_amp as i64)
                .clamp(1, 1000) as i32,
            rearrange_cnt: v["rearrange_cnt"]
                .as_i64()
                .unwrap_or(d.rearrange_cnt as i64)
                .clamp(0, 3000) as i32,
            walt_boost: v["walt_boost"].as_bool().unwrap_or(d.walt_boost),
            walt_boost_val: v["walt_boost_val"]
                .as_i64()
                .unwrap_or(d.walt_boost_val as i64)
                .clamp(0, 1024) as i32,
            walt_uclamp: v["walt_uclamp"].as_bool().unwrap_or(d.walt_uclamp),
            walt_uclamp_val: v["walt_uclamp_val"]
                .as_i64()
                .unwrap_or(d.walt_uclamp_val as i64)
                .clamp(0, 1024) as i32,
            rt_skip: v["rt_skip"].as_bool().unwrap_or(d.rt_skip),
            // 掩码内核数 >4 会被内核作废，持久化时先归一为 0，避免加载后写入无效值
            rt_skip_mask: {
                let m = v["rt_skip_mask"].as_u64().unwrap_or(d.rt_skip_mask);
                if m.count_ones() > 4 { 0 } else { m }
            },
            immuned: v["immuned"].as_bool().unwrap_or(d.immuned),
            immuned_names: v["immuned_names"]
                .as_str()
                .filter(|s| valid_immuned_names(s))
                .unwrap_or(&d.immuned_names)
                .to_string(),
            pipe_args: v["pipe_args"].as_bool().unwrap_or(d.pipe_args),
            pipe_args_lowlat: v["pipe_args_lowlat"]
                .as_i64()
                .unwrap_or(d.pipe_args_lowlat as i64)
                .clamp(0, 1024) as i32,
            pipe_args_nopipe: v["pipe_args_nopipe"]
                .as_i64()
                .unwrap_or(d.pipe_args_nopipe as i64)
                .clamp(0, 1024) as i32,
            pipe_args_dislike: v["pipe_args_dislike"].as_bool().unwrap_or(d.pipe_args_dislike),
            paused: v["paused"].as_bool().unwrap_or(d.paused),
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "web_enable": self.web_enable,
            "mode": self.mode,
            "pipeline_route": self.pipeline_route,
            "check_interval": self.check_interval,
            "cpuset_name": self.cpuset_name,
            "config_file": self.config_file,
            "rt_relax": self.rt_relax,
            "pipe_rearrange": self.pipe_rearrange,
            "skip_gameself": self.skip_gameself,
            "skip_self": self.skip_self,
            "rearrange_mode": self.rearrange_mode,
            "rearrange_amp": self.rearrange_amp,
            "rearrange_cnt": self.rearrange_cnt,
            "walt_boost": self.walt_boost,
            "walt_boost_val": self.walt_boost_val,
            "walt_uclamp": self.walt_uclamp,
            "walt_uclamp_val": self.walt_uclamp_val,
            "rt_skip": self.rt_skip,
            "rt_skip_mask": self.rt_skip_mask,
            "immuned": self.immuned,
            "immuned_names": self.immuned_names,
            "pipe_args": self.pipe_args,
            "pipe_args_lowlat": self.pipe_args_lowlat,
            "pipe_args_nopipe": self.pipe_args_nopipe,
            "pipe_args_dislike": self.pipe_args_dislike,
            "paused": self.paused,
        })
    }

    fn save(&self, path: &str) {
        let _guard = lock_ignore_poison(&SAVE_LOCK);
        let json = serde_json::to_string_pretty(&self.to_value()).unwrap_or_default();
        let tmp = format!("{}.tmp", path);
        let res = fs::File::create(&tmp)
            .and_then(|mut f| {
                f.write_all(format!("{}\n", json).as_bytes())?;
                f.sync_all()
            })
            .and_then(|_| fs::rename(&tmp, path));
        if let Err(e) = res {
            eprintln!("警告: 设置写入 {} 失败: {}", path, e);
        }
    }
}

pub fn settings_load(path: &str) -> Settings {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => Settings::from_json(&v),
            Err(e) => {
                eprintln!("警告: {} 已损坏({})，使用默认设置", path, e);
                Settings::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let d = Settings::default();
            d.save(path);
            println!("设置文件不存在，已写入默认设置: {}", path);
            d
        }
        Err(e) => {
            eprintln!("警告: 读取 {} 失败({})，使用默认设置", path, e);
            Settings::default()
        }
    }
}

pub fn settings_save() {
    Settings {
        web_enable: WEB_ENABLED.load(Ordering::Relaxed),
        mode: MODE_FORCE.load(Ordering::Relaxed),
        pipeline_route: crate::oplus::route(),
        check_interval: CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        cpuset_name: base_cpuset().rsplit('/').next().unwrap_or_default().to_string(),
        config_file: lock_ignore_poison(&CONFIG_FILE).clone(),
        rt_relax: crate::sched::RT_RELAX.load(Ordering::Relaxed),
        pipe_rearrange: crate::oplus::rearrange_opt_enabled(),
        skip_gameself: crate::oplus::skip_opt_enabled(),
        skip_self: crate::skipself::current(),
        rearrange_mode: crate::oplus::rearrange_mode(),
        rearrange_amp: crate::oplus::rearrange_amp(),
        rearrange_cnt: crate::oplus::rearrange_cnt(),
        walt_boost: crate::walt::boost_enabled(),
        walt_boost_val: crate::walt::boost_val(),
        walt_uclamp: crate::walt::uclamp_enabled(),
        walt_uclamp_val: crate::walt::uclamp_val(),
        rt_skip: crate::oplus::rt_cpumask_opt_enabled(),
        rt_skip_mask: crate::oplus::rt_cpumask_val(),
        immuned: crate::oplus::immuned_opt_enabled(),
        immuned_names: crate::oplus::immuned_names(),
        pipe_args: crate::oplus::pipeline_args_opt_enabled(),
        pipe_args_lowlat: crate::oplus::pipeline_args_lowlat(),
        pipe_args_nopipe: crate::oplus::pipeline_args_nopipe(),
        pipe_args_dislike: crate::oplus::pipeline_args_dislike() != 0,
        paused: PAUSED.load(Ordering::Relaxed),
    }
    .save(SETTINGS_FILE);
}
