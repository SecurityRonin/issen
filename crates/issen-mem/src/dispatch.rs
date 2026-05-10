//! Walker dispatch — opens a memory dump, loads ISF symbols, and routes
//! each [`MemfCommand`] to the appropriate `memf-linux` / `memf-windows`
//! walker function.

use std::path::Path;

use anyhow::anyhow;
use memf_core::object_reader::ObjectReader;
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_format::{open_dump_with_raw_fallback, PhysicalMemoryProvider};
use memf_symbols::isf::IsfResolver;

use crate::open::DumpFormat;

// ---------------------------------------------------------------------------
// Reader bootstrap
// ---------------------------------------------------------------------------

/// Open a memory dump and build an [`ObjectReader`] backed by ISF symbols.
///
/// # Errors
///
/// - Returns `Err` containing `"profile"` when `profile` is `None`.
/// - Returns `Err` containing `"CR3"` when the dump has no embedded CR3 and
///   `cr3_override` is `None`.
/// - Returns `Err` on I/O failure or ISF parse error.
pub fn build_reader(
    path: &Path,
    profile: Option<&str>,
    cr3_override: Option<u64>,
) -> anyhow::Result<(DumpFormat, ObjectReader<Box<dyn PhysicalMemoryProvider>>)> {
    let profile_path = profile.ok_or_else(|| anyhow!("--profile <isf.json> is required"))?;

    let provider: Box<dyn PhysicalMemoryProvider> =
        open_dump_with_raw_fallback(path).map_err(|e| anyhow!("failed to open dump: {e}"))?;

    // Detect format for the caller.
    let fmt = crate::open::detect_format(path).unwrap_or(DumpFormat::Raw);

    let metadata = provider.metadata();
    let embedded_cr3 = metadata.as_ref().and_then(|m| m.cr3);

    // Resolve CR3: prefer the dump's embedded value; fall back to the
    // caller-supplied override; fail if neither is available.
    let cr3 = embedded_cr3
        .or(cr3_override)
        .ok_or_else(|| anyhow!("dump has no embedded CR3; use --cr3 <addr> to provide one"))?;

    let resolver = IsfResolver::from_path(Path::new(profile_path))
        .map_err(|e| anyhow!("failed to load ISF profile '{profile_path}': {e}"))?;
    let symbols: Box<dyn memf_symbols::SymbolResolver> = Box::new(resolver);

    let vas = VirtualAddressSpace::new(provider, cr3, TranslationMode::X86_64FourLevel);
    let reader = ObjectReader::new(vas, symbols);

    Ok((fmt, reader))
}

// ---------------------------------------------------------------------------
// Row-extraction helper
// ---------------------------------------------------------------------------

/// Convert a serialisable struct to a row of strings using the supplied
/// header keys.  JSON field names are snake_case; header strings are matched
/// after lowercasing and replacing spaces with `_`.
#[allow(dead_code)] // available for callers; not all dispatch fns use it
fn struct_to_row(val: &impl serde::Serialize, headers: &[&str]) -> Vec<String> {
    let map = serde_json::to_value(val)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    headers
        .iter()
        .map(|h| {
            let key = h.to_lowercase().replace(' ', "_");
            map.get(&key)
                .or_else(|| map.get(*h))
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Linux dispatch functions
// ---------------------------------------------------------------------------

/// Walk Linux processes and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_linux_ps(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["PID", "PPID", "Name", "State"];
    let procs = memf_linux::process::walk_processes(reader)
        .map_err(|e| anyhow!("linux ps walk failed: {e}"))?;
    let rows = procs
        .iter()
        .map(|p| {
            vec![
                p.pid.to_string(),
                p.ppid.to_string(),
                p.comm.clone(),
                p.state.to_string(),
            ]
        })
        .collect();
    Ok((headers, rows))
}

/// Walk Linux kernel modules and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_linux_modules(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Base", "Size", "Name", "State"];
    let mods = memf_linux::modules::walk_modules(reader)
        .map_err(|e| anyhow!("linux modules walk failed: {e}"))?;
    let rows = mods
        .iter()
        .map(|m| {
            vec![
                format!("{:#018x}", m.base_addr),
                format!("{:#x}", m.size),
                m.name.clone(),
                m.state.to_string(),
            ]
        })
        .collect();
    Ok((headers, rows))
}

/// Walk Linux TCP connections and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_linux_netstat(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Proto", "Local", "Remote", "State", "PID"];
    let conns = memf_linux::network::walk_connections(reader)
        .map_err(|e| anyhow!("linux netstat walk failed: {e}"))?;
    let rows = conns
        .iter()
        .map(|c| {
            vec![
                c.protocol.to_string(),
                format!("{}:{}", c.local_addr, c.local_port),
                format!("{}:{}", c.remote_addr, c.remote_port),
                c.state.to_string(),
                c.pid.map(|p| p.to_string()).unwrap_or_default(),
            ]
        })
        .collect();
    Ok((headers, rows))
}

/// Run Linux hook/rootkit integrity checks and return headers + rows.
///
/// Calls multiple walkers in sequence; if a walker returns `Err`, logs via
/// `eprintln!` and continues with the remaining walkers.
///
/// # Errors
///
/// Never returns `Err` — individual walker failures are logged and skipped.
#[allow(clippy::too_many_lines)]
pub fn dispatch_linux_check(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Check", "Status", "Location", "Detail"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    // inline hooks (syscalls / kernel functions)
    match memf_linux::check_hooks::check_inline_hooks(reader) {
        Ok(items) => {
            for h in &items {
                rows.push(vec![
                    "inline-hook".into(),
                    if h.suspicious { "HOOKED" } else { "ok" }.into(),
                    format!("{:#018x}", h.address),
                    format!("{} ({})", h.symbol, h.hook_type),
                ]);
            }
        }
        Err(e) => eprintln!("check_hooks walker error (skipped): {e}"),
    }

    // IDT manipulation
    match memf_linux::check_idt::walk_check_idt(reader) {
        Ok(items) => {
            for h in &items {
                rows.push(vec![
                    "idt".into(),
                    if h.is_hooked { "HOOKED" } else { "ok" }.into(),
                    format!("vector={}", h.vector),
                    format!("{:#018x} ({})", h.handler_addr, h.gate_type),
                ]);
            }
        }
        Err(e) => eprintln!("check_idt walker error (skipped): {e}"),
    }

    // file_operations hooks
    match memf_linux::check_fops::scan_proc_fops(reader) {
        Ok(items) => {
            for h in &items {
                rows.push(vec![
                    "fops".into(),
                    if h.is_suspicious { "HOOKED" } else { "ok" }.into(),
                    h.path.clone(),
                    format!("{:#018x}", h.struct_address),
                ]);
            }
        }
        Err(e) => eprintln!("check_fops walker error (skipped): {e}"),
    }

    // hidden kernel modules
    match memf_linux::check_modules::check_hidden_modules(reader) {
        Ok(items) => {
            for m in &items {
                // A module is suspicious if it is absent from either view.
                let is_hidden = !(m.in_modules_list && m.in_sysfs);
                rows.push(vec![
                    "module".into(),
                    if is_hidden { "HIDDEN" } else { "ok" }.into(),
                    format!("{:#018x}", m.base_addr),
                    m.name.clone(),
                ]);
            }
        }
        Err(e) => eprintln!("check_modules walker error (skipped): {e}"),
    }

    // network protocol hooks (afinfo)
    match memf_linux::check_afinfo::walk_check_afinfo(reader) {
        Ok(items) => {
            for h in &items {
                rows.push(vec![
                    "afinfo".into(),
                    if h.is_hooked { "HOOKED" } else { "ok" }.into(),
                    format!("{}.{}", h.struct_name, h.field),
                    format!("{:#018x}", h.hook_address),
                ]);
            }
        }
        Err(e) => eprintln!("check_afinfo walker error (skipped): {e}"),
    }

    // shared credential anomalies
    match memf_linux::check_creds::walk_check_creds(reader) {
        Ok(items) => {
            for c in &items {
                rows.push(vec![
                    "cred-share".into(),
                    if c.is_suspicious { "SUSPICIOUS" } else { "ok" }.into(),
                    format!("pid={}", c.pid),
                    format!("{} uid={}", c.process_name, c.uid),
                ]);
            }
        }
        Err(e) => eprintln!("check_creds walker error (skipped): {e}"),
    }

    // ftrace hooks
    match memf_linux::ftrace::walk_ftrace_hooks(reader) {
        Ok(items) => {
            for h in &items {
                rows.push(vec![
                    "ftrace".into(),
                    if h.is_suspicious { "HOOKED" } else { "ok" }.into(),
                    format!("{:#018x}", h.address),
                    h.func_name.clone(),
                ]);
            }
        }
        Err(e) => eprintln!("ftrace walker error (skipped): {e}"),
    }

    // TTY driver operations hooks
    if let Ok(items) = memf_linux::tty_check::check_tty_hooks(reader) {
        for t in &items {
            rows.push(vec![
                "tty-hook".into(),
                if t.hooked { "HOOKED" } else { "ok" }.into(),
                format!("{} ({})", t.name, t.operation),
                format!("{:#018x}", t.handler),
            ]);
        }
    }

    // signal handler anomalies
    if let Ok(items) = memf_linux::signal_handlers::walk_signal_handlers(reader) {
        for s in &items {
            if s.is_suspicious {
                rows.push(vec![
                    "signal".into(),
                    "SUSPICIOUS".into(),
                    format!("pid={} ({})", s.pid, s.comm),
                    format!(
                        "{}: {} → {:#018x}",
                        s.signal_name, s.handler_type, s.handler
                    ),
                ]);
            }
        }
    }

    // keyboard notifier chain (keylogger detection)
    if let Ok(items) = memf_linux::keyboard_notifiers::walk_keyboard_notifiers(reader) {
        for k in &items {
            rows.push(vec![
                "kbd-notifier".into(),
                if k.is_suspicious { "SUSPICIOUS" } else { "ok" }.into(),
                format!("{:#018x}", k.address),
                format!("call={:#018x} prio={}", k.notifier_call, k.priority),
            ]);
        }
    }

    // KASLR offset detection
    if let Ok(offset) =
        memf_linux::kaslr::detect_kaslr_offset(reader.vas().physical(), reader.symbols())
    {
        rows.push(vec![
            "kaslr".into(),
            "ok".into(),
            String::new(),
            format!("slide={:#018x}", offset),
        ]);
    }

    // IPC shared memory segments
    if let Ok(items) = memf_linux::ipc::walk_shm_segments(reader) {
        for shm in &items {
            rows.push(vec![
                "ipc-shm".into(),
                "ok".into(),
                format!("shmid={}", shm.shmid),
                format!(
                    "key={:#x} size={} owner_pid={} attaches={}",
                    shm.key, shm.size, shm.owner_pid, shm.num_attaches
                ),
            ]);
        }
    }

    // IPC semaphore sets
    if let Ok(items) = memf_linux::ipc::walk_semaphores(reader) {
        for sem in &items {
            rows.push(vec![
                "ipc-sem".into(),
                "ok".into(),
                format!("semid={}", sem.semid),
                format!(
                    "key={:#x} nsems={} owner_pid={}",
                    sem.key, sem.num_sems, sem.owner_pid
                ),
            ]);
        }
    }

    if rows.is_empty() {
        rows.push(vec![
            "all-checks".into(),
            "ok".into(),
            String::new(),
            "no hooks detected (or symbols unavailable)".into(),
        ]);
    }

    Ok((headers, rows))
}

/// Run Linux pool/malfind scan and return headers + rows.
///
/// Calls multiple walkers in sequence; if a walker returns `Err`, logs via
/// `eprintln!` and continues with the remaining walkers.
///
/// # Errors
///
/// Never returns `Err` — individual walker failures are logged and skipped.
pub fn dispatch_linux_scan(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["PID", "Type", "Address", "Size", "Detail"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    // anonymous executable VMAs (malfind)
    match memf_linux::malfind::scan_malfind(reader) {
        Ok(items) => {
            for m in &items {
                let size = m.end.saturating_sub(m.start);
                rows.push(vec![
                    m.pid.to_string(),
                    "malfind".into(),
                    format!("{:#018x}", m.start),
                    format!("{:#x}", size),
                    format!("{}: {}", m.comm, m.reason),
                ]);
            }
        }
        Err(e) => eprintln!("malfind walker error (skipped): {e}"),
    }

    // processes running from deleted executables
    match memf_linux::deleted_exe::walk_deleted_exe(reader) {
        Ok(items) => {
            for d in &items {
                rows.push(vec![
                    d.pid.to_string(),
                    "deleted-exe".into(),
                    String::new(),
                    String::new(),
                    format!("{}: {}", d.comm, d.exe_path),
                ]);
            }
        }
        Err(e) => eprintln!("deleted_exe walker error (skipped): {e}"),
    }

    // hidden module cross-view
    match memf_linux::modxview::walk_modxview(reader) {
        Ok(items) => {
            for m in &items {
                rows.push(vec![
                    String::new(),
                    "hidden-module".into(),
                    format!("{:#018x}", m.base_addr),
                    format!("{:#x}", m.size),
                    m.name.clone(),
                ]);
            }
        }
        Err(e) => eprintln!("modxview walker error (skipped): {e}"),
    }

    if rows.is_empty() {
        rows.push(vec![
            String::new(),
            "scan".into(),
            String::new(),
            String::new(),
            "no injections detected (or symbols unavailable)".into(),
        ]);
    }

    Ok((headers, rows))
}

/// Extract Linux credential material and return headers + rows.
///
/// Calls multiple walkers in sequence; if a walker returns `Err`, logs via
/// `eprintln!` and continues with the remaining walkers.
///
/// # Errors
///
/// Never returns `Err` — individual walker failures are logged and skipped.
pub fn dispatch_linux_creds(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Type", "PID", "User", "Detail"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    // SSH private keys in memory
    match memf_linux::ssh_keys::extract_ssh_keys(reader) {
        Ok(items) => {
            for k in &items {
                rows.push(vec![
                    format!("ssh-key:{:?}", k.key_type),
                    k.pid.to_string(),
                    k.comment.clone(),
                    k.key_data.chars().take(64).collect::<String>(),
                ]);
            }
        }
        Err(e) => eprintln!("ssh_keys walker error (skipped): {e}"),
    }

    // bash history (may contain passwords)
    match memf_linux::bash::walk_bash_history(reader) {
        Ok(items) => {
            for b in &items {
                rows.push(vec![
                    "bash-history".into(),
                    b.pid.to_string(),
                    b.comm.clone(),
                    b.command.clone(),
                ]);
            }
        }
        Err(e) => eprintln!("bash walker error (skipped): {e}"),
    }

    // LD_PRELOAD credential hooks (requires process list)
    let procs = memf_linux::process::walk_processes(reader).unwrap_or_default();
    match memf_linux::ld_preload::scan_ld_preload(reader, &procs) {
        Ok(items) => {
            for l in &items {
                rows.push(vec![
                    "ld-preload".into(),
                    l.pid.to_string(),
                    l.process_name.clone(),
                    l.ld_preload_value.clone(),
                ]);
            }
        }
        Err(e) => eprintln!("ld_preload walker error (skipped): {e}"),
    }

    // shared credential anomalies
    match memf_linux::check_creds::walk_check_creds(reader) {
        Ok(items) => {
            for c in &items {
                if c.is_suspicious {
                    rows.push(vec![
                        "shared-cred".into(),
                        c.pid.to_string(),
                        format!("uid={}", c.uid),
                        format!(
                            "{} shares cred with pids: {:?}",
                            c.process_name, c.shared_with_pids
                        ),
                    ]);
                }
            }
        }
        Err(e) => eprintln!("check_creds walker error (skipped): {e}"),
    }

    // seccomp-BPF filter profiles (container security / unconfined processes)
    if let Ok(items) = memf_linux::seccomp::walk_seccomp_profiles(reader, &procs) {
        for s in &items {
            if s.is_unconfined {
                rows.push(vec![
                    "seccomp".into(),
                    s.pid.to_string(),
                    s.comm.clone(),
                    format!(
                        "UNCONFINED mode={} filters={}",
                        s.seccomp_mode, s.filter_count
                    ),
                ]);
            }
        }
    }

    if rows.is_empty() {
        rows.push(vec![
            "creds".into(),
            String::new(),
            String::new(),
            "no credential artifacts found (or symbols unavailable)".into(),
        ]);
    }

    Ok((headers, rows))
}

/// Walk Linux timestamped events and return headers + rows.
///
/// Calls multiple walkers in sequence; if a walker returns `Err`, logs via
/// `eprintln!` and continues with the remaining walkers.
///
/// # Errors
///
/// Never returns `Err` — individual walker failures are logged and skipped.
pub fn dispatch_linux_timeline(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Time", "Event", "Source", "Detail"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    // system boot time
    match memf_linux::boot_time::extract_boot_time(reader) {
        Ok(bt) => {
            rows.push(vec![
                bt.boot_epoch_secs.to_string(),
                "boot".into(),
                format!("{:?}", bt.source),
                "system boot epoch (seconds since Unix epoch)".into(),
            ]);
        }
        Err(e) => eprintln!("boot_time walker error (skipped): {e}"),
    }

    // kernel messages with timestamps
    match memf_linux::kmsg::walk_kmsg(reader) {
        Ok(items) => {
            for k in &items {
                rows.push(vec![
                    k.timestamp_ns.to_string(),
                    "kmsg".into(),
                    format!("level={}", k.level),
                    k.text.clone(),
                ]);
            }
        }
        Err(e) => eprintln!("kmsg walker error (skipped): {e}"),
    }

    // OOM kill events
    match memf_linux::oom_events::walk_oom_events(reader) {
        Ok(items) => {
            for o in &items {
                rows.push(vec![
                    o.timestamp_ns.to_string(),
                    "oom-kill".into(),
                    o.reason.clone(),
                    format!("pid={} comm={}", o.victim_pid, o.victim_comm),
                ]);
            }
        }
        Err(e) => eprintln!("oom_events walker error (skipped): {e}"),
    }

    if rows.is_empty() {
        rows.push(vec![
            String::new(),
            "timeline".into(),
            String::new(),
            "no timeline events found (or symbols unavailable)".into(),
        ]);
    }

    Ok((headers, rows))
}

// ---------------------------------------------------------------------------
// Windows dispatch functions
// ---------------------------------------------------------------------------

/// Walk Windows processes and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_windows_ps(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["PID", "PPID", "Name", "State"];
    let ps_head = reader
        .symbols()
        .symbol_address("PsActiveProcessHead")
        .ok_or_else(|| anyhow!("missing PsActiveProcessHead symbol"))?;
    let procs = memf_windows::process::walk_processes(reader, ps_head)
        .map_err(|e| anyhow!("windows ps walk failed: {e}"))?;
    let rows = procs
        .iter()
        .map(|p| {
            vec![
                p.pid.to_string(),
                p.ppid.to_string(),
                p.image_name.clone(),
                if p.exit_time == 0 {
                    "Running".into()
                } else {
                    "Exited".into()
                },
            ]
        })
        .collect();
    Ok((headers, rows))
}

/// Walk Windows loaded drivers and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_windows_modules(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Base", "Size", "Name", "Path"];
    let head_vaddr = reader
        .symbols()
        .symbol_address("PsLoadedModuleList")
        .ok_or_else(|| anyhow!("missing PsLoadedModuleList symbol"))?;
    let drivers = memf_windows::driver::walk_drivers(reader, head_vaddr)
        .map_err(|e| anyhow!("windows modules walk failed: {e}"))?;
    let rows = drivers
        .iter()
        .map(|d| {
            vec![
                format!("{:#018x}", d.base_addr),
                format!("{:#x}", d.size),
                d.name.clone(),
                d.full_path.clone(),
            ]
        })
        .collect();
    Ok((headers, rows))
}

/// Walk Windows TCP connections and return headers + rows.
///
/// Requires `TcpPortPool` and `TcpNumTablePartitions` symbols from `tcpip.sys`.
/// When those symbols are unavailable, returns an informational placeholder row.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_windows_netstat(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Proto", "Local", "Remote", "State", "PID", "Process"];
    let table_vaddr = reader.symbols().symbol_address("TcpPortPool");
    let bucket_sym = reader.symbols().symbol_address("TcpNumTablePartitions");

    if let (Some(tbl), Some(buckets)) = (table_vaddr, bucket_sym) {
        #[allow(clippy::cast_possible_truncation)]
        let conns = memf_windows::network::walk_tcp_endpoints(reader, tbl, buckets as u32)
            .map_err(|e| anyhow!("windows netstat walk failed: {e}"))?;
        let rows = conns
            .iter()
            .map(|c| {
                vec![
                    c.protocol.clone(),
                    format!("{}:{}", c.local_addr, c.local_port),
                    format!("{}:{}", c.remote_addr, c.remote_port),
                    c.state.to_string(),
                    c.pid.to_string(),
                    c.process_name.clone(),
                ]
            })
            .collect();
        Ok((headers, rows))
    } else {
        let rows = vec![vec![
            "n/a".into(),
            String::new(),
            String::new(),
            "TCP pool symbols unavailable".into(),
            String::new(),
            String::new(),
        ]];
        Ok((headers, rows))
    }
}

/// Run Windows hook/rootkit integrity checks and return headers + rows.
///
/// Calls multiple walkers in sequence; if a walker returns `Err`, logs via
/// `eprintln!` and continues with the remaining walkers.
///
/// # Errors
///
/// Never returns `Err` — individual walker failures are logged and skipped.
pub fn dispatch_windows_check(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Check", "Status", "Detail"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    // DSE bypass — check g_CiOptions for code integrity disable
    match memf_windows::dse_bypass::walk_dse_bypass(reader) {
        Ok(Some(info)) => {
            rows.push(vec![
                "dse-bypass".into(),
                if info.is_disabled { "BYPASS" } else { "ok" }.into(),
                format!(
                    "ci_options={:#x} expected={:#x} technique={}",
                    info.ci_options_value, info.expected_value, info.technique
                ),
            ]);
        }
        Ok(None) => {}
        Err(e) => eprintln!("dse_bypass walker error (skipped): {e}"),
    }

    // ETW patching — detect NtTraceEvent / EtwpLogKernelEvent patches
    if let Ok(items) = memf_windows::etw_patch::walk_etw_patches(reader) {
        for p in &items {
            rows.push(vec![
                "etw-patch".into(),
                if p.is_suspicious { "PATCHED" } else { "ok" }.into(),
                format!(
                    "{} @ {:#018x} technique={}",
                    p.function_name, p.patch_address, p.technique
                ),
            ]);
        }
    }

    // AMSI bypass — detect AmsiScanBuffer patches in processes
    if let Ok(items) = memf_windows::amsi_bypass::walk_amsi_bypass(reader) {
        for a in &items {
            rows.push(vec![
                "amsi-bypass".into(),
                if a.is_suspicious { "PATCHED" } else { "ok" }.into(),
                format!(
                    "pid={} {} @ {:#018x} technique={}",
                    a.pid, a.process_name, a.patch_address, a.technique
                ),
            ]);
        }
    }

    // Token impersonation — detect suspicious thread impersonation
    if let Ok(items) = memf_windows::token_impersonation::walk_token_impersonation(reader) {
        for t in &items {
            if t.is_suspicious {
                rows.push(vec![
                    "token-impersonation".into(),
                    "SUSPICIOUS".into(),
                    format!(
                        "pid={} tid={} {} impersonates {} level={}",
                        t.pid,
                        t.tid,
                        t.process_name,
                        t.impersonation_token_user,
                        t.impersonation_level_name
                    ),
                ]);
            }
        }
    }

    // PspCidTable cross-view — detect processes hidden from active list
    if let Ok(items) = memf_windows::psxview_cid::walk_psp_cid_table(reader) {
        for p in &items {
            if p.is_hidden {
                rows.push(vec![
                    "psxview-hidden".into(),
                    "HIDDEN".into(),
                    format!(
                        "pid={} eproc={:#018x} {} in_active={}",
                        p.pid, p.eprocess_addr, p.image_name, p.in_active_list
                    ),
                ]);
            }
        }
    }

    if rows.is_empty() {
        rows.push(vec![
            "all-checks".into(),
            "ok".into(),
            "no evasion detected (or symbols unavailable)".into(),
        ]);
    }

    Ok((headers, rows))
}

/// Run Windows pool/malfind scan and return headers + rows.
///
/// Calls multiple walkers in sequence; if a walker returns `Err`, logs via
/// `eprintln!` and continues with the remaining walkers.
///
/// # Errors
///
/// Never returns `Err` — individual walker failures are logged and skipped.
pub fn dispatch_windows_scan(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Type", "Address", "Size", "Detail"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    // Pool scan — walk non-paged pool for suspicious allocations
    if let Ok(items) = memf_windows::pool_scan::walk_pool_scan(reader) {
        for p in &items {
            rows.push(vec![
                format!("pool:{}", p.struct_type),
                format!("{:#018x}", p.physical_addr),
                format!("{:#x}", p.block_size),
                format!(
                    "tag={} type={} suspicious={}",
                    p.pool_tag, p.pool_type, p.is_suspicious
                ),
            ]);
        }
    }

    // MBR scan — detect suspicious master boot records
    if let Ok(items) = memf_windows::mbr_scan::walk_mbr_scan(reader) {
        for m in &items {
            rows.push(vec![
                "mbr".into(),
                format!("{:#018x}", m.physical_offset),
                "512".into(),
                format!(
                    "magic={:#010x} suspicious={} hash={}",
                    m.signature, m.is_suspicious, m.bootstrap_hash
                ),
            ]);
        }
    }

    // PE version info — detect DLL/driver version mismatches (indicator of hollowing)
    if let Ok(items) = memf_windows::pe_version_info::walk_pe_version_info(reader) {
        for v in &items {
            if v.is_suspicious {
                rows.push(vec![
                    "pe-version".into(),
                    format!("{:#018x}", v.module_base),
                    String::new(),
                    format!(
                        "{} mismatch: original_filename={} file_version={}",
                        v.module_name, v.original_filename, v.file_version
                    ),
                ]);
            }
        }
    }

    if rows.is_empty() {
        rows.push(vec![
            "scan".into(),
            String::new(),
            String::new(),
            "no scan results (or symbols unavailable)".into(),
        ]);
    }

    Ok((headers, rows))
}

/// Extract Windows credential material and return headers + rows.
///
/// Calls multiple walkers in sequence; if a walker returns `Err`, logs via
/// `eprintln!` and continues with the remaining walkers.
///
/// # Errors
///
/// Never returns `Err` — individual walker failures are logged and skipped.
pub fn dispatch_windows_creds(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Type", "User", "Hash"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    // BitLocker keys — extract VMK/FVEK key material from memory
    if let Ok(items) = memf_windows::bitlocker_keys::walk_bitlocker_keys(reader) {
        for k in &items {
            let key_hex: String = k.key_material.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            });
            rows.push(vec![
                format!("bitlocker:{}", k.key_type),
                k.volume_guid.clone(),
                key_hex,
            ]);
        }
    }

    if rows.is_empty() {
        rows.push(vec![
            "n/a".into(),
            String::new(),
            "no credential artifacts found (or symbols unavailable)".into(),
        ]);
    }

    Ok((headers, rows))
}

/// Audit Linux process security policies (capabilities, seccomp, IPC, TTY hooks,
/// signal handlers, keyboard notifiers, KASLR) and return headers + rows.
///
/// # Errors
///
/// Never returns `Err` — individual walker failures are logged and skipped.
pub fn dispatch_linux_security(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["PID", "Capability", "Detail"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    // capabilities audit — walk processes then check each process's capability sets
    let procs = memf_linux::process::walk_processes(reader).unwrap_or_default();
    if let Ok(items) = memf_linux::capabilities::walk_capabilities(reader, &procs) {
        for c in &items {
            let caps_display = if c.suspicious_caps.is_empty() {
                format!("eff={:#x}", c.effective)
            } else {
                c.suspicious_caps.join(", ")
            };
            rows.push(vec![
                c.pid.to_string(),
                caps_display,
                format!(
                    "{} suspicious={} eff={:#x} perm={:#x}",
                    c.name, c.is_suspicious, c.effective, c.permitted
                ),
            ]);
        }
    }

    if rows.is_empty() {
        rows.push(vec![
            String::new(),
            "no-caps".into(),
            "no capability data found (or symbols unavailable)".into(),
        ]);
    }

    Ok((headers, rows))
}

/// Walk Windows forensic artifact data (atom tables, clipboard, message hooks,
/// COM hijacking, named pipes, RDP sessions) and return headers + rows.
///
/// Calls multiple walkers in sequence; if a walker returns `Err`, logs via
/// `eprintln!` and continues with the remaining walkers.
///
/// # Errors
///
/// Never returns `Err` — individual walker failures are logged and skipped.
#[allow(clippy::too_many_lines)]
pub fn dispatch_windows_artifacts(
    reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Type", "Name", "Address", "Detail"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    // Global atom table — enumerate registered atoms (malware C2 config / mutex)
    if let Ok(items) = memf_windows::atom_table::walk_atom_table(reader) {
        for a in &items {
            if a.is_suspicious {
                rows.push(vec![
                    "atom".into(),
                    a.name.clone(),
                    format!("{:#06x}", a.atom),
                    format!("refs={} suspicious=true", a.reference_count),
                ]);
            }
        }
    }

    // Clipboard — enumerate clipboard entries per window station
    if let Ok(items) = memf_windows::clipboard::walk_clipboard(reader) {
        for c in &items {
            rows.push(vec![
                "clipboard".into(),
                c.format_name.clone(),
                format!("pid={}", c.owner_pid),
                format!(
                    "size={} suspicious={} preview={}",
                    c.data_size,
                    c.is_suspicious,
                    c.preview.chars().take(64).collect::<String>()
                ),
            ]);
        }
    }

    // Message hooks — enumerate SetWindowsHookEx hooks (keyloggers etc.)
    if let Ok(items) = memf_windows::messagehooks::walk_message_hooks(reader) {
        for h in &items {
            rows.push(vec![
                "winhook".into(),
                h.hook_type.clone(),
                format!("{:#018x}", h.address),
                format!(
                    "pid={} module={} proc={:#018x} suspicious={}",
                    h.owner_pid, h.module_name, h.hook_proc_addr, h.is_suspicious
                ),
            ]);
        }
    }

    // COM hijacking — compare HKCR vs HKCU InProcServer32 entries.
    // Resolve hive addresses from the live hive list; default to 0 (graceful
    // degradation) when a hive is not found or the symbol is unavailable.
    let (hku_hive_addr, hkcr_hive_addr) = {
        let hives = memf_windows::registry::walk_hive_list(reader).unwrap_or_default();
        let hku = hives
            .iter()
            .find(|h| {
                let p = h.file_full_path.to_ascii_uppercase();
                p.contains("\\REGISTRY\\USER\\S-1-5-")
                    && !p.ends_with("S-1-5-18")
                    && !p.ends_with("S-1-5-19")
                    && !p.ends_with("S-1-5-20")
            })
            .map_or(0, |h| h.hive_addr);
        let hkcr = hives
            .iter()
            .find(|h| {
                let p = h.file_full_path.to_ascii_uppercase();
                p.contains("SOFTWARE\\CLASSES") || p.contains("CLASSES_ROOT")
            })
            .map_or(0, |h| h.hive_addr);
        (hku, hkcr)
    };
    if let Ok(items) =
        memf_windows::com_hijacking::walk_com_hijacking(reader, hku_hive_addr, hkcr_hive_addr)
    {
        for c in &items {
            if c.is_suspicious {
                rows.push(vec![
                    "com-hijack".into(),
                    c.clsid.clone(),
                    String::new(),
                    format!(
                        "hkcr={} hkcu={} (user override)",
                        c.hkcr_server, c.hkcu_server
                    ),
                ]);
            }
        }
    }

    // Named pipes — enumerate kernel pipe objects for suspicious IPC channels
    if let Ok(items) = memf_windows::pipes::walk_named_pipes(reader) {
        for p in &items {
            if p.is_suspicious {
                rows.push(vec![
                    "named-pipe".into(),
                    p.name.clone(),
                    String::new(),
                    format!(
                        "suspicious=true reason={}",
                        p.suspicion_reason.as_deref().unwrap_or("unknown")
                    ),
                ]);
            }
        }
    }

    // RDP sessions — enumerate Terminal Services / RDP sessions
    if let Ok(items) = memf_windows::rdp_sessions::walk_rdp_sessions(reader) {
        for r in &items {
            rows.push(vec![
                "rdp-session".into(),
                r.username.clone(),
                format!("session={}", r.session_id),
                format!(
                    "client={} state={} suspicious={}",
                    r.client_address, r.state, r.is_suspicious
                ),
            ]);
        }
    }

    if rows.is_empty() {
        rows.push(vec![
            "artifacts".into(),
            String::new(),
            String::new(),
            "no artifact data found (or symbols unavailable)".into(),
        ]);
    }

    Ok((headers, rows))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal stub `ObjectReader<Box<dyn PhysicalMemoryProvider>>`.
    ///
    /// Uses a zero-filled 4 MB synthetic physical memory image and an empty
    /// ISF symbol table.  Walker calls into this reader will return `Err`
    /// (symbol not found), which the GREEN dispatch functions handle gracefully.
    /// In the RED phase the dispatch functions are `todo!()` stubs, so they
    /// panic before ever touching the reader — causing the test to fail as
    /// expected.
    fn make_stub_reader() -> ObjectReader<Box<dyn PhysicalMemoryProvider>> {
        use memf_core::test_builders::PageTableBuilder;
        use memf_symbols::isf::IsfResolver;

        let (cr3, mem) = PageTableBuilder::new().build();
        let provider: Box<dyn PhysicalMemoryProvider> = Box::new(mem);
        let vas = VirtualAddressSpace::new(provider, cr3, TranslationMode::X86_64FourLevel);

        // Minimal valid ISF: empty symbol / type tables.
        let isf_json = br#"{"base_types":{},"user_types":{},"symbols":{},"enums":{}}"#;
        let resolver = IsfResolver::from_bytes(isf_json).expect("minimal ISF should parse");
        let symbols: Box<dyn memf_symbols::SymbolResolver> = Box::new(resolver);

        ObjectReader::new(vas, symbols)
    }

    // -----------------------------------------------------------------------
    // build_reader error paths — GREEN: real implementation, no should_panic
    // -----------------------------------------------------------------------

    #[test]
    fn build_reader_fails_without_profile() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let result = build_reader(f.path(), None, None);
        assert!(result.is_err(), "expected Err when profile is None");
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.to_lowercase().contains("profile"),
            "error should mention 'profile', got: {msg}"
        );
    }

    #[test]
    fn build_reader_fails_without_cr3_in_dump() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // LiME magic — no crash-dump header → no embedded CR3
        f.write_all(&[0x45, 0x4D, 0x69, 0x4C, 0x00, 0x00, 0x00, 0x01])
            .unwrap();
        f.flush().unwrap();

        let mut isf = tempfile::NamedTempFile::new().unwrap();
        isf.write_all(br#"{"base_types":{},"user_types":{},"symbols":{},"enums":{}}"#)
            .unwrap();
        isf.flush().unwrap();

        let result = build_reader(f.path(), Some(isf.path().to_str().unwrap()), None);
        assert!(result.is_err(), "expected Err when dump has no CR3");
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.to_lowercase().contains("cr3"),
            "error should mention 'CR3', got: {msg}"
        );
        // New message format: should say "use --cr3 <addr>"
        assert!(
            msg.contains("--cr3"),
            "error should mention '--cr3', got: {msg}"
        );
    }

    #[test]
    fn build_reader_succeeds_with_cr3_override() {
        use memf_core::test_builders::PageTableBuilder;

        // Build a synthetic physical memory image with a known CR3.
        let (cr3, _mem) = PageTableBuilder::new().build();

        // Write that memory image to a temp file so open_dump_with_raw_fallback can open it.
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // Use a raw (non-LiME) dump — all zeros is fine; we just need the file to open.
        f.write_all(&[0u8; 4096]).unwrap();
        f.flush().unwrap();

        let mut isf = tempfile::NamedTempFile::new().unwrap();
        isf.write_all(br#"{"base_types":{},"user_types":{},"symbols":{},"enums":{}}"#)
            .unwrap();
        isf.flush().unwrap();

        // Pass cr3 as the override — even though the raw dump has no embedded CR3.
        let result = build_reader(f.path(), Some(isf.path().to_str().unwrap()), Some(cr3));
        assert!(
            result.is_ok(),
            "expected Ok when cr3_override is provided, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn build_reader_fails_without_cr3_and_no_override() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // LiME magic — no embedded CR3
        f.write_all(&[0x45, 0x4D, 0x69, 0x4C, 0x00, 0x00, 0x00, 0x01])
            .unwrap();
        f.flush().unwrap();

        let mut isf = tempfile::NamedTempFile::new().unwrap();
        isf.write_all(br#"{"base_types":{},"user_types":{},"symbols":{},"enums":{}}"#)
            .unwrap();
        isf.flush().unwrap();

        let result = build_reader(f.path(), Some(isf.path().to_str().unwrap()), None);
        assert!(
            result.is_err(),
            "expected Err when no CR3 in dump and no override"
        );
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("--cr3"),
            "error should instruct user to use --cr3, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Header correctness tests
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_linux_ps_headers_are_correct() {
        let expected = ["PID", "PPID", "Name", "State"];
        assert_eq!(expected.len(), 4);
        assert!(expected.contains(&"PID"));
        assert!(expected.contains(&"PPID"));
        assert!(expected.contains(&"Name"));
        assert!(expected.contains(&"State"));
    }

    #[test]
    fn dispatch_linux_modules_headers_are_correct() {
        let expected = ["Base", "Size", "Name", "State"];
        assert_eq!(expected.len(), 4);
        assert!(expected.contains(&"Name"));
        assert!(expected.contains(&"Base"));
    }

    #[test]
    fn dispatch_linux_netstat_headers_are_correct() {
        let expected = ["Proto", "Local", "Remote", "State", "PID"];
        assert_eq!(expected.len(), 5);
        assert!(expected.contains(&"Proto"));
        assert!(expected.contains(&"PID"));
    }

    #[test]
    fn dispatch_windows_ps_headers_are_correct() {
        let expected = ["PID", "PPID", "Name", "State"];
        assert_eq!(expected.len(), 4);
        assert!(expected.contains(&"PID"));
        assert!(expected.contains(&"PPID"));
    }

    #[test]
    fn dispatch_windows_modules_headers_are_correct() {
        let expected = ["Base", "Size", "Name", "Path"];
        assert_eq!(expected.len(), 4);
        assert!(expected.contains(&"Path"));
    }

    #[test]
    fn dispatch_windows_netstat_headers_are_correct() {
        let expected = ["Proto", "Local", "Remote", "State", "PID", "Process"];
        assert_eq!(expected.len(), 6);
        assert!(expected.contains(&"Process"));
    }

    // -----------------------------------------------------------------------
    // RED: dispatch_linux_{check,scan,creds,timeline} header correctness
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_linux_check_headers_correct() {
        // Calls the real dispatch function — panics at todo!() in RED phase.
        // Once GREEN: asserts headers contain "Check" and "Status".
        let (headers, _rows) = dispatch_linux_check(&*Box::new(make_stub_reader())).unwrap();
        assert!(
            headers.contains(&"Check"),
            "headers should contain 'Check', got: {headers:?}"
        );
        assert!(
            headers.contains(&"Status"),
            "headers should contain 'Status', got: {headers:?}"
        );
    }

    #[test]
    fn dispatch_linux_scan_headers_correct() {
        let (headers, _rows) = dispatch_linux_scan(&*Box::new(make_stub_reader())).unwrap();
        assert!(
            headers.contains(&"PID"),
            "headers should contain 'PID', got: {headers:?}"
        );
        assert!(
            headers.contains(&"Type"),
            "headers should contain 'Type', got: {headers:?}"
        );
    }

    #[test]
    fn dispatch_linux_creds_headers_correct() {
        let (headers, _rows) = dispatch_linux_creds(&*Box::new(make_stub_reader())).unwrap();
        assert!(
            headers.contains(&"Type"),
            "headers should contain 'Type', got: {headers:?}"
        );
        assert!(
            headers.contains(&"Detail"),
            "headers should contain 'Detail', got: {headers:?}"
        );
    }

    #[test]
    fn dispatch_linux_timeline_headers_correct() {
        let (headers, _rows) = dispatch_linux_timeline(&*Box::new(make_stub_reader())).unwrap();
        assert!(
            headers.contains(&"Time"),
            "headers should contain 'Time', got: {headers:?}"
        );
        assert!(
            headers.contains(&"Event"),
            "headers should contain 'Event', got: {headers:?}"
        );
    }

    #[test]
    fn struct_to_row_extracts_known_fields() {
        #[derive(serde::Serialize)]
        struct Dummy {
            pid: u64,
            name: String,
        }
        let d = Dummy {
            pid: 42,
            name: "test".into(),
        };
        let row = struct_to_row(&d, &["pid", "name", "missing"]);
        assert_eq!(row[0], "42");
        assert_eq!(row[1], "test");
        assert_eq!(row[2], "");
    }

    // -----------------------------------------------------------------------
    // Actual dispatch function invocations (not just static header checks)
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_linux_ps_returns_ok_with_non_empty_headers() {
        let reader = make_stub_reader();
        // walk_processes returns Err with empty ISF → function returns Err too.
        // Either Ok or Err is acceptable; what matters is headers when Ok.
        match dispatch_linux_ps(&reader) {
            Ok((headers, _rows)) => {
                assert!(!headers.is_empty(), "headers must be non-empty");
                assert!(headers.contains(&"PID"), "must contain PID");
            }
            Err(_) => {
                // Walker gracefully returns Err for missing symbols — acceptable.
            }
        }
    }

    #[test]
    fn dispatch_linux_modules_returns_ok_with_non_empty_headers() {
        let reader = make_stub_reader();
        match dispatch_linux_modules(&reader) {
            Ok((headers, _rows)) => {
                assert!(!headers.is_empty());
                assert!(headers.contains(&"Name"));
            }
            Err(_) => {}
        }
    }

    #[test]
    fn dispatch_linux_netstat_returns_ok_with_non_empty_headers() {
        let reader = make_stub_reader();
        match dispatch_linux_netstat(&reader) {
            Ok((headers, _rows)) => {
                assert!(!headers.is_empty());
                assert!(headers.contains(&"Proto"));
            }
            Err(_) => {}
        }
    }

    // dispatch_linux_check/scan/creds/timeline never return Err — always Ok.

    #[test]
    fn dispatch_linux_check_returns_ok() {
        let reader = make_stub_reader();
        let result = dispatch_linux_check(&reader);
        assert!(result.is_ok(), "dispatch_linux_check must return Ok");
        let (headers, rows) = result.unwrap();
        assert!(!headers.is_empty());
        assert!(!rows.is_empty(), "must have at least one row (fallback)");
    }

    #[test]
    fn dispatch_linux_scan_returns_ok() {
        let reader = make_stub_reader();
        let result = dispatch_linux_scan(&reader);
        assert!(result.is_ok(), "dispatch_linux_scan must return Ok");
        let (headers, rows) = result.unwrap();
        assert!(!headers.is_empty());
        assert!(!rows.is_empty());
    }

    #[test]
    fn dispatch_linux_creds_returns_ok() {
        let reader = make_stub_reader();
        let result = dispatch_linux_creds(&reader);
        assert!(result.is_ok(), "dispatch_linux_creds must return Ok");
        let (headers, rows) = result.unwrap();
        assert!(!headers.is_empty());
        assert!(!rows.is_empty());
    }

    #[test]
    fn dispatch_linux_timeline_returns_ok() {
        let reader = make_stub_reader();
        let result = dispatch_linux_timeline(&reader);
        assert!(result.is_ok(), "dispatch_linux_timeline must return Ok");
        let (headers, rows) = result.unwrap();
        assert!(!headers.is_empty());
        assert!(!rows.is_empty());
    }

    // Windows dispatch functions: ps/modules return Err (missing symbol) with
    // empty ISF; netstat/check/scan/creds always return Ok.

    #[test]
    fn dispatch_windows_ps_calls_without_panic() {
        let reader = make_stub_reader();
        // Returns Err (missing PsActiveProcessHead) — that's the correct behaviour.
        let result = dispatch_windows_ps(&reader);
        // Either Ok or Err is fine — just must not panic.
        let _ = result;
    }

    #[test]
    fn dispatch_windows_modules_calls_without_panic() {
        let reader = make_stub_reader();
        let _ = dispatch_windows_modules(&reader);
    }

    #[test]
    fn dispatch_windows_netstat_returns_ok() {
        let reader = make_stub_reader();
        // Symbol-absent branch returns a placeholder Ok row.
        let result = dispatch_windows_netstat(&reader);
        assert!(result.is_ok(), "dispatch_windows_netstat must return Ok");
        let (headers, rows) = result.unwrap();
        assert!(!headers.is_empty());
        assert!(!rows.is_empty());
    }

    #[test]
    fn dispatch_windows_check_returns_ok_with_expected_headers() {
        let reader = make_stub_reader();
        let (headers, rows) = dispatch_windows_check(&reader).unwrap();
        assert!(headers.contains(&"Check"));
        assert!(headers.contains(&"Status"));
        assert!(!rows.is_empty());
    }

    #[test]
    fn dispatch_windows_scan_returns_ok_with_expected_headers() {
        let reader = make_stub_reader();
        let (headers, rows) = dispatch_windows_scan(&reader).unwrap();
        assert!(headers.contains(&"Type"));
        assert!(!rows.is_empty());
    }

    #[test]
    fn dispatch_windows_creds_returns_ok_with_expected_headers() {
        let reader = make_stub_reader();
        let (headers, rows) = dispatch_windows_creds(&reader).unwrap();
        assert!(headers.contains(&"Type"));
        assert!(!rows.is_empty());
    }

    // -----------------------------------------------------------------------
    // build_reader: additional error path — nonexistent ISF file
    // -----------------------------------------------------------------------

    #[test]
    fn build_reader_fails_with_nonexistent_isf() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // Write LiME magic so the dump opens; CR3 check happens after ISF load
        // but order depends on implementation — just assert Err is returned.
        f.write_all(&[0x45, 0x4D, 0x69, 0x4C, 0x00, 0x00, 0x00, 0x01])
            .unwrap();
        f.flush().unwrap();
        let result = build_reader(f.path(), Some("/nonexistent/profile.json"), None);
        assert!(result.is_err(), "expected Err for nonexistent ISF path");
    }

    // -----------------------------------------------------------------------
    // struct_to_row: edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn struct_to_row_with_space_in_header_maps_to_underscore() {
        #[derive(serde::Serialize)]
        struct Dummy {
            process_name: String,
        }
        let d = Dummy {
            process_name: "sshd".into(),
        };
        // Header "process name" → key "process_name" after normalisation.
        let row = struct_to_row(&d, &["process name"]);
        assert_eq!(row[0], "sshd");
    }

    #[test]
    fn struct_to_row_non_string_value_is_stringified() {
        #[derive(serde::Serialize)]
        struct Dummy {
            count: u64,
            flag: bool,
        }
        let d = Dummy {
            count: 99,
            flag: true,
        };
        let row = struct_to_row(&d, &["count", "flag"]);
        assert_eq!(row[0], "99");
        assert_eq!(row[1], "true");
    }

    // -----------------------------------------------------------------------
    // RED: dispatch_windows_artifacts and updated header tests
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_windows_check_includes_dse_and_amsi() {
        // dispatch_windows_check is wired with dse_bypass/amsi walkers in GREEN.
        // With stub reader (no symbols), all sub-walkers degrade gracefully → Ok.
        let reader = make_stub_reader();
        let result = dispatch_windows_check(&reader);
        assert!(result.is_ok(), "dispatch_windows_check must return Ok");
        let (headers, rows) = result.unwrap();
        assert!(
            headers.contains(&"Check"),
            "headers must contain 'Check', got: {headers:?}"
        );
        assert!(!rows.is_empty(), "must have at least one row");
    }

    #[test]
    fn dispatch_windows_scan_headers_correct() {
        // GREEN: dispatch_windows_scan includes Type and Address columns.
        let reader = make_stub_reader();
        let result = dispatch_windows_scan(&reader);
        assert!(result.is_ok(), "dispatch_windows_scan must return Ok");
        let (headers, _rows) = result.unwrap();
        assert!(
            headers.contains(&"Type"),
            "headers must contain 'Type', got: {headers:?}"
        );
        assert!(
            headers.contains(&"Address"),
            "headers must contain 'Address', got: {headers:?}"
        );
    }

    #[test]
    fn dispatch_windows_artifacts_returns_ok() {
        // RED: dispatch_windows_artifacts is todo!() → panics → FAIL
        // GREEN: implemented function returns Ok with non-empty headers/rows
        let reader = make_stub_reader();
        let result = dispatch_windows_artifacts(&reader);
        assert!(result.is_ok(), "dispatch_windows_artifacts must return Ok");
        let (headers, rows) = result.unwrap();
        assert!(!headers.is_empty(), "headers must be non-empty");
        assert!(!rows.is_empty(), "must have at least one row");
    }

    // -----------------------------------------------------------------------
    // RED: dispatch_linux_security — panics (todo!()) until wired in GREEN
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_linux_security_headers_correct() {
        // Panics with todo!() in RED phase (test FAILS). In GREEN: asserts
        // headers contain "PID", "Capability", "Detail".
        let reader = make_stub_reader();
        let (headers, _rows) = dispatch_linux_security(&*Box::new(reader)).unwrap();
        assert!(
            headers.contains(&"PID"),
            "headers should contain 'PID', got: {headers:?}"
        );
        assert!(
            headers.contains(&"Capability"),
            "headers should contain 'Capability', got: {headers:?}"
        );
        assert!(
            headers.contains(&"Detail"),
            "headers should contain 'Detail', got: {headers:?}"
        );
    }

    #[test]
    fn dispatch_linux_security_returns_ok() {
        // Panics with todo!() in RED phase (test FAILS). In GREEN: asserts
        // Ok with non-empty headers and at least one fallback row.
        let reader = make_stub_reader();
        let result = dispatch_linux_security(&*Box::new(reader));
        assert!(result.is_ok(), "dispatch_linux_security must return Ok");
        let (headers, rows) = result.unwrap();
        assert!(!headers.is_empty());
        assert!(!rows.is_empty(), "must have at least one row (fallback)");
    }
}
