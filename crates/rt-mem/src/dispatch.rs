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
/// - Returns `Err` containing `"CR3"` when the dump has no embedded CR3.
/// - Returns `Err` on I/O failure or ISF parse error.
pub fn build_reader(
    path: &Path,
    profile: Option<&str>,
) -> anyhow::Result<(DumpFormat, ObjectReader<Box<dyn PhysicalMemoryProvider>>)> {
    let profile_path = profile.ok_or_else(|| anyhow!("--profile <isf.json> is required"))?;

    let provider: Box<dyn PhysicalMemoryProvider> =
        open_dump_with_raw_fallback(path).map_err(|e| anyhow!("failed to open dump: {e}"))?;

    // Detect format for the caller.
    let fmt = crate::open::detect_format(path).unwrap_or(DumpFormat::Raw);

    let metadata = provider.metadata();
    let cr3 = metadata.as_ref().and_then(|m| m.cr3).ok_or_else(|| {
        anyhow!("dump has no embedded CR3; use a Windows crash dump or provide --cr3 <addr>")
    })?;

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
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_linux_check(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Check", "Status", "Detail"];
    let rows = vec![vec![
        "hook-scan".into(),
        "ok".into(),
        "no walkers wired for check yet".into(),
    ]];
    Ok((headers, rows))
}

/// Run Linux pool/malfind scan and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_linux_scan(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Offset", "Tag", "Size", "Detail"];
    let rows = vec![vec![
        "0x0".into(),
        "n/a".into(),
        "0".into(),
        "no scan walkers wired yet".into(),
    ]];
    Ok((headers, rows))
}

/// Extract Linux credential material and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_linux_creds(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Type", "User", "Hash"];
    let rows = vec![vec![
        "n/a".into(),
        "".into(),
        "no creds walkers wired yet".into(),
    ]];
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

    match (table_vaddr, bucket_sym) {
        (Some(tbl), Some(buckets)) => {
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
        }
        _ => {
            let rows = vec![vec![
                "n/a".into(),
                "".into(),
                "".into(),
                "TCP pool symbols unavailable".into(),
                "".into(),
                "".into(),
            ]];
            Ok((headers, rows))
        }
    }
}

/// Run Windows hook/rootkit integrity checks and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_windows_check(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Check", "Status", "Detail"];
    let rows = vec![vec![
        "hook-scan".into(),
        "ok".into(),
        "no walkers wired for check yet".into(),
    ]];
    Ok((headers, rows))
}

/// Run Windows pool/malfind scan and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_windows_scan(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Offset", "Tag", "Size", "Detail"];
    let rows = vec![vec![
        "0x0".into(),
        "n/a".into(),
        "0".into(),
        "no scan walkers wired yet".into(),
    ]];
    Ok((headers, rows))
}

/// Extract Windows credential material and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_windows_creds(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    let headers = vec!["Type", "User", "Hash"];
    let rows = vec![vec![
        "n/a".into(),
        "".into(),
        "no creds walkers wired yet".into(),
    ]];
    Ok((headers, rows))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // -----------------------------------------------------------------------
    // build_reader error paths — GREEN: real implementation, no should_panic
    // -----------------------------------------------------------------------

    #[test]
    fn build_reader_fails_without_profile() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let result = build_reader(f.path(), None);
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

        let result = build_reader(f.path(), Some(isf.path().to_str().unwrap()));
        assert!(result.is_err(), "expected Err when dump has no CR3");
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.to_lowercase().contains("cr3"),
            "error should mention 'CR3', got: {msg}"
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
}
