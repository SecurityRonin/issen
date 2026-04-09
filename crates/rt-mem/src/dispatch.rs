//! Walker dispatch — opens a memory dump, loads ISF symbols, and routes
//! each [`MemfCommand`] to the appropriate `memf-linux` / `memf-windows`
//! walker function.

// Imports used by the GREEN implementation; suppressed in RED stub.
#[allow(unused_imports)]
use std::path::Path;

#[allow(unused_imports)]
use anyhow::anyhow;
use memf_core::object_reader::ObjectReader;
#[allow(unused_imports)]
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
#[allow(unused_imports)]
use memf_format::{open_dump_with_raw_fallback, PhysicalMemoryProvider};
#[allow(unused_imports)]
use memf_symbols::isf::IsfResolver;

use crate::open::DumpFormat;

// ---------------------------------------------------------------------------
// Reader bootstrap (not yet implemented — GREEN commit will fill this in)
// ---------------------------------------------------------------------------

/// Open a memory dump and build an [`ObjectReader`] backed by ISF symbols.
///
/// # Errors
///
/// - Returns `Err` containing `"profile"` when `profile` is `None`.
/// - Returns `Err` containing `"CR3"` when the dump has no embedded CR3.
/// - Returns `Err` on I/O failure or ISF parse error.
pub fn build_reader(
    _path: &Path,
    _profile: Option<&str>,
) -> anyhow::Result<(DumpFormat, ObjectReader<Box<dyn PhysicalMemoryProvider>>)> {
    // RED: not yet implemented
    todo!("build_reader not yet implemented")
}

// ---------------------------------------------------------------------------
// Row-extraction helper
// ---------------------------------------------------------------------------

#[allow(dead_code)] // used in GREEN implementation
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
// Linux dispatch functions (stubs — GREEN commit will implement)
// ---------------------------------------------------------------------------

/// Walk Linux processes and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_linux_ps(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Walk Linux kernel modules and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_linux_modules(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Walk Linux TCP connections and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_linux_netstat(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Run Linux hook/rootkit integrity checks and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_linux_check(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Run Linux pool/malfind scan and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_linux_scan(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Extract Linux credential material and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_linux_creds(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

// ---------------------------------------------------------------------------
// Windows dispatch functions (stubs — GREEN commit will implement)
// ---------------------------------------------------------------------------

/// Walk Windows processes and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_windows_ps(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Walk Windows loaded drivers and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_windows_modules(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Walk Windows TCP connections and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails (symbol not found, memory read error).
pub fn dispatch_windows_netstat(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Run Windows hook/rootkit integrity checks and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_windows_check(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Run Windows pool/malfind scan and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_windows_scan(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

/// Extract Windows credential material and return headers + rows.
///
/// # Errors
///
/// Returns `Err` if the walker fails.
pub fn dispatch_windows_creds(
    _reader: &ObjectReader<Box<dyn PhysicalMemoryProvider>>,
) -> anyhow::Result<(Vec<&'static str>, Vec<Vec<String>>)> {
    todo!()
}

// ---------------------------------------------------------------------------
// Tests (RED — these should fail until GREEN implementation is in place)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // RED: `build_reader` is a todo!() stub — the test panics until GREEN.
    // `#[should_panic]` proves the stub is hit; the real assertion (Err
    // containing "profile") is verified in GREEN once the impl is in place.
    #[test]
    #[should_panic(expected = "not yet implemented")]
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
    #[should_panic(expected = "not yet implemented")]
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
