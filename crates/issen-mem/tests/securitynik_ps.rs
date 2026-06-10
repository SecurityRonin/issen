//! Real-dump integration test for the memf `ps` Windows routing fix.
//!
//! Asserts that process listing (`ps`) on the real SecurityNik Windows dump
//! routes through the *Windows* walker and lists the expected processes —
//! at minimum `coreupdater` (the malicious process planted in the challenge)
//! and `spoolsv` (a benign Windows service).
//!
//! This is `#[ignore]`d by default because it needs the 1.3 GB Total Recall
//! zip. Run it with:
//!
//! ```bash
//! MEMF_TEST_DATA=/Users/4n6h4x0r/src/issen/tests/data/SecurityNik \
//!     cargo test -p issen-mem --test securitynik_ps -- --ignored --nocapture
//! ```
//!
//! Ground truth (sidecar JSON / memory-forensic real_data.rs): the dump is a
//! Win11 22621 PAGEDU64 crash dump, embedded CR3 (DTB) = 0x1AE000.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read;
use std::path::{Path, PathBuf};

use issen_mem::cmd_memf::{detect_os, profile_is_windows, resolve_target_os, TargetOs};
use issen_mem::dispatch::{build_reader, dispatch_windows_ps};

/// The Total Recall zip and the dump entry inside it.
const ZIP_NAME: &str = "TOTAL_RECALL_memory_forensics_CHALLENGE.zip";
const DMP_ENTRY: &str = "SECURITYNIK-WIN-20231116-235706.dmp";

/// Locate the SecurityNik zip via `MEMF_TEST_DATA` (the fleet-standard env
/// var), falling back to the in-repo corpus path.
fn securitynik_zip() -> Option<PathBuf> {
    if let Some(dir) = std::env::var("MEMF_TEST_DATA").ok().map(PathBuf::from) {
        let p = dir.join(ZIP_NAME);
        if p.exists() {
            return Some(p);
        }
    }
    let local = Path::new("../../tests/data/SecurityNik").join(ZIP_NAME);
    if local.exists() {
        Some(local)
    } else {
        None
    }
}

/// Extract the `.dmp` from the (Deflate64) zip into a temp file and return it.
fn extract_dmp(zip_path: &Path) -> PathBuf {
    let file = std::fs::File::open(zip_path).expect("open Total Recall zip");
    let mut archive = zip::ZipArchive::new(file).expect("read zip (needs deflate64)");
    let mut entry = archive
        .by_name(DMP_ENTRY)
        .expect("zip should contain the SecurityNik .dmp");

    let out_dir = std::env::temp_dir().join("issen_securitynik_ps");
    std::fs::create_dir_all(&out_dir).expect("create temp dir");
    let out_path = out_dir.join(DMP_ENTRY);

    // Reuse a previously-extracted dump to avoid re-inflating 4.29 GB.
    if out_path.exists()
        && std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0) == entry.size()
    {
        return out_path;
    }

    let mut out = std::fs::File::create(&out_path).expect("create dmp temp file");
    let mut buf = vec![0u8; 8 << 20];
    loop {
        let n = entry.read(&mut buf).expect("read zip entry");
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut out, &buf[..n]).expect("write dmp");
    }
    out_path
}

#[test]
#[ignore = "requires SecurityNik Total Recall zip (1.3 GB); set MEMF_TEST_DATA"]
fn securitynik_ps_lists_windows_processes() {
    let Some(zip_path) = securitynik_zip() else {
        eprintln!("Skipping: {ZIP_NAME} not found (set MEMF_TEST_DATA)");
        return;
    };

    let dump = extract_dmp(&zip_path);

    // Build the reader exactly as `run_memf_command` does: zero-config
    // auto-profile (None) resolves the Windows kernel symbols (post-B1).
    let (fmt, reader) = build_reader(&dump, None, None).expect("build_reader auto-profiles dump");

    // The routing decision: format-derived OS combined with the resolved
    // profile. This must land on Windows — that is the whole point of the fix.
    let format_os = detect_os(fmt);
    let win = profile_is_windows(reader.symbols());
    let os = resolve_target_os(format_os, win);
    assert_eq!(
        os,
        TargetOs::Windows,
        "SecurityNik dump must route to the Windows walker (format_os={format_os:?}, \
         profile_is_windows={win})"
    );

    // Drive the Windows process walker and collect image names.
    let (headers, rows) = dispatch_windows_ps(&reader).expect("windows ps walk");
    let name_col = headers
        .iter()
        .position(|h| *h == "Name")
        .expect("ps output has a Name column");

    let names: Vec<String> = rows
        .iter()
        .filter_map(|r| r.get(name_col).cloned())
        .collect();
    eprintln!("ps listed {} processes", names.len());

    let has = |needle: &str| {
        names
            .iter()
            .any(|n| n.to_ascii_lowercase().contains(needle))
    };

    assert!(
        has("coreupdater"),
        "expected malicious 'coreupdater' in ps output; got: {names:?}"
    );
    assert!(
        has("spoolsv"),
        "expected 'spoolsv' in ps output; got: {names:?}"
    );
}
