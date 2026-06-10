//! Real-dump integration tests for the memf `netstat` (B3) and `scan`/malfind
//! (B4) Windows paths against the SecurityNik TOTAL RECALL 2024 dump.
//!
//! These assert against *independently verified* ground truth from the
//! authoritative SecurityNik write-up
//! (<https://www.securitynik.com/2024/03/total-recall-2024-memory-forensics-self.html>),
//! NOT against the task brief's premise.
//!
//! ## Why the brief is wrong for this dump
//!
//! The brief named C2 `203.78.103.109:443` and `spoolsv`/`coreupdater`
//! injection. Those facts belong to a DIFFERENT challenge — DFIR Madness
//! "Stolen Szechuan Sauce" (Case-001) — and do NOT appear in this dump. The
//! `#35` agent already proved there is no `coreupdater` process here.
//!
//! ### Verified `windows.netscan` ESTABLISHED C2 sessions (B3)
//!
//! ```text
//! 10.0.0.108:4444  -> 10.0.0.110:38159  ESTABLISHED   (Metasploit 4444)
//! 10.0.0.108:49957 -> 10.0.0.110:443    ESTABLISHED
//! 10.0.0.108:49685 -> 10.0.0.101:4444   ESTABLISHED   (Metasploit 4444)
//! 10.0.0.108:49686 -> 10.0.0.110:22     ESTABLISHED   (SSH)
//! ```
//!
//! ### Verified `windows.malfind` injected regions (B4)
//!
//! ```text
//! 7164 vmtoolsd.exe  0x1b986d60000-0x1b986d91fff  VadS  PAGE_EXECUTE_READWRITE
//! 4852 powershell.exe                             VadS  PAGE_EXECUTE_READWRITE
//! ```
//!
//! Both injected regions begin with *zeros* (shellcode/Meterpreter), NOT an MZ
//! header — so the verified detector signal is MEM_PRIVATE + RWX, with MZ only
//! a sub-classifier.
//!
//! `#[ignore]`d by default because they need the 1.3 GB Total Recall zip:
//!
//! ```bash
//! MEMF_TEST_DATA=/Users/4n6h4x0r/src/issen/tests/data/SecurityNik \
//!     cargo test -p issen-mem --test securitynik_netscan_malfind -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::io::Read;
use std::path::{Path, PathBuf};

use issen_mem::dispatch::{build_reader, dispatch_windows_netstat, dispatch_windows_scan};

/// The Total Recall zip and the dump entry inside it.
const ZIP_NAME: &str = "TOTAL_RECALL_memory_forensics_CHALLENGE.zip";
const DMP_ENTRY: &str = "SECURITYNIK-WIN-20231116-235706.dmp";

/// Locate the SecurityNik zip via `MEMF_TEST_DATA`, falling back to the
/// in-repo corpus path.
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

    let out_dir = std::env::temp_dir().join("issen_securitynik_netscan_malfind");
    std::fs::create_dir_all(&out_dir).expect("create temp dir");
    let out_path = out_dir.join(DMP_ENTRY);

    // Reuse a previously-extracted dump to avoid re-inflating multiple GB.
    if out_path.exists()
        && std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0) == entry.size()
    {
        return out_path;
    }

    let mut out = std::fs::File::create(&out_path).expect("create extracted dump");
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    loop {
        let n = entry.read(&mut buf).expect("inflate dump entry");
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut out, &buf[..n]).expect("write extracted dump");
    }
    out_path
}

/// B3 — `windows.netscan` on the real dump surfaces the verified ESTABLISHED
/// 10.0.0.0/8 C2 sessions (and NOT the brief's 203.78.103.109).
#[test]
#[ignore = "needs the 1.3 GB SecurityNik Total Recall zip; set MEMF_TEST_DATA"]
fn securitynik_netstat_surfaces_verified_c2() {
    let Some(zip) = securitynik_zip() else {
        eprintln!("SecurityNik zip not found; skipping (set MEMF_TEST_DATA)");
        return;
    };
    let dmp = extract_dmp(&zip);
    let (_fmt, reader) = build_reader(&dmp, None, None).expect("build reader from dump");

    let (headers, rows) = dispatch_windows_netstat(&reader).expect("windows netstat walk");
    let col = |name: &str| headers.iter().position(|h| *h == name);
    let remote_col = col("Remote").expect("netstat has Remote column");
    let state_col = col("State").expect("netstat has State column");
    eprintln!("netstat produced {} rows", rows.len());

    let remotes: Vec<String> = rows
        .iter()
        .filter_map(|r| r.get(remote_col).cloned())
        .collect();

    // The brief's IP must NOT be present (it is from a different challenge).
    assert!(
        !remotes.iter().any(|r| r.contains("203.78.103.109")),
        "203.78.103.109 is from DFIR Madness, not Total Recall; got remotes: {remotes:?}"
    );

    // At least one verified ESTABLISHED C2 endpoint must surface. The write-up's
    // ground truth: 10.0.0.110 / 10.0.0.101 on ports 4444/443/22/38159.
    let established_external = rows.iter().any(|r| {
        let remote = r.get(remote_col).map(String::as_str).unwrap_or("");
        let state = r.get(state_col).map(String::as_str).unwrap_or("");
        state.contains("ESTABLISHED")
            && (remote.contains("10.0.0.110") || remote.contains("10.0.0.101"))
    });
    assert!(
        established_external,
        "expected a verified ESTABLISHED C2 session to 10.0.0.110/10.0.0.101; got remotes: {remotes:?}"
    );
}

/// B4 — `windows.scan` (malfind) on the real dump flags the verified injected
/// RWX-private regions in vmtoolsd.exe (7164) and powershell.exe (4852).
#[test]
#[ignore = "needs the 1.3 GB SecurityNik Total Recall zip; set MEMF_TEST_DATA"]
fn securitynik_malfind_flags_injected_processes() {
    let Some(zip) = securitynik_zip() else {
        eprintln!("SecurityNik zip not found; skipping (set MEMF_TEST_DATA)");
        return;
    };
    let dmp = extract_dmp(&zip);
    let (_fmt, reader) = build_reader(&dmp, None, None).expect("build reader from dump");

    let (headers, rows) = dispatch_windows_scan(&reader).expect("windows scan walk");
    eprintln!("scan produced {} rows ({} headers)", rows.len(), headers.len());

    // Collect the malfind rows (Type column begins with "malfind").
    let type_col = headers
        .iter()
        .position(|h| *h == "Type")
        .expect("scan has Type column");
    let malfind_rows: Vec<&Vec<String>> = rows
        .iter()
        .filter(|r| {
            r.get(type_col)
                .map(|t| t.starts_with("malfind"))
                .unwrap_or(false)
        })
        .collect();
    eprintln!("malfind flagged {} regions", malfind_rows.len());

    let joined: String = malfind_rows
        .iter()
        .flat_map(|r| r.iter())
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" | ");

    // The verified injected processes are vmtoolsd.exe and powershell.exe —
    // NOT spoolsv/coreupdater (those are from a different challenge).
    assert!(
        joined.contains("vmtoolsd"),
        "expected malfind to flag vmtoolsd.exe (PID 7164); got: {joined}"
    );
    assert!(
        joined.contains("powershell"),
        "expected malfind to flag powershell.exe (PID 4852); got: {joined}"
    );
    // The brief's premise must NOT spuriously match.
    assert!(
        !joined.contains("coreupdater"),
        "no coreupdater process exists in this dump (brief premise is wrong)"
    );
}
