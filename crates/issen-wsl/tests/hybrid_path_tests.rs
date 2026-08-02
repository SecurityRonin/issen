//! RED tests for HybridPath — Windows↔WSL path normalization.
//!
//! DrvFs rule: /mnt/<drive>/<rest> ↔ <DRIVE>:\<rest with / → \>
//! Native WSL paths (/home/..., /etc/...) have no Windows equivalent.
//! Native Windows paths (C:\...) have no WSL equivalent.

// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use issen_wsl::hybrid_path::HybridPath;

// ── Test 1: /mnt/c/... is recognized as DrvFs ────────────────────────────────

#[test]
fn drvfs_wsl_path_recognized() {
    let p = HybridPath::from_wsl_str("/mnt/c/Users/alice/Downloads/payload.exe");
    assert!(p.is_drvfs(), "should be DrvFs path");
}

// ── Test 2: /mnt/c/... resolves to Windows C:\... ────────────────────────────

#[test]
fn drvfs_wsl_to_windows() {
    let p = HybridPath::from_wsl_str("/mnt/c/Users/alice/Downloads/payload.exe");
    let win = p
        .windows_path()
        .expect("DrvFs should have Windows equivalent");
    assert_eq!(
        win.to_string_lossy(),
        r"C:\Users\alice\Downloads\payload.exe"
    );
}

// ── Test 3: /mnt/d/... uses correct drive letter ──────────────────────────────

#[test]
fn drvfs_d_drive() {
    let p = HybridPath::from_wsl_str("/mnt/d/data/secret.db");
    let win = p.windows_path().expect("should have Windows path");
    assert_eq!(win.to_string_lossy(), r"D:\data\secret.db");
}

// ── Test 4: /home/alice is native WSL (no Windows path) ──────────────────────

#[test]
fn native_wsl_path_has_no_windows() {
    let p = HybridPath::from_wsl_str("/home/alice/.bash_history");
    assert!(!p.is_drvfs(), "should not be DrvFs");
    assert!(
        p.windows_path().is_none(),
        "native WSL path has no Windows equivalent"
    );
}

// ── Test 5: Windows C:\... path from Windows side ────────────────────────────

#[test]
fn windows_path_to_wsl_drvfs() {
    let p = HybridPath::from_windows_str(r"C:\Users\alice\Downloads\payload.exe");
    assert!(p.is_drvfs(), "Windows path should produce DrvFs");
    let wsl = p.wsl_path().expect("should have WSL path");
    assert_eq!(
        wsl.to_string_lossy(),
        "/mnt/c/Users/alice/Downloads/payload.exe"
    );
}

// ── Test 6: Windows D:\... path ──────────────────────────────────────────────

#[test]
fn windows_d_drive_to_wsl() {
    let p = HybridPath::from_windows_str(r"D:\data\secret.db");
    let wsl = p.wsl_path().expect("should have WSL path");
    assert_eq!(wsl.to_string_lossy(), "/mnt/d/data/secret.db");
}

// ── Test 7: paths without drive letter are pure Windows ──────────────────────

#[test]
fn windows_unc_path_no_wsl() {
    let p = HybridPath::from_windows_str(r"\\server\share\file.txt");
    assert!(!p.is_drvfs(), "UNC path is not DrvFs");
    assert!(p.wsl_path().is_none());
}

// ── Test 8: same_file detects equivalent paths ───────────────────────────────

#[test]
fn same_file_drvfs_equivalence() {
    let from_wsl = HybridPath::from_wsl_str("/mnt/c/Users/alice/file.txt");
    let from_win = HybridPath::from_windows_str(r"C:\Users\alice\file.txt");
    assert!(
        from_wsl.same_file(&from_win),
        "DrvFs equivalents should be same_file"
    );
}

// ── Test 9: same_file is false for different paths ───────────────────────────

#[test]
fn same_file_different_paths_false() {
    let a = HybridPath::from_wsl_str("/mnt/c/Users/alice/a.txt");
    let b = HybridPath::from_wsl_str("/mnt/c/Users/alice/b.txt");
    assert!(!a.same_file(&b));
}

// ── Test 10: /mnt/ with no path component is not a drive ─────────────────────

#[test]
fn mnt_root_is_not_drvfs() {
    let p = HybridPath::from_wsl_str("/mnt/");
    assert!(!p.is_drvfs(), "/mnt/ itself is not a DrvFs path");
}

// ── Test 11: Display format is consistent ────────────────────────────────────

#[test]
fn display_drvfs_shows_both() {
    let p = HybridPath::from_wsl_str("/mnt/c/temp/x.exe");
    let s = p.to_string();
    assert!(
        s.contains("/mnt/c/temp/x.exe") || s.contains(r"C:\temp\x.exe"),
        "display should include at least one form, got: {s}"
    );
}
