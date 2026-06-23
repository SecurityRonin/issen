//! Real-dump validation for the memf-windows `com_hijacking` walker and the
//! shared HMAP registry navigation it delegates to, against the DFIR Madness
//! "Stolen Szechuan Sauce" domain-controller memory image (`citadeldc01.mem`,
//! Windows Server 2012 R2, kernel build 9600).
//!
//! Independent oracle: Volatility 3 (`windows.registry.hivelist` /
//! `windows.registry.printkey`) on the same image. The ground-truth constants
//! below were produced by Volatility, NOT self-authored:
//!
//! ```text
//! $ vol.py -f citadeldc01.mem windows.registry.hivelist
//!   0xc001f117a000  \SystemRoot\System32\Config\SOFTWARE
//!   0xc001f3208000  \??\C:\Users\Administrator\ntuser.dat
//!   0xc001f3216000  \??\C:\Users\Administrator\...\UsrClass.dat
//! $ vol.py ... printkey --offset 0xc001f117a000 --key 'Classes\CLSID'
//!   -> 4612 readable direct subkeys
//! $ vol.py ... printkey --offset 0xc001f3208000 --key 'Software\Classes\CLSID'
//!   -> key present, 0 subkeys (HKCU COM classes empty on this DC)
//! ```
//!
//! This exercises three things the synthetic `CellHive` unit tests cannot:
//!   1. memf's hive enumeration agrees with Volatility on the `_CMHIVE` VAs;
//!   2. the shared HMAP walker enumerates a real, heavily-populated key
//!      (`SOFTWARE\Classes\CLSID`, 4612 subkeys) with the exact stored count;
//!   3. `walk_com_hijacking` runs on real in-memory hives and does NOT
//!      fabricate hits where the oracle shows none.
//!
//! `#[ignore]`d by default (needs the 2 GB `citadeldc01.mem` extract, gitignored
//! per `docs/corpus-catalog.md`):
//!
//! ```bash
//! cargo test -p issen-mem --test szechuan_com_hijacking -- --ignored --nocapture
//! ```
//!
//! Override the dump location with `SZECHUAN_DC_MEM` if it lives elsewhere.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use issen_mem::dispatch::build_reader;

/// Volatility-reported `_CMHIVE` VA of the HKLM\SOFTWARE hive. Volatility prints
/// the 48-bit canonical form; memf keeps the full 64-bit sign-extended VA, so we
/// compare the low 48 bits ([`CANONICAL_VA_MASK`]).
const SOFTWARE_HIVE_VA: u64 = 0xc001_f117_a000;
/// Low-48-bit mask for canonical x86-64 VA comparison across the two tools.
const CANONICAL_VA_MASK: u64 = 0xFFFF_FFFF_FFFF;
/// Volatility-reported readable direct-subkey count of `SOFTWARE\Classes\CLSID`.
const CLSID_SUBKEY_COUNT_ORACLE: u32 = 4612;

/// Locate `citadeldc01.mem` via `SZECHUAN_DC_MEM`, falling back to the in-repo
/// corpus path (relative to this crate's `tests/` directory).
fn citadel_dc_mem() -> Option<PathBuf> {
    if let Some(p) = std::env::var("SZECHUAN_DC_MEM").ok().map(PathBuf::from) {
        if p.exists() {
            return Some(p);
        }
    }
    let local = Path::new("../../tests/data/dfirmadness-szechuan-sauce/extracted/citadeldc01.mem");
    if local.exists() {
        Some(local.to_path_buf())
    } else {
        None
    }
}

/// End-to-end validation of the `com_hijacking` walker + shared HMAP navigation
/// against the Volatility oracle on the real DC image.
#[test]
#[ignore = "needs the 2 GB DFIR Madness citadeldc01.mem; set SZECHUAN_DC_MEM"]
fn szechuan_com_hijacking_matches_volatility() {
    let Some(dump) = citadel_dc_mem() else {
        eprintln!("citadeldc01.mem not found; skipping (set SZECHUAN_DC_MEM)");
        return;
    };
    let (_fmt, reader) = build_reader(&dump, None, None).expect("build reader from dump");

    let hives = memf_windows::registry::walk_hive_list(&reader).expect("walk_hive_list");
    eprintln!("walk_hive_list: {} hives", hives.len());

    // ── Check 1: hive enumeration agrees with Volatility on the SOFTWARE VA ──
    let software = hives
        .iter()
        .find(|h| {
            h.file_user_name
                .to_ascii_uppercase()
                .trim_end_matches('\0')
                .ends_with("SOFTWARE")
        })
        .expect("SOFTWARE hive present in hive list");
    eprintln!(
        "SOFTWARE base_addr = {:#x} (oracle {:#x})",
        software.base_addr, SOFTWARE_HIVE_VA
    );
    assert_eq!(
        software.base_addr & CANONICAL_VA_MASK,
        SOFTWARE_HIVE_VA,
        "memf _CMHIVE VA for SOFTWARE must match Volatility hivelist (low 48 bits)"
    );

    // ── Check 2: positive — enumerate a real, heavily-populated key ──
    // Walk SOFTWARE to depth 2 (root -> Classes -> CLSID) and confirm the
    // shared HMAP navigation reports the exact stored subkey count Volatility
    // reads for SOFTWARE\Classes\CLSID.
    let keys = memf_windows::registry_keys::walk_registry_keys(&reader, software.base_addr, 2)
        .expect("walk_registry_keys SOFTWARE depth 2");
    let clsid = keys
        .iter()
        .find(|k| {
            let p = k.path.to_ascii_uppercase();
            p.ends_with("\\CLASSES\\CLSID")
        })
        .expect("SOFTWARE\\Classes\\CLSID reachable via shared HMAP walker");
    eprintln!(
        "SOFTWARE\\Classes\\CLSID subkey_count = {} (oracle {})",
        clsid.subkey_count, CLSID_SUBKEY_COUNT_ORACLE
    );
    assert_eq!(
        clsid.subkey_count, CLSID_SUBKEY_COUNT_ORACLE,
        "shared HMAP walker must read the exact stored CLSID subkey count Volatility sees"
    );

    // ── Check 3: end-to-end com_hijacking true-negative ──
    // HKCU = Administrator ntuser.dat (Software\Classes\CLSID), HKCR = the
    // Administrator UsrClass.dat. Volatility shows HKCU\Software\Classes\CLSID
    // empty, so a correct walker returns no hijacks (and crucially does not
    // fabricate any on a real in-memory hive).
    let ntuser = hives.iter().find(|h| {
        let p = h.file_user_name.to_ascii_uppercase();
        p.contains("ADMINISTRATOR") && p.trim_end_matches('\0').ends_with("NTUSER.DAT")
    });
    let usrclass = hives.iter().find(|h| {
        let p = h.file_user_name.to_ascii_uppercase();
        p.contains("ADMINISTRATOR") && p.trim_end_matches('\0').ends_with("USRCLASS.DAT")
    });

    let hku = ntuser.map_or(0, |h| h.base_addr);
    let hkcr = usrclass.map_or(0, |h| h.base_addr);
    eprintln!("HKCU ntuser base = {hku:#x}, HKCR usrclass base = {hkcr:#x}");
    assert!(hku != 0, "Administrator ntuser.dat present in hive list");

    let hijacks = memf_windows::com_hijacking::walk_com_hijacking(&reader, hku, hkcr)
        .expect("walk_com_hijacking");
    eprintln!("walk_com_hijacking returned {} candidate(s)", hijacks.len());
    for h in &hijacks {
        eprintln!("  {} -> {}", h.clsid, h.hkcu_server);
    }
    assert!(
        hijacks.is_empty(),
        "Volatility shows HKCU\\Software\\Classes\\CLSID empty on this DC; \
         walk_com_hijacking must not fabricate hits, got: {hijacks:?}"
    );
}

/// Locate the DESKTOP-SDN1RPT workstation image via `SDN1RPT_MEM`, falling back
/// to the in-repo corpus path.
fn sdn1rpt_mem() -> Option<PathBuf> {
    if let Some(p) = std::env::var("SDN1RPT_MEM").ok().map(PathBuf::from) {
        if p.exists() {
            return Some(p);
        }
    }
    let local =
        Path::new("../../tests/data/dfirmadness-szechuan-sauce/extracted/DESKTOP-SDN1RPT.mem");
    if local.exists() {
        Some(local.to_path_buf())
    } else {
        None
    }
}

/// Extended true-negative coverage on the DESKTOP-SDN1RPT workstation (Windows
/// 10 build 19041, a different kernel from the DC's 9600), across every real
/// per-user hive. Volatility confirms each user's `Software\Classes\CLSID` is
/// empty (the box has no COM-hijack persistence — the Szechuan attack chain is
/// Cobalt Strike + scheduled tasks, not T1546.015). The walker must enumerate
/// real per-user NTUSER hives without crashing and without fabricating hits.
///
/// Volatility ground truth (`windows.registry.hivelist` + `printkey`):
/// ```text
///   0xcf0482bb0000  \??\C:\Users\ricksanchez\ntuser.dat   Software\Classes\CLSID -> empty
///   0xcf048126f000  \??\C:\Users\Admin\ntuser.dat         Software\Classes\CLSID -> empty
///   0xcf0482c47000  \??\C:\Users\Administrator\ntuser.dat Software\Classes\CLSID -> empty
/// ```
#[test]
#[ignore = "needs the 2 GB DFIR Madness DESKTOP-SDN1RPT.mem; set SDN1RPT_MEM"]
fn sdn1rpt_com_hijacking_no_fabrication() {
    let Some(dump) = sdn1rpt_mem() else {
        eprintln!("DESKTOP-SDN1RPT.mem not found; skipping (set SDN1RPT_MEM)");
        return;
    };
    let (_fmt, reader) = build_reader(&dump, None, None).expect("build reader from dump");

    let hives = memf_windows::registry::walk_hive_list(&reader).expect("walk_hive_list");

    // Every real user NTUSER.DAT (under \Users\, not the service-profile hives).
    let user_hives: Vec<_> = hives
        .iter()
        .filter(|h| {
            let p = h.file_user_name.to_ascii_uppercase();
            let p = p.trim_end_matches('\0');
            p.contains("\\USERS\\") && p.ends_with("NTUSER.DAT")
        })
        .collect();
    eprintln!("workstation: {} user NTUSER.DAT hives", user_hives.len());
    assert!(
        !user_hives.is_empty(),
        "expected at least one \\Users\\*\\ntuser.dat on the workstation image"
    );

    for h in &user_hives {
        let hijacks = memf_windows::com_hijacking::walk_com_hijacking(&reader, h.base_addr, 0)
            .expect("walk_com_hijacking");
        eprintln!(
            "  {} (base {:#x}) -> {} hit(s)",
            h.file_user_name.trim_end_matches('\0'),
            h.base_addr,
            hijacks.len()
        );
        assert!(
            hijacks.is_empty(),
            "Volatility shows {} HKCU\\Software\\Classes\\CLSID empty; \
             walk_com_hijacking must not fabricate, got: {hijacks:?}",
            h.file_user_name.trim_end_matches('\0')
        );
    }
}
