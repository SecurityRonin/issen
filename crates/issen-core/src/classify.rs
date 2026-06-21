//! Path → artifact matcher predicates, one per `detect_artifact_type` arm.
//!
//! These are the medium-agnostic matchers a parser names in its
//! [`ArtifactSelector`](crate::plugin::selector::ArtifactSelector). Each is
//! **copied verbatim from `issen_fswalker::orchestrator::detect_artifact_type`**
//! so a registry-driven classifier (Stage 2) reproduces today's routing exactly;
//! the differential test asserts the two agree before the hand-written classifier
//! is retired. They are pure path predicates (the registry magic-byte fallback is
//! the one I/O touch, kept for parity) and read nothing at module scope.
//!
//! `case_sensitive_file_extension_comparisons` is allowed: every predicate
//! lowercases `name` first (mirroring the classifier), so the `ends_with(".evtx")`
//! style checks are already case-insensitive.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::path::Path;

/// `(file_name, full_path)` both lowercased — the two views every arm uses.
fn name_full(path: &Path) -> Option<(String, String)> {
    let name = path.file_name()?.to_str()?.to_lowercase();
    let full = path.to_str().unwrap_or_default().to_lowercase();
    Some((name, full))
}

/// Registry magic: a hive begins with the ASCII bytes `regf`.
fn is_regf(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok_and(|()| &buf == b"regf")
}

/// SEGB (Apple Biome) magic: the container begins with `SEGB`.
fn is_segb(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok_and(|()| &buf == b"SEGB")
}

/// `$UsnJrnl:$J` / `$J` change-journal stream.
#[must_use]
pub fn usn(path: &Path) -> bool {
    let Some((name, _)) = name_full(path) else {
        return false;
    };
    name == "$j" || name.contains("usnjrnl") || name.contains("$usnjrnl")
}

/// `$MFT` master file table (but not a prefetch file).
#[must_use]
pub fn mft(path: &Path) -> bool {
    let Some((name, _)) = name_full(path) else {
        return false;
    };
    name == "$mft" || name.contains("mft") && !name.contains("prefetch")
}

/// Windows event log (`*.evtx`).
#[must_use]
pub fn evtx(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name.ends_with(".evtx"))
}

/// Prefetch (`*.pf`).
#[must_use]
pub fn prefetch(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name.ends_with(".pf"))
}

/// Registry hive: the per-user hives by name unconditionally; the
/// generically-named machine hives only under a `registry`/`config` path or with
/// the `regf` magic.
#[must_use]
pub fn registry_hive(path: &Path) -> bool {
    let Some((name, full)) = name_full(path) else {
        return false;
    };
    if name == "ntuser.dat" || name == "usrclass.dat" {
        return true;
    }
    (name == "system" || name == "software" || name == "sam" || name == "security")
        && (full.contains("registry") || full.contains("config") || is_regf(path))
}

/// Amcache hive (`Amcache.hve`).
#[must_use]
pub fn amcache(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name == "amcache.hve")
}

/// SRUM database (`SRUDB.dat`).
#[must_use]
pub fn srum(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name == "srudb.dat")
}

/// Linux auth log (`auth.log` + rotated `auth.log.N`).
#[must_use]
pub fn auth_log(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name == "auth.log" || name.starts_with("auth.log."))
}

/// Windows shortcut (`*.lnk`).
#[must_use]
pub fn lnk(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name.ends_with(".lnk"))
}

/// Jump List file — `*.automaticDestinations-ms` (OLE/CFB) or
/// `*.customDestinations-ms` (flat). `name` is pre-lowercased.
#[must_use]
pub fn jumplist(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| {
        name.ends_with(".automaticdestinations-ms") || name.ends_with(".customdestinations-ms")
    })
}

/// Recycle-bin `$I` index file (gated on the `$recycle.bin` path component).
#[must_use]
pub fn recycle_i(path: &Path) -> bool {
    name_full(path)
        .is_some_and(|(name, full)| name.starts_with("$i") && full.contains("$recycle.bin"))
}

/// Linux syslog (`syslog` + rotated).
#[must_use]
pub fn syslog(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name == "syslog" || name.starts_with("syslog."))
}

/// Linux cron log (`cron`, `cron.log`, rotated).
#[must_use]
pub fn cron(path: &Path) -> bool {
    name_full(path)
        .is_some_and(|(name, _)| name == "cron.log" || name == "cron" || name.starts_with("cron."))
}

/// Linux shell history (`.bash_history` / `bash_history`).
#[must_use]
pub fn bash_history(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name == ".bash_history" || name == "bash_history")
}

/// macOS unified log (`system.log` / `*.logarchive`).
#[must_use]
pub fn macos_log(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name == "system.log" || name.ends_with(".logarchive"))
}

/// macOS FSEvents (any path component under `.fseventsd`).
#[must_use]
pub fn fsevents(path: &Path) -> bool {
    name_full(path).is_some_and(|(_, full)| full.contains("fseventsd"))
}

/// Windows device/driver install log (`setupapi.*`).
#[must_use]
pub fn setupapi(path: &Path) -> bool {
    name_full(path).is_some_and(|(name, _)| name.starts_with("setupapi."))
}

/// Executable in a user-writable / suspicious location (dropped-malware territory).
/// System32 / Program Files binaries are deliberately excluded — PE analysis is
/// expensive and routed only where a dropped binary is likely.
#[must_use]
pub fn pe_suspicious(path: &Path) -> bool {
    const SUSPICIOUS_DIRS: &[&str] = &[
        "\\temp\\",
        "/temp/",
        "\\appdata\\",
        "/appdata/",
        "\\downloads\\",
        "/downloads/",
        "\\programdata\\",
        "/programdata/",
        "$recycle.bin",
        "\\perflogs\\",
        "/perflogs/",
        "\\users\\public\\",
        "/users/public/",
    ];
    let Some((name, full)) = name_full(path) else {
        return false;
    };
    (name.ends_with(".exe") || name.ends_with(".dll") || name.ends_with(".scr"))
        && SUSPICIOUS_DIRS.iter().any(|d| full.contains(d))
}

/// Apple Biome SEGB container (by `SEGB` magic). Not classified by the current
/// hand-written classifier — Biome is command-routed today; declaring this
/// matcher makes the parser discovery-reachable in the registry model.
#[must_use]
pub fn segb(path: &Path) -> bool {
    is_segb(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn name_predicates_match_classifier_arms() {
        let p = Path::new;
        assert!(usn(p("/x/$J")) && usn(p("/x/$UsnJrnl")));
        assert!(mft(p("/x/$MFT")) && !mft(p("/x/something.pf")));
        assert!(evtx(p("/x/Security.evtx")));
        assert!(prefetch(p("/x/CMD.EXE-123.pf")));
        assert!(registry_hive(p("/x/NTUSER.DAT")));
        assert!(registry_hive(p("/Windows/System32/config/SYSTEM")));
        assert!(!registry_hive(p("/x/SYSTEM"))); // no config path, no regf magic
        assert!(amcache(p("/x/Amcache.hve")) && srum(p("/x/SRUDB.dat")));
        assert!(auth_log(p("/var/log/auth.log.1")) && bash_history(p("/h/.bash_history")));
        assert!(lnk(p("/x/Recent/a.lnk")));
        assert!(recycle_i(p("/x/$Recycle.Bin/S-1/$IABC.txt")) && !recycle_i(p("/x/$IABC")));
        assert!(syslog(p("/var/log/syslog")) && cron(p("/var/log/cron")));
        assert!(macos_log(p("/x/a.logarchive")) && fsevents(p("/x/.fseventsd/0001")));
        assert!(setupapi(p("/Windows/INF/setupapi.dev.log")));
        assert!(
            pe_suspicious(p("/Users/x/AppData/evil.exe"))
                && !pe_suspicious(p("/Windows/System32/svchost.exe"))
        );
    }

    #[test]
    fn regf_and_segb_magic_fallbacks() {
        let dir = tempdir().unwrap();
        let hive = dir.path().join("SYSTEM");
        std::fs::File::create(&hive)
            .unwrap()
            .write_all(b"regf....")
            .unwrap();
        assert!(
            registry_hive(&hive),
            "regf magic ⇒ registry even with no config path"
        );

        let bio = dir.path().join("App.MenuItem");
        std::fs::File::create(&bio)
            .unwrap()
            .write_all(b"SEGB....")
            .unwrap();
        assert!(segb(&bio) && !segb(&hive));
    }
}
