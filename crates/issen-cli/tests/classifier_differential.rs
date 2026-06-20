//! Classifier differential (issen #114, Stage 2).
//!
//! The registry-derived classifier `detect_from_registry` (highest-priority
//! matching selector wins) must agree with the hand-written
//! `detect_artifact_type` on a corpus of real artifact paths — that agreement is
//! the safety gate that lets Stage 4 delete the hand-written classifier. A second
//! test asserts no two *different*-type selectors collide at equal priority, so
//! the priority field is an unambiguous, tested replacement for the old
//! if-ladder's implicit precedence.
//!
//! Runtime over the real inventory: `use issen_cli` force-links the anchors so
//! every parser's selector is present; an under-population guard prevents a
//! false pass.

use std::path::Path;

use issen_cli as _;
use issen_core::artifacts::ArtifactType;
use issen_core::plugin::registry::{detect_from_registry, ParserRegistration};
use issen_fswalker::orchestrator::detect_artifact_type;

/// Representative real artifact paths (extracted-tree `/` separators), covering
/// every classified type, the overlap cases the priority order must resolve, and
/// negatives. Paths point at non-existent files so the `regf`/`SEGB` magic
/// fallbacks return `false` identically for both classifiers.
const CORPUS: &[&str] = &[
    // Windows filesystem / journal
    "/img/$MFT",
    "/img/$Extend/$UsnJrnl",
    "/img/Windows/Prefetch/CMD.EXE-0AB12345.pf",
    "/img/mft.pf",          // overlap: contains "mft" AND ".pf" → Mft wins (prio 99>97)
    "/img/prefetch_mft.pf", // "mft" but also "prefetch" → Mft guard off → Prefetch
    // Event logs
    "/img/Windows/System32/winevt/Logs/Security.evtx",
    "/img/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
    // Registry hives
    "/img/Windows/System32/config/SYSTEM",
    "/img/Windows/System32/config/SOFTWARE",
    "/img/Windows/System32/config/SAM",
    "/img/Windows/System32/config/SECURITY",
    "/img/Users/beth/NTUSER.DAT",
    "/img/Users/beth/AppData/Local/Microsoft/Windows/UsrClass.dat",
    "/img/exported/SYSTEM", // bare "system", no config path, no regf magic → None
    // Amcache / SRUM
    "/img/Windows/AppCompat/Programs/Amcache.hve",
    "/img/Windows/System32/sru/SRUDB.dat",
    // Shortcuts / recycle bin
    "/img/Users/beth/AppData/Roaming/Microsoft/Windows/Recent/secret.lnk",
    "/img/Users/beth/Desktop/Loot.lnk",
    "/img/$Recycle.Bin/S-1-5-21-1-2-3-500/$IU2L112.txt",
    "/img/$Recycle.Bin/S-1-5-21-1-2-3-500/$RU2L112.txt", // $R, not $I → None
    // Device install
    "/img/Windows/INF/setupapi.dev.log",
    "/img/Windows/INF/setupapi.setup.log",
    // Linux
    "/img/var/log/auth.log",
    "/img/var/log/auth.log.1",
    "/img/home/beth/.bash_history",
    "/img/var/log/syslog",
    "/img/var/log/syslog.2",
    "/img/var/log/cron",
    "/img/var/log/cron.log",
    // macOS
    "/img/var/log/system.log",
    "/img/private/var/db/diagnostics/foo.logarchive",
    "/img/.fseventsd/0000000000000001",
    // PE: suspicious dirs vs system32
    "/img/Users/beth/AppData/Local/Temp/evil.exe",
    "/img/Users/Public/dropper.dll",
    "/img/Windows/System32/svchost.exe", // not suspicious → None
    // Negatives
    "/img/Users/beth/Documents/report.docx",
    "/img/random/notes.txt",
];

fn require_populated() -> Vec<&'static ParserRegistration> {
    let regs: Vec<_> = inventory::iter::<ParserRegistration>.into_iter().collect();
    assert!(
        regs.len() >= 25,
        "parser inventory under-populated ({}) — anchors dropped from this test binary",
        regs.len()
    );
    regs
}

#[test]
fn registry_classifier_agrees_with_detect_artifact_type() {
    require_populated();
    let mut diffs = Vec::new();
    for p in CORPUS {
        let path = Path::new(p);
        let old = detect_artifact_type(path);
        let new = detect_from_registry(path);
        // Biome is the one intentional addition: it is discovery-unreachable in
        // the old classifier but its SEGB matcher would classify a real SEGB file.
        // No corpus path is a SEGB file, so this never fires here; documented for
        // completeness.
        if new == Some(ArtifactType::BiomeMenuItem) && old.is_none() {
            continue;
        }
        if old != new {
            diffs.push(format!("{p}: old={old:?} new={new:?}"));
        }
    }
    assert!(
        diffs.is_empty(),
        "registry classifier disagrees with detect_artifact_type:\n{}",
        diffs.join("\n")
    );
}

#[test]
fn no_two_different_type_selectors_collide_at_equal_priority() {
    let regs = require_populated();
    let mut collisions = Vec::new();
    for p in CORPUS {
        let path = Path::new(p);
        let matched: Vec<(u8, ArtifactType)> = regs
            .iter()
            .filter(|r| (r.selector.matches)(path))
            .map(|r| (r.selector.priority, r.selector.artifact_type))
            .collect();
        for (i, (pa, ta)) in matched.iter().enumerate() {
            for (pb, tb) in &matched[i + 1..] {
                if pa == pb && ta != tb {
                    collisions.push(format!(
                        "{p}: priority {pa} matched by both {ta:?} and {tb:?}"
                    ));
                }
            }
        }
    }
    assert!(
        collisions.is_empty(),
        "equal-priority selectors of different types match the same path \
         (ambiguous routing — give one a distinct priority):\n{}",
        collisions.join("\n")
    );
}
