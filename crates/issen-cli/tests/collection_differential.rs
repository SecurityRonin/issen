//! Collection differential (issen #114, Stage 3).
//!
//! The registry-derived disk-collection set (`triage_ntfs_sources`, gathered from
//! every default-cost parser's `disk_sources`) must reproduce `issen_disk`'s
//! hand-maintained `WINDOWS_*` triage lists — that equivalence is what makes
//! switching `extract_triage` to the registry behavior-preserving.
//!
//! The one documented difference: `\$LogFile` is in `WINDOWS_TRIAGE_PATHS` but no
//! parser consumes it, so the registry never collects it. Dropping that
//! collection changes nothing downstream (it produced zero events — no parser),
//! so it is exempt here.

use std::collections::BTreeSet;

use issen_cli as _;
use issen_core::plugin::registry::triage_ntfs_sources;
use issen_core::plugin::selector::{NameMatch, NtfsLoc};
use issen_disk::{
    WINDOWS_TRIAGE_GLOBS, WINDOWS_TRIAGE_PATHS, WINDOWS_TRIAGE_STREAMS, WINDOWS_USER_FILES,
    WINDOWS_USER_LNK_DIRS,
};

/// `WINDOWS_TRIAGE_PATHS` entries the registry intentionally does not reproduce
/// as fixed paths:
/// - `\$LogFile`: no parser consumes it, so it produces zero events whether
///   collected or not (a `$LogFile` parser would re-add its collection via its
///   own selector — exactly the registry model). See the LogFile research note.
/// - the four fixed `winevt\Logs\*.evtx` paths: already collected by the
///   `WINDOWS_TRIAGE_GLOBS` `DirSuffix` sweep of that same directory, so the
///   registry's single glob source subsumes them (a redundancy the old list
///   carried, collecting them twice).
const EXEMPT_FIXED: &[&str] = &[
    r"\$LogFile",
    r"\Windows\System32\winevt\Logs\Security.evtx",
    r"\Windows\System32\winevt\Logs\System.evtx",
    r"\Windows\System32\winevt\Logs\Application.evtx",
    r"\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
];

fn ntfs_loc_key(loc: &NtfsLoc) -> String {
    match loc {
        NtfsLoc::FixedPath(p) => format!("fixed:{p}"),
        NtfsLoc::DirSuffix { dir, suffix } => format!("dirsuffix:{dir}:{suffix}"),
        NtfsLoc::PerUserFile(c) => format!("peruser:{c}"),
        NtfsLoc::PerSubdirSweep { parent, rel, name } => {
            let n = match name {
                NameMatch::Suffix(s) => format!("suffix:{s}"),
                NameMatch::Prefix(p) => format!("prefix:{p}"),
            };
            format!("sweep:{parent}:{rel}:{n}")
        }
        NtfsLoc::NamedStream { path, stream } => format!("stream:{path}:{stream}"),
    }
}

/// The hand-maintained `WINDOWS_*` lists, as the same normalized key set, minus
/// the documented `$LogFile` exemption — plus the two code sweeps `extract_triage`
/// performs inline (per-user `.lnk` and per-SID `$Recycle.Bin\$I`).
fn hardcoded_keys() -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for p in WINDOWS_TRIAGE_PATHS {
        if !EXEMPT_FIXED.contains(p) {
            keys.insert(format!("fixed:{p}"));
        }
    }
    for g in WINDOWS_TRIAGE_GLOBS {
        keys.insert(format!("dirsuffix:{}:{}", g.dir, g.suffix));
    }
    for c in WINDOWS_USER_FILES {
        keys.insert(format!("peruser:{c}"));
    }
    for rel in WINDOWS_USER_LNK_DIRS {
        keys.insert(format!(r"sweep:\Users:{rel}:suffix:.lnk"));
    }
    keys.insert(r"sweep:\$Recycle.Bin::prefix:$i".to_string());
    for (path, stream) in WINDOWS_TRIAGE_STREAMS {
        keys.insert(format!("stream:{path}:{stream}"));
    }
    // Jump Lists: collected ONLY via the JumpLists selector's disk_sources — there
    // is no legacy `WINDOWS_*` const because Jump Lists were never collected before
    // the selector model. Post-migration the selector is the single source of truth
    // and `extract_triage` is fully selector-driven, so a new collection target is
    // added here (the expected set), not to a frozen const list.
    keys.insert(
        r"sweep:\Users:AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations:suffix:.automaticDestinations-ms"
            .to_string(),
    );
    keys.insert(
        r"sweep:\Users:AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations:suffix:.customDestinations-ms"
            .to_string(),
    );
    keys
}

#[test]
fn registry_disk_sources_reproduce_the_windows_triage_lists() {
    let registry: BTreeSet<String> = triage_ntfs_sources().iter().map(ntfs_loc_key).collect();
    assert!(
        registry.len() >= 15,
        "registry disk-source set under-populated ({}) — anchors dropped or selectors empty",
        registry.len()
    );
    let hardcoded = hardcoded_keys();

    let missing: Vec<_> = hardcoded.difference(&registry).cloned().collect();
    let extra: Vec<_> = registry.difference(&hardcoded).cloned().collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "registry-derived collection differs from the WINDOWS_* lists.\n\
         in WINDOWS_* but not the registry (a parser is missing a disk_source): {missing:?}\n\
         in the registry but not WINDOWS_* (an unexpected new collection target): {extra:?}"
    );
}
