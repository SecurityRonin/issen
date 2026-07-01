//! Memory leg of `issen correlate` (capstone #37, Tier C wiring).
//!
//! After the disk ingest, the correlate run discovers memory dumps in the case
//! directory and ingests each one into the same case timeline so the
//! cross-artifact rules can join a memory subject (a process image, a remote
//! C2 IP) against the disk/log legs. This is a **best-effort, Humble-Object
//! shell**: a case with no dump, or a dump the symbol auto-profiler cannot
//! resolve, is logged and skipped — the disk leg of correlate always completes.
//!
//! The discovery and per-dump decisions live in the pure helpers below
//! ([`discover_memory_dumps`], [`dump_stem`], [`acquisition_ns_from_filetime`],
//! [`resolve_acquisition_ns`]); the irreducible shell ([`ingest_memory_leg`])
//! does only the `build_reader` → `dispatch_windows_*` → `ingest_memory_dump`
//! wiring that genuinely needs a real dump.

use std::path::{Path, PathBuf};

use issen_mem::dispatch::{
    build_reader, dispatch_windows_netstat, dispatch_windows_ps, dispatch_windows_scan,
};
use issen_mem::mem_ingest::ingest_memory_dump;
use issen_timeline::store::TimelineStore;

/// File extensions (lower-case, without the dot) recognised as memory dumps,
/// plus the special-cased `hiberfil.sys` file name.
const DUMP_EXTENSIONS: &[&str] = &["mem", "raw", "vmem", "dmp"];

/// Windows FILETIME epoch offset: 100ns intervals between 1601-01-01 and the
/// Unix epoch (1970-01-01). `11_644_473_600 s * 10_000_000`.
const FILETIME_UNIX_EPOCH_DELTA: u64 = 116_444_736_000_000_000;

/// Documented placeholder acquisition instant used only when a dump exposes no
/// `system_time` metadata **and** its file mtime is unreadable: `2000-01-01T00:00:00Z`.
/// A run that falls back to this logs a warning so the report's memory epoch is
/// not silently mis-dated — see [`resolve_acquisition_ns`].
pub const PLACEHOLDER_ACQ_NS: i64 = 946_684_800_000_000_000;

/// Discover memory dumps directly under `case_dir`.
///
/// Matches files whose extension is one of [`DUMP_EXTENSIONS`] (case-insensitive)
/// or whose name is exactly `hiberfil.sys` (case-insensitive). Non-recursive:
/// the case dir's top level is the dump location, mirroring the disk-leg ingest
/// root. Returns a stable, sorted list so the ingest order is deterministic.
/// A missing or unreadable directory yields an empty list (best-effort).
#[must_use]
pub fn discover_memory_dumps(case_dir: &Path) -> Vec<PathBuf> {
    let mut dumps: Vec<PathBuf> = match std::fs::read_dir(case_dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && is_memory_dump_name(p))
            .collect(),
        Err(_) => Vec::new(),
    };
    dumps.sort();
    dumps
}

/// Returns `true` when `path`'s file name marks it as a memory dump.
fn is_memory_dump_name(path: &Path) -> bool {
    let name_is_hiberfil = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("hiberfil.sys"));
    let ext_matches = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| DUMP_EXTENSIONS.iter().any(|d| d.eq_ignore_ascii_case(ext)));
    name_is_hiberfil || ext_matches
}

/// The host / evidence-source id for a dump: its file stem (e.g.
/// `WIN-CASE001.mem` → `WIN-CASE001`). Falls back to the full file name, then to
/// `"memory-dump"` for a path with no name component.
#[must_use]
pub fn dump_stem(path: &Path) -> String {
    path.file_stem()
        .or_else(|| path.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("memory-dump")
        .to_string()
}

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) into Unix
/// nanoseconds, or `None` when the value is before the Unix epoch or the
/// conversion would overflow `i64`.
///
/// A FILETIME of `0` (no system time recorded) is before the Unix epoch and so
/// yields `None`, which the caller treats as "no metadata instant".
#[must_use]
pub fn acquisition_ns_from_filetime(filetime: u64) -> Option<i64> {
    // Preserve the pre-epoch guard (0 = "no system time" is below the delta, so
    // it too yields None): only decode FILETIMEs at or after the Unix epoch.
    if filetime < FILETIME_UNIX_EPOCH_DELTA {
        return None;
    }
    // Delegate the epoch arithmetic to the spec-cited timeglyph decoder (our own
    // fleet crate, [MS-DTYP]). A u64 above i64::MAX is garbage → None (no panic).
    let posix_ns = timeglyph::format("filetime")
        .ok()?
        .decode_int(i64::try_from(filetime).ok()?)
        .ok()?;
    i64::try_from(posix_ns.0).ok()
}

/// Resolve the acquisition instant (Unix ns) for a dump, in priority order:
/// the dump's `system_time` FILETIME metadata, then the file mtime, then the
/// documented [`PLACEHOLDER_ACQ_NS`].
///
/// Returns `(ns, source)` where `source` names which arm fired, so the shell
/// can log a warning when only the placeholder was available. Pure: the mtime
/// is passed in (already read by the shell) rather than read here.
#[must_use]
pub fn resolve_acquisition_ns(
    system_time_filetime: Option<u64>,
    mtime_ns: Option<i64>,
) -> (i64, &'static str) {
    if let Some(ns) = system_time_filetime.and_then(acquisition_ns_from_filetime) {
        return (ns, "dump system_time");
    }
    if let Some(ns) = mtime_ns {
        return (ns, "file mtime");
    }
    (PLACEHOLDER_ACQ_NS, "placeholder (2000-01-01)")
}

/// Read a file's modification time as Unix nanoseconds, or `None` if it is
/// unavailable / before the Unix epoch.
fn file_mtime_ns(path: &Path) -> Option<i64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(dur.as_nanos()).ok()
}

/// Ingest the memory leg of a correlate run: discover dumps under `case_dir`
/// and, for each, build a reader, run the three Windows dispatches, and persist
/// the rows into `store`. Best-effort — a dump that cannot be opened/profiled is
/// logged and skipped, and the overall result is always `Ok` so the disk leg of
/// correlate completes regardless.
///
/// Returns the total number of memory rows persisted across all dumps.
pub fn ingest_memory_leg(store: &TimelineStore, case_dir: &Path) -> u64 {
    let dumps = discover_memory_dumps(case_dir);
    if dumps.is_empty() {
        eprintln!(
            "[correlate] no memory dumps found under {} — skipping memory leg",
            case_dir.display()
        );
        return 0;
    }

    let mut total = 0u64;
    for dump in &dumps {
        match build_reader(dump, None, None) {
            Ok((_fmt, reader)) => {
                let stem = dump_stem(dump);
                let system_time = reader
                    .vas()
                    .physical()
                    .metadata()
                    .and_then(|m| m.system_time);
                let (acquired_at_ns, ts_source) =
                    resolve_acquisition_ns(system_time, file_mtime_ns(dump));
                if ts_source.starts_with("placeholder") {
                    eprintln!(
                        "[correlate] {}: no acquisition timestamp available; using {ts_source}",
                        dump.display()
                    );
                }

                // Best-effort dispatch: a walker that errors (missing symbols)
                // yields an empty leg rather than aborting the dump.
                let ps = dispatch_windows_ps(&reader).unwrap_or_default();
                let netstat = dispatch_windows_netstat(&reader).unwrap_or_default();
                let scan = dispatch_windows_scan(&reader).unwrap_or_default();

                match ingest_memory_dump(store, &stem, acquired_at_ns, &ps, &netstat, &scan) {
                    Ok(n) => {
                        eprintln!(
                            "[correlate] memory leg: {} ({stem}) → {n} event(s) [{ts_source}]",
                            dump.display()
                        );
                        total += n;
                    }
                    Err(e) => eprintln!(
                        "[correlate] {}: failed to persist memory events (skipped): {e}",
                        dump.display()
                    ),
                }
            }
            Err(e) => eprintln!(
                "[correlate] {}: could not open/profile dump (skipped): {e}",
                dump.display()
            ),
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ── discover_memory_dumps ────────────────────────────────────────────────

    #[test]
    fn discover_finds_known_extensions_and_hiberfil_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "dump.mem",
            "image.RAW",
            "vm.vmem",
            "crash.dmp",
            "HIBERFIL.SYS",
        ] {
            let mut f = std::fs::File::create(dir.path().join(name)).unwrap();
            f.write_all(b"x").unwrap();
        }
        // Non-dump files are ignored.
        std::fs::File::create(dir.path().join("notes.txt")).unwrap();
        std::fs::File::create(dir.path().join("evidence.E01")).unwrap();

        let found = discover_memory_dumps(dir.path());
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(found.len(), 5, "5 dumps, txt + E01 excluded: {names:?}");
        assert!(names.iter().any(|n| n == "dump.mem"));
        assert!(names.iter().any(|n| n == "image.RAW"));
        assert!(names.iter().any(|n| n == "HIBERFIL.SYS"));
        assert!(!names.iter().any(|n| n == "notes.txt"));
        assert!(!names.iter().any(|n| n == "evidence.E01"));
    }

    #[test]
    fn discover_on_missing_dir_returns_empty() {
        let found = discover_memory_dumps(Path::new("/no/such/case/dir/exists"));
        assert!(found.is_empty());
    }

    #[test]
    fn discover_is_sorted_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["c.mem", "a.mem", "b.mem"] {
            std::fs::File::create(dir.path().join(name)).unwrap();
        }
        let found = discover_memory_dumps(dir.path());
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["a.mem", "b.mem", "c.mem"]);
    }

    // ── dump_stem ────────────────────────────────────────────────────────────

    #[test]
    fn dump_stem_strips_extension() {
        assert_eq!(
            dump_stem(Path::new("/cases/WIN-CASE001.mem")),
            "WIN-CASE001"
        );
        assert_eq!(dump_stem(Path::new("/cases/hiberfil.sys")), "hiberfil");
    }

    // ── acquisition_ns_from_filetime ─────────────────────────────────────────

    #[test]
    fn filetime_unix_epoch_maps_to_zero_ns() {
        // FILETIME for 1970-01-01T00:00:00Z is exactly the epoch delta.
        assert_eq!(
            acquisition_ns_from_filetime(FILETIME_UNIX_EPOCH_DELTA),
            Some(0)
        );
    }

    #[test]
    fn filetime_known_instant_converts_correctly() {
        // 2023-11-14T22:13:20Z = 1_700_000_000 s since Unix epoch.
        // FILETIME = (1_700_000_000 + 11_644_473_600) * 10_000_000.
        let ft = (1_700_000_000u64 + 11_644_473_600) * 10_000_000;
        assert_eq!(
            acquisition_ns_from_filetime(ft),
            Some(1_700_000_000_000_000_000)
        );
    }

    #[test]
    fn filetime_zero_and_pre_epoch_yield_none() {
        assert_eq!(acquisition_ns_from_filetime(0), None);
        assert_eq!(
            acquisition_ns_from_filetime(FILETIME_UNIX_EPOCH_DELTA - 1),
            None
        );
    }

    // ── resolve_acquisition_ns priority order ────────────────────────────────

    #[test]
    fn resolve_prefers_system_time_then_mtime_then_placeholder() {
        let ft = (1_700_000_000u64 + 11_644_473_600) * 10_000_000;
        // system_time present → wins over mtime.
        let (ns, src) = resolve_acquisition_ns(Some(ft), Some(999));
        assert_eq!(ns, 1_700_000_000_000_000_000);
        assert_eq!(src, "dump system_time");

        // No system_time → mtime.
        let (ns, src) = resolve_acquisition_ns(None, Some(1_500_000_000_000_000_000));
        assert_eq!(ns, 1_500_000_000_000_000_000);
        assert_eq!(src, "file mtime");

        // A FILETIME of 0 is unusable → falls through to mtime.
        let (ns, src) = resolve_acquisition_ns(Some(0), Some(42));
        assert_eq!(ns, 42);
        assert_eq!(src, "file mtime");

        // Neither → documented placeholder, flagged.
        let (ns, src) = resolve_acquisition_ns(None, None);
        assert_eq!(ns, PLACEHOLDER_ACQ_NS);
        assert!(src.starts_with("placeholder"));
    }

    // ── ingest_memory_leg shell: no dumps → no-op, no panic ──────────────────

    #[test]
    fn ingest_memory_leg_with_no_dumps_is_a_clean_noop() {
        let store = TimelineStore::in_memory().expect("store");
        let dir = tempfile::tempdir().unwrap();
        let n = ingest_memory_leg(&store, dir.path());
        assert_eq!(n, 0, "no dumps → zero events, no error");
    }

    #[test]
    fn ingest_memory_leg_skips_unprofilable_dump_and_does_not_panic() {
        // A 4 KiB zero file is a "dump" by extension but has no kernel to
        // auto-profile, so build_reader errors — the shell logs and continues,
        // returning 0 rather than failing the correlate run.
        let store = TimelineStore::in_memory().expect("store");
        let dir = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(dir.path().join("bogus.mem")).unwrap();
        f.write_all(&[0u8; 4096]).unwrap();
        f.flush().unwrap();

        let n = ingest_memory_leg(&store, dir.path());
        assert_eq!(n, 0, "unprofilable dump is skipped, leg returns 0");
    }
}
