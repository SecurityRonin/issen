//! `issen correlate <case-dir>` — discover evidence, ingest the disk leg into
//! one timeline, run the cross-artifact correlation rules, and render a
//! "Correlated Findings" report (capstone task #37, plan v5 §7).
//!
//! This is a thin Humble-Object shell: the discovery/sequencing decisions and
//! the report rendering are pulled into testable free functions
//! ([`discover_evidence`], [`render_correlated_findings`]); `run` only wires
//! ingest → `run_and_persist` → print.
//!
//! The memory leg (Tier C) is intentionally out of scope here — the runner it
//! calls leaves an additive seam for memory-rule firings, so when that leg is
//! wired its correlations flow into the same report section unchanged.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use issen_correlation::correlation::Correlation;
use issen_timeline::store::TimelineStore;

/// Disk-image first-segment extensions. A split set (EWF `.E01/.E02…`, raw
/// `.001/.002…`) names only its FIRST segment here; the disk pipeline follows
/// the rest internally, so ingesting a later segment would double-crack the set.
/// Probing is by internal magic downstream (`open_collection`) — this list only
/// nominates candidate roots. `.mem`/`.raw`-memory dumps are excluded: they go
/// through the memory leg, not the disk pipeline.
const FIRST_SEGMENT_IMAGE_EXTS: &[&str] = &[
    "e01", "ex01", "001", "dd", "img", "vmdk", "vhd", "vhdx", "qcow2", "aff4", "iso",
];

/// True if `path` names a disk-image first segment we should ingest as a file.
fn is_disk_image_first_segment(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|ext| FIRST_SEGMENT_IMAGE_EXTS.contains(&ext.as_str()))
}

/// Recursively collect disk-image first-segment files under `dir`.
fn collect_disk_images(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // unreadable dir → contributes nothing, never panics
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_disk_images(&path, out);
        } else if is_disk_image_first_segment(&path) {
            out.push(path);
        }
    }
}

/// Discover the evidence root(s) to ingest under `case_dir`.
///
/// `run_auto` forks on its argument: a *file* is opened as a disk image /
/// collection (`run_collection_pipeline` → crack container → NTFS → artifacts),
/// while a *directory* is walked for already-extracted LOOSE artifacts. Handing
/// it the bare case dir therefore never cracks a nested `.E01` (the real-data
/// failure mode: 0 artifacts on the Case-001 DC image). So discovery returns the
/// disk-image first-segment file(s) under the case dir — each ingested as a file
/// — and falls back to the dir itself only when no image is present (the
/// loose-artifact / UAC-collection case the directory walk already handles).
#[must_use]
pub fn discover_evidence(case_dir: &Path) -> Vec<PathBuf> {
    let mut images = Vec::new();
    collect_disk_images(case_dir, &mut images);
    images.sort();
    if images.is_empty() {
        vec![case_dir.to_path_buf()]
    } else {
        images
    }
}

/// Format a nanosecond Unix timestamp as an RFC3339 UTC instant for display.
fn fmt_ns(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000) as u32;
    match Utc.timestamp_opt(secs, nanos).single() {
        Some(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => format!("{ns}ns"),
    }
}

/// Render the "Correlated Findings" report section for a set of correlations.
///
/// Pure and side-effect-free so the epistemics gate (plan v5 §7.5) can assert
/// over its text: every finding is narrated as an observation ("consistent
/// with"), never a verdict, and the section carries a tribunal footer handing
/// any legal conclusion back to the court.
#[must_use]
pub fn render_correlated_findings(correlations: &[Correlation]) -> String {
    let mut out = String::new();
    out.push_str("Correlated Findings\n");
    out.push_str("===================\n\n");

    if correlations.is_empty() {
        out.push_str(
            "No cross-artifact correlations fired. This is the absence of a matched \
             pattern, not evidence that no such activity occurred.\n\n",
        );
    } else {
        out.push_str(&format!(
            "{} correlation(s) — each is an observation that a set of timeline events \
             is consistent with a named behavior, never a verdict.\n\n",
            correlations.len()
        ));

        for (i, corr) in correlations.iter().enumerate() {
            out.push_str(&format!("[{}] {}\n", i + 1, corr.code));
            let attack = corr
                .attack_technique
                .as_deref()
                .map_or_else(|| "—".to_string(), ToString::to_string);
            out.push_str(&format!("    ATT&CK     : {attack}\n"));
            out.push_str(&format!("    Severity   : {}\n", corr.severity_str()));
            out.push_str(&format!(
                "    Time window: {} → {}\n",
                fmt_ns(corr.first_ts),
                fmt_ns(corr.last_ts)
            ));
            out.push_str(&format!("    Scope      : {}\n", corr.scope.as_str()));
            let members: Vec<String> = corr
                .members
                .iter()
                .map(|m| format!("#{} ({})", m.timeline_id, m.role.as_str()))
                .collect();
            out.push_str(&format!("    Members    : {}\n", members.join(", ")));
            out.push_str(&format!("    Assessment : {}\n\n", corr.note));
        }
    }

    out.push_str(
        "These findings are observations consistent with the behaviors named; they are \
         not legal conclusions. Whether the conduct they describe amounts to an offence, \
         breach, or intrusion is a matter for the tribunal — the Court may draw its own \
         conclusions.\n",
    );
    out
}

/// Run the correlate command: ingest the case dir, run + persist the disk-leg
/// correlations, and print the Correlated Findings report.
pub fn run(case_dir: &Path) -> Result<()> {
    let evidence_roots = discover_evidence(case_dir);
    let db_path = case_dir.join("correlate.duckdb");

    // Ingest each discovered disk image (or the loose-artifact dir) into the one
    // timeline DB, so cross-artifact rules join across every host's evidence.
    // Reuse the existing disk ingest — do not reimplement artifact parsing.
    for root in &evidence_roots {
        let source_id = root
            .file_stem()
            .and_then(|s| s.to_str())
            .map(ToString::to_string);
        crate::commands::ingest::run(
            root,
            &db_path,
            source_id.as_deref(),
            None,
            false,
            None,
            None,
            None,
            None,
        )
        .with_context(|| format!("ingesting evidence {}", root.display()))?;
    }

    let store = TimelineStore::open(&db_path)
        .with_context(|| format!("opening timeline database {}", db_path.display()))?;

    // Memory leg (Tier C): best-effort — discover and ingest any memory dumps in
    // the case dir into the same timeline so the cross-artifact rules can join
    // memory subjects against the disk leg. A missing or unprofilable dump is
    // logged and skipped inside the shell; it never fails the correlate run.
    crate::commands::correlate_mem::ingest_memory_leg(&store, case_dir);

    let correlations = store
        .run_and_persist()
        .context("running cross-artifact correlation rules")?;

    print!("{}", render_correlated_findings(&correlations));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::report::Severity;
    use issen_correlation::correlation::{Correlation, CorrelationMember, CorrelationRole};

    fn sample_findings() -> Vec<Correlation> {
        vec![
            Correlation::new("CORR-MALWARE-PERSIST", Severity::High)
                .with_attack_technique("T1543.003")
                .with_window(1_000_000_000, 2_000_000_000)
                .with_note(
                    "An executable file create followed by a service install naming that \
                     image is consistent with service-based persistence (T1543.003).",
                )
                .with_member(CorrelationMember::new(1, CorrelationRole::Anchor))
                .with_member(CorrelationMember::new(2, CorrelationRole::Consequent)),
            Correlation::new("CORR-BRUTEFORCE-LOGON", Severity::High)
                .with_attack_technique("T1110")
                .with_window(10_000_000_000, 16_000_000_000)
                .with_note(
                    "A failed-logon burst followed by a successful logon from the same \
                     source IP is consistent with a successful brute-force attempt (T1110).",
                )
                .with_member(CorrelationMember::new(7, CorrelationRole::Anchor))
                .with_member(CorrelationMember::new(8, CorrelationRole::Consequent)),
        ]
    }

    #[test]
    fn renders_each_finding_with_code_attack_severity_window_members() {
        let report = render_correlated_findings(&sample_findings());
        assert!(report.contains("Correlated Findings"));
        // Codes
        assert!(report.contains("CORR-MALWARE-PERSIST"));
        assert!(report.contains("CORR-BRUTEFORCE-LOGON"));
        // ATT&CK ids
        assert!(report.contains("T1543.003"));
        assert!(report.contains("T1110"));
        // Severity
        assert!(report.contains("high"));
        // Members (timeline ids + roles)
        assert!(report.contains("#1 (anchor)"));
        assert!(report.contains("#8 (consequent)"));
        // Time window rendered as instants
        assert!(report.contains("→"));
    }

    #[test]
    fn empty_findings_render_a_clean_absence_note() {
        let report = render_correlated_findings(&[]);
        assert!(report.contains("Correlated Findings"));
        assert!(report.contains("No cross-artifact correlations fired"));
        // Even with nothing fired, the tribunal footer is present.
        assert!(report.contains("the tribunal"));
    }

    /// Epistemics gate (plan v5 §7.5): the rendered report narrates findings as
    /// observations and hands legal conclusions to the tribunal — it must say
    /// "consistent with" and must never assert a verdict.
    #[test]
    fn rendered_report_is_hedged_and_carries_a_tribunal_footer() {
        let report = render_correlated_findings(&sample_findings()).to_ascii_lowercase();
        assert!(
            report.contains("consistent with"),
            "must hedge with 'consistent with'"
        );
        assert!(
            report.contains("the court may draw its own conclusions"),
            "must hand legal conclusions to the tribunal"
        );
        for forbidden in [
            "confirm",
            "prove",
            "proof",
            "exceed",
            "undoubtedly",
            "certainly",
        ] {
            assert!(
                !report.contains(forbidden),
                "report must not assert a verdict ({forbidden:?})"
            );
        }
    }

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(path, b"x").expect("write");
    }

    #[test]
    fn discover_evidence_finds_disk_image_first_segment() {
        // A raw EWF set: the first segment (.E01) is the ingest root; the disk
        // pipeline auto-follows .E02… internally, so we must NOT also ingest them.
        let dir = tempfile::tempdir().expect("tmpdir");
        touch(&dir.path().join("img.E01"));
        touch(&dir.path().join("img.E02"));
        let roots = discover_evidence(dir.path());
        assert_eq!(roots, vec![dir.path().join("img.E01")]);
    }

    #[test]
    fn discover_evidence_recurses_into_subdirs() {
        // Case-001 keeps the DC image in extracted/E01-DC01/ — discovery must
        // descend into subdirectories to find it.
        // .dd (not .raw — that extension is claimed by the memory leg) keeps
        // this a pure recursion check, free of the disk/memory ambiguity.
        let dir = tempfile::tempdir().expect("tmpdir");
        touch(&dir.path().join("E01-DC01").join("disk.dd"));
        let roots = discover_evidence(dir.path());
        assert_eq!(roots, vec![dir.path().join("E01-DC01").join("disk.dd")]);
    }

    #[test]
    fn discover_evidence_skips_sidecars_memory_dumps_and_trailing_segments() {
        let dir = tempfile::tempdir().expect("tmpdir");
        touch(&dir.path().join("img.E01"));
        touch(&dir.path().join("img.E02")); // trailing segment — not a root
        touch(&dir.path().join("img.E01.txt")); // sidecar metadata
        touch(&dir.path().join("citadeldc01.mem")); // memory leg, not disk
        let roots = discover_evidence(dir.path());
        assert_eq!(roots, vec![dir.path().join("img.E01")]);
    }

    #[test]
    fn discover_evidence_finds_multiple_images_sorted() {
        let dir = tempfile::tempdir().expect("tmpdir");
        touch(&dir.path().join("desktop.E01"));
        touch(&dir.path().join("E01-DC01").join("dc.E01"));
        let roots = discover_evidence(dir.path());
        assert_eq!(
            roots,
            vec![
                dir.path().join("E01-DC01").join("dc.E01"),
                dir.path().join("desktop.E01"),
            ]
        );
    }

    #[test]
    fn discover_evidence_falls_back_to_dir_when_no_images() {
        // A directory of loose, already-extracted artifacts (UAC/KAPE style):
        // no disk image present, so the dir itself is the ingest root and the
        // existing loose-artifact walk handles it.
        let dir = tempfile::tempdir().expect("tmpdir");
        touch(&dir.path().join("MFT"));
        touch(&dir.path().join("notes.txt"));
        let roots = discover_evidence(dir.path());
        assert_eq!(roots, vec![dir.path().to_path_buf()]);
    }
}
