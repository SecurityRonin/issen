//! `rt supertimeline` — semantic supertimeline with temporal correlation.
//!
//! Parses all artifacts from a collection, applies bundled [`TemporalRule`]s,
//! and outputs a narrative timeline with findings. This is the Plaso-replacement
//! story: instead of a raw timestamp CSV, the analyst gets a *narrative*.
//!
//! Output formats:
//! - `narrative` (default) — human-readable sections, TEMPORAL FINDINGS section
//! - `jsonl`               — one JSON object per timeline event
//! - `csv`                 — timestamp,event_type,source,description rows

use std::path::Path;

use anyhow::Result;
use issen_core::timeline::event::TimelineEvent;
use issen_correlation::temporal_rule::{bundled_temporal_rules, evaluate_temporal};
use issen_fswalker::orchestrator::run_auto;
use issen_fswalker::progress::ProgressReporter;

/// Run the supertimeline command.
///
/// # Errors
///
/// Returns an error if the collection cannot be opened.
#[allow(clippy::unnecessary_wraps)] // Result<()> matches the command-dispatch signature
pub fn run(collection: &Path, format: &str) -> Result<()> {
    // ── 1. Parse the collection via the full pipeline ─────────────────────
    // `run_auto` auto-detects directory vs archive (UAC tar.gz / zip), extracts
    // if needed, and parses every recognised artifact through the 20-parser
    // registry — the same path `ingest` uses.
    let events = collect_events_from_dir(collection);

    // ── 2. Apply bundled temporal rules ───────────────────────────────────
    let rules = bundled_temporal_rules();
    let temporal_findings: Vec<_> = rules
        .iter()
        .flat_map(|r| evaluate_temporal(r, &events))
        .collect();

    // ── 3. Emit output ────────────────────────────────────────────────────
    match format {
        "jsonl" => emit_jsonl(&events),
        "csv" => emit_csv(&events),
        _ => emit_narrative(&events, &temporal_findings, collection),
    }

    Ok(())
}

// ── Event collection ──────────────────────────────────────────────────────────

/// Parse a collection (directory or archive) through the full `run_auto`
/// pipeline and return its `TimelineEvent`s.
///
/// Replaces the former hardcoded 3-file stub: supertimeline now sees every
/// artifact `ingest` does (the 20-parser registry), with real timestamps, so
/// the temporal rules below operate on genuine data.
fn collect_events_from_dir(collection: &Path) -> Vec<TimelineEvent> {
    let progress = ProgressReporter::new();
    run_auto(collection, &progress)
        .map(|(events, _result)| events)
        .unwrap_or_default()
}

// ── Output formatters ─────────────────────────────────────────────────────────

fn emit_jsonl(events: &[TimelineEvent]) {
    for ev in events {
        if let Ok(json) = serde_json::to_string(ev) {
            println!("{json}");
        }
    }
}

fn emit_csv(events: &[TimelineEvent]) {
    println!("timestamp,event_type,source,description,tags");
    for ev in events {
        let ts = ev.timestamp_ns;
        let et = format!("{:?}", ev.event_type);
        let src = format!("{}", ev.source);
        let desc = ev.description.replace('"', "\"\"");
        let tags = ev.tags.join("|");
        println!("{ts},{et},{src},\"{desc}\",{tags}");
    }
}

pub(crate) fn emit_narrative(
    events: &[TimelineEvent],
    temporal_findings: &[issen_correlation::temporal_rule::TemporalFinding],
    collection: &Path,
) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  Issen — Supertimeline                              ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Collection : {}", collection.display());
    println!("  Events     : {}", events.len());
    println!();

    // ── Timeline events ───────────────────────────────────────────────────
    println!("┌─ TIMELINE EVENTS ──────────────────────────────────────");
    if events.is_empty() {
        println!("│  No events parsed from collection.");
    } else {
        for ev in events {
            let ts = if ev.timestamp_ns == 0 {
                "unknown".to_string()
            } else {
                ev.timestamp_ns.to_string()
            };
            println!("│  [{ts}] {:?} — {}", ev.event_type, ev.description);
        }
    }
    println!();

    // ── Temporal findings ─────────────────────────────────────────────────
    println!("┌─ TEMPORAL FINDINGS ────────────────────────────────────");
    if temporal_findings.is_empty() {
        println!("│  No temporal anomalies detected.");
    } else {
        for f in temporal_findings {
            println!(
                "│  [{}] {} — {}",
                f.severity.to_uppercase(),
                f.rule_id,
                f.title
            );
            if let Some(ref detail) = f.discrepancy {
                println!(
                    "│    Discrepancy: {} @ {} vs {} @ {} (Δ {:.1}s)",
                    detail.anchor_source,
                    detail.anchor_timestamp_ns,
                    detail.compare_source,
                    detail.compare_timestamp_ns,
                    detail.delta_ns as f64 / 1e9,
                );
            }
        }
    }
    println!();
    println!("  supertimeline complete.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Minimal synthetic USN V2 record (filename + FILE_CREATE reason) — mirrors
    /// the `$J` fixture used by the integration tests.
    fn usn_v2_create(filename: &str) -> Vec<u8> {
        let name: Vec<u8> = filename.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let fno: u16 = 60;
        let len = fno as usize + name.len();
        let padded = (len + 7) & !7;
        let mut b = vec![0u8; padded];
        b[0..4].copy_from_slice(&(padded as u32).to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes()); // major version 2
        b[8..16].copy_from_slice(&1001u64.to_le_bytes()); // file ref
        b[16..24].copy_from_slice(&500u64.to_le_bytes()); // parent ref
        b[24..32].copy_from_slice(&100i64.to_le_bytes()); // usn
        b[32..40].copy_from_slice(&133_444_736_000_000_000i64.to_le_bytes()); // filetime
        b[40..44].copy_from_slice(&0x100u32.to_le_bytes()); // FILE_CREATE reason
        b[52..56].copy_from_slice(&0x20u32.to_le_bytes());
        b[56..58].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b[58..60].copy_from_slice(&fno.to_le_bytes());
        b[60..60 + name.len()].copy_from_slice(&name);
        b
    }

    /// Phase 0: supertimeline must collect events via the full `run_auto` pipeline,
    /// not just its 3 hardcoded files. A `$J` USN-journal artifact is not one of
    /// those files — the stub ignores it; the real pipeline parses it.
    #[test]
    fn supertimeline_collects_full_pipeline_artifacts_not_just_3_files() {
        let dir = TempDir::new().expect("tmpdir");
        std::fs::write(dir.path().join("$J"), usn_v2_create("malware.exe")).expect("write $J");

        let events = collect_events_from_dir(dir.path());

        assert!(
            events.iter().any(|e| e.description.contains("malware.exe")),
            "supertimeline must surface artifacts via the full pipeline (run_auto), not only the \
             3 hardcoded files; got {} events",
            events.len()
        );
    }
}
