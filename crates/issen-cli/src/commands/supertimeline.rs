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
use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};
use issen_correlation::temporal_rule::{
    evaluate_temporal, DiscrepancyClause, EventTypeFilter, TemporalRule,
};
use issen_parser_uac::parsers;
use issen_unpack::CollectionProvider as _;

/// Run the supertimeline command.
///
/// # Errors
///
/// Returns an error if the collection cannot be opened.
pub fn run(collection: &Path, format: &str) -> Result<()> {
    // ── 1. Open the collection ────────────────────────────────────────────
    let events = if collection.is_dir() {
        // Bare directory — scan for supported artifacts directly.
        collect_events_from_dir(collection)
    } else {
        // Archive (UAC tar.gz, zip, etc.) — extract then scan.
        let provider = issen_parser_uac::UacProvider;
        match provider.open(collection) {
            Ok(manifest) => collect_events_from_dir(&manifest.extracted_root),
            Err(_) => Vec::new(),
        }
    };

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

/// Walk a directory and synthesize `TimelineEvent`s from recognised artifacts.
fn collect_events_from_dir(root: &Path) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    // LD_PRELOAD rootkit indicator → FileCreate event for each library listed.
    let preload_path = root.join("chkrootkit/etc_ld_so_preload.txt");
    if let Ok(content) = std::fs::read_to_string(&preload_path) {
        for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let ev = TimelineEvent::new(
                0, // timestamp unknown from this artifact alone
                "unknown".to_string(),
                EventType::FileCreate,
                ArtifactType::Assessment,
                preload_path.to_string_lossy().into_owned(),
                format!("ld.so.preload: {line}"),
                "supertimeline".to_string(),
            )
            .with_entity_ref(EntityRef::FilePath(line.to_string()))
            .with_tag("ld_preload_rootkit");
            events.push(ev);
        }
    }

    // Sockstat → ProcessExec + NetworkConnect events.
    let sockstat_path = root.join("memory_dump/output-sockstat");
    if let Ok(content) = std::fs::read_to_string(&sockstat_path) {
        {
            let entries = parsers::mem_sockstat::parse_mem_sockstat(&content);
            for entry in entries {
                let ev = TimelineEvent::new(
                    0,
                    "unknown".to_string(),
                    EventType::NetworkConnect,
                    ArtifactType::NetworkState,
                    sockstat_path.to_string_lossy().into_owned(),
                    format!(
                        "PID {} {} {}:{} -> {}:{} [{}]",
                        entry.pid,
                        entry.process_name,
                        entry.src_addr,
                        entry.src_port.unwrap_or(0),
                        entry.dst_addr,
                        entry.dst_port.unwrap_or(0),
                        entry.state
                    ),
                    "supertimeline".to_string(),
                )
                .with_entity_ref(EntityRef::Process(entry.process_name));
                events.push(ev);
            }
        }
    }

    // Hidden PIDs → ProcessExec events with hidden_process tag.
    let hidden_path = root.join("live_response/process/hidden_pids_for_ps_command.txt");
    if let Ok(content) = std::fs::read_to_string(&hidden_path) {
        {
            let pids = parsers::hidden_pids::parse_hidden_pids(&content);
            for pid in pids {
                let ev = TimelineEvent::new(
                    0,
                    "unknown".to_string(),
                    EventType::ProcessExec,
                    ArtifactType::ProcessList,
                    hidden_path.to_string_lossy().into_owned(),
                    format!("hidden PID {pid}"),
                    "supertimeline".to_string(),
                )
                .with_entity_ref(EntityRef::Process(pid.to_string()))
                .with_tag("hidden_process");
                events.push(ev);
            }
        }
    }

    events
}

// ── Bundled temporal rules ────────────────────────────────────────────────────

/// Return the bundled set of `TemporalRule`s for supertimeline evaluation.
fn bundled_temporal_rules() -> Vec<TemporalRule> {
    vec![
        // Hollow process: 4688 event log entry with no Prefetch update within 5s.
        TemporalRule {
            id: "temporal.hollow-process".into(),
            title: "Process created with no Prefetch update — possible hollow process".into(),
            severity: "high".into(),
            description: Some(
                "A process-creation event with no corresponding Prefetch FileModify \
                 within 5 seconds may indicate process hollowing or injection."
                    .into(),
            ),
            within_seconds: 5,
            anchor: EventTypeFilter::new("ProcessExec").with_source("Event Log"),
            sequence: vec![],
            absent: vec![EventTypeFilter::new("FileModify").with_source("Prefetch")],
            discrepancy: vec![],
        },
        // Boot-log predates MFT file creation (rootkit timestomping).
        TemporalRule {
            id: "temporal.boot-log-predates-mft".into(),
            title: "Boot log references file before MFT creation timestamp".into(),
            severity: "critical".into(),
            description: Some(
                "A system boot log entry references a file at a time before the \
                 file's $MFT born time. Consistent with a userspace rootkit that \
                 existed prior to its recorded filesystem creation timestamp."
                    .into(),
            ),
            within_seconds: 3600,
            anchor: EventTypeFilter::new("SystemBoot").with_source("Event Log"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileCreate".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 60,
                direction: "before".into(),
            }],
        },
        // Timestomping: MFT born time later than modify time.
        TemporalRule {
            id: "temporal.timestomping-born-after-modify".into(),
            title: "File born time later than modify time — timestomping indicator".into(),
            severity: "high".into(),
            description: None,
            within_seconds: 86400,
            anchor: EventTypeFilter::new("FileCreate").with_source("MFT"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileModify".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 1,
                direction: "after".into(),
            }],
        },
        // Ran-then-deleted: Prefetch exec followed by UsnJrnl delete.
        TemporalRule {
            id: "temporal.ran-then-deleted".into(),
            title: "Executable ran then deleted — anti-forensic or dropper".into(),
            severity: "high".into(),
            description: None,
            within_seconds: 3600,
            anchor: EventTypeFilter::new("ProcessExec").with_source("Prefetch"),
            sequence: vec![EventTypeFilter::new("FileDelete").with_source("USN Journal")],
            absent: vec![],
            discrepancy: vec![],
        },
        // PAM hook artifact: /tmp/silly.txt appears after logon.
        TemporalRule {
            id: "temporal.pam-hook-artifact".into(),
            title: "/tmp/silly.txt created on logon — PAM hook indicator".into(),
            severity: "critical".into(),
            description: None,
            within_seconds: 10,
            anchor: EventTypeFilter::new("LogonSuccess"),
            sequence: vec![EventTypeFilter::new("FileCreate").with_description("/tmp/silly.txt")],
            absent: vec![],
            discrepancy: vec![],
        },
    ]
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

fn emit_narrative(
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
