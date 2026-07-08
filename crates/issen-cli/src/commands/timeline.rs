use std::io;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use issen_core::timeline::event::TimelineEvent;
use issen_correlation::temporal_rule::{
    bundled_temporal_rules, evaluate_temporal, TemporalFinding,
};
use issen_timeline::findings;
use issen_timeline::query::{TimelineQuery, TimelineRow};
use issen_timeline::store::TimelineStore;
use issen_timeline::temporal::{render_at, Calendar, TimeRenderConfig};
use timeglyph::RenderZone;

use super::timeline_format;

/// Build a [`TimeRenderConfig`] from the CLI time-rendering flags.
///
/// Extracted so the flag→config translation is unit-testable without spawning
/// the CLI. Fails loud on an unknown timezone or an unrecognized calendar —
/// never a silent UTC / civil fallback.
///
/// - `tz`: `--timezone` spec (`""`/`"UTC"`/`"Z"` → UTC, `"+08:00"` → fixed
///   offset, `"America/New_York"` → IANA). An unknown zone is an error.
/// - `fmt`: optional `--time-format` jiff strftime pattern (`None` → RFC 3339).
/// - `calendar`: `"civil"` or `"lunisolar"`.
/// - `lon`: observer longitude east; only meaningful with `lunisolar`.
pub fn build_render_config(
    tz: &str,
    fmt: Option<&str>,
    calendar: &str,
    lon: Option<f64>,
) -> Result<TimeRenderConfig> {
    let zone = RenderZone::parse(tz).map_err(|e| anyhow!("invalid --timezone {tz:?}: {e}"))?;
    let calendar = match calendar {
        "civil" => Calendar::Civil,
        "lunisolar" => Calendar::Lunisolar(lon),
        other => {
            return Err(anyhow!(
                "invalid --calendar {other:?}: expected 'civil' or 'lunisolar'"
            ))
        }
    };
    Ok(TimeRenderConfig {
        zone,
        format: fmt.map(str::to_string),
        calendar,
    })
}

/// Run the timeline command: query events, show findings, or export.
#[allow(clippy::too_many_arguments)]
pub fn run(
    db_path: &Path,
    event_type: Option<&str>,
    source: Option<&str>,
    limit: u64,
    descending: bool,
    export_sqlite: Option<&Path>,
    flagged: bool,
    min_severity: &str,
    format: &str,
    narrative: bool,
    render_cfg: &TimeRenderConfig,
) -> Result<()> {
    let store = TimelineStore::open(db_path)
        .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

    // Handle --narrative: a pure view over the persisted DB — load events,
    // run the bundled temporal rules, emit the narrative. Never ingests.
    if narrative {
        return run_narrative(&store, db_path);
    }

    // Handle --flagged: show scan findings instead of timeline events.
    if flagged {
        return show_flagged(&store, min_severity, format);
    }

    // Handle SQLite export.
    if let Some(sqlite_path) = export_sqlite {
        let count = store
            .export_sqlite(sqlite_path)
            .context("Failed to export to SQLite")?;
        println!("Exported {count} events to {}", sqlite_path.display());
        return Ok(());
    }

    // Build query.
    let mut query = TimelineQuery::new().limit(limit);

    if let Some(et) = event_type {
        query = query.event_type(et);
    }
    if let Some(s) = source {
        query = query.source(s);
    }
    if descending {
        query = query.descending();
    }

    let rows = store.query(&query).context("Query failed")?;

    if format == "json" {
        let arr: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "timestamp": render_at(r.timestamp_ns, render_cfg),
                    "event_type": r.event_type,
                    "source": r.source,
                    "description": r.description,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }

    if format == "csv" {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        timeline_format::write_csv(&rows, render_cfg, &mut out).context("CSV export failed")?;
        return Ok(());
    }

    if format == "bodyfile" {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        timeline_format::write_bodyfile(&rows, &mut out).context("Bodyfile export failed")?;
        return Ok(());
    }

    if rows.is_empty() {
        println!("No events found.");
        return Ok(());
    }

    // Print events in a simple table format.
    println!(
        "{:<26} {:<16} {:<14} DESCRIPTION",
        "TIMESTAMP", "EVENT_TYPE", "SOURCE"
    );
    println!("{}", "-".repeat(80));

    for row in &rows {
        print_row(row, render_cfg);
    }

    println!("\n{} event(s) displayed.", rows.len());

    Ok(())
}

/// `--narrative`: render the temporal-rule narrative as a pure view over the
/// persisted DuckDB. Loads events, evaluates the bundled rules, and prints the
/// same narrative `supertimeline` emits — without re-parsing any evidence.
fn run_narrative(store: &TimelineStore, db_path: &Path) -> Result<()> {
    let (events, findings) = collect_narrative_findings(store)?;
    super::supertimeline::emit_narrative(&events, &findings, db_path);
    Ok(())
}

/// Load the persisted timeline and evaluate the bundled temporal rules over it.
///
/// The decision core of the `--narrative` view (Humble Object): it returns the
/// events and findings so it can be unit-tested without capturing stdout, while
/// [`run_narrative`] stays a thin load-evaluate-print shell.
fn collect_narrative_findings(
    store: &TimelineStore,
) -> Result<(Vec<TimelineEvent>, Vec<TemporalFinding>)> {
    let events = store
        .load_timeline_events()
        .context("Failed to load events from the timeline database")?;
    let rules = bundled_temporal_rules();
    let findings: Vec<TemporalFinding> = rules
        .iter()
        .flat_map(|rule| evaluate_temporal(rule, &events))
        .collect();
    Ok((events, findings))
}

/// Show scan findings from the scan_findings table.
fn show_flagged(store: &TimelineStore, min_severity: &str, format: &str) -> Result<()> {
    let conn = store.connection();

    // Ensure the table exists (it may not if no scanning was done).
    findings::create_findings_table(conn).context("Failed to access findings table")?;

    let severity_filter = if min_severity == "informational" {
        None
    } else {
        Some(min_severity)
    };

    let rows =
        findings::query_findings(conn, severity_filter).context("Failed to query findings")?;

    if format == "json" {
        return show_flagged_json(store, &rows);
    }

    if rows.is_empty() {
        println!("No scan findings found.");
        if severity_filter.is_some() {
            println!("Try lowering --min-severity to see more results.");
        }
        return Ok(());
    }

    // Show summary counts.
    let counts = findings::count_by_severity(conn).context("Failed to count findings")?;
    let total = findings::total_findings(conn).context("Failed to count total")?;

    println!("Scan findings: {total} total");
    for (sev, cnt) in &counts {
        println!("  {sev}: {cnt}");
    }
    println!();

    // Print findings table.
    println!(
        "{:<10} {:<10} {:<30} DESCRIPTION",
        "SEVERITY", "ENGINE", "RULE"
    );
    println!("{}", "-".repeat(90));

    for row in &rows {
        let desc = truncate_desc(&row.description);
        println!(
            "{:<10} {:<10} {:<30} {}",
            row.severity, row.engine, row.rule_name, desc
        );
    }

    println!("\n{} finding(s) displayed.", rows.len());

    Ok(())
}

/// Output scan findings as a JSON object.
fn show_flagged_json(store: &TimelineStore, rows: &[findings::FindingRow]) -> Result<()> {
    let conn = store.connection();
    let counts = findings::count_by_severity(conn).context("Failed to count findings")?;
    let total = findings::total_findings(conn).context("Failed to count total")?;

    // Build by_severity map.
    let by_severity: serde_json::Map<String, serde_json::Value> = counts
        .into_iter()
        .map(|(sev, cnt)| (sev, serde_json::Value::from(cnt)))
        .collect();

    // Build findings array, deserializing tags from JSON string to array.
    let findings_arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let tags: serde_json::Value = serde_json::from_str(&row.tags)
                .unwrap_or_else(|_| serde_json::Value::Array(vec![]));

            serde_json::json!({
                "evidence_source_id": row.evidence_source_id,
                "artifact_path": row.artifact_path,
                "engine": row.engine,
                "severity": row.severity,
                "rule_name": row.rule_name,
                "description": row.description,
                "matched_indicator": row.matched_indicator,
                "tags": tags,
            })
        })
        .collect();

    let output = serde_json::json!({
        "total": total,
        "by_severity": by_severity,
        "findings": findings_arr,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

/// Truncate `s` for display to at most 37 characters plus an ellipsis when it
/// exceeds 40. **Char-safe** — counts and slices by `char`, never by byte, so a
/// multi-byte UTF-8 filename (CJK, emoji, accented — routine in real evidence)
/// can never split a code point and panic.
fn truncate_desc(s: &str) -> String {
    if s.chars().count() > 40 {
        let head: String = s.chars().take(37).collect();
        format!("{head}...")
    } else {
        s.to_string()
    }
}

/// Human label for a stored event-type token. The timeline persists event types
/// as their `{:?}` round-trip token — e.g. `EventType::Other("MetadataChange")`
/// serializes to the literal `Other("MetadataChange")` (see
/// `EventType::from_debug_str`). That serialization form must never reach the
/// screen: unwrap the `Other(...)` wrapper to the parser's own name and drop the
/// Debug quotes, so a user sees `MetadataChange`, not `Other("MetadataChange")`.
fn clean_event_type(s: &str) -> &str {
    s.strip_prefix("Other(\"")
        .and_then(|r| r.strip_suffix("\")"))
        .or_else(|| s.strip_prefix("Other(").and_then(|r| r.strip_suffix(")")))
        .unwrap_or(s)
}

fn print_row(row: &TimelineRow, render_cfg: &TimeRenderConfig) {
    let desc = truncate_desc(&row.description);

    println!(
        "{:<26} {:<16} {:<14} {}",
        render_at(row.timestamp_ns, render_cfg),
        clean_event_type(&row.event_type),
        row.source,
        desc
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};
    use issen_timeline::store::TimelineStore;

    #[test]
    fn narrative_flags_hollow_process_pair() {
        // The narrative-over-DB view (issen #110 Phase 1) loads persisted
        // events and runs the bundled temporal rules. A 4688 process-creation
        // from the Event Log with NO Prefetch FileModify within 5s must fire
        // `temporal.hollow-process` — proving the view sees real DB events, not
        // a hardcoded file set.
        let store = TimelineStore::in_memory().expect("store");
        let exec = TimelineEvent::new(
            10_000_000_000,
            "2026-01-01T00:00:10Z".to_string(),
            EventType::ProcessExec,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            "evil.exe created (4688)".to_string(),
            "CASE-001".to_string(),
        );
        store.insert_batch(&[exec]).expect("ingest");

        let (events, findings) = collect_narrative_findings(&store).expect("narrative");
        assert_eq!(events.len(), 1, "one event ingested");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "temporal.hollow-process"),
            "expected temporal.hollow-process finding; got {:?}",
            findings
                .iter()
                .map(|f| f.rule_id.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn build_render_config_defaults_to_utc_civil() {
        let cfg = build_render_config("", None, "civil", None).expect("default config");
        assert!(
            matches!(cfg.zone, RenderZone::Utc),
            "empty --timezone must default to UTC, got {:?}",
            cfg.zone
        );
        assert!(cfg.format.is_none(), "default format is RFC 3339 (None)");
        assert!(
            matches!(cfg.calendar, Calendar::Civil),
            "default calendar is Civil"
        );
    }

    #[test]
    fn build_render_config_parses_named_zone() {
        let cfg = build_render_config("Asia/Tokyo", None, "civil", None).expect("named zone");
        assert!(
            matches!(cfg.zone, RenderZone::Named(_)),
            "Asia/Tokyo must resolve to a Named zone, got {:?}",
            cfg.zone
        );
    }

    #[test]
    fn build_render_config_rejects_unknown_zone() {
        let err = build_render_config("Mars/Olympus", None, "civil", None);
        assert!(
            err.is_err(),
            "an unknown zone must be a hard error, never a silent UTC fallback"
        );
    }

    #[test]
    fn build_render_config_lunisolar_with_longitude() {
        let cfg = build_render_config("Asia/Shanghai", None, "lunisolar", Some(120.0))
            .expect("lunisolar config");
        assert!(
            matches!(cfg.calendar, Calendar::Lunisolar(Some(l)) if (l - 120.0).abs() < 1e-9),
            "lunisolar + longitude must carry the observer longitude, got {:?}",
            cfg.calendar
        );
    }

    #[test]
    fn build_render_config_lunisolar_without_longitude_is_meridian_only() {
        let cfg =
            build_render_config("Asia/Shanghai", None, "lunisolar", None).expect("meridian-only");
        assert!(
            matches!(cfg.calendar, Calendar::Lunisolar(None)),
            "lunisolar with no --longitude is meridian-only, got {:?}",
            cfg.calendar
        );
    }

    #[test]
    fn build_render_config_rejects_unknown_calendar() {
        let err = build_render_config("", None, "mayan", None);
        assert!(
            err.is_err(),
            "an unknown --calendar value must be a hard, named error"
        );
    }

    // Regression: `issen timeline` panicked with "byte index N is not a char
    // boundary" when a description longer than 40 chars had a multi-byte UTF-8
    // char straddling byte 37 (routine for CJK/emoji/accented filenames in real
    // evidence). The old `&s[..37]` byte-slice crashed; `truncate_desc` must
    // slice by char and never panic.
    #[test]
    fn truncate_desc_is_char_safe_on_multibyte() {
        // 45 CJK chars (3 bytes each) — byte 37 lands mid-character.
        let cjk = "氀攀猀礀猀琀攀洀猀搀昀猀昀爀猀栀漀猀琀开㌀㄀戀昀㌀㠀愀戀挀搀攀昀最栀椀樀欀氀洀渀漀瀀焀爀猀琀"; // >40 chars
        let out = truncate_desc(cjk); // must not panic
        assert!(out.ends_with("..."), "long value is ellipsized");
        assert_eq!(out.chars().count(), 40, "37 kept chars + '...'");

        // Emoji (4-byte) straddling the boundary — also must not panic.
        let emoji = "malware_🦠_dropper_🔥_beacon_🧨_payload_💀_x_extra_tail_here";
        let _ = truncate_desc(emoji);

        // Short + ASCII pass through unchanged.
        assert_eq!(truncate_desc("short.txt"), "short.txt");
    }

    // Regression: the timeline persists event types as their `{:?}` token, so a
    // non-core type stored as `Other("MetadataChange")` was printed verbatim —
    // leaking Rust Debug syntax (wrapper + quotes) into the analyst's output.
    // The display must show the parser's clean name.
    #[test]
    fn clean_event_type_unwraps_the_debug_token() {
        assert_eq!(
            clean_event_type("Other(\"MetadataChange\")"),
            "MetadataChange"
        );
        assert_eq!(clean_event_type("Other(\"EventID:4672\")"), "EventID:4672");
        assert_eq!(clean_event_type("Other(MetadataChange)"), "MetadataChange"); // Display form
        assert_eq!(clean_event_type("FileCreate"), "FileCreate"); // core variant untouched
    }
}
