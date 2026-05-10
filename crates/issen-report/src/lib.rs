//! HTML report generator for `Issen`.
//!
//! Produces self-contained HTML reports from forensic timeline data stored
//! in a [`TimelineStore`](issen_timeline::store::TimelineStore). The report
//! includes summary statistics, a sortable events table, and a findings
//! section for scan results.

use std::fmt::Write as FmtWrite;
use std::path::Path;

pub mod mermaid;
pub mod misp;
pub mod pdf;
pub mod stix_output;
pub mod afb_output;
pub mod graphviz;
pub use pdf::export_pdf;
pub use misp::{MispEvent, MispAttribute, MispEventId, build_misp_event};
pub use stix_output::{StixBundle, findings_to_stix_bundle, write_stix_bundle};
pub use afb_output::{AfbDocument, AfbObject, AfbCamera, auto_layout_dag, findings_to_afb, write_afb};
pub use graphviz::{render_attack_chain_dot, render_attack_chain_png, render_mermaid_png};

pub use mermaid::{
    render_attack_chain, render_defenses,
    AttackChainInput, AttackChainNode, AttackChainEdge, AttackTactic,
    DefenseInput, DefenseItem, DefenseCategory,
};

use chrono::Utc;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during report generation.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// A `DuckDB` query failed.
    #[error("Database error: {0}")]
    Database(String),

    /// An I/O operation failed (e.g. writing the output file).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization / formatting failed.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<duckdb::Error> for ReportError {
    fn from(e: duckdb::Error) -> Self {
        Self::Database(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a report.
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Report title shown in the HTML header.
    pub title: String,
    /// Optional case identifier.
    pub case_id: Option<String>,
    /// Optional examiner name.
    pub examiner: Option<String>,
    /// Maximum number of events to include (default 10 000).
    pub max_events: Option<usize>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            title: "Issen Report".to_string(),
            case_id: None,
            examiner: None,
            max_events: Some(10_000),
        }
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A simplified event row for display in the report.
#[derive(Debug, Clone)]
pub struct EventRow {
    /// ISO-8601 timestamp string.
    pub timestamp: String,
    /// Event type label.
    pub event_type: String,
    /// Source artifact type label.
    pub source: String,
    /// Path of the artifact within the evidence.
    pub artifact_path: String,
    /// Human-readable description.
    pub description: String,
    /// Tags associated with the event.
    pub tags: Vec<String>,
}

/// Aggregate statistics for the report summary section.
#[derive(Debug, Clone)]
pub struct ReportSummary {
    /// Total number of events in the timeline.
    pub total_events: usize,
    /// Event counts grouped by source artifact type, sorted descending.
    pub events_by_source: Vec<(String, usize)>,
    /// Event counts grouped by event type, sorted descending.
    pub events_by_type: Vec<(String, usize)>,
    /// Earliest and latest timestamps (if any events exist).
    pub time_range: Option<(String, String)>,
    /// Total number of scan findings.
    pub total_findings: usize,
}

/// A scan finding row for display in the report.
#[derive(Debug, Clone)]
pub struct FindingRow {
    /// Scan engine (e.g. "YARA", "Sigma").
    pub engine: String,
    /// Name of the rule that matched.
    pub rule_name: String,
    /// Severity level (critical / high / medium / low / informational).
    pub severity: String,
    /// Target path or artifact that matched.
    pub target: String,
    /// Human-readable description of the finding.
    pub description: String,
}

/// All data needed to render a report.
#[derive(Debug, Clone)]
pub struct ReportData {
    /// Configuration used when collecting the report.
    pub config: ReportConfig,
    /// ISO-8601 timestamp of when the report was generated.
    pub generated_at: String,
    /// Event rows to display in the timeline table.
    pub events: Vec<EventRow>,
    /// Summary statistics.
    pub summary: ReportSummary,
    /// Scan findings to display (may be empty).
    pub findings: Vec<FindingRow>,
}

// ---------------------------------------------------------------------------
// Data collection
// ---------------------------------------------------------------------------

/// Collect report data from a [`TimelineStore`].
///
/// Queries the `DuckDB` database for events and (optionally) scan findings,
/// computes summary statistics, and returns everything packaged as
/// [`ReportData`] ready for rendering.
///
/// # Errors
///
/// Returns [`ReportError::Database`] if any SQL query fails.
#[allow(clippy::cast_possible_truncation)]
pub fn collect_repoissen_data(
    store: &issen_timeline::store::TimelineStore,
    config: ReportConfig,
) -> Result<ReportData, ReportError> {
    let conn = store.connection();
    let generated_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // --- Total event count ---------------------------------------------------
    let total_events: u64 = {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM timeline")?;
        stmt.query_row([], |row| row.get(0))?
    };
    let total_events = total_events as usize;

    // --- Events by source ----------------------------------------------------
    let events_by_source: Vec<(String, usize)> = {
        let mut stmt = conn.prepare(
            "SELECT source, COUNT(*) AS cnt FROM timeline GROUP BY source ORDER BY cnt DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let src: String = row.get(0)?;
            let cnt: u64 = row.get(1)?;
            Ok((src, cnt as usize))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    // --- Events by type ------------------------------------------------------
    let events_by_type: Vec<(String, usize)> = {
        let mut stmt = conn.prepare(
            "SELECT event_type, COUNT(*) AS cnt FROM timeline GROUP BY event_type ORDER BY cnt DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let et: String = row.get(0)?;
            let cnt: u64 = row.get(1)?;
            Ok((et, cnt as usize))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    // --- Time range ----------------------------------------------------------
    let time_range: Option<(String, String)> = if total_events > 0 {
        let mut stmt =
            conn.prepare("SELECT MIN(timestamp_display), MAX(timestamp_display) FROM timeline")?;
        stmt.query_row([], |row| {
            let min_ts: String = row.get(0)?;
            let max_ts: String = row.get(1)?;
            Ok(Some((min_ts, max_ts)))
        })?
    } else {
        None
    };

    // --- Event rows (limited) -----------------------------------------------
    let limit = config.max_events.unwrap_or(usize::MAX) as u64;
    let events: Vec<EventRow> = {
        let mut stmt = conn.prepare(
            "SELECT timestamp_display, event_type, source, artifact_path, description, tags
             FROM timeline
             ORDER BY timestamp_ns
             LIMIT ?",
        )?;
        let rows = stmt.query_map([limit], |row| {
            let tags_json: Option<String> = row.get(5)?;
            let tags: Vec<String> = tags_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            Ok(EventRow {
                timestamp: row.get(0)?,
                event_type: row.get(1)?,
                source: row.get(2)?,
                artifact_path: row.get(3)?,
                description: row.get(4)?,
                tags,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    // --- Findings (if table exists) ------------------------------------------
    let (findings, total_findings) = collect_findings(conn)?;

    // --- Assemble ------------------------------------------------------------
    let summary = ReportSummary {
        total_events,
        events_by_source,
        events_by_type,
        time_range,
        total_findings,
    };

    Ok(ReportData {
        config,
        generated_at,
        events,
        summary,
        findings,
    })
}

/// Attempt to read findings from the `scan_findings` table.
///
/// Returns an empty vec if the table does not exist.
#[allow(clippy::cast_possible_truncation)]
fn collect_findings(conn: &duckdb::Connection) -> Result<(Vec<FindingRow>, usize), ReportError> {
    // Check whether the table exists.
    let table_exists: bool = {
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'scan_findings'",
        )?;
        let count: u64 = stmt.query_row([], |row| row.get(0))?;
        count > 0
    };

    if !table_exists {
        return Ok((Vec::new(), 0));
    }

    let total: u64 = {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM scan_findings")?;
        stmt.query_row([], |row| row.get(0))?
    };

    let mut stmt = conn.prepare(
        "SELECT engine, rule_name, severity, artifact_path, description
         FROM scan_findings
         ORDER BY CASE severity
             WHEN 'critical' THEN 5
             WHEN 'high' THEN 4
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 2
             ELSE 1
         END DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(FindingRow {
            engine: row.get(0)?,
            rule_name: row.get(1)?,
            severity: row.get(2)?,
            target: row.get(3)?,
            description: row.get(4)?,
        })
    })?;

    let findings: Vec<FindingRow> = rows.collect::<Result<Vec<_>, _>>()?;

    Ok((findings, total as usize))
}

// ---------------------------------------------------------------------------
// HTML rendering
// ---------------------------------------------------------------------------

/// Escape a string for safe inclusion in HTML content.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Render [`ReportData`] to a self-contained HTML string.
///
/// The output includes inline CSS and JavaScript; no external resources are
/// referenced so the report can be viewed offline.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_html(data: &ReportData) -> String {
    let mut html = String::with_capacity(64 * 1024);

    // --- Head ----------------------------------------------------------------
    let _ = write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
    --bg: #1a1a2e;
    --surface: #16213e;
    --border: #0f3460;
    --text: #e0e0e0;
    --heading: #e94560;
    --accent: #0f3460;
    --link: #53a8b6;
    --severity-critical: #e94560;
    --severity-high: #ff6b35;
    --severity-medium: #f5a623;
    --severity-low: #7ecec1;
    --severity-info: #8899aa;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
}}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
header {{
    background: var(--surface);
    border-bottom: 3px solid var(--heading);
    padding: 24px 32px;
    margin-bottom: 24px;
}}
header h1 {{ color: var(--heading); font-size: 1.6rem; }}
header .meta {{ color: #8899aa; font-size: 0.85rem; margin-top: 6px; }}
section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 20px; margin-bottom: 20px; }}
section h2 {{ color: var(--heading); font-size: 1.2rem; margin-bottom: 14px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
.stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; }}
.stat-card {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 14px; text-align: center; }}
.stat-card .value {{ font-size: 1.8rem; font-weight: bold; color: var(--heading); }}
.stat-card .label {{ font-size: 0.8rem; color: #8899aa; text-transform: uppercase; letter-spacing: 0.5px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
th, td {{ padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ background: var(--bg); color: var(--heading); cursor: pointer; user-select: none; position: sticky; top: 0; }}
th:hover {{ background: var(--accent); }}
td {{ font-family: "SF Mono", "Fira Code", "Consolas", monospace; word-break: break-all; }}
.table-wrapper {{ max-height: 600px; overflow-y: auto; }}
.tag {{ display: inline-block; background: var(--accent); color: var(--text); padding: 1px 6px; border-radius: 3px; font-size: 0.72rem; margin: 1px 2px; }}
.severity-critical {{ color: var(--severity-critical); font-weight: bold; }}
.severity-high {{ color: var(--severity-high); font-weight: bold; }}
.severity-medium {{ color: var(--severity-medium); }}
.severity-low {{ color: var(--severity-low); }}
.severity-informational {{ color: var(--severity-info); }}
.breakdown {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
.breakdown-item {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 4px 10px; font-size: 0.82rem; }}
.breakdown-item .count {{ font-weight: bold; color: var(--heading); }}
footer {{ text-align: center; color: #556; font-size: 0.75rem; padding: 16px; }}
#filter {{ width: 100%; padding: 8px 12px; margin-bottom: 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text); font-size: 0.85rem; }}
</style>
</head>
<body>
"#,
        title = html_escape(&data.config.title),
    );

    // --- Header --------------------------------------------------------------
    let _ = write!(
        html,
        r#"<header>
<h1>{title}</h1>
<div class="meta">"#,
        title = html_escape(&data.config.title),
    );

    if let Some(ref case_id) = data.config.case_id {
        let _ = write!(html, "Case: {} &middot; ", html_escape(case_id));
    }
    if let Some(ref examiner) = data.config.examiner {
        let _ = write!(html, "Examiner: {} &middot; ", html_escape(examiner));
    }
    let _ = write!(
        html,
        "Generated: {}</div>\n</header>\n<div class=\"container\">\n",
        html_escape(&data.generated_at),
    );

    // --- Summary section -----------------------------------------------------
    render_summary(&mut html, &data.summary);

    // --- Events table --------------------------------------------------------
    render_events_table(&mut html, &data.events);

    // --- Findings section (only if findings exist) ---------------------------
    if !data.findings.is_empty() {
        render_findings_table(&mut html, &data.findings);
    }

    // --- Footer --------------------------------------------------------------
    let _ = write!(
        html,
        r"</div>
<footer>
Generated by Issen &middot; {generated}
</footer>
",
        generated = html_escape(&data.generated_at),
    );

    // --- Sort script ---------------------------------------------------------
    html.push_str(
        r"<script>
document.querySelectorAll('th[data-col]').forEach(th => {
    th.addEventListener('click', () => {
        const table = th.closest('table');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const col = parseInt(th.dataset.col, 10);
        const asc = th.dataset.dir !== 'asc';
        th.dataset.dir = asc ? 'asc' : 'desc';
        rows.sort((a, b) => {
            const at = a.children[col].textContent;
            const bt = b.children[col].textContent;
            return asc ? at.localeCompare(bt) : bt.localeCompare(at);
        });
        rows.forEach(r => tbody.appendChild(r));
    });
});
const filterInput = document.getElementById('filter');
if (filterInput) {
    filterInput.addEventListener('input', () => {
        const q = filterInput.value.toLowerCase();
        document.querySelectorAll('#events-tbody tr').forEach(r => {
            r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
    });
}
</script>
</body>
</html>
",
    );

    html
}

/// Render the summary section into the HTML buffer.
fn render_summary(html: &mut String, summary: &ReportSummary) {
    html.push_str("<section>\n<h2>Summary</h2>\n<div class=\"stat-grid\">\n");

    // Total events card
    let _ = writeln!(
        html,
        "<div class=\"stat-card\"><div class=\"value\">{}</div><div class=\"label\">Total Events</div></div>",
        summary.total_events,
    );

    // Total findings card
    let _ = writeln!(
        html,
        "<div class=\"stat-card\"><div class=\"value\">{}</div><div class=\"label\">Findings</div></div>",
        summary.total_findings,
    );

    // Time range card
    if let Some((ref start, ref end)) = summary.time_range {
        let _ = writeln!(
            html,
            "<div class=\"stat-card\"><div class=\"value\" style=\"font-size:0.9rem\">{} &mdash; {}</div><div class=\"label\">Time Range</div></div>",
            html_escape(start),
            html_escape(end),
        );
    }

    html.push_str("</div>\n");

    // Events by source breakdown
    if !summary.events_by_source.is_empty() {
        html.push_str("<h3 style=\"margin-top:14px;color:#e0e0e0;font-size:0.95rem\">Events by Source</h3>\n<div class=\"breakdown\">\n");
        for (source, count) in &summary.events_by_source {
            let _ = writeln!(
                html,
                "<div class=\"breakdown-item\">{} <span class=\"count\">{}</span></div>",
                html_escape(source),
                count,
            );
        }
        html.push_str("</div>\n");
    }

    // Events by type breakdown
    if !summary.events_by_type.is_empty() {
        html.push_str("<h3 style=\"margin-top:14px;color:#e0e0e0;font-size:0.95rem\">Events by Type</h3>\n<div class=\"breakdown\">\n");
        for (event_type, count) in &summary.events_by_type {
            let _ = writeln!(
                html,
                "<div class=\"breakdown-item\">{} <span class=\"count\">{}</span></div>",
                html_escape(event_type),
                count,
            );
        }
        html.push_str("</div>\n");
    }

    html.push_str("</section>\n");
}

/// Render the events table into the HTML buffer.
fn render_events_table(html: &mut String, events: &[EventRow]) {
    html.push_str("<section>\n<h2>Timeline Events</h2>\n");
    html.push_str("<input type=\"text\" id=\"filter\" placeholder=\"Filter events...\">\n");
    html.push_str("<div class=\"table-wrapper\">\n<table>\n<thead><tr>");

    let headers = ["Timestamp", "Type", "Source", "Path", "Description", "Tags"];
    for (i, hdr) in headers.iter().enumerate() {
        let _ = write!(html, "<th data-col=\"{i}\">{hdr}</th>");
    }
    html.push_str("</tr></thead>\n<tbody id=\"events-tbody\">\n");

    for ev in events {
        let tags_html: String = ev
            .tags
            .iter()
            .map(|t| format!("<span class=\"tag\">{}</span>", html_escape(t)))
            .collect::<Vec<_>>()
            .join(" ");

        let _ = writeln!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&ev.timestamp),
            html_escape(&ev.event_type),
            html_escape(&ev.source),
            html_escape(&ev.artifact_path),
            html_escape(&ev.description),
            tags_html,
        );
    }

    html.push_str("</tbody>\n</table>\n</div>\n</section>\n");
}

/// Render the findings table into the HTML buffer.
fn render_findings_table(html: &mut String, findings: &[FindingRow]) {
    html.push_str("<section>\n<h2>Scan Findings</h2>\n");
    html.push_str("<div class=\"table-wrapper\">\n<table>\n<thead><tr>");

    let headers = ["Engine", "Rule", "Severity", "Target", "Description"];
    for (i, hdr) in headers.iter().enumerate() {
        let _ = write!(html, "<th data-col=\"{i}\">{hdr}</th>");
    }
    html.push_str("</tr></thead>\n<tbody>\n");

    for f in findings {
        let sev_class = match f.severity.as_str() {
            "critical" => "severity-critical",
            "high" => "severity-high",
            "medium" => "severity-medium",
            "low" => "severity-low",
            _ => "severity-informational",
        };

        let _ = writeln!(
            html,
            "<tr><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&f.engine),
            html_escape(&f.rule_name),
            sev_class,
            html_escape(&f.severity),
            html_escape(&f.target),
            html_escape(&f.description),
        );
    }

    html.push_str("</tbody>\n</table>\n</div>\n</section>\n");
}

// ---------------------------------------------------------------------------
// Convenience: collect + render + write
// ---------------------------------------------------------------------------

/// Generate a self-contained HTML report and write it to a file.
///
/// This is a convenience wrapper that calls [`collect_repoissen_data`] followed
/// by [`render_html`] and writes the result to `output_path`.
///
/// # Errors
///
/// Returns [`ReportError::Database`] if querying the store fails, or
/// [`ReportError::Io`] if writing the output file fails.
pub fn generate_report(
    store: &issen_timeline::store::TimelineStore,
    config: ReportConfig,
    output_path: &Path,
) -> Result<(), ReportError> {
    let data = collect_repoissen_data(store, config)?;
    let html = render_html(&data);
    std::fs::write(output_path, html)?;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};
    use issen_timeline::findings;
    use issen_timeline::store::TimelineStore;

    // ---- Helpers ------------------------------------------------------------

    fn sample_event(ts_ns: i64, desc: &str, et: EventType, source: ArtifactType) -> TimelineEvent {
        TimelineEvent::new(
            ts_ns,
            format!("2023-11-14T22:13:20.{ts_ns:09}Z"),
            et,
            source,
            "C:/Users/analyst/report.docx".to_string(),
            desc.to_string(),
            "evidence-001".to_string(),
        )
    }

    fn make_store_with_events(events: &[TimelineEvent]) -> TimelineStore {
        let store = TimelineStore::in_memory().expect("create in-memory store");
        for ev in events {
            store.inseissen_event(ev).expect("insert event");
        }
        store
    }

    fn sample_repoissen_data(events: Vec<EventRow>, findings: Vec<FindingRow>) -> ReportData {
        let total_events = events.len();
        let total_findings = findings.len();

        let mut by_source: HashMap<String, usize> = HashMap::new();
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for ev in &events {
            *by_source.entry(ev.source.clone()).or_insert(0) += 1;
            *by_type.entry(ev.event_type.clone()).or_insert(0) += 1;
        }
        let mut events_by_source: Vec<(String, usize)> = by_source.into_iter().collect();
        events_by_source.sort_by(|a, b| b.1.cmp(&a.1));
        let mut events_by_type: Vec<(String, usize)> = by_type.into_iter().collect();
        events_by_type.sort_by(|a, b| b.1.cmp(&a.1));

        let time_range = if events.is_empty() {
            None
        } else {
            Some((
                events.first().expect("first event").timestamp.clone(),
                events.last().expect("last event").timestamp.clone(),
            ))
        };

        ReportData {
            config: ReportConfig::default(),
            generated_at: "2026-03-23T12:00:00Z".to_string(),
            events,
            summary: ReportSummary {
                total_events,
                events_by_source,
                events_by_type,
                time_range,
                total_findings,
            },
            findings,
        }
    }

    // ---- Tests --------------------------------------------------------------

    #[test]
    fn test_repoissen_config_default() {
        let cfg = ReportConfig::default();
        assert_eq!(cfg.title, "Issen Report");
        assert!(cfg.case_id.is_none());
        assert!(cfg.examiner.is_none());
        assert_eq!(cfg.max_events, Some(10_000));
    }

    #[test]
    fn test_render_html_empty() {
        let data = sample_repoissen_data(vec![], vec![]);
        let html = render_html(&data);

        assert!(
            html.contains("<!DOCTYPE html>"),
            "should start with doctype"
        );
        assert!(html.contains("</html>"), "should end with closing html tag");
        assert!(
            html.contains("Issen Report"),
            "should contain the title"
        );
        assert!(
            html.contains("Generated by Issen"),
            "should contain footer"
        );
        assert!(
            html.contains("Timeline Events"),
            "should contain events section header"
        );
        // With no findings, findings section should NOT appear
        assert!(
            !html.contains("Scan Findings"),
            "should not contain findings section when empty"
        );
    }

    #[test]
    fn test_render_html_with_events() {
        let events = vec![
            EventRow {
                timestamp: "2023-11-14T22:13:20Z".to_string(),
                event_type: "FileCreate".to_string(),
                source: "UsnJournal".to_string(),
                artifact_path: "C:/Users/analyst/report.docx".to_string(),
                description: "File created: report.docx".to_string(),
                tags: vec!["suspicious".to_string()],
            },
            EventRow {
                timestamp: "2023-11-14T22:14:00Z".to_string(),
                event_type: "LogonSuccess".to_string(),
                source: "EventLog".to_string(),
                artifact_path: "Security.evtx".to_string(),
                description: "Logon event for user ADMIN".to_string(),
                tags: vec![],
            },
        ];

        let data = sample_repoissen_data(events, vec![]);
        let html = render_html(&data);

        assert!(html.contains("File created: report.docx"));
        assert!(html.contains("Logon event for user ADMIN"));
        assert!(html.contains("UsnJournal"));
        assert!(html.contains("EventLog"));
        assert!(html.contains("FileCreate"));
        assert!(html.contains("LogonSuccess"));
        assert!(
            html.contains("<span class=\"tag\">suspicious</span>"),
            "should render tags"
        );
    }

    #[test]
    fn test_render_html_with_findings() {
        let findings = vec![
            FindingRow {
                engine: "YARA".to_string(),
                rule_name: "detect_malware".to_string(),
                severity: "critical".to_string(),
                target: "/evidence/malware.exe".to_string(),
                description: "Known malware signature matched".to_string(),
            },
            FindingRow {
                engine: "Sigma".to_string(),
                rule_name: "suspicious_login".to_string(),
                severity: "high".to_string(),
                target: "Security.evtx".to_string(),
                description: "Brute force login pattern".to_string(),
            },
        ];

        let data = sample_repoissen_data(vec![], findings);
        let html = render_html(&data);

        assert!(
            html.contains("Scan Findings"),
            "should contain findings section"
        );
        assert!(html.contains("detect_malware"));
        assert!(html.contains("suspicious_login"));
        assert!(html.contains("severity-critical"));
        assert!(html.contains("severity-high"));
        assert!(html.contains("Known malware signature matched"));
        assert!(html.contains("Brute force login pattern"));
    }

    #[test]
    fn test_event_row_from_timeline_event() {
        // Verify the conversion path used in collect_repoissen_data by inserting
        // an event into a store and reading it back as EventRow via collect.
        let ev = sample_event(
            1_700_000_000_000_000_000,
            "Test file created",
            EventType::FileCreate,
            ArtifactType::UsnJournal,
        )
        .with_tag("bookmarked");

        let store = make_store_with_events(&[ev]);
        let data =
            collect_repoissen_data(&store, ReportConfig::default()).expect("collect_repoissen_data");

        assert_eq!(data.events.len(), 1);
        let row = &data.events[0];
        assert_eq!(row.event_type, "FileCreate");
        assert_eq!(row.source, "UsnJournal");
        assert!(row.description.contains("Test file created"));
        assert_eq!(row.tags, vec!["bookmarked"]);
    }

    #[test]
    fn test_repoissen_summary_computation() {
        let events = vec![
            sample_event(
                1000,
                "Event A",
                EventType::FileCreate,
                ArtifactType::UsnJournal,
            ),
            sample_event(
                2000,
                "Event B",
                EventType::FileCreate,
                ArtifactType::UsnJournal,
            ),
            sample_event(
                3000,
                "Event C",
                EventType::LogonSuccess,
                ArtifactType::EventLog,
            ),
        ];

        let store = make_store_with_events(&events);
        let data =
            collect_repoissen_data(&store, ReportConfig::default()).expect("collect_repoissen_data");

        assert_eq!(data.summary.total_events, 3);
        assert_eq!(data.summary.total_findings, 0);

        // Time range should exist
        assert!(data.summary.time_range.is_some());

        // Check by-source counts
        let source_map: HashMap<&str, usize> = data
            .summary
            .events_by_source
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        assert_eq!(source_map.get("UsnJournal"), Some(&2));
        assert_eq!(source_map.get("EventLog"), Some(&1));

        // Check by-type counts
        let type_map: HashMap<&str, usize> = data
            .summary
            .events_by_type
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        assert_eq!(type_map.get("FileCreate"), Some(&2));
        assert_eq!(type_map.get("LogonSuccess"), Some(&1));
    }

    #[test]
    fn test_render_html_escapes_special_chars() {
        let events = vec![EventRow {
            timestamp: "2023-01-01T00:00:00Z".to_string(),
            event_type: "FileCreate".to_string(),
            source: "UsnJournal".to_string(),
            artifact_path: "C:/test.txt".to_string(),
            description: "<script>alert('XSS')</script> & \"quotes\"".to_string(),
            tags: vec!["tag<>".to_string()],
        }];

        let data = sample_repoissen_data(events, vec![]);
        let html = render_html(&data);

        // The raw dangerous characters must NOT appear unescaped.
        assert!(
            !html.contains("<script>alert"),
            "script tags must be escaped"
        );
        assert!(
            html.contains("&lt;script&gt;alert"),
            "should contain escaped script tag"
        );
        assert!(
            html.contains("&amp; &quot;quotes&quot;"),
            "should escape ampersand and quotes"
        );
        assert!(
            html.contains("tag&lt;&gt;"),
            "should escape tags in tag badges"
        );
    }

    #[test]
    fn test_html_escape_function() {
        assert_eq!(html_escape("hello"), "hello");
        assert_eq!(html_escape("<b>bold</b>"), "&lt;b&gt;bold&lt;/b&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("it's"), "it&#39;s");
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_collect_repoissen_data_empty_store() {
        let store = TimelineStore::in_memory().expect("create store");
        let data =
            collect_repoissen_data(&store, ReportConfig::default()).expect("collect_repoissen_data");

        assert_eq!(data.summary.total_events, 0);
        assert!(data.events.is_empty());
        assert!(data.findings.is_empty());
        assert!(data.summary.time_range.is_none());
    }

    #[test]
    fn test_collect_repoissen_data_with_findings() {
        let store = TimelineStore::in_memory().expect("create store");

        // Insert an event
        let ev = sample_event(1000, "Test event", EventType::FileCreate, ArtifactType::Mft);
        store.inseissen_event(&ev).expect("insert event");

        // Create findings table and insert findings
        findings::create_findings_table(store.connection()).expect("create findings table");
        let finding_rows = vec![issen_timeline::findings::FindingRow {
            evidence_source_id: "case-001".to_string(),
            artifact_path: "/evidence/malware.exe".to_string(),
            engine: "YARA".to_string(),
            severity: "critical".to_string(),
            rule_name: "detect_malware".to_string(),
            description: "Malware detected".to_string(),
            matched_indicator: Some("$bad_string".to_string()),
            tags: "[]".to_string(),
        }];
        findings::inseissen_findings(store.connection(), &finding_rows).expect("insert findings");

        let data =
            collect_repoissen_data(&store, ReportConfig::default()).expect("collect_repoissen_data");

        assert_eq!(data.summary.total_events, 1);
        assert_eq!(data.summary.total_findings, 1);
        assert_eq!(data.findings.len(), 1);
        assert_eq!(data.findings[0].engine, "YARA");
        assert_eq!(data.findings[0].rule_name, "detect_malware");
        assert_eq!(data.findings[0].severity, "critical");
    }

    #[test]
    fn test_collect_repoissen_data_max_events() {
        let store = TimelineStore::in_memory().expect("create store");

        // Insert 20 events
        for i in 0..20 {
            let ev = sample_event(
                i * 1_000_000_000,
                &format!("Event {i}"),
                EventType::FileCreate,
                ArtifactType::UsnJournal,
            );
            store.inseissen_event(&ev).expect("insert event");
        }

        // Limit to 5
        let config = ReportConfig {
            max_events: Some(5),
            ..ReportConfig::default()
        };
        let data = collect_repoissen_data(&store, config).expect("collect_repoissen_data");

        assert_eq!(data.events.len(), 5, "should respect max_events limit");
        assert_eq!(
            data.summary.total_events, 20,
            "summary should reflect total, not limited"
        );
    }

    #[test]
    fn test_generate_repoissen_writes_file() {
        let store = TimelineStore::in_memory().expect("create store");
        let ev = sample_event(
            1000,
            "File created",
            EventType::FileCreate,
            ArtifactType::Mft,
        );
        store.inseissen_event(&ev).expect("insert event");

        let dir = tempfile::tempdir().expect("create tmpdir");
        let output_path = dir.path().join("report.html");

        generate_report(&store, ReportConfig::default(), &output_path).expect("generate_report");

        assert!(output_path.exists(), "output file should exist");
        let contents = std::fs::read_to_string(&output_path).expect("read output file");
        assert!(contents.contains("<!DOCTYPE html>"));
        assert!(contents.contains("File created"));
    }

    #[test]
    fn test_render_html_config_metadata() {
        let data = ReportData {
            config: ReportConfig {
                title: "Case 42 Report".to_string(),
                case_id: Some("CASE-042".to_string()),
                examiner: Some("Jane Doe".to_string()),
                max_events: Some(10_000),
            },
            generated_at: "2026-03-23T12:00:00Z".to_string(),
            events: vec![],
            summary: ReportSummary {
                total_events: 0,
                events_by_source: vec![],
                events_by_type: vec![],
                time_range: None,
                total_findings: 0,
            },
            findings: vec![],
        };

        let html = render_html(&data);

        assert!(
            html.contains("Case 42 Report"),
            "should contain custom title"
        );
        assert!(html.contains("CASE-042"), "should contain case ID");
        assert!(html.contains("Jane Doe"), "should contain examiner name");
    }
}
