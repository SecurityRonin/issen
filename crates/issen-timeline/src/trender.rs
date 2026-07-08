//! One renderer for all typed-query output (Humble Object).
//!
//! The verbs decide *what* to ask ([`crate::tquery`]); this module decides *how*
//! to render — `text` or `json` — so both behave identically. Output is
//! attacker-controlled evidence, so every emitted string is sanitized through
//! `jsonguard` — `tsv_safe` neutralizes CSV/TSV formula injection (a leading
//! `=`/`+`/`-`/`@`) plus control/bidi in the tab-separated cells, `display_safe`
//! strips control/bidi from the provenance/JSON strings — and `json` also goes
//! through `serde_json`'s correct escaping rather than hand-built strings.

use jsonguard::{display_safe, tsv_safe};

use crate::tquery::QueryResult;

/// A self-describing provenance header attached to every result.
#[derive(Debug, Clone)]
pub struct Provenance {
    /// The case DB path the query ran against.
    pub db_path: String,
    /// One human-readable line per filter applied (e.g. `event-type=LogonSuccess`).
    pub filters: Vec<String>,
}

/// Render to plain text: a provenance line, the column headers, the rows, and
/// any empty-vs-absent diagnostic.
#[must_use]
pub fn render_text(result: &QueryResult, prov: &Provenance) -> String {
    let mut out = String::new();
    out.push_str(&format!("# db: {}\n", display_safe(prov.db_path.as_str())));
    if prov.filters.is_empty() {
        out.push_str("# filters: (none)\n");
    } else {
        let joined: Vec<String> = prov
            .filters
            .iter()
            .map(|f| display_safe(f.as_str()).to_string())
            .collect();
        out.push_str(&format!("# filters: {}\n", joined.join(" AND ")));
    }
    out.push_str(&format!("# rows: {}\n", result.row_count));

    let headers: Vec<&str> = result.columns.iter().map(|c| c.name.as_str()).collect();
    if !headers.is_empty() {
        out.push_str(&headers.join("\t"));
        out.push('\n');
        for i in 0..result.row_count {
            let cells: Vec<String> = result
                .columns
                .iter()
                .map(|c| tsv_safe(c.values.get(i).map_or("", |v| v.as_str())).to_string())
                .collect();
            out.push_str(&cells.join("\t"));
            out.push('\n');
        }
    }

    out.push_str(&empty_vs_absent(result));
    out
}

/// Render to JSON via `serde_json` (correct escaping by construction). Shape:
/// `{ "db", "filters", "row_count", "rows": [ {col: val, …} ], "field_coverage": {field: bool} }`.
#[must_use]
pub fn render_json(result: &QueryResult, prov: &Provenance) -> String {
    let rows: Vec<serde_json::Value> = (0..result.row_count)
        .map(|i| {
            let mut obj = serde_json::Map::new();
            for c in &result.columns {
                obj.insert(
                    c.name.clone(),
                    serde_json::Value::String(
                        display_safe(c.values.get(i).map_or("", |v| v.as_str())).to_string(),
                    ),
                );
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    let coverage: serde_json::Map<String, serde_json::Value> = result
        .field_populated
        .iter()
        .map(|(name, present)| (name.clone(), serde_json::Value::Bool(*present)))
        .collect();

    let value = serde_json::json!({
        "db": prov.db_path,
        "filters": prov.filters,
        "row_count": result.row_count,
        "rows": rows,
        "field_coverage": coverage,
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

/// The empty != absent diagnostic: when a result has zero rows but a filtered
/// field was never populated by any ingested source, say so explicitly.
fn empty_vs_absent(result: &QueryResult) -> String {
    let mut out = String::new();
    if result.row_count == 0 {
        for (field, present) in &result.field_populated {
            if *present {
                out.push_str(&format!(
                    "# note: 0 matches, but field '{field}' IS populated in this case (genuine empty result)\n"
                ));
            } else {
                out.push_str(&format!(
                    "# warning: field '{field}' was NEVER populated by any ingested source — \
                     0 rows means COVERAGE GAP, not a clean finding\n"
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tquery::Column;

    fn result_with(rows: usize, columns: Vec<Column>, fp: Vec<(String, bool)>) -> QueryResult {
        QueryResult {
            columns,
            row_count: rows,
            field_populated: fp,
        }
    }

    #[test]
    fn render_neutralises_bidi_and_control() {
        let r = result_with(
            1,
            vec![Column {
                name: "x".into(),
                values: vec!["ab\u{202E}cd\u{0007}ef".into()],
            }],
            vec![],
        );
        let prov = Provenance {
            db_path: "x.duckdb".into(),
            filters: vec![],
        };
        let out = render_text(&r, &prov);
        assert!(!out.contains('\u{202E}'), "bidi override survived: {out:?}");
        assert!(!out.contains('\u{0007}'), "control char survived: {out:?}");
        assert!(out.contains("abcdef"));
    }

    #[test]
    fn text_render_neutralises_csv_formula_injection() {
        let r = result_with(
            1,
            vec![Column {
                name: "app".into(),
                values: vec!["=SUM(1+1)".into()],
            }],
            vec![],
        );
        let prov = Provenance {
            db_path: "x.duckdb".into(),
            filters: vec![],
        };
        let out = render_text(&r, &prov);
        // A cell that opens with a formula sigil must be prefixed so a spreadsheet
        // opening the TSV cannot execute it.
        assert!(
            out.contains("'=SUM(1+1)"),
            "formula injection not neutralised: {out}"
        );
    }

    #[test]
    fn text_render_carries_provenance_and_rows() {
        let r = result_with(
            1,
            vec![Column {
                name: "count".into(),
                values: vec!["42".into()],
            }],
            vec![],
        );
        let prov = Provenance {
            db_path: "dc01.duckdb".into(),
            filters: vec!["event-type=LogonSuccess".into()],
        };
        let text = render_text(&r, &prov);
        assert!(text.contains("# db: dc01.duckdb"));
        assert!(text.contains("event-type=LogonSuccess"));
        assert!(text.contains("# rows: 1"));
        assert!(text.contains("42"));
    }

    #[test]
    fn empty_result_distinguishes_populated_from_absent_field() {
        // 0 rows + field present ⇒ genuine empty; 0 rows + field absent ⇒ gap.
        let present = result_with(0, vec![], vec![("ip".into(), true)]);
        let absent = result_with(0, vec![], vec![("service".into(), false)]);
        let prov = Provenance {
            db_path: "x".into(),
            filters: vec![],
        };
        assert!(render_text(&present, &prov).contains("genuine empty result"));
        assert!(render_text(&absent, &prov).contains("COVERAGE GAP"));
    }

    // Split display from serialization. The text/TSV view is for humans: a
    // non-core event type persisted as its round-trip Debug token
    // `Other("EventID:4672")` must display as the clean name `EventID:4672`.
    // The JSON view is a machine / re-import stream and must keep the token
    // verbatim so it round-trips through `EventType::from_debug_str`.
    #[test]
    fn event_type_humanized_in_text_but_token_kept_in_json() {
        let r = result_with(
            2,
            vec![Column {
                name: "event_type".into(),
                values: vec!["Other(\"EventID:4672\")".into(), "FileCreate".into()],
            }],
            vec![],
        );
        let prov = Provenance {
            db_path: "x".into(),
            filters: vec![],
        };

        let text = render_text(&r, &prov);
        assert!(text.contains("EventID:4672"), "human label missing: {text}");
        assert!(
            !text.contains("Other("),
            "raw Debug token leaked into the human text view: {text}"
        );
        assert!(
            text.contains("FileCreate"),
            "a core variant must pass through unchanged: {text}"
        );

        let json = render_json(&r, &prov);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(
            parsed["rows"][0]["event_type"], "Other(\"EventID:4672\")",
            "the machine/JSON stream must keep the round-trip token"
        );
    }

    #[test]
    fn json_render_is_valid_and_escaped() {
        let r = result_with(
            1,
            vec![Column {
                name: "user".into(),
                values: vec!["a\"b".into()],
            }],
            vec![("user".into(), true)],
        );
        let prov = Provenance {
            db_path: "x".into(),
            filters: vec![],
        };
        let json = render_json(&r, &prov);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["rows"][0]["user"], "a\"b");
        assert_eq!(parsed["field_coverage"]["user"], true);
    }
}
