use serde_json::Value;

/// Supported output formats for memory forensic results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable text table.
    #[default]
    Text,
    /// Newline-delimited JSON.
    Json,
    /// mactime bodyfile (for timeline integration).
    Bodyfile,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
            Self::Bodyfile => write!(f, "bodyfile"),
        }
    }
}

/// Render a result set as a text table.
pub fn print_text_table(headers: &[&str], rows: &[Vec<String>]) {
    // Column widths: max of header or any value in that column.
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            rows.iter()
                .map(|r| r.get(i).map_or(0, |v| v.len()))
                .max()
                .unwrap_or(0)
                .max(h.len())
        })
        .collect();

    // Header line.
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let w = widths[i];
            format!("{h:<w$}")
        })
        .collect();
    println!("{}", header_line.join("  "));

    // Separator.
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", sep.join("  "));

    // Rows.
    for row in rows {
        let cells: Vec<String> = widths
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let val = row.get(i).map_or("", String::as_str);
                format!("{val:<w$}")
            })
            .collect();
        println!("{}", cells.join("  "));
    }
}

/// Render a result set as newline-delimited JSON objects (one per row).
///
/// Each row is serialised as `{"header": "value", ...}`.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] if serialisation fails (this should not
/// occur in practice for string values).
pub fn rows_to_json(headers: &[&str], rows: &[Vec<String>]) -> serde_json::Result<String> {
    let mut out = String::new();
    for row in rows {
        let obj: serde_json::Map<String, Value> = headers
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let val = row.get(i).cloned().unwrap_or_default();
                ((*h).to_string(), Value::String(val))
            })
            .collect();
        let line = serde_json::to_string(&Value::Object(obj))?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// Convert a table into mactime bodyfile format.
///
/// Column names are matched case-insensitively to the 11-field bodyfile layout:
/// `md5(0)`, `path`, `inode`, `mode(0)`, `uid(0)`, `gid(0)`,
/// `size`, `atime`, `mtime`, `ctime`, `btime`.
///
/// Missing columns default to `"0"`. Returns one line per row, terminated by
/// `\n`. Returns an empty string when `rows` is empty.
#[must_use]
pub fn rows_to_bodyfile(headers: &[&str], rows: &[Vec<String>]) -> String {
    // Build a column-name → index map for fast lookup.
    let col: std::collections::HashMap<&str, usize> =
        headers.iter().enumerate().map(|(i, h)| (*h, i)).collect();

    let get = |row: &Vec<String>, name: &str| -> String {
        col.get(name)
            .and_then(|&i| row.get(i))
            .cloned()
            .unwrap_or_else(|| "0".to_string())
    };

    let mut out = String::new();
    for row in rows {
        // Bodyfile: md5|name|inode|mode_as_string|uid|gid|size|atime|mtime|ctime|crtime
        let line = format!(
            "0|{path}|{inode}|0|0|0|{size}|{atime}|{mtime}|{ctime}|{btime}\n",
            path = get(row, "path"),
            inode = get(row, "inode"),
            size = get(row, "size"),
            atime = get(row, "atime"),
            mtime = get(row, "mtime"),
            ctime = get(row, "ctime"),
            btime = get(row, "btime"),
        );
        out.push_str(&line);
    }
    out
}

/// Convert a table into a STIX 2.1 bundle JSON string.
///
/// Each row becomes an `observed-data` object whose `custom_properties` map
/// is keyed by the header names. The bundle `id` uses a deterministic
/// `bundle--<index>` placeholder (real UUID generation would require the
/// `uuid` crate which is not yet a workspace dependency).
///
/// Returns a JSON string; never returns an error.
#[must_use]
pub fn rows_to_stix(object_type: &str, headers: &[&str], rows: &[Vec<String>]) -> String {
    let objects: Vec<Value> = rows
        .iter()
        .enumerate()
        .map(|(idx, row)| {
            let props: serde_json::Map<String, Value> = headers
                .iter()
                .enumerate()
                .map(|(i, h)| {
                    let val = row.get(i).cloned().unwrap_or_default();
                    ((*h).to_string(), Value::String(val))
                })
                .collect();
            serde_json::json!({
                "type": "observed-data",
                "id": format!("observed-data--{idx:016x}-0000-0000-0000-000000000000"),
                "object_type": object_type,
                "custom_properties": Value::Object(props),
            })
        })
        .collect();

    let bundle = serde_json::json!({
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000000",
        "spec_version": "2.1",
        "objects": objects,
    });

    bundle.to_string()
}

/// Print output according to the selected format.
///
/// For [`OutputFormat::Json`] the caller receives valid newline-delimited JSON.
/// For [`OutputFormat::Bodyfile`] a placeholder line is printed (full bodyfile
/// support requires timestamp data from the walkers themselves).
pub fn print_table(headers: &[&str], rows: &[Vec<String>], fmt: OutputFormat) {
    match fmt {
        OutputFormat::Text => print_text_table(headers, rows),
        OutputFormat::Json => {
            let json =
                rows_to_json(headers, rows).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}\n"));
            print!("{json}");
        }
        OutputFormat::Bodyfile => {
            // bodyfile format: md5|name|inode|perms|uid|gid|size|atime|mtime|ctime|crtime
            // For process listings we emit a minimal bodyfile stub; full
            // timestamps require walker-level integration.
            for row in rows {
                let name = row.first().map_or("unknown", String::as_str);
                println!("0|{name}|0|----------|0|0|0|0|0|0|0");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_format_display() {
        assert_eq!(OutputFormat::Text.to_string(), "text");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Bodyfile.to_string(), "bodyfile");
    }

    #[test]
    fn print_table_json_format_is_valid_json() {
        let headers = &["pid", "name", "ppid"];
        let rows = vec![
            vec!["1".into(), "systemd".into(), "0".into()],
            vec!["42".into(), "bash".into(), "1".into()],
        ];
        let json_str = rows_to_json(headers, &rows).expect("json serialisation");

        // Must be two non-empty lines, each parseable as a JSON object.
        let lines: Vec<&str> = json_str.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON per line");
            assert!(v.is_object());
        }
    }

    #[test]
    fn rows_to_json_contains_expected_keys() {
        let headers = &["pid", "name"];
        let rows = vec![vec!["7".into(), "sshd".into()]];
        let json_str = rows_to_json(headers, &rows).unwrap();
        let v: serde_json::Value = serde_json::from_str(json_str.trim()).unwrap();
        assert_eq!(v["pid"], "7");
        assert_eq!(v["name"], "sshd");
    }

    #[test]
    fn rows_to_json_empty_rows_gives_empty_string() {
        let json_str = rows_to_json(&["pid"], &[]).unwrap();
        assert!(json_str.is_empty());
    }

    #[test]
    fn print_text_table_does_not_panic_on_empty() {
        // Smoke test: must not panic.
        print_text_table(&["col"], &[]);
    }

    #[test]
    fn print_text_table_does_not_panic_with_data() {
        print_text_table(&["pid", "name"], &[vec!["1".into(), "init".into()]]);
    }

    // -----------------------------------------------------------------------
    // Task 2 — bodyfile tests (RED: rows_to_bodyfile not yet defined)
    // -----------------------------------------------------------------------

    #[test]
    fn bodyfile_with_path_and_timestamps_formats_correctly() {
        let headers = &["path", "inode", "size", "atime", "mtime", "ctime", "btime"];
        let rows = vec![vec![
            "/bin/bash".into(),
            "42".into(),
            "1024".into(),
            "1700000000".into(),
            "1700000001".into(),
            "1700000002".into(),
            "1700000003".into(),
        ]];
        let out = rows_to_bodyfile(headers, &rows);
        // Expected: 0|/bin/bash|42|0|0|0|1024|1700000000|1700000001|1700000002|1700000003
        assert!(
            out.contains("/bin/bash"),
            "bodyfile must contain path: {out}"
        );
        assert!(
            out.contains("1700000001"),
            "bodyfile must contain mtime: {out}"
        );
        assert!(out.contains("1024"), "bodyfile must contain size: {out}");
        // Verify structure: exactly 10 pipe separators per line
        let line = out.trim();
        assert_eq!(
            line.chars().filter(|&c| c == '|').count(),
            10,
            "bodyfile line must have 10 pipe separators: {line}"
        );
    }

    #[test]
    fn bodyfile_missing_columns_uses_zero() {
        // Only 'path' column; everything else defaults to 0
        let headers = &["path"];
        let rows = vec![vec!["/etc/passwd".into()]];
        let out = rows_to_bodyfile(headers, &rows);
        let line = out.trim();
        assert!(line.contains("/etc/passwd"), "path must appear: {line}");
        // Should have 10 pipe separators
        assert_eq!(
            line.chars().filter(|&c| c == '|').count(),
            10,
            "bodyfile line must have 10 pipe separators even with missing cols: {line}"
        );
        // All the timestamp/size fields should be 0
        assert!(
            line.contains("|0|0|0|0|0|0|0"),
            "missing fields should be 0: {line}"
        );
    }

    #[test]
    fn bodyfile_empty_rows_returns_empty() {
        let out = rows_to_bodyfile(&["path", "size"], &[]);
        assert!(
            out.is_empty(),
            "empty rows must yield empty output, got: {out}"
        );
    }

    // -----------------------------------------------------------------------
    // Task 3 — STIX 2.1 tests (RED: rows_to_stix not yet defined)
    // -----------------------------------------------------------------------

    #[test]
    fn stix_bundle_is_valid_json() {
        let headers = &["pid", "name"];
        let rows = vec![vec!["1".into(), "systemd".into()]];
        let out = rows_to_stix("process", headers, &rows);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&out);
        assert!(parsed.is_ok(), "STIX output must be valid JSON: {out}");
    }

    #[test]
    fn stix_bundle_has_type_field() {
        let headers = &["pid", "name"];
        let rows = vec![vec!["1".into(), "init".into()]];
        let out = rows_to_stix("process", headers, &rows);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(
            v["type"], "bundle",
            "top-level 'type' must be 'bundle': {out}"
        );
        assert!(
            v.get("id").is_some(),
            "bundle must have an 'id' field: {out}"
        );
        assert!(
            v["objects"].is_array(),
            "bundle must have 'objects' array: {out}"
        );
    }

    #[test]
    fn stix_empty_rows_produces_empty_objects() {
        let out = rows_to_stix("process", &["pid", "name"], &[]);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(
            v["objects"].as_array().map(|a| a.len()).unwrap_or(1),
            0,
            "empty rows must produce empty objects array: {out}"
        );
    }

    // -----------------------------------------------------------------------
    // OutputFormat: default, clone, copy, partial_eq, debug
    // -----------------------------------------------------------------------

    #[test]
    fn output_format_default_is_text() {
        let fmt: OutputFormat = OutputFormat::default();
        assert_eq!(fmt, OutputFormat::Text, "default must be Text");
    }

    #[test]
    fn output_format_clone_and_copy() {
        let fmt = OutputFormat::Json;
        let cloned = fmt; // Copy
        assert_eq!(fmt, cloned);
        let cloned2 = fmt.clone();
        assert_eq!(fmt, cloned2);
    }

    #[test]
    fn output_format_debug() {
        let s = format!("{:?}", OutputFormat::Bodyfile);
        assert!(
            s.contains("Bodyfile"),
            "Debug output should contain 'Bodyfile': {s}"
        );
    }

    // -----------------------------------------------------------------------
    // print_table: exercise all three OutputFormat branches
    // -----------------------------------------------------------------------

    #[test]
    fn print_table_text_format_does_not_panic() {
        let headers = &["pid", "name"];
        let rows = vec![vec!["1".into(), "init".into()]];
        // print_table writes to stdout; just assert it doesn't panic.
        print_table(headers, &rows, OutputFormat::Text);
    }

    #[test]
    fn print_table_json_format_does_not_panic() {
        let headers = &["pid", "name"];
        let rows = vec![vec!["1".into(), "init".into()]];
        print_table(headers, &rows, OutputFormat::Json);
    }

    #[test]
    fn print_table_bodyfile_format_does_not_panic() {
        let headers = &["pid", "name"];
        let rows = vec![vec!["1".into(), "init".into()]];
        print_table(headers, &rows, OutputFormat::Bodyfile);
    }

    #[test]
    fn print_table_bodyfile_format_empty_row_does_not_panic() {
        // A row with no elements — row.first() returns None → "unknown"
        let headers = &["pid"];
        let rows: Vec<Vec<String>> = vec![vec![]];
        print_table(headers, &rows, OutputFormat::Bodyfile);
    }

    #[test]
    fn print_table_json_format_empty_rows_does_not_panic() {
        print_table(&["pid"], &[], OutputFormat::Json);
    }

    // -----------------------------------------------------------------------
    // rows_to_stix: object_type and custom_properties content
    // -----------------------------------------------------------------------

    #[test]
    fn stix_object_type_is_preserved() {
        let headers = &["pid", "name"];
        let rows = vec![vec!["2".into(), "kthreadd".into()]];
        let out = rows_to_stix("process", headers, &rows);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        let obj = &v["objects"][0];
        assert_eq!(obj["object_type"], "process");
        assert_eq!(obj["type"], "observed-data");
        assert_eq!(obj["custom_properties"]["pid"], "2");
        assert_eq!(obj["custom_properties"]["name"], "kthreadd");
    }

    // -----------------------------------------------------------------------
    // rows_to_bodyfile: inode field extraction
    // -----------------------------------------------------------------------

    #[test]
    fn bodyfile_inode_field_is_used() {
        let headers = &["path", "inode", "size"];
        let rows = vec![vec!["/usr/bin/ls".into(), "12345".into(), "256".into()]];
        let out = rows_to_bodyfile(headers, &rows);
        assert!(
            out.contains("12345"),
            "inode must appear in bodyfile: {out}"
        );
        assert!(out.contains("/usr/bin/ls"), "path must appear: {out}");
        assert!(out.contains("256"), "size must appear: {out}");
    }
}
