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
        .map(|(i, h)| format!("{:<width$}", h, width = widths[i]))
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
                let val = row.get(i).map(|s| s.as_str()).unwrap_or("");
                format!("{:<width$}", val, width = w)
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
                let name = row.first().map(|s| s.as_str()).unwrap_or("unknown");
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
}
