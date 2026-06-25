//! Tier-2 intent verbs (`issen logons|files|persistence|hosts`) and the guarded
//! read-only `issen timeline --sql` escape hatch (design Phase 2).
//!
//! Each verb is a thin front-end over a [`presets`] floor: the preset fixes the
//! event-type set, the default mode, and the baseline filters that *define* the
//! question; the per-run flags (`--service`, `--host`, `--ip`, `--path`, `--user`,
//! aggregation toggles) layer on top. The build functions are pure (Humble
//! Object) so the preset+flag composition is unit-testable without a DB; `run_*`
//! only opens the read-only handle and renders.

use std::path::Path;

use anyhow::{bail, Result};
use duckdb::types::Value as DuckValue;
use issen_timeline::sql_guard::check_query_safe;
use issen_timeline::tquery::{
    open_read_only, presets, Column, FieldFilter, FieldOp, FieldRegistry, Mode, QueryResult,
    TypedQuery,
};
use issen_timeline::trender::{render_json, render_text, Provenance};

/// The aggregation/projection toggles shared by every verb (mirrors the Tier-1
/// `Mode` selectors). Mutually exclusive — validated in [`apply_mode`].
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone)]
pub struct VerbCommon {
    pub count: bool,
    pub distinct: Option<String>,
    pub group_by: Option<String>,
    pub first: bool,
    pub last: bool,
    pub show: Option<String>,
    pub sort_desc: bool,
    pub limit: Option<u64>,
    pub format: String,
}

/// `logons` flags.
#[derive(Debug, Default, Clone)]
pub struct LogonsArgs {
    /// Restrict to a single user (`TargetUserName`).
    pub user: Option<String>,
    /// Restrict to a source IP (`IpAddress`).
    pub ip: Option<String>,
    pub common: VerbCommon,
}

/// `files` flags.
#[derive(Debug, Default, Clone)]
pub struct FilesArgs {
    /// Path glob (`*coreupdater*`, `*.lnk`).
    pub path: Option<String>,
    pub common: VerbCommon,
}

/// `persistence` flags.
#[derive(Debug, Default, Clone)]
pub struct PersistenceArgs {
    /// Restrict to a named service (`ServiceName`).
    pub service: Option<String>,
    /// Restrict to a registry key path (matches `artifact_path`).
    pub registry_key: Option<String>,
    pub common: VerbCommon,
}

/// `hosts` flags.
#[derive(Debug, Default, Clone)]
pub struct HostsArgs {
    /// Remote host IP (`IpAddress`).
    pub host: Option<String>,
    /// Remote port (`Port`).
    pub port: Option<String>,
    pub common: VerbCommon,
}

/// Apply the shared aggregation/projection toggles to a preset, validating that
/// at most one aggregation mode is selected (fails loud, never silently picks).
fn apply_mode(mut q: TypedQuery, common: &VerbCommon) -> Result<TypedQuery> {
    let agg = [
        common.count,
        common.distinct.is_some(),
        common.group_by.is_some(),
        common.first,
        common.last,
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if agg > 1 {
        bail!("--count, --distinct, --group-by, --first, --last are mutually exclusive");
    }

    q.ascending = !common.sort_desc;
    q.limit = common.limit;

    // An explicit aggregation flag overrides the preset's default mode; otherwise
    // keep the preset's mode unless --show requests specific row columns.
    if common.count {
        q.mode = Mode::Count;
    } else if let Some(t) = &common.distinct {
        q.mode = Mode::Distinct { target: t.clone() };
    } else if let Some(t) = &common.group_by {
        q.mode = Mode::GroupBy { target: t.clone() };
    } else if common.first {
        q.mode = Mode::Extreme { first: true };
    } else if common.last {
        q.mode = Mode::Extreme { first: false };
    } else if let Some(show) = &common.show {
        q.mode = Mode::Rows {
            show: show.split(',').map(|c| c.trim().to_string()).collect(),
        };
    }
    Ok(q)
}

/// Push an exact-match registry-field filter (`--service`, `--ip`, …) onto a
/// query. `field_name` is a registry constant supplied by a verb; an unresolved
/// name is a programmer error and fails loud (never a silently-dropped filter).
fn push_eq(q: &mut TypedQuery, field_name: &str, value: &str) -> Result<()> {
    let field = FieldRegistry::resolve(field_name).ok_or_else(|| {
        anyhow::anyhow!("internal: verb referenced unknown registry field '{field_name}'")
    })?;
    q.fields.push(FieldFilter {
        field,
        op: FieldOp::Eq,
        value: value.to_string(),
    });
    Ok(())
}

/// Build the `logons` query: the preset floor + optional `--user`/`--ip`.
pub fn build_logons(args: &LogonsArgs) -> Result<TypedQuery> {
    let mut q = presets::logons();
    if let Some(user) = &args.user {
        push_eq(&mut q, "user", user)?;
    }
    if let Some(ip) = &args.ip {
        push_eq(&mut q, "ip", ip)?;
    }
    apply_mode(q, &args.common)
}

/// Build the `files` query: the preset floor + optional `--path` glob.
pub fn build_files(args: &FilesArgs) -> Result<TypedQuery> {
    let mut q = presets::files();
    if let Some(path) = &args.path {
        q.path = Some(path.clone());
    }
    apply_mode(q, &args.common)
}

/// Build the `persistence` query: the preset floor + `--service`/`--registry-key`.
pub fn build_persistence(args: &PersistenceArgs) -> Result<TypedQuery> {
    let mut q = presets::persistence();
    if let Some(service) = &args.service {
        push_eq(&mut q, "service", service)?;
    }
    if let Some(key) = &args.registry_key {
        // A registry key path lives in artifact_path; reuse the escaped LIKE.
        q.path = Some(key.clone());
    }
    apply_mode(q, &args.common)
}

/// Build the `hosts` query: the preset floor + `--host`/`--port`.
pub fn build_hosts(args: &HostsArgs) -> Result<TypedQuery> {
    let mut q = presets::hosts();
    if let Some(host) = &args.host {
        push_eq(&mut q, "ip", host)?;
    }
    if let Some(port) = &args.port {
        push_eq(&mut q, "port", port)?;
    }
    apply_mode(q, &args.common)
}

/// One human-readable provenance line per applied filter (mirrors the Tier-1
/// renderer's filter summary).
fn describe(verb: &str, q: &TypedQuery) -> Vec<String> {
    let mut d = vec![format!("verb={verb}")];
    if !q.event_types.is_empty() {
        d.push(format!("event-type={}", q.event_types.join("|")));
    }
    for inf in &q.in_filters {
        d.push(format!("{} in [{}]", inf.field.name, inf.values.join(",")));
    }
    if let Some(p) = &q.path {
        d.push(format!("path={p}"));
    }
    for f in &q.fields {
        d.push(format!("{}={}", f.field.name, f.value));
    }
    if q.exclude_machine_accounts {
        d.push("exclude-machine-accounts".to_string());
    }
    d
}

/// Run a built verb query against a read-only DB and render it.
fn run_built(db_path: &Path, verb: &str, q: &TypedQuery, format: &str) -> Result<()> {
    let conn = open_read_only(db_path)?;
    let result = q.run(&conn)?;
    let prov = Provenance {
        db_path: db_path.display().to_string(),
        filters: describe(verb, q),
    };
    render_and_print(&result, &prov, format)
}

fn render_and_print(result: &QueryResult, prov: &Provenance, format: &str) -> Result<()> {
    let out = match format {
        "json" => render_json(result, prov),
        "text" => render_text(result, prov),
        other => bail!("unknown --format '{other}': expected text or json"),
    };
    print!("{out}");
    Ok(())
}

/// `issen logons <db> [flags]`.
pub fn run_logons(db_path: &Path, args: &LogonsArgs) -> Result<()> {
    let q = build_logons(args)?;
    run_built(db_path, "logons", &q, &args.common.format)
}

/// `issen files <db> [flags]`.
pub fn run_files(db_path: &Path, args: &FilesArgs) -> Result<()> {
    let q = build_files(args)?;
    run_built(db_path, "files", &q, &args.common.format)
}

/// `issen persistence <db> [flags]`.
pub fn run_persistence(db_path: &Path, args: &PersistenceArgs) -> Result<()> {
    let q = build_persistence(args)?;
    run_built(db_path, "persistence", &q, &args.common.format)
}

/// `issen hosts <db> [flags]`.
pub fn run_hosts(db_path: &Path, args: &HostsArgs) -> Result<()> {
    let q = build_hosts(args)?;
    run_built(db_path, "hosts", &q, &args.common.format)
}

/// `issen timeline <db> --sql "<query>"`: guarded read-only raw SQL. The guard
/// rejects any mutating keyword before the statement reaches DuckDB; the handle
/// is read-only regardless. Renders the result through the one shared renderer.
pub fn run_sql(db_path: &Path, sql: &str, format: &str) -> Result<()> {
    check_query_safe(sql)?;
    let conn = open_read_only(db_path)?;
    let result = run_raw_select(&conn, sql)?;
    let prov = Provenance {
        db_path: db_path.display().to_string(),
        filters: vec!["sql (read-only)".to_string()],
    };
    render_and_print(&result, &prov, format)
}

/// Execute a vetted read-only SELECT/WITH and collect it into a [`QueryResult`].
/// Each cell is read type-agnostically as a DuckDB [`DuckValue`] and stringified,
/// so numeric/temporal columns (e.g. a `count(*)` BIGINT) render their value
/// rather than collapsing to empty (NULL → empty string).
fn run_raw_select(conn: &duckdb::Connection, sql: &str) -> Result<QueryResult> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([])?;

    let mut columns: Vec<Column> = Vec::new();
    let mut headers_set = false;
    let mut row_count = 0usize;
    while let Some(row) = rows.next()? {
        if !headers_set {
            // Column names are only knowable after the statement has stepped; the
            // executed Statement is reachable via the row. Derive headers once.
            let stmt_ref = row.as_ref();
            let n = stmt_ref.column_count();
            for i in 0..n {
                let name = stmt_ref
                    .column_name(i)
                    .map_or_else(|_| format!("col{i}"), ToString::to_string);
                columns.push(Column {
                    name,
                    values: Vec::new(),
                });
            }
            headers_set = true;
        }
        for (i, col) in columns.iter_mut().enumerate() {
            let v: DuckValue = row.get(i).unwrap_or(DuckValue::Null);
            col.values.push(duck_value_to_string(&v));
        }
        row_count += 1;
    }
    Ok(QueryResult {
        columns,
        row_count,
        field_populated: Vec::new(),
    })
}

/// Stringify a DuckDB cell value for uniform rendering. NULL becomes the empty
/// string (consistent with the typed-query path); every other scalar uses its
/// natural value. This keeps the raw-`--sql` output faithful instead of silently
/// dropping non-text columns (e.g. a `count(*)` BIGINT).
fn duck_value_to_string(v: &DuckValue) -> String {
    match v {
        DuckValue::Null => String::new(),
        DuckValue::Boolean(b) => b.to_string(),
        DuckValue::TinyInt(n) => n.to_string(),
        DuckValue::SmallInt(n) => n.to_string(),
        DuckValue::Int(n) => n.to_string(),
        DuckValue::BigInt(n) => n.to_string(),
        DuckValue::HugeInt(n) => n.to_string(),
        DuckValue::UTinyInt(n) => n.to_string(),
        DuckValue::USmallInt(n) => n.to_string(),
        DuckValue::UInt(n) => n.to_string(),
        DuckValue::UBigInt(n) => n.to_string(),
        DuckValue::Float(n) => n.to_string(),
        DuckValue::Double(n) => n.to_string(),
        DuckValue::Decimal(d) => d.to_string(),
        DuckValue::Text(s) => s.clone(),
        DuckValue::Enum(s) => s.clone(),
        // Remaining variants (timestamps, blobs, lists, structs, …) are uncommon
        // in analyst SELECTs; their Debug form is faithful and never panics, so
        // it is a safe, lossless-enough fallback (never a silent empty cell).
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn duck_value_bigint_renders_its_number_not_empty() {
        // Regression: a count(*) BIGINT cell must render its value, never empty.
        assert_eq!(duck_value_to_string(&DuckValue::BigInt(42)), "42");
        assert_eq!(duck_value_to_string(&DuckValue::Int(-7)), "-7");
        assert_eq!(duck_value_to_string(&DuckValue::Text("x".into())), "x");
        assert_eq!(duck_value_to_string(&DuckValue::Boolean(true)), "true");
        assert_eq!(duck_value_to_string(&DuckValue::Null), "");
    }

    #[test]
    fn logons_preset_floor_with_user_and_ip() {
        let args = LogonsArgs {
            user: Some("rick".into()),
            ip: Some("10.0.0.1".into()),
            common: VerbCommon {
                count: true,
                format: "text".into(),
                ..Default::default()
            },
        };
        let q = build_logons(&args).expect("build");
        // preset floor preserved:
        assert_eq!(q.event_types, vec!["LogonSuccess".to_string()]);
        assert!(q.exclude_machine_accounts);
        assert_eq!(q.in_filters.len(), 1);
        assert_eq!(q.in_filters[0].values, vec!["2", "10", "11"]);
        // flags layered on:
        assert!(q
            .fields
            .iter()
            .any(|f| f.field.name == "user" && f.value == "rick"));
        assert!(q
            .fields
            .iter()
            .any(|f| f.field.name == "ip" && f.value == "10.0.0.1"));
        assert!(matches!(q.mode, Mode::Count));
    }

    #[test]
    fn files_preset_with_path_keeps_event_set() {
        let args = FilesArgs {
            path: Some("*coreupdater*".into()),
            common: VerbCommon {
                count: true,
                format: "text".into(),
                ..Default::default()
            },
        };
        let q = build_files(&args).expect("build");
        assert_eq!(
            q.event_types,
            vec!["FileCreate", "FileModify", "FileDelete", "FileRename"]
        );
        assert_eq!(q.path.as_deref(), Some("*coreupdater*"));
    }

    #[test]
    fn persistence_with_service_and_registry_key() {
        let svc = PersistenceArgs {
            service: Some("coreupdater".into()),
            common: VerbCommon {
                count: true,
                format: "text".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let q = build_persistence(&svc).expect("build");
        assert!(q.event_types.iter().any(|e| e == "ServiceInstall"));
        assert!(q
            .fields
            .iter()
            .any(|f| f.field.name == "service" && f.value == "coreupdater"));

        let key = PersistenceArgs {
            registry_key: Some("*Run*".into()),
            common: VerbCommon {
                format: "text".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let q2 = build_persistence(&key).expect("build");
        assert_eq!(q2.path.as_deref(), Some("*Run*"));
    }

    #[test]
    fn hosts_with_host_maps_to_ip() {
        let args = HostsArgs {
            host: Some("194.61.24.102".into()),
            common: VerbCommon {
                count: true,
                format: "text".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let q = build_hosts(&args).expect("build");
        assert!(q.event_types.iter().any(|e| e == "LogonSuccess"));
        assert!(q
            .fields
            .iter()
            .any(|f| f.field.name == "ip" && f.value == "194.61.24.102"));
    }

    #[test]
    fn mutually_exclusive_aggregations_rejected() {
        let args = LogonsArgs {
            common: VerbCommon {
                count: true,
                distinct: Some("user".into()),
                format: "text".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = build_logons(&args).expect_err("must fail loud").to_string();
        assert!(err.contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn logons_default_mode_is_distinct_user() {
        let args = LogonsArgs {
            common: VerbCommon {
                format: "text".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let q = build_logons(&args).expect("build");
        assert!(matches!(q.mode, Mode::Distinct { ref target } if target == "user"));
    }
}
