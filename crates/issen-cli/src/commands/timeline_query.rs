//! Tier-1 `issen timeline` typed-query surface (design Phase 1).
//!
//! Translates the typed CLI flags into a [`TypedQuery`] over a **read-only**
//! DuckDB handle and renders the result through the one shared renderer. The
//! analyst never writes SQL or learns `metadata.$.X`: named filters (`--ip`,
//! `--user`, `--service`, `--logon-type`) and `--field NAME OP VAL` resolve
//! through the curated [`FieldRegistry`]; an unknown field fails loud.

use std::path::Path;

use anyhow::{bail, Result};
use issen_timeline::tquery::{
    open_read_only, FieldFilter, FieldOp, FieldRegistry, Mode, TypedQuery,
};
use issen_timeline::trender::{render_json, render_text, Provenance};

/// The parsed, validated Tier-1 query arguments (a Humble-Object boundary: clap
/// fills this, [`run`] turns it into a [`TypedQuery`] and renders — no I/O
/// decisions leak into the query core).
///
/// The several bools mirror independent CLI presence flags (`--count`,
/// `--first`, `--last`, `--exclude-machine-accounts`); they are an argument bag,
/// not a state machine, so the excessive-bools lint does not apply.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone)]
pub struct QueryArgs {
    pub event_types: Vec<String>,
    pub sources: Vec<String>,
    pub path: Option<String>,
    /// Raw `--field NAME<OP>VAL` strings (parsed here so the error is loud).
    pub fields: Vec<String>,
    pub ip: Option<String>,
    pub user: Option<String>,
    pub service: Option<String>,
    pub logon_type: Option<String>,
    pub exclude_machine_accounts: bool,
    pub show: Option<String>,
    pub count: bool,
    pub distinct: Option<String>,
    pub group_by: Option<String>,
    pub first: bool,
    pub last: bool,
    pub sort_desc: bool,
    pub limit: Option<u64>,
    /// Inclusive time-window bounds (nanoseconds), parsed from `--from`/`--to`.
    pub from_ns: Option<i64>,
    pub to_ns: Option<i64>,
    pub format: String,
}

/// `--list-fields`: print the curated registry (name → JSON path, type, source).
pub fn list_fields() {
    println!(
        "{:<14} {:<18} {:<10} POPULATED BY",
        "FIELD", "JSON KEY", "TYPE"
    );
    println!("{}", "-".repeat(78));
    for f in FieldRegistry::all() {
        println!(
            "{:<14} {:<18} {:<10} {}",
            f.name,
            f.json_key,
            format!("{:?}", f.ftype),
            f.populated_by
        );
    }
}

/// Parse one `--field NAME<OP>VAL` into a [`FieldFilter`], failing loud on an
/// unknown field (listing the valid set) — never a silent empty result.
fn parse_field(spec: &str) -> Result<FieldFilter> {
    // Order matters: check two-char operators (`!=`, `>=`, `<=`) before the
    // one-char ones (`=`, `>`, `<`) so the longer match wins.
    let (name, op, value) = if let Some((n, v)) = spec.split_once("!=") {
        (n, FieldOp::Ne, v)
    } else if let Some((n, v)) = spec.split_once(">=") {
        (n, FieldOp::Ge, v)
    } else if let Some((n, v)) = spec.split_once("<=") {
        (n, FieldOp::Le, v)
    } else if let Some((n, v)) = spec.split_once('~') {
        (n, FieldOp::Contains, v)
    } else if let Some((n, v)) = spec.split_once('>') {
        (n, FieldOp::Gt, v)
    } else if let Some((n, v)) = spec.split_once('<') {
        (n, FieldOp::Lt, v)
    } else if let Some((n, v)) = spec.split_once('=') {
        (n, FieldOp::Eq, v)
    } else {
        bail!(
            "invalid --field '{spec}': expected NAME=VAL, NAME!=VAL, NAME~VAL, \
             or a range NAME>=VAL/NAME<=VAL/NAME>VAL/NAME<VAL. Valid fields: {}",
            FieldRegistry::valid_names()
        );
    };
    let field = FieldRegistry::resolve(name.trim()).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown --field '{}'. Valid fields: {}. (use --list-fields to see the registry)",
            name.trim(),
            FieldRegistry::valid_names()
        )
    })?;
    Ok(FieldFilter {
        field,
        op,
        value: value.to_string(),
    })
}

/// Build a sugar filter (`--ip`, `--user`, `--service`) as an exact-match field.
fn sugar(name: &str, value: &str) -> FieldFilter {
    FieldFilter {
        // Sugar names are registry constants, so resolve cannot fail here; if it
        // ever did, that is a programmer error and panicking is correct.
        field: FieldRegistry::resolve(name).expect("sugar name is a registry field"),
        op: FieldOp::Eq,
        value: value.to_string(),
    }
}

/// Translate validated args into a [`TypedQuery`]. Fails loud on conflicting
/// aggregation flags and on an unknown `--field`/`--distinct`/`--group-by`.
fn build_query(args: &QueryArgs) -> Result<(TypedQuery, Vec<String>)> {
    let mut fields: Vec<FieldFilter> = Vec::new();
    for spec in &args.fields {
        fields.push(parse_field(spec)?);
    }
    if let Some(ip) = &args.ip {
        fields.push(sugar("ip", ip));
    }
    if let Some(user) = &args.user {
        fields.push(sugar("user", user));
    }
    if let Some(service) = &args.service {
        fields.push(sugar("service", service));
    }
    // --logon-type N,N,N is OR semantics; Phase 1 supports a single value via
    // exact match (the deck's multi-value B4/B5 case is the intent-verb's job).
    // For a comma list we keep it honest: reject >1 with a clear message rather
    // than silently using only the first.
    if let Some(lt) = &args.logon_type {
        if lt.contains(',') {
            bail!(
                "--logon-type with multiple values ({lt}) is a Tier-2 intent (issen logons); \
                 Phase 1 accepts a single logon type"
            );
        }
        fields.push(sugar("logon-type", lt));
    }

    // Aggregation modes are mutually exclusive.
    let agg_count = [
        args.count,
        args.distinct.is_some(),
        args.group_by.is_some(),
        args.first,
        args.last,
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if agg_count > 1 {
        bail!("--count, --distinct, --group-by, --first, --last are mutually exclusive");
    }
    if args.first && args.last {
        bail!("--first and --last are mutually exclusive");
    }

    let mode = if args.count {
        Mode::Count
    } else if let Some(target) = &args.distinct {
        Mode::Distinct {
            target: target.clone(),
        }
    } else if let Some(target) = &args.group_by {
        Mode::GroupBy {
            target: target.clone(),
        }
    } else if args.first {
        Mode::Extreme { first: true }
    } else if args.last {
        Mode::Extreme { first: false }
    } else {
        let show = args.show.as_ref().map_or_else(
            || {
                ["timestamp_display", "event_type", "source", "artifact_path"]
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            },
            |s| s.split(',').map(|c| c.trim().to_string()).collect(),
        );
        Mode::Rows { show }
    };

    let mut filters_desc: Vec<String> = Vec::new();
    if !args.event_types.is_empty() {
        filters_desc.push(format!("event-type={}", args.event_types.join("|")));
    }
    if !args.sources.is_empty() {
        filters_desc.push(format!("source={}", args.sources.join("|")));
    }
    if let Some(p) = &args.path {
        filters_desc.push(format!("path={p}"));
    }
    for f in &fields {
        filters_desc.push(format!("{}{}{}", f.field.name, op_str(f.op), f.value));
    }
    if args.exclude_machine_accounts {
        filters_desc.push("exclude-machine-accounts".to_string());
    }
    if let Some(from) = args.from_ns {
        filters_desc.push(format!("from={from}ns"));
    }
    if let Some(to) = args.to_ns {
        filters_desc.push(format!("to={to}ns"));
    }

    let query = TypedQuery {
        event_types: args.event_types.clone(),
        sources: args.sources.clone(),
        path: args.path.clone(),
        fields,
        in_filters: Vec::new(),
        exclude_machine_accounts: args.exclude_machine_accounts,
        ascending: !args.sort_desc,
        limit: args.limit,
        from_ns: args.from_ns,
        to_ns: args.to_ns,
        mode,
    };
    Ok((query, filters_desc))
}

fn op_str(op: FieldOp) -> &'static str {
    match op {
        FieldOp::Eq => "=",
        FieldOp::Ne => "!=",
        FieldOp::Contains => "~",
        FieldOp::Ge => ">=",
        FieldOp::Le => "<=",
        FieldOp::Gt => ">",
        FieldOp::Lt => "<",
    }
}

/// Parse a `--from`/`--to` time bound into nanoseconds since the Unix epoch.
/// Accepts RFC 3339 / ISO 8601 with a zone (`2020-09-19T03:00:00Z`), a naive
/// datetime assumed UTC (`2020-09-19T03:00:00`), or a bare date treated as
/// midnight UTC (`2020-09-19`). Fails loud on an unparseable value.
pub fn parse_timestamp(s: &str) -> Result<i64> {
    use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
    let s = s.trim();
    let oor = || anyhow::anyhow!("timestamp out of representable range: {s}");
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return dt.timestamp_nanos_opt().ok_or_else(oor);
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Utc
            .from_utc_datetime(&ndt)
            .timestamp_nanos_opt()
            .ok_or_else(oor);
    }
    if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let ndt = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| anyhow::anyhow!("invalid date: {s}"))?;
        return Utc
            .from_utc_datetime(&ndt)
            .timestamp_nanos_opt()
            .ok_or_else(oor);
    }
    anyhow::bail!(
        "could not parse timestamp '{s}' \
         (use ISO 8601 like 2020-09-19T03:00:00Z or a date like 2020-09-19)"
    )
}

/// Parse a duration window like `30s`, `5m`, `2h`, `1d` into nanoseconds.
///
/// A bare number is rejected — the unit must be explicit so `--around 03:47
/// --window 5` can never silently mean 5 nanoseconds. Used by `--around` to
/// build a symmetric `[pivot-window, pivot+window]` slice.
pub fn parse_window(s: &str) -> Result<i64> {
    let s = s.trim();
    let (num, unit_ns) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1_000_000_000i64),
        Some('m') => (&s[..s.len() - 1], 60 * 1_000_000_000),
        Some('h') => (&s[..s.len() - 1], 3_600 * 1_000_000_000),
        Some('d') => (&s[..s.len() - 1], 24 * 3_600 * 1_000_000_000),
        _ => anyhow::bail!("window '{s}' needs an explicit unit (s/m/h/d), e.g. 5m or 2h"),
    };
    let magnitude: i64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("window '{s}' has a non-numeric magnitude"))?;
    magnitude
        .checked_mul(unit_ns)
        .ok_or_else(|| anyhow::anyhow!("window '{s}' is too large to represent"))
}

/// The half-open `[from, to]` ns bounds centered on `pivot_ns`, ± `window_ns`,
/// saturating at `i64` limits so an extreme pivot/window can never overflow.
pub fn around_bounds(pivot_ns: i64, window_ns: i64) -> (i64, i64) {
    (
        pivot_ns.saturating_sub(window_ns),
        pivot_ns.saturating_add(window_ns),
    )
}

/// Run the Tier-1 typed query and render the result. Read-only by construction.
pub fn run(db_path: &Path, args: &QueryArgs) -> Result<()> {
    let (query, filters_desc) = build_query(args)?;
    let conn = open_read_only(db_path)?;
    let result = query.run(&conn)?;
    let prov = Provenance {
        db_path: db_path.display().to_string(),
        filters: filters_desc,
    };
    let out = match args.format.as_str() {
        "json" => render_json(&result, &prov),
        "text" => render_text(&result, &prov),
        other => bail!("unknown --format '{other}': expected text or json"),
    };
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timestamp_accepts_iso_date_and_fails_loud() {
        // bare date = midnight UTC = the ISO form at 00:00:00Z
        assert_eq!(
            parse_timestamp("2020-09-19").expect("date"),
            parse_timestamp("2020-09-19T00:00:00Z").expect("iso")
        );
        // a later time is a larger ns
        assert!(
            parse_timestamp("2020-09-19T03:00:00Z").expect("iso")
                > parse_timestamp("2020-09-19").expect("date")
        );
        // naive datetime assumed UTC
        assert_eq!(
            parse_timestamp("2020-09-19T03:00:00").expect("naive"),
            parse_timestamp("2020-09-19T03:00:00Z").expect("iso")
        );
        // garbage fails loud
        assert!(parse_timestamp("not-a-timestamp").is_err());
    }

    #[test]
    fn parse_field_resolves_ops() {
        assert_eq!(parse_field("ip=1.2.3.4").expect("ip eq").op, FieldOp::Eq);
        assert_eq!(parse_field("user!=rick").expect("user ne").op, FieldOp::Ne);
        assert_eq!(
            parse_field("service~core").expect("service contains").op,
            FieldOp::Contains
        );
    }

    #[test]
    fn parse_field_unknown_name_fails_loud_with_valid_list() {
        let err = parse_field("nope=x")
            .expect_err("unknown field")
            .to_string();
        assert!(err.contains("unknown --field 'nope'"), "{err}");
        assert!(err.contains("ip"), "must list valid fields: {err}");
    }

    #[test]
    fn mutually_exclusive_aggregations_rejected() {
        let args = QueryArgs {
            count: true,
            distinct: Some("user".into()),
            format: "text".into(),
            ..Default::default()
        };
        let err = build_query(&args).expect_err("must fail loud").to_string();
        assert!(err.contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn sugar_ip_becomes_field_filter() {
        let args = QueryArgs {
            ip: Some("10.0.0.1".into()),
            count: true,
            format: "text".into(),
            ..Default::default()
        };
        let (q, desc) = build_query(&args).expect("build");
        assert_eq!(q.fields.len(), 1);
        assert_eq!(q.fields[0].field.name, "ip");
        assert!(desc.iter().any(|d| d == "ip=10.0.0.1"));
    }

    #[test]
    fn multi_logon_type_rejected_in_phase1() {
        let args = QueryArgs {
            logon_type: Some("2,10,11".into()),
            count: true,
            format: "text".into(),
            ..Default::default()
        };
        let err = build_query(&args).expect_err("must fail loud").to_string();
        assert!(err.contains("logon"), "{err}");
    }

    #[test]
    fn parse_window_requires_an_explicit_unit() {
        assert_eq!(parse_window("30s").expect("s"), 30 * 1_000_000_000);
        assert_eq!(parse_window("5m").expect("m"), 5 * 60 * 1_000_000_000);
        assert_eq!(parse_window("2h").expect("h"), 2 * 3_600 * 1_000_000_000);
        assert_eq!(parse_window("1d").expect("d"), 24 * 3_600 * 1_000_000_000);
        // A bare number must be rejected — never silently mean nanoseconds.
        assert!(parse_window("5").is_err(), "bare number rejected");
        assert!(parse_window("5x").is_err(), "unknown unit rejected");
        assert!(parse_window("").is_err(), "empty rejected");
        assert!(parse_window("m").is_err(), "missing magnitude rejected");
    }

    #[test]
    fn around_bounds_is_symmetric_and_saturates() {
        assert_eq!(around_bounds(1_000, 300), (700, 1_300));
        assert_eq!(
            around_bounds(i64::MAX, 1_000),
            (i64::MAX - 1_000, i64::MAX),
            "near-max pivot must not overflow"
        );
        assert_eq!(
            around_bounds(i64::MIN, 1_000),
            (i64::MIN, i64::MIN + 1_000),
            "near-min pivot must not underflow"
        );
    }
}
