//! Typed, injection-safe timeline query core (design Phase 1).
//!
//! Turns the tribal-knowledge raw-SQL workflow (`duckdb dc01.duckdb -c
//! "SELECT … json_extract_string(metadata,'$.IpAddress') …"`) into a typed
//! surface: a curated [field registry](FieldRegistry) maps analyst-facing names
//! (`ip`, `user`, `service`) to the JSON path inside `metadata`, and a
//! [`TypedQuery`] compiles to a **parameterized** query on a **read-only**
//! DuckDB handle. No analyst input is ever string-interpolated into SQL.
//!
//! Security invariants (see the design's "Security considerations"):
//! - read-only by construction ([`open_read_only`]),
//! - no interpolation (filters bind as parameters; `--path` globs are escaped),
//! - loud on unknown fields ([`QueryError::UnknownField`]), never a silent
//!   empty result,
//! - empty != absent ([`QueryResult::field_populated`] distinguishes "0 matches"
//!   from "that field was never present in this case").

use std::path::Path;

use duckdb::types::Value as DuckValue;
use duckdb::{AccessMode, Config, Connection};
use thiserror::Error;

/// The logical type a registry field carries (drives parsing/display).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// An IP address (string in the JSON, e.g. `IpAddress`).
    IpAddress,
    /// A free-text identifier (user/service/workstation names).
    Text,
    /// A logon-type code (numeric, stored as a JSON string like `"3"`).
    LogonType,
    /// A hex/identifier token (e.g. `TargetLogonId` `0x3cfe4`).
    Id,
}

/// One curated field: an analyst-facing name mapped to its `metadata` JSON key.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// The canonical analyst-facing name (`ip`, `user`, …).
    pub name: &'static str,
    /// Accepted aliases (e.g. `logon-type` ⇒ also `logontype`).
    pub aliases: &'static [&'static str],
    /// The JSON key inside the `metadata` blob (`IpAddress`, `TargetUserName`…).
    pub json_key: &'static str,
    /// The logical type.
    pub ftype: FieldType,
    /// Which `event_type`/`source` typically populates this field (doc/listing).
    pub populated_by: &'static str,
}

/// The curated field registry — the heart of the typed surface.
///
/// Hand-curated for Phase 1 (the design's "Open questions" prefers deriving
/// this from parser manifests later; YAGNI for now). Each entry turns a
/// `metadata.$.X` JSON path into a first-class, discoverable name.
pub struct FieldRegistry;

const FIELDS: &[Field] = &[
    Field {
        name: "ip",
        aliases: &["ipaddress", "ip-address"],
        json_key: "IpAddress",
        ftype: FieldType::IpAddress,
        populated_by: "LogonSuccess/Logoff (EventLog 4624/4634)",
    },
    Field {
        name: "user",
        aliases: &["username", "target-user"],
        json_key: "TargetUserName",
        ftype: FieldType::Text,
        populated_by: "LogonSuccess/Logoff (EventLog)",
    },
    Field {
        name: "logon-type",
        aliases: &["logontype", "logon_type"],
        json_key: "LogonType",
        ftype: FieldType::LogonType,
        populated_by: "LogonSuccess (EventLog 4624)",
    },
    Field {
        name: "service",
        aliases: &["service-name", "servicename"],
        json_key: "ServiceName",
        ftype: FieldType::Text,
        populated_by: "ServiceInstall (EventLog 7045)",
    },
    Field {
        name: "workstation",
        aliases: &["workstation-name", "workstationname"],
        json_key: "WorkstationName",
        ftype: FieldType::Text,
        populated_by: "LogonSuccess (EventLog 4624)",
    },
    Field {
        name: "logon-id",
        aliases: &["logonid", "target-logon-id", "targetlogonid"],
        json_key: "TargetLogonId",
        ftype: FieldType::Id,
        populated_by: "LogonSuccess/Logoff (EventLog)",
    },
    Field {
        name: "port",
        aliases: &["ip-port", "remote-port"],
        json_key: "Port",
        ftype: FieldType::Text,
        populated_by: "NetworkConnection/LogonSuccess (EventLog)",
    },
];

impl FieldRegistry {
    /// All curated fields (for `--list-fields`).
    #[must_use]
    pub fn all() -> &'static [Field] {
        FIELDS
    }

    /// Resolve a name or alias to its [`Field`]. `None` for an unknown name —
    /// callers must surface this loudly, never as an empty result.
    #[must_use]
    pub fn resolve(name: &str) -> Option<&'static Field> {
        let key = name.trim().to_ascii_lowercase();
        FIELDS.iter().find(|f| {
            f.name.eq_ignore_ascii_case(&key)
                || f.aliases.iter().any(|a| a.eq_ignore_ascii_case(&key))
        })
    }

    /// Sorted, comma-joined list of canonical field names (for error messages).
    #[must_use]
    pub fn valid_names() -> String {
        let mut names: Vec<&str> = FIELDS.iter().map(|f| f.name).collect();
        names.sort_unstable();
        names.join(", ")
    }
}

/// A filter operator over a registry field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldOp {
    /// `=` exact match.
    Eq,
    /// `!=` not equal.
    Ne,
    /// `~` substring (contains).
    Contains,
    /// `>=` numeric (the JSON string value is `TRY_CAST` to an integer).
    Ge,
    /// `<=` numeric.
    Le,
    /// `>` numeric.
    Gt,
    /// `<` numeric.
    Lt,
}

impl FieldOp {
    /// `true` for the numeric range comparators (`>=`, `<=`, `>`, `<`).
    #[must_use]
    pub fn is_range(self) -> bool {
        matches!(self, FieldOp::Ge | FieldOp::Le | FieldOp::Gt | FieldOp::Lt)
    }

    /// The SQL comparison symbol for a range op (panics for non-range ops; only
    /// reachable for a range op by construction in [`TypedQuery::build_where`]).
    fn range_sql(self) -> &'static str {
        match self {
            FieldOp::Ge => ">=",
            FieldOp::Le => "<=",
            FieldOp::Gt => ">",
            FieldOp::Lt => "<",
            // cov:unreachable: build_where only calls this in the range arm
            FieldOp::Eq | FieldOp::Ne | FieldOp::Contains => "=",
        }
    }
}

/// A set-membership filter (`FIELD IN (v1, v2, …)`); each value binds as a
/// parameter. Used by the `logons` intent verb (`LogonType IN ('2','10','11')`).
#[derive(Debug, Clone)]
pub struct FieldInFilter {
    /// Registry field (already resolved at construction).
    pub field: &'static Field,
    /// The candidate values (OR-combined); each binds as a parameter.
    pub values: Vec<String>,
}

/// A single typed metadata filter (`--field NAME OP VAL`, or its `--ip` sugar).
#[derive(Debug, Clone)]
pub struct FieldFilter {
    /// Registry field name (already resolved at parse time).
    pub field: &'static Field,
    /// The operator.
    pub op: FieldOp,
    /// The analyst-supplied value (bound as a parameter, never interpolated).
    pub value: String,
}

/// What to project / aggregate. A query is either rows or exactly one aggregate.
#[derive(Debug, Clone)]
pub enum Mode {
    /// Project the given columns/fields as rows.
    Rows {
        /// Columns to show: a table column name or a registry field name.
        show: Vec<String>,
    },
    /// `--count`: total matching rows.
    Count,
    /// `--distinct COL|FIELD`: distinct values (sorted).
    Distinct {
        /// The column/field whose distinct values to return.
        target: String,
    },
    /// `--group-by COL|FIELD`: histogram (value, count).
    GroupBy {
        /// The column/field to group on.
        target: String,
    },
    /// `--first`/`--last`: the min/max-timestamp row of the matched set.
    Extreme {
        /// `true` = first (min ts), `false` = last (max ts).
        first: bool,
    },
    /// `--stats`: a one-shot summary of the matched set — total, time span, and
    /// the top event-type / source breakdowns — as a `(metric, value)` table.
    Stats,
}

/// A typed, read-only timeline query (the design's Tier-1 engine).
#[derive(Debug, Clone)]
pub struct TypedQuery {
    /// `event_type` filters (OR within; AND with the rest).
    pub event_types: Vec<String>,
    /// `source` filters (OR within).
    pub sources: Vec<String>,
    /// `artifact_path` glob/substring (compiled to an escaped, parameterized LIKE).
    pub path: Option<String>,
    /// Typed metadata filters (AND-combined).
    pub fields: Vec<FieldFilter>,
    /// Set-membership filters (`FIELD IN (…)`, AND-combined with everything else).
    pub in_filters: Vec<FieldInFilter>,
    /// Drop `user` values ending in `$` (machine accounts).
    pub exclude_machine_accounts: bool,
    /// Sort ascending by timestamp (rows / group-by ordering).
    pub ascending: bool,
    /// Row limit (rows mode only).
    pub limit: Option<u64>,
    /// Inclusive lower time bound (`timestamp_ns >= from_ns`) — the incident
    /// window start. `None` = unbounded.
    pub from_ns: Option<i64>,
    /// Inclusive upper time bound (`timestamp_ns <= to_ns`). `None` = unbounded.
    pub to_ns: Option<i64>,
    /// What to project / aggregate.
    pub mode: Mode,
    /// `--context N`: also surface the N rows before and after each match (from
    /// the *unfiltered* timeline), grep `-C` style. `None` = matches only.
    /// Rows mode only.
    pub context: Option<u64>,
}

impl Default for TypedQuery {
    fn default() -> Self {
        Self {
            event_types: Vec::new(),
            sources: Vec::new(),
            path: None,
            fields: Vec::new(),
            in_filters: Vec::new(),
            exclude_machine_accounts: false,
            ascending: true,
            limit: None,
            from_ns: None,
            to_ns: None,
            mode: Mode::Rows {
                show: default_columns(),
            },
            context: None,
        }
    }
}

fn default_columns() -> Vec<String> {
    ["timestamp_display", "event_type", "source", "artifact_path"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Table columns the projection accepts directly (everything else is a field).
const TABLE_COLUMNS: &[&str] = &[
    "timestamp_ns",
    "timestamp_display",
    "event_type",
    "source",
    "artifact_path",
    "description",
    "user_account",
    "hostname",
    "evidence_source",
];

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("DuckDB error: {0}")]
    DuckDb(#[from] duckdb::Error),

    #[error(
        "unknown field '{name}'. Valid fields: {valid}. \
         (use --list-fields to see the registry)"
    )]
    UnknownField { name: String, valid: String },

    #[error("unknown column/field '{target}'. Valid: {valid}")]
    UnknownTarget { target: String, valid: String },
}

/// Open a case DB on a **read-only** handle. A write is impossible by
/// construction — the connection is opened with `access_mode=READ_ONLY`, so no
/// code path (this one or a future caller's) can mutate evidence.
pub fn open_read_only(path: &Path) -> Result<Connection, QueryError> {
    let config = Config::default().access_mode(AccessMode::ReadOnly)?;
    Ok(Connection::open_with_flags(path, config)?)
}

/// A single output column's name and its values for the matched rows.
#[derive(Debug, Clone)]
pub struct Column {
    /// The column header (analyst-facing name).
    pub name: String,
    /// One string per row.
    pub values: Vec<String>,
}

/// The result of a typed query: a uniform tabular shape the renderer consumes.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// Output columns (header + per-row values).
    pub columns: Vec<Column>,
    /// Number of result rows.
    pub row_count: usize,
    /// For each registry field referenced by a filter/projection: whether ANY
    /// ingested row in the case populated it. Distinguishes "0 matches" from
    /// "field never present" (empty != absent).
    pub field_populated: Vec<(String, bool)>,
}

/// A LIKE pattern escape: turn a `*`/`?` glob into SQL `%`/`_` while escaping
/// the analyst's literal `%`, `_`, and the escape char itself. The value is
/// still bound as a parameter — escaping only prevents an analyst `%` from
/// silently widening the match (it does not, and cannot, prevent injection,
/// which is handled by parameter binding).
fn glob_to_like(glob: &str) -> String {
    let mut out = String::with_capacity(glob.len() + 2);
    for ch in glob.chars() {
        match ch {
            '*' => out.push('%'),
            '?' => out.push('_'),
            '%' | '_' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// SQL expression extracting a registry field from the `metadata` JSON, with the
/// JSON key bound as a parameter (no interpolation of the key either).
fn field_expr() -> &'static str {
    "json_extract_string(metadata, '$.' || ?)"
}

impl TypedQuery {
    /// Resolve a projection/aggregation target to its SQL expression, binding
    /// any field JSON key as a parameter. Unknown names fail loud.
    fn target_expr(&self, target: &str, params: &mut Vec<DuckValue>) -> Result<String, QueryError> {
        let key = target.trim().to_ascii_lowercase();
        // event-type is the analyst spelling of the event_type column.
        if key == "event-type" {
            return Ok("event_type".to_string());
        }
        if TABLE_COLUMNS.contains(&key.as_str()) {
            return Ok(key);
        }
        if let Some(field) = FieldRegistry::resolve(target) {
            params.push(DuckValue::Text(field.json_key.to_string()));
            return Ok(field_expr().to_string());
        }
        Err(QueryError::UnknownTarget {
            target: target.to_string(),
            valid: format!(
                "{}, {}",
                TABLE_COLUMNS.join(", "),
                FieldRegistry::valid_names()
            ),
        })
    }

    /// Build the WHERE clause (without the leading `WHERE`), appending bound
    /// params in left-to-right order. All analyst input binds as a parameter.
    fn build_where(&self, params: &mut Vec<DuckValue>) -> String {
        let mut clauses: Vec<String> = vec!["1=1".to_string()];

        if !self.event_types.is_empty() {
            let placeholders = vec!["?"; self.event_types.len()].join(", ");
            clauses.push(format!("event_type IN ({placeholders})"));
            for et in &self.event_types {
                params.push(DuckValue::Text(et.clone()));
            }
        }
        if !self.sources.is_empty() {
            let placeholders = vec!["?"; self.sources.len()].join(", ");
            clauses.push(format!("source IN ({placeholders})"));
            for s in &self.sources {
                params.push(DuckValue::Text(s.clone()));
            }
        }
        if let Some(ref glob) = self.path {
            clauses.push("artifact_path LIKE ? ESCAPE '\\'".to_string());
            params.push(DuckValue::Text(glob_to_like(glob)));
        }
        if let Some(from) = self.from_ns {
            clauses.push("timestamp_ns >= ?".to_string());
            params.push(DuckValue::BigInt(from));
        }
        if let Some(to) = self.to_ns {
            clauses.push("timestamp_ns <= ?".to_string());
            params.push(DuckValue::BigInt(to));
        }
        for f in &self.fields {
            let expr = field_expr();
            params.push(DuckValue::Text(f.field.json_key.to_string()));
            match f.op {
                FieldOp::Eq => {
                    clauses.push(format!("{expr} = ?"));
                    params.push(DuckValue::Text(f.value.clone()));
                }
                FieldOp::Ne => {
                    clauses.push(format!("{expr} <> ?"));
                    params.push(DuckValue::Text(f.value.clone()));
                }
                FieldOp::Contains => {
                    clauses.push(format!("{expr} LIKE ? ESCAPE '\\'"));
                    params.push(DuckValue::Text(format!("%{}%", like_escape(&f.value))));
                }
                FieldOp::Ge | FieldOp::Le | FieldOp::Gt | FieldOp::Lt => {
                    // Numeric range: the JSON value is a string ("2"); TRY_CAST
                    // it to a BIGINT so the comparison is numeric, and bind the
                    // bound as an integer parameter. A non-numeric/absent value
                    // yields NULL and is excluded (never a panic, never a match).
                    let sym = f.op.range_sql();
                    let bound = f.value.trim().parse::<i64>().unwrap_or(0);
                    clauses.push(format!("TRY_CAST({expr} AS BIGINT) {sym} ?"));
                    params.push(DuckValue::BigInt(bound));
                }
            }
        }
        for inf in &self.in_filters {
            if inf.values.is_empty() {
                // An empty IN-set matches nothing; emit a constant-false clause
                // rather than invalid `IN ()` SQL.
                clauses.push("1=0".to_string());
                continue;
            }
            let expr = field_expr();
            params.push(DuckValue::Text(inf.field.json_key.to_string()));
            let placeholders = vec!["?"; inf.values.len()].join(", ");
            clauses.push(format!("{expr} IN ({placeholders})"));
            for v in &inf.values {
                params.push(DuckValue::Text(v.clone()));
            }
        }
        if self.exclude_machine_accounts {
            // Drop user values ending in '$' (machine accounts). The field key
            // and the literal pattern both bind as parameters.
            let expr = field_expr();
            params.push(DuckValue::Text("TargetUserName".to_string()));
            clauses.push(format!(
                "({expr} IS NULL OR {expr2} NOT LIKE ? ESCAPE '\\')",
                expr2 = {
                    params.push(DuckValue::Text("TargetUserName".to_string()));
                    field_expr()
                }
            ));
            params.push(DuckValue::Text("%\\$".to_string()));
        }

        clauses.join(" AND ")
    }

    /// Compile and run against a read-only connection, returning a uniform
    /// [`QueryResult`]. The SQL is fully parameterized.
    pub fn run(&self, conn: &Connection) -> Result<QueryResult, QueryError> {
        match &self.mode {
            Mode::Count => self.run_count(conn),
            Mode::Distinct { target } => self.run_distinct(conn, target),
            Mode::GroupBy { target } => self.run_group_by(conn, target),
            Mode::Extreme { first } => self.run_extreme(conn, *first),
            Mode::Stats => self.run_stats(conn),
            Mode::Rows { show } => self.run_rows(conn, show),
        }
    }

    fn field_populated_report(&self, conn: &Connection) -> Result<Vec<(String, bool)>, QueryError> {
        // For every registry field referenced by a filter, report whether ANY
        // row in the whole case populated it (empty != absent diagnostic).
        let mut out = Vec::new();
        for f in &self.fields {
            let populated = field_is_populated(conn, f.field.json_key)?;
            out.push((f.field.name.to_string(), populated));
        }
        for inf in &self.in_filters {
            if out.iter().any(|(n, _)| n == inf.field.name) {
                continue;
            }
            let populated = field_is_populated(conn, inf.field.json_key)?;
            out.push((inf.field.name.to_string(), populated));
        }
        Ok(out)
    }

    fn run_stats(&self, conn: &Connection) -> Result<QueryResult, QueryError> {
        let mut params: Vec<DuckValue> = Vec::new();
        let where_clause = self.build_where(&mut params);

        let mut metric: Vec<String> = Vec::new();
        let mut value: Vec<String> = Vec::new();

        // Total matching the same filter set as every other mode.
        let total: i64 = conn.query_row(
            &format!("SELECT count(*) FROM timeline WHERE {where_clause}"),
            params_slice(&params).as_slice(),
            |r| r.get(0),
        )?;
        metric.push("total".to_string());
        value.push(total.to_string());

        // Time span (min/max display; NULL when the matched set is empty).
        let (earliest, latest): (Option<String>, Option<String>) = conn.query_row(
            &format!(
                "SELECT min(timestamp_display), max(timestamp_display) \
                 FROM timeline WHERE {where_clause}"
            ),
            params_slice(&params).as_slice(),
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if let Some(e) = earliest {
            metric.push("earliest".to_string());
            value.push(e);
        }
        if let Some(l) = latest {
            metric.push("latest".to_string());
            value.push(l);
        }

        // Top event-type and source breakdowns (top 5 each by count).
        for (label, col) in [("event_type", "event_type"), ("source", "source")] {
            let sql = format!(
                "SELECT {col} AS v, count(*) AS c FROM timeline WHERE {where_clause} \
                 GROUP BY 1 ORDER BY c DESC, v ASC LIMIT 5"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_slice(&params).as_slice(), |row| {
                let v: Option<String> = row.get(0)?;
                let c: i64 = row.get(1)?;
                Ok((v.unwrap_or_default(), c))
            })?;
            for r in rows {
                let (v, c) = r?;
                metric.push(format!("{label}: {v}"));
                value.push(c.to_string());
            }
        }

        let row_count = metric.len();
        Ok(QueryResult {
            columns: vec![
                Column {
                    name: "metric".to_string(),
                    values: metric,
                },
                Column {
                    name: "value".to_string(),
                    values: value,
                },
            ],
            row_count,
            field_populated: self.field_populated_report(conn)?,
        })
    }

    fn run_rows_context(
        &self,
        conn: &Connection,
        show: &[String],
        n: u64,
    ) -> Result<QueryResult, QueryError> {
        // Projection exprs (may bind params for JSON-metadata fields).
        let mut select_params: Vec<DuckValue> = Vec::new();
        let mut exprs: Vec<String> = Vec::new();
        for col in show {
            exprs.push(self.target_expr(col, &mut select_params)?);
        }
        // The filter selects the `matches`; neighbors come from the UNFILTERED set.
        let mut where_params: Vec<DuckValue> = Vec::new();
        let where_clause = self.build_where(&mut where_params);

        let select_list = exprs.join(", ");
        let dir = if self.ascending { "ASC" } else { "DESC" };
        let limit = self.limit.map_or(String::new(), |l| format!(" LIMIT {l}"));

        // Rank the whole timeline chronologically, then keep any row within ±N
        // ranks of a match. Params appear in TEXT order: the matches-CTE WHERE
        // first, then the outer projection list. `n` is a validated u64 (safe to
        // inline); all analyst values stay bound parameters.
        let mut params: Vec<DuckValue> = where_params;
        params.extend(select_params);
        let sql = format!(
            "WITH ordered AS (\
                 SELECT *, row_number() OVER (ORDER BY timestamp_ns, record_hash, id) AS __rn \
                 FROM timeline\
             ), matches AS (SELECT __rn FROM ordered WHERE {where_clause}) \
             SELECT CASE WHEN o.__rn IN (SELECT __rn FROM matches) THEN 1 ELSE 0 END AS __is_match, \
                    {select_list} \
             FROM ordered o \
             WHERE EXISTS (SELECT 1 FROM matches m WHERE o.__rn BETWEEN m.__rn - {n} AND m.__rn + {n}) \
             ORDER BY o.__rn {dir}{limit}"
        );

        let ncols = show.len();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_slice(&params).as_slice(), |row| {
            let is_match: i64 = row.get(0)?;
            let mut vals = Vec::with_capacity(ncols);
            for i in 0..ncols {
                let v: Option<String> = row.get(i + 1)?;
                vals.push(v.unwrap_or_default());
            }
            Ok((is_match != 0, vals))
        })?;

        // A leading "match" marker column (`>` = match, blank = context), then
        // the requested projections.
        let mut columns: Vec<Column> = std::iter::once(Column {
            name: "match".to_string(),
            values: Vec::new(),
        })
        .chain(show.iter().map(|c| Column {
            name: c.clone(),
            values: Vec::new(),
        }))
        .collect();
        let mut row_count = 0;
        for r in rows {
            let (is_match, vals) = r?;
            columns[0].values.push(if is_match {
                ">".to_string()
            } else {
                String::new()
            });
            for (i, v) in vals.into_iter().enumerate() {
                columns[i + 1].values.push(v);
            }
            row_count += 1;
        }
        Ok(QueryResult {
            columns,
            row_count,
            field_populated: self.field_populated_report(conn)?,
        })
    }

    fn run_count(&self, conn: &Connection) -> Result<QueryResult, QueryError> {
        let mut params: Vec<DuckValue> = Vec::new();
        let where_clause = self.build_where(&mut params);
        let sql = format!("SELECT count(*) FROM timeline WHERE {where_clause}");
        let count: i64 = conn.query_row(&sql, params_slice(&params).as_slice(), |r| r.get(0))?;
        Ok(QueryResult {
            columns: vec![Column {
                name: "count".to_string(),
                values: vec![count.to_string()],
            }],
            row_count: 1,
            field_populated: self.field_populated_report(conn)?,
        })
    }

    fn run_distinct(&self, conn: &Connection, target: &str) -> Result<QueryResult, QueryError> {
        let mut expr_params: Vec<DuckValue> = Vec::new();
        let expr = self.target_expr(target, &mut expr_params)?;
        let mut params: Vec<DuckValue> = expr_params.clone();
        let where_clause = self.build_where(&mut params);
        let sql = format!(
            "SELECT DISTINCT {expr} AS value FROM timeline WHERE {where_clause} \
             ORDER BY value {dir}",
            dir = if self.ascending { "ASC" } else { "DESC" }
        );
        let values = self.collect_single_column(conn, &sql, &params)?;
        let row_count = values.len();
        Ok(QueryResult {
            columns: vec![Column {
                name: target.to_string(),
                values,
            }],
            row_count,
            field_populated: self.field_populated_for_target(conn, target)?,
        })
    }

    fn run_group_by(&self, conn: &Connection, target: &str) -> Result<QueryResult, QueryError> {
        let mut expr_params: Vec<DuckValue> = Vec::new();
        let expr = self.target_expr(target, &mut expr_params)?;
        // Bind params in statement order: the SELECT-expr param(s) (before
        // WHERE), then the WHERE filter params. GROUP BY references the SELECT
        // value by ORDINAL POSITION (`GROUP BY 1`) — the json_extract expr is
        // parameterized, so repeating it verbatim makes DuckDB treat the two as
        // distinct exprs ("metadata must appear in GROUP BY"); grouping by
        // position binds the param once and matches the SELECT exactly.
        let mut params: Vec<DuckValue> = expr_params;
        let where_clause = self.build_where(&mut params);
        let sql = format!(
            "SELECT {expr} AS value, count(*) AS count FROM timeline WHERE {where_clause} \
             GROUP BY 1 ORDER BY count {dir}, value ASC",
            dir = if self.ascending { "ASC" } else { "DESC" }
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_slice(&params).as_slice(), |row| {
            let value: Option<String> = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((value.unwrap_or_default(), count.to_string()))
        })?;
        let mut values = Vec::new();
        let mut counts = Vec::new();
        for r in rows {
            let (v, c) = r?;
            values.push(v);
            counts.push(c);
        }
        let row_count = values.len();
        Ok(QueryResult {
            columns: vec![
                Column {
                    name: target.to_string(),
                    values,
                },
                Column {
                    name: "count".to_string(),
                    values: counts,
                },
            ],
            row_count,
            field_populated: self.field_populated_for_target(conn, target)?,
        })
    }

    fn run_extreme(&self, conn: &Connection, first: bool) -> Result<QueryResult, QueryError> {
        let mut params: Vec<DuckValue> = Vec::new();
        let where_clause = self.build_where(&mut params);
        let dir = if first { "ASC" } else { "DESC" };
        let sql = format!(
            "SELECT timestamp_ns, timestamp_display, event_type, source, artifact_path \
             FROM timeline WHERE {where_clause} \
             ORDER BY timestamp_ns {dir}, record_hash {dir}, id {dir} LIMIT 1"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(params_slice(&params).as_slice(), |row| {
            Ok([
                row.get::<_, i64>(0)?.to_string(),
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ])
        })?;
        let headers = [
            "timestamp_ns",
            "timestamp_display",
            "event_type",
            "source",
            "artifact_path",
        ];
        let mut columns: Vec<Column> = headers
            .iter()
            .map(|h| Column {
                name: (*h).to_string(),
                values: Vec::new(),
            })
            .collect();
        let mut row_count = 0;
        if let Some(r) = rows.next() {
            let vals = r?;
            for (i, v) in vals.iter().enumerate() {
                columns[i].values.push(v.clone());
            }
            row_count = 1;
        }
        Ok(QueryResult {
            columns,
            row_count,
            field_populated: self.field_populated_report(conn)?,
        })
    }

    fn run_rows(&self, conn: &Connection, show: &[String]) -> Result<QueryResult, QueryError> {
        if let Some(n) = self.context {
            return self.run_rows_context(conn, show, n);
        }
        // Build each projection expression (binding field keys), then WHERE.
        let mut select_params: Vec<DuckValue> = Vec::new();
        let mut exprs: Vec<String> = Vec::new();
        for col in show {
            let e = self.target_expr(col, &mut select_params)?;
            exprs.push(e);
        }
        let mut params: Vec<DuckValue> = select_params;
        let where_clause = self.build_where(&mut params);
        let dir = if self.ascending { "ASC" } else { "DESC" };
        let limit = self.limit.map_or(String::new(), |l| format!(" LIMIT {l}"));
        let select_list = exprs.join(", ");
        let sql = format!(
            "SELECT {select_list} FROM timeline WHERE {where_clause} \
             ORDER BY timestamp_ns {dir}, record_hash {dir}, id {dir}{limit}"
        );
        let n = show.len();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_slice(&params).as_slice(), |row| {
            let mut vals = Vec::with_capacity(n);
            for i in 0..n {
                let v: Option<String> = row.get(i)?;
                vals.push(v.unwrap_or_default());
            }
            Ok(vals)
        })?;
        let mut columns: Vec<Column> = show
            .iter()
            .map(|c| Column {
                name: c.clone(),
                values: Vec::new(),
            })
            .collect();
        let mut row_count = 0;
        for r in rows {
            let vals = r?;
            for (i, v) in vals.into_iter().enumerate() {
                columns[i].values.push(v);
            }
            row_count += 1;
        }
        Ok(QueryResult {
            columns,
            row_count,
            field_populated: self.field_populated_report(conn)?,
        })
    }

    fn field_populated_for_target(
        &self,
        conn: &Connection,
        target: &str,
    ) -> Result<Vec<(String, bool)>, QueryError> {
        let mut out = self.field_populated_report(conn)?;
        if let Some(field) = FieldRegistry::resolve(target) {
            if !out.iter().any(|(n, _)| n == field.name) {
                out.push((
                    field.name.to_string(),
                    field_is_populated(conn, field.json_key)?,
                ));
            }
        }
        Ok(out)
    }

    fn collect_single_column(
        &self,
        conn: &Connection,
        sql: &str,
        params: &[DuckValue],
    ) -> Result<Vec<String>, QueryError> {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params_slice(params).as_slice(), |row| {
            let v: Option<String> = row.get(0)?;
            Ok(v.unwrap_or_default())
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

/// Intent-verb presets (design Phase 2): each returns a [`TypedQuery`] whose
/// event-type set, default mode, and baseline filters encode one analyst
/// question. CLI verbs layer their per-run flags (`--service`, `--host`, `--ip`,
/// `--path`, …) on top of these defaults — the preset is the *floor*, never a
/// special case. All values are constants here; analyst input still binds as a
/// parameter when it reaches [`TypedQuery::run`].
pub mod presets {
    use super::{FieldInFilter, FieldRegistry, Mode, TypedQuery};

    fn ev(types: &[&str]) -> Vec<String> {
        types.iter().map(|s| (*s).to_string()).collect()
    }

    /// `logons`: interactive/remote-interactive/cached logons, machine accounts
    /// dropped, distinct users. `LogonType IN (2, 10, 11)` (interactive, RDP,
    /// cached-interactive). Mirrors the deck's B4/B5 question.
    #[must_use]
    pub fn logons() -> TypedQuery {
        TypedQuery {
            event_types: ev(&["LogonSuccess"]),
            in_filters: vec![FieldInFilter {
                field: FieldRegistry::resolve("logon-type")
                    .expect("logon-type is a registry field"),
                values: ev(&["2", "10", "11"]),
            }],
            exclude_machine_accounts: true,
            mode: Mode::Distinct {
                target: "user".to_string(),
            },
            ..TypedQuery::default()
        }
    }

    /// `files`: filesystem activity (create/modify/delete/rename) — the analyst
    /// adds `--path`/`--first`/`--last`. Default mode is rows.
    #[must_use]
    pub fn files() -> TypedQuery {
        TypedQuery {
            event_types: ev(&["FileCreate", "FileModify", "FileDelete", "FileRename"]),
            ..TypedQuery::default()
        }
    }

    /// `persistence`: service install/start, registry modification, scheduled
    /// task — the analyst narrows with `--service`/`--registry-key`. Rows mode.
    #[must_use]
    pub fn persistence() -> TypedQuery {
        TypedQuery {
            event_types: ev(&[
                "ServiceInstall",
                "ServiceStart",
                "RegistryModify",
                "ScheduledTaskRun",
            ]),
            ..TypedQuery::default()
        }
    }

    /// `hosts`: network/lateral-movement events keyed by remote host — the
    /// analyst adds `--host`/`--port`. Rows mode.
    #[must_use]
    pub fn hosts() -> TypedQuery {
        TypedQuery {
            event_types: ev(&[
                "NetworkConnectionIPv4",
                "NetworkConnectionIPv6",
                "LogonSuccess",
                "SMBConnect",
            ]),
            ..TypedQuery::default()
        }
    }
}

/// Whether ANY row in the case populates a given JSON metadata key.
fn field_is_populated(conn: &Connection, json_key: &str) -> Result<bool, QueryError> {
    let sql = "SELECT count(*) > 0 FROM timeline \
               WHERE json_extract_string(metadata, '$.' || ?) IS NOT NULL";
    let populated: bool = conn.query_row(sql, [json_key], |r| r.get(0))?;
    Ok(populated)
}

/// Escape SQL LIKE metacharacters in a literal value used inside a `%…%`
/// contains pattern, so an analyst `%`/`_` does not silently widen the match.
fn like_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn params_slice(params: &[DuckValue]) -> Vec<&dyn duckdb::ToSql> {
    params.iter().map(|p| p as &dyn duckdb::ToSql).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_resolves_canonical_names_and_aliases() {
        assert_eq!(
            FieldRegistry::resolve("ip").expect("ip field").json_key,
            "IpAddress"
        );
        assert_eq!(
            FieldRegistry::resolve("user").expect("user field").json_key,
            "TargetUserName"
        );
        assert_eq!(
            FieldRegistry::resolve("logon-type")
                .expect("logon-type field")
                .json_key,
            "LogonType"
        );
        // alias
        assert_eq!(
            FieldRegistry::resolve("targetlogonid")
                .expect("logon-id alias")
                .json_key,
            "TargetLogonId"
        );
        assert!(FieldRegistry::resolve("nope").is_none());
    }

    #[test]
    fn registry_covers_the_six_required_fields() {
        for name in [
            "ip",
            "user",
            "logon-type",
            "service",
            "workstation",
            "logon-id",
        ] {
            assert!(
                FieldRegistry::resolve(name).is_some(),
                "registry must cover {name}"
            );
        }
    }

    #[test]
    fn glob_compiles_and_escapes_metacharacters() {
        // glob wildcards translate; analyst literal %/_ are escaped.
        assert_eq!(glob_to_like("*coreupdater*"), "%coreupdater%");
        assert_eq!(glob_to_like("a?b"), "a_b");
        assert_eq!(glob_to_like("100%_x"), "100\\%\\_x");
    }

    #[test]
    fn like_escape_neutralises_metacharacters() {
        assert_eq!(like_escape("a%b_c"), "a\\%b\\_c");
        assert_eq!(like_escape(r"x\y"), r"x\\y");
    }

    use crate::store::TimelineStore;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};

    fn seeded() -> TimelineStore {
        let store = TimelineStore::in_memory().expect("store");
        let logon = TimelineEvent::new(
            1_000,
            "2020-09-19T03:24:06Z".into(),
            EventType::Other("LogonSuccess".into()),
            ArtifactType::EventLog,
            "Security.evtx".into(),
            "logon".into(),
            "CASE".into(),
        )
        .with_metadata("IpAddress", serde_json::json!("10.42.85.115"))
        .with_metadata("TargetUserName", serde_json::json!("rick"))
        .with_metadata("LogonType", serde_json::json!("2"));
        let machine = TimelineEvent::new(
            2_000,
            "2020-09-19T03:25:00Z".into(),
            EventType::Other("LogonSuccess".into()),
            ArtifactType::EventLog,
            "Security.evtx".into(),
            "logon".into(),
            "CASE".into(),
        )
        .with_metadata("IpAddress", serde_json::json!("10.42.85.10"))
        .with_metadata("TargetUserName", serde_json::json!("CITADEL-DC01$"))
        .with_metadata("LogonType", serde_json::json!("2"));
        let file = TimelineEvent::new(
            3_000,
            "2020-09-19T03:26:00Z".into(),
            EventType::FileCreate,
            ArtifactType::Mft,
            "C:/coreupdater.exe".into(),
            "file".into(),
            "CASE".into(),
        );
        store.insert_event(&logon).expect("insert");
        store.insert_event(&machine).expect("insert");
        store.insert_event(&file).expect("insert");
        store
    }

    fn event_type_is(name: &str) -> Vec<String> {
        // The store records event_type via Debug formatting; Other("X") renders
        // as `Other("X")`. Match what the store actually stored.
        vec![format!("Other(\"{name}\")")]
    }

    #[test]
    fn ip_filter_extracts_metadata_field() {
        let store = seeded();
        let q = TypedQuery {
            event_types: event_type_is("LogonSuccess"),
            fields: vec![FieldFilter {
                field: FieldRegistry::resolve("ip").expect("ip field"),
                op: FieldOp::Eq,
                value: "10.42.85.115".into(),
            }],
            mode: Mode::Count,
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("count");
        assert_eq!(r.columns[0].values[0], "1");
    }

    #[test]
    fn path_filter_matches_case_insensitively() {
        // Windows evidence stores the same logical path in different cases across
        // sources (USN vs MFT vs registry), and NTFS paths are case-insensitive.
        // An analyst who types a different case must NOT silently miss the
        // artifact. `seeded()` stores `C:/coreupdater.exe` lowercase; an UPPERCASE
        // glob must still match it. Case-sensitive LIKE returns 0 (silent miss);
        // ILIKE returns 1.
        let store = seeded();
        let q = TypedQuery {
            path: Some("*COREUPDATER*".into()),
            mode: Mode::Count,
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("count");
        assert_eq!(
            r.columns[0].values[0], "1",
            "an uppercase --path glob must match a lowercase-stored path \
             (case-insensitive matching); a silent miss loses evidence"
        );
    }

    #[test]
    fn exclude_machine_accounts_drops_dollar_users() {
        let store = seeded();
        let q = TypedQuery {
            event_types: event_type_is("LogonSuccess"),
            exclude_machine_accounts: true,
            mode: Mode::Distinct {
                target: "user".into(),
            },
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("distinct");

        assert_eq!(
            r.columns[0].values,
            vec!["rick".to_string()],
            "CITADEL-DC01$ machine account must be dropped"
        );
    }

    #[test]
    fn group_by_metadata_field_does_not_error() {
        // Regression: GROUP BY on a JSON metadata field (e.g. `ip`) must not trip
        // DuckDB's binder ("metadata must appear in GROUP BY"). The json_extract
        // expr is parameterized, so it cannot be repeated verbatim in GROUP BY —
        // group by ordinal position instead.
        let store = seeded();
        let q = TypedQuery {
            event_types: event_type_is("LogonSuccess"),
            mode: Mode::GroupBy {
                target: "ip".into(),
            },
            ..Default::default()
        };
        let r = q
            .run(store.connection())
            .expect("group-by on a json field must not error");
        assert_eq!(r.columns.len(), 2, "value + count columns");
        assert_eq!(r.columns[1].name, "count");
        assert!(r.row_count >= 1, "expected at least one grouped Ip value");
    }

    #[test]
    fn injection_payload_binds_as_parameter_not_sql() {
        // A --path value containing SQL metacharacters/quotes must bind as a
        // parameter and break out of NOTHING — it simply matches no rows. The
        // table also survives (read-only handle would block a write regardless).
        let store = seeded();
        let q = TypedQuery {
            path: Some("'; DROP TABLE timeline;--".into()),
            mode: Mode::Count,
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("must not error or inject");
        assert_eq!(r.columns[0].values[0], "0");
        // table intact
        let n: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM timeline", [], |r| r.get(0))
            .expect("table survives");
        assert_eq!(n, 3);
    }

    #[test]
    fn context_surfaces_neighbors_around_each_match() {
        // seeded() in time order: logon(1000), machine(2000), file/coreupdater(3000).
        // Match only the file, ask for 1 neighbor each side -> file + its
        // predecessor machine = 2 rows; the file is flagged, machine is context.
        let store = seeded();
        let q = TypedQuery {
            path: Some("*coreupdater*".into()),
            context: Some(1),
            mode: Mode::Rows {
                show: vec!["event_type".into()],
            },
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("context query");
        assert_eq!(r.row_count, 2, "the match plus its one predecessor");
        let marker = r
            .columns
            .iter()
            .find(|c| c.name == "match")
            .expect("a leading match-marker column");
        assert_eq!(marker.values.len(), 2);
        assert_eq!(
            marker.values.iter().filter(|m| m.as_str() == ">").count(),
            1,
            "exactly one row is the match; the other is context"
        );
    }

    #[test]
    fn stats_summarizes_total_span_and_top_breakdowns() {
        // seeded() = 3 events: 2 LogonSuccess (EventLog), 1 FileCreate (Mft),
        // spanning 2020-09-19T03:24..03:26.
        let store = seeded();
        let q = TypedQuery {
            mode: Mode::Stats,
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("stats");
        assert_eq!(r.columns.len(), 2, "a (metric, value) table");
        let rows: Vec<(&str, &str)> = r.columns[0]
            .values
            .iter()
            .zip(&r.columns[1].values)
            .map(|(m, v)| (m.as_str(), v.as_str()))
            .collect();
        let get = |k: &str| rows.iter().find(|(m, _)| *m == k).map(|(_, v)| *v);
        assert_eq!(get("total"), Some("3"), "total respects the matched set");
        assert!(get("earliest").is_some(), "earliest present: {rows:?}");
        assert!(get("latest").is_some(), "latest present");
        // Top event-type breakdown: LogonSuccess (2) outranks FileCreate (1).
        let lt = rows
            .iter()
            .find(|(m, _)| m.contains("LogonSuccess"))
            .expect("top event_type listed");
        assert_eq!(lt.1, "2", "LogonSuccess count");
        // Top source breakdown present (EventLog appears twice).
        assert!(
            rows.iter().any(|(m, _)| m.contains("EventLog")),
            "top source listed: {rows:?}"
        );
    }

    #[test]
    fn unknown_target_fails_loud_not_empty() {
        let store = seeded();
        let q = TypedQuery {
            mode: Mode::Distinct {
                target: "nonexistent-field".into(),
            },
            ..Default::default()
        };
        let err = q.run(store.connection()).expect_err("must fail loud");
        match err {
            QueryError::UnknownTarget { target, valid } => {
                assert_eq!(target, "nonexistent-field");
                assert!(valid.contains("ip"), "must list valid fields");
            }
            other => panic!("expected UnknownTarget, got {other:?}"),
        }
    }

    #[test]
    fn empty_result_reports_field_populated_true_when_present() {
        let store = seeded();
        // ip IS populated, but no row matches this value ⇒ genuine empty.
        let q = TypedQuery {
            event_types: event_type_is("LogonSuccess"),
            fields: vec![FieldFilter {
                field: FieldRegistry::resolve("ip").expect("ip field"),
                op: FieldOp::Eq,
                value: "203.0.113.99".into(),
            }],
            mode: Mode::Count,
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("count");
        assert_eq!(r.columns[0].values[0], "0");
        assert_eq!(
            r.field_populated,
            vec![("ip".to_string(), true)],
            "ip must report populated=true (genuine empty, not coverage gap)"
        );
    }

    #[test]
    fn empty_result_reports_field_absent_when_never_present() {
        let store = seeded();
        // service is NEVER populated in this seed ⇒ coverage gap, not clean.
        let q = TypedQuery {
            fields: vec![FieldFilter {
                field: FieldRegistry::resolve("service").expect("service field"),
                op: FieldOp::Eq,
                value: "coreupdater".into(),
            }],
            mode: Mode::Count,
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("count");
        assert_eq!(r.columns[0].values[0], "0");
        assert_eq!(r.field_populated, vec![("service".to_string(), false)]);
    }

    #[test]
    fn path_first_returns_min_timestamp_row() {
        let store = seeded();
        let q = TypedQuery {
            path: Some("*coreupdater*".into()),
            mode: Mode::Extreme { first: true },
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("first");
        assert_eq!(r.row_count, 1);
        assert_eq!(r.columns[0].values[0], "3000"); // timestamp_ns of the file row
    }

    #[test]
    fn group_by_event_type_histogram() {
        let store = seeded();
        let q = TypedQuery {
            mode: Mode::GroupBy {
                target: "event-type".into(),
            },
            ascending: false,
            ..Default::default()
        };
        let r = q.run(store.connection()).expect("group-by");
        // Two LogonSuccess + one FileCreate.
        let logon_idx = r.columns[0]
            .values
            .iter()
            .position(|v| v.contains("LogonSuccess"))
            .expect("logon bucket");
        assert_eq!(r.columns[1].values[logon_idx], "2");
    }

    // --- Phase 2: range op + set-membership filters -----------------------

    #[test]
    fn range_op_filters_numeric_logon_type() {
        // The seed has two LogonType=2 logons. `logon-type >= 2` (Range::Ge)
        // must compare numerically (TRY_CAST), matching both. `>= 3` matches
        // none (both are exactly 2).
        let store = seeded();
        let ge2 = TypedQuery {
            event_types: event_type_is("LogonSuccess"),
            fields: vec![FieldFilter {
                field: FieldRegistry::resolve("logon-type").expect("logon-type"),
                op: FieldOp::Ge,
                value: "2".into(),
            }],
            mode: Mode::Count,
            ..Default::default()
        };
        assert_eq!(
            ge2.run(store.connection()).expect("ge2").columns[0].values[0],
            "2"
        );

        let gt2 = TypedQuery {
            event_types: event_type_is("LogonSuccess"),
            fields: vec![FieldFilter {
                field: FieldRegistry::resolve("logon-type").expect("logon-type"),
                op: FieldOp::Gt,
                value: "2".into(),
            }],
            mode: Mode::Count,
            ..Default::default()
        };
        assert_eq!(
            gt2.run(store.connection()).expect("gt2").columns[0].values[0],
            "0"
        );
    }

    #[test]
    fn in_filter_set_membership_binds_each_value() {
        // LogonType IN ('2') matches the two type-2 logons; IN ('10','11')
        // matches none in this seed. Each value binds as a parameter.
        let store = seeded();
        let in2 = TypedQuery {
            event_types: event_type_is("LogonSuccess"),
            in_filters: vec![FieldInFilter {
                field: FieldRegistry::resolve("logon-type").expect("logon-type"),
                values: vec!["2".into()],
            }],
            mode: Mode::Count,
            ..Default::default()
        };
        assert_eq!(
            in2.run(store.connection()).expect("in2").columns[0].values[0],
            "2"
        );

        let in10 = TypedQuery {
            event_types: event_type_is("LogonSuccess"),
            in_filters: vec![FieldInFilter {
                field: FieldRegistry::resolve("logon-type").expect("logon-type"),
                values: vec!["10".into(), "11".into()],
            }],
            mode: Mode::Count,
            ..Default::default()
        };
        assert_eq!(
            in10.run(store.connection()).expect("in10").columns[0].values[0],
            "0"
        );
    }

    #[test]
    fn in_filter_injection_value_binds_not_interpolated() {
        let store = seeded();
        let q = TypedQuery {
            in_filters: vec![FieldInFilter {
                field: FieldRegistry::resolve("logon-type").expect("logon-type"),
                values: vec!["2') OR 1=1 --".into()],
            }],
            mode: Mode::Count,
            ..Default::default()
        };
        // The payload binds as a literal value → matches nothing, never injects.
        assert_eq!(
            q.run(store.connection()).expect("bound").columns[0].values[0],
            "0"
        );
        let n: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM timeline", [], |r| r.get(0))
            .expect("table survives");
        assert_eq!(n, 3);
    }

    #[test]
    fn preset_logons_shape() {
        let q = presets::logons();
        assert_eq!(q.event_types, vec!["LogonSuccess".to_string()]);
        assert!(q.exclude_machine_accounts);
        assert_eq!(q.in_filters.len(), 1);
        assert_eq!(q.in_filters[0].field.name, "logon-type");
        assert_eq!(q.in_filters[0].values, vec!["2", "10", "11"]);
        assert!(matches!(q.mode, Mode::Distinct { ref target } if target == "user"));
    }

    #[test]
    fn preset_files_shape() {
        let q = presets::files();
        assert_eq!(
            q.event_types,
            vec!["FileCreate", "FileModify", "FileDelete", "FileRename"]
        );
        assert!(matches!(q.mode, Mode::Rows { .. }));
    }

    #[test]
    fn preset_persistence_shape() {
        let q = presets::persistence();
        assert_eq!(
            q.event_types,
            vec![
                "ServiceInstall",
                "ServiceStart",
                "RegistryModify",
                "ScheduledTaskRun"
            ]
        );
        assert!(matches!(q.mode, Mode::Rows { .. }));
    }

    #[test]
    fn preset_hosts_shape() {
        let q = presets::hosts();
        assert_eq!(
            q.event_types,
            vec![
                "NetworkConnectionIPv4",
                "NetworkConnectionIPv6",
                "LogonSuccess",
                "SMBConnect"
            ]
        );
    }

    #[test]
    fn time_window_from_to_bounds_the_timeline() {
        // seeded() has events at timestamp_ns 1000 (logon), 2000 (machine),
        // 3000 (file). --from/--to scope to the incident window, inclusive.
        let store = seeded();
        let count = |from: Option<i64>, to: Option<i64>| {
            let q = TypedQuery {
                from_ns: from,
                to_ns: to,
                mode: Mode::Count,
                ..Default::default()
            };
            q.run(store.connection()).expect("count").columns[0].values[0].clone()
        };
        assert_eq!(count(None, None), "3", "no bound = all");
        assert_eq!(count(Some(2_000), None), "2", "from 2000 = machine + file");
        assert_eq!(count(None, Some(2_000)), "2", "to 2000 = logon + machine");
        assert_eq!(
            count(Some(2_000), Some(2_000)),
            "1",
            "[2000,2000] = machine only"
        );
    }
}
