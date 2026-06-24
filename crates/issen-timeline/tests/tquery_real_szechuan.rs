//! Tier-2 acceptance: the typed query layer must reproduce, byte-for-byte, the
//! result of the equivalent RAW SQL run via the duckdb crate on the SAME real
//! Case 001 DB (`g1-rerun/dc01.duckdb`). The raw SQL is the independent oracle —
//! the very thing this typed layer replaces — so correctness is anchored to real
//! engine output, not a synthetic fixture we authored (Doer-Checker).
//!
//! Env-gated: skips cleanly when the DB is absent (large artifact, gitignored).

use std::path::PathBuf;

use duckdb::Connection;
use issen_timeline::tquery::{
    open_read_only, presets, FieldFilter, FieldInFilter, FieldOp, FieldRegistry, Mode, TypedQuery,
};

const DEFAULT_DB: &str =
    "/Users/4n6h4x0r/src/issen/tests/data/dfirmadness-szechuan-sauce/g1-rerun/dc01.duckdb";

fn dc01() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ISSEN_SZECHUAN_DC01_DUCKDB") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let p = PathBuf::from(DEFAULT_DB);
    p.exists().then_some(p)
}

/// Run a raw single-value SQL on the SAME read-only DB — the independent oracle.
fn raw_scalar(conn: &Connection, sql: &str) -> String {
    conn.query_row(sql, [], |r| {
        // values come back as i64 or string; normalise to string
        let as_i64: Result<i64, _> = r.get(0);
        match as_i64 {
            Ok(n) => Ok(n.to_string()),
            Err(_) => r.get::<_, String>(0),
        }
    })
    .expect("oracle scalar")
}

fn raw_column(conn: &Connection, sql: &str) -> Vec<String> {
    let mut stmt = conn.prepare(sql).expect("prepare oracle");
    let rows = stmt
        .query_map([], |r| {
            let v: Option<String> = r.get(0)?;
            Ok(v.unwrap_or_default())
        })
        .expect("oracle map");
    rows.map(|r| r.expect("oracle row")).collect()
}

/// Open the real DB read-only, or `None` to skip (env-gated, large artifact).
fn conn() -> Option<Connection> {
    let db = dc01()?;
    Some(open_read_only(&db).expect("read-only open"))
}

/// (a) Q4 — event_type histogram (`--group-by event-type`), default DESC.
#[test]
fn deck_a_q4_event_type_histogram() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let q = TypedQuery {
        mode: Mode::GroupBy {
            target: "event-type".into(),
        },
        ascending: false,
        ..Default::default()
    };
    let got = q.run(&conn).expect("group-by");
    let oracle_vals = raw_column(
        &conn,
        "SELECT event_type FROM timeline GROUP BY event_type \
         ORDER BY count(*) DESC, event_type ASC",
    );
    assert_eq!(
        got.columns[0].values, oracle_vals,
        "(a) Q4 histogram values must equal the raw-SQL oracle"
    );
    let top_count = raw_scalar(
        &conn,
        "SELECT count(*) FROM timeline WHERE event_type='RegistryModify'",
    );
    assert_eq!(got.columns[1].values[0], top_count);
}

/// (b) Q6.5 — first-seen `--path '*coreupdater*' --first`.
#[test]
fn deck_b_q65_coreupdater_first_seen() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let q = TypedQuery {
        path: Some("*coreupdater*".into()),
        mode: Mode::Extreme { first: true },
        ..Default::default()
    };
    let got = q.run(&conn).expect("first");
    let oracle = raw_scalar(
        &conn,
        "SELECT min(timestamp_ns) FROM timeline WHERE artifact_path LIKE '%coreupdater%'",
    );
    assert_eq!(
        got.columns[0].values[0], oracle,
        "(b) Q6.5 first-seen ns must equal the raw-SQL oracle"
    );
}

/// (c) B4/B5 — `--event-type LogonSuccess --logon-type 2,10,11
/// --exclude-machine-accounts --distinct user`. The deck's multi-value
/// `--logon-type` is OR semantics; the typed Phase-1 surface expresses one value
/// per run, so the union of the three runs must equal the raw IN-list oracle.
#[test]
fn deck_c_b4b5_interactive_users() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let oracle = raw_column(
        &conn,
        "SELECT DISTINCT json_extract_string(metadata,'$.TargetUserName') v \
         FROM timeline WHERE event_type='LogonSuccess' \
         AND json_extract_string(metadata,'$.LogonType') IN ('2','10','11') \
         AND (json_extract_string(metadata,'$.TargetUserName') IS NULL \
              OR json_extract_string(metadata,'$.TargetUserName') NOT LIKE '%\\$' ESCAPE '\\') \
         ORDER BY v",
    );
    let mut union: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for lt in ["2", "10", "11"] {
        let qq = TypedQuery {
            event_types: vec!["LogonSuccess".into()],
            fields: vec![FieldFilter {
                field: FieldRegistry::resolve("logon-type").expect("logon-type field"),
                op: FieldOp::Eq,
                value: lt.into(),
            }],
            exclude_machine_accounts: true,
            mode: Mode::Distinct {
                target: "user".into(),
            },
            ..Default::default()
        };
        for v in qq.run(&conn).expect("distinct user").columns[0]
            .values
            .clone()
        {
            union.insert(v);
        }
    }
    let union_vec: Vec<String> = union.into_iter().collect();
    assert_eq!(
        union_vec, oracle,
        "(c) B4/B5 interactive non-machine users must equal the raw-SQL oracle"
    );
}

/// (d) `--ip` logon filter (count of LogonSuccess from 10.42.85.115).
#[test]
fn deck_d_ip_logon_count() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let q = TypedQuery {
        event_types: vec!["LogonSuccess".into()],
        fields: vec![FieldFilter {
            field: FieldRegistry::resolve("ip").expect("ip field"),
            op: FieldOp::Eq,
            value: "10.42.85.115".into(),
        }],
        mode: Mode::Count,
        ..Default::default()
    };
    let got = q.run(&conn).expect("ip count");
    let oracle = raw_scalar(
        &conn,
        "SELECT count(*) FROM timeline WHERE event_type='LogonSuccess' \
         AND json_extract_string(metadata,'$.IpAddress')='10.42.85.115'",
    );
    assert_eq!(
        got.columns[0].values[0], oracle,
        "(d) --ip LogonSuccess count must equal the raw-SQL oracle"
    );
}

/// (e) `--count` total LogonSuccess.
#[test]
fn deck_e_logon_success_count() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let q = TypedQuery {
        event_types: vec!["LogonSuccess".into()],
        mode: Mode::Count,
        ..Default::default()
    };
    let got = q.run(&conn).expect("count");
    let oracle = raw_scalar(
        &conn,
        "SELECT count(*) FROM timeline WHERE event_type='LogonSuccess'",
    );
    assert_eq!(
        got.columns[0].values[0], oracle,
        "(e) total LogonSuccess count must equal the raw-SQL oracle"
    );
}

#[test]
fn injection_value_is_bound_not_interpolated_on_real_db() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    // A classic SQL-injection payload as a --path value. If interpolated it would
    // break out / drop the table; bound as a parameter it simply matches no rows
    // and the table survives. The read-only handle also makes a DROP impossible.
    let q = TypedQuery {
        path: Some("'; DROP TABLE timeline;--".into()),
        mode: Mode::Count,
        ..Default::default()
    };
    let got = q.run(&conn).expect("injection path must not error");
    assert_eq!(
        got.columns[0].values[0], "0",
        "injection payload must bind as a literal LIKE value (0 matches)"
    );
    // Table still present and intact.
    let still: String = conn
        .query_row("SELECT count(*) FROM timeline", [], |r| {
            Ok(r.get::<_, i64>(0)?.to_string())
        })
        .expect("timeline table must still exist");
    assert_ne!(still, "0", "timeline must survive the injection attempt");
}

// --- Phase 2: intent-verb presets vs the raw-SQL oracle ------------------
//
// Each verb's preset (plus the per-run flags the CLI verb would add) must
// reproduce the equivalent raw IN-list / WHERE SQL on the SAME real DB.

/// `logons` verb: `LogonType IN (2,10,11)`, machine accounts excluded, distinct
/// user — one single typed query (the in_filters set), equal to the raw oracle.
#[test]
fn verb_logons_distinct_interactive_users() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let q = presets::logons();
    let got = q.run(&conn).expect("logons distinct user");
    let oracle = raw_column(
        &conn,
        "SELECT DISTINCT json_extract_string(metadata,'$.TargetUserName') v \
         FROM timeline WHERE event_type='LogonSuccess' \
         AND json_extract_string(metadata,'$.LogonType') IN ('2','10','11') \
         AND (json_extract_string(metadata,'$.TargetUserName') IS NULL \
              OR json_extract_string(metadata,'$.TargetUserName') NOT LIKE '%\\$' ESCAPE '\\') \
         ORDER BY v",
    );
    assert_eq!(
        got.columns[0].values, oracle,
        "logons verb must equal the raw IN-list oracle"
    );
}

/// `files` verb + `--path '*coreupdater*'` `--count`: filesystem events whose
/// path matches the glob, equal to the raw File*-IN-list oracle.
#[test]
fn verb_files_path_count() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let mut q = presets::files();
    q.path = Some("*coreupdater*".into());
    q.mode = Mode::Count;
    let got = q.run(&conn).expect("files count");
    let oracle = raw_scalar(
        &conn,
        "SELECT count(*) FROM timeline \
         WHERE event_type IN ('FileCreate','FileModify','FileDelete','FileRename') \
         AND artifact_path LIKE '%coreupdater%'",
    );
    assert_eq!(
        got.columns[0].values[0], oracle,
        "files verb path count must equal the raw-SQL oracle"
    );
}

/// `persistence` verb + `--service coreupdater` `--count`: service/registry/task
/// persistence events for the named service, equal to the raw oracle.
#[test]
fn verb_persistence_service_count() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let mut q = presets::persistence();
    q.fields.push(FieldFilter {
        field: FieldRegistry::resolve("service").expect("service field"),
        op: FieldOp::Eq,
        value: "coreupdater".into(),
    });
    q.mode = Mode::Count;
    let got = q.run(&conn).expect("persistence count");
    let oracle = raw_scalar(
        &conn,
        "SELECT count(*) FROM timeline \
         WHERE event_type IN ('ServiceInstall','ServiceStart','RegistryModify','ScheduledTaskRun') \
         AND json_extract_string(metadata,'$.ServiceName')='coreupdater'",
    );
    assert_eq!(
        got.columns[0].values[0], oracle,
        "persistence verb service count must equal the raw-SQL oracle"
    );
}

/// `hosts` verb + `--host 194.61.24.102` `--count`: network/logon events keyed
/// by the remote host (IpAddress), equal to the raw oracle.
#[test]
fn verb_hosts_ip_count() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let mut q = presets::hosts();
    q.fields.push(FieldFilter {
        field: FieldRegistry::resolve("ip").expect("ip field"),
        op: FieldOp::Eq,
        value: "194.61.24.102".into(),
    });
    q.mode = Mode::Count;
    let got = q.run(&conn).expect("hosts count");
    let oracle = raw_scalar(
        &conn,
        "SELECT count(*) FROM timeline \
         WHERE event_type IN ('NetworkConnectionIPv4','NetworkConnectionIPv6','LogonSuccess','SMBConnect') \
         AND json_extract_string(metadata,'$.IpAddress')='194.61.24.102'",
    );
    assert_eq!(
        got.columns[0].values[0], oracle,
        "hosts verb ip count must equal the raw-SQL oracle"
    );
}

/// A `FieldOp::Ge` range filter on logon-type reproduces the numeric `>=` oracle
/// (the new range op, validated on real data).
#[test]
fn range_op_logon_type_ge_matches_oracle() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let q = TypedQuery {
        event_types: vec!["LogonSuccess".into()],
        fields: vec![FieldFilter {
            field: FieldRegistry::resolve("logon-type").expect("logon-type"),
            op: FieldOp::Ge,
            value: "10".into(),
        }],
        mode: Mode::Count,
        ..Default::default()
    };
    let got = q.run(&conn).expect("range count");
    let oracle = raw_scalar(
        &conn,
        "SELECT count(*) FROM timeline WHERE event_type='LogonSuccess' \
         AND TRY_CAST(json_extract_string(metadata,'$.LogonType') AS BIGINT) >= 10",
    );
    assert_eq!(
        got.columns[0].values[0], oracle,
        "logon-type >= 10 must equal the numeric raw-SQL oracle"
    );
}

/// The set-membership `in_filters` (LogonType IN (2,10,11)) as a single typed
/// query reproduces the raw IN-list count oracle.
#[test]
fn in_filter_logon_type_set_matches_oracle() {
    let Some(conn) = conn() else {
        eprintln!("skipping: dc01.duckdb absent");
        return;
    };
    let q = TypedQuery {
        event_types: vec!["LogonSuccess".into()],
        in_filters: vec![FieldInFilter {
            field: FieldRegistry::resolve("logon-type").expect("logon-type"),
            values: vec!["2".into(), "10".into(), "11".into()],
        }],
        mode: Mode::Count,
        ..Default::default()
    };
    let got = q.run(&conn).expect("in count");
    let oracle = raw_scalar(
        &conn,
        "SELECT count(*) FROM timeline WHERE event_type='LogonSuccess' \
         AND json_extract_string(metadata,'$.LogonType') IN ('2','10','11')",
    );
    assert_eq!(
        got.columns[0].values[0], oracle,
        "logon-type IN (2,10,11) must equal the raw-SQL oracle"
    );
}
