#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::elidable_lifetime_names,
    clippy::match_same_arms,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::field_reassign_with_default,
    clippy::inefficient_to_string,
    clippy::manual_strip,
    clippy::redundant_else,
    clippy::trim_split_whitespace,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::unused_self,
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::missing_fields_in_debug,
    clippy::result_unit_err,
    clippy::unreadable_literal,
    clippy::manual_contains,
    clippy::unnecessary_literal_bound
)]
// Tests opt out of the panic lints (fleet standard) — unwrap/expect in test code.
// Required in lib.rs (not main.rs) since L1 moved the command modules' tests here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Issen CLI library — the single code path for the `issen` binary and every
//! library-linked test harness. `main.rs` is a thin shim calling [`run`]; all
//! force-link anchors live here so the binary and the lib share one parser
//! registry (no lib/bin skew).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use is_terminal::IsTerminal;

// Force-link every parser + container-provider crate so their `inventory::submit!`
// registrations survive dead-code elimination, in BOTH the binary and every
// library-linked test harness. The anchor SET is now owned by two aggregator
// umbrellas whose `build.rs` generates one `extern crate <dep> as _;` per
// dependency from their own `Cargo.toml` — adding a parser/provider is one dep
// edit there, never a hand-written `extern crate` line here. These two root
// anchors are MANDATORY and must be real item references: a bare dependency or a
// passive `pub use` does NOT guarantee the link edge that pulls the aggregators
// (and their generated anchor sets) into the link.
extern crate issen_parsers as _;
extern crate issen_providers as _;

pub mod banner;
pub mod commands;
pub mod ingest_progress;
pub mod parsers;
pub mod progress_view;
pub mod scanning;

/// When to emit ANSI color codes.
#[derive(ValueEnum, Debug, Clone, Copy, Default)]
pub enum ColorChoice {
    /// Emit colors only when stdout is an interactive terminal (default).
    #[default]
    Auto,
    /// Always emit ANSI color codes.
    Always,
    /// Never emit ANSI color codes.
    Never,
}

/// Decide whether tracing should emit ANSI color, given the color policy, whether
/// stdout is a tty, and whether the terminal actually renders ANSI.
///
/// `Auto` requires BOTH a tty AND an ANSI-capable terminal: `is_terminal()` alone
/// is the wrong predicate because a Windows legacy console IS a tty yet does not
/// render ANSI (escapes would garble). On a Mac/Linux interactive terminal both
/// hold, so colors are kept; a piped/redirected stream isn't a tty, so it's clean.
fn should_use_ansi(color: ColorChoice, stdout_is_tty: bool, ansi_capable: bool) -> bool {
    match color {
        ColorChoice::Never => false,
        ColorChoice::Always => true,
        ColorChoice::Auto => stdout_is_tty && ansi_capable,
    }
}

/// Lower the shared verb flags ([`VerbCli`]) into the command layer's
/// [`commands::timeline_verbs::VerbCommon`] (the verb-agnostic aggregation bag).
fn verb_common(args: VerbCli) -> commands::timeline_verbs::VerbCommon {
    commands::timeline_verbs::VerbCommon {
        count: args.count,
        distinct: args.distinct,
        group_by: args.group_by,
        first: args.first,
        last: args.last,
        show: args.show,
        sort_desc: args.descending,
        limit: args.limit,
        format: args.format,
    }
}

/// Issen — fast forensic triage for incident responders.
#[derive(Parser, Debug)]
#[command(name = "issen", version, about, before_help = banner::BANNER)]
pub struct Cli {
    /// Enable verbose/debug logging.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Control ANSI color output: auto (default), always, or never.
    #[arg(long, global = true, default_value = "auto", value_name = "WHEN")]
    color: ColorChoice,

    #[command(subcommand)]
    command: Commands,
}

// The top-level dispatch enum is constructed exactly once per process (clap
// parses argv into a single value), so the stack-vs-heap concern behind
// `large_enum_variant` does not apply here — boxing every wide subcommand would
// only add indirection to a one-shot value. The variants are intentionally flat
// argument bags.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Rapid triage of a UAC or supported collection — rootkits, hidden processes, network.
    Analyse {
        /// Path to the collection file (UAC .tar.gz, zip, etc.).
        #[arg(value_name = "COLLECTION_PATH")]
        collection_path: PathBuf,
    },

    /// Ingest a case directory and surface cross-artifact Correlated Findings.
    Correlate {
        /// Path to the case directory holding the evidence to correlate.
        #[arg(value_name = "CASE_DIR")]
        case_dir: PathBuf,
    },

    /// Ingest evidence and parse artifacts into a timeline.
    Ingest {
        /// One or more evidence paths (file, directory, or a folder of disk
        /// images). Multiple inputs build one unified timeline, each tagged with
        /// a distinct per-source id for cross-host correlation.
        #[arg(value_name = "EVIDENCE_PATH", required = true, num_args = 1..)]
        evidence_paths: Vec<PathBuf>,

        /// Remote source URI to ingest from (s3://, gcs://, azblob://, webdav://, http(s)://, file://, gdrive://).
        /// When set, evidence is fetched from the remote URI before ingestion.
        #[arg(long, value_name = "URI")]
        source: Option<String>,

        /// Output DuckDB database path. Defaults to
        /// `issen-ingested-<UTC>Z.duckdb` in the current directory.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Evidence source identifier (e.g. case number or host).
        #[arg(short = 's', long)]
        evidence_source: Option<String>,

        /// Run signature scanning after ingest using cached threat intel feeds.
        #[arg(long)]
        scan: bool,

        /// Path to YARA rules file or directory.
        #[arg(long)]
        yara_rules: Option<PathBuf>,

        /// Path to Sigma rules directory.
        #[arg(long)]
        sigma_rules: Option<PathBuf>,

        /// Path to hash IOC file (one hash per line).
        #[arg(long)]
        hash_iocs: Option<Vec<PathBuf>>,

        /// Path to network IOC file (IPs/domains/CIDRs, one per line).
        #[arg(long)]
        network_iocs: Option<Vec<PathBuf>>,

        /// Re-parse and overwrite every unit, ignoring the prior completed-unit
        /// state. Default is resume: units already ingested for this evidence
        /// source are skipped (issen #115).
        #[arg(long)]
        refresh: bool,

        /// Emit full per-row events for high-volume parser tables instead of the
        /// default aggregate-per-app summary. Currently affects SRUM's
        /// PushNotifications/EnergyUsage tables (hundreds of low-signal rows are
        /// otherwise collapsed into one summary event per app). Off by default to
        /// keep the timeline flood-resistant.
        #[arg(long)]
        verbose_rows: bool,
    },

    /// Query and export the timeline.
    Timeline {
        /// Path to the DuckDB database. Optional only with --list-fields.
        #[arg(value_name = "DB_PATH")]
        db_path: Option<PathBuf>,

        /// Filter by event type (repeatable; OR within). Replaces the legacy
        /// single-value form for the typed-query path.
        #[arg(long = "event-type", value_name = "TYPE")]
        event_type: Vec<String>,

        /// Filter by artifact source (repeatable; OR within).
        #[arg(long, value_name = "SOURCE")]
        source: Vec<String>,

        /// Maximum number of events to display.
        #[arg(short = 'n', long, default_value = "50")]
        limit: u64,

        /// Sort newest first.
        #[arg(long)]
        descending: bool,

        /// Export to SQLite file instead of printing.
        #[arg(long)]
        export_sqlite: Option<PathBuf>,

        /// Show scan findings instead of timeline events.
        #[arg(long)]
        flagged: bool,

        /// Minimum severity for --flagged output (informational, low, medium, high, critical).
        #[arg(long, default_value = "informational")]
        min_severity: String,

        /// Output format: text or json (json is jsonguard-sanitized).
        #[arg(long, default_value = "text")]
        format: String,

        /// Render a temporal-rule narrative — a pure view over the DB (never ingests).
        #[arg(long)]
        narrative: bool,

        // --- Tier-1 typed-query surface (design Phase 1) ---
        /// Print the curated field registry (name -> JSON path) and exit.
        #[arg(long = "list-fields")]
        list_fields: bool,

        /// Filter artifact_path by a glob (e.g. '*coreupdater*', '*.lnk').
        #[arg(long, value_name = "GLOB")]
        path: Option<String>,

        /// Typed metadata filter NAME<OP>VAL (OP in =,!=,~). Repeatable.
        #[arg(long = "field", value_name = "NAME<OP>VAL")]
        field: Vec<String>,

        /// Sugar: filter by IpAddress (= --field ip=VAL).
        #[arg(long, value_name = "IP")]
        ip: Option<String>,

        /// Sugar: filter by TargetUserName (= --field user=VAL).
        #[arg(long, value_name = "USER")]
        user: Option<String>,

        /// Sugar: filter by ServiceName (= --field service=VAL).
        #[arg(long, value_name = "SERVICE")]
        service: Option<String>,

        /// Sugar: filter by LogonType (= --field logon-type=VAL).
        #[arg(long = "logon-type", value_name = "N")]
        logon_type: Option<String>,

        /// Drop user/account values ending in '$' (machine accounts).
        #[arg(long = "exclude-machine-accounts")]
        exclude_machine_accounts: bool,

        /// Projection: columns/fields to show (comma-separated).
        #[arg(long, value_name = "COLS")]
        show: Option<String>,

        /// Aggregation: total matching rows.
        #[arg(long)]
        count: bool,

        /// Aggregation: distinct values of a column/field.
        #[arg(long, value_name = "COL")]
        distinct: Option<String>,

        /// Aggregation: histogram (value, count) grouped by a column/field.
        #[arg(long = "group-by", value_name = "COL")]
        group_by: Option<String>,

        /// Aggregation: the earliest (min-timestamp) matching row.
        #[arg(long)]
        first: bool,

        /// Aggregation: the latest (max-timestamp) matching row.
        #[arg(long)]
        last: bool,

        /// Run a guarded read-only raw SQL query (SELECT/WITH only). Mutating
        /// keywords are refused; the handle is read-only regardless.
        #[arg(long, value_name = "QUERY")]
        sql: Option<String>,
    },

    /// Interactive/remote logons (LogonType IN 2,10,11), machine accounts dropped.
    Logons {
        #[command(flatten)]
        args: VerbCli,
        /// Restrict to a single user (TargetUserName).
        #[arg(long)]
        user: Option<String>,
        /// Restrict to a source IP (IpAddress).
        #[arg(long)]
        ip: Option<String>,
    },

    /// Filesystem activity (create/modify/delete/rename).
    Files {
        #[command(flatten)]
        args: VerbCli,
        /// Filter artifact_path by a glob (e.g. '*coreupdater*', '*.lnk').
        #[arg(long, value_name = "GLOB")]
        path: Option<String>,
    },

    /// Persistence (service install/start, registry modify, scheduled task).
    Persistence {
        #[command(flatten)]
        args: VerbCli,
        /// Restrict to a named service (ServiceName).
        #[arg(long)]
        service: Option<String>,
        /// Restrict to a registry key path (matches artifact_path glob).
        #[arg(long = "registry-key", value_name = "GLOB")]
        registry_key: Option<String>,
    },

    /// Network/lateral-movement events keyed by remote host.
    Hosts {
        #[command(flatten)]
        args: VerbCli,
        /// Remote host IP (IpAddress).
        #[arg(long)]
        host: Option<String>,
        /// Remote port (Port).
        #[arg(long)]
        port: Option<String>,
    },

    /// Show information about a timeline database.
    Info {
        /// Path to the DuckDB database.
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,
    },

    /// Manage threat intelligence feeds (list, update, inspect).
    Feed {
        #[command(subcommand)]
        action: FeedAction,
    },

    /// Scan files or indicators against threat intelligence signatures.
    Scan {
        /// File or directory to scan.
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Path to YARA rules file or directory.
        #[arg(long)]
        yara_rules: Option<PathBuf>,

        /// Path to Sigma rules directory.
        #[arg(long)]
        sigma_rules: Option<PathBuf>,

        /// Path to hash IOC file (one hash per line).
        #[arg(long)]
        hash_iocs: Option<Vec<PathBuf>>,

        /// Path to network IOC file (IPs/domains/CIDRs, one per line).
        #[arg(long)]
        network_iocs: Option<Vec<PathBuf>>,

        /// Path to STIX 2.1 bundle JSON file.
        #[arg(long)]
        stix_bundle: Option<Vec<PathBuf>>,

        /// Minimum severity to report (informational, low, medium, high, critical).
        #[arg(long, default_value = "informational")]
        min_severity: String,

        /// Output format: text, json.
        #[arg(long, default_value = "text")]
        format: String,

        /// Automatically load engines from cached threat intel feeds.
        #[arg(long)]
        auto_feeds: bool,
    },

    /// Scan evidence for remote access infrastructure.
    RemoteAccess {
        /// Path to evidence directory or mounted image.
        #[arg(value_name = "EVIDENCE_PATH")]
        evidence_path: PathBuf,
        /// Path to LOLRMM YAML rules directory.
        #[arg(long)]
        rules_dir: Option<PathBuf>,
        /// Path to custom YAML definitions directory.
        #[arg(long)]
        custom_rules: Option<PathBuf>,
        /// Comma-separated categories to scan (default: all).
        #[arg(long)]
        categories: Option<String>,
        /// Output format: table, json.
        #[arg(long, default_value = "table")]
        format: String,
        /// DuckDB database to write findings into.
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Analyse a physical memory dump (LiME, AVML, Windows crash dump, raw).
    #[command(visible_alias = "mem")]
    Memory {
        /// Path to the memory dump file.
        #[arg(value_name = "DUMP_PATH")]
        dump_path: PathBuf,

        /// Sub-command: ps, modules, netstat, check, timeline, scan, creds, all.
        #[arg(long, default_value = "all")]
        command: String,

        /// ISF / BTF / PDB symbol profile path, or "auto" (default).
        #[arg(long)]
        profile: Option<String>,

        /// Output format: text, json, bodyfile.
        #[arg(long, default_value = "text")]
        format: String,

        /// Filter output to a specific PID (process commands only).
        #[arg(long)]
        pid: Option<u32>,

        /// CR3 page-directory base register (hex, e.g. 0x1a2000 or 1a2000).
        /// Required for LiME/AVML dumps that have no embedded CR3.
        #[arg(long, value_parser = commands::memf::parse_cr3_hex)]
        cr3: Option<u64>,
    },

    /// Pivot engine — sync threat intelligence feeds, list rules, evaluate evidence.
    Pivot {
        #[command(subcommand)]
        action: PivotAction,
    },

    /// Generate a self-contained HTML report from a timeline database.
    Report {
        /// Path to the DuckDB database.
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,

        /// Output HTML file path (default: report.html).
        #[arg(short, long, default_value = "report.html")]
        output: PathBuf,

        /// Case identifier shown in the report header.
        #[arg(long)]
        case_id: Option<String>,

        /// Examiner name shown in the report header.
        #[arg(long)]
        examiner: Option<String>,

        /// Maximum number of events to include (default: 10000).
        #[arg(long)]
        max_events: Option<usize>,

        /// Output format: html (default) or attack-navigator (ATT&CK Navigator layer JSON).
        #[arg(long, default_value = "html")]
        format: String,
    },

    /// Build a semantic supertimeline from a collection — parses all artifacts,
    /// applies temporal correlation rules, and outputs a narrative timeline.
    Supertimeline {
        /// Path to the collection file (UAC .tar.gz, zip) or evidence directory.
        #[arg(value_name = "COLLECTION")]
        collection: PathBuf,

        /// Output format: narrative (default), jsonl, csv.
        #[arg(long, default_value = "narrative")]
        format: String,
    },

    /// Parse a SRUDB.dat file and display SRUM network usage and app usage records.
    Srum {
        /// Path to the SRUDB.dat file.
        #[arg(value_name = "SRUDB_PATH")]
        srudb_path: PathBuf,

        /// Output format: text (default), json.
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Parse an Apple Biome `App.MenuItem` SEGB file and display macOS menu-bar selections.
    Biome {
        /// Path to the SEGB stream file (e.g. `.../Biome/streams/restricted/App.MenuItem/local`).
        #[arg(value_name = "SEGB_PATH")]
        biome_path: PathBuf,

        /// Output format: text (default), json.
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Rare-event frequency analysis over EVTX files (Events Ripper posh600 technique).
    Frequency {
        /// Directory to search recursively for .evtx files.
        #[arg(long, value_name = "PATH", num_args = 1..)]
        evtx_dir: Vec<PathBuf>,

        /// Explicit .evtx file path (can be given multiple times).
        #[arg(long, value_name = "FILE", num_args = 1..)]
        evtx_file: Vec<PathBuf>,

        /// Anomaly threshold: report entries seen at most this many times (default: 5).
        #[arg(long, default_value = "5")]
        cap: usize,

        /// Field to group by: cmdline, image, user (default: image).
        #[arg(long, default_value = "image")]
        key: String,

        /// Output JSON instead of a summary table.
        #[arg(long)]
        json: bool,
    },

    /// List process creation events from one or more EVTX files.
    Processes {
        /// Directory to search recursively for .evtx files.
        #[arg(long, value_name = "PATH", num_args = 1..)]
        evtx_dir: Vec<PathBuf>,

        /// Explicit .evtx file path (can be given multiple times).
        #[arg(long, value_name = "FILE", num_args = 1..)]
        evtx_file: Vec<PathBuf>,

        /// Enrich process entries with logon session context.
        #[arg(long)]
        link_sessions: bool,

        /// Output JSON instead of a summary table.
        #[arg(long)]
        json: bool,
    },

    /// Correlate Windows logon sessions from one or more EVTX files.
    Session {
        /// Directory to search recursively for .evtx files.
        #[arg(long, value_name = "PATH", num_args = 1..)]
        evtx_dir: Vec<PathBuf>,

        /// Explicit .evtx file path (can be given multiple times).
        #[arg(long, value_name = "FILE", num_args = 1..)]
        evtx_file: Vec<PathBuf>,

        /// Output JSON instead of a summary table.
        #[arg(long)]
        json: bool,
    },
}

/// Shared flags for the Tier-2 intent verbs (`logons`/`files`/`persistence`/
/// `hosts`): the DB path plus the aggregation/projection toggles. The verb's own
/// filters (`--user`, `--service`, …) live on each subcommand.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct VerbCli {
    /// Path to the DuckDB database.
    #[arg(value_name = "DB_PATH")]
    pub db_path: PathBuf,

    /// Aggregation: total matching rows.
    #[arg(long)]
    pub count: bool,

    /// Aggregation: distinct values of a column/field.
    #[arg(long, value_name = "COL")]
    pub distinct: Option<String>,

    /// Aggregation: histogram (value, count) grouped by a column/field.
    #[arg(long = "group-by", value_name = "COL")]
    pub group_by: Option<String>,

    /// Aggregation: the earliest (min-timestamp) matching row.
    #[arg(long)]
    pub first: bool,

    /// Aggregation: the latest (max-timestamp) matching row.
    #[arg(long)]
    pub last: bool,

    /// Projection: columns/fields to show (comma-separated).
    #[arg(long, value_name = "COLS")]
    pub show: Option<String>,

    /// Sort newest first.
    #[arg(long)]
    pub descending: bool,

    /// Maximum number of events to display.
    #[arg(short = 'n', long)]
    pub limit: Option<u64>,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

#[derive(Subcommand, Debug)]
pub enum FeedAction {
    /// Show all configured feeds and their cache status.
    List,
    /// Download all enabled feeds.
    Update,
    /// Show details for a specific feed.
    Info {
        /// Feed identifier (e.g. "cisa-kev").
        id: String,
    },
    /// Download the CTID Attack Flow v3.0.0 corpus zip and cache locally.
    AttackFlow {
        /// Directory to cache the corpus zip (default: ~/.local/share/issen/attack-flow).
        #[arg(long)]
        cache_dir: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum PivotAction {
    /// Download stale threat intelligence feeds into the cache directory.
    Sync {
        /// Cache directory for pivot feeds (default: ~/.local/share/issen/pivot/).
        #[arg(long, value_name = "PATH")]
        cache_dir: Option<PathBuf>,
    },
    /// List bundled and directory-loaded pivot rules.
    Rules {
        /// Optional directory with additional YAML rule files.
        #[arg(long, value_name = "PATH")]
        rules_dir: Option<PathBuf>,
    },
    /// Evaluate pivot rules against a JSON evidence file.
    Eval {
        /// Path to a JSON file containing an array of Evidence objects.
        #[arg(value_name = "EVIDENCE_FILE")]
        evidence_file: PathBuf,
    },
}

impl FeedAction {
    /// Convert to the library's FeedAction type.
    fn to_lib_action(&self) -> commands::feed::FeedAction {
        match self {
            Self::List => commands::feed::FeedAction::List,
            Self::Update => commands::feed::FeedAction::Update,
            Self::Info { id } => commands::feed::FeedAction::Info { id: id.clone() },
            Self::AttackFlow { cache_dir } => commands::feed::FeedAction::AttackFlow {
                cache_dir: cache_dir.clone(),
            },
        }
    }
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();

    // Configure color output before any printing occurs.
    match cli.color {
        ColorChoice::Always => colored::control::set_override(true),
        ColorChoice::Never => colored::control::set_override(false),
        ColorChoice::Auto => {
            if !std::io::stdout().is_terminal() {
                colored::control::set_override(false);
            }
            // If it IS a terminal, leave colored's own auto-detection active
            // (it also respects NO_COLOR and TERM).
        }
    }

    // Initialize tracing. The third-party `evtx` crate logs one WARN per EVTX
    // BinXML boolean that isn't the strict spec literal 0/1 — but those are valid
    // Win32 BOOLs (any non-zero = true, per [MS-DTYP]) which it handles
    // correctly, so the warning is benign noise that floods a real ingest. Mute
    // it to ERROR in normal mode (genuine evtx errors still surface); `--verbose`
    // restores everything.
    let filter = if cli.verbose {
        "debug"
    } else {
        "warn,evtx=error"
    };
    // On Unix every tty renders ANSI, so `enable_ansi_support` is a no-op that
    // returns Ok — colors stay on. On Windows it attempts to turn on VT
    // processing; ANSI is capable iff that succeeded (a legacy console without VT
    // fails here, so we fall back to clean output instead of garbled escapes).
    let ansi_capable = enable_ansi_support::enable_ansi_support().is_ok();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(should_use_ansi(
            cli.color,
            std::io::stdout().is_terminal(),
            ansi_capable,
        ))
        .try_init()
        .ok();

    let result = match cli.command {
        Commands::Analyse { collection_path } => commands::analyse::run(&collection_path),
        Commands::Correlate { case_dir } => commands::correlate::run(&case_dir),
        Commands::Supertimeline { collection, format } => {
            commands::supertimeline::run(&collection, &format)
        }
        Commands::Ingest {
            evidence_paths,
            output,
            evidence_source,
            source,
            scan,
            yara_rules,
            sigma_rules,
            hash_iocs,
            network_iocs,
            refresh,
            verbose_rows,
        } => {
            // No -o → auto-name `issen-ingested-<UTC>Z.duckdb` in the cwd.
            let output =
                output.unwrap_or_else(|| commands::ingest::auto_output_path(chrono::Utc::now()));
            commands::ingest::run(
                &evidence_paths,
                &output,
                evidence_source.as_deref(),
                source.as_deref(),
                scan,
                yara_rules.as_deref(),
                sigma_rules.as_deref(),
                hash_iocs.as_deref(),
                network_iocs.as_deref(),
                refresh,
                cli.verbose,
                verbose_rows,
            )
        }
        Commands::Timeline {
            db_path,
            event_type,
            source,
            limit,
            descending,
            export_sqlite,
            flagged,
            min_severity,
            format,
            narrative,
            list_fields,
            path,
            field,
            ip,
            user,
            service,
            logon_type,
            exclude_machine_accounts,
            show,
            count,
            distinct,
            group_by,
            first,
            last,
            sql,
        } => {
            // --list-fields is a pure registry dump; no DB required.
            if list_fields {
                commands::timeline_query::list_fields();
                Ok(())
            } else if let Some(sql) = sql {
                // Guarded read-only raw SQL escape hatch.
                match db_path {
                    Some(db) => commands::timeline_verbs::run_sql(&db, &sql, &format),
                    None => Err(anyhow::anyhow!("a DB_PATH is required for --sql")),
                }
            } else {
                // Route to the Tier-1 typed-query path when any typed flag is
                // set; the legacy export/flagged/narrative path keeps its own
                // contract.
                let typed = path.is_some()
                    || !field.is_empty()
                    || ip.is_some()
                    || user.is_some()
                    || service.is_some()
                    || logon_type.is_some()
                    || exclude_machine_accounts
                    || show.is_some()
                    || count
                    || distinct.is_some()
                    || group_by.is_some()
                    || first
                    || last
                    || !event_type.is_empty()
                    || !source.is_empty();

                match db_path {
                    None => Err(anyhow::anyhow!(
                        "a DB_PATH is required (use --list-fields to list fields without one)"
                    )),
                    Some(db) if typed && export_sqlite.is_none() && !flagged && !narrative => {
                        let args = commands::timeline_query::QueryArgs {
                            event_types: event_type,
                            sources: source,
                            path,
                            fields: field,
                            ip,
                            user,
                            service,
                            logon_type,
                            exclude_machine_accounts,
                            show,
                            count,
                            distinct,
                            group_by,
                            first,
                            last,
                            sort_desc: descending,
                            limit: Some(limit),
                            format,
                        };
                        commands::timeline_query::run(&db, &args)
                    }
                    // Legacy path (export / flagged / narrative / plain listing):
                    // the typed event_type/source vecs collapse to their first.
                    Some(db) => commands::timeline::run(
                        &db,
                        event_type.first().map(String::as_str),
                        source.first().map(String::as_str),
                        limit,
                        descending,
                        export_sqlite.as_deref(),
                        flagged,
                        &min_severity,
                        &format,
                        narrative,
                    ),
                }
            }
        }
        Commands::Logons { args, user, ip } => {
            let db = args.db_path.clone();
            commands::timeline_verbs::run_logons(
                &db,
                &commands::timeline_verbs::LogonsArgs {
                    user,
                    ip,
                    common: verb_common(args),
                },
            )
        }
        Commands::Files { args, path } => {
            let db = args.db_path.clone();
            commands::timeline_verbs::run_files(
                &db,
                &commands::timeline_verbs::FilesArgs {
                    path,
                    common: verb_common(args),
                },
            )
        }
        Commands::Persistence {
            args,
            service,
            registry_key,
        } => {
            let db = args.db_path.clone();
            commands::timeline_verbs::run_persistence(
                &db,
                &commands::timeline_verbs::PersistenceArgs {
                    service,
                    registry_key,
                    common: verb_common(args),
                },
            )
        }
        Commands::Hosts { args, host, port } => {
            let db = args.db_path.clone();
            commands::timeline_verbs::run_hosts(
                &db,
                &commands::timeline_verbs::HostsArgs {
                    host,
                    port,
                    common: verb_common(args),
                },
            )
        }
        Commands::Info { db_path } => commands::info::run(&db_path),
        Commands::Feed { action } => commands::feed::run(&action.to_lib_action()),
        Commands::Scan {
            target,
            yara_rules,
            sigma_rules,
            hash_iocs,
            network_iocs,
            stix_bundle,
            min_severity,
            format,
            auto_feeds,
        } => commands::scan::run(
            &target,
            yara_rules.as_deref(),
            sigma_rules.as_deref(),
            hash_iocs.as_deref(),
            network_iocs.as_deref(),
            stix_bundle.as_deref(),
            &min_severity,
            &format,
            auto_feeds,
        ),
        Commands::RemoteAccess {
            evidence_path,
            rules_dir,
            custom_rules,
            categories,
            format,
            db,
        } => commands::remote_access::run(
            &evidence_path,
            rules_dir.as_deref(),
            custom_rules.as_deref(),
            categories.as_deref(),
            &format,
            db.as_deref(),
        ),
        Commands::Memory {
            dump_path,
            command,
            profile,
            format,
            pid,
            cr3,
        } => commands::memf::run(&dump_path, profile.as_deref(), &command, &format, pid, cr3),
        Commands::Report {
            db_path,
            output,
            case_id,
            examiner,
            max_events,
            format,
        } => commands::report::run(
            &db_path,
            &output,
            case_id.as_deref(),
            examiner.as_deref(),
            max_events,
            &format,
        ),
        Commands::Srum { srudb_path, format } => commands::srum::run(&srudb_path, &format),
        Commands::Biome { biome_path, format } => commands::biome::run(&biome_path, &format),
        Commands::Frequency {
            evtx_dir,
            evtx_file,
            cap,
            key,
            json,
        } => match commands::frequency::parse_key(&key) {
            Ok(freq_key) => commands::frequency::run(&evtx_dir, &evtx_file, cap, freq_key, json),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        },
        Commands::Processes {
            evtx_dir,
            evtx_file,
            json,
            link_sessions,
        } => commands::processes::run(&evtx_dir, &evtx_file, json, link_sessions),
        Commands::Session {
            evtx_dir,
            evtx_file,
            json,
        } => commands::session::run(&evtx_dir, &evtx_file, json),
        Commands::Pivot { action } => match action {
            PivotAction::Sync { cache_dir } => {
                let default_cache = dirs_next_cache();
                let cache = cache_dir.unwrap_or(default_cache);
                commands::pivot_cmd::run_sync(&cache)
            }
            PivotAction::Rules { rules_dir } => {
                commands::pivot_cmd::run_rules(rules_dir.as_deref())
            }
            PivotAction::Eval { evidence_file } => commands::pivot_cmd::run_eval(&evidence_file),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Return `~/.local/share/issen/pivot/` as the default pivot cache dir.
fn dirs_next_cache() -> PathBuf {
    std::env::var_os("HOME")
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join(".local")
        .join("share")
        .join("issen")
        .join("pivot")
}

#[cfg(test)]
mod parser_registration_tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::plugin::registry::all_parsers;

    #[test]
    fn all_parsers_includes_a_registry_parser() {
        // issen-parser-registry must be linked + inventory-registered so registry
        // hives are actually parsed during ingest (A2 link).
        let has_registry = all_parsers()
            .iter()
            .any(|p| p.supported_artifacts().contains(&ArtifactType::Registry));
        assert!(
            has_registry,
            "no registered parser supports ArtifactType::Registry — the crate is not linked"
        );
    }

    #[test]
    fn library_linked_registry_is_complete_not_just_registry() {
        // L1: the LIBRARY (not only the binary) must force-link every parser, or any
        // library-linked harness — lib unit tests, `tests/*.rs` using `use issen_cli`,
        // external consumers — sees an incomplete registry. This is the lib/bin skew
        // the supertimeline bug exposed. A lib unit test's link set == the library's
        // anchors, so it fails here until L1 moves all anchors into lib.rs.
        let supported: std::collections::HashSet<ArtifactType> = all_parsers()
            .iter()
            .flat_map(|p| p.supported_artifacts().iter().copied())
            .collect();
        for t in [
            ArtifactType::Registry,
            ArtifactType::Mft,
            ArtifactType::UsnJournal,
            ArtifactType::Lnk,
            ArtifactType::Prefetch,
            ArtifactType::Amcache,
            ArtifactType::EventLog,
        ] {
            assert!(
                supported.contains(&t),
                "library-linked registry missing a producer for {t:?} — force-link \
                 anchors must live in lib.rs, not only main.rs (L1)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parses_without_error() {
        // Verify the CLI definition is valid (no conflicting args, etc.).
        Cli::command().debug_assert();
    }

    // ── should_use_ansi (FIX 4) ──────────────────────────────────────────
    // Never => false regardless; Always => true regardless; Auto gates on
    // (stdout is a tty) AND (the terminal actually renders ANSI). The second
    // clause is what stops a Windows legacy console — a tty that does NOT render
    // ANSI — from garbling escapes.

    #[test]
    fn ansi_never_is_always_false() {
        for tty in [false, true] {
            for cap in [false, true] {
                assert!(!should_use_ansi(ColorChoice::Never, tty, cap));
            }
        }
    }

    #[test]
    fn ansi_always_is_always_true() {
        for tty in [false, true] {
            for cap in [false, true] {
                assert!(should_use_ansi(ColorChoice::Always, tty, cap));
            }
        }
    }

    #[test]
    fn ansi_auto_tty_and_capable_keeps_color() {
        // Mac/Linux interactive terminal: tty + capable ⇒ colors KEPT.
        assert!(should_use_ansi(ColorChoice::Auto, true, true));
    }

    #[test]
    fn ansi_auto_tty_but_not_capable_goes_clean() {
        // Windows legacy console: a tty that can't render ANSI ⇒ clean, not garbled.
        assert!(!should_use_ansi(ColorChoice::Auto, true, false));
    }

    #[test]
    fn ansi_auto_not_tty_is_false() {
        // Piped/redirected: not a tty ⇒ no ANSI, even if "capable".
        assert!(!should_use_ansi(ColorChoice::Auto, false, true));
        assert!(!should_use_ansi(ColorChoice::Auto, false, false));
    }
}
