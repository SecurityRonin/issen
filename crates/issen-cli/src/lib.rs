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

use clap::{Parser, Subcommand, ValueEnum};
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
#[derive(ValueEnum, Debug, Clone, Default)]
pub enum ColorChoice {
    /// Emit colors only when stdout is an interactive terminal (default).
    #[default]
    Auto,
    /// Always emit ANSI color codes.
    Always,
    /// Never emit ANSI color codes.
    Never,
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
        /// Path to the DuckDB database.
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,

        /// Filter by event type (e.g. FileCreate, ProcessExec).
        #[arg(long)]
        event_type: Option<String>,

        /// Filter by artifact source (e.g. UsnJournal, EventLog).
        #[arg(long)]
        source: Option<String>,

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

        /// Output format: text, json, csv, bodyfile.
        #[arg(long, default_value = "text")]
        format: String,

        /// Render a temporal-rule narrative — a pure view over the DB (never ingests).
        #[arg(long)]
        narrative: bool,
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
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
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
        } => commands::timeline::run(
            &db_path,
            event_type.as_deref(),
            source.as_deref(),
            limit,
            descending,
            export_sqlite.as_deref(),
            flagged,
            &min_severity,
            &format,
            narrative,
        ),
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
        } => commands::report::run(
            &db_path,
            &output,
            case_id.as_deref(),
            examiner.as_deref(),
            max_events,
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
}
