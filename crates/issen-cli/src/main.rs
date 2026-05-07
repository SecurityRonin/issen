use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod commands;
mod parsers;
mod scanning;

// Link parser crates so their inventory::submit! registrations are included.
extern crate issen_parser_evtx;
extern crate issen_parser_uac;
extern crate issen_parser_velociraptor;

/// Issen — fast forensic triage for incident responders.
#[derive(Parser, Debug)]
#[command(name = "rt", version, about)]
pub struct Cli {
    /// Enable verbose/debug logging.
    #[arg(short, long, global = true)]
    verbose: bool,

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

    /// Ingest evidence and parse artifacts into a timeline.
    Ingest {
        /// Path to evidence directory or file.
        #[arg(value_name = "EVIDENCE_PATH")]
        evidence_path: PathBuf,

        /// Remote source URI to ingest from (s3://, gcs://, azblob://, webdav://, http(s)://, file://, gdrive://).
        /// When set, evidence is fetched from the remote URI before ingestion.
        #[arg(long, value_name = "URI")]
        source: Option<String>,

        /// Output DuckDB database path (default: ./timeline.duckdb).
        #[arg(short, long, default_value = "timeline.duckdb")]
        output: PathBuf,

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
        expoissen_sqlite: Option<PathBuf>,

        /// Show scan findings instead of timeline events.
        #[arg(long)]
        flagged: bool,

        /// Minimum severity for --flagged output (informational, low, medium, high, critical).
        #[arg(long, default_value = "informational")]
        min_severity: String,

        /// Output format: text, json, csv, bodyfile.
        #[arg(long, default_value = "text")]
        format: String,
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
    Memf {
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

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize tracing.
    let filter = if cli.verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let result = match cli.command {
        Commands::Analyse { collection_path } => commands::analyse::run(&collection_path),
        Commands::Supertimeline { collection, format } => {
            commands::supertimeline::run(&collection, &format)
        }
        Commands::Ingest {
            evidence_path,
            output,
            evidence_source,
            source,
            scan,
            yara_rules,
            sigma_rules,
            hash_iocs,
            network_iocs,
        } => commands::ingest::run(
            &evidence_path,
            &output,
            evidence_source.as_deref(),
            source.as_deref(),
            scan,
            yara_rules.as_deref(),
            sigma_rules.as_deref(),
            hash_iocs.as_deref(),
            network_iocs.as_deref(),
        ),
        Commands::Timeline {
            db_path,
            event_type,
            source,
            limit,
            descending,
            expoissen_sqlite,
            flagged,
            min_severity,
            format,
        } => commands::timeline::run(
            &db_path,
            event_type.as_deref(),
            source.as_deref(),
            limit,
            descending,
            expoissen_sqlite.as_deref(),
            flagged,
            &min_severity,
            &format,
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
        Commands::Memf {
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
        Commands::Srum { srudb_path, format } => {
            commands::srum::run(&srudb_path, &format)
        }
        Commands::Pivot { action } => match action {
            PivotAction::Sync { cache_dir } => {
                let default_cache = dirs_next_cache();
                let cache = cache_dir.unwrap_or(default_cache);
                commands::pivot_cmd::run_sync(&cache)
            }
            PivotAction::Rules { rules_dir } => {
                commands::pivot_cmd::run_rules(rules_dir.as_deref())
            }
            PivotAction::Eval { evidence_file } => {
                commands::pivot_cmd::run_eval(&evidence_file)
            }
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
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("share")
        .join("issen")
        .join("pivot")
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
