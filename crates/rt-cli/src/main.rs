use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod commands;
mod scanning;

// Link parser crates so their inventory::submit! registrations are included.
extern crate rt_parser_evtx;
extern crate rt_parser_mft;
extern crate rt_parser_uac;
extern crate rt_parser_usnjrnl;
extern crate rt_parser_velociraptor;

/// RapidTriage — fast forensic triage for incident responders.
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
    /// Ingest evidence and parse artifacts into a timeline.
    Ingest {
        /// Path to evidence directory or file.
        #[arg(value_name = "EVIDENCE_PATH")]
        evidence_path: PathBuf,

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
        export_sqlite: Option<PathBuf>,

        /// Show scan findings instead of timeline events.
        #[arg(long)]
        flagged: bool,

        /// Minimum severity for --flagged output (informational, low, medium, high, critical).
        #[arg(long, default_value = "informational")]
        min_severity: String,

        /// Output format for --flagged: text, json.
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
}

impl FeedAction {
    /// Convert to the library's FeedAction type.
    fn to_lib_action(&self) -> commands::feed::FeedAction {
        match self {
            Self::List => commands::feed::FeedAction::List,
            Self::Update => commands::feed::FeedAction::Update,
            Self::Info { id } => commands::feed::FeedAction::Info { id: id.clone() },
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
        Commands::Ingest {
            evidence_path,
            output,
            evidence_source,
            scan,
            yara_rules,
            sigma_rules,
            hash_iocs,
            network_iocs,
        } => commands::ingest::run(
            &evidence_path,
            &output,
            evidence_source.as_deref(),
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
            export_sqlite,
            flagged,
            min_severity,
            format,
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
        } => commands::memf::run(&dump_path, profile.as_deref(), &command, &format, pid),
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
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
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
