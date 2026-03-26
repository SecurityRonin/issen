//! `rt-nav` — MFT-based forensic file navigator.
//!
//! Parses a raw `$MFT` file, reconstructs the NTFS directory tree in memory,
//! and presents it in an interactive Midnight Commander-style TUI.
//!
//! # Usage
//! ```text
//! rt-nav /path/to/$MFT            # direct MFT file
//! rt-nav /mnt/evidence/C           # folder treated as volume root
//! rt-nav --mft /a --usnj /b        # explicit artifact paths
//! ```

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Parser;
use crossterm::event::{self, Event};

mod app;
mod sources;
mod ui;

use app::{Action, App};
use rt_mft_tree::tree::FileTree;
use rt_signatures::heuristics::{self, HeuristicsConfig};
use sources::ArtifactSources;

#[derive(Parser)]
#[command(
    name = "rt-nav",
    about = "Forensic file navigator — browse a reconstructed NTFS tree from $MFT"
)]
struct Cli {
    /// Path to an extracted $MFT file or a folder (volume root) containing
    /// NTFS metadata files. If omitted on Windows, defaults to C:\.
    path: Option<PathBuf>,

    /// Explicit path to $MFT (overrides positional argument).
    #[arg(long)]
    mft: Option<PathBuf>,

    /// Explicit path to `$MFTMirr`.
    #[arg(long)]
    mftmirr: Option<PathBuf>,

    /// Explicit path to `$LogFile`.
    #[arg(long)]
    logfile: Option<PathBuf>,

    /// Explicit path to $UsnJrnl:$J.
    #[arg(long)]
    usnj: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let sources = resolve_sources(&cli)?;

    // -- Load MFT -----------------------------------------------------------
    eprintln!("  Loading {}", sources.mft.display());
    let mut tree = FileTree::from_mft(&sources.mft)?;

    // -- Enrich with USN journal if available --------------------------------
    let usn_records = if let Some(ref usnj_path) = sources.usn_journal {
        enrich_with_usnjrnl(&mut tree, usnj_path)
    } else {
        Vec::new()
    };

    // -- Report what we found -----------------------------------------------
    if let Some(ref mirror_path) = sources.mft_mirror {
        match rt_mft_tree::mirror::validate_mirror(&sources.mft, mirror_path) {
            Ok(result) => {
                if result.is_valid() {
                    eprintln!("  $MFTMirr: all 4 entries match (valid)");
                } else {
                    eprintln!(
                        "  $MFTMirr: {} of 4 entries differ!",
                        result.mismatch_count()
                    );
                }
            }
            Err(e) => {
                eprintln!("  Warning: failed to validate $MFTMirr: {e}");
            }
        }
    }
    if let Some(ref logfile_path) = sources.logfile {
        match rt_mft_tree::logfile::validate_logfile(logfile_path) {
            Ok(validation) => {
                eprintln!("  $LogFile: {}", validation.summary());
            }
            Err(e) => {
                eprintln!("  Warning: failed to validate $LogFile: {e}");
            }
        }
    }
    if sources.usn_journal.is_some() {
        eprintln!("  Found $UsnJrnl");
    }

    // -- Run heuristic analysis -----------------------------------------------
    let config = HeuristicsConfig::default();
    let mut anomaly_index = heuristics::run_tier1(&tree, &config);
    if !usn_records.is_empty() {
        let usn_index = heuristics::check_usn_stream(&usn_records, Some(&tree));
        anomaly_index.merge(usn_index);
    }

    // -- Tier 2: content-aware checks (requires volume root) -----------------
    if let Some(ref volume_root) = sources.volume_root {
        let reader = heuristics::FsFileReader::new(volume_root.clone(), &tree);
        let file_entries: Vec<usize> = (0..tree.node_count())
            .filter(|&i| !tree.node(i).is_dir)
            .collect();
        heuristics::run_tier2(&tree, &file_entries, &reader, &mut anomaly_index);
        eprintln!("  Tier 2 content checks complete.");
    }

    if anomaly_index.flagged_count() > 0 {
        eprintln!("  {} anomalies detected.", anomaly_index.flagged_count());
    }

    let mut app = App::new(tree, anomaly_index)?;

    // -- TUI event loop -----------------------------------------------------
    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, &mut app);
    ratatui::restore();

    result
}

fn resolve_sources(cli: &Cli) -> Result<ArtifactSources> {
    // Explicit flags take priority.
    if let Some(ref mft) = cli.mft {
        return ArtifactSources::from_explicit(
            mft,
            cli.mftmirr.as_deref(),
            cli.logfile.as_deref(),
            cli.usnj.as_deref(),
        );
    }

    // Positional argument.
    if let Some(ref path) = cli.path {
        return ArtifactSources::resolve_path(path);
    }

    // Default: try C:\ (works on Windows natively, or when evidence is
    // mounted / extracted to C:\).
    let default = PathBuf::from(r"C:\");
    if default.exists() {
        eprintln!("  No path specified, defaulting to C:\\");
        return ArtifactSources::resolve_path(&default);
    }

    bail!(
        "No path specified. Provide a path to an $MFT file or a folder containing NTFS artifacts.\n\
         Usage: rt-nav <PATH>  or  rt-nav --mft <MFT_PATH>"
    );
}

fn enrich_with_usnjrnl(
    tree: &mut FileTree,
    path: &std::path::Path,
) -> Vec<rt_parser_usnjrnl::UsnRecordV2> {
    eprintln!("  Enriching with USN journal from {} ...", path.display());
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  Warning: failed to read $UsnJrnl: {e}");
            return Vec::new();
        }
    };

    let mut records = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if let Some(rec) = rt_parser_usnjrnl::UsnRecordV2::parse(&data[offset..]) {
            let len = rec.record_length as usize;
            records.push(rec);
            offset += len;
        } else {
            // Skip forward to find next record (aligned to 8 bytes).
            offset += 8;
        }
    }

    // Build enrichment tuples from the records — mask the FRN to 48 bits
    // for MFT entry lookup, but keep unmasked FRNs in the records for USN
    // stream analysis.
    let enrich_tuples: Vec<(u64, String)> = records
        .iter()
        .map(|r| {
            (
                r.file_reference_number & 0x0000_FFFF_FFFF_FFFF,
                r.file_name.clone(),
            )
        })
        .collect();

    let count = records.len();
    tree.enrich_usn(&enrich_tuples);
    eprintln!("  Enriched tree with {count} USN journal records.");
    records
}

fn run_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;

        if let Event::Key(key) = event::read()? {
            if matches!(app.handle_key(key), Action::Quit) {
                return Ok(());
            }
        }
    }
}
