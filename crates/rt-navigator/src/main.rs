//! `rt-nav` — Forensic file navigator and investigation workbench.
//!
//! Parses a raw `$MFT` file, reconstructs the NTFS directory tree in memory,
//! and presents it in an interactive Midnight Commander-style TUI.
//!
//! When given a forensic collection archive (UAC `.tar.gz` or Velociraptor
//! `.zip`), launches the full Investigation Workbench with supertimeline,
//! artifact drill-in views, and alert detection.
//!
//! # Usage
//! ```text
//! rt-nav /path/to/$MFT            # direct MFT file
//! rt-nav /mnt/evidence/C           # folder treated as volume root
//! rt-nav --mft /a --usnj /b        # explicit artifact paths
//! rt-nav collection.tar.gz         # UAC/Velociraptor → workbench
//! ```

extern crate rt_parser_uac;
extern crate rt_parser_velociraptor;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;
use crossterm::event::{self, Event};
use rt_core::error::RtError;

mod app;
mod investigation;
mod search;
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
    /// Path to an extracted $MFT file, a folder (volume root) containing
    /// NTFS metadata files, or a forensic collection archive (UAC/Velociraptor).
    /// If omitted on Windows, defaults to C:\.
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

    // -- Try collection detection first (UAC / Velociraptor) ----------------
    if cli.mft.is_none() {
        if let Some(ref path) = cli.path {
            if path.is_file() {
                match try_open_collection(path) {
                    Ok(Some((data, mft_app, manifest))) => {
                        return run_workbench(data, mft_app, manifest);
                    }
                    Ok(None) => {} // Not a collection — fall through to MFT mode
                    Err(e) => {
                        eprintln!("  Warning: collection probe failed: {e}");
                        // Fall through to MFT mode
                    }
                }
            }
        }
    }

    // -- Existing MFT tree mode (unchanged) ---------------------------------
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
) -> Vec<usnjrnl_forensic::usn::UsnRecord> {
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
        // Skip zero-filled padding regions.
        if data[offset] == 0 {
            offset += 8;
            continue;
        }
        match usnjrnl_forensic::usn::parse_usn_record_v2(&data[offset..]) {
            Ok(rec) => {
                // Record length is the first 4 bytes of the raw record.
                let len = if data.len() >= offset + 4 {
                    u32::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]) as usize
                } else {
                    8
                };
                records.push(rec);
                offset += len.max(8);
            }
            Err(_) => {
                // Skip forward to find next record (aligned to 8 bytes).
                offset += 8;
            }
        }
    }

    // Build enrichment tuples from the records — mask the FRN to 48 bits
    // for MFT entry lookup, but keep unmasked FRNs in the records for USN
    // stream analysis.
    let enrich_tuples: Vec<(u64, String)> = records
        .iter()
        .map(|r| {
            (
                r.mft_entry & 0x0000_FFFF_FFFF_FFFF,
                r.filename.clone(),
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

        // Non-blocking poll — allows checking async search results + debounce
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if matches!(app.handle_key(key), Action::Quit) {
                    return Ok(());
                }
            }
        }

        // Process results from background search thread
        app.poll_search_results();

        // Fire debounced search if timer expired
        app.fire_debounced_search();
    }
}

// ---------------------------------------------------------------------------
// Investigation Workbench — collection detection + launch
// ---------------------------------------------------------------------------

/// Try to open the path as a forensic collection (UAC/Velociraptor).
///
/// Returns `Ok(None)` if no provider recognizes the format (not a collection).
/// Returns `Ok(Some(...))` with the parsed investigation data, optional MFT app,
/// and the collection manifest (which must be kept alive to preserve the temp dir).
fn try_open_collection(
    path: &std::path::Path,
) -> Result<
    Option<(
        investigation::data::InvestigationData,
        Option<App>,
        rt_unpack::CollectionManifest,
    )>,
> {
    use rt_unpack::registry::open_collection;

    let manifest = match open_collection(path) {
        Ok(m) => m,
        Err(e) => {
            // UnsupportedFormat means "no provider matched" — not an error,
            // just not a collection archive.
            if matches!(e, RtError::UnsupportedFormat(_)) {
                return Ok(None);
            }
            return Err(e.into());
        }
    };

    eprintln!("  Detected collection: {}", manifest.format_name);
    eprintln!("  Extracted to {}", manifest.extracted_root.display());

    let is_velociraptor = manifest.format_name.contains("elociraptor");

    // Dispatch to the appropriate collection loader
    let mut data = if is_velociraptor {
        investigation::data::load_velociraptor_collection(
            &manifest.extracted_root,
            &manifest.artifacts,
            &manifest.metadata,
        )
    } else {
        investigation::data::load_uac_collection(&manifest.extracted_root, Some(&manifest.metadata))
    };

    // For Velociraptor collections: try to find and load $MFT
    let mft_app = if is_velociraptor {
        try_load_mft(&manifest.extracted_root, &manifest.artifacts, &mut data)?
    } else {
        None
    };

    if !data.artifact_counts.is_empty() {
        let mut counts: Vec<_> = data.artifact_counts.iter().collect();
        counts.sort_by(|a, b| b.1.cmp(a.1));
        let summary: Vec<String> = counts.iter().map(|(k, v)| format!("{v} {k}")).collect();
        eprintln!("  Artifacts: {}", summary.join(", "));
    }

    eprintln!(
        "  {} timeline events, {} alerts",
        data.timeline.len(),
        data.alerts.len(),
    );

    Ok(Some((data, mft_app, manifest)))
}

/// Attempt to locate and load an `$MFT` file from a Velociraptor extraction.
///
/// Uses the manifest's pre-classified artifact entries to find the MFT and
/// USN journal by type, rather than guessing filesystem paths. This is robust
/// because `extract_velociraptor` already decoded the URL-encoded zip paths
/// into normalized relative paths (e.g., `$MFT`, `$Extend/$UsnJrnl:$J`).
fn try_load_mft(
    extracted_root: &std::path::Path,
    artifacts: &[rt_unpack::ManifestEntry],
    data: &mut investigation::data::InvestigationData,
) -> Result<Option<App>> {
    use investigation::timeline::{mft_to_events, usn_to_events};
    use rt_core::artifacts::ArtifactType;

    // Find MFT from manifest entries (already classified by path_decoder)
    let mft_entry = artifacts
        .iter()
        .find(|e| e.artifact_type == Some(ArtifactType::Mft));

    let Some(mft_entry) = mft_entry else {
        return Ok(None);
    };

    let mft_path = extracted_root.join(&mft_entry.path);
    if !mft_path.exists() {
        eprintln!(
            "  Warning: manifest lists $MFT at {} but file not found",
            mft_path.display()
        );
        return Ok(None);
    }

    eprintln!("  Loading $MFT from {}", mft_path.display());
    let mut tree = FileTree::from_mft(&mft_path)?;

    // Find $UsnJrnl from manifest entries
    let usn_entry = artifacts
        .iter()
        .find(|e| e.artifact_type == Some(ArtifactType::UsnJournal));
    let usn_records = if let Some(usn_entry) = usn_entry {
        let usn_path = extracted_root.join(&usn_entry.path);
        if usn_path.exists() {
            enrich_with_usnjrnl(&mut tree, &usn_path)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Convert MFT + USN to timeline events
    let mut mft_events = mft_to_events(&tree);
    if !usn_records.is_empty() {
        mft_events.extend(usn_to_events(&usn_records));
    }

    // Merge into existing timeline and re-sort
    data.timeline.extend(mft_events);
    data.timeline.sort_by_key(|e| e.timestamp);

    // Run heuristics on MFT
    let config = HeuristicsConfig::default();
    let mut anomaly_index = heuristics::run_tier1(&tree, &config);
    if !usn_records.is_empty() {
        let usn_index = heuristics::check_usn_stream(&usn_records, Some(&tree));
        anomaly_index.merge(usn_index);
    }

    // Convert anomalies to workbench alerts (before App::new takes ownership)
    let mft_alerts = investigation::alerts::anomalies_to_alerts(&anomaly_index, &tree);
    data.alerts.extend(mft_alerts);

    // Build the MFT App (takes ownership of tree and anomaly_index)
    let app = App::new(tree, anomaly_index)?;

    eprintln!(
        "  MFT loaded, {} total timeline events, {} alerts",
        data.timeline.len(),
        data.alerts.len(),
    );
    Ok(Some(app))
}

/// Launch the investigation workbench TUI.
///
/// The `_manifest` parameter is kept alive for the duration of the TUI session
/// to prevent the temp directory from being cleaned up.
fn run_workbench(
    data: investigation::data::InvestigationData,
    mft_app: Option<App>,
    _manifest: rt_unpack::CollectionManifest,
) -> Result<()> {
    let mut workbench = investigation::WorkbenchApp::new(data, mft_app);
    eprintln!("  Workbench: {:?}", workbench);

    let mut terminal = ratatui::init();
    let result = run_workbench_loop(&mut terminal, &mut workbench);
    ratatui::restore();

    result
}

/// Event loop for the investigation workbench.
fn run_workbench_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut investigation::WorkbenchApp,
) -> Result<()> {
    use investigation::workbench_ui::draw_workbench;

    loop {
        terminal.draw(|frame| draw_workbench(frame, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if matches!(app.handle_key(key), Action::Quit) {
                    return Ok(());
                }
            }
        }

        // If MFT app is active, poll its search results
        if let Some(ref mut mft_app) = app.mft_app {
            mft_app.poll_search_results();
            mft_app.fire_debounced_search();
        }
    }
}
