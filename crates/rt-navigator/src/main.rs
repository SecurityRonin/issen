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
    if let Some(ref usnj_path) = sources.usn_journal {
        enrich_with_usnjrnl(&mut tree, usnj_path);
    }

    // -- Report what we found -----------------------------------------------
    if sources.mft_mirror.is_some() {
        eprintln!("  Found $MFTMirr (validation not yet implemented)");
    }
    if sources.logfile.is_some() {
        eprintln!("  Found $LogFile (parsing not yet implemented)");
    }
    if sources.usn_journal.is_some() {
        eprintln!("  Found $UsnJrnl");
    }

    let mut app = App::new(tree)?;

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

fn enrich_with_usnjrnl(tree: &mut FileTree, path: &std::path::Path) {
    eprintln!("  Enriching with USN journal from {} ...", path.display());
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  Warning: failed to read $UsnJrnl: {e}");
            return;
        }
    };

    let mut records = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if let Some(rec) = rt_parser_usnjrnl::UsnRecordV2::parse(&data[offset..]) {
            let len = rec.record_length as usize;
            records.push((
                rec.file_reference_number & 0x0000_FFFF_FFFF_FFFF,
                rec.file_name,
            ));
            offset += len;
        } else {
            // Skip forward to find next record (aligned to 8 bytes).
            offset += 8;
        }
    }

    let count = records.len();
    tree.enrich_usn(&records);
    eprintln!("  Enriched tree with {count} USN journal records.");
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
