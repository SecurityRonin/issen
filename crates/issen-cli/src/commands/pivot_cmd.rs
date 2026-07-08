//! `rt pivot` subcommand — sync feeds, list rules, evaluate evidence.
//!
//! This module implements the three sub-subcommands:
//!   - `rt pivot sync`  — download stale feeds
//!   - `rt pivot rules` — list bundled + dir-loaded rules
//!   - `rt pivot eval`  — evaluate rules against a JSON evidence file

use std::path::Path;

use forensic_pivot::{
    bundled_rules, default_feeds,
    downloader::{download_feed, load_manifest, prepare_feed_cache, save_manifest, stale_feeds},
    evidence::Evidence,
    load_rules_from_dir,
    rule::{AssertionLevel, Severity},
    FeedSpec,
};

const STALE_THRESHOLD_SECS: u64 = 86_400; // 24 hours

// ---------------------------------------------------------------------------
// sync
// ---------------------------------------------------------------------------

/// Run `rt pivot sync [--cache-dir PATH]`.
///
/// # Errors
/// Returns an error if the manifest cannot be read/written or if any feed
/// download fails.
pub fn run_sync(cache_dir: &Path) -> anyhow::Result<()> {
    // Load or initialise manifest.
    let mut manifest = load_manifest(cache_dir)?;

    // Seed with default feeds if the manifest is empty.
    if manifest.feeds.is_empty() {
        manifest.feeds = default_feeds();
    }

    let stale: Vec<FeedSpec> = stale_feeds(&manifest, STALE_THRESHOLD_SECS)
        .into_iter()
        .cloned()
        .collect();

    if stale.is_empty() {
        println!("All feeds are up to date.");
        return Ok(());
    }

    println!("Syncing {} feed(s)...", stale.len());
    for spec in &stale {
        // Ensure cache directory exists.
        prepare_feed_cache(spec, cache_dir)?;
        match download_feed(spec, cache_dir) {
            Ok(()) => println!("  \u{2713} {}", spec.name),
            Err(e) => eprintln!("  \u{2717} {} — {e}", spec.name),
        }
        // Update last_synced in the manifest.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(entry) = manifest.feeds.iter_mut().find(|f| f.name == spec.name) {
            entry.last_synced = Some(now);
        }
        save_manifest(&manifest, cache_dir)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

/// Run `rt pivot rules [--rules-dir PATH]`.
///
/// # Errors
/// Never errors — a missing rules dir is silently ignored.
#[allow(clippy::unnecessary_wraps)] // Result<()> matches the command-dispatch signature
pub fn run_rules(rules_dir: Option<&Path>) -> anyhow::Result<()> {
    let mut rules = bundled_rules();
    if let Some(dir) = rules_dir {
        rules.extend(load_rules_from_dir(dir));
    }

    if rules.is_empty() {
        println!("No pivot rules found.");
        return Ok(());
    }

    // Header
    println!(
        "{:<40} {:<30} {:<10} {:<14} {:<10}",
        "ID", "NAME", "SEVERITY", "ASSERTION", "CONFIDENCE"
    );
    println!("{}", "-".repeat(108));

    for rule in &rules {
        println!(
            "{:<40} {:<30} {:<10} {:<14} {}%",
            rule.id,
            truncate(&rule.name, 29),
            fmt_severity(&rule.severity),
            fmt_assertion(&rule.assertion_level),
            rule.default_confidence,
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// eval
// ---------------------------------------------------------------------------

/// Run `rt pivot eval <EVIDENCE_FILE>`.
///
/// The evidence file must be a JSON array of [`Evidence`] objects.
///
/// # Errors
/// Returns an error if the file cannot be read or parsed.
pub fn run_eval(evidence_path: &Path) -> anyhow::Result<()> {
    let json = std::fs::read_to_string(evidence_path).map_err(|e| {
        anyhow::anyhow!(
            "cannot read evidence file '{}': {e}",
            evidence_path.display()
        )
    })?;

    let evidence: Vec<Evidence> = serde_json::from_str(&json).map_err(|e| {
        anyhow::anyhow!(
            "invalid evidence JSON in '{}': {e}",
            evidence_path.display()
        )
    })?;

    let rules = bundled_rules();
    let engine = forensic_pivot::PivotEngine::new(rules);
    let findings = engine.evaluate(&evidence);

    if findings.is_empty() {
        println!("No findings.");
        return Ok(());
    }

    // Header
    println!(
        "{:<40} {:<10} {:<10} EVIDENCE IDS",
        "RULE", "SEVERITY", "CONFIDENCE"
    );
    println!("{}", "-".repeat(80));

    for f in &findings {
        println!(
            "{:<40} {:<10} {:<10} {}",
            f.rule_id,
            fmt_severity(&f.severity),
            format!("{}%", f.confidence),
            f.matched_evidence.join(", "),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fmt_severity(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn fmt_assertion(a: &AssertionLevel) -> &'static str {
    match a {
        AssertionLevel::Observed => "Observed",
        AssertionLevel::Correlated => "Correlated",
        AssertionLevel::Inferred => "Inferred",
    }
}

/// Truncate `s` to at most `max` **characters** (char-safe — slices only at a
/// UTF-8 code-point boundary, so a multi-byte filename can never split and panic).
fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
