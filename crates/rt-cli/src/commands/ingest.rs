use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rt_remote_io::gdrive;
use rt_remote_io::uri::{UriScheme, is_remote_uri};
use rt_fswalker::orchestrator::run_auto;
use rt_fswalker::progress::ProgressReporter;
use rt_signatures::engines::ioc_hash::HashIocStore;
use rt_signatures::engines::ioc_network::NetworkIocStore;
use rt_signatures::engines::yara::YaraEngine;
use rt_signatures::matching::engine::ScanEngine;
use rt_timeline::findings;
use rt_timeline::store::TimelineStore;
use tracing::info;

use crate::scanning;

/// Get the default feed cache directory (same as feed subcommand).
fn default_feed_cache_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        Path::new(&home).join(".local/share/rapidtriage/feeds")
    } else {
        PathBuf::from(".rapidtriage/feeds")
    }
}

/// Run the ingest command: discover artifacts, parse them, store events in DuckDB.
///
/// When `scan` is true or any explicit scan rule flag is provided, runs the
/// post-ingest scanning phase and stores findings in the scan_findings table.
///
/// - `scan`: load engines from cached threat intel feeds
/// - `yara_rules`: path to YARA rules file or directory
/// - `sigma_rules`: path to Sigma rules directory
/// - `hash_iocs`: hash IOC files (one hash per line)
/// - `network_iocs`: network IOC files (IPs/domains/CIDRs)
#[allow(clippy::too_many_arguments)]
pub fn run(
    evidence_path: &Path,
    output: &Path,
    evidence_source: Option<&str>,
    source_uri: Option<&str>,
    scan: bool,
    yara_rules: Option<&Path>,
    sigma_rules: Option<&Path>,
    hash_iocs: Option<&[PathBuf]>,
    network_iocs: Option<&[PathBuf]>,
) -> Result<()> {
    // Remote source URI dispatch.
    if let Some(uri) = source_uri {
        if !is_remote_uri(uri) {
            anyhow::bail!("Unsupported URI scheme: {uri}");
        }

        let scheme = UriScheme::detect(uri)
            .ok_or_else(|| anyhow::anyhow!("Unsupported URI scheme: {uri}"))?;

        match scheme {
            UriScheme::GDrive => {
                let file_id = gdrive::parse_file_id(uri)
                    .ok_or_else(|| anyhow::anyhow!("Could not parse gdrive file ID from: {uri}"))?;
                let auth = rt_remote_io::gdrive::auth::resolve_auth_mode();
                println!("Remote source URI: gdrive://{file_id} (auth: {auth:?})");
                println!(
                    "Note: gdrive fetch is a stub — download would stream to a temp file for ingest."
                );
            }
            _ => {
                // All other recognised schemes use the OpenDAL operator.
                let (_, path) = rt_remote_io::operator::operator_for_uri(uri)
                    .with_context(|| format!("building operator for source URI: {uri}"))?;
                println!("Remote source URI: {uri} (path: {path})");
                println!(
                    "Note: remote fetch is a stub — bytes would be streamed to a temp file for ingest."
                );
            }
        }

        return Ok(());
    }

    if !evidence_path.exists() {
        anyhow::bail!("Evidence path does not exist: {}", evidence_path.display());
    }

    println!("Ingesting evidence from: {}", evidence_path.display());

    // Open or create the DuckDB timeline store.
    let store = TimelineStore::open(output).context("Failed to open timeline database")?;

    // Register evidence source if provided.
    let source_id = evidence_source.unwrap_or("default");
    store
        .register_evidence_source(source_id, &evidence_path.to_string_lossy(), None, None)
        .context("Failed to register evidence source")?;

    // Run the pipeline.
    let progress = ProgressReporter::new();
    let (events, result) =
        run_auto(evidence_path, &progress).context("Pipeline execution failed")?;

    // Insert events into DuckDB.
    let inserted = store
        .insert_batch(&events)
        .context("Failed to insert events into timeline")?;

    println!("Artifacts found:  {}", result.artifacts_found);
    println!("Artifacts parsed: {}", result.artifacts_parsed);
    println!("Events generated: {}", result.total_events);
    println!("Events inserted:  {inserted} (after dedup)");
    println!("Bytes processed:  {}", format_bytes(result.total_bytes));
    println!("Database:         {}", output.display());

    if !result.errors.is_empty() {
        eprintln!("\n{} error(s) during parsing:", result.errors.len());
        for err in &result.errors {
            eprintln!("  - {err}");
        }
    }

    // Post-ingest scanning phase.
    // Trigger if --scan is set OR if any explicit rule flag is provided.
    let has_explicit_rules = yara_rules.is_some()
        || sigma_rules.is_some()
        || hash_iocs.is_some()
        || network_iocs.is_some();

    if scan || has_explicit_rules {
        println!("\n--- Scanning phase ---");

        // Start with an engine from cached feeds if --scan, otherwise empty.
        let mut engine = if scan {
            let feed_cache_dir = default_feed_cache_dir();
            let registry =
                rt_signatures::feeds::config::FeedRegistry::with_defaults(&feed_cache_dir);
            let feed_cache = rt_signatures::feeds::fetcher::FeedCache::new(&feed_cache_dir);

            let load_result =
                rt_signatures::feeds::loader::load_cached_feeds(&registry, &feed_cache);
            let (eng, load_summary) = match load_result {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("Warning: failed to load feeds: {e}");
                    eprintln!("Scanning with empty engine (no feeds loaded).");
                    (
                        ScanEngine::new(),
                        rt_signatures::feeds::loader::LoadSummary::default(),
                    )
                }
            };

            if load_summary.feeds_loaded > 0 {
                eprintln!(
                    "Loaded {} feed(s): {} hash IOCs, {} network IOCs",
                    load_summary.feeds_loaded,
                    load_summary.hash_indicators,
                    load_summary.network_indicators,
                );
            }

            eng
        } else {
            ScanEngine::new()
        };

        // Layer on explicit YARA rules.
        if let Some(rules_path) = yara_rules {
            let yara = if rules_path.is_dir() {
                let mut sources = Vec::new();
                for entry in std::fs::read_dir(rules_path)
                    .with_context(|| format!("reading YARA rules dir: {}", rules_path.display()))?
                {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() {
                        let ext = path.extension().and_then(|e| e.to_str());
                        if matches!(ext, Some("yar" | "yara")) {
                            sources.push(std::fs::read_to_string(&path)?);
                        }
                    }
                }
                let refs: Vec<&str> = sources.iter().map(|s| s.as_str()).collect();
                if refs.is_empty() {
                    anyhow::bail!("No .yar/.yara files found in {}", rules_path.display());
                }
                YaraEngine::from_sources(&refs).with_context(|| "compiling YARA rules")?
            } else {
                YaraEngine::from_file(rules_path)
                    .with_context(|| format!("loading YARA rules from {}", rules_path.display()))?
            };
            info!(rules = yara.rule_count(), "YARA engine loaded");
            engine = engine.with_yara(yara);
        }

        // Layer on explicit Sigma rules.
        if let Some(sigma_path) = sigma_rules {
            let mut sigma = rt_signatures::engines::sigma::SigmaEngine::new();
            if sigma_path.is_dir() {
                let count = sigma.load_rules_dir(sigma_path).with_context(|| {
                    format!("loading Sigma rules from {}", sigma_path.display())
                })?;
                info!(rules = count, "Sigma engine loaded from directory");
            } else {
                let yaml = std::fs::read_to_string(sigma_path)?;
                sigma
                    .load_rule(&yaml)
                    .with_context(|| format!("loading Sigma rule from {}", sigma_path.display()))?;
                info!("Sigma engine loaded 1 rule");
            }
            engine = engine.with_sigma(sigma);
        }

        // Layer on explicit hash IOC files.
        if let Some(hash_files) = hash_iocs {
            for path in hash_files {
                let mut store = HashIocStore::new(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("hash-iocs"),
                );
                let count = store
                    .load_bad_from_file(path)
                    .with_context(|| format!("loading hash IOCs from {}", path.display()))?;
                info!(count, source = %path.display(), "hash IOC store loaded");
                engine.add_hash_store(store);
            }
        }

        // Layer on explicit network IOC files.
        if let Some(net_files) = network_iocs {
            for path in net_files {
                let mut store = NetworkIocStore::new(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("network-iocs"),
                );
                let count = store
                    .load_from_file(path)
                    .with_context(|| format!("loading network IOCs from {}", path.display()))?;
                info!(count, source = %path.display(), "network IOC store loaded");
                engine.add_network_store(store);
            }
        }

        let stats = engine.stats();
        eprintln!(
            "Scan engine: {} hash stores, {} network stores, {} Sigma rules",
            stats.hash_stores, stats.network_stores, stats.sigma_rules
        );

        // Run the scanning phase.
        let (finding_rows, scan_summary) =
            scanning::run_scan_phase(&events, &engine, evidence_path);

        // Enrich events with sig: tags from findings.
        let mut enriched_events = events;
        scanning::enrich_events(&mut enriched_events, &finding_rows);

        // Update enriched events in DuckDB (re-insert updates tags).
        let enriched_count = store.update_tags(&enriched_events).unwrap_or_else(|e| {
            eprintln!("Warning: failed to update event tags: {e}");
            0
        });
        if enriched_count > 0 {
            eprintln!("Enriched {enriched_count} event(s) with sig: tags");
        }

        // Store findings in DuckDB.
        findings::create_findings_table(store.connection())
            .context("Failed to create findings table")?;
        let findings_inserted = findings::insert_findings(store.connection(), &finding_rows)
            .context("Failed to insert findings")?;

        println!("Events evaluated:  {}", scan_summary.events_evaluated);
        println!("Files scanned:     {}", scan_summary.files_scanned);
        println!("Sigma findings:    {}", scan_summary.sigma_findings);
        println!("File findings:     {}", scan_summary.file_findings);
        println!("Network findings:  {}", scan_summary.network_findings);
        println!("Total findings:    {findings_inserted}");

        if scan_summary.total_findings > 0 {
            println!(
                "\nUse `rt timeline {} --flagged` to view findings.",
                output.display()
            );
        }
    }

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}
