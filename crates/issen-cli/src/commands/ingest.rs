use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use issen_core::artifacts::ArtifactType;
use issen_fswalker::orchestrator::run_auto_units;
use issen_remote_io::gdrive;
use issen_remote_io::uri::{is_remote_uri, UriScheme};
use issen_signatures::engines::ioc_hash::HashIocStore;
use issen_signatures::engines::ioc_network::NetworkIocStore;
use issen_signatures::engines::yara::YaraEngine;
use issen_signatures::matching::engine::ScanEngine;
use issen_timeline::findings;
use issen_timeline::store::TimelineStore;
use std::io::IsTerminal;
use tracing::info;

use crate::scanning;

/// Get the default feed cache directory (same as feed subcommand).
fn default_feed_cache_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        Path::new(&home).join(".local/share/issen/feeds")
    } else {
        PathBuf::from(".issen/feeds")
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
    evidence_paths: &[PathBuf],
    output: &Path,
    evidence_source: Option<&str>,
    source_uri: Option<&str>,
    scan: bool,
    yara_rules: Option<&Path>,
    sigma_rules: Option<&Path>,
    hash_iocs: Option<&[PathBuf]>,
    network_iocs: Option<&[PathBuf]>,
    refresh: bool,
    verbose: bool,
) -> Result<()> {
    // Remote source URI dispatch.
    if let Some(uri) = source_uri {
        if !is_remote_uri(uri) {
            anyhow::bail!("Unsupported URI scheme: {uri}");
        }

        let scheme = UriScheme::detect(uri)
            .ok_or_else(|| anyhow::anyhow!("Unsupported URI scheme: {uri}"))?;

        if scheme == UriScheme::GDrive {
            let file_id = gdrive::parse_file_id(uri)
                .ok_or_else(|| anyhow::anyhow!("Could not parse gdrive file ID from: {uri}"))?;
            let auth = issen_remote_io::gdrive::auth::resolve_auth_mode();
            println!("Remote source URI: gdrive://{file_id} (auth: {auth:?})");
            println!(
                "Note: gdrive fetch is a stub — download would stream to a temp file for ingest."
            );
        } else {
            // All other recognised schemes use the OpenDAL operator.
            let (_, path) = issen_remote_io::operator::operator_for_uri(uri)
                .with_context(|| format!("building operator for source URI: {uri}"))?;
            println!("Remote source URI: {uri} (path: {path})");
            println!(
                "Note: remote fetch is a stub — bytes would be streamed to a temp file for ingest."
            );
        }

        return Ok(());
    }

    for p in evidence_paths {
        if !p.exists() {
            anyhow::bail!("Evidence path does not exist: {}", p.display());
        }
    }

    // Open or create the DuckDB timeline store.
    let store = TimelineStore::open(output).context("Failed to open timeline database")?;

    // Guard against a concurrent ingest corrupting the resumable-ingestion state
    // (issen #115). RAII: the <case>.ingest.lock is released when `_case_lock`
    // drops at function exit. The lock logic is unit-tested in issen-timeline.
    let _case_lock = issen_timeline::ingest::CaseLock::acquire(output).context(
        "another ingest is already running for this case (delete a stale *.ingest.lock if not)",
    )?;

    // Resolve inputs into attributable evidence sources: a folder of disk images
    // expands to one source per image; each gets a collision-resistant id so two
    // hosts' otherwise-identical artifacts stay distinct in the unified timeline.
    let mut sources = issen_fswalker::sources::resolve_evidence_sources(evidence_paths);
    if sources.len() == 1 {
        // Single source keeps the historical id (explicit --evidence-source, else
        // "default") for backward compatibility and stable resume keys.
        sources[0].source_id = evidence_source.unwrap_or("default").to_string();
    } else if evidence_source.is_some() {
        eprintln!(
            "warning: --evidence-source is ignored for multi-source ingest; \
             a distinct per-source id is used for each input"
        );
    }

    // Live display: one bar per source, only on an interactive terminal and not
    // under --verbose (where the bar would fight scrolling logs). Bars draw to
    // stderr, so the TTY check is on stderr.
    let render = crate::progress_view::should_render_bar(std::io::stderr().is_terminal(), verbose);
    let mp = indicatif::MultiProgress::new();
    if render {
        // Restore the terminal if the analyst Ctrl-C's mid-ingest.
        crate::ingest_progress::install_sigint_cleanup(&mp);
    }
    let mut inserted = 0u64;
    // The committed events, kept flat for the optional signature-scan phase.
    let mut events = Vec::new();
    let mut t_found = 0usize;
    let mut t_parsed = 0usize;
    let mut t_events = 0u64;
    let mut t_bytes = 0u64;
    let mut t_skipped = 0usize;
    let mut all_errors: Vec<String> = Vec::new();

    for src in &sources {
        let source_id = src.source_id.as_str();
        let source_label = src.path.display().to_string();
        if !render {
            if sources.len() > 1 {
                println!("\n=== Source [{source_id}]: {source_label} ===");
            } else {
                println!("Ingesting evidence from: {source_label}");
            }
        }
        let sp = crate::ingest_progress::SourceProgress::start(&mp, &source_label, render);
        // Record source provenance (chain-of-custody): SHA-256 + size for a loose
        // evidence file, size only for a container (its acquisition hash is a
        // follow-up — needs an MD5/SHA1 schema field + ewf::stored_hashes).
        let (sha256, size) = issen_fswalker::sources::source_provenance(&src.path);
        store
            .register_evidence_source(
                source_id,
                &src.path.to_string_lossy(),
                sha256.as_deref(),
                size,
            )
            .context("Failed to register evidence source")?;

        // Resumable, per-unit ingestion (issen #115). Each (artifact, parser) is a
        // unit committed atomically; units already completed for this evidence
        // source are skipped (resume by default) unless `--refresh` forces a full
        // re-parse. Read the resume skip-list BEFORE parsing so completed units
        // skip the parse cost entirely. `commit_unit`'s delete-first makes a
        // re-parse idempotent.
        let completed = if refresh {
            std::collections::HashSet::new()
        } else {
            store
                .completed_units(source_id)
                .context("Failed to read resume state")?
        };

        // A unit is skipped when its (source, artifact-type, path, parser) identity
        // — the same stable id `commit_unit` keys on — is already complete. The
        // `bytes` field does not affect the id, so 0 here matches the commit path.
        let skip = |at: &ArtifactType, path: &Path, parser: &str| {
            let unit_id = issen_timeline::ingest::IngestUnit::new(
                source_id,
                &format!("{at:?}"),
                &path.to_string_lossy(),
                parser,
                0,
            )
            .unit_id;
            completed.contains(&unit_id)
        };
        let (units, result, skipped) =
            run_auto_units(&src.path, sp.reporter(), &skip).context("Pipeline execution failed")?;

        // Every returned unit is pending (completed ones were skipped before
        // parse), so each is committed unconditionally.
        for pu in units {
            let mut unit = issen_timeline::ingest::IngestUnit::new(
                source_id,
                &format!("{:?}", pu.artifact_type),
                &pu.path.to_string_lossy(),
                &pu.parser,
                i64::try_from(pu.bytes).unwrap_or(i64::MAX),
            );
            // Only mark the unit complete for resume if the parse terminally
            // completed; an Undeclared/Incomplete/Unsupported/CorruptFatal parse
            // keeps its events but stays re-parseable (issen #115 correctness).
            unit.complete = pu.completion.marks_complete();
            // Re-stamp each event's evidence_source_id with the resolved per-source
            // id (parsers hardcode a placeholder, e.g. "evtx-evidence"). Without
            // this, two hosts' identical events share a record_hash and one is
            // dropped as a duplicate — the cross-host attribution would be lost.
            let restamped: Vec<_> = pu
                .events
                .into_iter()
                .map(|e| e.with_evidence_source(source_id))
                .collect();
            inserted += store
                .commit_unit(&unit, &restamped)
                .context("Failed to commit ingest unit")?;
            events.extend(restamped);
        }

        t_found += result.artifacts_found;
        t_parsed += result.artifacts_parsed;
        t_events += result.total_events;
        t_bytes += result.total_bytes;
        t_skipped += skipped;
        let (n_parsed, n_events, n_errors) = (
            result.artifacts_parsed,
            result.total_events,
            result.errors.len(),
        );
        all_errors.extend(result.errors);
        let err_suffix = if n_errors > 0 {
            format!(" · {n_errors} errors")
        } else {
            String::new()
        };
        sp.finish(&format!(
            "✓ {n_parsed} artifacts · {n_events} events{err_suffix}"
        ));
    }

    if sources.len() > 1 {
        println!("\nSources ingested: {}", sources.len());
    }
    println!("Artifacts found:  {t_found}");
    println!("Artifacts parsed: {t_parsed}");
    println!("Events generated: {t_events}");
    println!("Events committed: {inserted} across {t_parsed} units");
    if t_skipped > 0 {
        println!("Units resumed:    {t_skipped} (already complete, skipped)");
    }
    println!("Bytes processed:  {}", format_bytes(t_bytes));
    println!("Database:         {}", output.display());

    if !all_errors.is_empty() {
        eprintln!("\n{} error(s) during parsing:", all_errors.len());
        for err in &all_errors {
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
                issen_signatures::feeds::config::FeedRegistry::with_defaults(&feed_cache_dir);
            let feed_cache = issen_signatures::feeds::fetcher::FeedCache::new(&feed_cache_dir);

            let load_result =
                issen_signatures::feeds::loader::load_cached_feeds(&registry, &feed_cache);
            let (eng, load_summary) = match load_result {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("Warning: failed to load feeds: {e}");
                    eprintln!("Scanning with empty engine (no feeds loaded).");
                    (
                        ScanEngine::new(),
                        issen_signatures::feeds::loader::LoadSummary::default(),
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
                let refs: Vec<&str> = sources.iter().map(std::string::String::as_str).collect();
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
            let mut sigma = issen_signatures::engines::sigma::SigmaEngine::new();
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

        // Run the scanning phase. The evidence-root label is the first source
        // (a per-event source_id already attributes findings per host).
        let scan_root = sources.first().map_or(output, |s| s.path.as_path());
        let (finding_rows, scan_summary) = scanning::run_scan_phase(&events, &engine, scan_root);

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
        let findings_inserted = findings::inseissen_findings(store.connection(), &finding_rows)
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

/// Default output DB path when `-o/--output` is omitted:
/// `issen-ingested-<UTC>Z.duckdb`, e.g. `issen-ingested-2026-06-20T180159Z.duckdb`.
/// The timestamp is colon-free for cross-platform filenames; the trailing `Z`
/// marks UTC (Zulu).
pub fn auto_output_path(now: chrono::DateTime<chrono::Utc>) -> PathBuf {
    PathBuf::from(format!(
        "issen-ingested-{}.duckdb",
        now.format("%Y-%m-%dT%H%M%SZ")
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn auto_output_name_is_utc_z_stamped() {
        // A fixed UTC instant → a colon-free, Z-suffixed default DB name.
        let ts = chrono::Utc
            .with_ymd_and_hms(2026, 6, 20, 18, 1, 59)
            .unwrap();
        assert_eq!(
            auto_output_path(ts),
            PathBuf::from("issen-ingested-2026-06-20T180159Z.duckdb")
        );
    }
}
