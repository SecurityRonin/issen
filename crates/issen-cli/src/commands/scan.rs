// Scan subcommand — scan files against threat intelligence signatures.
//
// Coordinates YARA, Sigma, hash IOC, network IOC, and STIX engines to scan
// files and report findings in text or JSON format.

use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

use issen_signatures::engines::ioc_hash::HashIocStore;
use issen_signatures::engines::ioc_network::NetworkIocStore;
use issen_signatures::engines::stix::StixParser;
use issen_signatures::engines::yara::YaraEngine;
use issen_signatures::matching::engine::ScanEngine;
use issen_signatures::matching::results::Severity;

/// Run the scan subcommand.
#[allow(clippy::too_many_arguments)]
pub fn run(
    target: &Path,
    yara_rules: Option<&Path>,
    sigma_rules: Option<&Path>,
    hash_iocs: Option<&[std::path::PathBuf]>,
    network_iocs: Option<&[std::path::PathBuf]>,
    stix_bundles: Option<&[std::path::PathBuf]>,
    min_severity: &str,
    format: &str,
    auto_feeds: bool,
) -> Result<()> {
    let threshold = Severity::from_str_lossy(min_severity);

    // Build the scan engine — optionally pre-loaded from cached feeds.
    let mut engine = if auto_feeds {
        load_engine_from_feeds()?
    } else {
        ScanEngine::new()
    };

    // Load YARA rules.
    if let Some(rules_path) = yara_rules {
        let yara = if rules_path.is_dir() {
            // Collect all .yar/.yara files from directory.
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

    // Load Sigma rules.
    if let Some(sigma_path) = sigma_rules {
        let mut sigma = issen_signatures::engines::sigma::SigmaEngine::new();
        if sigma_path.is_dir() {
            let count = sigma
                .load_rules_dir(sigma_path)
                .with_context(|| format!("loading Sigma rules from {}", sigma_path.display()))?;
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

    // Load hash IOC files.
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

    // Load network IOC files.
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

    // Load STIX bundles into hash/network stores.
    if let Some(bundles) = stix_bundles {
        for bundle_path in bundles {
            let indicators = StixParser::parse_file(bundle_path)
                .with_context(|| format!("parsing STIX bundle: {}", bundle_path.display()))?;

            let mut hash_store = HashIocStore::new(
                bundle_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("stix"),
            );
            let mut net_store = NetworkIocStore::new(
                bundle_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("stix"),
            );

            for indicator in &indicators {
                use issen_signatures::engines::stix::ExtractedIoc;
                for ioc in &indicator.iocs {
                    match ioc {
                        ExtractedIoc::Sha256(h) | ExtractedIoc::Sha1(h) | ExtractedIoc::Md5(h) => {
                            let _ = hash_store.inseissen_bad(h);
                        }
                        ExtractedIoc::Ipv4(ip) | ExtractedIoc::Ipv6(ip) => {
                            let _ = net_store.inseissen_ip(ip);
                        }
                        ExtractedIoc::Domain(d) => {
                            net_store.inseissen_domain(d);
                        }
                        ExtractedIoc::Url(u) => {
                            // Extract domain from URL.
                            if let Some(host) = extract_host(u) {
                                net_store.inseissen_domain(&host);
                            }
                        }
                    }
                }
            }

            let h_count = hash_store.bad_count();
            let n_count = net_store.ip_count() + net_store.domain_count();
            info!(
                hashes = h_count,
                network = n_count,
                source = %bundle_path.display(),
                "STIX bundle loaded"
            );

            if hash_store.bad_count() > 0 {
                engine.add_hash_store(hash_store);
            }
            if net_store.ip_count() + net_store.domain_count() + net_store.cidr_count() > 0 {
                engine.add_network_store(net_store);
            }
        }
    }

    // Print engine stats.
    let stats = engine.stats();
    eprintln!(
        "Scan engine: {} YARA rules, {} Sigma rules, {} hash stores ({} hashes), {} network stores",
        stats.yara_rules,
        stats.sigma_rules,
        stats.hash_stores,
        stats.total_bad_hashes,
        stats.network_stores
    );

    // Scan the target.
    let files = collect_files(target)?;
    if files.is_empty() {
        anyhow::bail!("No files found at {}", target.display());
    }

    eprintln!("Scanning {} file(s)...", files.len());

    let mut total_findings = 0;
    let mut all_reports = Vec::new();

    for file_path in &files {
        let report = engine
            .scan_file(file_path)
            .with_context(|| format!("scanning {}", file_path.display()))?;

        let filtered: Vec<_> = report
            .findings_at_or_above(threshold)
            .into_iter()
            .cloned()
            .collect();
        total_findings += filtered.len();

        if !filtered.is_empty() {
            if format == "text" {
                print_text_report(file_path, &filtered);
            }
            all_reports.push((file_path.clone(), filtered));
        }
    }

    if format == "json" {
        print_json_reports(&all_reports)?;
    }

    eprintln!(
        "\nScan complete: {} file(s) scanned, {} finding(s) at or above '{}' severity",
        files.len(),
        total_findings,
        threshold
    );

    Ok(())
}

/// Collect all files from a path (recurse into directories).
fn collect_files(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        collect_files_recursive(path, &mut files)?;
    }
    Ok(files)
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            collect_files_recursive(&path, files)?;
        }
    }
    Ok(())
}

/// Print findings for one file in text format.
fn print_text_report(file_path: &Path, findings: &[issen_signatures::matching::results::ScanFinding]) {
    println!("--- {} ---", file_path.display());
    for f in findings {
        let indicator_str = f
            .matched_indicator
            .as_deref()
            .map(|i| format!(" [{}]", i))
            .unwrap_or_default();
        println!(
            "  [{severity}] ({source}) {rule}{indicator}",
            severity = f.severity,
            source = f.source,
            rule = f.rule_name,
            indicator = indicator_str,
        );
        println!("    {}", f.description);
        if !f.tags.is_empty() {
            println!("    tags: {}", f.tags.join(", "));
        }
    }
}

/// Print all reports as JSON.
fn print_json_reports(
    reports: &[(
        std::path::PathBuf,
        Vec<issen_signatures::matching::results::ScanFinding>,
    )],
) -> Result<()> {
    let json_reports: Vec<serde_json::Value> = reports
        .iter()
        .map(|(path, findings)| {
            serde_json::json!({
                "file": path.display().to_string(),
                "findings": findings.iter().map(|f| {
                    serde_json::json!({
                        "source": format!("{}", f.source),
                        "severity": format!("{}", f.severity),
                        "rule_name": f.rule_name,
                        "description": f.description,
                        "matched_indicator": f.matched_indicator,
                        "tags": f.tags,
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_reports)?);
    Ok(())
}

/// Load a ScanEngine pre-populated from cached threat intel feeds.
fn load_engine_from_feeds() -> Result<ScanEngine> {
    let feed_cache_dir = default_feed_cache_dir();
    let registry = issen_signatures::feeds::config::FeedRegistry::with_defaults(&feed_cache_dir);
    let feed_cache = issen_signatures::feeds::fetcher::FeedCache::new(&feed_cache_dir);

    let (engine, summary) = issen_signatures::feeds::loader::load_cached_feeds(&registry, &feed_cache)
        .map_err(|e| anyhow::anyhow!("failed to load cached feeds: {e}"))?;

    if summary.feeds_loaded > 0 {
        eprintln!(
            "Auto-feeds: loaded {} feed(s) ({} hash IOCs, {} network IOCs)",
            summary.feeds_loaded, summary.hash_indicators, summary.network_indicators,
        );
    } else {
        eprintln!("Auto-feeds: no cached feeds found. Run `rt feed update` first.");
    }

    Ok(engine)
}

/// Get the default feed cache directory (same as feed/ingest subcommands).
fn default_feed_cache_dir() -> std::path::PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        std::path::Path::new(&home).join(".local/share/issen/feeds")
    } else {
        std::path::PathBuf::from(".issen/feeds")
    }
}

/// Extract the host from a URL string (simple implementation).
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.find("://").map(|pos| &url[pos + 3..]).unwrap_or(url);
    let host_port = after_scheme.split('/').next()?;
    let host = if let Some(colon) = host_port.rfind(':') {
        let after = &host_port[colon + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) && !after.is_empty() {
            &host_port[..colon]
        } else {
            host_port
        }
    } else {
        host_port
    };
    let h = host.trim().to_lowercase();
    if h.is_empty() {
        None
    } else {
        Some(h)
    }
}
