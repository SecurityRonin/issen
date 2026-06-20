// Feed management subcommand — list, update, and inspect threat intel feeds.
//
// Provides CLI access to the feed registry and downloader:
//   rt feed list    — show all configured feeds and their cache status
//   rt feed update  — download all enabled feeds
//   rt feed info ID — show details for one feed

use std::path::Path;

use anyhow::{Context, Result};

use issen_correlation::attack_flow::download_attack_flow_corpus_zip;
use issen_signatures::feeds::config::FeedRegistry;
use issen_signatures::feeds::downloader::{download_all_feeds, DownloadStatus};
use issen_signatures::feeds::fetcher::FeedCache;

/// Run the feed subcommand with the given action.
pub fn run(action: &FeedAction) -> Result<()> {
    // Use a standard cache directory under the user's data dir.
    let cache_dir = default_cache_dir();
    let registry = FeedRegistry::with_defaults(&cache_dir);
    let cache = FeedCache::new(&cache_dir);

    match action {
        FeedAction::List => run_list(&registry, &cache),
        FeedAction::Update => run_update(&registry, &cache),
        FeedAction::Info { id } => run_info(&registry, &cache, id),
        FeedAction::AttackFlow { cache_dir: dir } => run_attack_flow(dir.as_deref()),
    }
}

/// Feed subcommand actions.
#[derive(Debug, Clone)]
pub enum FeedAction {
    /// Show all configured feeds and their cache status.
    List,
    /// Download all enabled feeds.
    Update,
    /// Show details for a specific feed.
    Info { id: String },
    /// Download the CTID Attack Flow v3.0.0 corpus zip.
    AttackFlow {
        cache_dir: Option<std::path::PathBuf>,
    },
}

/// List all configured feeds with their status.
#[allow(clippy::unnecessary_wraps)] // signature must match sibling run_* arms in the dispatch match
fn run_list(registry: &FeedRegistry, cache: &FeedCache) -> Result<()> {
    println!(
        "{:<35} {:<8} {:<12} {:<10} Name",
        "ID", "Enabled", "Cached", "Type"
    );
    println!("{}", "-".repeat(90));

    for feed in &registry.feeds {
        let cached = if cache.is_cached(&feed.id) {
            "yes"
        } else {
            "no"
        };
        let enabled = if feed.enabled { "yes" } else { "no" };

        println!(
            "{:<35} {:<8} {:<12} {:<10} {}",
            feed.id,
            enabled,
            cached,
            format!("{:?}", feed.indicator_type).to_lowercase(),
            feed.name,
        );
    }

    println!(
        "\n{} feeds configured ({} enabled)",
        registry.len(),
        registry.enabled_feeds().len()
    );

    Ok(())
}

/// Download all enabled feeds.
fn run_update(registry: &FeedRegistry, cache: &FeedCache) -> Result<()> {
    println!(
        "Updating {} enabled feed(s)...\n",
        registry.enabled_feeds().len()
    );

    let results = download_all_feeds(registry, cache);

    let mut downloaded = 0;
    let mut not_modified = 0;
    let mut skipped = 0;
    let mut failed = 0;

    for result in &results {
        let status_str = match &result.status {
            DownloadStatus::Downloaded => {
                downloaded += 1;
                format!("downloaded ({} bytes)", result.bytes_downloaded)
            }
            DownloadStatus::NotModified => {
                not_modified += 1;
                "not modified".into()
            }
            DownloadStatus::Skipped(reason) => {
                skipped += 1;
                format!("skipped: {reason}")
            }
            DownloadStatus::Failed(err) => {
                failed += 1;
                format!("FAILED: {err}")
            }
        };
        println!("  {:<35} {}", result.feed_id, status_str);
    }

    println!(
        "\nSummary: {downloaded} downloaded, {not_modified} not modified, {skipped} skipped, {failed} failed"
    );

    if failed > 0 {
        anyhow::bail!("{failed} feed(s) failed to download");
    }

    Ok(())
}

/// Show details for a single feed.
fn run_info(registry: &FeedRegistry, cache: &FeedCache, id: &str) -> Result<()> {
    let feed = registry
        .find_feed(id)
        .with_context(|| format!("feed '{id}' not found in registry"))?;

    println!("Feed: {}", feed.name);
    println!("  ID:              {}", feed.id);
    println!("  Description:     {}", feed.description);
    println!(
        "  URL:             {}",
        feed.url.as_deref().unwrap_or("(none)")
    );
    println!("  Format:          {:?}", feed.format);
    println!("  Indicator type:  {:?}", feed.indicator_type);
    println!("  Update freq:     {:?}", feed.update_frequency);
    println!("  Enabled:         {}", feed.enabled);
    println!("  Requires API key:{}", feed.requires_api_key);
    println!(
        "  License:         {}",
        feed.license.as_deref().unwrap_or("(unknown)")
    );

    // Cache info.
    if cache.is_cached(&feed.id) {
        println!("  Cached:          yes");
        if let Ok(meta) = cache.load_metadata(&feed.id) {
            println!("  Last fetched:    {}", meta.last_fetched);
            println!("  File size:       {} bytes", meta.file_size);
            println!("  Indicators:      {}", meta.indicator_count);
            if let Some(ref etag) = meta.etag {
                println!("  ETag:            {etag}");
            }
        }
    } else {
        println!("  Cached:          no");
    }

    Ok(())
}

/// Download the CTID Attack Flow corpus zip.
fn run_attack_flow(cache_dir: Option<&Path>) -> Result<()> {
    let dir = if let Some(d) = cache_dir {
        d.to_path_buf()
    } else {
        dirs_or_fallback()
            .unwrap_or_else(|| std::path::PathBuf::from(".issen"))
            .join("attack-flow")
    };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("cannot create cache dir: {}", dir.display()))?;
    println!("Downloading Attack Flow corpus → {}", dir.display());
    let dest = download_attack_flow_corpus_zip(&dir)?;
    println!("  Saved: {}", dest.display());
    println!("  Done.");
    Ok(())
}

/// Get the default cache directory for feeds.
fn default_cache_dir() -> std::path::PathBuf {
    // Use $HOME/.local/share/issen/feeds or a sensible default.
    if let Some(data_dir) = dirs_or_fallback() {
        data_dir.join("feeds")
    } else {
        std::path::PathBuf::from(".issen/feeds")
    }
}

/// Try to find a data directory. Falls back to $HOME/.local/share/issen.
fn dirs_or_fallback() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| Path::new(&h).join(".local/share/issen"))
}
