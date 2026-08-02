// Tests opt out of the panic lints (fleet standard) — unwrap/expect in test code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
pub mod adapters;
pub mod downloader;
pub mod engine;
pub mod evidence;
pub mod feeds;
pub mod loader;
pub mod rule;

pub use downloader::{load_manifest, prepare_feed_cache, save_manifest, stale_feeds};
pub use engine::{Finding, PivotEngine};
pub use evidence::{Evidence, EvidenceKind, EvidenceSource, SubjectRef};
pub use feeds::{cache_path_for_feed, is_stale, FeedKind, FeedSpec, SyncManifest};
pub use loader::{bundled_rules, default_feeds, load_rules_from_dir, load_rules_from_yaml_str};
pub use rule::{AssertionLevel, MatchClause, PivotRule, Severity};
