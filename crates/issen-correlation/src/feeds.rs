use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Transport families ────────────────────────────────────────────────────────

/// Authentication configuration for feeds that require credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthConfig {
    /// HTTP Bearer token.
    Bearer { token: String },
    /// HTTP Basic auth.
    Basic { username: String, password: String },
    /// Pre-shared API key header (name + value).
    ApiKey { header: String, value: String },
}

/// Archive format for `HttpArchive` transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    TarGz,
    Zip,
    Plain,
}

/// How a feed is fetched from its upstream source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeedTransport {
    /// Git repository snapshot (clone or archive download).
    Git {
        repo_url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        branch: Option<String>,
    },
    /// Single archive file (zip, tar.gz, or plain).
    HttpArchive { url: String, format: ArchiveFormat },
    /// Plain JSON endpoint.
    HttpJson {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth: Option<AuthConfig>,
    },
    /// TAXII 2.x collection endpoint.
    Taxii {
        discovery_url: String,
        collection_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth: Option<AuthConfig>,
    },
    /// Direct MISP instance API.
    MispApi { base_url: String, auth_key: String },
}

// ── Schema family ─────────────────────────────────────────────────────────────

/// High-level schema/format family of a feed's content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaFamily {
    Yara,
    Sigma,
    Suricata,
    Stix,
    MispWarninglist,
    MispEvent,
    MispGalaxy,
    ZeekIntel,
    AttackStix,
    RtCorrelation,
    Other(String),
}

// ── Parse status ──────────────────────────────────────────────────────────────

/// Outcome of parsing a downloaded feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ParseStatus {
    /// All content parsed successfully.
    Ok { rule_count: usize },
    /// Some content parsed; errors noted but non-fatal.
    PartialError {
        rule_count: usize,
        errors: Vec<String>,
    },
    /// Parsing failed entirely.
    Failed { error: String },
}

// ── Feed manifest ─────────────────────────────────────────────────────────────

/// Persisted record of a completed feed sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedManifest {
    /// Stable identifier for this feed source (e.g. `"sigmahq/sigma"`).
    pub source_id: String,
    /// The schema/format family of the feed content.
    pub schema_family: SchemaFamily,
    /// Transport used to fetch the feed.
    pub transport: FeedTransport,
    /// Version token: git commit hash, HTTP `ETag`, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Incremental cursor for TAXII polling (`added_after` timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taxii_cursor: Option<String>,
    /// When this sync ran.
    pub fetched_at: DateTime<Utc>,
    /// Absolute path to the locally cached / extracted content.
    pub local_cache_path: PathBuf,
    /// Result of parsing the downloaded content.
    pub parse_status: ParseStatus,
}

pub fn placeholder() {}
