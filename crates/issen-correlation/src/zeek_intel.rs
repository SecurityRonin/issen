//! Zeek Intel file importer.
//!
//! Parses the tab-separated format used by the Zeek Intelligence Framework.
//! See <https://docs.zeek.org/en/current/frameworks/intel.html>.
//!
//! Format: each data row is tab-separated with at minimum:
//!   `indicator  indicator_type  meta.source  [additional fields...]`
//!
//! Lines starting with `#` are metadata / comments and are skipped.
//! Empty lines are also skipped.

use thiserror::Error;

use crate::model::IndicatorType;

// ── Output type ───────────────────────────────────────────────────────────────

/// A single atomic indicator imported from a Zeek intel file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeekIndicator {
    /// The raw indicator value (IP, domain, hash, etc.).
    pub value: String,
    /// Mapped `IndicatorType`.
    pub indicator_type: IndicatorType,
    /// `meta.source` field — provenance of this indicator.
    pub source: String,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ZeekIntelError {
    /// The `#fields` header line was absent or malformed.
    #[error("missing or malformed #fields header")]
    MissingHeader,
    /// A required column (`indicator`, `indicator_type`, or `meta.source`)
    /// was not found in the header.
    #[error("required column '{0}' not found in #fields header")]
    MissingColumn(String),
}

// ── Column index ──────────────────────────────────────────────────────────────

struct ColumnIndex {
    indicator: usize,
    indicator_type: usize,
    meta_source: usize,
}

impl ColumnIndex {
    fn from_fields_line(line: &str) -> Result<Self, ZeekIntelError> {
        // Strip the leading "#fields\t" prefix, then split on tabs.
        let fields_part = line
            .strip_prefix("#fields\t")
            .ok_or(ZeekIntelError::MissingHeader)?;
        let cols: Vec<&str> = fields_part.split('\t').collect();

        let find = |name: &str| {
            cols.iter()
                .position(|&c| c == name)
                .ok_or_else(|| ZeekIntelError::MissingColumn(name.to_string()))
        };

        Ok(Self {
            indicator: find("indicator")?,
            indicator_type: find("indicator_type")?,
            meta_source: find("meta.source")?,
        })
    }
}

// ── Type mapping ──────────────────────────────────────────────────────────────

fn map_indicator_type(raw: &str) -> IndicatorType {
    match raw {
        "Intel::ADDR" => IndicatorType::IpAddr,
        "Intel::DOMAIN" => IndicatorType::Domain,
        "Intel::URL" => IndicatorType::Url,
        "Intel::EMAIL" => IndicatorType::Email,
        "Intel::MD5" | "Intel::SHA1" | "Intel::SHA256" | "Intel::PUBKEY_HASH" => {
            IndicatorType::FileHash
        }
        "Intel::SOFTWARE" | "Intel::USER_NAME" => IndicatorType::Other(raw.to_string()),
        other => IndicatorType::Other(other.to_string()),
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a Zeek intel file from its full text content.
///
/// The function is lenient: malformed data rows are skipped silently.
///
/// # Errors
///
/// Returns an error only if the `#fields` header is absent or missing
/// required columns (`indicator`, `indicator_type`, `meta.source`).
pub fn parse_zeek_intel(content: &str) -> Result<Vec<ZeekIndicator>, ZeekIntelError> {
    let mut col_idx: Option<ColumnIndex> = None;
    let mut indicators = Vec::new();

    for line in content.lines() {
        // Blank lines — skip.
        if line.trim().is_empty() {
            continue;
        }

        if line.starts_with("#fields\t") {
            col_idx = Some(ColumnIndex::from_fields_line(line)?);
            continue;
        }

        // Other comment / metadata lines — skip.
        if line.starts_with('#') {
            continue;
        }

        // Data row.
        let Some(ref idx) = col_idx else {
            // No header seen yet; skip.
            continue;
        };

        let cols: Vec<&str> = line.split('\t').collect();
        let get = |i: usize| cols.get(i).copied().unwrap_or("").trim();

        let value = get(idx.indicator);
        let raw_type = get(idx.indicator_type);
        let source = get(idx.meta_source);

        if value.is_empty() || raw_type.is_empty() {
            continue;
        }

        indicators.push(ZeekIndicator {
            value: value.to_string(),
            indicator_type: map_indicator_type(raw_type),
            source: source.to_string(),
        });
    }

    Ok(indicators)
}
