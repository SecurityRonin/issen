//! MISP warninglist importer.
//!
//! Parses the JSON format used by <https://github.com/MISP/misp-warninglists>.
//! Warninglists are imported as `ReferenceDataset` content used for
//! false-positive suppression during finding post-processing.

use std::collections::HashSet;

use serde::Deserialize;
use thiserror::Error;

/// A parsed MISP warninglist, ready for FP-candidate lookup.
#[derive(Debug, Clone)]
pub struct Warninglist {
    /// Human-readable name (e.g. "Top 1000 Alexa").
    pub name: String,
    /// Type string as given by MISP (e.g. "hostname", "ip-dst", "url").
    pub list_type: String,
    /// The set of values in this list.
    entries: HashSet<String>,
}

impl Warninglist {
    /// Returns `true` if `value` is present in the warninglist.
    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.entries.contains(value)
    }

    /// Returns `true` if `indicator` is a false-positive candidate (i.e. it
    /// appears in this warninglist).
    #[must_use]
    pub fn is_fp_candidate(&self, indicator: &str) -> bool {
        self.contains(indicator)
    }
}

// ── JSON schema ───────────────────────────────────────────────────────────────

/// Raw deserialization shape of a single MISP warninglist file.
#[derive(Debug, Deserialize)]
struct RawWarninglist {
    name: String,
    #[serde(rename = "type")]
    list_type: String,
    list: Vec<String>,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum WarninglistError {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a single MISP warninglist from its JSON representation.
///
/// # Errors
///
/// Returns [`WarninglistError::Json`] if `json` is not valid warninglist JSON.
pub fn parse_warninglist(json: &str) -> Result<Warninglist, WarninglistError> {
    let raw: RawWarninglist = serde_json::from_str(json)?;
    Ok(Warninglist {
        name: raw.name,
        list_type: raw.list_type,
        entries: raw.list.into_iter().collect(),
    })
}
