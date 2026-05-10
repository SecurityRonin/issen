use std::fs;
use std::path::{Path, PathBuf};

use crate::model::CorrelationRule;

#[derive(Debug, thiserror::Error)]
pub enum RuleLoadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[must_use]
pub fn bundled_rule_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules")
}

/// Load a single correlation rule from a YAML file.
///
/// # Errors
///
/// Returns [`RuleLoadError::Io`] if the file cannot be read, or
/// [`RuleLoadError::Yaml`] if the YAML cannot be parsed.
pub fn load_rule_file(path: &Path) -> Result<CorrelationRule, RuleLoadError> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&raw)?)
}

/// Load all `.yml`/`.yaml` correlation rules from a directory, sorted by filename.
///
/// # Errors
///
/// Returns [`RuleLoadError`] if any file cannot be read or parsed.
pub fn load_rule_pack(dir: &Path) -> Result<Vec<CorrelationRule>, RuleLoadError> {
    let mut entries = fs::read_dir(dir)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| matches!(ext, "yml" | "yaml"))
        })
        .collect::<Vec<_>>();
    entries.sort();

    entries
        .into_iter()
        .map(|path| load_rule_file(&path))
        .collect()
}

/// Load and merge correlation rules from multiple directories.
///
/// Rules from later directories override earlier ones when they share the same `id`.
///
/// # Errors
///
/// Returns [`RuleLoadError`] if any file cannot be read or parsed.
pub fn load_rule_sources(dirs: &[PathBuf]) -> Result<Vec<CorrelationRule>, RuleLoadError> {
    let mut merged = Vec::new();

    for dir in dirs {
        for rule in load_rule_pack(dir)? {
            if let Some(existing) = merged
                .iter()
                .position(|current: &CorrelationRule| current.id == rule.id)
            {
                merged[existing] = rule;
            } else {
                merged.push(rule);
            }
        }
    }

    merged.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(merged)
}
