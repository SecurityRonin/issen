#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::elidable_lifetime_names,
    clippy::match_same_arms,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::field_reassign_with_default,
    clippy::inefficient_to_string,
    clippy::manual_strip,
    clippy::redundant_else,
    clippy::trim_split_whitespace,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::unused_self,
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::missing_fields_in_debug,
    clippy::result_unit_err,
    clippy::unreadable_literal,
    clippy::manual_contains,
    clippy::unnecessary_literal_bound
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Remote access detection crate — public scan API.
//!
//! Orchestrates the LOLRMM/custom rule engine and category scanners,
//! returning merged [`Finding`]s via a single [`scan()`] entry point.

pub mod aggregator;
pub mod model;
pub mod providers;
pub mod rules;
pub mod scanners;
pub mod store;

use std::path::PathBuf;

use crate::model::{Finding, RemoteAccessCategory};
use crate::providers::{ArtifactProvider, ProviderCapability};
use crate::rules::detection_rule::compile_lolrmm;
use crate::rules::evaluator::evaluate_all;
use crate::rules::lolrmm::load_lolrmm_directory;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a scan run.
#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    /// Directory containing LOLRMM YAML definition files.
    pub lolrmm_dir: Option<PathBuf>,
    /// Directory containing custom YAML detection rules.
    pub custom_rules_dir: Option<PathBuf>,
    /// Category filter — `None` means scan all categories.
    pub categories: Option<Vec<RemoteAccessCategory>>,
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// The output of a [`scan()`] invocation.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Merged findings (deduplicated per tool + category).
    pub findings: Vec<Finding>,
    /// Capabilities advertised by the provider.
    pub available_capabilities: Vec<ProviderCapability>,
    /// Categories that were actually scanned.
    pub categories_scanned: Vec<RemoteAccessCategory>,
    /// Non-fatal warnings collected during the scan (e.g. failed scanners).
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run a full remote-access scan against the given provider.
///
/// Three phases:
/// 1. **Rule engine** — load LOLRMM and/or custom YAML, compile to
///    [`DetectionRule`](rules::detection_rule::DetectionRule)s, evaluate.
/// 2. **Category scanners** — run each [`CategoryScanner`](scanners::CategoryScanner),
///    optionally filtered by `config.categories`.
/// 3. **Merge** — deduplicate findings via [`aggregator::merge_findings`].
pub fn scan(provider: &dyn ArtifactProvider, config: &ScanConfig) -> ScanResult {
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut categories_scanned: Vec<RemoteAccessCategory> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // ------------------------------------------------------------------
    // Phase 1: Rule engine (LOLRMM + custom YAML)
    // ------------------------------------------------------------------
    let (rule_findings, rule_warnings) = run_rule_engine(provider, config);
    all_findings.extend(rule_findings);
    warnings.extend(rule_warnings);

    // ------------------------------------------------------------------
    // Phase 2: Category scanners
    // ------------------------------------------------------------------
    let scanners = scanners::all_scanners();
    for scanner in &scanners {
        let cat = scanner.category();

        // Apply category filter if configured.
        if let Some(ref allowed) = config.categories {
            if !allowed.contains(&cat) {
                continue;
            }
        }

        match scanner.scan(provider) {
            Ok(findings) => {
                if !categories_scanned.contains(&cat) {
                    categories_scanned.push(cat);
                }
                all_findings.extend(findings);
            }
            Err(e) => {
                let msg = format!("{} scanner failed: {e}", scanner.category());
                tracing::warn!(error = %e, "category scanner failed");
                warnings.push(msg);
            }
        }
    }

    // ------------------------------------------------------------------
    // Phase 3: Merge
    // ------------------------------------------------------------------
    let findings = aggregator::merge_findings(all_findings);
    let available_capabilities = provider.capabilities();

    ScanResult {
        findings,
        available_capabilities,
        categories_scanned,
        warnings,
    }
}

// ---------------------------------------------------------------------------
// Internal: rule engine
// ---------------------------------------------------------------------------

/// Load LOLRMM and custom YAML directories, compile rules, and evaluate.
///
/// Returns `(findings, warnings)`.
fn run_rule_engine(
    provider: &dyn ArtifactProvider,
    config: &ScanConfig,
) -> (Vec<Finding>, Vec<String>) {
    let mut rules = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // LOLRMM directory
    if let Some(ref dir) = config.lolrmm_dir {
        if dir.exists() {
            match load_lolrmm_directory(dir) {
                Ok(defs) => {
                    for (source_path, def) in &defs {
                        let source = source_path.display().to_string();
                        rules.push(compile_lolrmm(def, &source));
                    }
                }
                Err(e) => {
                    let msg = format!("failed to load LOLRMM directory {}: {e}", dir.display());
                    tracing::warn!(error = %e, "failed to load LOLRMM directory");
                    warnings.push(msg);
                }
            }
        }
    }

    // Custom rules directory (same format)
    if let Some(ref dir) = config.custom_rules_dir {
        if dir.exists() {
            match load_lolrmm_directory(dir) {
                Ok(defs) => {
                    for (source_path, def) in &defs {
                        let source = source_path.display().to_string();
                        rules.push(compile_lolrmm(def, &source));
                    }
                }
                Err(e) => {
                    let msg = format!(
                        "failed to load custom rules directory {}: {e}",
                        dir.display()
                    );
                    tracing::warn!(error = %e, "failed to load custom rules directory");
                    warnings.push(msg);
                }
            }
        }
    }

    if rules.is_empty() {
        return (Vec::new(), warnings);
    }

    (evaluate_all(&rules, provider), warnings)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{MockArtifactProvider, ProviderCapability, RegistryEntry};

    #[test]
    fn test_scan_with_mock_provider() {
        // Mock with RDP enabled: fDenyTSConnections = 0
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::RegistryKeys,
                ProviderCapability::EventLogs,
            ],
            ..MockArtifactProvider::default()
        };

        // The BuiltinRemoteScanner checks registry_values at this path
        // for fDenyTSConnections == "0".
        let ts_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
        mock.add_registry_value(
            ts_path,
            RegistryEntry {
                path: ts_path.into(),
                name: "fDenyTSConnections".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );

        let config = ScanConfig::default(); // no LOLRMM dir, scan all categories
        let result = scan(&mock, &config);

        // Should detect RDP as a finding.
        let rdp_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.tool_name == "RDP")
            .collect();
        assert!(
            !rdp_findings.is_empty(),
            "should detect RDP finding; got {:?}",
            result.findings
        );

        // Capabilities should be present.
        assert!(result
            .available_capabilities
            .contains(&ProviderCapability::RegistryKeys));

        // BuiltInRemoteAccess should be among scanned categories.
        assert!(
            result
                .categories_scanned
                .contains(&RemoteAccessCategory::BuiltInRemoteAccess),
            "BuiltInRemoteAccess should be in categories_scanned; got {:?}",
            result.categories_scanned
        );

        // A normal scan should produce no warnings.
        assert!(
            result.warnings.is_empty(),
            "successful scan should have no warnings; got {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_scan_empty_provider() {
        let mock = MockArtifactProvider::default(); // no caps, no data
        let config = ScanConfig::default();
        let result = scan(&mock, &config);

        assert!(
            result.findings.is_empty(),
            "empty provider should produce no findings"
        );
        assert!(
            result.available_capabilities.is_empty(),
            "empty provider should have no capabilities"
        );
        assert!(
            result.warnings.is_empty(),
            "empty provider scan should have no warnings"
        );
    }
}
