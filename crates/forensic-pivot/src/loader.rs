use std::path::Path;

use crate::rule::PivotRule;

/// Parse a YAML string (one or more `---`-separated documents) into rules.
pub fn load_rules_from_yaml_str(_yaml: &str) -> anyhow::Result<Vec<PivotRule>> {
    todo!("Phase 3 GREEN: implement YAML rule loading")
}

/// Walk `dir` for `*.yml` / `*.yaml` files and load rules from each.
/// Never fails — bad files are silently skipped.
#[must_use]
pub fn load_rules_from_dir(_dir: &Path) -> Vec<PivotRule> {
    todo!("Phase 3 GREEN: implement directory scanning")
}

/// Return the built-in rule set compiled into the binary.
#[must_use]
pub fn bundled_rules() -> Vec<PivotRule> {
    todo!("Phase 3 GREEN: implement bundled rules")
}
