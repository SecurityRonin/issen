use std::path::Path;

use super::selector::{ArtifactSelector, NtfsLoc};
use super::traits::ForensicParser;
use crate::artifacts::ArtifactType;

/// Registration entry for the parser inventory.
///
/// Parser crates submit these via `inventory::submit!` to register
/// themselves at compile time with zero runtime cost.
pub struct ParserRegistration {
    pub create: fn() -> Box<dyn ForensicParser>,
    /// The artifact this parser consumes — the single source of truth the
    /// pipeline derives classification and disk collection from.
    ///
    /// Required: the compiler enforces that no parser can register without a
    /// selector, so "registered but unclassified/uncollected" is structurally
    /// impossible — the exact drift the dark-parser bugs came from.
    pub selector: ArtifactSelector,
}

inventory::collect!(ParserRegistration);

/// Discover all registered parsers. Returns one instance per registration.
///
/// This iterates the compile-time inventory — no filesystem scanning,
/// no dynamic loading, no configuration. Parsers are discovered by
/// linking them into the binary.
#[must_use]
pub fn all_parsers() -> Vec<Box<dyn ForensicParser>> {
    inventory::iter::<ParserRegistration>
        .into_iter()
        .map(|reg| (reg.create)())
        .collect()
}

/// Classify a path by the registered parsers' selectors: of every selector whose
/// `matches` accepts `path`, return the highest-`priority` one's `artifact_type`.
///
/// This is the registry-derived classifier that will replace the hand-written
/// `detect_artifact_type`. It is only meaningful where parser crates are linked
/// (the `issen` binary / a test that force-links the anchors); with no parsers
/// linked the inventory is empty and it returns `None`.
#[must_use]
pub fn detect_from_registry(path: &Path) -> Option<ArtifactType> {
    inventory::iter::<ParserRegistration>
        .into_iter()
        .filter(|reg| (reg.selector.matches)(path))
        .max_by_key(|reg| reg.selector.priority)
        .map(|reg| reg.selector.artifact_type)
}

/// The NTFS disk-collection locations every default-cost parser declares — the
/// registry-derived replacement for `issen_disk`'s hand-maintained `WINDOWS_*`
/// triage lists. `CostTier::OptIn` artifacts (e.g. PE) are excluded from default
/// triage. Only meaningful where parser crates are linked (empty otherwise).
#[must_use]
pub fn triage_ntfs_sources() -> Vec<NtfsLoc> {
    // Stage-3 stub: the collection differential drives the real implementation.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_parsers_returns_vec() {
        // No parsers are registered in rt-core itself,
        // so this should return an empty vec.
        // When parser crates are linked, they auto-register.
        let parsers = all_parsers();
        // We can't assert a specific count here because other test
        // binaries might link parser crates. Just assert it doesn't panic.
        assert!(parsers.len() < 1000, "sanity check");
    }

    #[test]
    fn test_parser_registration_struct() {
        use crate::artifacts::ArtifactType;
        use crate::error::RtError;
        use crate::plugin::traits::{DataSource, EventEmitter, ParseStats, ParserCapabilities};
        struct TestParser;

        impl ForensicParser for TestParser {
            fn name(&self) -> &'static str {
                "Test Parser"
            }
            fn supported_artifacts(&self) -> &[ArtifactType] {
                &[ArtifactType::Mft]
            }
            fn parse(
                &self,
                _input: &dyn DataSource,
                _emitter: &dyn EventEmitter,
            ) -> Result<ParseStats, RtError> {
                Ok(ParseStats::new())
            }
            fn capabilities(&self) -> ParserCapabilities {
                ParserCapabilities {
                    max_memory_bytes: None,
                    streaming: false,
                    deterministic: true,
                }
            }
        }

        let reg = ParserRegistration {
            create: || Box::new(TestParser),
            selector: ArtifactSelector {
                artifact_type: ArtifactType::Mft,
                matches: crate::classify::mft,
                priority: 0,
                disk_sources: &[],
                cost: crate::plugin::selector::CostTier::Default,
            },
        };
        let parser = (reg.create)();
        assert_eq!(parser.name(), "Test Parser");
        assert_eq!(parser.supported_artifacts(), &[ArtifactType::Mft]);
    }
}
