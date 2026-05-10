use super::traits::ForensicParser;

/// Registration entry for the parser inventory.
///
/// Parser crates submit these via `inventory::submit!` to register
/// themselves at compile time with zero runtime cost.
pub struct ParserRegistration {
    pub create: fn() -> Box<dyn ForensicParser>,
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
            fn name(&self) -> &str {
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
        };
        let parser = (reg.create)();
        assert_eq!(parser.name(), "Test Parser");
        assert_eq!(parser.supported_artifacts(), &[ArtifactType::Mft]);
    }
}
