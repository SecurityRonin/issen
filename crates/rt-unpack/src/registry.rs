use std::path::Path;

use rt_core::error::RtError;
use tracing::info;

use crate::{CollectionManifest, CollectionProvider, Confidence};

/// Registration entry for the collection provider inventory.
pub struct ProviderRegistration {
    pub create: fn() -> Box<dyn CollectionProvider>,
}

inventory::collect!(ProviderRegistration);

/// Probe all registered providers and open the collection with the best match.
///
/// Returns an error if no provider recognizes the format.
pub fn open_collection(path: &Path) -> Result<CollectionManifest, RtError> {
    let mut best: Option<(Box<dyn CollectionProvider>, Confidence)> = None;

    for reg in inventory::iter::<ProviderRegistration> {
        let provider = (reg.create)();
        match provider.probe(path) {
            Ok(confidence) if confidence > Confidence::None => {
                info!(provider = provider.name(), ?confidence, "Provider matched");
                if best.as_ref().map_or(true, |(_, c)| confidence > *c) {
                    best = Some((provider, confidence));
                }
            }
            Ok(_) => {} // Confidence::None — skip
            Err(e) => {
                // Probe failed — log and continue to next provider.
                info!(provider = provider.name(), error = %e, "Probe failed, skipping");
            }
        }
    }

    match best {
        Some((provider, confidence)) => {
            info!(
                provider = provider.name(),
                ?confidence,
                "Opening collection"
            );
            provider.open(path)
        }
        None => {
            let provider_names: Vec<String> = inventory::iter::<ProviderRegistration>
                .into_iter()
                .map(|reg| (reg.create)().name().to_string())
                .collect();
            Err(RtError::UnsupportedFormat(format!(
                "No collection provider recognized {}. Probed: [{}]",
                path.display(),
                provider_names.join(", ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_collection_no_providers_returns_error() {
        // With no providers registered in this test binary, we expect an error.
        let result = open_collection(Path::new("/nonexistent/file.zip"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("No collection provider recognized"),
            "Error should mention no provider: {err}"
        );
    }
}
