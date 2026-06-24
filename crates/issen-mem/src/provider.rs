//! Collection-registry provider for memory dumps.
//!
//! Without this, `.mem`/`.vmem`/LiME/AVML/crashdump files fall through to the
//! raw disk (`DD`) fallback and die with a cryptic disk-image error. This
//! provider claims memory dumps first (beating `DdProvider`'s `Low`) and
//! redirects the user to the `memory` subcommand.
//!
//! It is DETECT + REDIRECT only: the `ingest` pipeline expects a
//! [`CollectionManifest`] of extracted files, which memory walking does not
//! produce. `open` therefore fails loud with an actionable message rather than
//! fabricating an empty timeline.

use std::path::Path;

use issen_core::error::RtError;
use issen_unpack::{CollectionManifest, CollectionProvider, Confidence};

use crate::open::{detect_format, DumpFormat};

/// File extensions that denote a raw, headerless memory image (no magic).
const MEMORY_EXTENSIONS: &[&str] = &["mem", "vmem", "lime", "raw", "dmp"];

/// Format-recognition provider for memory dumps.
#[derive(Debug, Default)]
pub struct MemoryProvider;

impl CollectionProvider for MemoryProvider {
    fn name(&self) -> &str {
        "Memory"
    }

    fn probe(&self, _path: &Path) -> Result<Confidence, RtError> {
        // RED stub.
        Ok(Confidence::None)
    }

    fn open(&self, _path: &Path) -> Result<CollectionManifest, RtError> {
        // RED stub.
        Err(RtError::UnsupportedFormat("stub".to_string()))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(MemoryProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_file(ext: &str, bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(&format!(".{ext}"))
            .tempfile()
            .expect("tempfile");
        f.write_all(bytes).expect("write");
        f
    }

    #[test]
    fn probe_lime_magic_returns_high() {
        // LiME "EMiL" magic — recognized by detect_format regardless of ext.
        let f = make_file("bin", &[0x45, 0x4D, 0x69, 0x4C, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            MemoryProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn probe_crashdump_magic_returns_high() {
        let f = make_file("bin", &[0x50, 0x41, 0x47, 0x45, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            MemoryProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn probe_mem_extension_raw_bytes_returns_medium() {
        // Headerless raw memory, but the .mem extension is the tiebreak.
        let f = make_file("mem", &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            MemoryProvider.probe(f.path()).expect("probe"),
            Confidence::Medium
        );
    }

    #[test]
    fn probe_unrelated_extension_raw_bytes_returns_none() {
        let f = make_file("txt", &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            MemoryProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn probe_nonexistent_returns_err() {
        assert!(MemoryProvider
            .probe(Path::new("/tmp/nonexistent_mem_99999.mem"))
            .is_err());
    }

    #[test]
    fn open_redirects_to_memory_subcommand_naming_format() {
        let f = make_file("bin", &[0x45, 0x4D, 0x69, 0x4C, 0x00, 0x00, 0x00, 0x01]);
        let err = MemoryProvider
            .open(f.path())
            .expect_err("must redirect, not extract");
        let msg = err.to_string();
        assert!(
            matches!(err, RtError::UnsupportedFormat(_)),
            "expected UnsupportedFormat; got: {err:?}"
        );
        assert!(
            msg.contains("LiME"),
            "message must name the detected format; got: {msg}"
        );
        assert!(
            msg.contains("issen memory"),
            "message must redirect to 'issen memory'; got: {msg}"
        );
    }

    #[test]
    fn registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"Memory".to_string()),
            "MemoryProvider must be in inventory; got: {names:?}"
        );
    }
}
