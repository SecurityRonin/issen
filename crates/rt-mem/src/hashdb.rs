/// Re-exports and smoke tests for forensic-hashdb integration.
pub use forensic_hashdb::known_bad::KnownBadDb;
pub use forensic_hashdb::{BadFileInfo, BadFileSource, DriverInfo};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_bad_db_empty() {
        let db = KnownBadDb::from_entries([]);
        assert!(db.is_empty());
        assert!(db.lookup(&[0u8; 32]).is_none());
    }

    #[test]
    fn known_bad_db_lookup_hit() {
        let sha = [0x42u8; 32];
        let info = BadFileInfo {
            sha256: sha,
            source: BadFileSource::MalwareBazaar,
            malware_family: Some("TestFamily".into()),
            tags: vec!["ransomware".into()],
        };
        let db = KnownBadDb::from_entries([(sha, info)]);
        assert!(db.lookup(&sha).is_some());
        assert!(db.might_be_malicious(&sha));
    }

    #[test]
    fn bad_file_source_variants() {
        assert_ne!(BadFileSource::MalwareBazaar, BadFileSource::VirusShare);
        assert_eq!(
            BadFileSource::Custom("feed"),
            BadFileSource::Custom("feed")
        );
    }
}
