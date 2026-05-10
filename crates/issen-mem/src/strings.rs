/// Re-exports and smoke tests for memf-strings integration.
pub use memf_strings::{ClassifiedString, StringCategory, StringEncoding};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_category_url_roundtrip() {
        assert_eq!(StringCategory::Url, StringCategory::Url);
        assert_ne!(StringCategory::Url, StringCategory::Email);
    }

    #[test]
    fn classified_string_constructs() {
        let cs = ClassifiedString {
            value: "https://example.com".into(),
            physical_offset: 0x1000,
            encoding: StringEncoding::Ascii,
            categories: vec![(StringCategory::Url, 0.99)],
        };
        assert_eq!(cs.categories.len(), 1);
    }

    #[test]
    fn string_encoding_variants_are_distinct() {
        assert_ne!(StringEncoding::Ascii, StringEncoding::Utf16Le);
        assert_ne!(StringEncoding::Utf8, StringEncoding::Utf16Le);
    }
}
