/// Returns true if the string looks like a remote URI (has a recognised scheme).
pub fn is_remote_uri(s: &str) -> bool {
    UriScheme::detect(s).is_some()
}

/// All URI schemes that rt-remote-io recognises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriScheme {
    S3,
    Gcs,
    AzBlob,
    GDrive,
    Sftp,
    WebDav,
    Hdfs,
    Http,
    Https,
    Mem,
    File,
}

impl UriScheme {
    /// Detect the scheme from a URI string. Returns None for unrecognised schemes.
    pub fn detect(uri: &str) -> Option<Self> {
        let scheme = uri.split("://").next()?;
        if scheme == uri {
            // No "://" found.
            return None;
        }
        match scheme {
            "s3" => Some(Self::S3),
            "gcs" => Some(Self::Gcs),
            "azblob" => Some(Self::AzBlob),
            "gdrive" => Some(Self::GDrive),
            "sftp" => Some(Self::Sftp),
            "webdav" => Some(Self::WebDav),
            "hdfs" => Some(Self::Hdfs),
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "mem" => Some(Self::Mem),
            "file" => Some(Self::File),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_remote_uri_recognised_schemes() {
        for uri in &[
            "s3://bucket/key",
            "gcs://bucket/obj",
            "azblob://container/blob",
            "http://example.com/file",
            "https://example.com/file",
            "mem://bucket/key",
            "file:///tmp/foo",
            "gdrive://file-id",
        ] {
            assert!(is_remote_uri(uri), "expected true for {uri}");
        }
    }

    #[test]
    fn is_remote_uri_bare_path_is_false() {
        assert!(!is_remote_uri("/tmp/local/file"));
        assert!(!is_remote_uri("relative/path"));
        assert!(!is_remote_uri(""));
        assert!(!is_remote_uri("unknown://host/path"));
    }

    #[test]
    fn uri_scheme_detect_each_scheme() {
        assert_eq!(UriScheme::detect("s3://bucket/key"), Some(UriScheme::S3));
        assert_eq!(UriScheme::detect("gcs://bucket/obj"), Some(UriScheme::Gcs));
        assert_eq!(
            UriScheme::detect("azblob://container/blob"),
            Some(UriScheme::AzBlob)
        );
        assert_eq!(
            UriScheme::detect("gdrive://file-id"),
            Some(UriScheme::GDrive)
        );
        assert_eq!(UriScheme::detect("sftp://host/path"), Some(UriScheme::Sftp));
        assert_eq!(
            UriScheme::detect("webdav://host/path"),
            Some(UriScheme::WebDav)
        );
        assert_eq!(UriScheme::detect("hdfs://host/path"), Some(UriScheme::Hdfs));
        assert_eq!(
            UriScheme::detect("http://example.com/file"),
            Some(UriScheme::Http)
        );
        assert_eq!(
            UriScheme::detect("https://example.com/file"),
            Some(UriScheme::Https)
        );
        assert_eq!(
            UriScheme::detect("mem://bucket/key"),
            Some(UriScheme::Mem)
        );
        assert_eq!(UriScheme::detect("file:///tmp/foo"), Some(UriScheme::File));
    }

    #[test]
    fn uri_scheme_detect_unknown_is_none() {
        assert_eq!(UriScheme::detect("unknown://host/path"), None);
        assert_eq!(UriScheme::detect("/tmp/local"), None);
        assert_eq!(UriScheme::detect(""), None);
    }
}
