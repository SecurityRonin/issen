use std::collections::HashMap;

use crate::model::{
    DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
};
use crate::providers::ArtifactProvider;
use crate::scanners::{CategoryScanner, ScanError};

/// Scanner for web shell artifacts.
///
/// Detects file presence in common web root paths:
/// - `*inetpub*wwwroot*` (IIS)
/// - `*xampp*htdocs*` (XAMPP)
/// - `*nginx*html*` (nginx)
/// - `*apache*htdocs*` (Apache on Windows)
pub struct WebShellScanner;

/// Glob patterns for common web root directories where web shells are
/// typically planted.
const WEB_ROOT_PATTERNS: &[(&str, &str)] = &[
    ("*inetpub*wwwroot*", "IIS"),
    ("*xampp*htdocs*", "XAMPP"),
    ("*nginx*html*", "nginx"),
    ("*apache*htdocs*", "Apache"),
];

impl WebShellScanner {
    /// Create a new `WebShellScanner`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan for suspicious files in web root directories.
    ///
    /// Checks each known web root pattern for file presence. Files found
    /// in these locations may indicate web shell deployment.
    fn scan_web_roots(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        for &(pattern, server_name) in WEB_ROOT_PATTERNS {
            if let Ok(files) = provider.file_exists(pattern) {
                for file in &files {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::FilePresence,
                        source_path: file.path.clone(),
                        value: format!("Web root file ({server_name}): {}", file.path),
                        timestamp: file.modified.or(file.created),
                        context: HashMap::from([
                            ("file_path".into(), file.path.clone()),
                            ("web_server".into(), server_name.into()),
                            (
                                "file_size".into(),
                                file.size
                                    .map_or_else(|| "unknown".into(), |s| s.to_string()),
                            ),
                        ]),
                    });
                }
            }
        }

        hits
    }
}

impl Default for WebShellScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CategoryScanner for WebShellScanner {
    fn category(&self) -> RemoteAccessCategory {
        RemoteAccessCategory::WebShell
    }

    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        let web_hits = self.scan_web_roots(provider);
        if !web_hits.is_empty() {
            let first_seen = web_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = web_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "Web Shell".into(),
                category: RemoteAccessCategory::WebShell,
                artifacts: web_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("webshell".into()),
            });
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{FileEntry, MockArtifactProvider, ProviderCapability};

    #[test]
    fn test_iis_webshell_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::FilePresence],
            ..MockArtifactProvider::default()
        };
        mock.add_file(
            "*inetpub*wwwroot*",
            FileEntry {
                path: r"C:\inetpub\wwwroot\cmd.aspx".into(),
                size: Some(1_024),
                created: Some(1_700_000_000_000_000_000),
                modified: Some(1_700_000_100_000_000_000),
            },
        );

        let scanner = WebShellScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "Web Shell");
        assert_eq!(findings[0].category, RemoteAccessCategory::WebShell);
        assert_eq!(
            findings[0].detection_source,
            DetectionSource::CategoryScanner("webshell".into())
        );
        assert!(!findings[0].artifacts.is_empty());
        assert_eq!(
            findings[0].artifacts[0].artifact_type,
            HitArtifactType::FilePresence
        );
        assert!(findings[0].artifacts[0].value.contains("cmd.aspx"));
        assert_eq!(
            findings[0].artifacts[0].context.get("web_server"),
            Some(&"IIS".to_string())
        );
    }

    #[test]
    fn test_no_webshell_found() {
        let mock = MockArtifactProvider {
            caps: vec![ProviderCapability::FilePresence],
            ..MockArtifactProvider::default()
        };

        let scanner = WebShellScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "expected no findings on empty mock, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_xampp_webshell_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::FilePresence],
            ..MockArtifactProvider::default()
        };
        mock.add_file(
            "*xampp*htdocs*",
            FileEntry {
                path: r"C:\xampp\htdocs\shell.php".into(),
                size: Some(512),
                created: None,
                modified: Some(1_700_000_000_000_000_000),
            },
        );

        let scanner = WebShellScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "Web Shell");
        assert!(findings[0].artifacts[0].value.contains("shell.php"));
        assert_eq!(
            findings[0].artifacts[0].context.get("web_server"),
            Some(&"XAMPP".to_string())
        );
    }
}
