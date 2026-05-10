/// Browser forensic integration layer for Issen.
///
/// Wraps browser-core, browser-chrome, and browser-firefox.
pub use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily, detect_browser};
pub use browser_chrome::parse_history as parse_chrome_history;
pub use browser_firefox::parse_history as parse_firefox_history;
pub use browser_safari::parse_history as parse_safari_history;

use anyhow::Result;
use std::path::Path;

/// Detect the browser family from `path` and dispatch to the appropriate
/// history parser. Returns an error if the browser cannot be detected or
/// the file cannot be parsed.
///
/// # Errors
///
/// Returns an error if the path cannot be identified as a known browser
/// artifact or if the underlying SQLite query fails.
pub fn parse_browser_history(path: &Path) -> Result<Vec<BrowserEvent>> {
    match detect_browser(path) {
        Some(BrowserFamily::Chromium) => parse_chrome_history(path),
        Some(BrowserFamily::Firefox) => parse_firefox_history(path),
        Some(BrowserFamily::Safari) => parse_safari_history(path),
        None => anyhow::bail!(
            "cannot detect browser family from path: {}",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_family_chromium_and_firefox_are_distinct() {
        assert_ne!(BrowserFamily::Chromium, BrowserFamily::Firefox);
    }

    #[test]
    fn detect_browser_chrome_history_path() {
        let p = Path::new("/home/user/.config/google-chrome/Default/History");
        assert_eq!(detect_browser(p), Some(BrowserFamily::Chromium));
    }

    #[test]
    fn detect_browser_firefox_places_path() {
        let p = Path::new("/home/user/.mozilla/firefox/abc.default/places.sqlite");
        assert_eq!(detect_browser(p), Some(BrowserFamily::Firefox));
    }

    #[test]
    fn parse_browser_history_unknown_path_returns_error() {
        let result = parse_browser_history(Path::new("/tmp/unknown_artifact.db"));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("cannot detect browser family"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn parse_chrome_history_empty_db() {
        use rusqlite::Connection;
        use tempfile::NamedTempFile;

        let f = NamedTempFile::new().expect("tempfile");
        let conn = Connection::open(f.path()).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT DEFAULT '',
                visit_count INTEGER DEFAULT 0 NOT NULL,
                last_visit_time INTEGER NOT NULL
            );",
        )
        .expect("create table");
        drop(conn);

        let events = parse_chrome_history(f.path()).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_firefox_history_empty_db() {
        use rusqlite::Connection;
        use tempfile::NamedTempFile;

        let f = NamedTempFile::new().expect("tempfile");
        let conn = Connection::open(f.path()).expect("open");
        conn.execute_batch(
            "CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT,
                visit_count INTEGER DEFAULT 0,
                last_visit_date INTEGER
            );",
        )
        .expect("create table");
        drop(conn);

        let events = parse_firefox_history(f.path()).expect("parse");
        assert!(events.is_empty());
    }
}
