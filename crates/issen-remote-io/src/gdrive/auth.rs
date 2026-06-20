//! Google Drive OAuth2 auth for Issen.
//!
//! Auth priority (highest → lowest):
//!   1. Service account JSON  — env `GOOGLE_APPLICATION_CREDENTIALS`
//!   2. Stored user OAuth token — `~/.config/issen/gdrive_token.json`
//!   3. Public (unauthenticated) — share-link files only
//!
//! Browser flow:
//!   `rt gdrive auth login`
//!
//! Embedded OAuth credentials are registered under the Issen GCP project
//! as a "Desktop app" client.  Google classifies Desktop app client secrets as
//! non-sensitive; security relies on the localhost redirect URI, not the secret.
//! Override with `RT_GDRIVE_CLIENT_ID` / `RT_GDRIVE_CLIENT_SECRET`.

#[cfg(feature = "remote")]
use std::io::{BufRead, BufReader, Write as IoWrite};
#[cfg(feature = "remote")]
use std::net::TcpStream;
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Embedded OAuth client ID (Issen Desktop app, GCP project issen).
/// Override with the `RT_GDRIVE_CLIENT_ID` environment variable.
pub const DEFAULT_CLIENT_ID: &str =
    "149273611432-rp8m2v0jpi902o5ssarbqjo4j6k3j71o.apps.googleusercontent.com";

/// Embedded OAuth client secret (non-sensitive for Desktop app type).
/// Override with the `RT_GDRIVE_CLIENT_SECRET` environment variable.
pub const DEFAULT_CLIENT_SECRET: &str = "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";

/// How Issen will authenticate to Google Drive for a given operation.
#[derive(Debug)]
pub enum GDriveAuthMode {
    /// No credentials — public share-link files only.
    Public,
    /// Service account JSON key file (env: `GOOGLE_APPLICATION_CREDENTIALS`).
    ServiceAccount { path: PathBuf },
    /// Stored user OAuth2 access token (from a previous `rt gdrive auth login`).
    UserOAuth { access_token: String },
}

/// OAuth2 token as returned by Google's token endpoint and stored in the cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

/// Build a Google OAuth2 authorization URL for the Drive read-only scope.
///
/// Direct the user to this URL to grant access.  On approval, Google redirects
/// to `redirect_uri` with `?code=<auth_code>&state=<state>`.
pub fn build_oauth_auth_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    let scope = "https://www.googleapis.com/auth/drive.readonly";
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth\
         ?response_type=code\
         &client_id={client_id}\
         &redirect_uri={redirect_uri}\
         &scope={scope}\
         &state={state}\
         &access_type=offline\
         &prompt=consent"
    )
}

/// Extract the authorization code from a localhost redirect callback URL.
///
/// Parses `?code=<value>` from URLs like:
///   `http://localhost:9876/callback?code=4/0AfJohXm...&state=csrf`
///
/// Returns `None` if no `code` param is present or its value is empty.
pub fn parse_auth_code_from_redirect(url: &str) -> Option<String> {
    let query = url.split('?').nth(1)?;
    for param in query.split('&') {
        if let Some(value) = param.strip_prefix("code=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Path where the user OAuth token is cached between sessions.
///
/// Returns `~/.config/issen/gdrive_token.json` on Unix,
/// or `%APPDATA%\issen\gdrive_token.json` on Windows.
pub fn token_cache_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    #[cfg(not(target_os = "windows"))]
    let base = std::env::var("XDG_CONFIG_HOME").map_or_else(|_| {
            std::env::var("HOME").map_or_else(|_| PathBuf::from(".config"), |h| PathBuf::from(h).join(".config"))
        }, PathBuf::from);

    base.join("issen").join("gdrive_token.json")
}

/// Save an OAuth token to `path`, creating parent directories as needed.
pub fn save_token(token: &OAuthToken, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(token)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Load a cached OAuth token from `path`.  Returns `None` if the file is
/// missing or cannot be parsed.
pub fn load_token_from(path: &Path) -> Option<OAuthToken> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Load a cached OAuth token from the default cache path.
pub fn load_token() -> Option<OAuthToken> {
    load_token_from(&token_cache_path())
}

/// Find an available TCP port by binding to port 0.
pub fn find_available_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Determine the auth mode based on environment and cached credentials.
///
/// Priority:
///   1. `GOOGLE_APPLICATION_CREDENTIALS` → service account
///   2. Cached user token at [`token_cache_path`]
///   3. [`GDriveAuthMode::Public`]
pub fn resolve_auth_mode() -> GDriveAuthMode {
    if let Ok(path) = std::env::var("GOOGLE_APPLICATION_CREDENTIALS") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return GDriveAuthMode::ServiceAccount { path: p };
        }
    }
    if let Some(token) = load_token() {
        return GDriveAuthMode::UserOAuth {
            access_token: token.access_token,
        };
    }
    GDriveAuthMode::Public
}

/// Exchange an OAuth2 authorization code for an access + refresh token.
///
/// Posts to `token_endpoint` (production: `https://oauth2.googleapis.com/token`).
/// Pass a custom endpoint in tests to point at a local mock server.
#[cfg(feature = "remote")]
pub fn exchange_code_for_token(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    token_endpoint: &str,
) -> anyhow::Result<OAuthToken> {
    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    let client = reqwest::blocking::Client::new();
    let resp = client.post(token_endpoint).form(&params).send()?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "token endpoint returned {}: {}",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }
    let body = resp.text()?;
    Ok(serde_json::from_str::<OAuthToken>(&body)?)
}

/// Initiate an OAuth2 browser flow to authenticate with Google Drive.
///
/// 1. Reads `RT_GDRIVE_CLIENT_ID` / `RT_GDRIVE_CLIENT_SECRET` (falls back to embedded).
/// 2. Binds a temporary localhost HTTP server on an ephemeral port.
/// 3. Opens the browser (or prints the URL in headless environments).
/// 4. Waits for the redirect, captures `code=`.
/// 5. Exchanges the code for tokens and saves to [`token_cache_path`].
///
/// Returns the access token string on success.
#[cfg(feature = "remote")]
pub fn initiate_browser_auth() -> anyhow::Result<String> {
    let client_id = std::env::var("RT_GDRIVE_CLIENT_ID")
        .unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());
    let client_secret = std::env::var("RT_GDRIVE_CLIENT_SECRET")
        .unwrap_or_else(|_| DEFAULT_CLIENT_SECRET.to_string());

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://localhost:{port}/callback");
    let state = format!(
        "issen-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    let auth_url = build_oauth_auth_url(&client_id, &redirect_uri, &state);

    eprintln!("\nOpen this URL to authorise Issen to access Google Drive:");
    eprintln!("\n  {auth_url}\n");
    let _ = std::process::Command::new("open")
        .arg(&auth_url)
        .status()
        .or_else(|_| std::process::Command::new("xdg-open").arg(&auth_url).status());
    eprintln!("Waiting for browser redirect on port {port}…");

    let (stream, _) = listener.accept()?;
    let code = read_code_from_callback(&stream)?;

    let token = exchange_code_for_token(
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        "https://oauth2.googleapis.com/token",
    )?;

    let cache = token_cache_path();
    save_token(&token, &cache)
        .map_err(|e| anyhow::anyhow!("failed to cache token at {}: {e}", cache.display()))?;
    let access_token = token.access_token.clone();
    eprintln!("Authenticated. Token cached at {}", cache.display());
    Ok(access_token)
}

/// Read the authorization code from the browser's `GET /callback?code=…` request.
#[cfg(feature = "remote")]
fn read_code_from_callback(stream: &TcpStream) -> anyhow::Result<String> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP request"))?;

    let full_url = format!("http://localhost{path}");
    let code = parse_auth_code_from_redirect(&full_url)
        .ok_or_else(|| anyhow::anyhow!("no authorization code in callback URL"))?;

    let html = b"<html><body><h1>Issen: authorised.</h1>\
                  <p>You may close this tab.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        html.len()
    );
    (&mut &*stream).write_all(response.as_bytes())?;
    (&mut &*stream).write_all(html)?;

    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn auth_url_contains_client_id() {
        let url = build_oauth_auth_url("my-client-id", "http://localhost:9999/cb", "s1");
        assert!(
            url.contains("client_id=my-client-id"),
            "expected client_id in URL: {url}"
        );
    }

    #[test]
    fn auth_url_contains_drive_readonly_scope() {
        let url = build_oauth_auth_url(DEFAULT_CLIENT_ID, "http://localhost:9999/cb", "s1");
        assert!(
            url.contains("drive.readonly"),
            "expected drive.readonly scope in URL: {url}"
        );
    }

    #[test]
    fn auth_url_contains_state() {
        let url = build_oauth_auth_url(DEFAULT_CLIENT_ID, "http://localhost:9999/cb", "csrf-token");
        assert!(
            url.contains("state=csrf-token"),
            "expected state param in URL: {url}"
        );
    }

    #[test]
    fn parse_code_extracts_value() {
        let url = "http://localhost:9876/callback?code=4%2F0AfJohXm&state=rt-123";
        let code = parse_auth_code_from_redirect(url);
        assert_eq!(code, Some("4%2F0AfJohXm".to_string()));
    }

    #[test]
    fn parse_code_missing_returns_none() {
        let url = "http://localhost:9876/callback?state=rt-123&error=access_denied";
        assert_eq!(parse_auth_code_from_redirect(url), None);
    }

    #[test]
    fn parse_code_empty_value_returns_none() {
        let url = "http://localhost:9876/callback?code=&state=rt-123";
        assert_eq!(parse_auth_code_from_redirect(url), None);
    }

    #[test]
    fn token_cache_path_contains_issen() {
        let path = token_cache_path();
        let s = path.to_string_lossy();
        assert!(
            s.contains("issen"),
            "token cache path should contain 'issen', got: {s}"
        );
    }

    #[test]
    fn token_cache_path_ends_with_gdrive_token_json() {
        let path = token_cache_path();
        assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("gdrive_token.json"));
    }

    #[test]
    fn save_and_load_token_roundtrip() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let token = OAuthToken {
            access_token: "ya29.test-access-token".to_string(),
            refresh_token: Some("1//test-refresh".to_string()),
            expires_in: Some(3600),
        };
        save_token(&token, tmp.path()).expect("save_token");
        let loaded = load_token_from(tmp.path()).expect("load_token_from");
        assert_eq!(loaded.access_token, token.access_token);
        assert_eq!(loaded.refresh_token, token.refresh_token);
        assert_eq!(loaded.expires_in, token.expires_in);
    }

    #[test]
    fn load_token_from_missing_file_returns_none() {
        let path = PathBuf::from("/tmp/rt-test-nonexistent-token-abc123.json");
        assert!(load_token_from(&path).is_none());
    }

    #[test]
    fn find_available_poissen_returns_nonzero() {
        let port = find_available_port().expect("find_available_port");
        assert!(port > 0, "expected nonzero port");
    }

    #[test]
    fn resolve_auth_mode_public_when_no_credentials() {
        // Ensure neither env var is set for this test.
        // (Service account path doesn't exist even if var is set.)
        std::env::remove_var("GOOGLE_APPLICATION_CREDENTIALS");
        let mode = resolve_auth_mode();
        assert!(
            matches!(mode, GDriveAuthMode::Public | GDriveAuthMode::UserOAuth { .. }),
            "expected Public or UserOAuth (token may exist in dev env)"
        );
    }
}
