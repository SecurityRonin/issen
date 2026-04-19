//! Google Drive file download for RapidTriage.
//!
//! Downloads a file by ID, streaming bytes to a [`std::io::Write`] sink.

use crate::gdrive::auth::GDriveAuthMode;

/// Download a Google Drive file, streaming bytes to `sink`.
///
/// Auth modes:
/// - [`GDriveAuthMode::Public`] — uses the usercontent download endpoint
/// - [`GDriveAuthMode::UserOAuth`] — uses the Drive v3 API with a Bearer token
/// - [`GDriveAuthMode::ServiceAccount`] — not yet implemented; returns `Err`
///
/// Pass `base_url_override` to redirect requests to a mock server in tests.
///
/// Returns the total number of bytes written to `sink`.
#[cfg(feature = "remote")]
pub fn download_gdrive_file(
    file_id: &str,
    auth: &GDriveAuthMode,
    sink: &mut dyn std::io::Write,
    base_url_override: Option<&str>,
) -> anyhow::Result<u64> {
    let client = reqwest::blocking::Client::new();

    let request = match auth {
        GDriveAuthMode::Public => {
            let base = base_url_override.unwrap_or("https://drive.usercontent.google.com");
            let url = format!(
                "{base}/download?id={file_id}&export=download&confirm=t"
            );
            client.get(&url)
        }
        GDriveAuthMode::UserOAuth { access_token } => {
            let base = base_url_override.unwrap_or("https://www.googleapis.com");
            let url = format!("{base}/drive/v3/files/{file_id}?alt=media");
            client.get(&url).header("Authorization", format!("Bearer {access_token}"))
        }
        GDriveAuthMode::ServiceAccount { .. } => {
            anyhow::bail!("service account not yet implemented");
        }
    };

    let mut response = request.send().map_err(|e| anyhow::anyhow!("request failed: {e}"))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "server returned {}: {}",
            response.status(),
            response.text().unwrap_or_default()
        );
    }

    let bytes = response.copy_to(sink)?;
    Ok(bytes)
}

#[cfg(all(test, feature = "remote"))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    /// Spin up a one-shot mock HTTP server that returns `response_body`.
    /// The server reads the full HTTP request, then sends a 200 response.
    /// Returns `(addr, join_handle)`.  The handle finishes after one request.
    fn make_mock_server(
        response_body: &'static [u8],
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("local_addr");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");

            // Drain the request so the client doesn't get ECONNRESET mid-send.
            {
                let mut reader = BufReader::new(&stream);
                // Read until blank line (end of HTTP headers).
                let mut line = String::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line).expect("read line");
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
            }

            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Connection: close\r\n\r\n",
                response_body.len()
            );
            stream.write_all(header.as_bytes()).expect("write header");
            stream.write_all(response_body).expect("write body");
        });

        (addr, handle)
    }

    /// Same as `make_mock_server` but also captures the raw request lines for inspection.
    fn make_mock_server_capture(
        response_body: &'static [u8],
    ) -> (
        std::net::SocketAddr,
        std::thread::JoinHandle<Vec<String>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("local_addr");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");

            let mut request_lines = Vec::new();
            {
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line).expect("read line");
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request_lines.push(line.trim_end().to_string());
                }
            }

            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Connection: close\r\n\r\n",
                response_body.len()
            );
            stream.write_all(header.as_bytes()).expect("write header");
            stream.write_all(response_body).expect("write body");

            request_lines
        });

        (addr, handle)
    }

    #[test]
    fn public_download_writes_bytes() {
        const BODY: &[u8] = b"hello from google drive";
        let (addr, server) = make_mock_server(BODY);
        let base_url = format!("http://{addr}");

        let auth = GDriveAuthMode::Public;
        let mut sink: Vec<u8> = Vec::new();
        download_gdrive_file("test-file-id", &auth, &mut sink, Some(&base_url))
            .expect("download_gdrive_file should succeed");

        server.join().expect("mock server panicked");
        assert_eq!(sink, BODY, "sink should contain exactly the response body");
    }

    #[test]
    fn oauth_download_sends_bearer_token() {
        const BODY: &[u8] = b"secure content";
        let (addr, server) = make_mock_server_capture(BODY);
        let base_url = format!("http://{addr}");

        let auth = GDriveAuthMode::UserOAuth {
            access_token: "my-secret-token-xyz".to_string(),
        };
        let mut sink: Vec<u8> = Vec::new();
        download_gdrive_file("file-abc", &auth, &mut sink, Some(&base_url))
            .expect("oauth download should succeed");

        let request_lines = server.join().expect("mock server panicked");
        let has_bearer = request_lines
            .iter()
            .any(|l| l.to_lowercase().starts_with("authorization:") && l.contains("Bearer") && l.contains("my-secret-token-xyz"));
        assert!(
            has_bearer,
            "request should contain Authorization: Bearer header; got: {request_lines:?}"
        );
        assert_eq!(sink, BODY, "sink should contain exactly the response body");
    }

    #[test]
    fn service_account_returns_error() {
        let auth = GDriveAuthMode::ServiceAccount {
            path: std::path::PathBuf::from("/nonexistent/sa.json"),
        };
        let mut sink: Vec<u8> = Vec::new();
        let result = download_gdrive_file("any-id", &auth, &mut sink, None);
        assert!(result.is_err(), "ServiceAccount should return Err");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("service account") || msg.contains("not yet implemented") || msg.contains("not implemented"),
            "error message should mention service account or not implemented; got: {msg}"
        );
    }

    #[test]
    fn returns_byte_count() {
        const BODY: &[u8] = b"exactly twenty bytes!!";
        let (addr, server) = make_mock_server(BODY);
        let base_url = format!("http://{addr}");

        let auth = GDriveAuthMode::Public;
        let mut sink: Vec<u8> = Vec::new();
        let count = download_gdrive_file("count-test-id", &auth, &mut sink, Some(&base_url))
            .expect("download should succeed");

        server.join().expect("mock server panicked");
        assert_eq!(
            count,
            BODY.len() as u64,
            "returned byte count should match body length"
        );
    }
}
