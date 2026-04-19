//! MISP event builder and push utilities for `RapidTriage`.
//!
//! Provides types to construct a MISP event from forensic findings and
//! (behind the `remote` feature) push it to a MISP instance via the REST API.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// MISP data types
// ---------------------------------------------------------------------------

/// A single MISP attribute.
#[derive(Debug, Clone, Serialize)]
pub struct MispAttribute {
    /// MISP attribute type, e.g. `"text"`, `"threat-actor"`, `"comment"`.
    pub r#type: String,
    /// MISP category, e.g. `"External analysis"`, `"Artifacts dropped"`.
    pub category: String,
    /// The attribute value.
    pub value: String,
    /// Free-text comment.
    pub comment: String,
    /// Whether to flag for IDS export.
    pub to_ids: bool,
}

/// A MISP event payload ready for serialization / POST.
#[derive(Debug, Clone, Serialize)]
pub struct MispEvent {
    /// Human-readable event title (shown as "info" in MISP).
    pub info: String,
    /// Distribution level: `0` = org-only.
    pub distribution: u8,
    /// Threat level: `1` = high, `2` = medium, `3` = low, `4` = undefined.
    pub threat_level_id: u8,
    /// Analysis state: `0` = initial, `1` = ongoing, `2` = completed.
    pub analysis: u8,
    /// Attributes attached to this event.
    #[serde(rename = "Attribute")]
    pub attributes: Vec<MispAttribute>,
}

/// The newly created MISP event's numeric ID, returned by the MISP API.
#[derive(Debug, Deserialize)]
pub struct MispEventId(pub u64);

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build a [`MispEvent`] from a slice of human-readable finding strings.
///
/// Each element of `findings` becomes one `"text"` attribute in the
/// `"External analysis"` category.  The resulting event defaults to
/// `distribution = 0` (org-only), `threat_level_id = 2` (medium), and
/// `analysis = 0` (initial).
#[must_use]
pub fn build_misp_event(title: &str, findings: &[String]) -> MispEvent {
    let attributes = findings
        .iter()
        .map(|f| MispAttribute {
            r#type: "text".to_string(),
            category: "External analysis".to_string(),
            value: f.clone(),
            comment: String::new(),
            to_ids: false,
        })
        .collect();

    MispEvent {
        info: title.to_string(),
        distribution: 0,
        threat_level_id: 2,
        analysis: 0,
        attributes,
    }
}

// ---------------------------------------------------------------------------
// Remote push (feature-gated)
// ---------------------------------------------------------------------------

/// POST a [`MispEvent`] to a MISP instance and return the new event ID.
///
/// Sends a JSON body to `{base_url}/events` with the header
/// `Authorization: <misp_key>`.  The response is expected to contain
/// `{"Event": {"id": "<numeric_string>"}}`.
///
/// # Errors
///
/// Returns an error if the HTTP request fails or if the response cannot be
/// parsed as a MISP event-creation response.
#[cfg(feature = "remote")]
pub fn push_to_misp(
    event: &MispEvent,
    base_url: &str,
    misp_key: &str,
) -> anyhow::Result<MispEventId> {
    #[derive(Deserialize)]
    struct EventWrapper {
        #[serde(rename = "Event")]
        inner: EventIdField,
    }
    #[derive(Deserialize)]
    struct EventIdField {
        id: serde_json::Value,
    }

    let url = format!("{base_url}/events");
    let body = serde_json::to_string(event)?;
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", misp_key)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(body)
        .send()?;

    let text = resp.text()?;
    let wrapper: EventWrapper = serde_json::from_str(&text)?;
    // MISP returns the id as a JSON string ("42"), so parse from either string or number.
    let id: u64 = match &wrapper.inner.id {
        serde_json::Value::String(s) => s.parse()?,
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("MISP event id is not a valid u64"))?,
        other => anyhow::bail!("unexpected MISP event id type: {other}"),
    };
    Ok(MispEventId(id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- build_misp_event: one attribute per finding -----------------------

    #[test]
    fn build_misp_event_creates_one_attribute_per_finding() {
        let findings = vec![
            "Suspicious process injection detected".to_string(),
            "Credential dumping via LSASS".to_string(),
            "Lateral movement via SMB".to_string(),
        ];
        let event = build_misp_event("Test case", &findings);
        assert_eq!(
            event.attributes.len(),
            3,
            "should have one attribute per finding"
        );
    }

    // ---- build_misp_event: title goes into info field ----------------------

    #[test]
    fn build_misp_event_title_in_info_field() {
        let event = build_misp_event("My Investigation", &[]);
        assert_eq!(event.info, "My Investigation");
    }

    // ---- build_misp_event: empty findings → empty attributes ---------------

    #[test]
    fn build_misp_event_empty_findings_gives_empty_attributes() {
        let event = build_misp_event("Empty case", &[]);
        assert!(
            event.attributes.is_empty(),
            "empty findings should produce no attributes"
        );
    }

    // ---- MispEvent serialises with "Attribute" key -------------------------

    #[test]
    fn misp_event_serialises_to_json() {
        let event = build_misp_event(
            "Serialisation test",
            &["Finding one".to_string()],
        );
        let json = serde_json::to_string(&event).expect("serialise MispEvent");
        assert!(
            json.contains("\"Attribute\""),
            "JSON must use the MISP 'Attribute' key (got: {json})"
        );
    }

    // ---- push_to_misp: mock HTTP server ------------------------------------

    #[cfg(feature = "remote")]
    #[test]
    fn push_to_misp_posts_to_events_endpoint() {
        use std::io::{BufRead, BufReader, Write as IoWrite};
        use std::net::TcpListener;
        use std::thread;

        // Spin up a minimal mock HTTP/1.1 server.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TcpListener");
        let port = listener.local_addr().expect("local_addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

            // Consume request headers to find Authorization.
            let mut auth_found = false;
            let mut path_ok = false;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("read header line");
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    break; // end of headers
                }
                if trimmed.starts_with("POST") && trimmed.contains("/events") {
                    path_ok = true;
                }
                if trimmed.to_ascii_lowercase().starts_with("authorization:") {
                    auth_found = true;
                }
            }

            // Drain the body (Content-Length based).
            // For simplicity just return the response immediately; reqwest
            // will get the response before it finishes writing the body for
            // short payloads.
            let body = r#"{"Event":{"id":"99"}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body,
            );
            stream.write_all(response.as_bytes()).expect("write response");

            (auth_found, path_ok)
        });

        let event = build_misp_event("Push test", &["Finding A".to_string()]);
        let base_url = format!("http://127.0.0.1:{port}");
        let result = push_to_misp(&event, &base_url, "test-api-key-abc123")
            .expect("push_to_misp should succeed");

        let (auth_found, path_ok) = server.join().expect("server thread");
        assert!(auth_found, "Authorization header must be sent");
        assert!(path_ok, "POST must target /events path");
        assert_eq!(result.0, 99, "MispEventId should be 99");
    }
}
