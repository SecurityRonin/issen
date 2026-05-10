use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::artifacts::ArtifactType;

/// Event classifications for the unified forensic timeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    FileCreate,
    FileDelete,
    FileModify,
    FileRename,
    FileAccess,
    ProcessExec,
    ProcessExit,
    RegistryModify,
    RegistryCreate,
    RegistryDelete,
    LogonSuccess,
    LogonFailure,
    Logoff,
    NetworkConnect,
    NetworkListen,
    ServiceInstall,
    ServiceStart,
    ServiceStop,
    ScheduledTaskCreate,
    ScheduledTaskRun,
    UserAccountChange,
    PolicyChange,
    SystemBoot,
    SystemShutdown,
    /// Catch-all for artifact-specific events not in the core taxonomy.
    Other(String),
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(s) => write!(f, "Other({s})"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// A typed reference to the entity (file, process, user, IP) that an event
/// relates to. Used by `EntityIndex` and `temporal_join` to correlate events
/// from different artifact sources that share the same entity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityRef {
    /// A file system path (absolute or relative).
    FilePath(String),
    /// A process name or full image path.
    Process(String),
    /// A user account name or SID.
    User(String),
    /// An IP address (v4 or v6).
    Ip(String),
}

/// A single event in the unified forensic timeline.
///
/// This is the canonical data structure that flows through the entire
/// Issen pipeline: parsers emit it, the timeline store indexes it,
/// and the report engine renders it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Nanosecond-precision Unix timestamp (maps to DuckDB TIMESTAMP_NS).
    pub timestamp_ns: i64,
    /// ISO 8601 display string preserving original timezone.
    pub timestamp_display: String,
    /// Event classification.
    pub event_type: EventType,
    /// Source artifact type that produced this event.
    pub source: ArtifactType,
    /// Path within the VirtualFilesystem (or evidence source).
    pub artifact_path: String,
    /// Human-readable description of what happened.
    pub description: String,
    /// Structured key-value metadata (artifact-specific fields).
    pub metadata: HashMap<String, serde_json::Value>,
    /// User account or SID associated with the event.
    pub user: Option<String>,
    /// Machine hostname.
    pub hostname: Option<String>,
    /// Tags for filtering and annotation.
    pub tags: Vec<String>,
    /// SHA-256 of the canonical record content for deduplication and integrity.
    pub record_hash: String,
    /// Evidence source identifier for chain-of-custody tracking.
    pub evidence_source_id: String,
    /// Entity references for temporal cross-correlation.
    /// Populated by parsers that know the entity (file path, process, user, IP)
    /// an event relates to. Defaults to empty for backwards compatibility.
    #[serde(default)]
    pub entity_refs: Vec<EntityRef>,
}

impl TimelineEvent {
    /// Compute the record hash from the event's content fields.
    ///
    /// The hash covers: timestamp_ns, event_type, source, artifact_path,
    /// description, and evidence_source_id. This ensures that the same
    /// event parsed twice produces the same hash (deterministic dedup).
    #[must_use]
    pub fn compute_record_hash(
        timestamp_ns: i64,
        event_type: &EventType,
        source: &ArtifactType,
        artifact_path: &str,
        description: &str,
        evidence_source_id: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(timestamp_ns.to_le_bytes());
        hasher.update(format!("{event_type:?}").as_bytes());
        hasher.update(format!("{source:?}").as_bytes());
        hasher.update(artifact_path.as_bytes());
        hasher.update(description.as_bytes());
        hasher.update(evidence_source_id.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Create a new `TimelineEvent` with auto-computed record hash.
    #[must_use]
    pub fn new(
        timestamp_ns: i64,
        timestamp_display: String,
        event_type: EventType,
        source: ArtifactType,
        artifact_path: String,
        description: String,
        evidence_source_id: String,
    ) -> Self {
        let record_hash = Self::compute_record_hash(
            timestamp_ns,
            &event_type,
            &source,
            &artifact_path,
            &description,
            &evidence_source_id,
        );
        Self {
            timestamp_ns,
            timestamp_display,
            event_type,
            source,
            artifact_path,
            description,
            metadata: HashMap::new(),
            user: None,
            hostname: None,
            tags: Vec::new(),
            record_hash,
            evidence_source_id,
            entity_refs: Vec::new(),
        }
    }

    /// Add a metadata key-value pair. Returns self for chaining.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Set the user field. Returns self for chaining.
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Set the hostname field. Returns self for chaining.
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Add a tag. Returns self for chaining.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add an entity reference. Returns self for chaining.
    #[must_use]
    pub fn with_entity_ref(mut self, entity: EntityRef) -> Self {
        self.entity_refs.push(entity);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> TimelineEvent {
        TimelineEvent::new(
            1_700_000_000_000_000_000, // 2023-11-14T22:13:20Z in nanos
            "2023-11-14T22:13:20.000000000Z".to_string(),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            "C:/Users/analyst/Documents/report.docx".to_string(),
            "File created: report.docx".to_string(),
            "evidence-001".to_string(),
        )
    }

    #[test]
    fn test_event_construction() {
        let event = sample_event();
        assert_eq!(event.timestamp_ns, 1_700_000_000_000_000_000);
        assert_eq!(event.event_type, EventType::FileCreate);
        assert_eq!(event.source, ArtifactType::UsnJournal);
        assert_eq!(
            event.artifact_path,
            "C:/Users/analyst/Documents/report.docx"
        );
        assert!(event.metadata.is_empty());
        assert!(event.user.is_none());
        assert!(event.hostname.is_none());
        assert!(event.tags.is_empty());
        assert!(!event.record_hash.is_empty());
        assert_eq!(event.evidence_source_id, "evidence-001");
    }

    #[test]
    fn test_record_hash_deterministic() {
        let event1 = sample_event();
        let event2 = sample_event();
        assert_eq!(
            event1.record_hash, event2.record_hash,
            "Same inputs must produce same hash"
        );
    }

    #[test]
    fn test_record_hash_differs_on_different_input() {
        let event1 = sample_event();
        let event2 = TimelineEvent::new(
            1_700_000_000_000_000_001, // one nanosecond later
            "2023-11-14T22:13:20.000000001Z".to_string(),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            "C:/Users/analyst/Documents/report.docx".to_string(),
            "File created: report.docx".to_string(),
            "evidence-001".to_string(),
        );
        assert_ne!(
            event1.record_hash, event2.record_hash,
            "Different timestamps must produce different hashes"
        );
    }

    #[test]
    fn test_record_hash_is_sha256_hex() {
        let event = sample_event();
        assert_eq!(event.record_hash.len(), 64, "SHA-256 hex is 64 chars");
        assert!(
            event.record_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash must be valid hex"
        );
    }

    #[test]
    fn test_builder_pattern() {
        let event = sample_event()
            .with_user("S-1-5-21-123456-1001")
            .with_hostname("WORKSTATION01")
            .with_tag("suspicious")
            .with_tag("bookmarked")
            .with_metadata("usn_reason", serde_json::json!("FILE_CREATE"));

        assert_eq!(event.user.as_deref(), Some("S-1-5-21-123456-1001"));
        assert_eq!(event.hostname.as_deref(), Some("WORKSTATION01"));
        assert_eq!(event.tags, vec!["suspicious", "bookmarked"]);
        assert_eq!(
            event.metadata.get("usn_reason"),
            Some(&serde_json::json!("FILE_CREATE"))
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let event = sample_event()
            .with_user("analyst")
            .with_metadata("reason_flags", serde_json::json!(0x100));

        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: TimelineEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(event.timestamp_ns, deserialized.timestamp_ns);
        assert_eq!(event.event_type, deserialized.event_type);
        assert_eq!(event.source, deserialized.source);
        assert_eq!(event.artifact_path, deserialized.artifact_path);
        assert_eq!(event.record_hash, deserialized.record_hash);
        assert_eq!(event.user, deserialized.user);
        assert_eq!(event.metadata, deserialized.metadata);
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(format!("{}", EventType::FileCreate), "FileCreate");
        assert_eq!(
            format!("{}", EventType::Other("CustomEvent".to_string())),
            "Other(CustomEvent)"
        );
    }

    #[test]
    fn test_artifact_type_display() {
        assert_eq!(format!("{}", ArtifactType::UsnJournal), "USN Journal");
        assert_eq!(format!("{}", ArtifactType::Mft), "MFT");
        assert_eq!(format!("{}", ArtifactType::EventLog), "Event Log");
    }

    #[test]
    fn test_metadata_does_not_affect_hash() {
        let event1 = sample_event();
        let event2 = sample_event().with_metadata("extra", serde_json::json!("data"));
        assert_eq!(
            event1.record_hash, event2.record_hash,
            "Metadata is not part of the hash (only content-addressed fields)"
        );
    }

    #[test]
    fn test_tags_do_not_affect_hash() {
        let event1 = sample_event();
        let event2 = sample_event().with_tag("bookmarked");
        assert_eq!(
            event1.record_hash, event2.record_hash,
            "Tags are annotations, not part of the content hash"
        );
    }
}
