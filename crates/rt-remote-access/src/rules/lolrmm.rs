//! LOLRMM YAML loader.
//!
//! Deserialises [LOLRMM](https://lolrmm.io/) YAML detection definitions
//! into strongly-typed Rust structs.  Supports loading a single file or an
//! entire directory of `.yaml`/`.yml` files.

use std::path::Path;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-level definition
// ---------------------------------------------------------------------------

/// A single LOLRMM tool definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LolrmmDefinition {
    /// Tool name (e.g. "`AnyDesk`").
    pub name: String,

    /// Category string (e.g. "RMM").
    #[serde(default)]
    pub category: String,

    /// Human-readable description of the tool.
    #[serde(default)]
    pub description: String,

    /// Extended detail block.
    pub details: Option<LolrmmDetails>,

    /// Artifact indicators grouped by type.
    pub artifacts: Option<LolrmmArtifacts>,

    /// Sigma / detection rule references.
    pub detections: Option<Vec<LolrmmDetection>>,

    /// External reference URLs.
    pub references: Option<Vec<String>>,

    // -- fields we parse but don't actively use yet -------------------------
    /// Author(s) of the definition.
    #[serde(default)]
    pub author: Option<String>,

    /// Date the definition was created.
    #[serde(default)]
    pub created: Option<String>,

    /// Date the definition was last modified.
    #[serde(default)]
    pub last_modified: Option<String>,

    /// Acknowledgements.
    #[serde(default)]
    pub acknowledgement: Option<Vec<Acknowledgement>>,
}

/// Acknowledgement entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Acknowledgement {
    #[serde(default)]
    pub person: Option<String>,
    #[serde(default)]
    pub handle: Option<String>,
}

// ---------------------------------------------------------------------------
// Details
// ---------------------------------------------------------------------------

/// Extended details about an RMM tool.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LolrmmDetails {
    /// Vendor website URL.
    #[serde(default)]
    pub website: Option<String>,

    /// PE metadata entries (can be a single object or list in the YAML).
    #[serde(
        default,
        rename = "PEMetadata",
        deserialize_with = "deserialize_pe_metadata"
    )]
    pub pe_metadata: Vec<PeMetadata>,

    /// Required privilege level (e.g. "User", "user").
    #[serde(default)]
    pub privileges: Option<String>,

    /// Whether a free tier is available.
    /// LOLRMM encodes this as `true`, `false`, or an empty string.
    #[serde(default, deserialize_with = "deserialize_optional_bool")]
    pub free: Option<bool>,

    /// Whether identity verification is required.
    #[serde(default, deserialize_with = "deserialize_optional_bool")]
    pub verification: Option<bool>,

    /// Operating systems the tool runs on.
    #[serde(default, rename = "SupportedOS")]
    pub supported_os: Vec<String>,

    /// Capability tags (e.g. "File Transfer", "Remote Control").
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Links to CVE / vulnerability databases.
    #[serde(default)]
    pub vulnerabilities: Vec<String>,

    /// Common installation paths / binary names.
    #[serde(default)]
    pub installation_paths: Vec<String>,
}

/// PE metadata for a tool binary.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PeMetadata {
    /// Binary filename on disk.
    #[serde(default)]
    pub filename: Option<String>,

    /// `OriginalFileName` PE version-info field.
    #[serde(default)]
    pub original_file_name: Option<String>,

    /// `FileDescription` PE version-info field.
    #[serde(default)]
    pub description: Option<String>,

    /// `ProductName` PE version-info field.
    #[serde(default)]
    pub product: Option<String>,
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

/// Artifact indicators grouped by category.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LolrmmArtifacts {
    /// Disk / filesystem artifacts.
    #[serde(default)]
    pub disk: Option<Vec<DiskArtifact>>,

    /// Windows Event Log artifacts.
    #[serde(default)]
    pub event_log: Option<Vec<EventLogArtifact>>,

    /// Registry key / value artifacts.
    #[serde(default)]
    pub registry: Option<Vec<RegistryArtifact>>,

    /// Network indicators (domains, ports).
    #[serde(default)]
    pub network: Option<Vec<NetworkArtifact>>,

    /// Miscellaneous indicators (mutexes, named pipes, user-agents, etc.).
    #[serde(default)]
    pub other: Option<Vec<OtherArtifact>>,
}

/// A filesystem artifact indicator.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DiskArtifact {
    /// File path or glob pattern.
    #[serde(default)]
    pub file: Option<String>,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Target operating system.
    #[serde(default, rename = "OS")]
    pub os: Option<String>,

    /// Match type (e.g. "Regex").
    #[serde(default, rename = "Type")]
    pub artifact_type: Option<String>,

    /// Example data snippets.
    #[serde(default, rename = "Example")]
    pub example: Option<Vec<String>>,
}

/// A Windows Event Log artifact indicator.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventLogArtifact {
    /// Windows Event ID.
    #[serde(default, rename = "EventID")]
    pub event_id: Option<u32>,

    /// Event provider / source name.
    #[serde(default)]
    pub provider_name: Option<String>,

    /// Log file path (e.g. "System.evtx").
    #[serde(default)]
    pub log_file: Option<String>,

    /// Associated service name (extra context).
    #[serde(default)]
    pub service_name: Option<String>,

    /// Image path of the service binary (extra context).
    #[serde(default)]
    pub image_path: Option<String>,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

/// A registry artifact indicator.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegistryArtifact {
    /// Registry key path.
    #[serde(default)]
    pub path: Option<String>,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

/// A network artifact indicator.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkArtifact {
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Domain names or patterns (e.g. "*.anydesk.com").
    #[serde(default)]
    pub domains: Option<Vec<String>>,

    /// Network ports.  Stored as strings because LOLRMM sometimes uses
    /// "N/A" instead of a numeric value.
    #[serde(default, deserialize_with = "deserialize_ports")]
    pub ports: Option<Vec<String>>,
}

/// Miscellaneous artifact (mutex, named pipe, user-agent, etc.).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OtherArtifact {
    /// Artifact type label (e.g. "Mutex", "`NamedPipe`", "User-Agent").
    #[serde(default, rename = "Type")]
    pub artifact_type: Option<String>,

    /// Artifact value.
    #[serde(default)]
    pub value: Option<String>,
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------

/// A detection rule reference.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LolrmmDetection {
    /// URL to a Sigma rule.
    #[serde(default)]
    pub sigma: Option<String>,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Custom deserialisers
// ---------------------------------------------------------------------------

/// Deserialise `PEMetadata` that may be a single object **or** an array.
fn deserialize_pe_metadata<'de, D>(deserializer: D) -> Result<Vec<PeMetadata>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(PeMetadata),
        Many(Vec<PeMetadata>),
    }

    match Option::<OneOrMany>::deserialize(deserializer)? {
        Some(OneOrMany::One(single)) => Ok(vec![single]),
        Some(OneOrMany::Many(list)) => Ok(list),
        None => Ok(Vec::new()),
    }
}

/// Deserialise a bool that may arrive as `true`, `false`, `""`, or absent.
fn deserialize_optional_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrString {
        Bool(bool),
        Str(String),
    }

    match Option::<BoolOrString>::deserialize(deserializer)? {
        Some(BoolOrString::Bool(b)) => Ok(Some(b)),
        Some(BoolOrString::Str(s)) if s.is_empty() => Ok(None),
        Some(BoolOrString::Str(s)) => match s.to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Ok(Some(true)),
            "false" | "no" | "0" => Ok(Some(false)),
            _ => Ok(None),
        },
        None => Ok(None),
    }
}

/// Deserialise ports that may be integers or strings (e.g. "N/A", "443").
fn deserialize_ports<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PortValue {
        Num(u16),
        Str(String),
    }

    let raw: Option<Vec<PortValue>> = Option::deserialize(deserializer)?;
    Ok(raw.map(|v| {
        v.into_iter()
            .map(|p| match p {
                PortValue::Num(n) => n.to_string(),
                PortValue::Str(s) => s,
            })
            .collect()
    }))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load and parse a single LOLRMM YAML file.
///
/// # Errors
///
/// Returns an error message if the file cannot be read or parsed.
pub fn load_lolrmm_file(path: &Path) -> Result<LolrmmDefinition, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_yaml::from_str::<LolrmmDefinition>(&content)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

/// Load all `.yaml` / `.yml` files from a directory.
///
/// Files that fail to parse are logged via [`tracing::warn!`] and skipped.
///
/// # Errors
///
/// Returns an error message if the directory cannot be read.
pub fn load_lolrmm_directory(dir: &Path) -> Result<Vec<LolrmmDefinition>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory {}: {e}", dir.display()))?;

    let mut definitions = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| format!("directory iteration error: {e}"))?;
        let path = entry.path();

        let is_yaml = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext == "yaml" || ext == "yml");

        if !is_yaml {
            continue;
        }

        match load_lolrmm_file(&path) {
            Ok(def) => definitions.push(def),
            Err(e) => {
                tracing::warn!("skipping {}: {e}", path.display());
            }
        }
    }

    Ok(definitions)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Returns the path to the vendored LOLRMM test fixtures.
    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("lolrmm")
    }

    #[test]
    fn test_load_anydesk_yaml() {
        let path = fixtures_dir().join("anydesk.yaml");
        if !path.exists() {
            eprintln!("Skipping test_load_anydesk_yaml: fixture not found");
            return;
        }

        let def = load_lolrmm_file(&path).expect("should parse anydesk.yaml");
        assert_eq!(def.name, "AnyDesk");
        assert_eq!(def.category, "RMM");

        // Must have artifacts with disk or registry entries.
        let artifacts = def.artifacts.expect("should have artifacts");
        let has_disk = artifacts.disk.as_ref().map_or(false, |d| !d.is_empty());
        let has_registry = artifacts.registry.as_ref().map_or(false, |r| !r.is_empty());
        assert!(
            has_disk || has_registry,
            "AnyDesk should have disk or registry artifacts"
        );

        // Verify some detail fields parsed correctly.
        let details = def.details.expect("should have details");
        assert!(details.free == Some(true));
        assert!(!details.supported_os.is_empty());

        // Check detections are present.
        let detections = def.detections.expect("should have detections");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_load_teamviewer_yaml() {
        let path = fixtures_dir().join("teamviewer.yaml");
        if !path.exists() {
            eprintln!("Skipping test_load_teamviewer_yaml: fixture not found");
            return;
        }

        let def = load_lolrmm_file(&path).expect("should parse teamviewer.yaml");
        assert_eq!(def.name, "TeamViewer");
        assert_eq!(def.category, "RMM");

        // TeamViewer has network artifacts with domains.
        let artifacts = def.artifacts.expect("should have artifacts");
        let network = artifacts.network.expect("should have network artifacts");
        assert!(!network.is_empty());
    }

    #[test]
    fn test_load_splashtop_yaml() {
        let path = fixtures_dir().join("splashtop.yaml");
        if !path.exists() {
            eprintln!("Skipping test_load_splashtop_yaml: fixture not found");
            return;
        }

        let def = load_lolrmm_file(&path).expect("should parse splashtop.yaml");
        assert_eq!(def.name, "Splashtop");

        // Splashtop has empty-string Free/Verification — should parse as None.
        let details = def.details.expect("should have details");
        assert_eq!(details.free, None);
        assert_eq!(details.verification, None);

        // Ports contain "N/A" — should still parse.
        let artifacts = def.artifacts.expect("should have artifacts");
        let network = artifacts.network.expect("should have network artifacts");
        let first = network
            .first()
            .expect("should have at least one network artifact");
        if let Some(ports) = &first.ports {
            // "N/A" should be preserved as a string.
            assert!(ports.iter().any(|p| p == "N/A" || p.parse::<u16>().is_ok()));
        }
    }

    #[test]
    fn test_load_directory() {
        let dir = fixtures_dir();
        if !dir.exists() {
            eprintln!("Skipping test_load_directory: fixtures dir not found");
            return;
        }

        let defs = load_lolrmm_directory(&dir).expect("should load directory");
        assert!(
            !defs.is_empty(),
            "should have loaded at least one definition"
        );
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = fixtures_dir().join("nonexistent.yaml");
        let result = load_lolrmm_file(&path);
        assert!(result.is_err(), "loading nonexistent file should fail");
    }

    #[test]
    fn test_load_nonexistent_directory() {
        let dir = fixtures_dir().join("nonexistent_dir");
        let result = load_lolrmm_directory(&dir);
        assert!(result.is_err(), "loading nonexistent directory should fail");
    }

    #[test]
    fn test_load_full_lolrmm_catalog() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("lolrmm");
        if !dir.exists() {
            eprintln!("Skipping: LOLRMM data not vendored yet");
            return;
        }
        let defs = load_lolrmm_directory(&dir).expect("load");
        assert!(defs.len() > 200, "Expected 200+ tools, got {}", defs.len());

        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"AnyDesk"), "AnyDesk should be in catalog");
        assert!(
            names.contains(&"TeamViewer"),
            "TeamViewer should be in catalog"
        );
    }

    #[test]
    fn test_load_custom_vpn_definitions() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("custom");
        if !dir.exists() {
            eprintln!("Skipping: custom VPN data not present");
            return;
        }
        let defs = load_lolrmm_directory(&dir).expect("load custom");
        assert_eq!(
            defs.len(),
            3,
            "Expected 3 custom VPN/ZTNA definitions, got {}",
            defs.len()
        );

        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"Tailscale"), "Tailscale should be present");
        assert!(names.contains(&"WireGuard"), "WireGuard should be present");
        assert!(names.contains(&"OpenVPN"), "OpenVPN should be present");

        // Verify VPN category
        for def in &defs {
            assert_eq!(def.category, "VPN", "{} should have VPN category", def.name);
        }
    }
}
