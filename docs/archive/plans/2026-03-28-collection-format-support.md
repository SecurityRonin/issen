# Collection Format Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Open UAC (.tar.gz) and Velociraptor (.zip) forensic collection archives, discover artifacts inside them, and route them to existing parsers via a new `CollectionProvider` abstraction.

**Architecture:** A two-stage pipeline — `rt-unpack` opens the archive envelope using confidence-based format probing and extracts to a temp directory, then `rt-fswalker` (renamed from `rt-pipeline`) walks the extracted tree using existing artifact discovery and parser dispatch. Three new crates (`rt-unpack`, `rt-parser-velociraptor`, `rt-parser-uac`) plus a rename and integration wiring.

**Tech Stack:** Rust, `zip` crate (Velociraptor), `flate2`+`tar` (UAC), `percent-encoding` (URL decode), `inventory` (compile-time registration), `tempfile` (managed extraction), `chrono` (timestamps)

**Spec:** `docs/superpowers/specs/2026-03-28-collection-format-support-design.md`

---

## File Map

```
crates/rt-core/src/artifacts/types.rs          — MODIFY: add 10 Linux/UAC ArtifactType variants
crates/rt-pipeline/ → crates/rt-fswalker/      — RENAME entire directory
crates/rt-fswalker/Cargo.toml                  — MODIFY: package name rt-pipeline → rt-fswalker
crates/rt-fswalker/src/orchestrator.rs         — MODIFY: add run_collection_pipeline()
Cargo.toml                                     — MODIFY: workspace members + deps rename
crates/rt-cli/Cargo.toml                       — MODIFY: dep rename + add new crates
crates/rt-cli/src/main.rs                      — MODIFY: extern crate for new parsers
crates/rt-cli/src/commands/ingest.rs           — MODIFY: use rt_fswalker + file-vs-dir detection

crates/rt-unpack/Cargo.toml                    — CREATE
crates/rt-unpack/src/lib.rs                    — CREATE: CollectionProvider trait, Confidence, types
crates/rt-unpack/src/registry.rs               — CREATE: inventory-based provider registration
crates/rt-unpack/src/tempdir.rs                — CREATE: managed temp directory

crates/parsers/rt-parser-velociraptor/Cargo.toml      — CREATE
crates/parsers/rt-parser-velociraptor/src/lib.rs      — CREATE: VelociraptorProvider + registration
crates/parsers/rt-parser-velociraptor/src/probe.rs    — CREATE: zip inspection
crates/parsers/rt-parser-velociraptor/src/extract.rs  — CREATE: extraction + path normalization
crates/parsers/rt-parser-velociraptor/src/path_decoder.rs — CREATE: URL decode + path mapping

crates/parsers/rt-parser-uac/Cargo.toml               — CREATE
crates/parsers/rt-parser-uac/src/lib.rs                — CREATE: UacProvider + registration
crates/parsers/rt-parser-uac/src/probe.rs              — CREATE: tar.gz inspection
crates/parsers/rt-parser-uac/src/extract.rs            — CREATE: extraction + metadata
crates/parsers/rt-parser-uac/src/parsers/mod.rs        — CREATE: category dispatcher
crates/parsers/rt-parser-uac/src/parsers/bodyfile.rs   — CREATE: mactime bodyfile parser
crates/parsers/rt-parser-uac/src/parsers/network.rs    — CREATE: netstat/ss parser
crates/parsers/rt-parser-uac/src/parsers/process.rs    — CREATE: ps/crontab parser
crates/parsers/rt-parser-uac/src/parsers/system.rs     — CREATE: last/uptime/uname parser
crates/parsers/rt-parser-uac/src/parsers/packages.rs   — CREATE: dpkg/rpm parser
crates/parsers/rt-parser-uac/src/parsers/hardware.rs   — CREATE: dmesg/lspci parser
crates/parsers/rt-parser-uac/src/parsers/storage.rs    — CREATE: df/mount parser
crates/parsers/rt-parser-uac/src/parsers/hash_execs.rs — CREATE: executable hash parser
crates/parsers/rt-parser-uac/src/parsers/chkrootkit.rs — CREATE: rootkit scan parser
crates/parsers/rt-parser-uac/src/parsers/configs.rs    — CREATE: /etc config parser
```

---

### Task 1: Rename rt-pipeline to rt-fswalker

Mechanical rename of the existing pipeline crate. Must happen first since all other tasks reference the new name.

**Files:**
- Rename: `crates/rt-pipeline/` → `crates/rt-fswalker/`
- Modify: `crates/rt-fswalker/Cargo.toml`
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/rt-cli/Cargo.toml`
- Modify: `crates/rt-cli/src/commands/ingest.rs`

- [ ] **Step 1: Rename the directory**

```bash
mv crates/rt-pipeline crates/rt-fswalker
```

- [ ] **Step 2: Update the crate's own Cargo.toml**

In `crates/rt-fswalker/Cargo.toml`, change the package name and description:

```toml
[package]
name = "rt-fswalker"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "Apache-2.0"
description = "Filesystem walker and artifact dispatch for Issen"
repository.workspace = true

[dependencies]
rt-core = { workspace = true }
rayon = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }
memmap2 = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
insta = { workspace = true }

[lints]
workspace = true
```

- [ ] **Step 3: Update workspace Cargo.toml**

In the root `Cargo.toml`:

Change `"crates/rt-pipeline"` to `"crates/rt-fswalker"` in the `members` array.

Change the workspace dependency:
```toml
rt-fswalker = { path = "crates/rt-fswalker" }
```

Remove the old `rt-pipeline` line from `[workspace.dependencies]`.

- [ ] **Step 4: Update rt-cli Cargo.toml**

In `crates/rt-cli/Cargo.toml`, replace `rt-pipeline` with `rt-fswalker`:

```toml
rt-fswalker = { workspace = true }
```

- [ ] **Step 5: Update rt-cli import in ingest.rs**

In `crates/rt-cli/src/commands/ingest.rs`, change:

```rust
use rt_fswalker::orchestrator::run_pipeline;
use rt_fswalker::progress::ProgressReporter;
```

- [ ] **Step 6: Run tests to verify rename is clean**

```bash
cd /Users/4n6h4x0r/src/Issen && cargo test --workspace 2>&1 | tail -5
```

Expected: All existing tests pass (the crate name change is transparent to test code since internal `use crate::` paths don't change).

- [ ] **Step 7: Run clippy**

```bash
cargo clippy --workspace -- -D warnings 2>&1 | tail -10
```

Expected: No errors (warnings from existing code are acceptable).

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "refactor: rename rt-pipeline to rt-fswalker"
```

---

### Task 2: Extend ArtifactType with Linux/UAC variants

Add new artifact type variants that UAC sub-parsers will use. This is prerequisite for rt-unpack and rt-parser-uac.

**Files:**
- Modify: `crates/rt-core/src/artifacts/types.rs`

- [ ] **Step 1: Write the failing test**

Add to the bottom of the existing `#[cfg(test)] mod tests` block in `crates/rt-core/src/artifacts/types.rs` (if there is one) or create tests. Since this file has no tests module, add one:

In `crates/rt-core/src/artifacts/types.rs`, append after the `Display` impl:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_artifact_types_display() {
        assert_eq!(format!("{}", ArtifactType::Bodyfile), "Bodyfile");
        assert_eq!(format!("{}", ArtifactType::NetworkState), "Network State");
        assert_eq!(format!("{}", ArtifactType::ProcessList), "Process List");
        assert_eq!(format!("{}", ArtifactType::PackageList), "Package List");
        assert_eq!(format!("{}", ArtifactType::SystemInfo), "System Info");
        assert_eq!(format!("{}", ArtifactType::LoginHistory), "Login History");
        assert_eq!(format!("{}", ArtifactType::CrontabConfig), "Crontab");
        assert_eq!(format!("{}", ArtifactType::HashManifest), "Hash Manifest");
        assert_eq!(format!("{}", ArtifactType::RootkitScan), "Rootkit Scan");
        assert_eq!(format!("{}", ArtifactType::SystemConfig), "System Config");
    }

    #[test]
    fn test_artifact_type_serde_roundtrip() {
        let original = ArtifactType::Bodyfile;
        let json = serde_json::to_string(&original).expect("serialize");
        let back: ArtifactType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, back);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p rt-core -- tests::test_linux_artifact_types_display 2>&1 | tail -5
```

Expected: FAIL — `Bodyfile` variant doesn't exist yet.

- [ ] **Step 3: Add the new variants and Display arms**

In `crates/rt-core/src/artifacts/types.rs`, add to the `ArtifactType` enum (after `Assessment`):

```rust
    /// Mactime bodyfile (filesystem timeline from UAC)
    Bodyfile,
    /// Network state snapshot (netstat, ss, arp)
    NetworkState,
    /// Running process list (ps, lsof)
    ProcessList,
    /// Installed package inventory (dpkg, rpm, pip)
    PackageList,
    /// System information (hostname, uname, uptime)
    SystemInfo,
    /// Login/logout history (last, loginctl)
    LoginHistory,
    /// Crontab / scheduled task configuration
    CrontabConfig,
    /// Hash manifest of executables
    HashManifest,
    /// Rootkit scan results (chkrootkit, rkhunter)
    RootkitScan,
    /// System configuration files (/etc)
    SystemConfig,
```

Add to the `Display` impl `match` block:

```rust
            Self::Bodyfile => write!(f, "Bodyfile"),
            Self::NetworkState => write!(f, "Network State"),
            Self::ProcessList => write!(f, "Process List"),
            Self::PackageList => write!(f, "Package List"),
            Self::SystemInfo => write!(f, "System Info"),
            Self::LoginHistory => write!(f, "Login History"),
            Self::CrontabConfig => write!(f, "Crontab"),
            Self::HashManifest => write!(f, "Hash Manifest"),
            Self::RootkitScan => write!(f, "Rootkit Scan"),
            Self::SystemConfig => write!(f, "System Config"),
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p rt-core -- tests::test_linux 2>&1 | tail -5
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/rt-core/src/artifacts/types.rs && git commit -m "feat(rt-core): add Linux/UAC artifact type variants"
```

---

### Task 3: rt-unpack — CollectionProvider trait and types

Create the `rt-unpack` crate with the core trait and types. No provider implementations yet — just the abstraction.

**Files:**
- Create: `crates/rt-unpack/Cargo.toml`
- Create: `crates/rt-unpack/src/lib.rs`
- Create: `crates/rt-unpack/src/tempdir.rs`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Create Cargo.toml**

Create `crates/rt-unpack/Cargo.toml`:

```toml
[package]
name = "rt-unpack"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "Apache-2.0"
description = "Collection format detection and extraction for Issen"
repository.workspace = true

[dependencies]
rt-core = { workspace = true }
chrono = { workspace = true }
inventory = { workspace = true }
tempfile = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }

[lints]
workspace = true
```

- [ ] **Step 2: Add to workspace**

In root `Cargo.toml`, add `"crates/rt-unpack"` to the `members` array and add to workspace dependencies:

```toml
rt-unpack = { path = "crates/rt-unpack" }
```

- [ ] **Step 3: Write tests for Confidence ordering and types**

Create `crates/rt-unpack/src/lib.rs`:

```rust
pub mod registry;
pub mod tempdir;

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rt_core::artifacts::ArtifactType;

/// How confident a provider is that it can handle a given file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Cannot handle this format.
    None,
    /// Structure looks plausible but not definitive.
    Low,
    /// Key structural markers found.
    Medium,
    /// Definitive signature identified.
    High,
}

/// Operating system type detected from the collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsType {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

/// Metadata extracted from the collection itself.
#[derive(Debug, Clone)]
pub struct CollectionMetadata {
    pub hostname: Option<String>,
    pub collection_time: Option<DateTime<Utc>>,
    pub os_type: OsType,
    pub tool_version: Option<String>,
}

/// A single entry in the collection manifest.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    /// Path relative to extracted_root.
    pub path: PathBuf,
    /// Pre-classified artifact type, or None to let the fswalker detect.
    pub artifact_type: Option<ArtifactType>,
}

/// Result of opening a collection — where it was extracted and what's inside.
#[derive(Debug)]
pub struct CollectionManifest {
    pub format_name: String,
    pub extracted_root: PathBuf,
    pub artifacts: Vec<ManifestEntry>,
    pub metadata: CollectionMetadata,
    /// Handle to the temp directory — dropped when manifest is dropped.
    _tempdir: tempfile::TempDir,
}

impl CollectionManifest {
    /// Create a new manifest. The `TempDir` handle keeps the directory alive.
    pub fn new(
        format_name: String,
        tempdir: tempfile::TempDir,
        artifacts: Vec<ManifestEntry>,
        metadata: CollectionMetadata,
    ) -> Self {
        let extracted_root = tempdir.path().to_path_buf();
        Self {
            format_name,
            extracted_root,
            artifacts,
            metadata,
            _tempdir: tempdir,
        }
    }
}

/// Trait implemented by each collection format handler.
///
/// Providers are registered at compile time via `inventory::submit!`.
/// The registry probes all providers and picks the highest-confidence match.
pub trait CollectionProvider: Send + Sync {
    /// Human-readable name of this format (e.g., "Velociraptor", "UAC").
    fn name(&self) -> &str;

    /// Inspect the file and return confidence that this provider can handle it.
    ///
    /// Implementations MUST inspect internal structure (not file extension).
    fn probe(&self, path: &Path) -> Result<Confidence, rt_core::error::RtError>;

    /// Extract the collection to a temp directory and return a manifest.
    fn open(&self, path: &Path) -> Result<CollectionManifest, rt_core::error::RtError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::None < Confidence::Low);
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
    }

    #[test]
    fn test_confidence_max_selects_highest() {
        let levels = vec![Confidence::Low, Confidence::High, Confidence::Medium];
        assert_eq!(levels.into_iter().max(), Some(Confidence::High));
    }

    #[test]
    fn test_manifest_entry_with_type() {
        let entry = ManifestEntry {
            path: PathBuf::from("$MFT"),
            artifact_type: Some(ArtifactType::Mft),
        };
        assert_eq!(entry.artifact_type, Some(ArtifactType::Mft));
    }

    #[test]
    fn test_manifest_entry_without_type() {
        let entry = ManifestEntry {
            path: PathBuf::from("unknown.dat"),
            artifact_type: None,
        };
        assert!(entry.artifact_type.is_none());
    }

    #[test]
    fn test_collection_metadata_defaults() {
        let meta = CollectionMetadata {
            hostname: None,
            collection_time: None,
            os_type: OsType::Unknown,
            tool_version: None,
        };
        assert_eq!(meta.os_type, OsType::Unknown);
        assert!(meta.hostname.is_none());
    }

    #[test]
    fn test_collection_manifest_holds_tempdir() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = tempdir.path().to_path_buf();
        let manifest = CollectionManifest::new(
            "test".into(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Unknown,
                tool_version: None,
            },
        );
        // Temp directory should still exist while manifest is alive
        assert!(path.exists());
        assert_eq!(manifest.extracted_root, path);
        drop(manifest);
        // After drop, temp directory is cleaned up
        assert!(!path.exists());
    }
}
```

- [ ] **Step 4: Create tempdir.rs**

Create `crates/rt-unpack/src/tempdir.rs`:

```rust
use rt_core::error::RtError;

/// Create a managed temp directory for collection extraction.
///
/// The returned `TempDir` will be automatically cleaned up when dropped.
/// The caller should store it in the `CollectionManifest` to keep it alive.
pub fn create_extraction_dir() -> Result<tempfile::TempDir, RtError> {
    tempfile::Builder::new()
        .prefix("rt-unpack-")
        .tempdir()
        .map_err(RtError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_extraction_dir() {
        let dir = create_extraction_dir().expect("create dir");
        assert!(dir.path().exists());
        let path = dir.path().to_path_buf();
        drop(dir);
        assert!(!path.exists(), "tempdir should be cleaned up on drop");
    }
}
```

- [ ] **Step 5: Create stub registry.rs**

Create `crates/rt-unpack/src/registry.rs`:

```rust
use std::path::Path;

use rt_core::error::RtError;
use tracing::info;

use crate::{CollectionManifest, CollectionProvider, Confidence};

/// Registration entry for the collection provider inventory.
pub struct ProviderRegistration {
    pub create: fn() -> Box<dyn CollectionProvider>,
}

inventory::collect!(ProviderRegistration);

/// Probe all registered providers and open the collection with the best match.
///
/// Returns an error if no provider recognizes the format.
pub fn open_collection(path: &Path) -> Result<CollectionManifest, RtError> {
    let mut best: Option<(Box<dyn CollectionProvider>, Confidence)> = None;

    for reg in inventory::iter::<ProviderRegistration> {
        let provider = (reg.create)();
        match provider.probe(path) {
            Ok(confidence) if confidence > Confidence::None => {
                info!(
                    provider = provider.name(),
                    ?confidence,
                    "Provider matched"
                );
                if best.as_ref().map_or(true, |(_, c)| confidence > *c) {
                    best = Some((provider, confidence));
                }
            }
            Ok(_) => {} // Confidence::None — skip
            Err(e) => {
                // Probe failed — log and continue to next provider.
                info!(provider = provider.name(), error = %e, "Probe failed, skipping");
            }
        }
    }

    match best {
        Some((provider, confidence)) => {
            info!(
                provider = provider.name(),
                ?confidence,
                "Opening collection"
            );
            provider.open(path)
        }
        None => {
            let provider_names: Vec<String> = inventory::iter::<ProviderRegistration>
                .into_iter()
                .map(|reg| (reg.create)().name().to_string())
                .collect();
            Err(RtError::UnsupportedFormat(format!(
                "No collection provider recognized {}. Probed: [{}]",
                path.display(),
                provider_names.join(", ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_collection_no_providers_returns_error() {
        // With no providers registered in this test binary, we expect an error.
        let result = open_collection(Path::new("/nonexistent/file.zip"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("No collection provider recognized"),
            "Error should mention no provider: {err}"
        );
    }
}
```

- [ ] **Step 6: Run tests**

```bash
cargo test -p rt-unpack 2>&1 | tail -10
```

Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/rt-unpack Cargo.toml && git commit -m "feat(rt-unpack): add CollectionProvider trait, Confidence, and registry"
```

---

### Task 4: rt-parser-velociraptor — path decoder

The URL-decode and path normalization module, ported from `~/src/tl`. This is independently testable with no archive I/O.

**Files:**
- Create: `crates/parsers/rt-parser-velociraptor/Cargo.toml`
- Create: `crates/parsers/rt-parser-velociraptor/src/lib.rs`
- Create: `crates/parsers/rt-parser-velociraptor/src/path_decoder.rs`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Create crate scaffold**

Create `crates/parsers/rt-parser-velociraptor/Cargo.toml`:

```toml
[package]
name = "rt-parser-velociraptor"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "Apache-2.0"
description = "Velociraptor collection format handler for Issen"
repository.workspace = true

[dependencies]
rt-core = { workspace = true }
rt-unpack = { workspace = true }
inventory = { workspace = true }
tracing = { workspace = true }
zip = { workspace = true }
percent-encoding = { workspace = true }
chrono = { workspace = true }
regex = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }

[lints]
workspace = true
```

Add to workspace root `Cargo.toml`:
- Add `"crates/parsers/rt-parser-velociraptor"` to `members`
- Add `rt-parser-velociraptor = { path = "crates/parsers/rt-parser-velociraptor" }` to workspace deps
- Add `zip = "2"` and `percent-encoding = "2"` to workspace deps

- [ ] **Step 2: Write failing tests for path decoder**

Create `crates/parsers/rt-parser-velociraptor/src/path_decoder.rs`:

```rust
use rt_core::artifacts::ArtifactType;

/// Which Velociraptor accessor produced this entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessorType {
    /// Raw NTFS accessor: uploads/ntfs/...
    Ntfs,
    /// Auto accessor: uploads/auto/...
    Auto,
}

/// A decoded Velociraptor zip entry path.
#[derive(Debug, Clone)]
pub struct DecodedPath {
    /// The normalized Windows-style path (e.g., `C:\$MFT`).
    pub windows_path: String,
    /// Which accessor produced this entry.
    pub accessor: AccessorType,
    /// The original zip entry path (needed for extraction).
    pub original_zip_path: String,
    /// Detected artifact type if recognizable.
    pub artifact_type: Option<ArtifactType>,
}

/// Decode a Velociraptor zip entry path into a normalized form.
///
/// Velociraptor encodes paths like:
/// - NTFS: `uploads/ntfs/%5C%5C.%5CC%3A/$MFT` → `C:\$MFT`
/// - Auto: `uploads/auto/C%3A/Windows/System32/config/SYSTEM` → `C:\Windows\System32\config\SYSTEM`
///
/// Returns `None` if the path is not a Velociraptor artifact entry.
pub fn decode_velociraptor_path(zip_path: &str) -> Option<DecodedPath> {
    let decoded = percent_encoding::percent_decode_str(zip_path)
        .decode_utf8_lossy()
        .to_string();

    if let Some(rest) = decoded.strip_prefix("uploads/ntfs/") {
        // NTFS accessor: \\.\C:\path -> C:\path
        let normalized = rest
            .strip_prefix("\\\\.\\C:\\")
            .or_else(|| rest.strip_prefix("\\\\.\\C:/"))
            .unwrap_or(rest);
        let windows_path = format!("C:\\{}", normalized.replace('/', "\\"));
        let artifact_type = classify_artifact(&windows_path);
        Some(DecodedPath {
            windows_path,
            accessor: AccessorType::Ntfs,
            original_zip_path: zip_path.to_string(),
            artifact_type,
        })
    } else if let Some(rest) = decoded.strip_prefix("uploads/auto/") {
        // Auto accessor: C:/path -> C:\path
        let windows_path = if rest.starts_with("C:") || rest.starts_with("c:") {
            rest.replace('/', "\\")
        } else {
            format!("C:\\{}", rest.replace('/', "\\"))
        };
        let artifact_type = classify_artifact(&windows_path);
        Some(DecodedPath {
            windows_path,
            accessor: AccessorType::Auto,
            original_zip_path: zip_path.to_string(),
            artifact_type,
        })
    } else {
        None
    }
}

/// Classify a normalized Windows path into an `ArtifactType`.
fn classify_artifact(path: &str) -> Option<ArtifactType> {
    let lower = path.to_lowercase();

    // NTFS core artifacts
    if lower.ends_with("$mft") {
        return Some(ArtifactType::Mft);
    }
    if lower.contains("$usnjrnl") || lower.ends_with("$j") {
        return Some(ArtifactType::UsnJournal);
    }

    // Event logs
    if lower.ends_with(".evtx") {
        return Some(ArtifactType::EventLog);
    }

    // Registry hives
    if (lower.ends_with("\\system")
        || lower.ends_with("\\software")
        || lower.ends_with("\\sam")
        || lower.ends_with("\\security"))
        && lower.contains("config")
    {
        return Some(ArtifactType::Registry);
    }
    if lower.ends_with("ntuser.dat") || lower.ends_with("usrclass.dat") {
        return Some(ArtifactType::Registry);
    }

    // Amcache
    if lower.ends_with("amcache.hve") {
        return Some(ArtifactType::Amcache);
    }

    // Prefetch
    if lower.ends_with(".pf") && lower.contains("prefetch") {
        return Some(ArtifactType::Prefetch);
    }

    // LNK files
    if lower.ends_with(".lnk") {
        return Some(ArtifactType::Lnk);
    }

    // SRUM
    if lower.ends_with("srudb.dat") {
        return Some(ArtifactType::Srum);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_ntfs_mft() {
        let path = "uploads/ntfs/%5C%5C.%5CC%3A/$MFT";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        assert_eq!(decoded.accessor, AccessorType::Ntfs);
        assert_eq!(decoded.windows_path, "C:\\$MFT");
        assert_eq!(decoded.artifact_type, Some(ArtifactType::Mft));
        assert_eq!(decoded.original_zip_path, path);
    }

    #[test]
    fn test_decode_ntfs_usnjrnl() {
        let path = "uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        assert_eq!(decoded.accessor, AccessorType::Ntfs);
        assert!(decoded.windows_path.contains("$UsnJrnl"));
        assert_eq!(decoded.artifact_type, Some(ArtifactType::UsnJournal));
    }

    #[test]
    fn test_decode_auto_evtx() {
        let path = "uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        assert_eq!(decoded.accessor, AccessorType::Auto);
        assert!(decoded.windows_path.ends_with("Security.evtx"));
        assert_eq!(decoded.artifact_type, Some(ArtifactType::EventLog));
    }

    #[test]
    fn test_decode_auto_registry() {
        let path = "uploads/auto/C%3A/Windows/System32/config/SYSTEM";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        assert_eq!(decoded.artifact_type, Some(ArtifactType::Registry));
    }

    #[test]
    fn test_decode_auto_ntuser() {
        let path = "uploads/auto/C%3A/Users/admin/NTUSER.DAT";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        assert_eq!(decoded.artifact_type, Some(ArtifactType::Registry));
    }

    #[test]
    fn test_decode_auto_lnk() {
        let path = "uploads/auto/C%3A/Users/admin/AppData/Roaming/Microsoft/Windows/Recent/foo.lnk";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        assert_eq!(decoded.artifact_type, Some(ArtifactType::Lnk));
    }

    #[test]
    fn test_decode_non_velociraptor_path_returns_none() {
        assert!(decode_velociraptor_path("some/random/file.txt").is_none());
        assert!(decode_velociraptor_path("").is_none());
    }

    #[test]
    fn test_decode_unknown_artifact() {
        let path = "uploads/auto/C%3A/Windows/Temp/random.tmp";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        assert!(decoded.artifact_type.is_none());
    }

    #[test]
    fn test_classify_amcache() {
        assert_eq!(
            classify_artifact("C:\\Windows\\AppCompat\\Programs\\Amcache.hve"),
            Some(ArtifactType::Amcache)
        );
    }

    #[test]
    fn test_classify_srum() {
        assert_eq!(
            classify_artifact("C:\\Windows\\System32\\SRU\\SRUDB.dat"),
            Some(ArtifactType::Srum)
        );
    }
}
```

Create `crates/parsers/rt-parser-velociraptor/src/lib.rs`:

```rust
pub mod path_decoder;
pub mod probe;
pub mod extract;
```

Create stub files:

`crates/parsers/rt-parser-velociraptor/src/probe.rs`:
```rust
// Velociraptor zip probing — implemented in Task 5.
```

`crates/parsers/rt-parser-velociraptor/src/extract.rs`:
```rust
// Velociraptor extraction — implemented in Task 5.
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p rt-parser-velociraptor 2>&1 | tail -10
```

Expected: All path decoder tests PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/parsers/rt-parser-velociraptor Cargo.toml && git commit -m "feat(rt-parser-velociraptor): add URL path decoder with artifact classification"
```

---

### Task 5: rt-parser-velociraptor — probe, extract, and provider

Implement the `VelociraptorProvider` that probes zip files for Velociraptor structure and extracts with normalized paths.

**Files:**
- Modify: `crates/parsers/rt-parser-velociraptor/src/lib.rs`
- Modify: `crates/parsers/rt-parser-velociraptor/src/probe.rs`
- Modify: `crates/parsers/rt-parser-velociraptor/src/extract.rs`

- [ ] **Step 1: Write failing tests for probe**

Replace `crates/parsers/rt-parser-velociraptor/src/probe.rs`:

```rust
use std::path::Path;

use rt_core::error::RtError;
use rt_unpack::Confidence;

/// Probe a file to check if it's a Velociraptor collection zip.
///
/// Checks for:
/// 1. Valid zip archive
/// 2. Entries starting with `uploads/`
/// 3. URL-encoded path separators (`%5C` or `%3A`)
pub fn probe_velociraptor(path: &Path) -> Result<Confidence, RtError> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(Confidence::None),
    };

    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return Ok(Confidence::None), // Not a valid zip
    };

    let mut has_uploads = false;
    let mut has_encoded_paths = false;

    // Check first 200 entries (enough to detect structure without scanning entire archive)
    let limit = archive.len().min(200);
    for i in 0..limit {
        if let Ok(entry) = archive.by_index_raw(i) {
            let name = entry.name().to_string();
            if name.starts_with("uploads/") {
                has_uploads = true;
                if name.contains("%5C") || name.contains("%5c") || name.contains("%3A") || name.contains("%3a") {
                    has_encoded_paths = true;
                    break; // Both confirmed, no need to continue
                }
            }
        }
    }

    if has_uploads && has_encoded_paths {
        Ok(Confidence::High)
    } else if has_uploads {
        Ok(Confidence::Medium)
    } else {
        Ok(Confidence::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_nonexistent_file() {
        let result = probe_velociraptor(Path::new("/nonexistent/file.zip"));
        assert_eq!(result.expect("should not error"), Confidence::None);
    }

    #[test]
    fn test_probe_non_zip_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("not_a_zip.txt");
        std::fs::write(&path, b"this is not a zip file").expect("write");
        assert_eq!(
            probe_velociraptor(&path).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn test_probe_empty_zip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("empty.zip");
        let file = std::fs::File::create(&path).expect("create");
        zip::ZipWriter::new(file).finish().expect("zip finish");
        assert_eq!(
            probe_velociraptor(&path).expect("probe"),
            Confidence::None,
            "Empty zip has no uploads/ directory"
        );
    }

    #[test]
    fn test_probe_zip_with_uploads_and_encoded() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("velo.zip");
        let file = std::fs::File::create(&path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("uploads/ntfs/%5C%5C.%5CC%3A/$MFT", opts)
            .expect("entry");
        zip.write_all(b"fake mft data").expect("write");
        zip.finish().expect("finish");

        assert_eq!(
            probe_velociraptor(&path).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn test_probe_zip_with_uploads_no_encoding() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("maybe_velo.zip");
        let file = std::fs::File::create(&path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("uploads/plain/file.txt", opts).expect("entry");
        zip.write_all(b"data").expect("write");
        zip.finish().expect("finish");

        assert_eq!(
            probe_velociraptor(&path).expect("probe"),
            Confidence::Medium,
            "Has uploads/ but no encoded paths"
        );
    }
}
```

Add `use std::io::Write;` at the top of the test module (needed for `zip.write_all`).

- [ ] **Step 2: Run tests to verify they pass**

```bash
cargo test -p rt-parser-velociraptor -- probe 2>&1 | tail -10
```

Expected: PASS (probe is implemented inline above).

- [ ] **Step 3: Implement extract.rs**

Replace `crates/parsers/rt-parser-velociraptor/src/extract.rs`:

```rust
use std::io::Read;
use std::path::{Path, PathBuf};

use rt_core::artifacts::ArtifactType;
use rt_core::error::RtError;
use rt_unpack::{CollectionManifest, CollectionMetadata, ManifestEntry, OsType};
use tracing::info;

use crate::path_decoder::{decode_velociraptor_path, DecodedPath};

/// Extract a Velociraptor collection zip to the given destination directory.
///
/// Returns a manifest of all extracted artifacts with their classified types.
pub fn extract_velociraptor(
    zip_path: &Path,
    dest: &Path,
) -> Result<(Vec<ManifestEntry>, CollectionMetadata), RtError> {
    let file = std::fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| RtError::InvalidData(format!("Failed to open zip: {e}")))?;

    let mut entries = Vec::new();
    let metadata = extract_metadata_from_filename(zip_path);

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| RtError::InvalidData(format!("Zip entry {i}: {e}")))?;

        if entry.is_dir() {
            continue;
        }

        let zip_entry_name = entry.name().to_string();

        if let Some(decoded) = decode_velociraptor_path(&zip_entry_name) {
            let rel_path = decoded_to_relative_path(&decoded);
            let full_path = dest.join(&rel_path);

            // Create parent directories
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Extract file contents
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .map_err(|e| RtError::Io(e))?;
            std::fs::write(&full_path, &buf)?;

            entries.push(ManifestEntry {
                path: rel_path,
                artifact_type: decoded.artifact_type,
            });
        }
    }

    info!(
        artifacts = entries.len(),
        "Extracted Velociraptor collection"
    );

    Ok((entries, metadata))
}

/// Convert a decoded Velociraptor path to a relative extraction path.
///
/// Strips the drive letter and uses forward slashes for cross-platform compat.
fn decoded_to_relative_path(decoded: &DecodedPath) -> PathBuf {
    let stripped = decoded
        .windows_path
        .strip_prefix("C:\\")
        .or_else(|| decoded.windows_path.strip_prefix("c:\\"))
        .unwrap_or(&decoded.windows_path);
    PathBuf::from(stripped.replace('\\', "/"))
}

/// Extract hostname and timestamp from the Velociraptor zip filename.
///
/// Pattern: `Collection-<hostname>-<timestamp>.zip`
fn extract_metadata_from_filename(path: &Path) -> CollectionMetadata {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();

    let (hostname, collection_time) = if let Some(rest) = stem.strip_prefix("Collection-") {
        // Find the timestamp portion (ISO 8601-ish at the end)
        // Pattern: hostname-YYYY-MM-DDTHH_MM_SSZ
        if let Some(idx) = rest.find("-20") {
            // Heuristic: find the year portion
            let host = &rest[..idx];
            let ts_str = &rest[idx + 1..];
            let ts = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H_%M_%SZ")
                .ok()
                .map(|dt| dt.and_utc());
            (Some(host.to_string()), ts)
        } else {
            (Some(rest.to_string()), None)
        }
    } else {
        (None, None)
    };

    CollectionMetadata {
        hostname,
        collection_time,
        os_type: OsType::Windows,
        tool_version: Some("Velociraptor".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_decoded_to_relative_path() {
        let decoded = DecodedPath {
            windows_path: "C:\\$MFT".into(),
            accessor: crate::path_decoder::AccessorType::Ntfs,
            original_zip_path: String::new(),
            artifact_type: Some(ArtifactType::Mft),
        };
        assert_eq!(decoded_to_relative_path(&decoded), PathBuf::from("$MFT"));
    }

    #[test]
    fn test_decoded_to_relative_nested() {
        let decoded = DecodedPath {
            windows_path: "C:\\Windows\\System32\\config\\SYSTEM".into(),
            accessor: crate::path_decoder::AccessorType::Auto,
            original_zip_path: String::new(),
            artifact_type: Some(ArtifactType::Registry),
        };
        assert_eq!(
            decoded_to_relative_path(&decoded),
            PathBuf::from("Windows/System32/config/SYSTEM")
        );
    }

    #[test]
    fn test_extract_metadata_from_filename() {
        let path = Path::new("Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
        let meta = extract_metadata_from_filename(path);
        assert_eq!(meta.hostname.as_deref(), Some("A380_localdomain"));
        assert!(meta.collection_time.is_some());
        assert_eq!(meta.os_type, OsType::Windows);
    }

    #[test]
    fn test_extract_metadata_non_collection_name() {
        let path = Path::new("random_archive.zip");
        let meta = extract_metadata_from_filename(path);
        assert!(meta.hostname.is_none());
        assert!(meta.collection_time.is_none());
    }

    #[test]
    fn test_extract_velociraptor_basic() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let zip_path = dir.path().join("Collection-TEST-2025-01-01T00_00_00Z.zip");
        let dest = dir.path().join("extracted");
        std::fs::create_dir_all(&dest).expect("mkdir");

        // Create a synthetic Velociraptor zip
        let file = std::fs::File::create(&zip_path).expect("create zip");
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();

        zip.start_file("uploads/ntfs/%5C%5C.%5CC%3A/$MFT", opts).expect("add");
        zip.write_all(b"fake-mft-data").expect("write");

        zip.start_file("uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx", opts).expect("add");
        zip.write_all(b"fake-evtx").expect("write");

        zip.finish().expect("finish");

        let (entries, meta) = extract_velociraptor(&zip_path, &dest).expect("extract");

        assert_eq!(entries.len(), 2);
        assert_eq!(meta.hostname.as_deref(), Some("TEST"));

        // Check MFT was extracted
        let mft_entry = entries.iter().find(|e| e.artifact_type == Some(ArtifactType::Mft));
        assert!(mft_entry.is_some());
        assert!(dest.join("$MFT").exists());
        assert_eq!(std::fs::read(dest.join("$MFT")).expect("read"), b"fake-mft-data");

        // Check evtx was extracted
        let evtx_entry = entries.iter().find(|e| e.artifact_type == Some(ArtifactType::EventLog));
        assert!(evtx_entry.is_some());
    }
}
```

- [ ] **Step 4: Wire up the VelociraptorProvider in lib.rs**

Replace `crates/parsers/rt-parser-velociraptor/src/lib.rs`:

```rust
pub mod extract;
pub mod path_decoder;
pub mod probe;

use std::path::Path;

use rt_core::error::RtError;
use rt_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// Velociraptor collection format handler.
///
/// Recognizes `.zip` files containing URL-encoded paths under `uploads/`.
pub struct VelociraptorProvider;

impl CollectionProvider for VelociraptorProvider {
    fn name(&self) -> &str {
        "Velociraptor"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        probe::probe_velociraptor(path)
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        let tempdir = rt_unpack::tempdir::create_extraction_dir()?;
        let (entries, metadata) = extract::extract_velociraptor(path, tempdir.path())?;
        Ok(CollectionManifest::new(
            "Velociraptor".into(),
            tempdir,
            entries,
            metadata,
        ))
    }
}

// Register with the collection provider inventory.
inventory::submit!(rt_unpack::registry::ProviderRegistration {
    create: || Box::new(VelociraptorProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_velociraptor_provider_name() {
        let provider = VelociraptorProvider;
        assert_eq!(provider.name(), "Velociraptor");
    }

    #[test]
    fn test_velociraptor_provider_probe_and_open() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let zip_path = dir.path().join("Collection-HOST-2025-01-01T00_00_00Z.zip");

        let file = std::fs::File::create(&zip_path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("uploads/ntfs/%5C%5C.%5CC%3A/$MFT", opts).expect("add");
        zip.write_all(b"mft").expect("write");
        zip.finish().expect("finish");

        let provider = VelociraptorProvider;
        let confidence = provider.probe(&zip_path).expect("probe");
        assert_eq!(confidence, Confidence::High);

        let manifest = provider.open(&zip_path).expect("open");
        assert_eq!(manifest.format_name, "Velociraptor");
        assert_eq!(manifest.metadata.hostname.as_deref(), Some("HOST"));
        assert!(!manifest.artifacts.is_empty());
    }
}
```

- [ ] **Step 5: Run all tests**

```bash
cargo test -p rt-parser-velociraptor 2>&1 | tail -10
```

Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/parsers/rt-parser-velociraptor Cargo.toml && git commit -m "feat(rt-parser-velociraptor): probe, extract, and VelociraptorProvider"
```

---

### Task 6: rt-parser-uac — scaffold, probe, and extract

Create the UAC handler crate with tar.gz probing and extraction.

**Files:**
- Create: `crates/parsers/rt-parser-uac/Cargo.toml`
- Create: `crates/parsers/rt-parser-uac/src/lib.rs`
- Create: `crates/parsers/rt-parser-uac/src/probe.rs`
- Create: `crates/parsers/rt-parser-uac/src/extract.rs`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Create crate scaffold**

Create `crates/parsers/rt-parser-uac/Cargo.toml`:

```toml
[package]
name = "rt-parser-uac"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "Apache-2.0"
description = "UAC (Unix Artifact Collector) collection format handler for Issen"
repository.workspace = true

[dependencies]
rt-core = { workspace = true }
rt-unpack = { workspace = true }
chrono = { workspace = true }
flate2 = { workspace = true }
inventory = { workspace = true }
regex = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tar = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }

[lints]
workspace = true
```

Add to workspace root `Cargo.toml`:
- Add `"crates/parsers/rt-parser-uac"` to `members`
- Add `rt-parser-uac = { path = "crates/parsers/rt-parser-uac" }` to workspace deps
- Add `flate2 = "1"` and `tar = "0.4"` to workspace deps

- [ ] **Step 2: Implement probe.rs**

Create `crates/parsers/rt-parser-uac/src/probe.rs`:

```rust
use std::path::Path;

use rt_core::error::RtError;
use rt_unpack::Confidence;

/// Probe a file to check if it's a UAC collection tar.gz.
///
/// Checks for:
/// 1. Valid gzip-compressed tar archive
/// 2. Presence of `uac.log` entry
/// 3. Known UAC directory structure (bodyfile/, live_response/)
pub fn probe_uac(path: &Path) -> Result<Confidence, RtError> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(Confidence::None),
    };

    let gz = match flate2::read::GzDecoder::new(file) {
        gz => {
            // Check if it's actually gzip by trying to read header
            let mut archive = tar::Archive::new(gz);
            let entries = match archive.entries() {
                Ok(e) => e,
                Err(_) => return Ok(Confidence::None),
            };

            let mut has_uac_log = false;
            let mut has_uac_dirs = false;
            let mut count = 0;

            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => return Ok(Confidence::None), // Not a valid tar
                };

                let path_str = entry.path()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                if path_str.ends_with("uac.log") || path_str.contains("/uac.log") {
                    has_uac_log = true;
                }
                if path_str.contains("/bodyfile/")
                    || path_str.contains("/live_response/")
                    || path_str.contains("/system/")
                {
                    has_uac_dirs = true;
                }

                if has_uac_log && has_uac_dirs {
                    break; // Both confirmed
                }

                count += 1;
                if count > 200 {
                    break; // Scanned enough entries
                }
            }

            if has_uac_log {
                return Ok(Confidence::High);
            }
            if has_uac_dirs {
                return Ok(Confidence::Medium);
            }
            return Ok(Confidence::None);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_uac_tar_gz(dir: &Path, include_uac_log: bool) -> std::path::PathBuf {
        let tar_gz_path = dir.join("uac-test.tar.gz");
        let file = std::fs::File::create(&tar_gz_path).expect("create");
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar = tar::Builder::new(gz);

        // Add a header entry for the root dir
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, "uac-test/bodyfile/", &[] as &[u8]).expect("dir");

        if include_uac_log {
            let data = b"[2026-03-24 19:38:07] UAC started";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "uac-test/uac.log", &data[..]).expect("uac.log");
        }

        let bf_data = b"0|/bin/ls|1234|100755|0|0|100|1711111111|1711111112|1711111113|0";
        let mut header = tar::Header::new_gnu();
        header.set_size(bf_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "uac-test/bodyfile/bodyfile.txt", &bf_data[..]).expect("bodyfile");

        let gz = tar.into_inner().expect("tar finish");
        gz.finish().expect("gz finish");

        tar_gz_path
    }

    #[test]
    fn test_probe_nonexistent_file() {
        assert_eq!(
            probe_uac(Path::new("/nonexistent.tar.gz")).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn test_probe_non_gzip_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("not_gz.txt");
        std::fs::write(&path, b"not gzip").expect("write");
        assert_eq!(probe_uac(&path).expect("probe"), Confidence::None);
    }

    #[test]
    fn test_probe_uac_with_log() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = create_uac_tar_gz(dir.path(), true);
        assert_eq!(probe_uac(&path).expect("probe"), Confidence::High);
    }

    #[test]
    fn test_probe_uac_without_log() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = create_uac_tar_gz(dir.path(), false);
        assert_eq!(
            probe_uac(&path).expect("probe"),
            Confidence::Medium,
            "Has UAC dirs but no uac.log"
        );
    }
}
```

- [ ] **Step 3: Implement extract.rs**

Create `crates/parsers/rt-parser-uac/src/extract.rs`:

```rust
use std::io::Read;
use std::path::{Path, PathBuf};

use rt_core::error::RtError;
use rt_unpack::{CollectionMetadata, ManifestEntry, OsType};
use tracing::info;

/// Extract a UAC tar.gz to the destination directory.
///
/// Preserves the UAC directory structure. Returns manifest entries
/// and metadata extracted from uac.log.
pub fn extract_uac(
    tar_gz_path: &Path,
    dest: &Path,
) -> Result<(Vec<ManifestEntry>, CollectionMetadata), RtError> {
    let file = std::fs::File::open(tar_gz_path)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    let mut entries = Vec::new();
    let mut uac_log_content = String::new();
    let mut root_prefix: Option<String> = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.to_string_lossy().to_string();

        // Detect the root prefix (e.g., "uac-vbox-linux-20260324193807/")
        if root_prefix.is_none() {
            if let Some(idx) = entry_path.find('/') {
                root_prefix = Some(entry_path[..=idx].to_string());
            }
        }

        // Strip root prefix for relative paths
        let rel_path = if let Some(ref prefix) = root_prefix {
            entry_path.strip_prefix(prefix).unwrap_or(&entry_path)
        } else {
            &entry_path
        };

        if rel_path.is_empty() {
            continue;
        }

        let full_path = dest.join(rel_path);

        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&full_path)?;
            continue;
        }

        // Create parent directories
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Read and write file contents
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(RtError::Io)?;
        std::fs::write(&full_path, &buf)?;

        // Capture uac.log for metadata extraction
        if rel_path == "uac.log" {
            uac_log_content = String::from_utf8_lossy(&buf).to_string();
        }

        entries.push(ManifestEntry {
            path: PathBuf::from(rel_path),
            artifact_type: None, // UAC parsers handle classification
        });
    }

    let metadata = parse_uac_metadata(&uac_log_content, tar_gz_path);

    info!(
        files = entries.len(),
        hostname = ?metadata.hostname,
        "Extracted UAC collection"
    );

    Ok((entries, metadata))
}

/// Parse UAC metadata from the uac.log content and the archive filename.
fn parse_uac_metadata(uac_log: &str, archive_path: &Path) -> CollectionMetadata {
    let hostname = extract_hostname_from_filename(archive_path);

    let collection_time = uac_log
        .lines()
        .next()
        .and_then(|line| {
            // Pattern: [YYYY-MM-DD HH:MM:SS] ...
            let ts_str = line.trim_start_matches('[').split(']').next()?;
            chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|dt| dt.and_utc())
        });

    let os_type = if uac_log.contains("Linux") || uac_log.contains("linux") {
        OsType::Linux
    } else if uac_log.contains("Darwin") || uac_log.contains("macOS") {
        OsType::MacOS
    } else {
        OsType::Unknown
    };

    CollectionMetadata {
        hostname,
        collection_time,
        os_type,
        tool_version: Some("UAC".into()),
    }
}

/// Extract hostname from UAC filename pattern: `uac-<hostname>-<timestamp>.tar.gz`
fn extract_hostname_from_filename(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    // Strip .tar from .tar.gz
    let stem = stem.strip_suffix(".tar").unwrap_or(stem);

    if let Some(rest) = stem.strip_prefix("uac-") {
        // Find the timestamp portion at the end (YYYYMMDDHHMMSS)
        if let Some(idx) = rest.rfind('-') {
            let candidate = &rest[idx + 1..];
            // Verify it looks like a timestamp (all digits, 14 chars)
            if candidate.len() == 14 && candidate.chars().all(|c| c.is_ascii_digit()) {
                return Some(rest[..idx].to_string());
            }
        }
        Some(rest.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hostname_from_filename() {
        assert_eq!(
            extract_hostname_from_filename(Path::new("uac-vbox-linux-20260324193807.tar.gz")),
            Some("vbox-linux".into())
        );
    }

    #[test]
    fn test_extract_hostname_non_uac() {
        assert_eq!(
            extract_hostname_from_filename(Path::new("random-archive.tar.gz")),
            None
        );
    }

    #[test]
    fn test_parse_uac_metadata_linux() {
        let log = "[2026-03-24 19:38:07] UAC 2.9.0 started on Linux";
        let meta = parse_uac_metadata(log, Path::new("uac-host-20260324193807.tar.gz"));
        assert_eq!(meta.hostname.as_deref(), Some("host"));
        assert!(meta.collection_time.is_some());
        assert_eq!(meta.os_type, OsType::Linux);
    }

    #[test]
    fn test_parse_uac_metadata_empty_log() {
        let meta = parse_uac_metadata("", Path::new("archive.tar.gz"));
        assert!(meta.hostname.is_none());
        assert!(meta.collection_time.is_none());
    }

    #[test]
    fn test_extract_uac_synthetic() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let tar_gz_path = dir.path().join("uac-testhost-20260101000000.tar.gz");
        let dest = dir.path().join("extracted");
        std::fs::create_dir_all(&dest).expect("mkdir");

        // Build a synthetic UAC tar.gz
        let file = std::fs::File::create(&tar_gz_path).expect("create");
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar = tar::Builder::new(gz);

        let log_data = b"[2026-01-01 00:00:00] UAC 2.9.0 started on Linux";
        let mut header = tar::Header::new_gnu();
        header.set_size(log_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "uac-testhost-20260101000000/uac.log", &log_data[..]).expect("log");

        let bf_data = b"0|/bin/ls|1234|100755|0|0|100|1711111111|1711111112|1711111113|0";
        let mut header = tar::Header::new_gnu();
        header.set_size(bf_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "uac-testhost-20260101000000/bodyfile/bodyfile.txt", &bf_data[..]).expect("bf");

        let gz = tar.into_inner().expect("tar");
        gz.finish().expect("gz");

        let (entries, meta) = extract_uac(&tar_gz_path, &dest).expect("extract");

        assert_eq!(entries.len(), 2); // uac.log + bodyfile.txt
        assert_eq!(meta.hostname.as_deref(), Some("testhost"));
        assert_eq!(meta.os_type, OsType::Linux);
        assert!(dest.join("uac.log").exists());
        assert!(dest.join("bodyfile/bodyfile.txt").exists());
    }
}
```

- [ ] **Step 4: Wire up UacProvider in lib.rs**

Create `crates/parsers/rt-parser-uac/src/lib.rs`:

```rust
pub mod extract;
pub mod parsers;
pub mod probe;

use std::path::Path;

use rt_core::error::RtError;
use rt_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// UAC (Unix Artifact Collector) collection format handler.
///
/// Recognizes `.tar.gz` files containing `uac.log` and standard UAC directories.
pub struct UacProvider;

impl CollectionProvider for UacProvider {
    fn name(&self) -> &str {
        "UAC"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        probe::probe_uac(path)
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        let tempdir = rt_unpack::tempdir::create_extraction_dir()?;
        let (entries, metadata) = extract::extract_uac(path, tempdir.path())?;
        Ok(CollectionManifest::new(
            "UAC".into(),
            tempdir,
            entries,
            metadata,
        ))
    }
}

inventory::submit!(rt_unpack::registry::ProviderRegistration {
    create: || Box::new(UacProvider),
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uac_provider_name() {
        assert_eq!(UacProvider.name(), "UAC");
    }
}
```

Create stub `crates/parsers/rt-parser-uac/src/parsers/mod.rs`:

```rust
pub mod bodyfile;
pub mod chkrootkit;
pub mod configs;
pub mod hardware;
pub mod hash_execs;
pub mod network;
pub mod packages;
pub mod process;
pub mod storage;
pub mod system;
```

Create empty stub files for each sub-parser module so compilation succeeds:

For each of `bodyfile.rs`, `chkrootkit.rs`, `configs.rs`, `hardware.rs`, `hash_execs.rs`, `network.rs`, `packages.rs`, `process.rs`, `storage.rs`, `system.rs` in `crates/parsers/rt-parser-uac/src/parsers/`:

```rust
// Sub-parser — implemented in subsequent tasks.
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p rt-parser-uac 2>&1 | tail -10
```

Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/parsers/rt-parser-uac Cargo.toml && git commit -m "feat(rt-parser-uac): scaffold, probe, extract, and UacProvider"
```

---

### Task 7: rt-parser-uac — bodyfile parser

The bodyfile (mactime) parser is the most forensically valuable UAC artifact — it provides a full filesystem timeline.

**Files:**
- Modify: `crates/parsers/rt-parser-uac/src/parsers/bodyfile.rs`

- [ ] **Step 1: Write failing tests**

Replace `crates/parsers/rt-parser-uac/src/parsers/bodyfile.rs`:

```rust
use serde::Serialize;

/// A parsed entry from a mactime bodyfile.
///
/// Format: `md5|path|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`
#[derive(Debug, Clone, Serialize)]
pub struct BodyfileEntry {
    pub md5: String,
    pub path: String,
    pub inode: u64,
    pub mode: String,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Option<i64>,
    pub mtime: Option<i64>,
    pub ctime: Option<i64>,
    pub crtime: Option<i64>,
}

/// Parse a single bodyfile line into a `BodyfileEntry`.
///
/// Returns `None` if the line is malformed or a comment/header.
pub fn parse_bodyfile_line(line: &str) -> Option<BodyfileEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let fields: Vec<&str> = line.splitn(11, '|').collect();
    if fields.len() < 11 {
        return None;
    }

    let parse_ts = |s: &str| -> Option<i64> {
        let n: i64 = s.trim().parse().ok()?;
        if n == 0 { None } else { Some(n) }
    };

    Some(BodyfileEntry {
        md5: fields[0].to_string(),
        path: fields[1].to_string(),
        inode: fields[2].parse().unwrap_or(0),
        mode: fields[3].to_string(),
        uid: fields[4].parse().unwrap_or(0),
        gid: fields[5].parse().unwrap_or(0),
        size: fields[6].parse().unwrap_or(0),
        atime: parse_ts(fields[7]),
        mtime: parse_ts(fields[8]),
        ctime: parse_ts(fields[9]),
        crtime: parse_ts(fields[10]),
    })
}

/// Parse an entire bodyfile (file contents as string).
pub fn parse_bodyfile(content: &str) -> Vec<BodyfileEntry> {
    content.lines().filter_map(parse_bodyfile_line).collect()
}

/// Parse a bodyfile from a file path.
pub fn parse_bodyfile_path(path: &std::path::Path) -> Result<Vec<BodyfileEntry>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_bodyfile(&content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bodyfile_line_valid() {
        let line = "d41d8cd98f00b204e9800998ecf8427e|/bin/ls|1234|100755|0|0|12345|1711111111|1711111112|1711111113|0";
        let entry = parse_bodyfile_line(line).expect("should parse");
        assert_eq!(entry.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(entry.path, "/bin/ls");
        assert_eq!(entry.inode, 1234);
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.size, 12345);
        assert_eq!(entry.atime, Some(1_711_111_111));
        assert_eq!(entry.mtime, Some(1_711_111_112));
        assert_eq!(entry.ctime, Some(1_711_111_113));
        assert_eq!(entry.crtime, None); // 0 → None
    }

    #[test]
    fn test_parse_bodyfile_line_comment() {
        assert!(parse_bodyfile_line("# header comment").is_none());
    }

    #[test]
    fn test_parse_bodyfile_line_empty() {
        assert!(parse_bodyfile_line("").is_none());
        assert!(parse_bodyfile_line("   ").is_none());
    }

    #[test]
    fn test_parse_bodyfile_line_too_few_fields() {
        assert!(parse_bodyfile_line("a|b|c").is_none());
    }

    #[test]
    fn test_parse_bodyfile_multiple_lines() {
        let content = "0|/bin/ls|1|100755|0|0|100|1000|2000|3000|0\n\
                        # comment\n\
                        0|/bin/cat|2|100755|0|0|200|4000|5000|6000|0\n\
                        \n";
        let entries = parse_bodyfile(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/bin/ls");
        assert_eq!(entries[1].path, "/bin/cat");
    }

    #[test]
    fn test_parse_bodyfile_zero_timestamps() {
        let line = "0|/tmp/file|0|100644|1000|1000|0|0|0|0|0";
        let entry = parse_bodyfile_line(line).expect("parse");
        assert!(entry.atime.is_none(), "0 timestamp should be None");
        assert!(entry.mtime.is_none());
    }

    #[test]
    fn test_parse_bodyfile_path_with_pipes() {
        // Bodyfile paths can contain spaces and special chars
        let line = "0|/home/user/my file (copy)|99|100644|1000|1000|50|1000|2000|3000|0";
        let entry = parse_bodyfile_line(line).expect("parse");
        assert_eq!(entry.path, "/home/user/my file (copy)");
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p rt-parser-uac -- bodyfile 2>&1 | tail -10
```

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/parsers/rt-parser-uac/src/parsers/bodyfile.rs && git commit -m "feat(rt-parser-uac): bodyfile (mactime) parser"
```

---

### Task 8: rt-parser-uac — network parser

Parse netstat/ss output from UAC live_response/network/.

**Files:**
- Modify: `crates/parsers/rt-parser-uac/src/parsers/network.rs`

- [ ] **Step 1: Implement and test**

Replace `crates/parsers/rt-parser-uac/src/parsers/network.rs`:

```rust
use serde::Serialize;

/// A parsed network connection from netstat or ss output.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<u32>,
    pub program: Option<String>,
}

/// Parse ss (socket statistics) output.
///
/// Expected format (header + data lines):
/// `State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process`
pub fn parse_ss_output(content: &str) -> Vec<NetworkConnection> {
    let mut results = Vec::new();

    for line in content.lines().skip(1) {
        // Skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }

        let state = fields[0].to_string();
        let local_addr = fields[3].to_string();
        let remote_addr = fields[4].to_string();

        // Try to extract PID/program from remaining fields
        let (pid, program) = if fields.len() > 5 {
            parse_pid_program(&fields[5..].join(" "))
        } else {
            (None, None)
        };

        results.push(NetworkConnection {
            protocol: String::new(), // ss doesn't always show protocol in basic output
            local_addr,
            remote_addr,
            state,
            pid,
            program,
        });
    }

    results
}

/// Parse netstat output.
///
/// Expected format:
/// `Proto Recv-Q Send-Q Local Address  Foreign Address  State  PID/Program`
pub fn parse_netstat_output(content: &str) -> Vec<NetworkConnection> {
    let mut results = Vec::new();

    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }

        // Skip header lines
        let proto = fields[0].to_lowercase();
        if !proto.starts_with("tcp") && !proto.starts_with("udp") {
            continue;
        }

        let local_addr = fields[3].to_string();
        let remote_addr = fields[4].to_string();
        let state = if fields.len() > 5 && !fields[5].contains('/') {
            fields[5].to_string()
        } else {
            String::new()
        };

        let pid_field = fields.last().unwrap_or(&"");
        let (pid, program) = parse_pid_program(pid_field);

        results.push(NetworkConnection {
            protocol: proto,
            local_addr,
            remote_addr,
            state,
            pid,
            program,
        });
    }

    results
}

/// Parse PID/Program field (format: `1234/program` or `users:(("prog",pid=1234,...))`)
fn parse_pid_program(field: &str) -> (Option<u32>, Option<String>) {
    // netstat format: "1234/nginx"
    if let Some((pid_str, prog)) = field.split_once('/') {
        let pid = pid_str.trim().parse::<u32>().ok();
        let program = if prog.is_empty() { None } else { Some(prog.to_string()) };
        return (pid, program);
    }

    // ss format: users:(("nginx",pid=1234,fd=5))
    if field.contains("pid=") {
        let pid = field
            .split("pid=")
            .nth(1)
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|s| s.parse::<u32>().ok());
        let program = field
            .split("((\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(String::from);
        return (pid, program);
    }

    (None, None)
}

/// Parse all network-related files in a UAC network directory.
pub fn parse_network_dir(dir: &std::path::Path) -> Vec<NetworkConnection> {
    let mut all = Vec::new();

    // Try ss output files
    for name in &["ss.txt", "ss-tlnp.txt", "ss-anp.txt"] {
        let path = dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(parse_ss_output(&content));
        }
    }

    // Try netstat output files
    for name in &["netstat.txt", "netstat-tlnp.txt", "netstat-anp.txt"] {
        let path = dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(parse_netstat_output(&content));
        }
    }

    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss_output() {
        let content = "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n\
                        LISTEN  0       128     0.0.0.0:22         0.0.0.0:*          users:((\"sshd\",pid=1234,fd=3))\n\
                        ESTAB   0       0       10.0.0.1:22        10.0.0.2:54321\n";
        let conns = parse_ss_output(content);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].state, "LISTEN");
        assert_eq!(conns[0].local_addr, "0.0.0.0:22");
        assert_eq!(conns[0].pid, Some(1234));
        assert_eq!(conns[0].program.as_deref(), Some("sshd"));
        assert_eq!(conns[1].state, "ESTAB");
        assert!(conns[1].pid.is_none());
    }

    #[test]
    fn test_parse_netstat_output() {
        let content = "Active Internet connections\n\
                        Proto Recv-Q Send-Q Local Address     Foreign Address   State       PID/Program\n\
                        tcp   0      0      0.0.0.0:22        0.0.0.0:*         LISTEN      1234/sshd\n\
                        tcp   0      0      10.0.0.1:22       10.0.0.2:54321    ESTABLISHED -\n";
        let conns = parse_netstat_output(content);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].protocol, "tcp");
        assert_eq!(conns[0].pid, Some(1234));
        assert_eq!(conns[0].program.as_deref(), Some("sshd"));
    }

    #[test]
    fn test_parse_pid_program_netstat() {
        let (pid, prog) = parse_pid_program("1234/nginx");
        assert_eq!(pid, Some(1234));
        assert_eq!(prog.as_deref(), Some("nginx"));
    }

    #[test]
    fn test_parse_pid_program_ss() {
        let (pid, prog) = parse_pid_program("users:((\"sshd\",pid=1234,fd=3))");
        assert_eq!(pid, Some(1234));
        assert_eq!(prog.as_deref(), Some("sshd"));
    }

    #[test]
    fn test_parse_pid_program_dash() {
        let (pid, prog) = parse_pid_program("-");
        assert!(pid.is_none());
        assert!(prog.is_none());
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p rt-parser-uac -- network 2>&1 | tail -10
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add crates/parsers/rt-parser-uac/src/parsers/network.rs && git commit -m "feat(rt-parser-uac): network parser (ss/netstat)"
```

---

### Task 9: rt-parser-uac — process, system, and packages parsers

Three closely related parsers that parse standard Linux command output.

**Files:**
- Modify: `crates/parsers/rt-parser-uac/src/parsers/process.rs`
- Modify: `crates/parsers/rt-parser-uac/src/parsers/system.rs`
- Modify: `crates/parsers/rt-parser-uac/src/parsers/packages.rs`

- [ ] **Step 1: Implement process.rs**

Replace `crates/parsers/rt-parser-uac/src/parsers/process.rs`:

```rust
use serde::Serialize;

/// A parsed process from ps output.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub user: String,
    pub command: String,
    pub cpu_pct: Option<String>,
    pub mem_pct: Option<String>,
    pub start_time: Option<String>,
}

/// A parsed crontab entry.
#[derive(Debug, Clone, Serialize)]
pub struct CrontabEntry {
    pub schedule: String,
    pub command: String,
    pub user: String,
}

/// Parse `ps auxww` output.
pub fn parse_ps_output(content: &str) -> Vec<ProcessInfo> {
    let mut results = Vec::new();
    let mut lines = content.lines();

    // Skip header line
    let header = match lines.next() {
        Some(h) => h,
        None => return results,
    };

    // Detect column positions from header
    let has_start = header.contains("START") || header.contains("STARTED");

    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 11 {
            continue;
        }

        let user = fields[0].to_string();
        let pid = fields[1].parse::<u32>().unwrap_or(0);
        let cpu_pct = Some(fields[2].to_string());
        let mem_pct = Some(fields[3].to_string());
        let ppid = 0; // ps aux doesn't show ppid directly

        // Command is everything from field 10 onwards (it can contain spaces)
        let command = fields[10..].join(" ");

        let start_time = if has_start {
            Some(fields[8].to_string())
        } else {
            None
        };

        results.push(ProcessInfo {
            pid,
            ppid,
            user,
            command,
            cpu_pct,
            mem_pct,
            start_time,
        });
    }

    results
}

/// Parse crontab file content.
pub fn parse_crontab(content: &str, user: &str) -> Vec<CrontabEntry> {
    content
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            // First 5 fields are the schedule, rest is the command
            let schedule = fields[..5].join(" ");
            let command = fields[5..].join(" ");
            Some(CrontabEntry {
                schedule,
                command,
                user: user.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ps_output() {
        let content = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n\
                        root         1  0.0  0.1 169456 11784 ?        Ss   Mar24   0:03 /sbin/init\n\
                        root         2  0.0  0.0      0     0 ?        S    Mar24   0:00 [kthreadd]\n";
        let procs = parse_ps_output(content);
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 1);
        assert_eq!(procs[0].user, "root");
        assert_eq!(procs[0].command, "/sbin/init");
        assert_eq!(procs[0].start_time.as_deref(), Some("Mar24"));
    }

    #[test]
    fn test_parse_crontab() {
        let content = "# cron jobs\n\
                        */5 * * * * /usr/bin/check_health\n\
                        0 2 * * * /usr/bin/backup --full\n\
                        \n";
        let entries = parse_crontab(content, "root");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].schedule, "*/5 * * * *");
        assert_eq!(entries[0].command, "/usr/bin/check_health");
        assert_eq!(entries[0].user, "root");
    }

    #[test]
    fn test_parse_crontab_skips_comments() {
        let content = "# every hour\n\n";
        assert!(parse_crontab(content, "user").is_empty());
    }
}
```

- [ ] **Step 2: Implement system.rs**

Replace `crates/parsers/rt-parser-uac/src/parsers/system.rs`:

```rust
use serde::Serialize;

/// A parsed login record from `last` command output.
#[derive(Debug, Clone, Serialize)]
pub struct LoginRecord {
    pub user: String,
    pub terminal: String,
    pub source: String,
    pub login_time: Option<String>,
    pub logout_time: Option<String>,
    pub duration: Option<String>,
}

/// System information parsed from UAC system artifacts.
#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub hostname: Option<String>,
    pub uname: Option<String>,
    pub uptime: Option<String>,
}

/// Parse `last` command output.
///
/// Format: `user  tty  source  login_day login_time - logout_time  (duration)`
pub fn parse_last_output(content: &str) -> Vec<LoginRecord> {
    let mut results = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("wtmp begins")
            || trimmed.starts_with("btmp begins")
        {
            continue;
        }

        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let user = fields[0].to_string();
        let terminal = fields[1].to_string();

        // Determine if field 2 is a source IP or a day
        let (source, time_start_idx) = if fields.len() > 4
            && (fields[2].contains('.') || fields[2].contains(':') || fields[2] == "0.0.0.0")
        {
            (fields[2].to_string(), 3)
        } else {
            (String::new(), 2)
        };

        let login_time = if time_start_idx + 2 <= fields.len() {
            Some(fields[time_start_idx..time_start_idx + 2].join(" "))
        } else {
            None
        };

        // Look for "- <time>" pattern for logout
        let logout_time = fields.iter().position(|&f| f == "-").and_then(|i| {
            fields.get(i + 1).map(|s| s.to_string())
        });

        // Look for "(HH:MM)" duration
        let duration = fields.iter().find(|f| f.starts_with('(')).map(|f| {
            f.trim_start_matches('(').trim_end_matches(')').to_string()
        });

        results.push(LoginRecord {
            user,
            terminal,
            source,
            login_time,
            logout_time,
            duration,
        });
    }

    results
}

/// Parse system info from UAC system directory files.
pub fn parse_system_info(dir: &std::path::Path) -> SystemInfo {
    let hostname = std::fs::read_to_string(dir.join("hostname.txt"))
        .ok()
        .map(|s| s.trim().to_string());
    let uname = std::fs::read_to_string(dir.join("uname-a.txt"))
        .ok()
        .map(|s| s.trim().to_string());
    let uptime = std::fs::read_to_string(dir.join("uptime.txt"))
        .ok()
        .map(|s| s.trim().to_string());

    SystemInfo {
        hostname,
        uname,
        uptime,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_last_output() {
        let content = "root     pts/0        10.0.0.5         Mon Mar 24 19:38   still logged in\n\
                        admin    tty1                          Mon Mar 24 10:00 - 12:30  (02:30)\n\
                        \n\
                        wtmp begins Mon Mar 24 00:00:00 2026\n";
        let records = parse_last_output(content);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].user, "root");
        assert_eq!(records[0].terminal, "pts/0");
        assert_eq!(records[0].source, "10.0.0.5");
        assert_eq!(records[1].user, "admin");
    }

    #[test]
    fn test_parse_last_empty() {
        assert!(parse_last_output("").is_empty());
        assert!(parse_last_output("wtmp begins Mon Mar 24 00:00:00 2026\n").is_empty());
    }

    #[test]
    fn test_parse_system_info() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("hostname.txt"), "testhost\n").expect("write");
        std::fs::write(dir.path().join("uname-a.txt"), "Linux testhost 5.15.0\n").expect("write");

        let info = parse_system_info(dir.path());
        assert_eq!(info.hostname.as_deref(), Some("testhost"));
        assert!(info.uname.as_ref().unwrap().contains("Linux"));
        assert!(info.uptime.is_none()); // file doesn't exist
    }
}
```

- [ ] **Step 3: Implement packages.rs**

Replace `crates/parsers/rt-parser-uac/src/parsers/packages.rs`:

```rust
use serde::Serialize;

/// Package manager that produced this listing.
#[derive(Debug, Clone, Serialize)]
pub enum PackageManager {
    Dpkg,
    Rpm,
    Pip,
    Snap,
}

/// A parsed installed package entry.
#[derive(Debug, Clone, Serialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub manager: PackageManager,
}

/// Parse dpkg -l output.
///
/// Format: `ii  package-name  version  arch  description`
pub fn parse_dpkg_output(content: &str) -> Vec<InstalledPackage> {
    content
        .lines()
        .filter(|line| line.starts_with("ii"))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                return None;
            }
            Some(InstalledPackage {
                name: fields[1].to_string(),
                version: fields[2].to_string(),
                manager: PackageManager::Dpkg,
            })
        })
        .collect()
}

/// Parse all package files in a UAC packages directory.
pub fn parse_packages_dir(dir: &std::path::Path) -> Vec<InstalledPackage> {
    let mut all = Vec::new();

    for name in &["dpkg-l.txt", "dpkg.txt"] {
        let path = dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(parse_dpkg_output(&content));
        }
    }

    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dpkg_output() {
        let content = "Desired=Unknown/Install/Remove/Purge/Hold\n\
                        | Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n\
                        |/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n\
                        ||/ Name           Version      Architecture Description\n\
                        +++-==============-============-============-=================================\n\
                        ii  bash           5.1-6ubuntu1 amd64        GNU Bourne Again SHell\n\
                        ii  coreutils      8.32-4.1ubun amd64        GNU core utilities\n\
                        rc  old-package    1.0          amd64        removed package\n";
        let pkgs = parse_dpkg_output(content);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].version, "5.1-6ubuntu1");
        assert_eq!(pkgs[1].name, "coreutils");
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p rt-parser-uac -- process --test-threads=1 && cargo test -p rt-parser-uac -- system --test-threads=1 && cargo test -p rt-parser-uac -- packages --test-threads=1
```

Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add crates/parsers/rt-parser-uac/src/parsers/process.rs crates/parsers/rt-parser-uac/src/parsers/system.rs crates/parsers/rt-parser-uac/src/parsers/packages.rs && git commit -m "feat(rt-parser-uac): process, system, and packages parsers"
```

---

### Task 10: rt-parser-uac — remaining parsers

Hardware, storage, hash_execs, chkrootkit, and configs parsers. These are simpler parsers for less forensically-critical data.

**Files:**
- Modify: `crates/parsers/rt-parser-uac/src/parsers/hardware.rs`
- Modify: `crates/parsers/rt-parser-uac/src/parsers/storage.rs`
- Modify: `crates/parsers/rt-parser-uac/src/parsers/hash_execs.rs`
- Modify: `crates/parsers/rt-parser-uac/src/parsers/chkrootkit.rs`
- Modify: `crates/parsers/rt-parser-uac/src/parsers/configs.rs`

- [ ] **Step 1: Implement hash_execs.rs**

Replace `crates/parsers/rt-parser-uac/src/parsers/hash_execs.rs`:

```rust
use serde::Serialize;

/// A hashed executable from UAC hash_executables output.
#[derive(Debug, Clone, Serialize)]
pub struct HashedExecutable {
    pub hash: String,
    pub path: String,
    pub algorithm: String,
}

/// Parse a UAC hash file (one `hash  path` per line).
///
/// UAC typically produces md5sum/sha1sum/sha256sum output format.
pub fn parse_hash_file(content: &str, algorithm: &str) -> Vec<HashedExecutable> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            // Format: "hash  path" or "hash *path"
            let (hash, path) = line.split_once(|c: char| c.is_whitespace())?;
            let path = path.trim().trim_start_matches('*');
            if hash.is_empty() || path.is_empty() {
                return None;
            }
            Some(HashedExecutable {
                hash: hash.to_string(),
                path: path.to_string(),
                algorithm: algorithm.to_string(),
            })
        })
        .collect()
}

/// Parse all hash files in a UAC hash_executables directory.
pub fn parse_hash_dir(dir: &std::path::Path) -> Vec<HashedExecutable> {
    let mut all = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let algo = if name.contains("md5") {
                "md5"
            } else if name.contains("sha256") {
                "sha256"
            } else if name.contains("sha1") {
                "sha1"
            } else {
                "unknown"
            };
            if let Ok(content) = std::fs::read_to_string(&path) {
                all.extend(parse_hash_file(&content, algo));
            }
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash_file() {
        let content = "d41d8cd98f00b204e9800998ecf8427e  /usr/bin/ls\n\
                        abc123  /usr/bin/cat\n";
        let hashes = parse_hash_file(content, "md5");
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].hash, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hashes[0].path, "/usr/bin/ls");
        assert_eq!(hashes[0].algorithm, "md5");
    }

    #[test]
    fn test_parse_hash_file_star_prefix() {
        let content = "abc123 */usr/bin/ls\n";
        let hashes = parse_hash_file(content, "sha256");
        assert_eq!(hashes[0].path, "/usr/bin/ls");
    }
}
```

- [ ] **Step 2: Implement hardware.rs**

Replace `crates/parsers/rt-parser-uac/src/parsers/hardware.rs`:

```rust
use serde::Serialize;

/// Hardware information parsed from UAC hardware artifacts.
#[derive(Debug, Clone, Serialize)]
pub struct HardwareInfo {
    pub source: String,
    pub content: String,
}

/// Parse all hardware files in a UAC hardware directory.
///
/// Hardware files (dmesg, lspci, lsusb, dmidecode) are stored as-is
/// since their formats are too varied for structured parsing.
pub fn parse_hardware_dir(dir: &std::path::Path) -> Vec<HardwareInfo> {
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let source = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                if let Ok(content) = std::fs::read_to_string(&path) {
                    results.push(HardwareInfo { source, content });
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hardware_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("dmesg.txt"), "kernel boot log").expect("write");
        std::fs::write(dir.path().join("lspci.txt"), "00:00.0 Host bridge").expect("write");

        let info = parse_hardware_dir(dir.path());
        assert_eq!(info.len(), 2);
    }
}
```

- [ ] **Step 3: Implement storage.rs**

Replace `crates/parsers/rt-parser-uac/src/parsers/storage.rs`:

```rust
use serde::Serialize;

/// A parsed mount point from df or mount output.
#[derive(Debug, Clone, Serialize)]
pub struct MountInfo {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub options: String,
}

/// Parse `mount` command output.
pub fn parse_mount_output(content: &str) -> Vec<MountInfo> {
    content
        .lines()
        .filter_map(|line| {
            // Format: device on mount_point type fstype (options)
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if parts.len() < 5 || parts[1] != "on" || parts[3] != "type" {
                return None;
            }
            let options = parts.get(5).map_or(String::new(), |o| {
                o.trim_start_matches('(').trim_end_matches(')').to_string()
            });
            Some(MountInfo {
                device: parts[0].to_string(),
                mount_point: parts[2].to_string(),
                fs_type: parts[4].to_string(),
                options,
            })
        })
        .collect()
}

/// Parse all storage files in a UAC storage directory.
pub fn parse_storage_dir(dir: &std::path::Path) -> Vec<MountInfo> {
    let mut all = Vec::new();
    for name in &["mount.txt", "mounts.txt"] {
        let path = dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(parse_mount_output(&content));
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mount_output() {
        let content = "/dev/sda1 on / type ext4 (rw,relatime)\n\
                        tmpfs on /tmp type tmpfs (rw,nosuid)\n";
        let mounts = parse_mount_output(content);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].device, "/dev/sda1");
        assert_eq!(mounts[0].mount_point, "/");
        assert_eq!(mounts[0].fs_type, "ext4");
    }
}
```

- [ ] **Step 4: Implement chkrootkit.rs**

Replace `crates/parsers/rt-parser-uac/src/parsers/chkrootkit.rs`:

```rust
use serde::Serialize;

/// A finding from chkrootkit scan.
#[derive(Debug, Clone, Serialize)]
pub struct ChkrootkitFinding {
    pub check_name: String,
    pub result: String,
    pub is_infected: bool,
}

/// Parse chkrootkit log output.
pub fn parse_chkrootkit_log(content: &str) -> Vec<ChkrootkitFinding> {
    content
        .lines()
        .filter(|line| line.contains("INFECTED") || line.contains("not infected") || line.contains("not found"))
        .map(|line| {
            let is_infected = line.contains("INFECTED") && !line.contains("not infected");
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            ChkrootkitFinding {
                check_name: parts.first().unwrap_or(&"").trim().to_string(),
                result: parts.get(1).unwrap_or(&"").trim().to_string(),
                is_infected,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chkrootkit_clean() {
        let content = "Checking `amd'... not found\n\
                        Checking `basename'... not infected\n";
        let findings = parse_chkrootkit_log(content);
        assert_eq!(findings.len(), 2);
        assert!(!findings[0].is_infected);
        assert!(!findings[1].is_infected);
    }

    #[test]
    fn test_parse_chkrootkit_infected() {
        let content = "Checking `bindshell'... INFECTED\n";
        let findings = parse_chkrootkit_log(content);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].is_infected);
    }
}
```

- [ ] **Step 5: Implement configs.rs**

Replace `crates/parsers/rt-parser-uac/src/parsers/configs.rs`:

```rust
use serde::Serialize;

/// A system configuration file captured by UAC.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigFile {
    pub path: String,
    pub content: String,
}

/// Collect all config files from a UAC system directory.
///
/// These are stored as-is for analyst review — the forensic value
/// is in having the configuration snapshot, not in parsing each format.
pub fn collect_configs(dir: &std::path::Path) -> Vec<ConfigFile> {
    let mut results = Vec::new();
    collect_recursive(dir, dir, &mut results);
    results
}

fn collect_recursive(
    base: &std::path::Path,
    current: &std::path::Path,
    results: &mut Vec<ConfigFile>,
) {
    if let Ok(entries) = std::fs::read_dir(current) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_recursive(base, &path, results);
            } else if path.is_file() {
                let rel = path.strip_prefix(base).unwrap_or(&path);
                if let Ok(content) = std::fs::read_to_string(&path) {
                    results.push(ConfigFile {
                        path: rel.to_string_lossy().to_string(),
                        content,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_configs() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("mkdir");
        std::fs::write(etc.join("passwd"), "root:x:0:0::/root:/bin/bash\n").expect("write");
        std::fs::write(etc.join("hostname"), "testhost\n").expect("write");

        let configs = collect_configs(dir.path());
        assert_eq!(configs.len(), 2);
    }
}
```

- [ ] **Step 6: Run all tests**

```bash
cargo test -p rt-parser-uac 2>&1 | tail -10
```

Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/parsers/rt-parser-uac/src/parsers/ && git commit -m "feat(rt-parser-uac): hardware, storage, hash_execs, chkrootkit, and configs parsers"
```

---

### Task 11: rt-parser-uac — category dispatcher (parsers/mod.rs)

Wire all sub-parsers together with a top-level dispatch function.

**Files:**
- Modify: `crates/parsers/rt-parser-uac/src/parsers/mod.rs`

- [ ] **Step 1: Implement the dispatcher**

Replace `crates/parsers/rt-parser-uac/src/parsers/mod.rs`:

```rust
pub mod bodyfile;
pub mod chkrootkit;
pub mod configs;
pub mod hardware;
pub mod hash_execs;
pub mod network;
pub mod packages;
pub mod process;
pub mod storage;
pub mod system;

use std::path::Path;

use serde::Serialize;
use tracing::info;

/// Aggregated results from parsing all UAC categories.
#[derive(Debug, Default, Serialize)]
pub struct UacParseResult {
    pub bodyfile_entries: usize,
    pub network_connections: usize,
    pub processes: usize,
    pub packages: usize,
    pub login_records: usize,
    pub hashed_executables: usize,
    pub chkrootkit_findings: usize,
    pub config_files: usize,
    pub crontab_entries: usize,
}

/// Parse all UAC categories from an extracted collection directory.
///
/// The `extracted_root` should contain the UAC directory structure
/// (bodyfile/, live_response/, system/, etc.).
pub fn parse_all_categories(extracted_root: &Path) -> UacParseResult {
    let mut result = UacParseResult::default();

    // Bodyfile
    let bf_path = extracted_root.join("bodyfile/bodyfile.txt");
    if bf_path.exists() {
        if let Ok(entries) = bodyfile::parse_bodyfile_path(&bf_path) {
            result.bodyfile_entries = entries.len();
            info!(entries = entries.len(), "Parsed bodyfile");
        }
    }

    // Network
    let net_dir = extracted_root.join("live_response/network");
    if net_dir.is_dir() {
        let conns = network::parse_network_dir(&net_dir);
        result.network_connections = conns.len();
        info!(connections = conns.len(), "Parsed network state");
    }

    // Process
    for name in &["ps_auxwww.txt", "ps-auxwww.txt", "ps.txt"] {
        let path = extracted_root.join("live_response/process").join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let procs = process::parse_ps_output(&content);
            result.processes += procs.len();
        }
    }

    // Crontab
    let crontab_dir = extracted_root.join("live_response/process");
    for name in &["crontab.txt", "crontab-l.txt"] {
        let path = crontab_dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let entries = process::parse_crontab(&content, "root");
            result.crontab_entries += entries.len();
        }
    }

    // Packages
    let pkg_dir = extracted_root.join("live_response/packages");
    if pkg_dir.is_dir() {
        let pkgs = packages::parse_packages_dir(&pkg_dir);
        result.packages = pkgs.len();
    }

    // System (login history)
    for name in &["last.txt", "last-a.txt"] {
        let path = extracted_root.join("live_response/system").join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let records = system::parse_last_output(&content);
            result.login_records += records.len();
        }
    }

    // Hash executables
    let hash_dir = extracted_root.join("hash_executables");
    if hash_dir.is_dir() {
        let hashes = hash_execs::parse_hash_dir(&hash_dir);
        result.hashed_executables = hashes.len();
    }

    // Chkrootkit
    let chk_path = extracted_root.join("chkrootkit/chkrootkit.log");
    if let Ok(content) = std::fs::read_to_string(&chk_path) {
        let findings = chkrootkit::parse_chkrootkit_log(&content);
        result.chkrootkit_findings = findings.len();
    }

    // Configs
    let sys_dir = extracted_root.join("system");
    if sys_dir.is_dir() {
        let configs = configs::collect_configs(&sys_dir);
        result.config_files = configs.len();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_all_categories_empty_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let result = parse_all_categories(dir.path());
        assert_eq!(result.bodyfile_entries, 0);
        assert_eq!(result.network_connections, 0);
    }

    #[test]
    fn test_parse_all_categories_with_bodyfile() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let bf_dir = dir.path().join("bodyfile");
        std::fs::create_dir_all(&bf_dir).expect("mkdir");
        std::fs::write(
            bf_dir.join("bodyfile.txt"),
            "0|/bin/ls|1|100755|0|0|100|1000|2000|3000|0\n\
             0|/bin/cat|2|100755|0|0|200|4000|5000|6000|0\n",
        )
        .expect("write");

        let result = parse_all_categories(dir.path());
        assert_eq!(result.bodyfile_entries, 2);
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p rt-parser-uac 2>&1 | tail -10
```

Expected: All PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/parsers/rt-parser-uac/src/parsers/mod.rs && git commit -m "feat(rt-parser-uac): category dispatcher wiring all sub-parsers"
```

---

### Task 12: rt-fswalker — collection pipeline integration

Add `run_collection_pipeline()` to the orchestrator and make the existing `run_pipeline` transparently handle both files and directories.

**Files:**
- Modify: `crates/rt-fswalker/Cargo.toml`
- Modify: `crates/rt-fswalker/src/orchestrator.rs`

- [ ] **Step 1: Add rt-unpack dependency**

In `crates/rt-fswalker/Cargo.toml`, add:

```toml
rt-unpack = { workspace = true }
```

- [ ] **Step 2: Write failing test**

Add to the bottom of `crates/rt-fswalker/src/orchestrator.rs`, inside the existing `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn test_run_collection_pipeline_unsupported_format() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("random.bin");
        std::fs::write(&path, b"not a collection").expect("write");

        let progress = ProgressReporter::new();
        let result = run_collection_pipeline(&path, &progress);
        assert!(result.is_err(), "Unknown format should error");
    }
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cargo test -p rt-fswalker -- test_run_collection_pipeline 2>&1 | tail -5
```

Expected: FAIL — `run_collection_pipeline` doesn't exist yet.

- [ ] **Step 4: Implement run_collection_pipeline**

Add to `crates/rt-fswalker/src/orchestrator.rs`, after `run_pipeline`:

```rust
/// Run the pipeline on a collection archive.
///
/// Uses `rt-unpack` to detect format, extract to temp dir, then runs the
/// normal filesystem-walking pipeline on the extracted contents.
pub fn run_collection_pipeline(
    collection_path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    let manifest = rt_unpack::registry::open_collection(collection_path)
        .map_err(|e| RtError::UnsupportedFormat(e.to_string()))?;

    tracing::info!(
        format = %manifest.format_name,
        artifacts = manifest.artifacts.len(),
        root = %manifest.extracted_root.display(),
        "Collection opened, running pipeline"
    );

    run_pipeline(&manifest.extracted_root, progress)
}

/// Run the pipeline, auto-detecting whether the input is a directory or collection archive.
///
/// - If `path` is a directory, walks it directly.
/// - If `path` is a file, tries to open it as a collection archive first.
pub fn run_auto(
    path: &Path,
    progress: &ProgressReporter,
) -> Result<(Vec<TimelineEvent>, IngestResult), RtError> {
    if path.is_dir() {
        run_pipeline(path, progress)
    } else {
        run_collection_pipeline(path, progress)
    }
}
```

Add `use crate::progress::ProgressReporter;` to the imports if not already present (it's used in run_pipeline already via the function parameter but check).

- [ ] **Step 5: Run tests**

```bash
cargo test -p rt-fswalker 2>&1 | tail -10
```

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/rt-fswalker && git commit -m "feat(rt-fswalker): add run_collection_pipeline and run_auto"
```

---

### Task 13: rt-cli — wire collection support

Update the CLI to use the new `run_auto` function and link the new parser crates.

**Files:**
- Modify: `crates/rt-cli/Cargo.toml`
- Modify: `crates/rt-cli/src/main.rs`
- Modify: `crates/rt-cli/src/commands/ingest.rs`

- [ ] **Step 1: Add dependencies to rt-cli**

In `crates/rt-cli/Cargo.toml`, add to `[dependencies]`:

```toml
rt-parser-velociraptor = { workspace = true }
rt-parser-uac = { workspace = true }
rt-unpack = { workspace = true }
```

- [ ] **Step 2: Add extern crate declarations**

In `crates/rt-cli/src/main.rs`, add after the existing `extern crate` lines:

```rust
extern crate rt_parser_velociraptor;
extern crate rt_parser_uac;
```

- [ ] **Step 3: Update ingest command to use run_auto**

In `crates/rt-cli/src/commands/ingest.rs`, change the import:

```rust
use rt_fswalker::orchestrator::run_auto;
use rt_fswalker::progress::ProgressReporter;
```

Then change the `run_pipeline` call to `run_auto`:

```rust
    let (events, result) =
        run_auto(evidence_path, &progress).context("Pipeline execution failed")?;
```

- [ ] **Step 4: Run all workspace tests**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: All tests PASS.

- [ ] **Step 5: Run clippy**

```bash
cargo clippy --workspace -- -D warnings 2>&1 | tail -10
```

Expected: Clean (or only pre-existing warnings from other crates).

- [ ] **Step 6: Commit**

```bash
git add crates/rt-cli Cargo.toml && git commit -m "feat(rt-cli): wire collection format support into ingest command"
```

---

### Task 14: Integration tests with real test data

End-to-end tests using the actual UAC and Velociraptor test data files.

**Files:**
- Create: `crates/parsers/rt-parser-velociraptor/tests/integration_test.rs`
- Create: `crates/parsers/rt-parser-uac/tests/integration_test.rs`

- [ ] **Step 1: Velociraptor integration test**

Create `crates/parsers/rt-parser-velociraptor/tests/integration_test.rs`:

```rust
use std::path::Path;

use rt_unpack::{CollectionProvider, Confidence};

#[test]
fn test_probe_real_velociraptor_collection() {
    let path = Path::new("../../tests/data/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = rt_parser_velociraptor::VelociraptorProvider;
    let confidence = provider.probe(path).expect("probe should succeed");
    assert_eq!(confidence, Confidence::High, "Should detect Velociraptor zip");
}

#[test]
fn test_open_real_velociraptor_collection() {
    let path = Path::new("../../tests/data/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = rt_parser_velociraptor::VelociraptorProvider;
    let manifest = provider.open(path).expect("open should succeed");

    assert_eq!(manifest.format_name, "Velociraptor");
    assert_eq!(manifest.metadata.hostname.as_deref(), Some("A380_localdomain"));
    assert!(!manifest.artifacts.is_empty(), "Should discover artifacts");

    // Check that key artifacts were found
    let has_mft = manifest.artifacts.iter().any(|e| {
        e.artifact_type == Some(rt_core::artifacts::ArtifactType::Mft)
    });
    let has_evtx = manifest.artifacts.iter().any(|e| {
        e.artifact_type == Some(rt_core::artifacts::ArtifactType::EventLog)
    });

    assert!(has_mft, "Should find $MFT");
    assert!(has_evtx, "Should find event logs");

    // Verify files were actually extracted
    assert!(manifest.extracted_root.exists());
}
```

- [ ] **Step 2: UAC integration test**

Create `crates/parsers/rt-parser-uac/tests/integration_test.rs`:

```rust
use std::path::Path;

use rt_unpack::{CollectionProvider, Confidence};

#[test]
fn test_probe_real_uac_collection() {
    let path = Path::new("../../tests/data/uac-vbox-linux-20260324193807.tar.gz");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = rt_parser_uac::UacProvider;
    let confidence = provider.probe(path).expect("probe should succeed");
    assert_eq!(confidence, Confidence::High, "Should detect UAC tar.gz");
}

#[test]
fn test_open_real_uac_collection() {
    let path = Path::new("../../tests/data/uac-vbox-linux-20260324193807.tar.gz");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = rt_parser_uac::UacProvider;
    let manifest = provider.open(path).expect("open should succeed");

    assert_eq!(manifest.format_name, "UAC");
    assert_eq!(manifest.metadata.hostname.as_deref(), Some("vbox-linux"));
    assert_eq!(manifest.metadata.os_type, rt_unpack::OsType::Linux);
    assert!(!manifest.artifacts.is_empty(), "Should discover artifacts");

    // Verify extracted files exist
    assert!(manifest.extracted_root.join("bodyfile/bodyfile.txt").exists());
    assert!(manifest.extracted_root.join("uac.log").exists());
}

#[test]
fn test_parse_real_uac_categories() {
    let path = Path::new("../../tests/data/uac-vbox-linux-20260324193807.tar.gz");
    if !path.exists() {
        eprintln!("Skipping: test data not found at {}", path.display());
        return;
    }

    let provider = rt_parser_uac::UacProvider;
    let manifest = provider.open(path).expect("open should succeed");

    // Parse all categories
    let result = rt_parser_uac::parsers::parse_all_categories(&manifest.extracted_root);

    assert!(result.bodyfile_entries > 0, "Should parse bodyfile entries");
    eprintln!("UAC parse results: bodyfile={}, network={}, processes={}, packages={}, logins={}, hashes={}, chkrootkit={}, configs={}",
        result.bodyfile_entries,
        result.network_connections,
        result.processes,
        result.packages,
        result.login_records,
        result.hashed_executables,
        result.chkrootkit_findings,
        result.config_files,
    );
}
```

- [ ] **Step 3: Run integration tests (if test data available)**

```bash
cargo test -p rt-parser-velociraptor --test integration_test 2>&1 | tail -10
cargo test -p rt-parser-uac --test integration_test 2>&1 | tail -10
```

Expected: PASS (or skip with message if test data not found).

- [ ] **Step 4: Run full workspace tests and clippy**

```bash
cargo test --workspace 2>&1 | tail -20
cargo clippy --workspace -- -D warnings 2>&1 | tail -10
cargo fmt --check 2>&1 | tail -5
```

Expected: All clean.

- [ ] **Step 5: Commit**

```bash
git add crates/parsers/rt-parser-velociraptor/tests crates/parsers/rt-parser-uac/tests && git commit -m "test: add integration tests for Velociraptor and UAC providers"
```

---

## Appendix: Workspace Dependency Additions

These are the new entries needed in the root `Cargo.toml` `[workspace.dependencies]` section, accumulated across all tasks:

```toml
# New internal crates
rt-unpack = { path = "crates/rt-unpack" }
rt-fswalker = { path = "crates/rt-fswalker" }  # replaces rt-pipeline
rt-parser-velociraptor = { path = "crates/parsers/rt-parser-velociraptor" }
rt-parser-uac = { path = "crates/parsers/rt-parser-uac" }

# New external deps
zip = "2"
percent-encoding = "2"
flate2 = "1"
tar = "0.4"
```

The old `rt-pipeline` line is removed.
