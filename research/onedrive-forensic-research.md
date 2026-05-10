# OneDrive Forensic Parsing — Comprehensive Research

**Date:** 2026-03-25
**Purpose:** Inform design of `~/src/onedrive-forensic` Rust crate

---

## 1. OneDriveExplorer Analysis (Reference Implementation)

**Author:** Brian Maloney (Beercow) | **Language:** Python (MIT) | **Stars:** 230+

### Architecture
- CLI (`OneDriveExplorer.py`) + GUI (`OneDriveExplorer_GUI.py`)
- Core: `ode/` package — `parsers/`, `helpers/`, `renderers/`, `views/`
- ODL parsing based on Yogesh Khatri's `odl.py`

### 12 Artifact Types Parsed
1. `<UserCid>.dat` — Proprietary binary with file/folder names + UUIDs (resource IDs)
2. `<UserCid>.dat.previous` — Previous version
3. `SyncEngineDatabase.db` — SQLite (schema v8–v40, replacing dat since v23.038+)
4. `SafeDelete.db` — Deletion tracking with process attribution
5. `Microsoft.ListSync.db` — Offline mode (Project Nucleus) — has dates NOT in SyncEngine
6. `Microsoft.FileUsageSync.db` — Business-only, sharing metadata, activity dates
7. `Microsoft.FilesOnDemand.db` — Offline editing availability (added v2025.11.07)
8. ODL logs (`.odl`, `.odlgz`, `.odlsent`, `.aold`) — Binary sync operation logs
9. `ObfuscationStringMap.txt` — Pre-April 2022 deobfuscation dictionary
10. `general.keystore` / `vault.keystore` — Post-April 2022 AES decryption keys
11. Registry hives — NTUSER.DAT for mount point resolution
12. `$Recycle.Bin` — Deleted file correlation

### Limitations
- Python-only (no native performance)
- No carving from unallocated space
- No SQLite WAL/freelist recovery
- No corrupted-file recovery
- No ETL trace parsing
- No streaming from forensic images
- Schema-dependent (breaks on new versions)

---

## 2. OneDrive File Formats

### A. SyncEngineDatabase.db (SQLite)
**Location:** `%LOCALAPPDATA%\Microsoft\OneDrive\settings\<Business1-9|Personal>\SyncEngineDatabase.db`
**Schema versions:** v8 through v40 (as of OneDrive v25.228.1120.0001)

Key tables:
- `od_ClientFile_Records` — File metadata with resourceID/parentResourceID tree
- `od_ClientFolder_Records` — Folder metadata
- `od_ScopeInfo_Records` — tenantID/siteID/webID/listID
- `od_GraphMetadata_Records` — createdBy/modifiedBy
- `od_HydrationData` — first/last hydration timestamps, count

### B. UserCid.dat (Legacy Binary)
**Location:** `%LOCALAPPDATA%\Microsoft\OneDrive\settings\<type>\<UserCid>.dat`
- Proprietary binary, walked sequentially
- Each entry: name, type (file/folder), UUID, parent UUID, metadata
- UUIDs = OneDrive resource IDs for tree reconstruction

### C. SafeDelete.db
- `filter_delete_info` table — process attribution for deletions
- Links deletions to specific applications

### D. Microsoft.ListSync.db
- Offline mode (Project Nucleus)
- Has creation/modification dates NOT in SyncEngineDatabase
- May contain MORE files than SyncEngine

### E. Microsoft.FileUsageSync.db (Business only)
- `recent_files_formatted_spo` table — rich JSON
- Sharing metadata, activity dates, SharePoint IDs

### F. Microsoft.FilesOnDemand.db
- Offline editing availability tracking

### G. ODL Log Files (Binary)

**Locations:**
- Windows: `%LOCALAPPDATA%\Microsoft\OneDrive\logs\{Common,Business1,Personal}\`
- macOS: `~/Library/Logs/OneDrive/`

**Binary format:**
```
Header (256 bytes):
  signature[8] = "EBFGONED"
  unk_version: u32
  unknown2: u32
  unknown3: u64 (= 0)
  unknown4: u32 (= 1)
  one_drive_version: [u8; 0x40]
  os_version: [u8; 0x40]
  reserved: [u8; 0x64]

Data_block:
  signature: u64 = 0xCCDDEEFF00000000
  timestamp: u64 (Unix milliseconds)
  unk1: u32
  unk2: u32
  unk3_guid: [u8; 16]
  unk4: u32
  unk5: u32 (mostly 1)
  data_len: u32
  unk6: u32 (mostly 0)
  data: [u8; data_len]

Data:
  code_file_name_len: u32
  code_file_name: [u8; code_file_name_len]
  unknown: u32
  code_function_name_len: u32
  code_function_name: [u8; code_function_name_len]
  parameters: [u8; ...]
```

**Obfuscation (pre-April 2022):** ObfuscationStringMap.txt (tab-separated, UTF-8/UTF-16LE). 3-word keys map to original strings.

**Encryption (post-April 2022):** AES-128-CBC. Key in `general.keystore` (base64 JSON). IV is first 16 bytes of ciphertext.

### H. Registry Artifacts

**HKCU:**
- `HKCU\Software\Microsoft\OneDrive` — Main config, `UserNameCollection`
- `HKCU\...\OneDrive\Accounts\Personal` — `UserCid`, `UserEmail`, `UserFolder`
- `HKCU\...\OneDrive\Accounts\Business1` — `SPOResourceID`, `TenantId`, `ServiceEndpointUri`
- `HKCU\...\OneDrive\Accounts\<type>\Tenants\<name>` — Shared folder paths

**HKLM:**
- `HKLM\SOFTWARE\Microsoft\OneDrive` — Machine-wide settings
- `HKLM\SOFTWARE\Policies\Microsoft\OneDrive` — Group Policy

### I. INI/Text Files
- `<UserCid>.ini` — Folder location, sync time, usage stats
- `ClientPolicy.ini` — Tenant sync boundaries
- `ProfileServiceResponse.txt` — User identity
- `SyncDiagnostics.txt` — Diagnostic info

### J. Hash Algorithm
**QuickXorHash** — 160-bit, non-cryptographic, XOR-based. Replaced SHA1 as the only guaranteed hash from Microsoft. NOT collision-resistant — supplement with cryptographic hashing for evidence.

### K. Cloud Filter Placeholders
- NTFS reparse points via `cldflt.sys`
- Forensic images capture reparse points but NOT file content
- Collection may trigger automatic hydration (evidence alteration risk!)

---

## 3. macOS Artifacts

- **Sync Root:** `~/Library/CloudStorage/OneDrive-Personal` or `OneDrive-<OrgName>`
- **Cache:** `.ODContainer` hidden directory
- **Logs:** `~/Library/Logs/OneDrive/{Common,Business1,Personal}/`
- **Settings:** `~/Library/Containers/com.microsoft.OneDrive-mac/.../OneDrive/settings/`
- **Preferences:** `~/Library/Containers/.../Preferences/com.microsoft.OneDrive-mac.plist`
- **Group Containers:** `~/Library/Group Containers/UBF8T346G9.OneDriveSyncClientSuite/`

---

## 4. Existing Tools

| Tool | Type | Strengths | Limitations |
|------|------|-----------|-------------|
| OneDriveExplorer | Open-source (Python) | Most comprehensive parser | No carving, no recovery |
| KAPE | Commercial (free LE) | Collection + ODE module | Collection-focused |
| Velociraptor | Open-source | KapeFiles targets | Collection-focused |
| Magnet AXIOM | Commercial | Cloud extraction | Proprietary |
| Cellebrite | Commercial | Mobile + cloud | Proprietary |
| FQLite | Open-source | SQLite deleted records | Not OneDrive-specific |
| Belkasoft X | Commercial | SQLite WAL/carving | Proprietary |

---

## 5. Gaps for Rust Crate

1. Carving OneDrive artifacts from raw disk/unallocated space
2. Corrupted SQLite database recovery
3. WAL/journal analysis for deleted records
4. Native performance (all existing tools are Python)
5. Partial/corrupted dat file recovery
6. ETL trace log parsing (no tool does this)
7. Streaming/incremental parsing from forensic image streams
8. Schema-agnostic SQLite parsing (auto-detect v8–v40+)
9. QuickXorHash implementation for integrity verification
10. NTFS Cloud Filter reparse point analysis
11. macOS artifact correlation
12. Unified cross-artifact timeline generation

---

## 6. Recommended Architecture

```
onedrive-forensic/
├── src/
│   ├── lib.rs                    # Public API
│   ├── dat/                      # UserCid.dat binary parser
│   │   ├── parser.rs             # Binary walk parser
│   │   ├── carver.rs             # Dat fragment carving
│   │   └── types.rs              # Dat structures
│   ├── sqlite/                   # SQLite database parsers
│   │   ├── sync_engine.rs        # SyncEngineDatabase.db
│   │   ├── safe_delete.rs        # SafeDelete.db
│   │   ├── list_sync.rs          # Microsoft.ListSync.db
│   │   ├── file_usage_sync.rs    # Microsoft.FileUsageSync.db
│   │   ├── files_on_demand.rs    # Microsoft.FilesOnDemand.db
│   │   ├── schema.rs             # Schema version detection
│   │   ├── recovery.rs           # Deleted record recovery
│   │   └── carver.rs             # SQLite carving
│   ├── odl/                      # ODL log parser
│   │   ├── parser.rs             # Binary format parser
│   │   ├── deobfuscate.rs        # ObfuscationStringMap
│   │   ├── decrypt.rs            # AES-128-CBC decryption
│   │   └── types.rs
│   ├── registry/                 # Registry artifacts
│   │   ├── accounts.rs           # Account enumeration
│   │   ├── tenants.rs            # Tenant/shared folders
│   │   └── settings_dat.rs       # settings.dat (REGF format)
│   ├── ini/                      # INI file parsers
│   ├── cloud_filter/             # Reparse point analysis
│   ├── hash/                     # QuickXorHash implementation
│   ├── carving/                  # Signature + fragment carving
│   └── timeline/                 # Cross-artifact timeline
```

**Dependencies:** `rusqlite`, `aes`+`cbc`, `base64`, `nom`/`binrw`, `chrono`, `serde`, `flate2`, `notatin`, `thiserror`, `encoding_rs`, `memmap2`

---

## Sources
- [OneDriveExplorer](https://github.com/Beercow/OneDriveExplorer)
- [Brian Maloney Blog](https://malwaremaloney.blogspot.com/)
- [SyncEngineDatabase Schema](https://malwaremaloney.blogspot.com/p/syncenginedatabasedb.html)
- [Yogesh Khatri ODL Parser](https://github.com/ydkhatri/OneDrive)
- [SANS — Recreating OneDrive Folder Structure](https://www.sans.org/blog/recreating-onedrive-s-folder-structure-from-usercid-dat)
- [Microsoft — QuickXorHash](https://learn.microsoft.com/en-us/onedrive/developer/code-snippets/quickxorhash)
- [Microsoft — Cloud Filter API](https://learn.microsoft.com/en-us/windows/win32/cfapi/build-a-cloud-file-sync-engine)
- [HackTricks — Local Cloud Storage](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.html)
- [Forensafe — OneDrive](https://www.forensafe.com/blogs/onedrive.html)
- [ElcomSoft — The Cloud Gap](https://blog.elcomsoft.com/2026/01/the-cloud-gap-forensic-triage-vs-disk-imaging-in-the-age-of-on-demand-sync/)
