# External File Metadata Forensics: Complete Reference for Rust Parser Development

> Research compiled 2026-03-25 for Issen forensic parser development.
> Covers NTFS ADS, macOS xattrs, Linux xattrs, ACLs, and related external metadata systems.

---

## Part 1: NTFS Alternate Data Streams (ADS)

### 1.1 Zone.Identifier (Mark of the Web)

#### Format

The Zone.Identifier is an NTFS ADS stored as a plain-text INI file attached to downloaded files. It is accessed as `filename:Zone.Identifier:$DATA`.

```ini
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://example.com/downloads/
HostUrl=https://example.com/downloads/file.exe
HostIpAddress=203.0.113.50
LastWriterPackageFamilyName=Microsoft.MicrosoftEdge_8wekyb3d8bbwe
AppZoneId=4
```

#### ZoneId Values

| ZoneId | Name | Description |
|--------|------|-------------|
| 0 | Local Machine | File originated from the local system |
| 1 | Local Intranet | File from intranet zone |
| 2 | Trusted Sites | File from a trusted site |
| 3 | Internet | File downloaded from the internet |
| 4 | Restricted Sites | File from restricted/untrusted zone |

#### Properties Reference

| Property | Since | Description |
|----------|-------|-------------|
| `ZoneId` | XP SP2 | Security zone of origin (0-4) |
| `ReferrerUrl` | Win10 1703 | Page URL where the download link was clicked |
| `HostUrl` | Win10 1703 | Direct download URL of the file |
| `HostIpAddress` | Win10 1703 | IP address of the download server |
| `LastWriterPackageFamilyName` | Win10 1703 | UWP/Store app package family name that wrote the file |
| `AppZoneId` | Win10 1703 | SmartScreen reputation assessment zone |

#### Browser Behavior Differences

| Property | Chrome | Edge (Legacy/UWP) | Edge (Chromium) | Firefox (older) | Firefox (newer) |
|----------|--------|-------------------|-----------------|-----------------|-----------------|
| ZoneId | Yes | Yes | Yes | Yes | Yes |
| HostUrl | Yes | Sometimes | Yes | No | Yes |
| ReferrerUrl | Yes | Sometimes | Yes | No | Yes |
| HostIpAddress | No | Yes | Varies | No | No |
| LastWriterPackageFamilyName | No | Yes | No | No | No |
| AppZoneId | No | Via SmartScreen | Via SmartScreen | No | No |

**Key forensic notes:**
- `curl` and `wget` on Windows do NOT create Zone.Identifier streams.
- Archive extraction via Windows Explorer propagates Zone.Identifier to extracted files, with `ReferrerUrl` pointing back to the archive's local path.
- HTML smuggling (blob: URLs) results in `HostUrl=about:internet` in Chromium-based browsers.
- Incognito/Private browsing may omit `ReferrerUrl`/`HostUrl` but still writes `ZoneId`.

#### Parsing from Raw NTFS $MFT

The Zone.Identifier is stored as a named `$DATA` attribute in the MFT record. In the MFT entry for a file:
1. Locate all `$DATA` attributes (type 0x80).
2. Named `$DATA` attributes have a non-zero name offset and name length in the attribute header.
3. The stream name `Zone.Identifier` is stored as UTF-16LE.
4. For resident attributes, the data follows inline. For non-resident, follow the data run list.

#### Anti-Forensic Considerations

- "Unblock" via file properties deletes the entire Zone.Identifier ADS.
- Zone.Identifier can be disabled via Group Policy: `User Configuration > Administrative Templates > Windows Components > Attachment Manager > Do not preserve zone information`.
- Copying to FAT/FAT32/exFAT removes all ADS.
- MotW bypass CVEs: CVE-2022-41091, CVE-2022-44698, CVE-2023-36584, CVE-2024-38217.
- ISO/VHD/VHDX containers bypass MotW because their internal filesystems don't support NTFS ADS.

### 1.2 SmartScreen ADS

Windows SmartScreen creates an ADS named `:SmartScreen` on some downloaded executables. The content is typically the string `"Anaheim"` (the codename for Chromium-based Edge), marking the file as having been assessed by SmartScreen.

**Forensic significance:** Presence of `:SmartScreen` confirms the file was downloaded and assessed. Useful for IR/threat hunting: `dir /r` or Sysmon to search for these streams.

### 1.3 Other Known NTFS ADS Names

| ADS Name | Source | Purpose |
|----------|--------|---------|
| `:$DATA` (unnamed) | NTFS | Default data stream (file content) |
| `:Zone.Identifier` | Windows | Mark of the Web download provenance |
| `:SmartScreen` | Windows Defender | SmartScreen reputation assessment |
| `:{GUID}` (various) | Kaspersky, AV products | File scan result hash/signature |
| `:encryptable` | EFS | EFS encryption metadata |
| `:OECustomProperty` | Outlook | Custom email properties |
| `:com.dropbox.attrs` | Dropbox | Dropbox sync metadata |
| `:AFP_Resource` | SFM/ExtremeZ-IP | Mac resource fork (NTFS interop) |
| `:AFP_AfpInfo` | SFM/ExtremeZ-IP | Mac AFP metadata (NTFS interop) |
| `:{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}` | Legacy Windows | Summary Information (OLE) |
| `:Favicon` | Internet Explorer | Cached favicon data |
| `:ms-properties` | Windows | Windows property store |
| `:bin` | BitPaymer ransomware | Malware hiding (copies itself here) |

### 1.4 ADS in $UsnJrnl

The USN Journal (`$Extend\$UsnJrnl:$J`) tracks ADS operations with specific reason codes:

| Reason Code | Value | Description |
|-------------|-------|-------------|
| `USN_REASON_NAMED_DATA_OVERWRITE` | `0x00000010` | Named data stream (ADS) content overwritten |
| `USN_REASON_NAMED_DATA_EXTEND` | `0x00000020` | Named data stream (ADS) content extended |
| `USN_REASON_NAMED_DATA_TRUNCATION` | `0x00000040` | Named data stream (ADS) content truncated |
| `USN_REASON_STREAM_CHANGE` | (various) | Generic stream change indicator |

These are distinct from `USN_REASON_DATA_OVERWRITE` (0x00000001) and `USN_REASON_DATA_EXTEND` (0x00000002), which apply to the default unnamed stream.

**Forensic approach:** Parse `$UsnJrnl:$J` and filter for `NAMED_DATA_*` reason flags to detect ADS creation/modification, even if the files are deleted.

### 1.5 ADS in $LogFile

The NTFS `$LogFile` (MFT entry #2) records redo/undo operations for all metadata changes. ADS creation shows up as new `$DATA` attribute creation in the MFT record. The $LogFile is a circular log (default 64KB blocks), so data retention is typically minutes to hours on active volumes.

### 1.6 ADS Preservation During File Operations

| Operation | ADS Preserved? |
|-----------|----------------|
| NTFS-to-NTFS file copy (Windows API) | Yes |
| NTFS-to-NTFS folder copy (Explorer, post-Win7) | No (bug in IFileOperation) |
| NTFS-to-FAT/FAT32/exFAT | No (ADS stripped) |
| NTFS-to-network share | Often No |
| Upload (FTP, cloud, email attachment) | No |
| ZIP/archive compression | No (unless tool specifically preserves) |
| Unblock file (Properties dialog) | Deletes Zone.Identifier only |

### 1.7 Malware Use of ADS (MITRE T1564.004)

Known threat actors and malware families abusing ADS:

| Threat | Technique |
|--------|-----------|
| **BitPaymer** | Copies self to `:bin` ADS of a new file, executes from ADS |
| **WastedLocker** | Stores executable content in ADS |
| **Valak** | Saves and executes files as ADS |
| **APT32 (OceanLotus)** | Used ADS during Cobalt Kitty campaign |
| **Regin** | Stores encrypted executables in `$EA` (Extended Attributes) |
| **Zeroaccess** | Stores operational data in Extended Attributes |
| **Latrodectus** | Uses ADS for self-deletion while process is running |

**LOLBins that can manipulate ADS:** `type`, `esentutl`, `expand`, `extrac32`, `findstr`, `certutil.exe`, `makecab`, `print`, `reg export`, `regedit`, PowerShell (`Set-Content -Stream`, `Get-Content -Stream`).

**Detection:** Monitor Sysmon Event ID 1 for execution with ADS parameters. Watch for filenames containing colons. Use `dir /r` or `streams.exe` (Sysinternals) for enumeration.

---

## Part 2: NTFS $EA (Extended Attributes)

### 2.1 $EA vs ADS

`$EA` is a distinct MFT attribute (type 0xE0) from ADS (`$DATA` type 0x80). Extended Attributes store name-value pairs used by OS/2 compatibility, WSL, SMB, and NFS.

### 2.2 On-Disk Structure: FILE_FULL_EA_INFORMATION

Each EA entry uses the `FILE_FULL_EA_INFORMATION` structure:

```
Offset  Size  Field
0x00    4     NextEntryOffset (0 = last entry; otherwise offset to next entry, padded to DWORD)
0x04    1     Flags (0x00 or 0x80 = FILE_NEED_EA)
0x05    1     EaNameLength (length of name, excluding null terminator)
0x06    2     EaValueLength (length of value data)
0x08    var   EaName (null-terminated ASCII string)
var     var   EaValue (raw bytes, length = EaValueLength)
```

### 2.3 WSL Linux Metadata in $EA

#### Legacy LxFs Format: `LXATTRB`

A single EA entry named `LXATTRB` containing a packed 56-byte structure:

```
Offset  Size  Field
0x00    2     Flags
0x02    2     Version
0x04    4     st_mode (Linux file mode, e.g., 0100644)
0x08    4     st_uid (Linux user ID)
0x0C    4     st_gid (Linux group ID)
0x10    4     st_rdev (device ID)
0x14    4     atime_sec (access time seconds)
0x18    4     atime_nsec (access time nanoseconds)
0x1C    4     (padding)
0x20    4     mtime_sec
0x24    4     mtime_nsec
0x28    4     (padding)
0x2C    4     ctime_sec
0x30    4     ctime_nsec
0x34    4     (padding)
```

#### Newer WslFs / DrvFs Format: Separate EA Entries

| EA Name | Size | Content |
|---------|------|---------|
| `$LXUID` | 4 bytes | Linux User ID (uint32 LE) |
| `$LXGID` | 4 bytes | Linux Group ID (uint32 LE) |
| `$LXMOD` | 4 bytes | Linux file mode (uint32 LE) |
| `$LXDEV` | 4 bytes | Linux device ID (uint32 LE) |

**Known bug:** DrvFs with metadata has an off-by-one error in `FILE_FULL_EA_INFORMATION` layout, causing Windows API (`ZwQueryEaFile`) to misread by 1 byte.

### 2.4 Common $EA Names (Velociraptor Default Exclusions)

The Velociraptor `Windows.NTFS.ExtendedAttributes` artifact excludes these common legitimate EA names:
- `$KERNEL.PURGE.ESBCACHE`
- `$KERNEL.PURGE.APPXFICACHE`
- `$CI.CATALOGHINT`
- `{GUID}.CSC.*` patterns

### 2.5 Forensic Tools

- **EaTools** (jschicht/GitHub): Parse and manipulate $EA on NTFS
- **Velociraptor**: `Windows.NTFS.ExtendedAttributes` artifact
- **MFTECmd** (Eric Zimmerman): Parses MFT including $EA attribute

---

## Part 3: NTFS Security Descriptors & Access Control

### 3.1 Security Descriptor Binary Structure

#### Header (20 bytes)

```
Offset  Size  Field
0x00    1     Revision (always 0x01)
0x01    1     Padding (0x00)
0x02    2     Control Flags (LE)
0x04    4     Offset to Owner SID (from start of descriptor)
0x08    4     Offset to Group SID
0x0C    4     Offset to SACL (0 if no SACL)
0x10    4     Offset to DACL (0 if no DACL)
```

#### Control Flags

| Value | Name | Description |
|-------|------|-------------|
| 0x0001 | SE_OWNER_DEFAULTED | Owner was set by default mechanism |
| 0x0002 | SE_GROUP_DEFAULTED | Group was set by default mechanism |
| 0x0004 | SE_DACL_PRESENT | DACL is present |
| 0x0008 | SE_DACL_DEFAULTED | DACL was set by default |
| 0x0010 | SE_SACL_PRESENT | SACL is present |
| 0x0020 | SE_SACL_DEFAULTED | SACL was set by default |
| 0x0100 | SE_DACL_AUTO_INHERIT_REQ | DACL auto-inherit requested |
| 0x0200 | SE_SACL_AUTO_INHERIT_REQ | SACL auto-inherit requested |
| 0x0400 | SE_DACL_AUTO_INHERITED | DACL was auto-inherited |
| 0x0800 | SE_SACL_AUTO_INHERITED | SACL was auto-inherited |
| 0x1000 | SE_DACL_PROTECTED | DACL is protected from inheritance |
| 0x2000 | SE_SACL_PROTECTED | SACL is protected from inheritance |
| 0x4000 | SE_RM_CONTROL_VALID | Resource Manager control valid |
| 0x8000 | SE_SELF_RELATIVE | Self-relative format (offsets, not pointers) |

Common value on disk: `0x8004` (DACL Present + Self-Relative) or `0x8014` (DACL + SACL Present + Self-Relative).

#### ACL Header (8 bytes)

```
Offset  Size  Field
0x00    1     AclRevision (0x02 = ACL_REVISION, 0x04 = ACL_REVISION_DS)
0x01    1     Sbz1 (padding, 0x00)
0x02    2     AclSize (total size of ACL in bytes, LE)
0x04    2     AceCount (number of ACEs, LE)
0x06    2     Sbz2 (padding, 0x00)
```

#### ACE (Access Control Entry) Structure

```
Offset  Size  Field
0x00    1     AceType
0x01    1     AceFlags
0x02    2     AceSize (total size of this ACE in bytes, LE)
0x04    4     AccessMask (32-bit access rights bitmask, LE)
0x08    var   SID (variable-length Security Identifier)
```

#### ACE Types

| Value | Name | Description |
|-------|------|-------------|
| 0x00 | ACCESS_ALLOWED_ACE_TYPE | Grants access |
| 0x01 | ACCESS_DENIED_ACE_TYPE | Denies access |
| 0x02 | SYSTEM_AUDIT_ACE_TYPE | Audit (in SACL) |
| 0x03 | SYSTEM_ALARM_ACE_TYPE | Alarm (reserved) |
| 0x05 | ACCESS_ALLOWED_OBJECT_ACE_TYPE | Object-specific allow (AD) |
| 0x06 | ACCESS_DENIED_OBJECT_ACE_TYPE | Object-specific deny (AD) |
| 0x07 | SYSTEM_AUDIT_OBJECT_ACE_TYPE | Object-specific audit |
| 0x11 | SYSTEM_MANDATORY_LABEL_ACE_TYPE | Mandatory Integrity label |
| 0x12 | SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE | Resource attribute |
| 0x13 | SYSTEM_SCOPED_POLICY_ID_ACE_TYPE | Scoped policy |

#### ACE Flags (Inheritance)

| Value | Name | Description |
|-------|------|-------------|
| 0x01 | OBJECT_INHERIT_ACE | ACE inherited by child objects |
| 0x02 | CONTAINER_INHERIT_ACE | ACE inherited by child containers |
| 0x04 | NO_PROPAGATE_INHERIT_ACE | Inheritance stops after one level |
| 0x08 | INHERIT_ONLY_ACE | ACE applies only to children, not this object |
| 0x10 | INHERITED_ACE | ACE was inherited from parent |
| 0x40 | SUCCESSFUL_ACCESS_ACE_FLAG | Audit on successful access (SACL) |
| 0x80 | FAILED_ACCESS_ACE_FLAG | Audit on failed access (SACL) |

#### Access Mask Bit Fields

| Value | Name |
|-------|------|
| 0x00000001 | FILE_READ_DATA / FILE_LIST_DIRECTORY |
| 0x00000002 | FILE_WRITE_DATA / FILE_ADD_FILE |
| 0x00000004 | FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY |
| 0x00000008 | FILE_READ_EA |
| 0x00000010 | FILE_WRITE_EA |
| 0x00000020 | FILE_EXECUTE / FILE_TRAVERSE |
| 0x00000040 | FILE_DELETE_CHILD |
| 0x00000080 | FILE_READ_ATTRIBUTES |
| 0x00000100 | FILE_WRITE_ATTRIBUTES |
| 0x00010000 | DELETE |
| 0x00020000 | READ_CONTROL |
| 0x00040000 | WRITE_DAC |
| 0x00080000 | WRITE_OWNER |
| 0x00100000 | SYNCHRONIZE |
| 0x01000000 | ACCESS_SYSTEM_SECURITY |
| 0x02000000 | MAXIMUM_ALLOWED |
| 0x10000000 | GENERIC_ALL |
| 0x20000000 | GENERIC_EXECUTE |
| 0x40000000 | GENERIC_WRITE |
| 0x80000000 | GENERIC_READ |

#### SID Binary Structure

```
Offset  Size  Field
0x00    1     Revision (always 0x01)
0x01    1     SubAuthorityCount (1-15)
0x02    6     IdentifierAuthority (big-endian 48-bit value)
0x08    4*N   SubAuthority[N] (array of uint32 LE values)
```

Total size: `8 + (4 * SubAuthorityCount)` bytes.

Example: `S-1-5-32-544` (Administrators):
```
01              Revision = 1
02              SubAuthorityCount = 2
000000000005    IdentifierAuthority = 5 (NT Authority)
20000000        SubAuthority[0] = 32 (BUILTIN_DOMAIN)
20020000        SubAuthority[1] = 544 (DOMAIN_ALIAS_RID_ADMINS)
```

### 3.2 $Secure File and SecurityId Mapping

Security descriptors are NOT stored per-file in NTFS 3.0+. Instead:

1. Each MFT record's `$STANDARD_INFORMATION` attribute (type 0x10) contains a `SecurityId` field (at offset 0x34, 4 bytes LE).
2. `SecurityId` maps to the `$Secure` system file (MFT entry #9).
3. `$Secure` contains three data streams:
   - **`$SDS`** (Security Descriptor Stream): Contains all security descriptors sequentially. Each entry has: offset, hash, SecurityId, descriptor size, then the actual descriptor.
   - **`$SII`** (Security ID Index): B+ tree index mapping SecurityId to offset in `$SDS`.
   - **`$SDH`** (Security Descriptor Hash): B+ tree index mapping descriptor hashes to offset in `$SDS`. Used to deduplicate identical descriptors.

**Lookup flow:**
```
MFT $STANDARD_INFORMATION.SecurityId
  -> $Secure:$SII (SecurityId -> SDS offset)
  -> $Secure:$SDS (offset -> full security descriptor)
```

**Forensic slack:** The `$SDS` stream contains slack space between entries and beyond the last valid entry, which can be carved for deleted/overwritten security descriptors.

### 3.3 Well-Known SIDs

| SID | Name | Forensic Significance |
|-----|------|----------------------|
| S-1-0-0 | Null SID | No security principal |
| S-1-1-0 | Everyone | Universal group; overly permissive if in DACL |
| S-1-3-0 | Creator Owner | Placeholder in inheritable ACEs |
| S-1-5-7 | Anonymous Logon | Indicates anonymous/unauthenticated access |
| S-1-5-11 | Authenticated Users | All authenticated users |
| S-1-5-18 | SYSTEM (LocalSystem) | OS service account; normal on system files |
| S-1-5-19 | Local Service | NT Authority\LocalService |
| S-1-5-20 | Network Service | NT Authority\NetworkService |
| S-1-5-32-544 | Administrators | Built-in Administrators group |
| S-1-5-32-545 | Users | Built-in Users group |
| S-1-5-32-546 | Guests | Built-in Guests group |
| S-1-5-21-*-500 | Domain Administrator | Built-in admin (RID 500) |
| S-1-5-21-*-501 | Domain Guest | Guest account (RID 501) |
| S-1-5-21-*-512 | Domain Admins | Domain admin group |
| S-1-5-21-*-513 | Domain Users | All domain users |
| S-1-16-0 | Untrusted Integrity | MIC: Untrusted level |
| S-1-16-4096 | Low Integrity | MIC: Low (sandboxed/downloaded) |
| S-1-16-8192 | Medium Integrity | MIC: Medium (standard user) |
| S-1-16-12288 | High Integrity | MIC: High (elevated/admin) |
| S-1-16-16384 | System Integrity | MIC: System level |

### 3.4 Mandatory Integrity Control (MIC)

MIC uses a `SYSTEM_MANDATORY_LABEL_ACE` (type 0x11) in the SACL to store integrity level. The ACE's SID is one of the integrity level SIDs (S-1-16-*).

**Forensic significance:**
- Files with Low Integrity (S-1-16-4096) were likely created by sandboxed processes (e.g., Internet Explorer Protected Mode, Chrome sandbox).
- An executable running at System integrity level has unrestricted access.
- Integrity control evaluation happens BEFORE DACL evaluation and can override discretionary access.

**Default behavior:** Objects without an explicit integrity label are treated as Medium integrity.

---

## Part 4: macOS Extended Attributes (xattr)

### 4.1 `com.apple.quarantine` (Mark of the Web Equivalent)

#### Format

UTF-8 string with semicolon-delimited fields:

```
<flags>;<hex_timestamp>;<agent_name>;<UUID>
```

Example:
```
0083;5c54614c;Safari;B555DB5F-D82A-408B-B9A6-D4F4012FD520
```

#### Fields

| Field | Format | Description |
|-------|--------|-------------|
| Flags | Hex (4 digits) | Quarantine type + status flags |
| Timestamp | Hex | Unix epoch timestamp of download |
| Agent Name | String | App that triggered quarantine (e.g., `Safari`, `com.google.Chrome`) |
| UUID | UUID string | Links to QuarantineEventsV2 database entry |

#### Quarantine Flag Values

**Low-order bits (download type):**

| Bits | Value | Constant | Meaning |
|------|-------|----------|---------|
| 0x00 | 0 | kLSQuarantineTypeWebDownload | HTTP(S) download |
| 0x01 | 1 | kLSQuarantineTypeOtherDownload | Generic/other download |
| 0x02 | 2 | kLSQuarantineTypeEmailAttachment | Email attachment |
| 0x03 | 3 | kLSQuarantineTypeInstantMessageAttachment | IM attachment |
| 0x04 | 4 | kLSQuarantineTypeCalendarEventAttachment | Calendar event |
| 0x06 | 6 | kLSQuarantineTypeSandboxed | Sandboxed app |

**High-order bit flags:**

| Bit | Hex Mask | Meaning |
|-----|----------|---------|
| Bit 0 | 0x01 | App has been run (Sierra and earlier) |
| Bit 5 | 0x20 | Installer package (.pkg/.mpkg) opened |
| Bit 6 | 0x40 | Gatekeeper "Open" dialog accepted |
| Bit 7 | 0x80 | File is still in quarantine, awaiting first-run check |

**Common values and transitions:**

| Hex | Binary | Meaning |
|-----|--------|---------|
| `0000` | `00000000` | Web download, no flags |
| `0001` | `00000001` | Other/generic download |
| `0002` | `00000010` | Email attachment |
| `0003` | `00000011` | IM attachment |
| `0041` | `01000001` | Other download, Gatekeeper dialog accepted |
| `0042` | `01000010` | Email attachment, Gatekeeper dialog accepted |
| `0081` | `10000001` | Other download, first-run pending |
| `0083` | `10000011` | Web/IM download, first-run pending (most common initial value) |
| `00C3` | `11000011` | Gatekeeper first-run check passed (Mojave+) |
| `00E3` | `11100011` | Gatekeeper passed + app run (Sierra and earlier) |

#### QuarantineEventsV2 Database

**Location:** `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`

**Type:** SQLite3

**Key columns:**

| Column | Description |
|--------|-------------|
| LSQuarantineEventIdentifier | UUID (matches xattr UUID field) |
| LSQuarantineTimeStamp | Download timestamp |
| LSQuarantineAgentBundleIdentifier | App bundle ID (e.g., `com.apple.Safari`) |
| LSQuarantineAgentName | App display name |
| LSQuarantineDataURLString | Direct download URL |
| LSQuarantineOriginURLString | Referrer/origin URL |
| LSQuarantineSenderName | Sender name (for email/IM) |
| LSQuarantineSenderAddress | Sender address |
| LSQuarantineTypeNumber | Download type enum value |

**Forensic notes:**
- Residual database entries persist even after files are deleted. This is a valuable forensic artifact.
- Each user has their own database; no system-level equivalent exists.
- macOS 13.3+ reportedly broke database consistency, reducing forensic value on newer systems.
- One database per user; located in the user's home directory.

#### Browser Differences (macOS)

| Attribute | Safari | Chrome | Firefox |
|-----------|--------|--------|---------|
| `com.apple.quarantine` | Yes | Yes | Yes |
| `com.apple.metadata:kMDItemWhereFroms` | Yes | Yes | No |
| `com.apple.metadata:kMDItemDownloadedDate` | Yes | No | No |

### 4.2 `com.apple.metadata:kMDItemWhereFroms`

**Format:** Binary plist (bplist) containing an array of strings.

**Content:** Array of URLs:
- Index 0: Direct download URL
- Index 1: Referrer URL (page that linked to the download)

**Decoding:**
```bash
xattr -p com.apple.metadata:kMDItemWhereFroms <file> | xxd -r -p | plutil -p -
```

**Forensic significance:** Persists indefinitely across reboots. Safari stores both URLs; Chrome stores download URL only.

**Security note:** A vulnerability reported in 2023 showed that `kMDItemWhereFroms` could leak authentication tokens embedded in download URLs. Apple patched this quietly.

### 4.3 `com.apple.metadata:kMDItemDownloadedDate`

**Format:** Binary plist containing an NSDate (CFAbsoluteTime).

**Content:** Timestamp of when the file was downloaded.

**Note:** Only Safari writes this attribute; Chrome does not.

### 4.4 `com.apple.lastuseddate#PS`

**Format:** 8 bytes, little-endian, Unix timestamp (seconds since epoch as `f64`).

**Content:** Last time the file was opened/used.

### 4.5 `com.apple.macl` (Mandatory Access Control Label)

**Format:** Binary blob, 72 bytes per entry, SIP-protected.

**Structure:**
- Header byte `0x00`
- Followed by UUID(s) of applications permitted to access the file
- Each UUID block separated by `0x00` bytes
- Multiple UUIDs if file was accessed by multiple applications via drag-and-drop

**Forensic significance:**
- Proves which specific application(s) accessed a file via TCC drag-and-drop.
- UUID is unique per system + user + application, so it cannot be transferred between machines.
- Protected by SIP; cannot be cleared without disabling SIP (workaround: zip, delete, unzip).
- Managed by the Sandbox subsystem, NOT tccd.
- Enumerating the attribute's existence does NOT trigger TCC popup; reading its value DOES.

### 4.6 `com.apple.provenance`

**Introduced:** macOS Ventura (13.x)

**Purpose:** Marks that an app has successfully cleared quarantine and Gatekeeper assessment. Applied when:
1. App is moved to a new folder (e.g., /Applications)
2. App is launched for the first time via Finder
3. Gatekeeper assessment succeeds

**Protection:** NOT protected by SIP (unlike `com.apple.macl` after assessment).

### 4.7 `com.apple.FinderInfo`

**Format:** Exactly 32 bytes (strict requirement; any other size causes error).

**Binary Layout:**

```
Offset  Size  Field                Description
0x00    4     fdType               File type code (4 ASCII chars, e.g., 'TEXT', 'JPEG')
0x04    4     fdCreator            Creator code (4 ASCII chars, e.g., 'MACS', 'GKON')
0x08    2     fdFlags              Finder flags (see below)
0x0A    2     fdLocationV          Vertical position in Finder window
0x0C    2     fdLocationH          Horizontal position in Finder window
0x0E    2     fdFldr               Directory ID
0x10    16    FXInfo               Extended Finder Info (extended flags, script code, etc.)
```

**Finder Flags (fdFlags):**

| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 0x01 | isOnDesk (not used in modern macOS) |
| 1 | 0x02 | Color (bits 1-3 encode label color) |
| 4 | 0x10 | isShared |
| 5 | 0x20 | hasNoINITs |
| 6 | 0x40 | hasBeenInited |
| 7 | 0x80 | isAlias |
| 8 | 0x0100 | hasCustomIcon |
| 9 | 0x0200 | isStationery |
| 10 | 0x0400 | nameLocked |
| 11 | 0x0800 | hasBundle |
| 12 | 0x1000 | isInvisible |

**Parsing tool:** [`finderinfo-rust`](https://github.com/dropbox/finderinfo-rust) (Rust crate by Dropbox).

### 4.8 Other macOS Extended Attributes

| Attribute | Format | Purpose |
|-----------|--------|---------|
| `com.apple.metadata:kMDItemFinderComment` | Binary plist (string) | User-set Finder comment |
| `com.apple.metadata:kMDItem_kMDItemUserTags` | Binary plist (array) | Finder tags (color labels) |
| `com.apple.metadata:kMDItemLastUsedDate` | Binary plist (date) | Last opened date |
| `com.apple.metadata:kMDItemUseCount` | Binary plist (int) | Number of times opened |
| `com.apple.ResourceFork` | Raw binary | Classic Mac resource fork data |
| `com.apple.TextEncoding` | UTF-8 string | Text file encoding (e.g., `utf-8;134217984`) |
| `com.apple.diskimages.recentcksum` | String | Disk image checksum + timestamp |
| `com.apple.diskimages.fsck` | String | Filesystem check data for DMG |
| `com.apple.rootless` | (flag presence) | SIP protection flag |
| `com.apple.decmpfs` | Binary | HFS+ transparent compression metadata |
| `com.apple.genstore` | Binary | Document version store data |
| `com.apple.security` | Binary | Access Control List data |
| `com.apple.backupd` | Binary | Time Machine backup metadata |
| `com.apple.cs.CodeDirectory` | Binary | Code signature hash |

### 4.9 APFS xattr Storage

#### Inline (Embedded) Storage

For xattrs up to 3,804 bytes, data is stored directly in the xattr record in the filesystem metadata tree.

**Key structure (`j_xattr_key_t`):**
```
Field       Type      Description
hdr         j_key_t   Standard FS record key header (contains object_id + type APFS_TYPE_XATTR)
name_len    uint16    Length of attribute name including null terminator
name        char[]    UTF-8 null-terminated attribute name
```

**Value structure (`j_xattr_val_t`):**
```
Field       Type      Description
flags       uint16    XATTR_DATA_STREAM (0x01) or XATTR_DATA_EMBEDDED (0x02)
xdata_len   uint16    Length of inline data (0 if stream-based)
xdata       uint8[]   Inline data (present only if XATTR_DATA_EMBEDDED)
```

#### Data Stream (Extent-Based) Storage

For xattrs larger than 3,804 bytes, the `flags` field has `XATTR_DATA_STREAM` set, and `xdata` contains an 8-byte object identifier pointing to the data stream's extent records (`APFS_TYPE_FILE_EXTENT`).

**Forensic note:** APFS clones (copy-on-write copies) share xattrs with the original; they are NOT duplicated.

### 4.10 HFS+ xattr Storage

On HFS+, extended attributes are stored in the **Attributes B-tree** (`$AttrFile`), a separate B-tree that maps (CNID, attribute name) pairs to attribute data.

---

## Part 5: macOS Gatekeeper & TCC

### 5.1 Gatekeeper Assessment Databases

| Database Path | Protection | Purpose |
|---------------|------------|---------|
| `/var/db/SystemPolicy` | Root-writable (not SIP) | Gatekeeper rules (authority table) |
| `/var/db/.SystemPolicy-default` | Backup | Original backup of SystemPolicy |
| `/var/db/SystemPolicyConfiguration/ExecPolicy` | Not SIP-protected | Execution policy cache and provenance |
| `/var/db/SystemPolicyConfiguration/gke.bundle` | SIP-protected | Gatekeeper exclusions |
| `/var/db/SystemPolicyConfiguration/TamperExceptions.plist` | SIP-protected | Anti-tampering exception list |

**ExecPolicy tables of forensic interest:**
- `executable_measurements_v2` — Code hash measurements
- `legacy_exec_history_v4` — Historical execution records
- `provenance_tracking` — App provenance (cdhash + metadata)
- `policy_scan_cache` — Cached scan results

### 5.2 TCC (Transparency, Consent, and Control) Database

**Locations:**
- User: `~/Library/Application Support/com.apple.TCC/TCC.db`
- System: `/Library/Application Support/com.apple.TCC/TCC.db`
- iOS: `/private/var/mobile/Library/TCC/TCC.db`

**Type:** SQLite3 (SIP-protected from editing, but readable with Full Disk Access)

**Primary table: `access`**

| Column | Type | Description |
|--------|------|-------------|
| service | TEXT | Permission type (e.g., `kTCCServiceSystemPolicyAllFiles`) |
| client | TEXT | Bundle ID or absolute path |
| client_type | INT | 0 = Bundle ID, 1 = Absolute path |
| auth_value | INT | 0=Denied, 1=Unknown, 2=Allowed, 3=Limited |
| auth_reason | INT | 1=Error, 2=User Consent, 3=User Set, 4=System Set, 5=Service Policy, 6=MDM Policy, 7=Override Policy, 8=Missing usage string, 9=Prompt Timeout, 10=Preflight Unknown, 11=Entitled, 12=App Type Policy |
| csreq | BLOB | Code signing requirement (binary blob) |
| policy_id | INT | MDM policy reference |
| indirect_object_identifier | TEXT | Target (for AppleEvents: bundle ID/path of target app) |

**Key service values:**
- `kTCCServiceSystemPolicyAllFiles` — Full Disk Access
- `kTCCServiceAccessibility` — Accessibility (control computer)
- `kTCCServiceScreenCapture` — Screen recording
- `kTCCServiceMicrophone` — Microphone access
- `kTCCServiceCamera` — Camera access
- `kTCCServicePostEvent` — Send keystrokes
- `kTCCServiceListenEvent` — Input monitoring
- `kTCCServiceDeveloperTool` — Developer tool access

**Forensic significance:** TCC entries reveal which applications requested and received permission to access protected resources. Critical for identifying spyware, RATs, or unauthorized monitoring.

---

## Part 6: Linux Extended Attributes

### 6.1 Namespaces

| Namespace | Read | Write | Purpose |
|-----------|------|-------|---------|
| `user.*` | Any (with file read) | Any (with file write) | Arbitrary user metadata |
| `security.*` | Root (CAP_SYS_ADMIN) | Root (CAP_SYS_ADMIN) | Security modules (SELinux, capabilities, IMA) |
| `system.*` | Varies | Varies | Kernel subsystems (ACLs) |
| `trusted.*` | Root (CAP_SYS_ADMIN) | Root (CAP_SYS_ADMIN) | Privileged process metadata |

**Important:** `getfattr` defaults to `user.*` pattern only. Use `-m -` (dash as pattern) to see all namespaces.

**Note:** Cannot set `user.*` xattrs on symlinks or device special files (resource consumption protection).

### 6.2 `security.selinux`

**Format:** Null-terminated string containing the SELinux security context label.

**Example:** `unconfined_u:object_r:user_home_t:s0`

**Structure:** `user:role:type:level`

**Forensic significance:** Reveals the mandatory access control context. Changes to SELinux labels may indicate policy manipulation or compromise.

### 6.3 `security.capability` (File Capabilities)

#### Binary Format (`struct vfs_cap_data`)

```c
struct vfs_cap_data {
    __le32 magic_etc;        // Revision in upper byte + effective flag in bit 0
    struct {
        __le32 permitted;    // Permitted capability bitmask
        __le32 inheritable;  // Inheritable capability bitmask
    } data[VFS_CAP_U32];    // 1 pair for v1, 2 pairs for v2/v3
};
```

#### Revision Versions

| Revision | Constant | Total xattr Size | Capability Bits | Extra Fields |
|----------|----------|------------------|-----------------|--------------|
| v1 | `VFS_CAP_REVISION_1` (0x01000000) | 12 bytes | 32-bit | None |
| v2 | `VFS_CAP_REVISION_2` (0x02000000) | 20 bytes | 64-bit | None |
| v3 | `VFS_CAP_REVISION_3` (since Linux 4.14) | 24 bytes | 64-bit | `rootid` (4 bytes, namespace root UID) |

#### magic_etc Field Decoding

```
magic_etc & 0xFF000000 = Revision
magic_etc & 0x00000001 = VFS_CAP_FLAGS_EFFECTIVE (if set, capabilities are auto-activated)
```

#### Key Capabilities (Forensically Significant)

| Capability | Bit | Description | Forensic Concern |
|------------|-----|-------------|------------------|
| CAP_SETUID | 7 | Manipulate UIDs | Privilege escalation |
| CAP_SETGID | 6 | Manipulate GIDs | Privilege escalation |
| CAP_NET_RAW | 13 | RAW/PACKET sockets | Network sniffing |
| CAP_NET_ADMIN | 12 | Network administration | Network manipulation |
| CAP_SYS_ADMIN | 21 | Broad admin operations | Near-root access |
| CAP_DAC_OVERRIDE | 1 | Bypass file read/write/execute checks | File access bypass |
| CAP_SYS_PTRACE | 19 | Trace processes | Process injection |
| CAP_SYS_MODULE | 16 | Load kernel modules | Rootkit installation |

#### Hunting for Capabilities

```bash
# Find all binaries with capabilities
getcap -r / 2>/dev/null

# Decode capability hex from /proc
capsh --decode=0x0000000000000080  # = cap_setuid
```

### 6.4 `security.ima` (Integrity Measurement Architecture)

**Format:** Binary data structure containing either a hash or a digital signature.

**Hash mode:**
- Default algorithm: SHA-1 (configurable to SHA-256 via `ima_hash=sha256` boot param)
- Stored as raw hash bytes with algorithm identifier prefix

**Signature mode:**
- RSA-key based digital signature of the file contents
- Private key signs; public key verifies at runtime

**IMA Appraisal Modes:**
- `enforce` — Deny access if hash mismatch or missing
- `log` — Log mismatches but allow access
- `fix` — Create/update hashes for files
- `off` — Disabled

**Runtime measurement log:** `/sys/kernel/security/ima/ascii_runtime_measurements`

### 6.5 `security.evm` (Extended Verification Module)

**Format:** HMAC-SHA1 hash of all security xattrs (`security.ima`, `security.selinux`, etc.).

**Purpose:** Detects offline tampering of security xattrs by hashing them together and signing with a key (either HMAC symmetric or RSA asymmetric).

### 6.6 XDG Origin Attributes

| Attribute | Description | Set By |
|-----------|-------------|--------|
| `user.xdg.origin.url` | Download source URL | Chromium, wget, curl, Snapcraft |
| `user.xdg.referrer.url` | Referrer URL | Chromium |
| `user.xdg.origin.email.from` | Email sender (attachments) | Thunderbird |
| `user.xdg.origin.email.subject` | Email subject (attachments) | Thunderbird |
| `user.xdg.publisher` | Publisher/author | Various |
| `user.xdg.comment` | User comment | File managers |

**Note:** Not yet in widespread use (as of 2025). Adoption is growing with Chromium, wget, curl.

### 6.7 POSIX ACLs (`system.posix_acl_access` / `system.posix_acl_default`)

#### UAPI (Userspace) Binary Format

**Header (4 bytes):**
```
Offset  Size  Field
0x00    4     a_version (__le32, value = 0x0002 = POSIX_ACL_XATTR_VERSION)
```

**Each entry (8 bytes):**
```
Offset  Size  Field
0x00    2     e_tag (__le16)
0x02    2     e_perm (__le16)
0x04    4     e_id (__le32, ACL_UNDEFINED_ID = 0xFFFFFFFF for entries without qualifier)
```

**Total size:** `4 + (8 * entry_count)` bytes.

#### Tag Values (e_tag)

| Value | Name | Description |
|-------|------|-------------|
| 0x01 | ACL_USER_OBJ | File owner permissions |
| 0x02 | ACL_USER | Named user permissions (e_id = uid) |
| 0x04 | ACL_GROUP_OBJ | File group permissions |
| 0x08 | ACL_GROUP | Named group permissions (e_id = gid) |
| 0x10 | ACL_MASK | Maximum permissions for ACL_USER/ACL_GROUP_OBJ/ACL_GROUP |
| 0x20 | ACL_OTHER | Everyone else |

#### Permission Bits (e_perm)

| Value | Name |
|-------|------|
| 0x04 | ACL_READ |
| 0x02 | ACL_WRITE |
| 0x01 | ACL_EXECUTE |

#### Ext4 On-Disk Format (Compact)

Uses `EXT4_ACL_VERSION = 0x0001`. Short entries (4 bytes, no e_id) for `ACL_USER_OBJ`, `ACL_GROUP_OBJ`, `ACL_MASK`, `ACL_OTHER`. Full entries (8 bytes, with e_id) for `ACL_USER` and `ACL_GROUP`.

#### Validity Rules

A valid ACL must contain exactly one each of `ACL_USER_OBJ`, `ACL_GROUP_OBJ`, and `ACL_OTHER`. If any `ACL_USER` or `ACL_GROUP` entries exist, exactly one `ACL_MASK` entry is required.

### 6.8 NFSv4 ACLs (`system.nfs4_acl`)

More complex than POSIX ACLs. Supports ALLOW, DENY, AUDIT, and ALARM ACE types with rich permission masks and inheritance flags similar to Windows DACLs.

---

## Part 7: Cross-Platform Interoperability

### 7.1 AppleDouble Format (`._filename`)

Used when macOS stores files on non-fork-aware filesystems (FAT, ext4, NFS, etc.).

**Filename convention:** `._<original_filename>` (e.g., `._document.pdf`)

**Header:**
```
Offset  Size  Field
0x00    4     Magic (0x00051607)
0x04    4     Version (0x00020000)
0x08    16    Home File System (zero-padded string)
0x18    2     Number of entries
```

**Each entry descriptor (12 bytes):**
```
Offset  Size  Field
0x00    4     Entry ID (1=Data Fork, 2=Resource Fork, 9=Finder Info, 15=ATTR header)
0x04    4     Offset in file
0x08    4     Length
```

**Extended attributes:** In macOS AppleDouble files, the 32-byte Finder Info (Entry ID 9) is followed by `"ATTR"` magic and a list of extended attribute name-value pairs.

All multi-byte values are big-endian.

### 7.2 NTFS Interop: AFP Streams

When macOS connects to NTFS volumes via SMB:
- Resource forks are stored as `:AFP_Resource` ADS
- AFP metadata is stored as `:AFP_AfpInfo` ADS (60 bytes)

**Samba `vfs_fruit` module:** Bridges AppleDouble and ADS storage, intercepting `AFP_AfpInfo` and `AFP_Resource` streams.

### 7.3 Preservation Caveats

| Source FS | Destination FS | xattrs/ADS Preserved? |
|-----------|---------------|----------------------|
| NTFS ADS | NTFS | Yes (files), No (folders post-Win7) |
| NTFS ADS | FAT/exFAT | No |
| APFS xattrs | APFS | Yes (including clones) |
| APFS xattrs | FAT/exFAT | Stored as AppleDouble (._files) |
| ext4 xattrs | ext4 | Yes (if tool supports: `cp --preserve=xattr`, `tar --xattrs`) |
| ext4 xattrs | FAT | No |
| `mv` across filesystems | Target FS | Silently discards xattrs if unsupported |

**Critical for forensic practitioners:** Always ensure evidence collection tools preserve extended attributes. Use `tar --xattrs` or forensic imaging (dd, ewfacquire) rather than file-level copy.

---

## Part 8: Rust Parsing Approach Summary

### Recommended Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `ntfs` (Colin Finck) | NTFS MFT parsing, attribute enumeration, ADS reading |
| `nom` | Binary format parsing (ACLs, security descriptors, EA) |
| `plist` | macOS binary plist parsing (kMDItem* attributes) |
| `xattr` | Reading xattrs from live filesystems |
| `rusqlite` | Parsing QuarantineEventsV2, TCC.db, SystemPolicy SQLite DBs |
| `uuid` | UUID parsing for quarantine links, macl entries |
| `chrono` | Timestamp handling (Unix epoch, Core Data epoch, FILETIME) |
| `finderinfo` (Dropbox) | Parsing com.apple.FinderInfo 32-byte structure |

### Key Parsing Tasks by Platform

**Windows (NTFS):**
1. Parse MFT records: enumerate all `$DATA` attributes (type 0x80) for ADS names
2. Parse `Zone.Identifier` ADS content as INI file
3. Parse `$EA` attributes (type 0xE0) using `FILE_FULL_EA_INFORMATION` structure
4. Resolve `SecurityId` from `$STANDARD_INFORMATION` -> `$Secure:$SII` -> `$Secure:$SDS`
5. Parse security descriptors: header -> DACL/SACL -> ACEs -> SIDs
6. Parse `$UsnJrnl:$J` for `USN_REASON_NAMED_DATA_*` flags

**macOS (APFS/HFS+):**
1. Read all xattrs per file
2. Parse `com.apple.quarantine` as semicolon-delimited UTF-8 text
3. Parse `kMDItem*` attributes as binary plists
4. Parse `com.apple.FinderInfo` as 32-byte FInfo+FXInfo structure
5. Parse `com.apple.macl` as series of 72-byte UUID entries
6. Cross-reference UUIDs with QuarantineEventsV2 SQLite DB

**Linux (ext4/btrfs/XFS):**
1. Read all xattrs across all namespaces
2. Parse `security.capability` as `vfs_cap_data` structure (check revision for size)
3. Parse `system.posix_acl_access` / `system.posix_acl_default` as POSIX ACL binary format
4. Parse `security.selinux` as null-terminated UTF-8 string
5. Parse `security.ima` / `security.evm` as binary hash/signature
6. Parse `user.xdg.origin.*` as UTF-8 strings

---

## Sources

### NTFS & Windows
- [Digital Detective - Zone.Identifier Forensic Analysis](https://www.digital-detective.net/forensic-analysis-of-zone-identifier-stream/)
- [CyberEngage - ADS Zone.Identifier Investigation](https://www.cyberengage.org/post/unveiling-file-origins-the-role-of-alternate-data-streams-ads-zone-identifier-in-forensic-inve)
- [The Swanepoel Method - Highway To The Danger Zone.Identifier](https://www.dfir.co.za/2018/06/18/highway-to-the-danger-zone-identifier/)
- [SecurityJosh - Detecting HTML Smuggling with Zone.Identifier](https://securityjosh.github.io/2021/01/27/Detect-HTML-Smuggling-Sysmon.html)
- [MITRE ATT&CK T1564.004 - NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/)
- [Red Canary Atomic Red Team - T1564.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md)
- [Winitor - NTFS Alternate Data Streams (PDF)](https://www.winitor.com/pdf/NtfsAlternateDataStreams.pdf)
- [NTFS Documentation - $SECURITY_DESCRIPTOR](https://flatcap.github.io/linux-ntfs/ntfs/attributes/security_descriptor.html)
- [artifacts.help - NTFS $Secure](https://artefacts.help/windows_secure.html)
- [jschicht/Secure2Csv](https://github.com/jschicht/Secure2Csv)
- [jschicht/EaTools](https://github.com/jschicht/EaTools)
- [Velociraptor - Windows.NTFS.ExtendedAttributes](https://docs.velociraptor.app/artifact_references/pages/windows.ntfs.extendedattributes/)
- [Microsoft - Security Descriptors in File Systems](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/security-descriptors)
- [Microsoft - Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [Microsoft - Well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
- [Microsoft WSL Issue #2777 - EA Incompatibility](https://github.com/Microsoft/WSL/issues/2777)
- [SANS DFIR - USN Journal](https://isc.sans.edu/diary/31990)
- [CyberEngage - NTFS Journaling Forensics](https://www.cyberengage.org/post/power-of-ntfs-journaling-in-digital-forensics-logfile-usnjrnl)
- [Count Upon Security - NTFS Change Journal](https://countuponsecurity.com/2017/05/25/digital-forensics-ntfs-change-journal/)

### macOS
- [Eclectic Light Company - com.apple.quarantine](https://eclecticlight.co/2017/12/11/xattr-com-apple-quarantine-the-quarantine-flag/)
- [Eclectic Light Company - Quarantine and the quarantine flag](https://eclecticlight.co/2020/10/29/quarantine-and-the-quarantine-flag/)
- [Eclectic Light Company - Quarantine, SIP, and MACL](https://eclecticlight.co/2020/01/30/quarantine-sip-and-macl-macos-per-file-security-controls/)
- [Eclectic Light Company - com.apple.FinderInfo](https://eclecticlight.co/2017/12/19/xattr-com-apple-finderinfo-information-for-the-finder/)
- [Eclectic Light Company - How macOS tracks provenance](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [Eclectic Light Company - APFS Extended Attributes Revisited](https://eclecticlight.co/2024/05/13/apfs-extended-attributes-revisited/)
- [HackMD - Extended Attributes macOS Forensics](https://hackmd.io/@M4shl3/xattr)
- [dfir.ch - macOS Extended Attributes Case Study](https://dfir.ch/posts/macos_extended_attributes/)
- [0xmachos - Quarantine Intro](https://0xmachos.com/2019-02-01-Quarantine-Intro/)
- [nixhacker - Gatekeeper Security](https://nixhacker.com/security-protection-in-macos-1/)
- [Scott Knight - syspolicyd internals](https://knight.sc/reverse%20engineering/2019/02/20/syspolicyd-internals.html)
- [Red Canary - Gatekeeping in macOS](https://redcanary.com/blog/threat-detection/gatekeeper/)
- [HackTricks - macOS Gatekeeper/Quarantine/XProtect](https://hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-gatekeeper.html)
- [Rainforest QA - TCC.db Deep Dive](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [slyd0g - Extended Attributes and TCC on macOS](https://slyd0g.medium.com/extended-attributes-and-tcc-on-macos-a535878f2c8d)
- [Apple - APFS Reference (PDF)](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf)
- [ERNW - APFS Forensics Whitepaper](https://static.ernw.de/whitepaper/ERNW_Whitepaper65_APFS-forensics_signed.pdf)
- [Joe Sylve - APFS Data Streams](https://jtsylve.blog/post/2022/12/19/APFS-Data-Streams)
- [libfsapfs Documentation](https://github.com/libyal/libfsapfs/blob/main/documentation/Apple%20File%20System%20(APFS).asciidoc)
- [Dropbox finderinfo-rust](https://github.com/dropbox/finderinfo-rust)
- [AFine - macOS Extended Attributes Expose Auth Tokens](https://afine.com/how-macos-file-metadata-exposed-authentication-tokens)
- [reitermarkus/quarantine findings](https://github.com/reitermarkus/quarantine/blob/master/findings.md)
- [Apple - Gatekeeper and runtime protection](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web)

### Linux
- [man7.org - xattr(7)](https://man7.org/linux/man-pages/man7/xattr.7.html)
- [man7.org - capabilities(7)](https://www.man7.org/linux/man-pages/man7/capabilities.7.html)
- [man7.org - acl(5)](https://www.man7.org/linux/man-pages/man5/acl.5.html)
- [Linux kernel - posix_acl_xattr.h](https://github.com/torvalds/linux/blob/master/include/linux/posix_acl_xattr.h)
- [Linux kernel - ext4/acl.h](https://github.com/torvalds/linux/blob/master/fs/ext4/acl.h)
- [Linux kernel - posix_acl.h (UAPI)](https://github.com/torvalds/linux/blob/master/include/uapi/linux/posix_acl.h)
- [dfir.ch - Linux Capabilities Revisited](https://dfir.ch/posts/linux_capabilities/)
- [ArchWiki - Extended Attributes](https://wiki.archlinux.org/title/Extended_attributes)
- [Wikipedia - Extended File Attributes](https://en.wikipedia.org/wiki/Extended_file_attributes)
- [Red Hat - IMA Documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/kernel_administration_guide/enhancing_security_with_the_kernel_integrity_subsystem)
- [Red Hat - How to use IMA](https://www.redhat.com/en/blog/how-use-linux-kernels-integrity-measurement-architecture)
- [IMA Documentation](https://ima-doc.readthedocs.io/en/latest/ima-concepts.html)
- [USENIX - POSIX ACLs on Linux](https://www.usenix.org/legacyurl/posix-access-control-lists-linux)
- [Kernel.org - ext4 Extended Attributes](https://www.kernel.org/doc/html/latest/filesystems/ext4/attributes.html)

### Cross-Platform / Interoperability
- [Grokipedia - AppleSingle and AppleDouble Formats](https://grokipedia.com/page/AppleSingle_and_AppleDouble_formats)
- [LOC - AppleDouble Resource Fork](https://www.loc.gov/preservation/digital/formats/fdd/fdd000625.shtml)
- [Samba - vfs_fruit](https://www.samba.org/samba/docs/4.5/man-html/vfs_fruit.8.html)
- [Apple Developer - File System Details](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
