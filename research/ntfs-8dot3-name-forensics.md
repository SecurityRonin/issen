# NTFS 8.3 Short Filename Forensics: Anomaly Detection for MFT-Based Triage

**Date**: 2026-03-27
**Purpose**: Research for Issen heuristics engine -- evaluating whether to add a heuristic
that compares Win32 vs DOS `$FILE_NAME` attributes for anomalies indicative of malware
obfuscation.

---

## Table of Contents

1. [How NTFS 8.3 Names Work](#1-how-ntfs-83-names-work)
2. [Malware Abuse Techniques](#2-malware-abuse-techniques)
3. [Forensic Detection Opportunities](#3-forensic-detection-opportunities)
4. [Real-World Examples and CVEs](#4-real-world-examples-and-cves)
5. [What the `mft` Crate Actually Does](#5-what-the-mft-crate-actually-does)
6. [Recommendations for Issen](#6-recommendations-for-issen)
7. [References](#7-references)

---

## 1. How NTFS 8.3 Names Work

### 1.1 The `$FILE_NAME` Attribute (0x30)

Every file and directory on NTFS has at least one `$FILE_NAME` attribute (attribute type 0x30)
in its MFT entry. This attribute stores:

- **Parent directory MFT reference** (used for path reconstruction)
- **Four timestamps**: Created, Modified, MFT-modified, Accessed (kernel-managed, not
  user-modifiable via standard APIs)
- **Logical and physical size**
- **File attribute flags**
- **Namespace** (1 byte at offset 0x41 within the attribute body)
- **File name** (UTF-16LE encoded)

A copy of each `$FILE_NAME` attribute is also stored in the parent directory's `$INDEX_ROOT`
or `$INDEX_ALLOCATION` (B+ tree index), though the two copies are not always kept in sync.

### 1.2 The Four Namespace Values

The namespace byte determines how the file name should be interpreted:

| Value | Name         | Description |
|-------|-------------|-------------|
| 0x00  | **POSIX**   | Most permissive. Allows all Unicode characters including case-sensitive duplicates. Up to 255 characters. Rarely used in practice. |
| 0x01  | **Win32**   | Standard Windows long filename. Disallows `/`, `\`, `:`, `>`, `<`, `?`, `*`, `"`. Case-preserving but case-insensitive for lookup. |
| 0x02  | **DOS**     | 8.3 short name. Uppercase only, no special characters, max 8+3 characters. This is the auto-generated compatibility name. |
| 0x03  | **Win32AndDos** | Special combined value. Indicates the filename is already valid as both a Win32 long name and a DOS short name. Only ONE `$FILE_NAME` attribute exists in this case. |

### 1.3 When Windows Generates 8.3 Names

Windows generates a separate DOS (0x02) `$FILE_NAME` attribute alongside the Win32 (0x01)
attribute when:

- The long filename exceeds 8 characters (base) or 3 characters (extension)
- The long filename contains characters invalid in DOS (spaces, multiple dots, etc.)
- The long filename contains lowercase characters (DOS names are uppercase-only)

When the filename is already 8.3-compliant AND uppercase, Windows stores a single
`$FILE_NAME` with namespace 0x03 (Win32AndDos) -- no separate DOS name is created.

When the filename is 8.3-compliant but uses mixed case (e.g., `TextFile.Txt`), Windows stores:
- A Win32 (0x01) attribute with `TextFile.Txt`
- A DOS (0x02) attribute with `TEXTFILE.TXT`

**Result**: A typical MFT entry contains either:
- **One** `$FILE_NAME` with namespace=3 (Win32AndDos) -- the name is already 8.3-compliant
- **Two** `$FILE_NAME` attributes: namespace=1 (Win32) + namespace=2 (DOS)
- Additional `$FILE_NAME` attributes for hard links (each with its own parent reference)

### 1.4 The 8.3 Name Generation Algorithm

Windows uses a multi-stage algorithm in `ntfs.sys` to generate short names:

**Stage 1 -- Pre-processing:**
1. Strip all characters invalid in DOS names
2. Remove all periods except the last one
3. Convert to uppercase
4. Replace `+` and some special characters with `_`
5. Truncate extension to 3 characters

**Stage 2 -- Simple tilde mangling (~1 through ~4):**
1. Truncate basename to 6 characters
2. Append `~1` (e.g., `SomeStuff.aspx` -> `SOMEST~1.ASP`)
3. If `~1` collides with existing file in same directory, try `~2`, `~3`, `~4`

**Stage 3 -- Hash-based mangling (after ~4 exhausted):**
1. Truncate basename to 2 characters
2. Insert 4 hex digits from an undocumented hash of the long filename
3. Append `~1` (e.g., `SomeStuff.aspx` -> `SOBC84~1.ASP`)

The hash function was reverse-engineered from `ntfs.sys` and uses the magic constant
`0x12b9b0a5` (314159269 -- first 8 digits of pi with the 9th digit intentionally wrong),
characteristic of a Linear Congruential Generator (LCG). The hash was updated in Windows 7
to reduce collisions; earlier versions used a different algorithm.

**Stage 4 -- Overflow:**
If hash-based names also collide, Windows increments the tilde suffix (`~2` through `~9`),
then starts truncating further: `TEB00~10.TXT` -> `TEB0~100.TXT` -> etc.

### 1.5 Controlling 8.3 Name Generation

The registry key `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisable8dot3NameCreation`
controls whether short names are generated:

| Value | Behavior |
|-------|----------|
| 0     | Enable 8.3 creation on all volumes (default on older Windows) |
| 1     | Disable on all volumes |
| 2     | Per-volume setting (set via `fsutil 8dot3name set <volume> <0\|1>`) |
| 3     | Disable on all volumes except the system volume |

Note: Disabling only affects *new* files. Existing short names persist until explicitly
stripped via `fsutil 8dot3name strip`.

---

## 2. Malware Abuse Techniques

### 2.1 Path Obfuscation to Bypass String-Based Detection

The most common abuse is referencing malicious files via their 8.3 short name to evade
detection rules that pattern-match on long filenames or paths.

**Example:**
```
# Detection rule looking for:
C:\Program Files\Internet Explorer\iexplore.exe

# Attacker invokes as:
C:\PROGRA~1\INTERN~1\iexplore.exe

# Or even more obfuscated with custom short names:
C:\PROGRA~1\INTERN~1\IEXPLO~1.EXE
```

Security tools that check process image paths, command-line arguments, or registry values
against known patterns will miss the match if they don't normalize 8.3 paths to their long
equivalents.

**Affected detection surfaces:**
- EDR/AV process monitoring (image path, command line)
- SIEM correlation rules on Sysmon Event ID 1 (Process Creation)
- Registry Run key analysis (persistence paths)
- Scheduled task arguments
- Service binary paths

### 2.2 Using 8.3 Names in Persistence Mechanisms

Attackers can write persistence entries using 8.3 paths:

```
# Registry Run key with short name path:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  "Updater" = "C:\Users\ADMINI~1\AppData\Local\Temp\UPDATE~1.EXE"

# Scheduled task with short name:
schtasks /create /tn "SystemUpdate" /tr "C:\PROGRA~2\COMMON~1\MICROS~1\svchost.exe" /sc onlogon

# Service binary path:
sc create MySvc binPath= "C:\WINDOW~1\SYSTEM~1\DRIVER~1\malware.sys"
```

The short-name path is completely valid and will execute correctly, but may not match
detection signatures that look for the full long path.

### 2.3 The `fsutil file setshortname` Technique

Administrators (and attackers with admin privileges) can set **arbitrary** short names
on any file:

```cmd
fsutil file setshortname "C:\Users\Attacker\malware.exe" SVCHOST.EXE
fsutil file setshortname "C:\Users\Attacker\backdoor.dll" KERNEL32.DLL
```

Key points:
- The custom short name does NOT need to follow the `~1` convention
- The short name does NOT need to contain a tilde at all
- This requires `SeRestorePrivilege` (typically admin/SYSTEM)
- The custom short name can be set to mimic legitimate system file names

**Forensic implication**: A file with a DOS name that does not follow the standard Windows
generation algorithm (no tilde, or a tilde pattern that doesn't match what Windows would
have generated) is a strong indicator of deliberate manipulation.

### 2.4 `NtSetInformationFile` with `FileShortNameInformation`

The NT native API `NtSetInformationFile` (class `FileShortNameInformation`, value 40) can
programmatically set arbitrary short names without using `fsutil`. This is the underlying
API that `fsutil file setshortname` calls.

Malware can use this API to:
- Set a short name that mimics a trusted system file
- Set a short name that collides with or shadows another file's short name
- Remove or change a short name to evade forensic tools that check short names

### 2.5 Extension Truncation via 8.3 Names

Because DOS names truncate extensions to 3 characters, a file with a 4+ character extension
gets a different apparent extension in its short name:

| Long Name | Short Name | Effect |
|-----------|-----------|--------|
| `script.shtml` | `SCRIPT~1.SHT` | SHTML handler not triggered; file served raw |
| `config.aspx` | `CONFIG~1.ASP` | Different handler invoked |
| `payload.docm` | `PAYLOA~1.DOC` | Macro-enabled document appears as regular .doc |

This has been exploited in web server attacks (Nginx, Cherokee, LightTPD, Apache on Windows)
to bypass file-type handling rules and serve protected content.

### 2.6 Forcing Specific `~N` Suffix Assignment

An attacker can influence which tilde suffix a target file receives by pre-creating files
that consume earlier suffixes:

```
# Create files to consume ~1 through ~3:
echo. > "C:\temp\important_document_1.txt"  # gets IMPORT~1.TXT
echo. > "C:\temp\important_document_2.txt"  # gets IMPORT~2.TXT
echo. > "C:\temp\important_document_3.txt"  # gets IMPORT~3.TXT

# Now the malicious file gets a specific suffix:
copy malware.exe "C:\temp\important_document_4.exe"  # gets IMPORT~4.EXE
```

This can be used to ensure a specific short name is assigned, potentially shadowing a
known-good short name or matching a detection allowlist entry.

---

## 3. Forensic Detection Opportunities

### 3.1 Anomalous Short Name Patterns

**What to flag:**

| Anomaly | Severity | Description |
|---------|----------|-------------|
| DOS name doesn't follow standard generation rules | HIGH | Short name doesn't match what Windows would auto-generate for the long name (e.g., no tilde, wrong hash, wrong truncation) |
| File has only DOS namespace (0x02) with no Win32 (0x01) | HIGH | Extremely unusual -- almost never occurs naturally. May indicate direct manipulation of MFT records. |
| DOS name mimics a system file name | HIGH | Short name is `SVCHOST`, `CSRSS`, `LSASS`, `KERNEL32`, etc. but long name is unrelated |
| Win32AndDos (0x03) namespace on a name that isn't 8.3-compliant | MEDIUM | Indicates MFT corruption or manual manipulation |
| Short name has no tilde but long name would require one | HIGH | Custom short name was set via `fsutil` or `NtSetInformationFile` |
| Multiple `$FILE_NAME` attributes beyond the expected Win32+DOS pair | MEDIUM | May indicate hard links used for obfuscation, or POSIX names |

### 3.2 Timestamp Anomalies Between Win32 and DOS `$FILE_NAME` Attributes

Each `$FILE_NAME` attribute has its own set of four timestamps. Normally, the Win32 and
DOS `$FILE_NAME` attributes are created simultaneously and have **identical** timestamps.

**Anomalies to detect:**

- **Timestamps differ between Win32 and DOS `$FILE_NAME`**: If the DOS name was changed
  after file creation (via `fsutil file setshortname`), the DOS `$FILE_NAME`'s timestamps
  will reflect the time of the short name change, while the Win32 `$FILE_NAME`'s timestamps
  reflect original file creation. A divergence here is a strong indicator of post-creation
  short name manipulation.

- **DOS `$FILE_NAME` timestamps newer than Win32 `$FILE_NAME`**: This is especially
  suspicious -- it means the short name was (re-)created after the file already existed.

### 3.3 Directories with Disabled 8.3 Generation

If `NtfsDisable8dot3NameCreation` is set to 1 or 3, files created after that point will
have only a Win32AndDos (0x03) namespace attribute, even for long filenames. Conversely,
if you find files WITH DOS short names in a directory where most files lack them, those
files may have been:
- Created before 8.3 was disabled (normal)
- Had short names manually assigned (suspicious if the file is newer)

### 3.4 Short Names in Suspicious Locations

Flag short name usage in:
- Registry Run/RunOnce keys
- Scheduled task actions
- Service binary paths (`ImagePath`)
- WMI event consumer scripts
- Startup folder shortcuts

The Sigma rules `proc_creation_win_susp_ntfs_short_name_path_use_cli.yml` and
`proc_creation_win_susp_ntfs_short_name_path_use_image.yml` detect tilde patterns
(`~1` through `~2`) in process command lines and image paths, mapped to MITRE ATT&CK
T1564.004 (Hide Artifacts: NTFS File Attributes).

### 3.5 Cross-Artifact Validation

The short name provides an additional data point for cross-artifact validation:

- If a persistence mechanism references `C:\PROGRA~1\SUBFOL~1\MALWAR~1.EXE`, resolve
  both the long AND short names and verify they point to the same file
- Compare short names found in registry/scheduled tasks against the actual DOS name stored
  in the MFT -- a mismatch means either the file was renamed, the short name was changed,
  or the reference is stale/fabricated
- Check if the short name in the MFT matches what Windows would have generated for the
  given long name in that directory context

---

## 4. Real-World Examples and CVEs

### 4.1 CVE-2012-4774 -- Windows Filename Parsing Vulnerability (MS12-081)

**Severity**: Critical (remote code execution)
**Affected**: Windows XP SP2/SP3, Server 2003 SP2, Vista SP2, Server 2008 SP2/R2, Windows 7

A vulnerability in how Windows handles files with specially crafted names (related to short
filename processing) allowed remote code execution. The security update modified how Windows
handles files with specially crafted names.

**Reference**: [MS12-081 Security Bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-081) |
[CVE-2012-4774 NVD](https://nvd.nist.gov/vuln/detail/CVE-2012-4774)

### 4.2 CWE-58: Path Equivalence -- Windows 8.3 Filename

Formally cataloged weakness covering the class of vulnerabilities where security mechanisms
restrict access to long filenames but fail to restrict the equivalent 8.3 short name.

**Observed CVEs under this CWE** (from [CVEDetails](https://www.cvedetails.com/cwe-details/58/Path-Equivalence-Windows-8.3-Filename.html)):
- Multiple web server bypasses (Nginx, Cherokee, Mongoose, LightTPD on Windows)
- IIS short name enumeration (information disclosure, first discovered 2010, still
  exploitable on IIS 10 / Windows Server 2022)

### 4.3 CoreLabs Advisory: Multiple Web Server 8.3 Pseudonym Vulnerabilities

CoreSecurity published a comprehensive advisory documenting how multiple web servers
(Nginx, Cherokee, Mongoose, LightTPD) on Windows failed to properly handle 8.3 aliases,
allowing security bypass of file handling rules, IP restrictions, and authentication.

**Reference**: [CoreLabs Advisory](https://www.coresecurity.com/core-labs/advisories/filename-pseudonyms-vulnerabilities)

### 4.4 IIS Tilde Enumeration (Ongoing)

The IIS short name enumeration vulnerability (using `~` character in HTTP requests) was
discovered in 2010 and remains exploitable. Microsoft considers it a configuration issue
and has not patched it. The [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
tool can detect vulnerable servers.

### 4.5 Short Name Usage in Malware / Living-off-the-Land

While no major published APT campaign has been attributed to primarily using 8.3 names
as its core evasion technique, the technique is recognized in the security community:

- **Sigma rules exist** specifically for detecting short name usage in command lines and
  process image paths, indicating observed real-world abuse
- **FortiSIEM** includes dedicated detection rules for 8.3 name abuse
- **MITRE ATT&CK T1564.004** (Hide Artifacts: NTFS File Attributes) covers the broader
  category of NTFS attribute abuse for evasion
- **MITRE ATT&CK T1036** (Masquerading) covers the related technique of making files
  appear as legitimate system files, which short name manipulation enables
- **GootKit malware** has been observed using path obfuscation techniques (including
  `PROGRA~1` style paths) to set Windows Defender exclusions

The technique is most commonly seen as a **supplementary evasion layer** combined with
other techniques (timestomping, ADS abuse, masquerading), rather than as a primary
attack vector.

---

## 5. What the `mft` Crate Actually Does

### 5.1 `find_best_name_attribute()` Implementation

The `mft` crate (v0.6.1, `omerbenamram/mft`) implements `find_best_name_attribute()` on
`MftEntry` as follows (from `src/entry.rs`, lines 220-239):

```rust
pub fn find_best_name_attribute(&self) -> Option<FileNameAttr> {
    let file_name_attributes: Vec<FileNameAttr> = self
        .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
        .filter_map(Result::ok)
        .filter_map(|a| a.data.into_file_name())
        .collect();

    // Try to find a human-readable filename first
    let win32_filename = file_name_attributes
        .iter()
        .find(|a| [FileNamespace::Win32, FileNamespace::Win32AndDos].contains(&a.namespace));

    match win32_filename {
        Some(filename) => Some(filename.clone()),
        None => {
            // Try to take anything
            file_name_attributes.get(0).cloned()
        }
    }
}
```

**Behavior analysis:**

1. Collects ALL `$FILE_NAME` attributes from the MFT entry
2. Looks for the FIRST one with namespace Win32 (0x01) or Win32AndDos (0x03)
3. If found, returns that (the human-readable long name)
4. If NOT found, returns the first available `$FILE_NAME` regardless of namespace
5. This means: **if only a DOS (0x02) name exists, it IS returned as fallback**
6. POSIX (0x00) names are also returned as fallback if no Win32 name exists

### 5.2 The `FileNamespace` Enum

Defined in `src/attribute/x30.rs`:

```rust
#[derive(FromPrimitive, Serialize, Clone, Debug, PartialOrd, PartialEq)]
#[repr(u8)]
pub enum FileNamespace {
    POSIX = 0,
    Win32 = 1,
    DOS = 2,
    Win32AndDos = 3,
}
```

### 5.3 The `FileNameAttr` Struct

```rust
pub struct FileNameAttr {
    pub parent: MftReference,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub mft_modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub logical_size: u64,
    pub physical_size: u64,
    pub flags: FileAttributeFlags,
    pub reparse_value: u32,
    pub name_length: u8,
    pub namespace: FileNamespace,
    pub name: String,
}
```

### 5.4 Current Issen Usage (Gap Analysis)

Currently, Issen uses `find_best_name_attribute()` in two places:

1. **`crates/rt-mft-tree/src/parse.rs`** (line 56): Gets the "best" name for tree building.
   Only stores one name per entry. Does NOT preserve the DOS short name separately.

2. **`crates/parsers/rt-parser-mft/src/lib.rs`** (line 212): Gets the "best" name for
   timeline event generation. Again, only one name.

**What is lost:**
- The DOS short name (if different from the Win32 name) is discarded
- The namespace of the chosen name is not recorded
- Timestamps from the DOS `$FILE_NAME` are lost (only Win32 `$FILE_NAME` or `$SI` timestamps
  are preserved)
- No comparison between Win32 and DOS names is performed
- No anomaly detection on namespace values is possible

### 5.5 Can We Get BOTH Names?

**Yes.** The `mft` crate's `iter_attributes_matching()` method returns ALL `$FILE_NAME`
attributes. We can collect them all and compare:

```rust
let file_name_attrs: Vec<FileNameAttr> = entry
    .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
    .filter_map(Result::ok)
    .filter_map(|a| a.data.into_file_name())
    .collect();

let win32_name = file_name_attrs.iter()
    .find(|a| matches!(a.namespace, FileNamespace::Win32 | FileNamespace::Win32AndDos));

let dos_name = file_name_attrs.iter()
    .find(|a| matches!(a.namespace, FileNamespace::DOS));
```

This gives us both names and their respective timestamps for comparison.

---

## 6. Recommendations for Issen

### 6.1 Should We Add an 8.3 Name Anomaly Heuristic?

**Yes.** The forensic value is high and the implementation cost is moderate.

### 6.2 Proposed Data Model Changes

Add to `FileNode`:

```rust
/// DOS (8.3) short name, if different from the Win32 long name.
/// `None` if namespace is Win32AndDos (name is already 8.3-compliant).
pub dos_name: Option<String>,

/// Namespace of the "best" (Win32) $FILE_NAME attribute.
pub fn_namespace: u8,

/// $FILE_NAME timestamps from the DOS attribute, if they differ from the Win32 attribute.
/// Divergence indicates the short name was set/changed after file creation.
pub dos_fn_timestamps: Option<NtfsTimestamps>,
```

### 6.3 Proposed Heuristic Rules

| Rule ID | Severity | Condition | Rationale |
|---------|----------|-----------|-----------|
| **HEUR-FN-001** | HIGH | File has only DOS (0x02) namespace, no Win32 (0x01) or Win32AndDos (0x03) | Almost never occurs naturally; indicates direct MFT manipulation |
| **HEUR-FN-002** | HIGH | DOS name doesn't match expected Windows generation for the Win32 name (no tilde, wrong pattern) | Custom short name set via `fsutil` or `NtSetInformationFile` |
| **HEUR-FN-003** | MEDIUM | DOS `$FILE_NAME` timestamps diverge from Win32 `$FILE_NAME` timestamps by >1 second | Short name was changed after file creation |
| **HEUR-FN-004** | MEDIUM | DOS name mimics a Windows system binary name (`svchost`, `csrss`, `lsass`, `services`, `smss`, `winlogon`, `explorer`) but long name doesn't | Masquerading via short name |
| **HEUR-FN-005** | LOW | File has POSIX (0x00) namespace `$FILE_NAME` | Very rare on Windows; may indicate cross-platform tool or manipulation |

### 6.4 Short Name Validation Logic

To implement HEUR-FN-002, we need a function that validates whether a DOS name is what
Windows would have generated for a given Win32 name. Simplified validation:

1. If Win32 name is already 8.3-compliant uppercase -> namespace should be Win32AndDos (0x03),
   not separate Win32+DOS
2. If separate DOS name exists, it should:
   - Be uppercase
   - Have a tilde followed by a digit (e.g., `~1`, `~2`)
   - The base before the tilde should be a prefix of the uppercased Win32 name (first 2-6 chars)
   - The extension should be the first 3 characters of the Win32 extension (uppercased)
3. If none of these patterns match, the short name was likely manually set

Note: We cannot perfectly reproduce the Windows hash-based mangling (Stage 3) because we
don't have the full directory context, but we CAN detect obviously non-standard patterns
(no tilde at all, tilde in wrong position, extension mismatch).

### 6.5 Implementation Priority

**Medium-High.** This heuristic:
- Catches a class of evasion that current heuristics completely miss
- Has very low false positive rate (anomalous short names are rare in legitimate use)
- Can be implemented incrementally (start with HEUR-FN-001 which requires no validation
  logic, just namespace checking)
- Requires changes to the MFT parsing phase to preserve both names (currently only the
  "best" name is kept)

---

## 7. References

### Primary Sources

- [NTFS $FILE_NAME Attribute Analysis](https://digitalinvestigator.blogspot.com/2022/03/the-filename-attribute.html) -- Detailed breakdown of attribute structure and namespace values
- [NTFS MFT Advanced Forensic Analysis (deaddisk)](https://www.deaddisk.com/posts/ntfs-mft-advanced-forensic-analysis-guide/) -- Comprehensive MFT forensics guide including dual-timestamp analysis
- [$STANDARD_INFORMATION vs $FILE_NAME timestamps (dfir.ru)](https://dfir.ru/2021/01/10/standard_information-vs-file_name/) -- Timestamp comparison methodology
- [NTFS Curiosities Part I: Short File Names (Microsoft Archive)](https://learn.microsoft.com/en-us/archive/blogs/adioltean/ntfs-curiosities-part-i-short-file-names) -- Microsoft engineer's explanation of short name generation
- [A Tale of Two Filenames (OSnews/tomgalvin.uk)](https://www.osnews.com/story/28621/a-tale-of-two-file-names/) -- Reverse engineering of the ntfs.sys hash algorithm for 8.3 name generation
- [8.3 Filename (Wikipedia)](https://en.wikipedia.org/wiki/8.3_filename) -- General background on the 8.3 naming convention

### Security Advisories and CVEs

- [CWE-58: Path Equivalence: Windows 8.3 Filename](https://cwe.mitre.org/data/definitions/58.html) -- MITRE CWE classification
- [CVE-2012-4774 / MS12-081](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-081) -- Critical Windows filename parsing RCE
- [Multiple Vulnerabilities with 8.3 Filename Pseudonyms (CoreLabs)](https://www.coresecurity.com/core-labs/advisories/filename-pseudonyms-vulnerabilities) -- Web server bypass via 8.3 aliases
- [IIS Short Name Enumeration (Microsoft TechCommunity)](https://techcommunity.microsoft.com/blog/iis-support-blog/iis-short-name-enumeration/3951320) -- Microsoft's guidance on IIS tilde vulnerability
- [IIS-ShortName-Scanner (GitHub)](https://github.com/irsdl/IIS-ShortName-Scanner) -- Scanner tool for IIS 8.3 disclosure

### Detection Rules

- [Sigma: Use NTFS Short Name Path in Command Line](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_ntfs_short_name_path_use_cli.yml) -- Sigma detection rule for CLI short name abuse
- [Sigma: Use NTFS Short Name Path in Image](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_ntfs_short_name_path_use_image.yml) -- Sigma detection rule for process image short name abuse
- [FortiSIEM: Windows Use NTFS Short Name in Command Line](https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_0/rules/PH_RULE_Use_NTFS_Short_Name_in_Command_Line.htm) -- FortiSIEM implementation

### MITRE ATT&CK

- [T1564.004: Hide Artifacts: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/) -- NTFS attribute abuse for evasion
- [T1036: Masquerading](https://attack.mitre.org/techniques/T1036/) -- Making files appear legitimate

### Tools and APIs

- [fsutil 8dot3name (Microsoft Docs)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-8dot3name) -- Managing 8.3 name generation settings
- [NtSetInformationFile (NtDoc)](https://ntdoc.m417z.com/ntsetinformationfile) -- Native API documentation including FileShortNameInformation class
- [mft crate (docs.rs)](https://docs.rs/mft/latest/mft/) -- Rust MFT parser documentation
- [omerbenamram/mft (GitHub)](https://github.com/omerbenamram/mft) -- MFT crate source code

### Related Research

- [Windows Short (8.3) Filenames -- A Security Nightmare? (Acunetix)](https://www.acunetix.com/blog/articles/windows-short-8-3-filenames-web-security-problem/) -- Overview of security implications
- [NTFS 8.3 Short Names -- A Primer (Guy Leech)](https://guyrleech.wordpress.com/2014/04/11/ntfs-8-3-short-names-primer/) -- Practical guide to short names
- [Resolving File Paths Using the MFT (Harel Segev)](https://harelsegev.github.io/posts/resolving-file-paths-using-the-mft/) -- Namespace-aware path resolution from MFT
- [Analysis of Hidden Data in the NTFS File System (Forensic Focus)](https://www.forensicfocus.com/articles/analysis-of-hidden-data-in-the-ntfs-file-system/) -- NTFS hiding techniques overview
