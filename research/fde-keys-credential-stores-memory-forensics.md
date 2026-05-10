# Full Disk Encryption Keys, OS Credential Stores, and Keychain Items Recoverable from Memory Dumps

> **Purpose**: Comprehensive technical reference for implementing FDE key recovery and credential extraction in a Rust-based memory forensics tool.
> **Date**: 2026-03-30

---

## Table of Contents

1. [BitLocker](#1-bitlocker)
2. [FileVault 2 (macOS)](#2-filevault-2-macos)
3. [LUKS (Linux)](#3-luks-linux)
4. [VeraCrypt / TrueCrypt](#4-veracrypt--truecrypt)
5. [macOS Keychain](#5-macos-keychain)
6. [Windows DPAPI](#6-windows-dpapi)
7. [Windows Credential Guard / LSA](#7-windows-credential-guard--lsa)
8. [macOS Plist Credential Stores](#8-macos-plist-credential-stores)
9. [SSH Agent Keys in Memory](#9-ssh-agent-keys-in-memory)
10. [Browser Credential Stores in Memory](#10-browser-credential-stores-in-memory)

---

## 1. BitLocker

### 1.1 Key Architecture

BitLocker uses a two-layer key design:

```
Key Protector(s) --> VMK (Volume Master Key) --> FVEK (Full Volume Encryption Key) --> Encrypted Data
```

- **FVEK (Full Volume Encryption Key)**: The actual key used to encrypt/decrypt disk sectors. Generated once at volume creation and never changes, even if the password is changed.
- **VMK (Volume Master Key)**: 256-bit key that wraps the FVEK. Multiple copies stored on disk, each encrypted by a different key protector.
- **Key Protectors**: Mechanisms for unlocking the VMK (TPM, password, recovery key, external key, etc.).

### 1.2 FVEK Format and Memory Layout

The FVEK metadata entry is always **512 bits (64 bytes)** total regardless of encryption mode:

| Encryption Mode | FVEK Size | Tweak Key Size | Total |
|-----------------|-----------|----------------|-------|
| AES-128-CBC | 128 bits | 128 bits (Elephant Diffuser) | 512 bits |
| AES-256-CBC | 256 bits | 256 bits (Elephant Diffuser) | 512 bits |
| AES-128-XTS | 128 bits | 128 bits | 512 bits |
| AES-256-XTS | 256 bits | 256 bits | 512 bits |

**Note**: The Elephant Diffuser was removed in Windows 8 and later. XTS-AES was introduced in Windows 10 (Fall 2015).

**Encryption mode identifiers in memory**:
- `0x0480` = XTS-AES-128
- `0x8001` = AES-256 with Diffuser (legacy)

### 1.3 VMK Structure

- VMK is always **256 bits**.
- VMK header is identified by byte sequence: `0x2C 0x00 0x00 0x00`
- Multiple VMK copies in metadata, each encrypted with a different protector.
- When decrypted, all VMK copies are identical; if they differ, decryption failed.
- VMK is encrypted using AES-CCM (for key wrapping).

### 1.4 On-Disk Metadata Format

- BitLocker volume starts with signature: **`-FVE-FS-`** (replacing standard NTFS header)
- Volume contains **3 identical metadata blocks** for redundancy
- Each FVE metadata block: block header + metadata header + array of metadata entries + padding
- FVE metadata header (v1): **48 bytes**

**Key metadata entry types**:
| Entry Type | Value Type | Description |
|------------|-----------|-------------|
| FVE Stretch Encrypted Key | `0x0001` | Stretched key entry |
| FVE Stretch Encrypted Key | `0x0003` | Alternative stretch entry |
| FVE External Key | `0x0009` | External key data |
| FVE Volume Header Block | `0x000f` | Location of unencrypted header |

### 1.5 Recovery Key Format

- **48-digit numeric code** divided into **8 groups of 6 digits**
- Format: `XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX`
- Example: `471207-278498-422125-177177-561902-537405-468088-123456`
- **Validation**: Each 6-digit group must be divisible by 11 with remainder 0
- Each group / 11 = 16-bit value; 8 groups = 128-bit key
- Key protector type for recovery password: **type 3 (Numerical password)**

### 1.6 BEK File (External Key) Structure

- Filename format: `{GUID}.BEK` where GUID matches key identifier in metadata
- File is commonly **156 bytes**
- Contains: external key identifier + **32-byte external key**
- Key protector type: **type 2 (External key)**

### 1.7 Key Protector Types

| Type ID | Protector |
|---------|-----------|
| 0 | Unknown / other |
| 1 | TPM |
| 2 | External key (USB/BEK file) |
| 3 | Numerical password (recovery key) |
| 4 | TPM + PIN |
| 5 | TPM + Startup Key |
| 6 | TPM + PIN + Startup Key |
| 7 | Public Key |
| 8 | Passphrase |
| 9 | TPM Certificate |
| 10 | CNG Protector |

### 1.8 In-Memory FVEK Storage (fvevol.sys)

When BitLocker is active, the FVEK is held decrypted in kernel memory by `fvevol.sys`. The key is located in Windows kernel pool allocations with specific pool tags that vary by Windows version:

| Windows Version | Pool Tag | Module |
|-----------------|----------|--------|
| Windows 7 | **`FVEc`** | `fvevol.sys` |
| Windows 8/8.1/10 | **`Cngb`** | `ksecdd.sys` |
| Windows 11 | **`dFVE`** | `dumpfve.sys` |

### 1.9 Memory Scan Patterns

#### Pool Tag Scanning

```rust
// Pool tags to scan for (4 bytes each, ASCII)
const POOL_TAGS: &[&[u8]] = &[
    b"FVEc",  // Windows 7
    b"Cngb",  // Windows 8/8.1/10
    b"dFVE",  // Windows 11
];
```

#### AES Key Schedule Validation

After locating pool allocations, validate AES key schedules:

- **AES-128 key schedule**: 176 bytes (11 round keys x 16 bytes)
- **AES-256 key schedule**: 240 bytes (15 round keys x 16 bytes)

**Validation algorithm** (from aeskeyfind):

1. **Entropy pre-filter**: Skip blocks where any single byte value appears > 8 times in 176-byte window
2. **Key expansion check**: Compute expected round keys from first 16/32 bytes
3. **Hamming distance**: Compare computed schedule vs actual bytes
4. **Threshold**: Accept if total bit errors below configurable threshold (resilient to memory corruption)

```rust
// Pseudocode for AES-128 key schedule validation
fn validate_aes128_schedule(data: &[u8; 176]) -> bool {
    // Step 1: Entropy check
    let mut freq = [0u16; 256];
    for &b in data.iter() {
        freq[b as usize] += 1;
        if freq[b as usize] > 8 { return false; }
    }

    // Step 2: Expand first 16 bytes as AES-128 key
    let expected = aes128_key_expansion(&data[0..16]);

    // Step 3: Hamming distance
    let bit_errors: u32 = data.iter()
        .zip(expected.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();

    bit_errors <= THRESHOLD // typically 0 for intact memory
}
```

#### Encryption Mode Prefix

Under the `dFVE` pool tag (Windows 11), the FVEK is prefaced by a **2-byte mode identifier**:
- `0x04 0x80` = XTS-AES-128

### 1.10 Volatility Plugin Output Structure

The Volatility 3 bitlocker plugin outputs:

| Field | Description |
|-------|-------------|
| PoolOffset | Memory offset of pool allocation |
| PoolTag | Which tag was matched (FVEc/Cngb/dFVE) |
| Cipher | Encryption mode (AES-128-XTS, AES-256-XTS, etc.) |
| FVEK | The Full Volume Encryption Key (hex) |
| Tweak | The XTS Tweak Key (hex) |
| PoolSize | Size of the pool allocation |

### 1.11 False Positive Considerations

- AES key schedule patterns can appear in other cryptographic operations (TLS, IPsec, etc.)
- Must validate that found keys actually correspond to BitLocker by:
  - Cross-referencing with pool tag location
  - Attempting trial decryption of a known sector
  - Checking the FVEK against the encrypted volume's metadata
- On Windows 8+, keys may be in `Cngb` pools that serve multiple CNG consumers

### 1.12 CVE-2025-21210: CrashXTS Vulnerability

A vulnerability (discovered by Maxim Suhanov) allows an attacker with physical access to manipulate the `DumpFilters` registry key, disabling the `dumpfve.sys` crash dump filter driver, causing Windows to write an unencrypted hibernation file to disk. Microsoft patched `fvevol.sys` to ensure `dumpfve.sys` remains listed.

### 1.13 Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| [Volatility 3 bitlocker](https://github.com/lorelyai/volatility3-bitlocker) | Open source | Scans pools, validates key schedules |
| [elceef/bitlocker](https://github.com/elceef/bitlocker) | Open source | Volatility 2 plugin, FVEc pool scanning |
| [tribalchicken/volatility-bitlocker](https://github.com/tribalchicken/volatility-bitlocker) | Open source | Win7-10 support, FVEc+Cngb tags |
| [breppo/Volatility-BitLocker](https://github.com/breppo/Volatility-BitLocker) | Open source | Tested on Win7-Win10 x64 |
| [Dislocker](https://github.com/Aorimn/dislocker) | Open source | Decrypts BitLocker volumes with FVEK |
| bdemount (libbde) | Open source | Mount BitLocker volumes |
| [Elcomsoft Forensic Disk Decryptor](https://www.elcomsoft.com/efdd.html) | Commercial | Extracts keys from memory dumps |
| [Passware Kit Forensic](https://www.passware.com/) | Commercial | VMK extraction from memory |
| bitlocker2john | Open source | Extract hashes for John the Ripper |

### 1.14 References

- [forensics.wiki: BitLocker Disk Encryption](https://forensics.wiki/bitlocker_disk_encryption/)
- [libyal/libbde format documentation](https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc)
- [hackyboiz: Unlocking BitLocker Under Attack (2026)](https://hackyboiz.github.io/2026/01/22/banda/BitLocker_part1/en/)
- [Forensic Decryption of FAT BitLocker Volumes (PDF)](https://eudl.eu/pdf/10.1007/978-3-319-14289-0_2)
- [Microsoft: BitLocker Recovery Overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview)
- [Pulse Security: Extracting BitLocker Keys from a TPM](https://pulsesecurity.co.nz/articles/TPM-sniffing)
- [ScienceDirect: Forensic method for decrypting TPM-protected BitLocker using Intel DCI](https://www.sciencedirect.com/science/article/pii/S266628172300015X)

---

## 2. FileVault 2 (macOS)

### 2.1 Key Architecture

```
User Password + Hardware UID --> KEK (Key Encryption Key) --> VEK (Volume Encryption Key) --> Encrypted Data
Recovery Key ---------------/
```

- **VEK (Volume Encryption Key)**: 256-bit AES-XTS key that encrypts the volume. Created at encryption time. Never changes.
- **KEK (Key Encryption Key)**: Wraps the VEK. Protected by user password + hardware UID.
- **Recovery Key**: Alternative unwrapping path for the KEK.

### 2.2 VEK Format

- **Algorithm**: AES-XTS with 128-bit blocks and 256-bit key
- **Key Material**: Two 128-bit AES keys (key1 for data, key2 for tweak), total 256 bits
- The tweak key (key2) is derived from the volume master key and another value

### 2.3 Core Storage / APFS Key Hierarchy

#### HFS+ (Core Storage) - macOS Lion through High Sierra

Core Storage is Apple's logical volume manager introduced for FileVault 2:
- Full volume manager layer between encrypted volume and HFS+ filesystem
- Volume metadata contains encrypted key material
- Key wrapping uses AES Key Wrap (RFC 3394)

#### APFS (macOS High Sierra+)

- **Container Keybag**: Contains wrapped VEKs for each encrypted volume + location of each volume's keybag
- **Volume Keybag**: Contains one or more wrapped KEKs + optional passphrase hint
- APFS uses AES Key Wrap Specification (RFC 3394)
- Separate VEK and KEK enable multiple KEKs per VEK

#### Key Derivation for Recovery

The recovery password string (including dashes) is used with PBKDF2 and a salt from `PassphraseWrappedKEKStruct` to derive the recovery key, which decrypts the KEK, which in turn unwraps the VEK from `KEKWrappedVolumeKeyStruct`.

### 2.4 Recovery Key Format

- **24 alphanumeric characters** in groups of 4, separated by dashes
- Format: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`
- Character set: uppercase letters + digits 1-9 (no zero)
- Encodes a **120-bit** recovery key
- Example: `A3B7-C4D9-E2F1-G8H5-J6K3-L9M2`

### 2.5 In-Memory VEK Storage (Kernel Memory)

On **Intel Macs without T2 chip** (pre-2018):
- VEK resides in kernel memory (`kernel_task` process) while volume is mounted
- The VMK/VEK exists at **3 locations** in kernel memory:
  1. The raw key
  2. The key schedule (aligned to page boundary, with key at start)
  3. At key schedule location + **0x430**

**Memory scan pattern**:
```
Key schedule is always aligned with the start of its page (4096 bytes)
Search for: string aligned on map boundary repeated exactly 0x430 bytes later
Memory submap has read-only permissions (r - -)
```

On **T2 / Apple Silicon Macs** (2018+):
- VEK is managed entirely within the **Secure Enclave**
- **Never exposed to CPU cores or main RAM**
- Traditional memory forensics for key recovery is **infeasible** against internal SSDs
- The Secure Enclave also enforces limited password attempt counts

### 2.6 Memory Scan Strategy (Pre-T2 Only)

```rust
// FileVault 2 VEK memory scan
fn scan_filevault_vek(memory: &[u8], page_size: usize) -> Vec<FvKey> {
    let mut candidates = Vec::new();

    // Scan page-aligned offsets
    for offset in (0..memory.len()).step_by(page_size) {
        if offset + 0x430 + 32 > memory.len() { break; }

        let block1 = &memory[offset..offset + 32];  // 256-bit key
        let block2 = &memory[offset + 0x430..offset + 0x430 + 32];

        // Check if same 32 bytes appear at offset and offset+0x430
        if block1 == block2 && is_high_entropy(block1) {
            candidates.push(FvKey {
                offset,
                key: block1.to_vec(),
            });
        }
    }
    candidates
}
```

### 2.7 Cold Boot Attack Considerations

- DRAM retains data for seconds to minutes at room temperature
- Longer with cooling (Princeton 2008 study)
- AES key schedules contain redundancy that aids recovery even with bit decay
- Cold boot attacks worked against FileVault (demonstrated 2008)
- Modern Macs with Secure Enclave mitigate this for internal storage

### 2.8 Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| [libfvde](https://github.com/libyal/libfvde) | Open source | Library to decrypt FV2 volumes (HFS+, Lion-Catalina) |
| [fvde2john](https://github.com/kholia/fvde2john) | Open source | Extract hashes for John the Ripper |
| apfs2john | Open source | For APFS-encrypted volumes |
| [volatility-filevault2](https://github.com/tribalchicken/volatility-filevault2) | Open source | Volatility plugin for VMK extraction |
| [Elcomsoft Forensic Disk Decryptor](https://blog.elcomsoft.com/2016/07/mac-os-forensics-attacking-filevault-2/) | Commercial | Memory + attack-based decryption |
| [Passware Kit](https://www.passware.com/) | Commercial | Memory-based key extraction |

### 2.9 References

- [Apple: Volume Encryption with FileVault in macOS](https://support.apple.com/guide/security/volume-encryption-with-filevault-sec4c6dc1b6e/web)
- [Analysis of FileVault 2 (Choudary, 2012)](https://www.cl.cam.ac.uk/~osc22/docs/cl_fv2_presentation_2012.pdf)
- [Security Analysis and Decryption of Lion FDE (eprint.iacr.org)](https://eprint.iacr.org/2012/374.pdf)
- [Eclectic Light: FileVault and Volume Encryption Explained (2025)](https://eclecticlight.co/2025/01/10/filevault-and-volume-encryption-explained/)
- [libfvde FVDE Format Documentation](https://github.com/libyal/libfvde/blob/main/documentation/FileVault%20Drive%20Encryption%20(FVDE).asciidoc)
- [Tribal Chicken: Extracting FileVault 2 Keys with Volatility](https://tribalchicken.net/extracting-filevault-2-keys-with-volatility/)
- [Swiftforensics: Decrypting FileVault](https://www.swiftforensics.com/2013/03/decrypting-apple-filevault-full-volume.html)

---

## 3. LUKS (Linux)

### 3.1 Key Architecture

```
User Passphrase --> PBKDF2 --> Key Slot Key --> Master Key --> dm-crypt --> Encrypted Data
```

- **Master Key**: The actual encryption key used by dm-crypt. Generated at volume creation.
- **Key Slots**: Up to 8 slots (LUKS1) or 32 (LUKS2), each capable of independently unlocking the master key.
- Each slot stores the master key encrypted with a slot-specific key derived from a user passphrase via PBKDF2.

### 3.2 Master Key Format and Size

| Cipher + Mode | Master Key Size | Notes |
|---------------|-----------------|-------|
| AES-128-XTS | 32 bytes (256 bits) | 2 x 128-bit keys (data + tweak) |
| AES-256-XTS | 64 bytes (512 bits) | 2 x 256-bit keys (data + tweak) |
| AES-256-CBC-ESSIV | 32 bytes (256 bits) | Single 256-bit key |
| Serpent-256-XTS | 64 bytes (512 bits) | 2 x 256-bit keys |
| Twofish-256-XTS | 64 bytes (512 bits) | 2 x 256-bit keys |

The master key size can be determined from the LUKS header via `cryptsetup luksDump`.

### 3.3 LUKS Header Structure

#### LUKS1 Header (first 592 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 6 | Magic: `LUKS\xba\xbe` |
| 6 | 2 | Version (0x0001) |
| 8 | 32 | Cipher name (e.g., "aes") |
| 40 | 32 | Cipher mode (e.g., "xts-plain64") |
| 72 | 32 | Hash spec (e.g., "sha256") |
| 104 | 4 | Payload offset (sectors) |
| 108 | 4 | Key bytes |
| 112 | 20 | Master key digest (PBKDF2 of master key) |
| 132 | 32 | Master key digest salt |
| 164 | 4 | Master key digest iterations |
| 168 | 40 | UUID |
| 208 | 48 x 8 | Key slot headers (8 slots) |

**Magic bytes for scanning**: `4C 55 4B 53 BA BE` ("LUKS" + 0xBABE)

#### LUKS2 Header

- JSON-based metadata area
- Header size: typically 16 KiB but configurable up to 4 MiB
- Magic: `LUKS\xba\xbe` followed by version 0x0002
- LUKS2 supports key storage in the **kernel keyring** (not directly accessible from userspace)

### 3.4 dm-crypt `crypt_config` Structure

The `struct crypt_config` in the Linux kernel (`drivers/md/dm-crypt.c`) holds the decrypted master key:

```c
struct crypt_config {
    struct dm_dev *dev;
    sector_t start;

    // ... cipher information ...
    char *cipher_auth;
    char *key_string;

    // Cipher transformation objects
    union {
        struct crypto_skcipher **tfms;      // For standard ciphers
        struct crypto_aead **tfms_aead;     // For authenticated encryption
    } cipher_tfm;

    unsigned int tfms_count;
    unsigned long cipher_flags;

    // Key-related fields
    unsigned int dmreq_start;
    unsigned int per_bio_data_size;
    unsigned long flags;
    unsigned int key_size;          // Total key size in bytes
    unsigned int key_parts;         // Independent parts (e.g., 2 for XTS)
    unsigned int key_extra_size;    // Additional keys length
    unsigned int key_mac_size;      // MAC key size for authenc
    unsigned int integrity_tag_size;
    unsigned int integrity_iv_size;
    unsigned int on_disk_tag_size;

    // ... more fields ...

    u8 key[0];  // Flexible array: key material at end of struct
};
```

**Key location**: The master key is stored as a flexible array member `key[0]` at the end of the `crypt_config` structure, with `key_size` bytes of actual key data.

In older kernel versions (early dm-crypt), the structure was simpler:
```c
struct crypt_config {
    struct crypto_tfm *tfm;
    unsigned int key_size;
    u8 key[0];  // Key directly at end
};
```

### 3.5 Key Recovery Methods

#### Method 1: dmsetup (Live System, Root Access)

```bash
dmsetup table --target crypt --showkey /dev/mapper/<target>
```

Outputs master key in hex. **Caveat**: If volume key is stored in kernel keyring (LUKS2 default), this won't work from userspace due to ring3->ring0 security boundary.

#### Method 2: Memory Dump + AES Key Finding

```bash
# Dump kernel memory with LiME
insmod lime.ko "path=/tmp/memdump.raw format=raw"

# Find AES keys
aeskeyfind /tmp/memdump.raw
```

**Limitations**:
- Only works for AES; aeskeyfind cannot find Serpent or Twofish keys
- For XTS (512-bit master key), aeskeyfind finds two 256-bit keys that must be concatenated
- Verify key length with `cryptsetup luksDump`

#### Method 3: drgn Kernel Debugger

```python
# Navigate from gendisk -> dm internals -> crypt_config
import drgn

prog = drgn.Program()
prog.set_kernel()

# Find the crypt_config for the dm-crypt device
# Navigate: gendisk -> dm_table -> dm_target -> crypt_config
cc = find_crypt_config(prog, "dm-0")
key_hex = cc.key.read_(cc.key_size.value_()).hex()
print(f"Master key: {key_hex}")
```

#### Method 4: Volatility dm_dump Plugin

Identifies dm-crypt mounted devices and extracts arguments needed to remount with `dmsetup`.

### 3.6 Memory Scan Patterns

For scanning raw memory dumps:

```rust
// LUKS header magic for on-disk detection
const LUKS_MAGIC: &[u8] = &[0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE];

// For in-memory key detection, use AES key schedule validation
// Same algorithm as BitLocker section (aeskeyfind approach)
// Key sizes: 32 bytes (AES-256-CBC) or 64 bytes (AES-256-XTS)

// For Serpent keys: use byte-run heuristics (Interrogate tool approach)
// Serpent key schedule: 33 round keys x 16 bytes = 528 bytes total
// Uses bitslice S-boxes, distinctive memory pattern

// For Twofish keys: look for 4KB MK table
// Twofish key-dependent S-boxes produce a 4096-byte table
// Use byte-run counting heuristics for identification
```

### 3.7 Key Wiping

When dm-crypt device is closed (`cryptsetup close` or `luksSuspend`), the master key is **wiped from kernel memory**. This limits the window for memory-based key recovery to when the device is actively mounted.

### 3.8 False Positive Considerations

- AES key schedules are common in kernel memory (TLS, IPsec, dm-crypt)
- Must correlate found keys with active dm-crypt devices
- For LUKS2 with kernel keyring storage, keys may not be directly in `crypt_config`
- Multiple AES keys found may belong to different subsystems

### 3.9 Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| [aeskeyfind](https://www.kali.org/tools/aeskeyfind/) | Open source | AES key schedule scanner |
| [findaes](https://sourceforge.net/projects/findaes/) | Open source | AES-128/192/256 key finder |
| [aes-finder](https://github.com/mmozeiko/aes-finder) | Open source | Fast AES key finder for running processes |
| [Interrogate](https://dfrws.org/sites/default/files/session-files/2009_USA_paper-the_persistence_of_memory_-_forensic_identification_and_extraction_of_cryptographic_keys.pdf) | Research | AES + Serpent + Twofish key recovery |
| [drgn](https://drgn.readthedocs.io/en/latest/case_studies/dm_crypt_key.html) | Open source | Kernel debugger for key extraction |
| [LiME](https://github.com/504ensicsLabs/LiME) | Open source | Linux memory extractor |
| cryptsetup luksDump | Built-in | Dumps LUKS header metadata |
| Elcomsoft EDPR | Commercial | Password recovery |

### 3.10 References

- [Linux Kernel: dm-crypt.c source](https://github.com/torvalds/linux/blob/master/drivers/md/dm-crypt.c)
- [drgn: Recovering a dm-crypt Encryption Key](https://drgn.readthedocs.io/en/latest/case_studies/dm_crypt_key.html)
- [Linux Kernel Documentation: dm-crypt](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html)
- [DFRWS 2009: The Persistence of Memory (Maartmann-Moe et al.)](https://www.sciencedirect.com/science/article/pii/S1742287609000486)
- [Wikipedia: LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup)
- [RAM is Key: Extracting Disk Encryption Keys from Volatile Memory (Kaplan)](https://cryptome.org/0003/RAMisKey.pdf)

---

## 4. VeraCrypt / TrueCrypt

### 4.1 Volume Header Format

The volume header occupies the **first 512 bytes** of a VeraCrypt/TrueCrypt volume:

| Offset | Size | Encrypted? | Description |
|--------|------|-----------|-------------|
| 0 | 64 bytes | No | **Salt** (512 bits, random) |
| 64 | 4 bytes | Yes | **Magic**: "VERA" (VeraCrypt) or "TRUE" (TrueCrypt) |
| 68 | ... | Yes | Header version, minimum version, etc. |
| 256 | Variable | Yes | **Master keys** (encrypted) |

**Critical**: Until decrypted, the entire volume (including header) appears as random data. There are **no magic bytes or signatures** in the encrypted form.

**Decryption validation**: If first 4 bytes of decrypted header = ASCII `"VERA"` (or `"TRUE"`) AND CRC-32 of last 256 bytes matches value at byte #8, decryption is successful.

### 4.2 Hidden Volume Header

- Located at byte offset **65536** of the host volume
- Same layout as standard volume header
- If no hidden volume exists, bytes 65536-131071 contain random data (indistinguishable)

### 4.3 Backup Header

- Located at **end of volume**
- Same format but encrypted with **different header key** derived from **different salt**

### 4.4 Key Derivation

- **Method**: PBKDF2 (PKCS #5 v2.0) or Argon2id (VeraCrypt only, newer)
- **Salt**: 512 bits (64 bytes) from the volume header

**Iteration counts**:

| Configuration | TrueCrypt | VeraCrypt |
|--------------|-----------|-----------|
| System, SHA-256 | 1,000 (RIPEMD-160) | 200,000 |
| System, SHA-512/Whirlpool | N/A | 500,000 |
| Non-system, any hash | 1,000-2,000 | 500,000 |

**PIM (Personal Iterations Multiplier)** in VeraCrypt:
- System (non-SHA-512/Whirlpool): `PIM x 2048`
- System (SHA-512/Whirlpool): `15000 + (PIM x 1000)`
- Non-system: `15000 + (PIM x 1000)`

**Available PRFs**: HMAC-SHA-512, HMAC-SHA-256, HMAC-Whirlpool, HMAC-BLAKE2s-256, HMAC-Streebog (VeraCrypt only)

### 4.5 Master Key Structure

For XTS mode (default), the master key consists of:

| Component | Size | Purpose |
|-----------|------|---------|
| Primary key | 256 bits | Data encryption |
| Secondary key (XTS) | 256 bits | Tweak encryption |
| **Total** | **512 bits (64 bytes)** | Complete key material |

For cascade ciphers (e.g., AES-Twofish-Serpent):
- Multiple concatenated key pairs
- Up to **3 x 512 bits = 1536 bits (192 bytes)** for triple cascades

### 4.6 In-Memory Key Storage

The master key **must remain in RAM** while a volume is mounted (for transparent encryption/decryption). This is the fundamental forensic attack surface.

#### VeraCrypt 1.24+ RAM Encryption (Countermeasure)

Since version 1.24 (2019), VeraCrypt optionally encrypts master keys in RAM on x86-64 Windows:
- Keys encrypted with a RAM-specific key
- Keys re-encrypted when a new device is connected (optional "panic" feature)
- Memory cleared on new device insertion (optional, causes BSOD)
- **Only Elcomsoft Forensic Disk Decryptor 2.18+** can extract these protected keys

### 4.7 Memory Scan Patterns

#### Approach 1: AES Key Schedule Detection (aeskeyfind)

Same algorithm as described in BitLocker and LUKS sections. Works for AES-based volumes.

#### Approach 2: Volatility CRYPTO_INFO Structure Detection

The Volatility `truecryptmaster` plugin locates the `CRYPTO_INFO` structure in driver memory:

```c
// TrueCrypt/VeraCrypt CRYPTO_INFO structure (simplified)
typedef struct {
    int mode;           // 1=XTS, 2=LRW, 3=CBC
    // ... cipher parameters ...
    unsigned char master_keydata[MASTER_KEYDATA_SIZE]; // 64 bytes for AES-XTS
    unsigned char k2[MASTER_KEYDATA_SIZE];             // Secondary key for XTS
    // ... key schedule data ...
} CRYPTO_INFO;
```

The plugin uses structure-based detection (not key schedule patterns), so it works with **any cipher** (AES, Serpent, Twofish, cascades).

**Volatility plugin version support**:
- `truecryptsummary`: TrueCrypt 3.1a+ (2005)
- `truecryptmaster`: TrueCrypt 6.3a+ (2009)
- **Not available in Volatility 3** (only Volatility 2.6)

#### Approach 3: Windows Cache Manager

Once a TrueCrypt/VeraCrypt volume is mounted, files accessed on it are cached by the Windows Cache Manager in **plaintext**. Volatility's `dumpfiles` plugin can recover:
- `$Mft`, `$MftMirr`, `$Directory` (NTFS metadata)
- Recently accessed user files

### 4.8 False Positive Considerations

- No magic bytes in encrypted form = cannot identify VeraCrypt volumes without attempting decryption
- AES key schedules from other sources may be mistaken for VeraCrypt keys
- CRYPTO_INFO structure detection is more reliable but requires version-specific offsets
- VeraCrypt 1.24+ RAM encryption creates additional challenge for key extraction

### 4.9 Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| Volatility truecryptmaster | Open source | CRYPTO_INFO structure detection, any cipher |
| Volatility truecryptsummary | Open source | Volume identification and summary |
| [aeskeyfind](https://www.kali.org/tools/aeskeyfind/) | Open source | AES-only key schedule detection |
| [Elcomsoft Forensic Disk Decryptor](https://blog.elcomsoft.com/2021/06/breaking-veracrypt-obtaining-and-extracting-on-the-fly-encryption-keys/) | Commercial | Supports VeraCrypt 1.24+ RAM encryption |
| [Passware Kit Forensic](https://www.forensicfocus.com/articles/how-to-efficiently-decrypt-truecrypt-veracrypt-encryption-using-passware/) | Commercial | Memory + brute-force approaches |
| [pytruecrypt](https://github.com/4144414D/pytruecrypt) | Open source | Volume parsing library |

### 4.10 References

- [VeraCrypt Volume Format Specification](https://veracrypt.io/en/VeraCrypt%20Volume%20Format%20Specification.html)
- [VeraCrypt Header Key Derivation](https://veracrypt.io/en/Header%20Key%20Derivation.html)
- [VeraCrypt Encryption Scheme](https://veracrypt.io/en/Encryption%20Scheme.html)
- [Volatility Labs: TrueCrypt Master Key Extraction](https://volatility-labs.blogspot.com/2014/01/truecrypt-master-key-extraction-and.html)
- [Elcomsoft: Breaking VeraCrypt](https://blog.elcomsoft.com/2021/06/breaking-veracrypt-obtaining-and-extracting-on-the-fly-encryption-keys/)
- [Raedts.biz: TrueCrypt and VeraCrypt Forensics](https://www.raedts.biz/forensics/truecrypt-and-veracrypt/)

---

## 5. macOS Keychain

### 5.1 Keychain File Format

macOS maintains three types of keychains:

| Type | Location | Encryption |
|------|----------|------------|
| **Login Keychain** | `~/Library/Keychains/login.keychain-db` | 3DES-CBC (legacy) or AES-256-GCM |
| **System Keychain** | `/Library/Keychains/System.keychain` | Decryptable with `/private/var/db/SystemKey` |
| **Local Items (iCloud)** | `~/Library/Keychains/keychain-2.db` + `user.kb` | AES-256-GCM via Secure Enclave |

#### Legacy Format (login.keychain, pre-Sierra)

- **Database header magic**: `kych` (4 bytes)
- Structure: Apple Database Header -> Schema -> Tables -> Records
- Header fields: magic (4B), version (4B), header size (4B), schema offset (4B), auth offset (4B)
- **Encryption**: 3DES-CBC-PKCS#1 with 24-byte database key

#### Modern Format (login.keychain-db, Sierra+)

- SQLite database
- Two AES-256-GCM keys:
  - **Metadata key**: Encrypts all attributes except `kSecValue` (for fast searches)
  - **Secret key**: Encrypts `kSecValueData` (the actual secret)
- Metadata key: protected by Secure Enclave, cached in Application Processor
- Secret key: requires Secure Enclave round-trip for each access

### 5.2 Keychain Item Types

| Item Class | Record Type | Content |
|------------|-------------|---------|
| Generic Passwords | `CSSM_DL_DB_RECORD_GENERIC_PASSWORD` | Application passwords, API tokens |
| Internet Passwords | `CSSM_DL_DB_RECORD_INTERNET_PASSWORD` | Website credentials (URL, user, pass) |
| Certificates | `CSSM_DL_DB_RECORD_X509_CERTIFICATE` | X.509 certificates |
| Private Keys | `CSSM_DL_DB_RECORD_PRIVATE_KEY` | RSA/EC private keys |
| Symmetric Keys | `CSSM_DL_DB_RECORD_SYMMETRIC_KEY` | AES/3DES symmetric keys |
| Secure Notes | N/A | Encrypted text notes |

### 5.3 securityd Memory Layout

The `securityd` daemon (process) manages all keychain access on macOS. Master keys reside in its process memory.

#### Key Memory Regions

- Master keys are in the **MALLOC_TINY** area (1 MB) within securityd's heap space
- The virtual memory space can be analyzed through `vmmap` of the Mach task structure
- Each Mach task contains a pointer to a virtual memory map (`vmmap`) representing the task address space

#### Master Key Pattern in Memory

```
// Search pattern in securityd heap memory
const MASTER_KEY_INDICATOR: u64 = 0x0000000000000018;

// Found in MALLOC_TINY region of securityd process
// Master key candidates are identified by this pattern
// Further deobfuscation required (see keychaindump source)
```

#### SSGP Label

- 16 bytes in length
- Used as an identifier matching the corresponding record key
- Can be used to correlate keychain items with their encryption keys in memory

### 5.4 Decryption Flow

1. Find `securityd` process in memory dump
2. Locate MALLOC_TINY heap regions (1 MB each)
3. Search for master key candidates (pattern: `0x0000000000000018`)
4. For each candidate, attempt to decrypt the Metadata Table (`CSSM_DL_DB_RECORD_METADATA`)
5. Successful decryption yields the **24-byte database key** (for 3DES)
6. Use database key to decrypt KeyBlob records from other tables
7. Decrypt individual keychain item secrets

### 5.5 Memory Scan Patterns

```rust
// Keychain master key scan strategy
struct KeychainScanner {
    // Step 1: Find securityd process in memory image
    // Step 2: Locate MALLOC_TINY regions in its vmmap
    // Step 3: Search for 0x0000000000000018 pattern
    // Step 4: Extract candidate keys and validate against keychain file
}

// Magic bytes for keychain file identification
const KEYCHAIN_MAGIC: &[u8] = b"kych";

// Database key size
const LEGACY_DB_KEY_SIZE: usize = 24; // 3DES
```

### 5.6 False Positive Considerations

- The `0x0000000000000018` pattern may appear elsewhere in memory
- Multiple master key candidates are typically found (e.g., 6 candidates in a 1 MB range)
- Validation requires attempting decryption against the actual keychain file
- Modern macOS versions with Secure Enclave make memory-based extraction significantly harder

### 5.7 Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| [chainbreaker](https://github.com/n0fate/chainbreaker) | Open source | Keychain forensic tool, needs password/master key/SystemKey |
| [keychaindump](https://github.com/juuso/keychaindump) | Open source | Extracts master key from securityd memory |
| [volafox](https://github.com/n0fate/volafox) | Open source | macOS memory forensics, keychaindump module |
| [Passware Kit](https://support.passware.com/hc/en-us/articles/4573379868567) | Commercial | Deep keychain decryption |
| [Elcomsoft Phone Breaker](https://blog.elcomsoft.com/2015/09/digging-mac-os-keychains/) | Commercial | Keychain extraction |

### 5.8 References

- [Keychain Analysis with Mac OS X Memory Forensics (Lee & Koo, 2013)](https://repo.zenk-security.com/Forensic/Keychain%20Analysis%20with%20Mac%20OS%20X%20Memory%20Forensics.pdf)
- [Passware: A Deep Dive into Apple Keychain Decryption](https://blog.passware.com/a-deep-dive-into-apple-keychain-decryption/)
- [Apple: Keychain Data Protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [HackTricks: macOS Sensitive Locations](https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-sensitive-locations.html)
- [Elcomsoft: Digging Mac OS Keychains](https://blog.elcomsoft.com/2015/09/digging-mac-os-keychains/)

---

## 6. Windows DPAPI

### 6.1 DPAPI Overview

DPAPI (Data Protection API) provides `CryptProtectData()` and `CryptUnprotectData()` for encrypting/decrypting opaque data blobs using implicit keys tied to a specific user or system.

**Used by**: Internet Explorer, Chrome, Edge, Skype, Outlook, Windows Credential Manager, WiFi keys (WEP/WPA), EFS certificates, and many more Windows applications.

### 6.2 Master Key Format and Storage

#### User Master Keys

- **Location**: `%APPDATA%\Microsoft\Protect\{SID}\{GUID}`
- **Size**: Each master key file contains a 64-byte (512-bit) master key
- **Naming**: GUID-based filenames, e.g., `{12345678-abcd-...}`
- **Protection**: Encrypted with PBKDF2-derived key from user's password (Triple-DES)
- **Backup**: Also encrypted with domain backup key (for AD environments)
- **Rotation**: New master key generated periodically; old ones retained

#### Master Key File Structure

| Section | Description |
|---------|-------------|
| Section 1 | User-encrypted Master Key (password-derived protection) |
| Section 2 | Local Encryption Key (legacy, Windows 2000 only; not used since XP) |
| Section 3 | Credential History (GUID -> CREDHIST file chain of password history) |

#### System Master Keys

- **Location**: `%SYSTEMROOT%\System32\Microsoft\Protect\S-1-5-18\{GUID}`
- Same structure as user master keys
- Decrypted using LSA DPAPI secret key (from SYSTEM registry hive, encrypted by Syskey)
- **DPAPI System Data**: 44 bytes total: version (4B) + User Cred (20B) + Machine Cred (20B)

### 6.3 DPAPI Blob Structure

Every DPAPI-encrypted blob has a consistent binary structure:

#### Magic Bytes (20-byte header)

```
01 00 00 00 D0 8C 9D DF 01 15 D1 11 8C 7A 00 C0 4F C2 97 EB
```

Breakdown:
- `01 00 00 00` = `dwVersion` (DWORD = 1, little-endian)
- `D0 8C 9D DF 01 15 D1 11 8C 7A 00 C0 4F C2 97 EB` = `guidProvider` GUID = `{df9d8cd0-1501-11d1-8c7a-00c04fc297eb}`

**Base64-encoded form starts with**: `AQAAANC...`

#### Full Blob Structure

```c
typedef struct {
    DWORD   dwVersion;          // 4 bytes - always 0x00000001
    GUID    guidProvider;       // 16 bytes - {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
    DWORD   dwMasterKeyVersion; // 4 bytes
    GUID    guidMasterKey;      // 16 bytes - GUID of master key used
    DWORD   dwFlags;            // 4 bytes
    DWORD   dwDescriptionLen;   // 4 bytes
    PWSTR   szDescription;      // Variable - human-readable description
    ALG_ID  algCrypt;           // 4 bytes - encryption algorithm
    DWORD   dwAlgCryptLen;      // 4 bytes - crypto key length
    DWORD   dwSaltLen;          // 4 bytes
    PBYTE   pbSalt;             // Variable
    DWORD   dwHmacKeyLen;       // 4 bytes
    PBYTE   pbHmackKey;         // Variable
    ALG_ID  algHash;            // 4 bytes - hash algorithm
    DWORD   dwAlgHashLen;       // 4 bytes
    DWORD   dwHmac2KeyLen;      // 4 bytes
    PBYTE   pbHmack2Key;        // Variable
    DWORD   dwDataLen;          // 4 bytes
    PBYTE   pbData;             // Variable - encrypted payload
    DWORD   dwSignLen;          // 4 bytes
    PBYTE   pbSign;             // Variable - digital signature
} DPAPI_BLOB;
```

#### Common Algorithm Identifiers

| Algorithm | Hex Value | Purpose |
|-----------|-----------|---------|
| CALG_3DES | `0x00006603` | Triple DES encryption |
| CALG_AES_256 | `0x00006610` | AES-256 encryption |
| CALG_SHA1 | `0x00008004` | SHA-1 hashing |
| CALG_SHA_512 | `0x0000800e` | SHA-512 hashing |

### 6.4 In-Memory Master Key Locations

- LSASS process caches per-logon DPAPI keys
- Running as SYSTEM allows reading master keys from LSASS memory
- Mimikatz `sekurlsa::dpapi` extracts cached DPAPI master keys from LSASS

### 6.5 Chrome/Edge Passwords via DPAPI

#### On-Disk Storage

1. Passwords stored in `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` (SQLite)
2. Each `password_value` is encrypted with AES-256-GCM
3. The AES key is wrapped with DPAPI and stored in `Local State` file under `os_crypt.encrypted_key`

#### Forensic Decryption Workflow

```
1. Extract os_crypt.encrypted_key from Local State JSON
2. Base64-decode the key
3. Strip "DPAPI" prefix (5 bytes)
4. Decrypt using CryptUnprotectData (or mimikatz with master key)
   -> yields AES-256 key
5. For each Login Data entry:
   - Extract IV (bytes 3-14 of password_value)
   - Extract ciphertext (bytes 15 to end-16)
   - Extract auth tag (last 16 bytes)
   - Decrypt with AES-256-GCM using the key and IV
```

#### In Browser Process Memory

When Chrome is running, decrypted passwords may exist in clear text in browser process memory (see Section 10 for details).

### 6.6 Memory Scan Patterns

```rust
// DPAPI blob magic bytes for scanning
const DPAPI_BLOB_MAGIC: &[u8] = &[
    0x01, 0x00, 0x00, 0x00,  // dwVersion = 1
    0xD0, 0x8C, 0x9D, 0xDF,  // guidProvider start
    0x01, 0x15, 0xD1, 0x11,
    0x8C, 0x7A, 0x00, 0xC0,
    0x4F, 0xC2, 0x97, 0xEB,  // guidProvider end
];

// DPAPI master key file header pattern
// Located in %APPDATA%\Microsoft\Protect\{SID}\
// Each file is a GUID-named master key

// To find DPAPI blobs in raw memory:
fn scan_dpapi_blobs(memory: &[u8]) -> Vec<DpapiBlob> {
    let mut results = Vec::new();
    for offset in 0..memory.len() - 20 {
        if &memory[offset..offset + 20] == DPAPI_BLOB_MAGIC {
            if let Some(blob) = parse_dpapi_blob(&memory[offset..]) {
                results.push(blob);
            }
        }
    }
    results
}
```

### 6.7 Domain-Level Attack

- Domain backup key (stored on DCs) can decrypt any user's master keys
- This key is **immutable** -- once compromised, all future DPAPI secrets are at risk
- Mimikatz: `lsadump::backupkeys /system:dc01 /export`

### 6.8 False Positive Considerations

- DPAPI magic bytes are highly specific (20-byte sequence), false positives are rare
- The `guidMasterKey` field links the blob to a specific master key file
- Verify by checking that `dwVersion` = 1 and `guidProvider` matches
- Some blobs may be in Base64 form (starts with `AQAAANC...`)

### 6.9 Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) dpapi module | Open source | Full DPAPI attack suite |
| [SharpDPAPI](https://docs.specterops.io/ghostpack-docs/SharpDPAPI-mdx/commands/blob) | Open source | .NET DPAPI decryptor |
| [pypykatz](https://github.com/skelsec/pypykatz) | Open source | Python mimikatz, DPAPI support |
| [Impacket](https://github.com/fortra/impacket) dpapi.py | Open source | DPAPI blob and master key tools |
| DPAPImk2john | Open source | Extract hashes for John the Ripper |
| [Passcape DPAPI Tools](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28) | Commercial | Full DPAPI analysis |

### 6.10 References

- [Medium: Extracting DPAPI MasterKey Data](https://medium.com/@toneillcodes/extracting-dpapi-masterkey-data-1381168ad5b8)
- [Medium: Reading DPAPI Protected Blobs](https://medium.com/@toneillcodes/decoding-dpapi-blobs-1ed9b4832cf6)
- [Medium: DPAPI Blob Hunting](https://medium.com/@toneillcodes/dpapi-blob-hunting-967d2baead6a)
- [HackTricks: DPAPI Extracting Passwords](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords)
- [Core Security: Reading DPAPI Encrypted Keys with Mimikatz](https://www.coresecurity.com/core-labs/articles/reading-dpapi-encrypted-keys-mimikatz)
- [Sygnia: What is DPAPI](https://www.sygnia.co/blog/the-downfall-of-dpapis-top-secret-weapon/)
- [insecurity.be: DPAPI In-Depth](https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/)

---

## 7. Windows Credential Guard / LSA

### 7.1 LSASS Process Memory Layout

LSASS (Local Security Authority Subsystem Service) caches credentials for SSO:

#### Security Support Providers (SSPs) and Their Credential Types

| SSP | DLL | Credential Type | Storage |
|-----|-----|----------------|---------|
| MSV1_0 | `msv1_0.dll` | NTLM hashes (NT + LM) | `LogonSessionList` in `lsasrv.dll` |
| Kerberos | `kerberos.dll` | TGTs, service tickets | Kerberos package memory |
| WDigest | `wdigest.dll` | Plaintext passwords (if enabled) | WDigest credential cache |
| CredSSP | `credssp.dll` | RDP SSO credentials | CredSSP cache |
| TSPKG | `tspkg.dll` | Terminal Services credentials | TSPkg memory |
| SSP | `msv1_0.dll` | Custom SSP credentials | SSP credential list |
| CredMan | `lsasrv.dll` | Credential Manager entries | CredMan list |
| DPAPI | `dpapisrv.dll` | DPAPI cached keys | See Section 6 |

#### In-Memory Encryption of Credentials

Credentials in LSASS are encrypted using reversible encryption:
- **NT 5.x (XP/2003)**: RC4 (`lsasrv!g_pRandomKey`) and DES-X (`lsasrv!g_pDESXKey`, `lsasrv!g_Feedback`)
- **NT 6.x (Vista+)**: 3DES (`lsasrv!h3DesKey`) and AES (`lsasrv!hAesKey`) with initialization vector (`lsasrv!InitializationVector`)

These encryption keys are found via pattern matching on `.text`/`.data` sections of `lsasrv.dll`.

### 7.2 MSV1_0 LogonSession Structure

Mimikatz and similar tools navigate these structures:

```
lsasrv!LogonSessionList     -> Doubly-linked list of LogonSessions
lsasrv!LogonSessionListCount -> ULONG, number of sessions

Each LogonSession:
  -> KIWI_MSV1_0_CREDENTIAL_LIST
    -> PRIMARY_CREDENTIAL_ENC (encrypted blob)
      -> MSV1_0_PRIMARY_CREDENTIAL (after decryption)
```

#### MSV1_0_PRIMARY_CREDENTIAL (Windows 11 24H2)

```c
typedef struct _MSV1_0_PRIMARY_CREDENTIAL_11_H24_DEC {
    // ... fields ...
    // Format flag at offset 40 distinguishes DPAPI-protected vs standard
    UCHAR NtPassword[16];  // NT hash (MD4 of Unicode password)
    UCHAR LmPassword[16];  // LM hash (if available)
    // ... additional fields ...
} MSV1_0_PRIMARY_CREDENTIAL_11_H24_DEC;
```

#### MSV1_0_SUPPLEMENTAL_CREDENTIAL (Official Microsoft)

```c
typedef struct _MSV1_0_SUPPLEMENTAL_CREDENTIAL {
    ULONG Version;
    ULONG Flags;
    UCHAR LmPassword[MSV1_0_OWF_PASSWORD_LENGTH]; // 16 bytes
    UCHAR NtPassword[MSV1_0_OWF_PASSWORD_LENGTH];  // 16 bytes
} MSV1_0_SUPPLEMENTAL_CREDENTIAL;
```

### 7.3 Credential Extraction Workflow

1. **Open LSASS process** (requires SeDebugPrivilege)
2. **Find DLLs** via PEB/LDR enumeration: `lsasrv.dll`, `msv1_0.dll`, `wdigest.dll`, `kerberos.dll`
3. **Resolve crypto keys** via signature/pattern matching in `.text`/`.data` sections
4. **Find LogonSessionList** via RIP-relative signature in `lsasrv.dll`
5. **Walk doubly-linked list** (one node per LogonSession)
6. **Decrypt credential blobs** using extracted crypto keys:
   - Auto-detect: 3DES-CBC, AES-CBC, AES-CFB, DES-X-CBC, or RC4
   - Detection based on buffer alignment and OS version

### 7.4 WDigest Plaintext Passwords

- **Enabled by default**: Windows 7, Server 2008 R2 and earlier
- **Disabled by default**: Windows 8.1, Server 2012 R2 and later
- **Registry control**: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
  - `UseLogonCredential` = 1 (enabled) / 0 (disabled)
- When enabled, plaintext passwords are stored in WDigest SSP memory

### 7.5 Kerberos Tickets in Memory

- **TGT (Ticket Granting Ticket)**: Valid for 10 hours by default
- **Service tickets**: Cached after first use
- Kerberos package in LSASS holds active tickets
- **With Credential Guard**: TGT is protected, but service tickets are not

### 7.6 Cached Domain Credentials

- Up to 10 domain credentials cached (for offline logon)
- **Registry location**: `HKLM\SECURITY\Cache` (SYSTEM-only access)
- MS-CACHEv2 format: PBKDF2(NTLM hash, username, 10240 iterations)
- Slower to crack than raw NTLM hashes

### 7.7 SAM and SECURITY Hive In-Memory

- SAM hive contains local account NT hashes
- SECURITY hive contains LSA secrets, cached credentials, DPAPI secrets
- Both loaded into memory by LSASS at boot
- Can be extracted from memory dumps

### 7.8 Credential Guard Architecture (VTL1)

```
+--------------------------------------------------+
|  VTL1 (Secure World)                             |
|  +--------------------------------------------+  |
|  | Secure Kernel (Ring 0)                      |  |
|  +--------------------------------------------+  |
|  | LsaIso.exe (Ring 3, IUM)                   |  |
|  |   - Actual credential secrets               |  |
|  |   - Auth cookies for context handles        |  |
|  |   - Protected by VBS memory isolation       |  |
|  +--------------------------------------------+  |
+--------------------------------------------------+
|  VTL0 (Normal World)                             |
|  +--------------------------------------------+  |
|  | NT Kernel (Ring 0)                          |  |
|  +--------------------------------------------+  |
|  | LSASS.exe (Ring 3)                          |  |
|  |   - Only encrypted blobs (not raw secrets)  |  |
|  |   - Context handles for ALPC/RPC to LsaIso |  |
|  +--------------------------------------------+  |
+--------------------------------------------------+
```

- **LsaIso.exe**: IUM process in VTL1 Ring 3
- LSASS and LsaIso communicate via **ALPC and RPC**
- VTL0 code (even Ring 0) **cannot read VTL1 memory**
- All binaries in VTL1 must be signed with VBS-trusted certificate
- **Protected secrets**: NTLM hashes, Kerberos TGTs
- **Not protected**: Kerberos service tickets, credentials entered after SSP installation

### 7.9 Credential Guard Bypass Techniques

| Technique | Method | Status |
|-----------|--------|--------|
| WDigest patch | Patch `g_fParameter_UseLogonCredential` and `g_IsCredGuardEnabled` in `wdigest.dll` | Works, enables plaintext caching |
| Pass-the-Challenge | Abuse LsaIso's `NtlmIumCalculateNtResponse` to crack NTLMv1 offline | Requires LSASS dump for context handle |
| Windows Downdate | Downgrade CVE-2022-34709 patch for Ring3-VTL0 to Ring3-VTL1 escalation | Patched in newer Win11 |
| SSP Installation | Install custom SSP to capture future credentials | Does not access stored hashes |

### 7.10 Memory Scan Patterns for LSASS

```rust
// Key DLLs to locate in LSASS process memory
const LSASS_DLLS: &[&str] = &[
    "lsasrv.dll",    // LogonSessionList, crypto keys
    "msv1_0.dll",    // MSV1_0 credentials, NTLM hashes
    "wdigest.dll",   // WDigest plaintext passwords
    "kerberos.dll",  // Kerberos tickets
    "dpapisrv.dll",  // DPAPI cached keys
    "tspkg.dll",     // Terminal Services credentials
    "credssp.dll",   // CredSSP credentials
];

// NT hash: 16 bytes (MD4 of UTF-16LE password)
// LM hash: 16 bytes (DES-based, legacy)
// Kerberos TGT: variable length, starts with ASN.1 APPLICATION tag

// Crypto key signatures in lsasrv.dll (version-dependent):
// NT 6.x: Search for patterns near h3DesKey, hAesKey, InitializationVector symbols
// These are resolved via pattern matching on code sections
```

### 7.11 Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Open source | sekurlsa::logonpasswords, lsadump::* |
| [pypykatz](https://github.com/skelsec/pypykatz) | Open source | Python-based LSASS parser |
| [VMkatz](https://github.com/nikaiw/VMkatz) | Open source | Extract from VM memory/disks directly |
| [KvcForensic](https://github.com/wesmar/KvcForensic) | Open source | Win11 24H2/25H2, pure Win32 |
| [lsa-whisperer](https://github.com/EvanMcBroom/lsa-whisperer) | Open source | LSA/SSP research tool |
| [secretsdump.py](https://github.com/fortra/impacket) (Impacket) | Open source | Remote credential extraction |
| ProcDump | Microsoft Sysinternals | LSASS minidump creation |
| comsvcs.dll MiniDump | Built-in Windows | `rundll32 comsvcs.dll,MiniDump` |

### 7.12 References

- [MITRE ATT&CK: T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft: How Credential Guard Works](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works)
- [Praetorian: Inside Mimikatz Pass-the-Hash (Part 2)](https://www.praetorian.com/blog/inside-mimikatz-part2/)
- [ADSecurity: Mimikatz](https://adsecurity.org/?page_id=1821)
- [ired.team: Dumping Credentials from LSASS](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-credentials-from-lsass.exe-process-memory)
- [SecurityScientist: 12 Questions About LSASS Memory](https://www.securityscientist.net/blog/12-questions-and-answers-about-lsass-memory-t1003-001/)
- [Incendium: Defeating Credential Guard](https://www.incendium.rocks/posts/Defeating-Windows-Credential-Guard/)
- [Quarkslab: Debugging IUM Processes](https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html)
- [syfuhs.net: How Credential Guard Works](https://syfuhs.net/how-windows-defender-credential-guard-works)
- [Medium: LsaIso.exe and Credential Guard](https://medium.com/@boutnaru/the-windows-process-journey-lsaiso-exe-credential-guard-key-guard-99d8d558e3b8)

---

## 8. macOS Plist Credential Stores

### 8.1 Plist File Formats

macOS uses three plist formats:
- **XML**: Human-readable, older format
- **Binary**: Default since Mac OS X 10.4, starts with magic `bplist00`
- **ASCII**: Rarely used legacy format

### 8.2 WiFi Password Storage

WiFi passwords are stored in the **System Keychain** (not directly in plists), but the known network metadata (without passwords) is in plists:

#### Known Networks Plist Locations

| File | Content |
|------|---------|
| `/Library/Preferences/com.apple.wifi.known-networks.plist` | SSIDs, security type, timestamps (added, joined, disconnected, last updated) |
| `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` | Network list with AddReason, JoinedByUserAt, JoinedBySystemAt |
| iOS: `/private/var/preferences/com.apple.wifi.known-networks.plist` | Mobile known networks |

**Forensic value**: These plists record:
- SSID of all known networks
- Whether network was user-joined or system-auto-joined
- Whether synced from another device (via iCloud)
- Historical timestamps going back years (some synced networks > 10 years old)

The actual WiFi passwords are in the **System Keychain** (`/Library/Keychains/System.keychain`), decryptable with the System Master Key (`/private/var/db/SystemKey`).

### 8.3 Other Credential-Bearing Plists

| Plist | Content |
|-------|---------|
| `/etc/kcpassword` | Autologin password (XOR-encoded with multi-byte key) |
| `~/Library/Preferences/com.apple.loginwindow.plist` | Autologin settings |
| Various `/Library/Managed Preferences/` | MDM-deployed credentials |
| `/var/db/auth.db` | AuthorizationDB (SQLite, authorization rules) |

#### Autologin Password Decryption

When autologin is enabled, macOS stores the password in `/etc/kcpassword`, XOR-encoded with a known multi-byte key. The `kcpass.py` tool can decode it.

### 8.4 Memory Forensics for Plists

#### Binary Plist in Memory

- **Magic number**: `bplist00` (8 bytes)
- Variable length; no simple footer for binary format
- Can be carved from memory dumps using `foremost` with the `bplist00` header

#### XML Plist in Memory

- Header: `<?xml` or `<plist` tags
- Footer: `</plist>`
- Easier to carve than binary format

#### Memory Carving Results

Running `foremost` against a macOS memory image can extract:
- 10,000+ binary plists
- 12,000+ XML plists
- Search keyword `KnownNetworks` in carved output for WiFi connection data

### 8.5 Memory Scan Patterns

```rust
// Binary plist magic
const BPLIST_MAGIC: &[u8] = b"bplist00";

// XML plist markers
const XML_PLIST_START: &[u8] = b"<plist";
const XML_PLIST_END: &[u8] = b"</plist>";

// WiFi-specific search strings in memory
const WIFI_KEYWORDS: &[&str] = &[
    "KnownNetworks",
    "com.apple.wifi",
    "SSIDString",
    "JoinedByUserAt",
    "JoinedBySystemAt",
];

// Autologin password XOR key (known static key)
// Used by kcpassword encoding
```

### 8.6 Parsing Tools

| Tool | Purpose |
|------|---------|
| `plutil` | Native macOS plist parser |
| Python `plistlib` | Standard library plist decoder |
| `binplist` + `Construct` | Python binary plist parsing |
| `foremost` | Carve plists from memory dumps |
| PlistEdit Pro | GUI binary plist viewer |

### 8.7 References

- [mac4n6.com: Plist Tag](https://www.mac4n6.com/blog/tag/plist)
- [Medium: macOS Forensics 102 - Hidden Plists](https://medium.com/@jakeperalta7/macos-forensics-102-5b65acb0468d)
- [forensafe.com: Apple Known WiFi Networks](https://forensafe.com/blogs/AppleKnownWifi.html)
- [Forensic Focus: Apple Property List vs Windows Registry](https://www.forensicfocus.com/articles/apple-property-list-comparing-the-mac-os-x-property-list-to-the-windows-registry/)
- [SANS: Mac OS Forensics RAM Acquisition](https://www.sans.org/blog/mac-os-forensics-how-to-simple-ram-acquisition-and-analysis-with-mac-memory-reader-part-2)

---

## 9. SSH Agent Keys in Memory

### 9.1 OpenSSH Pre-8.0: Plaintext Keys in Memory

Before June 2019, `ssh-agent` stored private keys in **plaintext** in heap memory.

**Memory layout**:
- Keys stored in stack/heap as serialized `sshkey` structures
- Format differs from on-disk SSH key format
- Identifiable by key type strings: `"ssh-rsa"`, `"ssh-ed25519"`, `"ecdsa-sha2-nistp256"`

**Extraction tools**:
- **[ssh-keyfinder](https://github.com/Kracken256/ssh-keyfinder)**: Automated extraction from ssh-agent, supports RSA, ECDSA, DSA
- **parse_mem.py** (from NetSPI): Parses memory dump for valid RSA SSH keys using pyasn1
- **Volatility**: Extract stack of ssh-agent process

### 9.2 OpenSSH 8.0+: Shielded Private Keys

Since OpenSSH 8.1 (June 2019), keys are **shielded** in memory:

#### Shielding Mechanism

```
1. Generate pre_key: 16 KiB (16,384 bytes) of random data via arc4random_buf()
2. Derive encryption key: SHA-512(pre_key) -> first 32 bytes = AES-256-CTR key
3. Encrypt (shield) the private key with AES-256-CTR
4. Store in sshkey struct:
   - public key (plaintext)
   - shielded_private (encrypted private key blob)
   - shield_prekey (the 16 KiB pre_key)
5. Zero all intermediates: cipher context, derived key, IV, old sshkey structs
6. Re-shield with NEW pre_key after every use
```

#### Memory Layout of Shielded Identity

```c
struct Identity {
    char *comment;        // Key comment string
    struct sshkey *key;   // Points to shielded key struct
    // ...
};

struct sshkey {
    // ... public key fields ...
    u_char *shielded_private;  // AES-256-CTR encrypted private key
    size_t shielded_len;
    u_char *shield_prekey;     // 16 KiB random pre_key
    size_t shield_prekey_len;  // Always 16384
};
```

#### Extraction of Shielded Keys (Root/Debug Access)

With full memory access, both `shielded_private` and `shield_prekey` reside in the same process:

1. Find key comment string in heap memory
2. Follow cross-references to locate `Identity` struct
3. Extract `shielded_private` and `shield_prekey`
4. Call `sshkey_unshield_private()` to decrypt
5. Call `sshkey_save_private()` to save plaintext key

**Tools**: gdb + gcore for process dump, Ghidra for analysis, or compile ssh-keygen with symbols and use gdb to call unshield functions directly.

### 9.3 Windows OpenSSH Agent (ssh-agent service)

On Windows 10+, the built-in OpenSSH ssh-agent stores private keys:
- **Protected with DPAPI** (CryptProtectData)
- **Stored in HKCU registry** hive
- After DPAPI decryption, the binary format matches Linux ssh-agent's memory format
- Contains `"ssh-rsa"` string visible in decoded data

### 9.4 Pageant (PuTTY SSH Agent)

- Holds private keys in **plaintext** in memory (no shielding)
- Keys already decoded for immediate use
- Windows allows other processes to read Pageant's memory via debug APIs
- Any malicious program can extract keys from Pageant process memory

### 9.5 Memory Scan Patterns

```rust
// SSH key type identifiers in memory
const SSH_KEY_TYPES: &[&[u8]] = &[
    b"ssh-rsa",
    b"ssh-ed25519",
    b"ecdsa-sha2-nistp256",
    b"ecdsa-sha2-nistp384",
    b"ecdsa-sha2-nistp521",
    b"ssh-dss",
];

// For pre-8.0 OpenSSH: search for key type strings followed by key material
// For 8.0+: search for key type strings, then locate Identity struct
//   - shield_prekey_len will be 16384 (0x00004000)
//   - shielded_private is nearby in heap

// Pageant keys: search for key type strings in Pageant process memory
// Keys are in plaintext immediately following the type string

// Windows ssh-agent: search for DPAPI blob magic in registry data
// After DPAPI decryption, look for "ssh-rsa" etc.
```

### 9.6 False Positive Considerations

- SSH key type strings appear in many contexts (known_hosts, authorized_keys, config files)
- Must validate structure around the string (length-prefixed fields, valid key parameters)
- For RSA: validate that e, n, d, p, q values are reasonable (correct bit lengths)
- Shield_prekey is 16 KiB of high-entropy data -- distinctive size signature

### 9.7 Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| [ssh-keyfinder](https://github.com/Kracken256/ssh-keyfinder) | Open source | Automated extraction from ssh-agent |
| [HN Security shielded extraction](https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/) | Research | gdb/Ghidra technique for 8.0+ |
| parse_mem.py (NetSPI) | Open source | RSA key parser from memory dumps |
| Volatility linux_ssh_agent | Open source | Process memory extraction |
| [ropnop: Windows SSH Key Extraction](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/) | Research | DPAPI-based Windows extraction |

### 9.8 References

- [HN Security: OpenSSH Shielded Private Key Extraction](https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/)
- [xorhash.gitlab.io: OpenSSH Key Shielding](https://xorhash.gitlab.io/xhblog/0010.html)
- [NetSPI: Stealing Unencrypted SSH-Agent Keys from Memory](https://www.netspi.com/blog/technical-blog/network-pentesting/stealing-unencrypted-ssh-agent-keys-from-memory/)
- [ropnop: Extracting SSH Private Keys from Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)
- [The Hacker News: OpenSSH Encrypts Secret Keys in Memory](https://thehackernews.com/2019/06/openssh-side-channel-vulnerability.html)

---

## 10. Browser Credential Stores in Memory

### 10.1 Chrome / Chromium-Based Browsers

#### Clear-Text Credentials in Process Memory

CyberArk research (2022) demonstrated that Chrome stores credentials in **clear text** in process memory:

- **Affected browsers**: Google Chrome, Microsoft Edge, Brave, Opera (all Chromium-based)
- **Data accessible**: URLs, usernames, passwords, session cookies
- **Access method**: `OpenProcess` + `ReadProcessMemory` from any non-elevated process on the same machine
- **No physical access required**: Remote access or any running malware is sufficient

#### What's in Memory

| Data Type | When Present | Memory Location |
|-----------|-------------|-----------------|
| URL + username + password (active login) | When user authenticates | Multiple chrome.exe processes |
| All saved Login Data entries | On browser startup | Browser process memory |
| Session cookies | During active session | Browser process memory |
| Form autofill data | On page load | Renderer process memory |

#### Memory Characteristics

- **Many processes**: Chrome spawns numerous processes, each with large virtual memory (some >230 GB virtual)
- **Private memory (MEM_PRIVATE)**: Despite MSDN documentation, `ReadProcessMemory` can access these pages
- **Scattered**: Components of a single credential record (URL, username, password) may be in distant memory locations
- **Persistent**: Credentials loaded at startup remain in memory until browser exit

#### Session Cookie Theft

- Session cookies extracted from memory can hijack authenticated sessions
- Bypasses MFA (session is already authenticated)
- Gmail session cookies have **2-year expiration**
- The application sees it as continuation of an authenticated session, not a new device

#### On-Disk Credential Storage

```
Chrome Profile/
  Login Data       -- SQLite: encrypted passwords (AES-256-GCM)
  Local State      -- JSON: os_crypt.encrypted_key (DPAPI-wrapped AES key)
  Cookies          -- SQLite: encrypted cookie values
```

Encryption chain: `User Password -> DPAPI Master Key -> AES Key (in Local State) -> Individual passwords/cookies`

#### Google's Response

Chromium.org stated **"Won't Fix"**: "there is no way for Chrome (or any application) to defend against a malicious user who has managed to log into your device as you."

### 10.2 Firefox

#### NSS / PKCS#11 Credential Storage

- **Key database**: `key4.db` (SQLite, Firefox 58+) or `key3.db` (Berkeley DB, pre-58)
- **Encrypted logins**: `logins.json`
- **Encryption**: 3DES-CBC (pre-Firefox 73) or AES (Firefox 73+ with NSS 3.49.x)
- **Optional master password**: Protects the key material; if not set, decryption is trivial

#### Decryption Process

1. Extract encoded+encrypted "password-check" from `key4.db`
2. ASN.1 decode, then 3DES/AES decrypt
3. If master password set, derive key with PBKDF2
4. Validate decryption against password-check value
5. Use derived key to decrypt `logins.json` entries

#### Memory Behavior

- Firefox stores decrypted credentials in memory **when `about:logins` page is open**
- Credentials are cleared from memory when the page is closed (unlike Chrome)
- NSS uses **arena-based memory management** with zeroing on free
- However, academic research shows credentials can be recovered from VM snapshots even after page closure

#### Key Files

| File | Format | Content |
|------|--------|---------|
| `key4.db` | SQLite | Master encryption key (Firefox 58+) |
| `logins.json` | JSON | Encrypted usernames and passwords |
| `pkcs11.txt` | Text | PKCS#11 module configuration |
| `cert9.db` | SQLite | Certificate database |
| `key3.db` | Berkeley DB | Legacy key database (pre-58) |
| `cert8.db` | Berkeley DB | Legacy certificate database |

### 10.3 Safari

- Credentials stored in **macOS Keychain** (see Section 5)
- No separate credential database
- In-memory behavior governed by `securityd` and Keychain access patterns
- On T2/Apple Silicon Macs: credentials protected by Secure Enclave

### 10.4 Memory Scan Patterns

```rust
// Chrome/Chromium credential patterns in memory
// Search for URL patterns near credential data
const URL_PATTERNS: &[&[u8]] = &[
    b"https://",
    b"http://",
    b"android://",  // Android credential entries
];

// Login form action indicators
const FORM_INDICATORS: &[&[u8]] = &[
    b"password_value",
    b"username_value",
    b"login_url",
    b"signon_realm",
];

// Firefox-specific patterns
const FIREFOX_PATTERNS: &[&[u8]] = &[
    b"encryptedUsername",
    b"encryptedPassword",
    b"formSubmitURL",
    b"httpRealm",
];

// Session cookie patterns
const COOKIE_INDICATORS: &[&[u8]] = &[
    b"SID=",           // Google session
    b"HSID=",          // Google HTTPS session
    b"SSID=",          // Google secure session
    b".ASPXAUTH",      // ASP.NET auth cookie
    b"connect.sid",    // Express.js session
    b"JSESSIONID",     // Java session
    b"session_token",  // Generic session
];
```

### 10.5 Private Browsing Forensics

- Neither Chrome nor Firefox writes browsing data to disk in private mode
- **However**: Memory analysis can recover browsing history, search queries, usernames, and passwords from private browsing sessions
- In VMware environments, data recoverable even **after browser restart**
- Host OS pagefile (`pagefile.sys`) may contain browser process memory pages

### 10.6 False Positive Considerations

- URLs and username-like strings appear throughout browser memory for many purposes
- Must validate by structural analysis (correlating URL + username + password in proximity)
- Cookie data is abundant; focus on session-critical cookies
- Credential data from previous sessions may persist as "ghost" data in freed memory

### 10.7 Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| [CyberArk Chrome Extract](https://www.cyberark.com/resources/threat-research-blog/extracting-clear-text-credentials-directly-from-chromium-s-memory) | Research PoC | OpenProcess + ReadProcessMemory |
| [Hindsight](https://github.com/obsidianforensics/hindsight) | Open source | Chrome/Chromium artifact analyzer |
| [firefox_decrypt](https://github.com/unode/firefox_decrypt) | Open source | Offline Firefox password decryptor |
| [firefed](https://github.com/numirias/firefed) | Open source | Firefox profile forensics tool |
| [LaZagneForensic](https://github.com/AlessandroZ/LaZagneForensic) | Open source | Multi-browser password extractor |
| Process Hacker | Open source | Memory string search in browser processes |
| OSForensics | Commercial | Multi-browser password recovery |

### 10.8 References

- [CyberArk: Extracting Clear-Text Credentials from Chromium's Memory](https://www.cyberark.com/resources/threat-research-blog/extracting-clear-text-credentials-directly-from-chromium-s-memory)
- [CyberArk: Go BLUE! Protection Plan for Chromium Credentials](https://www.cyberark.com/resources/threat-research-blog/go-blue-a-protection-plan-for-credentials-in-chromium-based-browsers)
- [gHacks: Browser Stores Passwords in Clear Text in Memory](https://www.ghacks.net/2022/06/12/your-browser-stores-passwords-and-sensitive-data-in-clear-text-in-memory/)
- [ScienceDirect: Digital Forensic Analysis of Private Browsing](https://www.sciencedirect.com/science/article/pii/S0167404822000256)
- [ScienceDirect: Plain Text Passwords - A Forensic RAM-Raid](https://www.sciencedirect.com/science/article/abs/pii/S1355030620300137)
- [GitHub: firefox_decrypt](https://github.com/unode/firefox_decrypt)
- [GitHub: Hindsight](https://github.com/obsidianforensics/hindsight)
- [Medium: Forensic Recovery of Chrome Based Browser Passwords](https://palmenas.medium.com/forensic-recovery-of-chrome-based-browser-passwords-e8df90d4a3cd)

---

## Appendix A: Cross-Reference Summary Table

| Target | Key Size | Memory Signature | Pool Tag / Magic | Scan Method |
|--------|----------|------------------|------------------|-------------|
| BitLocker FVEK | 128 or 256 bits + tweak | AES key schedule (176/240 bytes) | FVEc / Cngb / dFVE | Pool tag scan + key schedule validation |
| FileVault VEK | 256 bits (AES-XTS) | Key at page boundary, repeated at +0x430 | N/A (kernel_task) | Page-aligned duplicate detection |
| LUKS Master Key | 32-64 bytes | AES key schedule | N/A (crypt_config) | AES key schedule + Serpent/Twofish heuristics |
| VeraCrypt Master | 512 bits (XTS) | CRYPTO_INFO struct | N/A (no magic) | Structure-based or key schedule |
| macOS Keychain | 24 bytes (3DES) / varies | `0x0000000000000018` pattern | `kych` (file) | MALLOC_TINY heap scan in securityd |
| DPAPI Blob | Variable | `01000000D08C9DDF...` (20 bytes) | N/A | Magic byte scan |
| LSASS NTLM | 16 bytes | LogonSessionList linked list | N/A | DLL pattern matching + list walk |
| SSH Agent | Key-type dependent | `ssh-rsa` / `ssh-ed25519` strings | N/A | Key type string + struct walk |
| Chrome Passwords | Variable (plaintext) | URL + credential strings | N/A | String search in browser process |
| Firefox Passwords | Variable | `encryptedUsername`/`encryptedPassword` | N/A | NSS arena scan or `about:logins` |

## Appendix B: AES Key Schedule Detection Algorithm

The core algorithm used by `aeskeyfind`, `findaes`, and similar tools:

```rust
/// Validate a candidate AES-128 key schedule in memory
/// Returns true if the 176 bytes at `data` form a valid AES-128 key schedule
fn validate_aes128_key_schedule(data: &[u8]) -> bool {
    if data.len() < 176 { return false; }

    // Pre-filter: entropy check
    let mut freq = [0u32; 256];
    for &b in &data[..176] {
        freq[b as usize] += 1;
        if freq[b as usize] > 8 { return false; } // Too many repeats
    }

    // Extract candidate key (first 16 bytes)
    let key = &data[0..16];

    // Expand key schedule
    let mut expected = [0u8; 176];
    expected[0..16].copy_from_slice(key);

    let rcon: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    for i in 1..11 {
        let prev = &expected[(i-1)*16..i*16];
        let mut next = [0u8; 16];

        // RotWord + SubBytes on last word of previous round key
        let w3 = &prev[12..16];
        let rot_sub = [
            AES_SBOX[w3[1] as usize] ^ rcon[i-1],
            AES_SBOX[w3[2] as usize],
            AES_SBOX[w3[3] as usize],
            AES_SBOX[w3[0] as usize],
        ];

        // XOR with corresponding words
        for j in 0..4 {
            next[j] = prev[j] ^ rot_sub[j];
        }
        for w in 1..4 {
            for j in 0..4 {
                next[w*4 + j] = prev[w*4 + j] ^ next[(w-1)*4 + j];
            }
        }

        expected[i*16..(i+1)*16].copy_from_slice(&next);
    }

    // Compare: Hamming distance
    let bit_errors: u32 = data[..176].iter()
        .zip(expected.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();

    bit_errors == 0 // Strict match for intact memory; relax for cold boot
}

/// Validate AES-256 key schedule (240 bytes, 15 round keys)
fn validate_aes256_key_schedule(data: &[u8]) -> bool {
    if data.len() < 240 { return false; }

    // Similar to AES-128 but with 32-byte key and additional SubBytes step
    // every 4th word (due to Nk=8 for AES-256)
    // ... (implementation follows AES-256 key expansion spec)
    todo!()
}
```

## Appendix C: Implementation Priority for Issen

Based on prevalence and forensic value, recommended implementation order:

| Priority | Module | Rationale |
|----------|--------|-----------|
| 1 | DPAPI Blob Scanner | Highly specific magic bytes, low false positives, widely used |
| 2 | BitLocker FVEK Extractor | Pool tag + AES schedule, well-documented patterns |
| 3 | LSASS Credential Parser | High-value target, complex but well-understood |
| 4 | AES Key Schedule Scanner | Generic, benefits BitLocker + LUKS + VeraCrypt |
| 5 | SSH Agent Key Finder | String-based detection, moderate complexity |
| 6 | Browser Credential Scanner | String search, high noise but high value |
| 7 | VeraCrypt CRYPTO_INFO | Structure-based, version-dependent offsets |
| 8 | macOS Keychain (securityd) | Platform-specific, complex heap analysis |
| 9 | FileVault VEK (pre-T2) | Limited to older Macs, declining relevance |
| 10 | Plist Credential Carving | Low complexity but limited credential content |
