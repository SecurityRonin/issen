# Encryption & Anti-Forensic Tools: Windows Registry Artifacts

> Exhaustive forensic reference for registry parser development.
> Research date: 2026-03-25

---

## Table of Contents

- [Part 1: Encryption Tools](#part-1-encryption-tools)
- [Part 2: Secure Wipe / Anti-Forensic Tools](#part-2-secure-wipe--anti-forensic-tools)
- [Part 3: Indirect Detection of Anti-Forensic Activity](#part-3-indirect-detection-of-anti-forensic-activity)
- [Part 4: Detecting Encrypted Volumes Without Registry Footprint](#part-4-detecting-encrypted-volumes-without-registry-footprint)

---

# Part 1: Encryption Tools

---

### 1. VeraCrypt

**Hive(s):** SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\veracrypt` | `ImagePath` | REG_EXPAND_SZ | Driver installation path (`system32\drivers\veracrypt.sys`) |
| `HKLM\SYSTEM\CurrentControlSet\Services\veracrypt` | `Start` | REG_DWORD | Driver start type (0=boot, 1=system, 2=auto, 3=manual) |
| `HKLM\SYSTEM\CurrentControlSet\Services\veracrypt` | `Type` | REG_DWORD | Service type |
| `HKLM\SYSTEM\CurrentControlSet\Services\veracrypt` | `VeraCryptEraseKeysShutdown` | REG_DWORD | If 0, disables erasing encryption keys on shutdown |
| `HKLM\SYSTEM\CurrentControlSet\Services\veracrypt` | `VeraCryptEnableMemoryProtection` | REG_DWORD | Memory protection for non-admin process reads (0=disabled) |
| `HKLM\SYSTEM\CurrentControlSet\Services\veracrypt` | `VeraCryptEncryptionFragmentSize` | REG_DWORD | Encryption data fragment size in KiB (default 256, max 2048) |
| `HKLM\SYSTEM\CurrentControlSet\Services\veracrypt` | `VeraCryptEncryptionIoRequestCount` | REG_DWORD | Max parallel I/O requests for SSD tuning |
| `HKLM\SYSTEM\MountedDevices` | `\??\Volume{GUID}` | REG_BINARY | Hex data starting with `566572614372797074566F6C756D65` decodes to "VeraCryptVolume" -- proves VC volume was mounted |
| `HKLM\SYSTEM\MountedDevices` | `\DosDevices\X:` | REG_BINARY | Drive letter assignment for mounted VC volume; same hex signature |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt` | `DisplayName` | REG_SZ | "VeraCrypt" -- proves installation |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt` | `InstallLocation` | REG_SZ | Installation directory |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt` | `UninstallString` | REG_SZ | Uninstall command |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{GUID}` | (Default) | - | LastWrite time = when volume was last mounted by this user |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{GUID}` | `MaxCapacity` | REG_DWORD | Recycle Bin size reveals VC volume capacity (10% of volume) |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | ROT-13 encoded path | REG_BINARY | VeraCrypt.exe execution count & last run time |
| ShellBags in NTUSER.DAT & UsrClass.dat | Various | Various | Folder navigation inside mounted VC volumes; persists after unmount |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | MRUListEx + entries | REG_BINARY/REG_SZ | Recently accessed files including .hc container files |

**Configuration Files (non-registry but critical):**
- `%APPDATA%\VeraCrypt\Configuration.xml` -- main settings
- `%APPDATA%\VeraCrypt\History.xml` -- last 20 volumes/devices attempted
- `%APPDATA%\VeraCrypt\Favorite Volumes.xml` -- saved favorite volumes
- `%APPDATA%\VeraCrypt\System Encryption.xml` -- system drive encryption state

**Additional Artifacts:**
- Prefetch: `VERACRYPT.EXE-{hash}.pf` and `VERACRYPT-X64.EXE-{hash}.pf`
- AmCache/ShimCache: Execution evidence with SHA1 hash
- Event Logs: Driver load events in System log

---

### 2. TrueCrypt (Legacy)

**Hive(s):** SYSTEM, SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\truecrypt` | `ImagePath` | REG_EXPAND_SZ | Driver path (`system32\drivers\truecrypt.sys`) |
| `HKLM\SYSTEM\CurrentControlSet\Services\truecrypt` | `Start` | REG_DWORD | Driver start type |
| `HKLM\SYSTEM\MountedDevices` | `\??\Volume{GUID}` | REG_BINARY | TrueCrypt volumes identifiable by hex signature (differs from VeraCrypt) |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\TrueCrypt` | `DisplayName` | REG_SZ | "TrueCrypt" -- proves installation |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\TrueCrypt` | `InstallLocation` | REG_SZ | Installation directory |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | ROT-13 (`GehrPelcg`) | REG_BINARY | "TrueCrypt" ROT-13 encoded as "GehrPelcg"; execution count & timestamps |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{GUID}` | (Default) | - | Volume mount association with user |

**Configuration Files:**
- `%APPDATA%\TrueCrypt\Configuration.xml` -- preferences; "Never save history" still leaves at least one artifact
- `IconCache.db` -- caches TrueCrypt icon references per-user

**Additional Artifacts:**
- Volatility `truecryptsummary` plugin for memory analysis
- Hibernation file (`hiberfil.sys`) may contain encryption keys
- Prefetch: `TRUECRYPT.EXE-{hash}.pf`

---

### 3. GnuPG / GPG4Win

**Hive(s):** NTUSER.DAT, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\GNU\GnuPG` | `HomeDir` | REG_SZ | Custom keyring location override; if present, keys are NOT in default location |
| `HKCU\Software\GNU\GnuPG` | (Default) | - | LastWrite = last config change |
| `HKLM\SOFTWARE\GNU\GnuPG` | (various) | - | System-wide GnuPG configuration |
| `HKLM\SOFTWARE\Gpg4win` | `Install Directory` | REG_SZ | GPG4Win installation path |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Gpg4win` | `DisplayName` | REG_SZ | Installation evidence |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\GPG4Win` | `InstallLocation` | REG_SZ | Installation directory |

**Key File Locations:**
- Default keyring: `%APPDATA%\gnupg\` (pubring.gpg, secring.gpg, trustdb.gpg)
- Private keys (GnuPG 2.x): `%APPDATA%\gnupg\private-keys-v1.d\`
- System trust: `C:\ProgramData\GNU\etc\gnupg\trustlist.txt`
- LDAP servers: `C:\ProgramData\GNU\etc\dirmngr\ldapservers.conf`

**Note:** Keyring data persists even after GPG4Win uninstallation.

---

### 4. BitLocker (Comprehensive FVE)

**Hive(s):** SOFTWARE, SYSTEM

#### Group Policy / Configuration (SOFTWARE Hive)

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `EncryptionMethod` | REG_DWORD | Encryption algorithm: 1=AES-128-Diffuser, 2=AES-256-Diffuser, 3=AES-128, 4=AES-256, 6=XTS-AES-128, 7=XTS-AES-256 |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `EncryptionMethodWithXtsOs` | REG_DWORD | OS drive encryption method (XTS variants) |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `EncryptionMethodWithXtsFdv` | REG_DWORD | Fixed data volume encryption method |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `EncryptionMethodWithXtsRdv` | REG_DWORD | Removable data volume encryption method |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `UseTPM` | REG_DWORD | TPM usage: 0=disallow, 1=require, 2=allow |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `UseTPMKey` | REG_DWORD | TPM+startup key: 0=disallow, 1=require, 2=allow |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `UseTPMKeyPIN` | REG_DWORD | TPM+key+PIN: 0=disallow, 1=require, 2=allow |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `UseTPMPIN` | REG_DWORD | TPM+PIN: 0=disallow, 1=require, 2=allow |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSRecovery` | REG_DWORD | OS drive recovery options enabled (boolean) |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSRecoveryKey` | REG_DWORD | Allow 256-bit recovery key for OS drive |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSRecoveryPassword` | REG_DWORD | Allow 48-digit recovery password for OS drive |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSActiveDirectoryBackup` | REG_DWORD | 1=backup recovery to AD DS enabled |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSHideRecoveryPage` | REG_DWORD | 0=show recovery page, 1=hide |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSRequireActiveDirectoryBackup` | REG_DWORD | 1=require AD backup before enabling BitLocker |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSActiveDirectoryInfoToStore` | REG_DWORD | What to store in AD: 1=password+key package, 2=password only |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVRecovery` | REG_DWORD | Fixed data volume recovery enabled |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVRecoveryKey` | REG_DWORD | Allow recovery key for fixed volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVRecoveryPassword` | REG_DWORD | Allow recovery password for fixed volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVActiveDirectoryBackup` | REG_DWORD | AD backup for fixed volume recovery |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `RDVRecovery` | REG_DWORD | Removable volume recovery enabled |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `IdentificationField` | REG_DWORD | Enable BitLocker identification field |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `IdentificationFieldString` | REG_SZ | BitLocker identification field string |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `SecondaryIdentificationField` | REG_SZ | Allowed BitLocker identification field |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `DefaultRecoveryFolderPath` | REG_SZ | Default recovery key save location |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSHardwareEncryption` | REG_DWORD | Hardware encryption for OS drive |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVHardwareEncryption` | REG_DWORD | Hardware encryption for fixed volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `RDVHardwareEncryption` | REG_DWORD | Hardware encryption for removable volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSAllowedHardwareEncryptionAlgorithms` | REG_SZ | Allowed hardware encryption cipher suites |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSUseEnhancedBcdProfile` | REG_DWORD | Enhanced BCD validation profile |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSBcdAdditionalExcludedSettings` | REG_MULTI_SZ | Additional BCD settings to exclude from validation |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSBcdAdditionalSecurityCriticalSettings` | REG_MULTI_SZ | Additional security-critical BCD settings |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `MorBehavior` | REG_DWORD | Memory Overwrite Request behavior |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `UseEnhancedPin` | REG_DWORD | Allow enhanced PINs with non-numeric chars |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `MinimumPIN` | REG_DWORD | Minimum PIN length |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `DisableExternalDMAUnderLock` | REG_DWORD | Block DMA ports when locked |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `EnablePrebootInputProtectorsOnSlates` | REG_DWORD | Pre-boot input on tablets |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVDiscoveryVolumeType` | REG_SZ | Discovery volume type for fixed drives |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `RDVDiscoveryVolumeType` | REG_SZ | Discovery volume type for removable drives |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVPassphrase` | REG_DWORD | Passphrase for fixed data volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `RDVPassphrase` | REG_DWORD | Passphrase for removable volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSManageDRA` | REG_DWORD | Manage Data Recovery Agent for OS drive |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVManageDRA` | REG_DWORD | Manage DRA for fixed volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `RDVManageDRA` | REG_DWORD | Manage DRA for removable volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `EnableBDEWithNoTPM` | REG_DWORD | Allow BitLocker without TPM |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `UseAdvancedStartup` | REG_DWORD | Require additional auth at startup |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSEncryptionType` | REG_DWORD | 0=full, 1=used-space-only encryption |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVEncryptionType` | REG_DWORD | Encryption type for fixed volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `RDVEncryptionType` | REG_DWORD | Encryption type for removable volumes |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `RDVDenyWriteAccess` | REG_DWORD | Deny write to removable drives not protected by BitLocker |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `RDVDenyCrossOrg` | REG_DWORD | Deny write to drives from other organizations |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `FDVDenyWriteAccess` | REG_DWORD | Deny write to unencrypted fixed drives |

**Alternative Key Path:**
| `HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE` | (same values as above) | - | Alternative policy location |

#### Operational State (SYSTEM Hive)

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus` | `BootStatus` | REG_DWORD | Boot status of BitLocker |
| `HKLM\SYSTEM\CurrentControlSet\Services\BDESVC` | `Start` | REG_DWORD | BitLocker service startup type |
| `HKLM\SYSTEM\CurrentControlSet\Services\fvevol` | `Start` | REG_DWORD | BitLocker volume driver startup (0=boot) |
| `HKLM\SYSTEM\CurrentControlSet\Services\fvevol` | `ImagePath` | REG_EXPAND_SZ | Volume filter driver path |

**PCR Validation:**
| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Policies\Microsoft\FVE\OSPlatformValidation_BIOS` | `Enabled` | REG_DWORD | PCR validation for BIOS systems |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE\OSPlatformValidation_UEFI` | `Enabled` | REG_DWORD | PCR validation for UEFI systems |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE\OSPlatformValidation_UEFI_SecureBoot` | `Enabled` | REG_DWORD | PCR validation for UEFI + Secure Boot |

**Network Unlock:**
| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Policies\Microsoft\FVE` | `OSNetworkUnlock` | REG_DWORD | Network Unlock feature enabled |
| `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP` | (certificates) | - | Network Unlock certificates |

---

### 5. EFS (Encrypting File System)

**Hive(s):** NTUSER.DAT, SOFTWARE, SYSTEM

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS` | `EfsConfiguration` | REG_DWORD | EFS configuration: 0=enabled, 1=disabled |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS` | `AlgorithmID` | REG_DWORD | Encryption algorithm OID |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS` | `KeyLength` | REG_DWORD | Key length for self-signed certs |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS` | `EfsConfiguration` | REG_DWORD | Group Policy: disable EFS |
| `HKCU\Software\Microsoft\Windows NT\CurrentVersion\EFS\CurrentKeys` | `CertificateHash` | REG_BINARY | Current user's EFS certificate thumbprint |
| `HKLM\SOFTWARE\Microsoft\SystemCertificates\EFS\Certificates` | (thumbprints) | REG_BINARY | EFS Data Recovery Agent certificates |
| `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\EFS\Certificates` | (thumbprints) | REG_BINARY | GP-distributed EFS recovery agent certs |
| `HKCU\Software\Microsoft\SystemCertificates\My\Certificates` | (thumbprints) | REG_BINARY | User's personal certificate store (includes EFS certs) |

**File System Artifacts:**
- Encrypted files have `$EFS` attribute in NTFS containing DDF (Data Decryption Field) and DRF (Data Recovery Field)
- Self-signed EFS certs valid for 100 years by default
- Private keys: `%APPDATA%\Microsoft\Crypto\RSA\{SID}\`
- Machine keys: `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\`
- Plaintext not wiped during encryption (recoverable from slack space unless SSD TRIM)

---

### 6. 7-Zip

**Hive(s):** NTUSER.DAT, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\7-Zip` | (various) | - | Base key; LastWrite = last config change |
| `HKCU\Software\7-Zip\FM` | `PanelPath0` | REG_SZ | Last folder path in main panel |
| `HKCU\Software\7-Zip\FM` | `PanelPath1` | REG_SZ | Last folder path in second panel |
| `HKCU\Software\7-Zip\FM` | `CopyHistory` | REG_SZ | Copy/extract destination history |
| `HKCU\Software\7-Zip\FM` | `FolderHistory` | REG_SZ | Folder navigation history |
| `HKCU\Software\7-Zip\FM` | `ArcHistory` | REG_SZ | Archive creation history -- may reveal encrypted archives |
| `HKCU\Software\7-Zip\Options` | `ContextMenu` | REG_DWORD | Shell integration settings |
| `HKLM\SOFTWARE\7-Zip` | `Path` | REG_SZ | Installation path (e.g., `C:\Program Files\7-Zip\`) |
| `HKLM\SOFTWARE\7-Zip` | `Path32` | REG_SZ | 32-bit installation path |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip` | `DisplayName` | REG_SZ | Installation evidence |

**Encryption Note:** 7z format uses AES-256-CBC; encrypted archives have no magic bytes indicating encryption (must attempt extraction to confirm).

---

### 7. WinRAR

**Hive(s):** NTUSER.DAT, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\WinRAR` | (various) | - | Base configuration key |
| `HKCU\Software\WinRAR\ArcHistory` | `0`, `1`, `2`, `3` | REG_SZ | Recent archive paths -- reveals encrypted archives opened |
| `HKCU\Software\WinRAR\DialogEditHistory\ArcName` | `0`, `1`, etc. | REG_SZ | Archives created/modified (MRU list) |
| `HKCU\Software\WinRAR\DialogEditHistory\ExtrPath` | `0`, `1`, etc. | REG_SZ | Extraction destination history |
| `HKCU\Software\WinRAR\General` | `LastFolder` | REG_SZ | Last accessed folder |
| `HKCU\Software\WinRAR\General` | `EncryptName` | REG_DWORD | Header encryption default: 1=encrypt file names |
| `HKLM\SOFTWARE\WinRAR` | (various) | - | System-wide settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinRAR archiver` | `DisplayName` | REG_SZ | Installation evidence |

**File Artifacts:** `%APPDATA%\WinRAR\` -- settings, error logs. RAR 5.0 uses AES-256-CBC.

---

### 8. AxCrypt

**Hive(s):** NTUSER.DAT, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\AxantumAxCrypt` | (various) | - | User configuration |
| `HKLM\SOFTWARE\AxantumSoftwareAB\AxantumAxCrypt` | (various) | - | System-wide installation |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AxCrypt` | `DisplayName` | REG_SZ | Installation evidence |

**File Indicators:** `.axx` file extension association; AES-256 encryption (v2.x); AES-128 (v1.x). Includes built-in file shredding.

---

### 9. Folder Lock

**Hive(s):** NTUSER.DAT, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\NewSoftwaresNet\Folder Lock` | (various) | - | User settings and locked folder paths |
| `HKLM\SOFTWARE\NewSoftwaresNet\Folder Lock` | (various) | - | System installation settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Folder Lock` | `DisplayName` | REG_SZ | Installation evidence |

**Note:** Folder Lock creates virtual lockers stored as `.flk` or `.flka` files; encrypted with AES-256. Registration info in registry.

---

### 10. Cypherix / Cryptainer

**Hive(s):** SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Cypherix` | (various) | - | Installation presence |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cryptainer PE` | `DisplayName` | REG_SZ | Installation evidence |
| `HKLM\SYSTEM\MountedDevices` | (drive letter entries) | REG_BINARY | Virtual drive letters assigned to Cryptainer vaults |

**File Signatures:** Cryptainer volumes have identifiable file header -- ASCII signature detectable in unallocated space. Uses 448-bit Blowfish encryption.

---

### 11. DiskCryptor

**Hive(s):** SYSTEM

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt` | `ImagePath` | REG_SZ | `system32\drivers\dcrypt.sys` |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt` | `Type` | REG_DWORD | 1 (kernel driver) |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt` | `Start` | REG_DWORD | 0 (boot start) |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt` | `ErrorControl` | REG_DWORD | 3 (critical) |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt` | `Group` | REG_SZ | "Filter" |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt` | `DisplayName` | REG_SZ | "DiskCryptor driver" |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt` | `DependOnService` | REG_MULTI_SZ | "FltMgr" |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt\config` | `Flags` | REG_DWORD | Configuration flags |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt\config` | `Hotkeys` | REG_BINARY | Configured hotkeys |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt\config` | `sysBuild` | REG_DWORD | Build number of driver |
| `HKLM\SYSTEM\CurrentControlSet\Services\dcrypt\Instances` | `DefaultInstance` | REG_SZ | "dcrypt" |

**Note:** Also used by HDDCryptor/Mamba ransomware. Boot-start driver = strong indicator.

---

### 12. BestCrypt (Jetico)

**Hive(s):** SOFTWARE, SYSTEM

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Jetico\BestCrypt` | (various) | - | Installation and configuration |
| `HKLM\SOFTWARE\Jetico\BestCrypt Volume Encryption` | (various) | - | Volume encryption settings |
| `HKLM\SYSTEM\CurrentControlSet\Services\BestCrypt Volume Encryption` | `ImagePath` | REG_EXPAND_SZ | Driver path |
| `HKLM\SYSTEM\CurrentControlSet\Services\BestCrypt Volume Encryption` | `Start` | REG_DWORD | Service start type |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BestCrypt` | `DisplayName` | REG_SZ | Installation evidence |

**Encryption metadata stored in disk header** (algorithm, hash function, rounds) -- unlike VeraCrypt. Detected by Elcomsoft Encrypted Disk Hunter.

---

### 13. Symantec Endpoint Encryption / PGP Desktop

**Hive(s):** SYSTEM, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\PGPdisk` | `ImagePath` | REG_EXPAND_SZ | `PGPdisk.SYS` driver |
| `HKLM\SYSTEM\CurrentControlSet\Services\PGPwdefs` | `ImagePath` | REG_EXPAND_SZ | `Pgpwdefs.sys` driver |
| `HKLM\SYSTEM\CurrentControlSet\Services\PGPwded` | `ImagePath` | REG_EXPAND_SZ | `PGPwded.sys` whole disk encryption driver |
| `HKLM\SOFTWARE\PGP Corporation\PGP` | (various) | - | PGP configuration and licensing |
| `HKLM\SOFTWARE\Symantec\Symantec Endpoint Encryption` | (various) | - | SEE configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PGP Desktop` | `DisplayName` | REG_SZ | Installation evidence |

**File Signatures:** PGP container files have ASCII signature `PGPdMAINd`. PGP WDE generates 66+ registry keys during installation; most persist after uninstallation.

---

### 14. McAfee Drive Encryption

**Hive(s):** SOFTWARE, SYSTEM

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\McAfee\Endpoint Encryption` | (various) | - | Encryption configuration |
| `HKLM\SOFTWARE\McAfee\DesktopProtection` | (various) | - | Desktop protection settings |
| `HKLM\SOFTWARE\McAfee\Agent` | (various) | - | McAfee agent configuration |
| `HKLM\SOFTWARE\McAfee\DLP\Agent` | (various) | - | DLP agent settings |
| `HKLM\SOFTWARE\McAfee\SystemCore` | (various) | - | Core system settings |
| `HKLM\SOFTWARE\McAfee\Endpoint\Modules\Endpoint Security Platform` | (various) | - | Platform module config |
| `HKLM\SYSTEM\CurrentControlSet\Services\MfeFDE` | (various) | - | FDE driver service |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee Endpoint Encryption` | `DisplayName` | REG_SZ | Installation evidence |

**Forensic Decryption:** McAfee ePO exports XML with decryption key; DETech bootable tool for sector-by-sector decryption. AES-256-CBC default.

---

### 15. Sophos SafeGuard

**Hive(s):** SOFTWARE, SYSTEM

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Utimaco\SafeGuard Enterprise` | (various) | - | SafeGuard configuration root |
| `HKLM\SOFTWARE\Utimaco\SafeGuard Enterprise\Authentication` | (various) | - | Authentication settings |
| `HKLM\SOFTWARE\Policies\Utimaco\SGLANCrypt` | (various) | - | LAN Crypt policy |
| `HKLM\SOFTWARE\Policies\Utimaco\SGLANCrypt\Customer Messages\Client` | (error codes) | REG_SZ | Custom error messages |
| `HKLM\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense` | `Start` | REG_DWORD | Service start type |
| `HKLM\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config` | `SAVEnabled` | REG_DWORD | Tamper protection status |
| `HKLM\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config` | `SEDEnabled` | REG_DWORD | Endpoint defense tamper protection |
| `HKLM\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\EndpointFlags` | (various) | - | Required for service initialization |
| `HKLM\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\Paths` | (various) | - | Critical initialization paths |
| `HKLM\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\Scanning\Config` | (various) | - | Scanning exclusions/policies |
| `HKLM\SOFTWARE\WOW6432Node\Sophos\SAVService\TamperProtection` | `Enabled` | REG_DWORD | AV tamper protection |

**Detection Tool:** SGNstate utility checks encryption status.

---

### 16. LUKS (Linux Unified Key Setup)

**Hive(s):** N/A (Linux-native)

LUKS does not create Windows registry entries. However, LUKS volumes can be detected on Windows by:
- **Disk signatures:** LUKS header starts with `LUKS\xba\xbe` magic bytes
- **LibreCrypt/DoxBox:** Windows tool that mounts LUKS volumes; see entry #17
- **Elcomsoft Encrypted Disk Hunter:** Detects LUKS volumes on live Windows systems via disk scanning
- **MountedDevices:** If mounted via third-party tools, drive letter entries appear in `HKLM\SYSTEM\MountedDevices`

---

### 17. LibreCrypt (formerly DoxBox / FreeOTFE)

**Hive(s):** SYSTEM, SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\LibreCrypt*` | (various) | - | Driver services (multiple drivers for different ciphers) |
| `HKLM\SYSTEM\CurrentControlSet\Control\CI` | `TestSigning` | REG_DWORD | 1=test signing mode enabled (required for 64-bit); STRONG forensic indicator |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LibreCrypt` | `DisplayName` | REG_SZ | Installation evidence |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DoxBox` | `DisplayName` | REG_SZ | Legacy DoxBox installation |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FreeOTFE` | `DisplayName` | REG_SZ | Legacy FreeOTFE installation |
| `HKLM\SYSTEM\MountedDevices` | (drive letters) | REG_BINARY | Mounted encrypted container evidence |

**Key Indicator:** "Test Mode" watermark on Windows desktop due to test-signed drivers.
**File Signatures:** Rohos: `ROHO...`; volumes have identifiable headers.

---

### 18. Rohos Disk Encryption

**Hive(s):** SOFTWARE, SYSTEM, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Tesline-Service\Rohos` | (various) | - | Installation configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Rohos Disk Encryption` | `DisplayName` | REG_SZ | Installation evidence |
| `HKLM\SYSTEM\MountedDevices` | (drive letters) | REG_BINARY | Virtual disk mount evidence |

**File Signatures:** Rohos containers have ASCII signature `ROHO...` -- detectable in unallocated space even after deletion. Creates hidden encrypted partitions on USB drives, local disks, or cloud storage.

---

### 19. Boxcryptor

**Hive(s):** NTUSER.DAT, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\Boxcryptor` | (various) | - | User configuration |
| `HKLM\SOFTWARE\Boxcryptor` | (various) | - | System-wide settings |
| `HKLM\SYSTEM\CurrentControlSet\Services\CBFSConnect*` or `CbFs*` | (various) | - | Virtual filesystem driver (Callback File System) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Boxcryptor` | `DisplayName` | REG_SZ | Installation evidence |

**Note:** Boxcryptor was acquired by Dropbox in November 2022. Standalone product discontinued but existing installations persist.

---

### 20. Cryptomator

**Hive(s):** SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Cryptomator` | (various) | - | Installation settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cryptomator` | `DisplayName` | REG_SZ | Installation evidence |
| `HKCU\Software\Cryptomator` | (various) | - | User configuration, vault paths |

**File Indicators:** Vault root directory contains `masterkey.cryptomator` and `vault.cryptomator` files. Uses AES-256-SIV for filename and content encryption. Mounts via WebDAV or WinFsp (FUSE).

---

### 21. NordLocker

**Hive(s):** SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\NordLocker` | (various) | - | Installation settings |
| `HKCU\Software\NordLocker` | (various) | - | User preferences, vault locations |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NordLocker` | `DisplayName` | REG_SZ | Installation evidence |

**File Indicators:** `.locker` files; AES-256 encryption. Electron-based app -- look for Electron framework artifacts.

---

### 22. Picocrypt

**Hive(s):** Minimal/None

Picocrypt is a portable single-binary tool (Go compiled). It does NOT install and creates minimal registry artifacts.

| Detection Method | Location | Forensic Significance |
|---|---|---|
| Prefetch | `C:\Windows\Prefetch\PICOCRYPT.EXE-{hash}.pf` | Execution evidence |
| AmCache | `Amcache.hve` | SHA1 hash, path, execution time |
| ShimCache | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | File presence evidence |
| UserAssist | `HKCU\...\UserAssist` | ROT-13 encoded execution |

**File Indicators:** `.pcv` encrypted files. Uses XChaCha20 + Argon2id. No installer = no Uninstall key.

---

### 23. Age Encryption

**Hive(s):** None (CLI tool)

Age (`age-keygen`, `age`) is a command-line encryption tool with no Windows installer. Registry artifacts are limited to:

| Detection Method | Location | Forensic Significance |
|---|---|---|
| Prefetch | `AGE.EXE-{hash}.pf` | Execution evidence |
| AmCache/ShimCache | Registry hives | Execution with file path and hash |
| Console history | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Command-line usage with arguments |
| Environment variables | `HKCU\Environment` or `HKLM\SYSTEM\...\Environment` | `AGE_KEY_FILE` or `AGE_IDENTITY` variables |

**File Indicators:** `.age` file extension. Keys in `~/.age/` or custom paths.

---

### 24. OpenSSL

**Hive(s):** SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Wow6432Node\OpenSSL-<version>-<ctx>` | `OPENSSLDIR` | REG_SZ | OpenSSL configuration directory |
| `HKLM\SOFTWARE\Wow6432Node\OpenSSL-<version>-<ctx>` | `MODULESDIR` | REG_SZ | OpenSSL modules directory |
| `HKLM\SOFTWARE\OpenSSL-<version>-<ctx>` | (same) | REG_SZ | 64-bit variant |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpenSSL*` | `DisplayName` | REG_SZ | Installation evidence |

**Note:** `<version>` is major.minor (e.g., "3.0"), `<ctx>` is build context string. Multiple installs can coexist. Registry keys set by official installer from github.com/openssl/installer.

---

### 25. S/MIME Certificate Stores

**Hive(s):** NTUSER.DAT, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\Microsoft\SystemCertificates\My\Certificates\{Thumbprint}` | `Blob` | REG_BINARY | Personal S/MIME certificates (DER-encoded) |
| `HKCU\Software\Microsoft\SystemCertificates\CA\Certificates\{Thumbprint}` | `Blob` | REG_BINARY | Intermediate CA certificates |
| `HKCU\Software\Microsoft\SystemCertificates\Root\Certificates\{Thumbprint}` | `Blob` | REG_BINARY | Trusted root certificates |
| `HKCU\Software\Microsoft\SystemCertificates\AddressBook\Certificates\{Thumbprint}` | `Blob` | REG_BINARY | Other people's certificates (for S/MIME recipients) |
| `HKCU\Software\Policies\Microsoft\SystemCertificates\*` | (same structure) | - | GP-distributed user certificates |
| `HKLM\SOFTWARE\Microsoft\SystemCertificates\My\Certificates\{Thumbprint}` | `Blob` | REG_BINARY | Machine-level certificates |
| `HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\{Thumbprint}` | `Blob` | REG_BINARY | Third-party root certificates |
| `HKLM\SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\{Thumbprint}` | `Blob` | REG_BINARY | Revoked/untrusted certificates |
| `HKLM\SOFTWARE\Microsoft\SystemCertificates\TrustedPeople\Certificates\{Thumbprint}` | `Blob` | REG_BINARY | Trusted person certificates |
| `HKLM\SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\Certificates\{Thumbprint}` | `Blob` | REG_BINARY | Trusted software publishers |
| `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\*` | (same structure) | - | GP-distributed machine certificates |
| `HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\*` | (same structure) | - | Enterprise-shared certificates |
| `HKLM\SOFTWARE\Microsoft\Cryptography\Services\{ServiceName}\SystemCertificates\*` | (same structure) | - | Service account certificates |
| `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{CA}\PolicyModules\...\DefaultSMIME` | (various) | - | CA S/MIME default capabilities |

**Private Key Locations:**
- User: `%APPDATA%\Microsoft\Crypto\RSA\{SID}\`
- Machine: `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\`

---

# Part 2: Secure Wipe / Anti-Forensic Tools

---

### 1. SDelete (Sysinternals)

**Hive(s):** NTUSER.DAT (per-user), DEFAULT (SYSTEM account)

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\Sysinternals\SDelete` | `EulaAccepted` | REG_DWORD | 1 = SDelete was executed under this user account |
| `HKU\.DEFAULT\Software\Sysinternals\SDelete` | `EulaAccepted` | REG_DWORD | SDelete run as SYSTEM (scheduled task, service, or psexec) |

**Additional Artifacts:**

| Artifact | Location | Details |
|---|---|---|
| Prefetch | `SDELETE.EXE-{hash}.pf` or `SDELETE64.EXE-{hash}.pf` | Execution timestamps, count |
| AmCache | `Amcache.hve` | SHA1 hash, path, execution time |
| ShimCache | `SYSTEM\...\AppCompatCache` | File presence |
| USN Journal | `$Extend\$UsnJrnl:$J` | Files renamed to `AAAAAAA.AAAAA` pattern before deletion |
| Event Log | Security Event ID 4656 | Object access: files with `AAAAAA` pattern deleted |
| Sysmon | Event ID 1 (Process Create), Event ID 13 (Registry Set) | Process creation and EulaAccepted write |

**SIGMA Detection Rules:**
- `registry_set_pua_sysinternals_susp_execution_via_eula` -- detects EulaAccepted creation
- `registry_set_renamed_sysinternals_eula_accepted` -- detects renamed SDelete execution
- MITRE ATT&CK: T1485 (Data Destruction), T1588.002 (Obtain Capabilities: Tool)

---

### 2. Eraser (Heidi Eraser)

**Hive(s):** NTUSER.DAT, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\Eraser` | (various) | - | User configuration; LastWrite = last config/execution change |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` | `C:\Program Files\Eraser\Eraser.exe` = "RUNASADMIN" | REG_SZ | Shows Eraser configured to run elevated |
| `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` | (same value) | REG_SZ | Per-user AppCompat run-as-admin |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{DE7E16F5-A9B5-434D-B95C-3EC6FE5AEB92}` | `DisplayName` | REG_SZ | Eraser 6.x installation (GUID may vary by version) |

**Additional Artifacts:**

| Artifact | Location | Details |
|---|---|---|
| Task List | `%LOCALAPPDATA%\Eraser 6\Task List.ersx` (Vista/7+) | Scheduled erase tasks (XML format) |
| Schedule Log | `schedlog.txt` | When Eraser was run (not what was wiped) |
| Prefetch | `ERASER.EXE-{hash}.pf` | Execution evidence |
| UserAssist | `HKCU\...\UserAssist` | Execution count and timestamps |
| $I30 entries | NTFS directory indexes | May retain file names even after MFT entries wiped |
| Volume Shadow Copies | VSCs created pre-install | Files recoverable from earlier snapshots |

**Wipe Methods:** Gutmann (35-pass), DoD 5220.22-M, British HMG IS5, Pseudorandom (1-pass). Research shows single pass sufficient for modern drives.
**Regshot comparison:** 60,916 keys deleted, 3,253 keys added, 213,523 values deleted during use.

---

### 3. CCleaner

**Hive(s):** NTUSER.DAT, SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\Piriform\CCleaner` | `(App)Browser` | REG_SZ | True/False: browser artifacts selected for cleaning |
| `HKCU\Software\Piriform\CCleaner` | `(App)Cookies` | REG_SZ | True/False: cookies selected |
| `HKCU\Software\Piriform\CCleaner` | `(App)History` | REG_SZ | True/False: history selected |
| `HKCU\Software\Piriform\CCleaner` | `(App)Recent Documents` | REG_SZ | True/False: recent docs selected |
| `HKCU\Software\Piriform\CCleaner` | `(App)Run (in Start Menu)` | REG_SZ | True/False: Run MRU selected |
| `HKCU\Software\Piriform\CCleaner` | `(App)Temporary Files` | REG_SZ | True/False: temp files selected |
| `HKCU\Software\Piriform\CCleaner` | `(App)Log Files` | REG_SZ | True/False: Event logs selected for wiping |
| `HKCU\Software\Piriform\CCleaner` | `(App)Prefetch Data` | REG_SZ | True/False: Prefetch selected for wiping |
| `HKCU\Software\Piriform\CCleaner` | `WipeFreeSpaceDrives` | REG_SZ | Drive letters selected for free space wiping |
| `HKCU\Software\Piriform\CCleaner` | `SecureDeleteMethod` | REG_SZ | 0=Simple(1-pass), 1=DoD(3-pass), 2=NSA(7-pass), 3=Gutmann(35-pass) |
| `HKCU\Software\Piriform\CCleaner` | `SecureDeleteType` | REG_SZ | 0=Disabled, 1=Enabled |
| `HKCU\Software\Piriform\CCleaner` | `AutoClose` | REG_SZ | Auto-close after cleaning |
| `HKCU\Software\Piriform\CCleaner` | `CookiesToSave` | REG_SZ | Preserved cookies list |
| `HKCU\Software\Piriform\CCleaner` | `BackupDir` | REG_SZ | Registry backup save location |
| `HKCU\Software\Piriform\CCleaner` | `BackupPrompt` | REG_SZ | 0/1: prompt before registry changes |
| `HKCU\Software\Piriform\CCleaner` | `Language` | REG_SZ | LCID locale identifier |
| `HKCU\Software\Piriform\CCleaner` | `Monitoring` | REG_SZ | Smart Cleaning enabled |
| `HKCU\Software\Piriform\CCleaner` | `SystemMonitoring` | REG_SZ | Active monitoring/System Smart Cleaning |
| `HKCU\Software\Piriform\CCleaner` | `HomeScreen` | REG_SZ | 0=Custom Clean, 1=Health Check |
| `HKCU\Software\Piriform\CCleaner` | `WINDOW_LEFT` | REG_SZ | Window position |
| `HKCU\Software\Piriform\CCleaner` | `WINDOW_WIDTH` | REG_SZ | Window dimensions |
| `HKCU\Software\Piriform\CCleaner` | `UpdateCheck` | REG_SZ | Auto update check |
| `HKLM\SOFTWARE\Piriform\CCleaner` | (various) | - | System-level configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CCleaner` | `DisplayName` | REG_SZ | Installation evidence |

**Key Forensic Notes:**
- LastWrite on `HKCU\Software\Piriform\CCleaner` = approximate last execution time
- Values prefixed `(App)` set to `True` = items selected for cleaning
- Scheduled task: `\Windows\System32\Tasks\CCleanerSkipUAC - <username>`
- Shell event log: EventID 28115 for shortcut creation at install
- Export config via: `CCleaner.exe /EXPORT`
- **Surviving artifacts after wipe:** pagefile, volume shadows, hibernation file, some Prefetch entries
- USN Journal shows evtx files overwritten to header-only size (not truly cleared)

---

### 4. BCWipe (Jetico)

**Hive(s):** SOFTWARE, SYSTEM, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Jetico\BCWipe` | (various) | - | Installation and configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BCWipe` | `DisplayName` | REG_SZ | Installation evidence |
| `HKCU\Software\Jetico\BCWipe` | (various) | - | User-level wipe configuration |

**Temporary Files:** BCWipe creates `~BCWipe.tmp` files during operation -- detectable in USN Journal and $MFT.
**Wipe Methods:** DoD 5220.28-STD, Gutmann 35-pass, and custom schemes. Can wipe MFT records, slack space, and NTFS metadata.

---

### 5. KillDisk

**Hive(s):** SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\LSoft Technologies\Active@ KillDisk` | (various) | - | Installation and operation settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KillDisk` | `DisplayName` | REG_SZ | Installation evidence |

**Note:** When run from bootable media (typical use case), no registry artifacts on the target system. When run from within Windows, leaves standard installation artifacts. NSA-certified for secure erasure when used as whole-disk wipe.

---

### 6. DBAN (Darik's Boot and Nuke)

**Hive(s):** None

DBAN boots from external media and wipes entire disks. It does **not** create any Windows registry artifacts on the target system. Detection relies on:
- Physical media found during investigation (CD/USB with DBAN)
- BIOS/UEFI boot order changes (may be logged in BIOS event log)
- Lack of any data on drives (complete zero-fill or random-fill patterns)
- If DBAN was downloaded: browser history, download artifacts, Prefetch on the downloading system

---

### 7. Cipher.exe (/w flag)

**Hive(s):** N/A (built-in Windows utility)

| Detection Method | Location | Forensic Significance |
|---|---|---|
| Prefetch | `CIPHER.EXE-{hash}.pf` | Proves cipher.exe was executed; timestamps show when |
| AmCache/ShimCache | Registry hives | Additional execution evidence |
| Temporary Files | `EFSTMPWP` directory/file | Created during `/w` (wipe) operation; left behind on interruption |
| USN Journal | `$Extend\$UsnJrnl:$J` | EFSTMPWP file creation/deletion events |
| Event Log | Security audit | Object access events for EFSTMPWP |
| Command History | PowerShell/CMD history | `cipher /w:C:` commands |

**Note:** `cipher /w` writes three passes: 0x00, 0xFF, then random data to free space. The presence of `EFSTMPWP` is a strong indicator of free space wiping.

---

### 8. BleachBit

**Hive(s):** SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BleachBit` | `DisplayName` | REG_SZ | Installation evidence |
| `HKCU\Software\BleachBit` | (various) | - | User configuration |

**Configuration Files:** `%APPDATA%\BleachBit\BleachBit.ini` -- contains cleaning targets and settings.
**What BleachBit Targets:** MRU lists, Prefetch, clipboard, cookies, history, temp files, memory dumps, broken shortcuts, unused registry entries, slack space overwrite.
**Detection:** Prefetch (`BLEACHBIT.EXE-{hash}.pf`), AmCache, USN Journal patterns, residual .ini config.

---

### 9. Wise Disk Cleaner

**Hive(s):** SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\WiseCleaner\Wise Disk Cleaner` | (various) | - | Installation settings |
| `HKCU\Software\WiseCleaner\Wise Disk Cleaner` | (various) | - | User configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wise Disk Cleaner` | `DisplayName` | REG_SZ | Installation evidence |

---

### 10. PrivaZer

**Hive(s):** NTUSER.DAT (portable mode leaves minimal registry traces)

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKCU\Software\PrivaZer` | (various) | - | User configuration (if installed; portable mode may skip) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PrivaZer` | `DisplayName` | REG_SZ | Installation evidence |

**Configuration Files:**
- `data.ini` -- contains `last_erase_date2` (FILETIME object) showing last execution date
- `%USERPROFILE%\Desktop\PrivaZer registry backups\` -- registry backup directory created during cleaning
- **What PrivaZer Cleans:** Registry keys, index.dat, jump lists, thumbnail cache, USN journal, MFT free entries, pagefile, and more.

---

### 11. Privacy Eraser

**Hive(s):** SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Cybertron Software\Privacy Eraser` | (various) | - | Installation settings |
| `HKCU\Software\Cybertron Software\Privacy Eraser` | (various) | - | User configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Privacy Eraser` | `DisplayName` | REG_SZ | Installation evidence |

---

### 12. East-Tec Eraser

**Hive(s):** SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\East-Tec\Eraser` | (various) | - | Installation and configuration settings |
| `HKCU\Software\East-Tec\Eraser` | (various) | - | User wipe preferences and log history |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\East-Tec Eraser` | `DisplayName` | REG_SZ | Installation evidence |

**Note:** East-Tec Eraser stores configuration and a log history of when it was run.

---

### 13. O&O SafeErase

**Hive(s):** SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\O&O\O&O SafeErase` | (various) | - | Installation and licensing |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` (O&O GUID) | `DisplayName` | REG_SZ | "O&O SafeErase Professional" installation evidence |

---

### 14. Acronis Drive Cleanser

**Hive(s):** SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Acronis\DriveCleanser` | (various) | - | Configuration and licensing |
| `HKLM\SOFTWARE\Acronis\TrueImage` | (various) | - | Parent suite if installed as part of Acronis True Image/Cyber Protect |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` (Acronis) | `DisplayName` | REG_SZ | Installation evidence |

---

### 15. WipeDrive / WhiteCanyon

**Hive(s):** SOFTWARE (if run from within Windows); None (if booted from external media)

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\WhiteCanyon\WipeDrive` | (various) | - | Installation settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WipeDrive` | `DisplayName` | REG_SZ | Installation evidence |

**Note:** WipeDrive is NSA-certified. When used from bootable media for whole-disk wipe, no registry artifacts remain. When installed on Windows, standard uninstall keys are present.

---

### 16. HDShredder

**Hive(s):** SOFTWARE (if installed on Windows); None (bootable version)

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Miray Software\HDShredder` | (various) | - | Installation configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HDShredder` | `DisplayName` | REG_SZ | Installation evidence |

---

### 17. Parted Magic

**Hive(s):** None

Parted Magic is a Linux-based bootable environment. It creates **no** Windows registry artifacts. Detection:
- Physical media (USB/CD) found during search
- BIOS boot order changes
- Disk state analysis (zero-filled or random-filled sectors)

---

### 18. Samsung Magician (Secure Erase)

**Hive(s):** SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Samsung Magician` | (various) | - | Installation and SSD management settings |
| `HKLM\SOFTWARE\WOW6432Node\Samsung Magician` | (various) | - | 64-bit system alternative path |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` (Samsung) | `DisplayName` | REG_SZ | "Samsung Magician" installation evidence |

**Forensic Note:** Samsung Magician's Secure Erase uses ATA SE command at hardware level, wiping all flash blocks including over-provisioned areas. **Data is irrecoverable** after ATA Secure Erase on Samsung SSDs. However, the tool itself leaves registry traces proving it was installed and likely used.

---

### 19. Intel SSD Toolbox (Intel Memory and Storage Tool)

**Hive(s):** SOFTWARE

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Intel\SSD Toolbox` | (various) | - | Installation settings |
| `HKLM\SOFTWARE\Intel\Intel(R) Memory And Storage Tool` | (various) | - | Newer naming |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` (Intel) | `DisplayName` | REG_SZ | Installation evidence |

**Note:** Intel self-encrypting SSDs generate a new internal encryption key on Secure Erase, instantly rendering all data unreadable (crypto-erase).

---

### 20. hdparm (ATA Secure Erase)

**Hive(s):** None (Linux tool)

hdparm is a Linux utility. If run from Linux live environment, no Windows registry artifacts. If Cygwin/WSL is used:
- WSL: `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` -- WSL distribution registration
- Cygwin: `HKLM\SOFTWARE\Cygwin` -- Cygwin installation evidence
- Prefetch: May show `BASH.EXE` or `WSL.EXE` execution

---

### 21. USBKill

**Hive(s):** None (Python script, typically Linux/macOS)

USBKill is a Python script that monitors USB port changes and triggers shutdown/wipe on unauthorized device insertion or removal.

| Detection Method | Location | Forensic Significance |
|---|---|---|
| Python installation | `HKLM\SOFTWARE\Python` | Python runtime presence |
| Prefetch | `PYTHON.EXE-{hash}.pf` | Python execution evidence |
| File system | `usbkill.py` or compiled binary | Script/binary presence |
| Scheduled tasks / services | Task Scheduler / Services registry | Persistence mechanism |

**Related Tool:** xxUSBSentinel -- Windows-native anti-forensics USB monitoring tool; look for service registration in `HKLM\SYSTEM\CurrentControlSet\Services`.

---

### 22. Silk Guardian

**Hive(s):** None (Linux kernel module)

Silk Guardian is a Linux LKM (Loadable Kernel Module). It creates **no** Windows registry artifacts. Detection on Linux systems only via:
- Loaded kernel module list
- Module files in `/lib/modules/`
- System logs

---

### 23. Cain & Abel

**Hive(s):** NTUSER.DAT, SOFTWARE, SYSTEM

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\Software\Cain` | (various) | - | Application configuration |
| `HKCU\Software\Cain` | (various) | - | Per-user settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cain & Abel v4.9.*` | `DisplayName` | REG_SZ | "Cain & Abel v4.9.xx" -- installation evidence |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cain & Abel v4.9.*` | `UninstallString` | REG_SZ | `C:\PROGRA~2\Cain\UNINSTAL.EXE` |
| `HKLM\SYSTEM\CurrentControlSet\Services\Abel` | (various) | - | Abel NT service registration |
| WinPcap driver keys under `HKLM\SYSTEM\CurrentControlSet\Services` | (various) | - | Packet capture driver (dependency) |

**Additional Artifacts:**
- Install path: `C:\Program Files (x86)\Cain\`
- AV signatures: "CainAbel" (Symantec), "Cain n Abel" (Sophos)
- Temp files: `GL_*.tmp`, `~GLH*.TMP` patterns

---

### 24. Evidence Eliminator

**Hive(s):** SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Robin Hood Software\Evidence Eliminator` | (various) | - | Installation and configuration |
| `HKCU\Software\Robin Hood Software\Evidence Eliminator` | (various) | - | User preferences |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Evidence Eliminator` | `DisplayName` | REG_SZ | Installation evidence |

**Forensic Note:** CMU study found Evidence Eliminator "failed to eradicate some sensitive information." NTUSER.DAT entries for typed URLs, recent documents, and recently used programs may survive.

---

### 25. Window Washer (Webroot)

**Hive(s):** SOFTWARE, NTUSER.DAT

| Registry Path | Value Name | Data Type | Forensic Significance |
|---|---|---|---|
| `HKLM\SOFTWARE\Webroot\Window Washer` | (various) | - | Installation and configuration |
| `HKCU\Software\Webroot\Window Washer` | (various) | - | User cleaning preferences |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Window Washer` | `DisplayName` | REG_SZ | Installation evidence |

**Forensic Note:** Window Washer removes cache, cookies, history, mail trash, address bar, autocomplete, Recycle Bin, Registry streams, temp files. Bleaching feature overwrites files up to 10x. However, it left portions of recent documents and typed URLs intact (Carlton & Kessler study).

---

### 26. Timestomp / SetMACE / NTFSSecurity PowerShell Module

**Hive(s):** N/A (these modify timestamps, not traditional registry-installed tools)

| Detection Method | Location | Forensic Significance |
|---|---|---|
| $MFT $SI vs $FN comparison | NTFS Master File Table | $SI creation before $FN creation = timestomping |
| Subsecond precision | $MFT timestamps | All seven subseconds = `.0000000` indicates automated tool |
| USN Journal | `$Extend\$UsnJrnl:$J` | `BasicInfoChange` + `Close` update reasons without corresponding file operations |
| Prefetch | `TIMESTOMP.EXE-{hash}.pf`, `SETMACE.EXE-{hash}.pf` | Tool execution evidence |
| AmCache/ShimCache | Registry hives | Execution evidence with hashes |
| PowerShell logs | `Microsoft-Windows-PowerShell/Operational` | NTFSSecurity module import and `Set-NTFSSecurityDescriptor` commands |
| Script Block Logging | Event ID 4104 | PowerShell script content including timestamp modification commands |
| Module Logging | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging` | If enabled, captures NTFSSecurity module usage |

**Detection Notes:**
- SetMACE v1.0.0.6+ writes directly to system drive (patched by Microsoft in 2018)
- Moving a file after $SI timestomping copies altered times to $FN (defeats $SI/$FN comparison)
- nTimetools can set arbitrary nanoseconds (defeats `.0000000` detection)
- Best detection: correlate USN Journal + $LogFile + Prefetch + Event Logs

---

### 27. Log Cleaners: ClearLogs.exe, wevtutil, Event Log Tampering

**Hive(s):** SYSTEM, SECURITY

| Registry Path / Detection Method | Value/Event | Forensic Significance |
|---|---|---|
| Security Event Log | Event ID 1102 | "The audit log was cleared" -- includes SID of who cleared it |
| System Event Log | Event ID 104 | "The [log name] log file was cleared" |
| System Event Log | Event ID 7035 | Service Control Manager: EventLog service stop/start |
| Security Event Log | Event ID 4719 | System audit policy was changed (tampering indicator) |
| `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\{LogName}` | `MaxSize` | REG_DWORD | Anomalously small log size = potential tampering |
| `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\{LogName}` | `Retention` | REG_DWORD | Modified retention policy |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\{Channel}` | `Enabled` | REG_DWORD | 0 = logging disabled for this channel |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\{Channel}` | `MaxSize` | REG_DWORD | Channel max size |
| Prefetch | `WEVTUTIL.EXE-{hash}.pf` | wevtutil execution evidence |
| Prefetch | `CLEARLOGS.EXE-{hash}.pf` | ClearLogs execution evidence |
| Command History | PowerShell ConsoleHost_history.txt | `wevtutil cl Security`, `Clear-EventLog` commands |
| USN Journal | evtx file entries | Shows evtx files overwritten to header-only size |
| Sysmon | Event ID 1 | Process creation for wevtutil.exe with `cl` argument |

**Advanced Tampering:**
- Disabling EventLog service: `sc stop EventLog` or `Set-Service -Name EventLog -StartupType Disabled`
- Killing EventLog threads via API (leaves no Event ID 1102)
- DanderSpritz (NSA tool) event log tampering -- modifies individual records
- Detection: timeline gaps, log file sizes dropping, EventLog service restart events

---

### 28. MFT Manipulation Tools

**Hive(s):** Varies

MFT wipers are typically run from bootable environments or use raw disk access. Registry artifacts:

| Detection Method | Location | Forensic Significance |
|---|---|---|
| $MFT gaps | Master File Table | Sequence number anomalies, zeroed entries, missing expected entries |
| $LogFile | NTFS transaction log | Records of MFT modifications; may contain pre-wipe file names |
| $UsnJrnl | NTFS USN Journal | Bulk rename/delete operations in rapid succession |
| AmCache/ShimCache | Registry hives | Execution evidence for MFT wipe tools |
| Volume Shadow Copies | VSC snapshots | Pre-wipe MFT state may be recoverable |
| Prefetch | `C:\Windows\Prefetch\` | MFT tool execution with timestamps |

---

# Part 3: Indirect Detection of Anti-Forensic Activity

Even when tools leave no direct registry traces, investigators can detect anti-forensic activity through these indicators:

---

### MRU Sequence Gaps

| Artifact | Location | Indicator |
|---|---|---|
| RecentDocs MRUListEx | `HKCU\...\Explorer\RecentDocs` | Non-sequential MRU order values; gaps in numbering |
| OpenSaveMRU | `HKCU\...\Explorer\ComDlg32\OpenSavePidlMRU` | Missing entries in sequence |
| RunMRU | `HKCU\...\Explorer\RunMRU` | Gaps or cleared entries |
| LastVisitedMRU | `HKCU\...\Explorer\ComDlg32\LastVisitedPidlMRU` | Missing program entries |

### ShellBags Anomalies

| Artifact | Location | Indicator |
|---|---|---|
| Missing ShellBags | NTUSER.DAT + UsrClass.dat | Folders known to exist have no ShellBag entries = selective deletion |
| Timestamp inconsistencies | ShellBag timestamps | ShellBag access time before creation time |
| Deleted folder references | ShellBag entries | References to folders no longer on disk (including VeraCrypt mount points) |

### Timestamp Anomalies

| Indicator | Description |
|---|---|
| $SI < $FN creation time | $STANDARD_INFORMATION created before $FILE_NAME = timestomping |
| All subseconds `.0000000` | Automated tool set the timestamp (natural occurrence is extremely rare) |
| Clustered identical timestamps | Multiple files with exactly the same timestamp down to nanosecond |
| Timestamps before OS install | File created before the OS was installed |
| Future timestamps | Timestamps in the future |
| Windows epoch timestamps | `1601-01-01 00:00:00.0000000` = zeroed/wiped timestamps |

### Event Log Indicators

| Indicator | Description |
|---|---|
| Event ID 1102 in Security | Audit log was cleared |
| Event ID 104 in System | A log file was cleared |
| Event ID 4719 in Security | Audit policy changed |
| Event ID 7035 (EventLog service) | Service stopped/started unexpectedly |
| Timeline gaps | Missing time ranges in otherwise continuous logging |
| Log size anomalies | Logs at minimum size (header-only after wipe) |
| Channel disabled | `WINEVT\Channels\{channel}\Enabled` = 0 |

### Prefetch Indicators

| Indicator | Description |
|---|---|
| Wipe tool prefetch files | `SDELETE*.pf`, `ERASER.EXE*.pf`, `CIPHER.EXE*.pf`, `BCWIPE*.pf`, `BLEACHBIT*.pf`, `CCLEANER*.pf`, `PRIVAZER*.pf` |
| Missing prefetch files | Prefetch directory exists but contains very few files (wiper cleaned them) |
| Prefetch settings | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` = 0 (disabled by attacker) |

### AmCache / ShimCache Indicators

| Indicator | Description |
|---|---|
| Anti-forensic tool entries | SHA1 hashes and paths of known wipe/encryption tools in `Amcache.hve` |
| Deleted file persistence | Entries persist for deleted executables |
| Timestamp discrepancies | AmCache timestamp vs. ShimCache vs. $MFT timestamps don't align |
| Location: | AmCache: `C:\Windows\appcompat\Programs\Amcache.hve` |
| Location: | ShimCache: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` |

### USN Journal Indicators

| Indicator | Description |
|---|---|
| Bulk rename patterns | Rapid sequential file renames (SDelete `AAAAAAA.AAAAA` pattern) |
| DataOverwrite + DataExtend | Many sequential overwrite operations in short time = wiping activity |
| EFSTMPWP creation | `cipher.exe /w` free space wiping |
| `~BCWipe.tmp` creation | BCWipe operation |
| Journal gaps | Missing time ranges in journal = potential journal clearing |
| BasicInfoChange storms | Numerous `BasicInfoChange` entries = possible timestomping |

### Volume Shadow Copy Indicators

| Indicator | Description |
|---|---|
| VSC deletion events | `vssadmin delete shadows` or `wmic shadowcopy delete` |
| No VSCs on system with VSS enabled | Deliberate destruction of shadow copies |
| Pre-wipe data in older VSCs | Files accessible in earlier snapshots that are gone from current state |

### Registry Transaction Log Indicators

| Indicator | Description |
|---|---|
| Deleted key recovery | Windows registry transaction logs (`.LOG1`, `.LOG2`) may contain registry data that was subsequently deleted by wiping tools |
| Orphaned transaction entries | Registry writes that reference keys no longer present |

---

# Part 4: Detecting Encrypted Volumes Without Registry Footprint

### Entropy Analysis

| Method | Description |
|---|---|
| High entropy files | Encrypted data has entropy close to 8.0 bits/byte (maximum); normal files range 4.0-7.5 |
| Large single files | Encrypted containers are typically large (>100MB) single files with no recognizable header |
| Uniform byte distribution | Chi-squared test shows statistically uniform distribution = encryption or compression |

### File Size Heuristics

| Indicator | Description |
|---|---|
| Size divisible by 512 | Both TrueCrypt and VeraCrypt containers are always exact multiples of 512 bytes |
| Large file in unexpected location | e.g., `C:\Users\Public\backup.bak` that is 50GB with no file signature |
| Size matches physical partition | Container size matching a common disk/partition size |

### Lack of Magic Bytes

| Indicator | Description |
|---|---|
| No file signature match | File identification tools fail to match any known header |
| Random-looking header | First bytes appear random (no structured header) |
| VeraCrypt specifically | No magic bytes at all by design (plausible deniability) |
| TrueCrypt specifically | No magic bytes (identical approach) |

### Disk-Level Detection

| Method | Description |
|---|---|
| Unpartitioned space | Large regions of disk not assigned to any partition but containing high-entropy data |
| Hidden volumes | Requires specific knowledge or memory analysis; cannot be distinguished from random padding |
| MBR/GPT anomalies | Modified boot records for DiskCryptor/TrueCrypt system encryption |
| Elcomsoft Encrypted Disk Hunter | Free tool: detects VeraCrypt, TrueCrypt, BitLocker, PGP WDE, BestCrypt, LUKS via disk scanning |

### Memory / Hibernation Analysis

| Method | Description |
|---|---|
| RAM dump analysis | Encryption keys may persist in memory; use Elcomsoft Forensic Disk Decryptor or Volatility |
| `hiberfil.sys` analysis | Hibernation file may contain encryption keys from mounted volumes |
| `pagefile.sys` analysis | Page file may contain fragments of decrypted data or encryption keys |
| ColdBoot attack | Physical RAM cooling to preserve keys after power-off (research demonstrated) |

---

## Universal Detection: Execution Evidence Sources

For ANY tool (encryption or anti-forensic), these Windows artifacts provide execution evidence:

| Artifact | Registry Location / Path | What It Proves |
|---|---|---|
| **Uninstall Keys** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{name}` | Software was installed |
| **UserAssist** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | GUI program execution (ROT-13 encoded; count + timestamps) |
| **ShimCache** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | File was present on system (not definitive execution proof) |
| **AmCache** | `C:\Windows\appcompat\Programs\Amcache.hve` | Execution with SHA1 hash, path, timestamps |
| **Prefetch** | `C:\Windows\Prefetch\{EXECUTABLE}-{hash}.pf` | Execution with timestamps and run count |
| **MUICache** | `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache` | Program name as displayed to user |
| **BAM/DAM** | `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` | Background Activity Moderator: execution with timestamp (Win10 1709+) |
| **Jump Lists** | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | File access via specific application |
| **SRUM** | `C:\Windows\System32\sru\SRUDB.dat` | System Resource Usage Monitor: network/disk usage per-app |
| **Services** | `HKLM\SYSTEM\CurrentControlSet\Services\{ServiceName}` | Service/driver installation |
| **Run/RunOnce** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Startup persistence |
| **Scheduled Tasks** | `C:\Windows\System32\Tasks\` + Event ID 4698 | Task creation for automation |

---

## References & Sources

### Research Papers
- AlHarbi et al., "Forensic analysis of anti-forensic file-wiping tools on Windows," *Journal of Forensic Sciences*, 2022
- Palmbach & Breitinger, "Artifacts for Detecting Timestamp Manipulation in NTFS on Windows and Their Reliability," *Forensic Science International: Digital Investigation*, 2020
- SANS GIAC, "A Forensic Analysis of the Encrypting File System," White Paper #40160
- Carlton & Kessler, "Identifying Trace Evidence from Target-Specific Data Wiping Application Software," *JDFSL*, 2012
- IEEE, "Forensic Artifacts Left by Virtual Disk Encryption Tools," 2010

### Key Online Resources
- [Tracking Encryption Part 1: VeraCrypt Usage - sparky.tech](https://sparky.tech/tracking-encryption-part-1-veracrypt-usage/)
- [CCleaner Forensics - Synacktiv](https://www.synacktiv.com/en/publications/ccleaner-forensics)
- [BitLocker Policy Settings - Geoff Chappell](https://www.geoffchappell.com/studies/windows/win32/fveapi/policy/index.htm)
- [JPCERT SDelete Analysis](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/sdelete.htm)
- [CCleaner Registry - winreg-kb](https://winreg-kb.readthedocs.io/en/latest/sources/application-keys/CCleaner.html)
- [WinRAR Registry - winreg-kb](https://winreg-kb.readthedocs.io/en/latest/sources/application-keys/WinRAR.html)
- [Windows Certificate Store Locations - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations)
- [7-Zip Forensic Artifacts - forensafe.com](https://www.forensafe.com/blogs/7zip.html)
- [WinRAR Forensic Artifacts - forensafe.com](https://www.forensafe.com/blogs/winrar.html)
- [MITRE ATT&CK T1070.006 - Timestomp](https://attack.mitre.org/techniques/T1070/006/)
- [Defence Evasion: Timestomping Detection - Inversecos](https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html)
- [Event Log Tampering - svch0st](https://svch0st.medium.com/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c)
- [ShimCache vs AmCache - Magnet Forensics](https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/)
- [Countering Anti-Forensic Efforts - Belkasoft](https://belkasoft.com/countering-anti-forensic-efforts-part-2)
- [De-Wipimization: Detection of data wiping traces - ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0167404820303072)
- [RegSeek: Windows Registry Forensics Reference](https://regseek.github.io/)
- [Windows Forensic Artifacts - Psmths GitHub](https://github.com/Psmths/windows-forensic-artifacts)
- [OpenSSL Windows Notes - GitHub](https://github.com/openssl/openssl/blob/master/NOTES-WINDOWS.md)
- [What Did CCleaner Wipe? - KoreLogic](https://blog.korelogic.com/blog/2015/05/18/what_did_ccleaner_wipe)
- [Writing a CCleaner RegRipper Plugin - Cheeky4n6Monkey](http://cheeky4n6monkey.blogspot.com/2012/02/writing-ccleaner-regripper-plugin-part.html)
- [SSD and eMMC Forensics 2016 Part 3 - Belkasoft](https://belkasoft.com/ssd-2016-part3)
- [USBKill - Wikipedia](https://en.wikipedia.org/wiki/USBKill)
- [Silk Guardian - GitHub](https://github.com/NateBrune/silk-guardian)
