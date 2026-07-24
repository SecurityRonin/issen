# Test Data — Issen

Forensic disk images, memory dumps, and UAC/Velociraptor collections, plus other test artifacts.
These files are large and not tracked in git — download them manually.

Files are organized into per-challenge or per-source subfolders. For the **fleet-wide** corpus
inventory (every repo, real vs synthetic, provenance + licenses) see
[`docs/corpus-catalog.md`](../../docs/corpus-catalog.md).

## Directory Layout

```
tests/data/
├── CyberDefenders/
│   └── 78-DeepDive.zip                              (537 MB)
├── cyberspace-ctf-2024/
│   └── csctf-2024_forensics_memory.zip             (671 MB)
├── 2018-lonewolf/
│   └── SYSTEM {,.LOG1,.LOG2}                        (12 MB — extracted Win10 SYSTEM registry hive)
├── defcon-dfir-ctf-2018/
│   └── MaxPowersCDrive.E01                          (29 GB)
├── dfirmadness-szechuan-sauce/   (full case, both hosts)
│   ├── DC01-E01.zip / DC01-memory.zip / DC01-pagefile.zip          (Server 2012 R2)
│   ├── DESKTOP-E01.zip / DESKTOP-SDN1RPT-memory.zip / …-pagefile.zip  (Windows 10)
│   ├── {DC01,DESKTOP-SDN1RPT}-autorunsc.zip + *Protected*Files*.zip ×2
│   └── case001-pcap.zip
├── hal-linux-dfir-challenge/
│   ├── uac-vbox-linux-20260324193807.tar.gz        (143 MB — no memory dump)
│   └── uac-vbox-linux-20260324234043.tar.gz        (5.9 GB — includes avml.lime)
├── magnet-summit-2023-ctf/
│   └── PC-MUS-001.E01                               (49 GB)
├── SecurityNik/
│   └── TOTAL_RECALL_memory_forensics_CHALLENGE.zip (1.2 GB)
├── Volatility/
│   └── cridex_memdump.zip                           (38 MB)
└── Collection-A380_localdomain-2025-08-10T03_41_20Z.zip   (2.2 GB — Velociraptor, root)
```

## Files

### 2018-lonewolf/

#### SYSTEM (+ SYSTEM.LOG1, SYSTEM.LOG2) — extracted Windows 10 registry hive

- **Source:** Digital Corpora — 2018 Lone Wolf Scenario (Thomas "Tom" Moore; GMU CFRS 780), a real physical Windows 10 laptop (Samsung SSD 850 PRO 512 GB), imaged with FTK Imager 3.1.1.8 on 2018-04-06.
- **Identity:** the `SYSTEM` hive (`/Windows/System32/config/SYSTEM` + `.LOG1`/`.LOG2`) carved from the disk image; single control set (`Current=1` → ControlSet001).
- **Scenario page:** <https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/>
- **Original image (E01–E09, ~12.9 GB):** <https://downloads.digitalcorpora.org/corpora/scenarios/2018-lonewolf/LoneWolf_Image_Files/>
- **Full-image MD5:** `7af48fa65519e84246b1729e5b68f140` · **SHA1:** `694e26624d1ea029eb50d793b198edf85be4b4fc` (per the FTK acquisition log, re-verified with `ewfinfo`).
- **Extracted-hive SHA256:** `SYSTEM` = `9154e260abdc4ac206ef9d872dd4e1add0150b869bda5b112944af2ff5ec39b4` (12,845,056 B); `SYSTEM.LOG1` = `9bc4bd3324313b689e0cda9275494d93c714dcb03b434a69927bae8ac7ebc065`; `SYSTEM.LOG2` = `fc1c4b211d19ca3ec1c6c402f602c4f67d287a4fb9664069c3e0172898940652`.
- **Extraction:** TSK/libewf (`icat` from the ControlSet path) → the 12.9 GB image was deleted after carving; transaction logs applied with **regipy** (315 dirty pages recovered).
- **Notable contents (BTHPORT, verified with regipy as an independent oracle):** `Services\BTHPORT\Parameters\Devices` is **EMPTY (0 paired devices)**; `Parameters\Keys` holds one host-adapter subkey `28e347017777` (radio `28:E3:47:01:77:77`) with no link keys; `PerDevices` empty. The full Bluetooth stack is installed (BTHPORT, bthserv, BTHUSB, BthLEEnum, …) — the machine had a radio but was never paired.
- **Use case:** the **"BT-adapter-present, zero-pairings" edge-case fixture** for `bluetooth-forensic` — the parser must return 0 pairings gracefully (empty `Devices`; an adapter under `Keys` with no link keys) without panicking. Env-gated via `BLUETOOTH_TEST_SYSTEM_HIVE` (point it at `tests/data/2018-lonewolf/SYSTEM`); skips cleanly when absent. This is **not** a positive/pairing oracle — a hive *with* pairings must be minted on a real Windows box (`reg save HKLM\SYSTEM`) for that.
- **Redistribution:** Digital Corpora content is provided for research/education; the extracted hive is **gitignored, not committed** — re-derive from the public image above.
- **Classification:** REAL-ext (real-world artifact, third-party corpus).

### defcon-dfir-ctf-2018/

#### MaxPowersCDrive.E01

- **Source:** DEFCON DFIR CTF 2018, organized by David Cowen
- **Identity:** Image 3 (Desktop) — C: drive of user `mpowers` (Max Powers)
- **EWF metadata:** Case "MaxPowers-1", examiner "Professor Frink", linen 5 format, acquired May 5, 2018 with f-response
- **Blog:** <https://www.hecfblog.com/2018/08/daily-blog-451-defcon-dfir-ctf-2018.html>
- **Writeup:** <https://or10nlabs.tech/defcon-dfir-ctf-2018/>
- **Original download:** <https://www.dropbox.com/s/jvaqb4rfi3jojbk/Image3.7z> (may be expired)
- **MD5:** `10c1fbc9c01d969789ada1c67211b89f`
- **Notable contents:** Has `pagefile.sys` and `swapfile.sys` but NO `hiberfil.sys` (hibernation was disabled)

### dfirmadness-szechuan-sauce/

**Full case present — both hosts** (the folder name predates the DC host): CitadelDC01
(Server 2012 R2) and DESKTOP-SDN1RPT (Windows 10), each with disk E01 + memory + pagefile, plus
the PCAP, autoruns, and protected-files bundles.

- **Source:** DFIR Madness — "The Case of the Stolen Szechuan Sauce" (Case 001)
- **Created by:** James Smith (DFIR Madness)
- **Site:** <https://dfirmadness.com/the-stolen-szechuan-sauce/> (may be down)
- **Mirror:** <https://mimircyber.com/the-case-of-the-stolen-szechuan-sauce/>
- **MD5 manifest** — `DESKTOP-E01.zip` is the only hash DFIR Madness published, and our local copy
  **matches** it (upstream-verified). The case page publishes no hash for the other ten, so those are
  **local integrity hashes** of the downloaded copies (they detect later corruption/truncation but are
  not upstream-verified; originally cross-checked by byte-length vs server `content-length`):

  | File | MD5 | Provenance |
  |------|-----|-----------|
  | `DESKTOP-E01.zip` | `71c5c3509331f472abcdf81eb6efff07` | **published** (DFIR Madness) — local copy matches |
  | `DC01-E01.zip` | `e57fc636e833c5f1ab58dface873bbde` | local integrity only |
  | `DESKTOP-SDN1RPT-memory.zip` | `cf31e2635c77811aaa1bb04a92a721e2` | local integrity only |
  | `DC01-memory.zip` | `64a4e2cb47138084a5c2878066b2d7b1` | local integrity only |
  | `Desktop-SDN1RPT-pagefile.zip` | `45c096f2688a0b5de0346fb72391b245` | local integrity only |
  | `DC01-pagefile.zip` | `964eeaf0009d08cc101de4a83a4e5d23` | local integrity only |
  | `case001-pcap.zip` | `422046b753cf8a4df49d2c4ce892db16` | local integrity only |
  | `DESKTOP-SDN1RPT-Protected Files.zip` | `3e1a358d50003a9351ac2160ae6f0495` | local integrity only |
  | `DC01-ProtectedFiles.zip` | `ad29830a583efe49c8c1c35faffd264f` | local integrity only |
  | `DESKTOP-SDN1RPT-autorunsc.zip` | `3627dcafa54e1365489a4ec0cc3d6a1c` | local integrity only |
  | `DC01-autorunsc.zip` | `964f2d710687d170c77c94947da29e66` | local integrity only |
- **Used by:** BSidesHK 3hr workshop (`docs/workshop-3hr/`, disk + RAM only — pcap/autoruns/
  protected-files downloaded for completeness but excluded from the lab) and `usnjrnl-forensic`
  integration tests (desktop E01).

### hal-linux-dfir-challenge/

Used by automated tests in `issen-parser-uac` and `issen-navigator`. The small archive runs in CI; the large one is `#[ignore]`d unless explicitly requested.

#### uac-vbox-linux-20260324193807.tar.gz (143 MB)

- **Source:** Self-collected using UAC on a Linux VirtualBox VM, March 24, 2026
- **Tool:** [UAC — Unix-like Artifacts Collector](https://github.com/tclahr/uac)
- **Contents:** Filesystem artifacts only (no memory dump) — bodyfile, network, processes, system info, etc.
- **Use case:** UAC parser integration tests (`issen-parser-uac`, `issen-navigator`)

#### uac-vbox-linux-20260324234043.tar.gz (5.9 GB)

- **Source:** Self-collected using UAC on a Linux VirtualBox VM, March 24, 2026
- **Tool:** [UAC](https://github.com/tclahr/uac) with AVML memory acquisition
- **Contents:** Full UAC collection including `memory_dump/avml.lime` (~5.5 GB AVML-format memory dump)
- **Use case:** End-to-end UAC pipeline tests including memory dump detection, AVML format provider, Linux process/module/network walking

### magnet-summit-2023-ctf/

#### PC-MUS-001.E01 (50 GB)

- **Source:** magnet-summit-2023-ctf challenge
- **Created by:** Jessica Hyde and Champlain College Digital Forensic Association (DFA) for Magnet Forensics
- **EWF metadata:** Case "1", evidence "PhysicalDrive0", EnCase 6 format, acquired Jan 7, 2023
- **Writeups:**
  - <https://www.stark4n6.com/2023/03/magnet-virtual-summit-2023-ctf-windows.html>
  - <https://download.getdata.com/support/documents/ctf/Magnet%20Virtual%20Summit%202023%20CTF%20-%20Windows%2011.pdf>
  - <https://getdataforensics.com/capture-the-flag/>
- **MD5:** `522df9db8289f4f8132cf47b14d20fb8`
- **Notable contents:** Contains `hiberfil.sys` (MFT entry 54, 3.37 GB allocated) — usable as real test data for `memf-format` hiberfil provider

### magnet-summit-2025-ctf/

- **Source:** **2025 Magnet Virtual Summit CTF** — authored by the **Hexordia** team (Kevin Pagano
  authored the harder questions) with Champlain College DFA interns (Yehuda Bollen, Fatima Omorevic,
  Adam Hachem, James Cangelosi, Cece Ehgotz, Nathan Kreit), for Magnet Forensics.
- **Scenario:** two personas "Ruth" and "Mary"; activity across mobile + computer + web, Nov–Dec 2024.
- **Devices/images:** iOS 18 full-file-system, Android 14, **Windows 11**, and a **Chromebook**.
- **Catalog page:** NIST **CFReDS** — <https://cfreds.nist.gov/all/Hexordia/2025MVSCTF>
  (the public index). **Note:** CFReDS *hosts this dataset on Google Drive* — its download API resolves
  files by Drive `fileIds` (`POST /api/google-drive/files`), so CFReDS and the folder below are the
  **same Google Drive files**, subject to the same per-file quota.
- **Writeup:** <https://www.magnetforensics.com/blog/announcing-the-winners-of-the-2025-magnet-virtual-summit-ctf/>
- **Google Drive folder:** <https://drive.google.com/drive/folders/1qLwXFZTZidkx1tWpG8uenVQnX6zWF-Oa>.
  Contains `userbss.ad1` (AccessData **AD1** logical image; Drive id `1ImeVi8BzHcuLDOV7LhAle9kRnZOMFb64`)
  among others.
- **Download status (2026-07-01):** **acquired** — `userbss.ad1` obtained via a logged-in
  browser (bypasses the public Drive quota). It lives in the AD1 repo, not here:
  `ad1-forensic/tests/data/userbss.ad1` (gitignored), with full provenance in
  `ad1-forensic/tests/data/README.md`.
  - Size: 51,678,663,221 bytes (≈ 48.1 GiB)
  - MD5: `0b6b53e3475b97ae8b3bd3c1e7cec2d9`
  - SHA256: `743e1e89e1d4fa9d6f75d91e820f6dd02d2d906e1bab70eb4731a2fdb4458e7c`
- **Used by (planned):** Windows 11 leg → NTFS/registry/EVTX triage; `userbss.ad1` exercises a future
  **AD1 (AccessData logical image) container** reader (issen does not yet parse AD1); the iOS 18 /
  Android / Chromebook legs are mobile/cross-platform corpora for later parsers.

### CyberDefenders/

#### 78-DeepDive.zip (537 MB)

- **Source:** CyberDefenders Blue-Team lab **#78 "DeepDive"** (<https://cyberdefenders.org/blueteam-ctf-challenges/deepdive/>)
- **Contents:** `banking-malware.vmem` (2.0 GB) — Win7 SP1 x64 memory image of an **Emotet** banking-trojan infection (DKOM-hidden process `vds_ps.exe`). *Confirmed by inspecting the archive (2026-06-09).*
- **Redistribution:** CyberDefenders educational license — verify before redistribution.

### cyberspace-ctf-2024/

#### csctf-2024_forensics_memory.zip (671 MB)

- **Source:** **cyberspace-ctf-2024**, "Memory" forensics challenge (30 Aug–01 Sep 2024; CTFtime event #2428)
- **Contents:** `mem.dmp` (2.0 GB) — MS Windows 64-bit crash dump; recover-deleted-`flag.jpg` via PowerShell/AES/environment-variables. *Confirmed by inspecting the archive + write-ups (2026-06-09).*
- **Redistribution:** Verify CyberSpace CTF terms.

### SecurityNik/

#### TOTAL_RECALL_memory_forensics_CHALLENGE.zip (1.2 GB)

- **Source:** SecurityNik **TOTAL RECALL 2024** memory-forensics challenge by Nik Alleyne (write-up <https://www.securitynik.com/2024/03/total-recall-2024-memory-forensics-self.html>, files <https://github.com/SecurityNik/CTF>)
- **Contents:** `SECURITYNIK-WIN-20231116-235706.dmp` (4.29 GB) + sidecar `.json` — Windows 11 (build 22621) x64 crash dump, acquired with **DumpIt 3.0**, host `SECURITYNIK-WIN` / user `securitynik`. **SHA256** `cabe2fd543eac1cd2eab9ccd0a840d83481a3f00e16015287323b2cb44fe0686`. *Confirmed from embedded metadata (2026-06-09).*
- **Redistribution:** SecurityNik public challenge — attribution.

### Volatility/

#### cridex_memdump.zip (38 MB)

- **Source:** Volatility Foundation public sample — Cridex banking-trojan memory image (<https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples>)
- **Contents:** `cridex.vmem` (512 MB) — the canonical Windows XP Cridex memory sample (2012-08-02) from the Volatility tutorials. *Confirmed by inspecting the archive (2026-06-09).*
- **Redistribution:** Volatility Foundation public sample.

### josh-hickman-ios17-biome-segb/

Real iOS 17 device data — the DFIR community's standard public test image. Used by
**`sqlite-forensic`** as a real-world SQLite + **WAL** validation source (env-gated robustness
test; CI skips when absent — these files are gitignored and downloaded manually).

- **Source:** Josh Hickman (The Binary Hick), iOS 17 public research image. Blog/index:
  <https://thebinaryhick.blog/2023/12/05/ios-17-image-now-available-with-a-twist/> (series index
  <https://thebinaryhick.blog/images/>). Documented + hashed on the source post; download via the
  Mega link there (manual — Mega is not curl-fetchable).
- **Contents:**
  - `iOS_17_Public_Image.tar.gz` (21 GB) — the full file-system image (unextracted here). Holds the
    full set of real app SQLite (e.g. `knowledgeC.db`, `sms.db`, Safari `History.db`, CallHistory) —
    extract it to broaden the SQLite corpus.
  - `biome_ffs/filesystem1/` — a Biome-focused partial extract. **3 genuine iOS app SQLite databases,
    each with a live `-wal` + `-shm` sidecar** (real Write-Ahead Log, captured uncheckpointed):
    `private/var/mobile/Library/Biome/sync/sync.db`,
    `…/Biome/databases/ApplePay.Security.Features/ApplePay.Security.Features.sqlite3`, and
    `…/Caches/CloudKit/com.apple.biomesyncd/…/MMCS/.cs/ChunkStoreDatabase`.
  - `biome_extract/` — decoded Biome SEGB streams (Apple's `SEGB` event format).
  - `iOS17-ImageCreation.pdf` (3 MB) — Josh Hickman's image-creation documentation.
- **Use case (`sqlite-forensic`):** real iOS app SQLite + real WAL for the panic-free robustness suite
  and WAL version-history validation — genuine on-device structures, not synthetic. Point the test at
  this folder via `SQLITE_FORENSIC_IOS_CORPUS=<this path>` (or extract the full image and point there).
- **Redistribution:** Josh Hickman's public research images — free for research/testing, attribution.
  Belongs to **issen** (large, gitignored); `sqlite-forensic` reads it in place via the env var.

### josh-hickman-android10/

Real Android 10 device data — Josh Hickman's public **Pixel 3** research image (the Android
counterpart to his iOS series), hosted on **Digital Corpora** under the **AWS Open Data
Sponsorship** program (freely redistributable). It carries a genuine **WhatsApp `msgstore.db`**
with a live WAL, used by **`timeglyph`** as a **redistributable tier-1 timestamp oracle**: WhatsApp
stores message times as Unix-milliseconds, and the decoded dates fall in the image's Feb 2020
capture window. This replaces the previously-used unlicensed `msgstore.db` fixture.

- **Source:** Josh Hickman (The Binary Hick), Android 10 Pixel 3 public research image, published on
  **Digital Corpora**. Blog: <https://thebinaryhick.blog/> (Android image series). The Digital Corpora
  S3 bucket is public under the **AWS Open Data Sponsorship** program.
- **Original download:** <https://digitalcorpora.s3.amazonaws.com/corpora/mobile/android_10/Non-Cellebrite%20Extraction/Pixel%203.zip>
  (verified: served the exact 5,247,820,897-byte object; a full file-system pull, not a Cellebrite container).
- **File:** `android10-pixel3-fs.zip` (4.89 GB / 5,247,820,897 bytes; valid zip, 76,408 entries).
  - **SHA-256:** `ca6918ef8b20486b6a5ded15609ac51318f377829480f93be3ba15364a8aa00a`
  - **MD5:** `9cc37ebbbc4e918ee5427de1fe1deecc`
- **Key artifact:** `Pixel 3/data/data/com.whatsapp/databases/msgstore.db` (804 KB) + live `-wal`/`-shm`
  sidecars — a real WhatsApp message store (legacy `messages` table, 19 rows, Unix-ms `timestamp`).
  - `msgstore.db` **SHA-256:** `9e133d7262f526b1dab7313f636a1a3f32984d8008310a1a699c83496dd13105`
  - `msgstore.db` **MD5:** `9313bcb2d92c3249aff3c20ad8a2ab7a`
- **Use case (`timeglyph`):** real-world WhatsApp `msgstore.db` timestamps as a tier-1 decoding oracle —
  e.g. `1581271502890` → timeglyph ranks `unix_ms` = `2020-02-09T18:05:02.89Z`, consistent with the
  image's capture window. Extract the DB (+ WAL/SHM) to `/tmp` (never under `~/src`) and point the
  env-gated test there.
- **Redistribution:** Digital Corpora / AWS Open Data — free for research/testing with attribution.
  Belongs to **issen** (large, gitignored); `timeglyph` reads it in place via an env var.

### josh-hickman-ios13/

Real iOS 13.3.1 device data — Josh Hickman's public research image, hosted on **Digital Corpora**
under the **AWS Open Data Sponsorship** program (freely redistributable). It carries a genuine
**WhatsApp `ChatStorage.sqlite`**, the iOS counterpart to the Android `msgstore.db` in
`josh-hickman-android10/`. WhatsApp on iOS stores `ZWAMESSAGE.ZMESSAGEDATE` as **Cocoa /
CFAbsoluteTime** (seconds since 2001) — a different epoch/format family from Android's Unix-ms — so
this is the real-data oracle for **`timeglyph`**'s `cocoa`/`iostime` decoders.

- **Source:** Josh Hickman (The Binary Hick), iOS 13.3.1 public research image, published on
  **Digital Corpora**. Blog: <https://thebinaryhick.blog/> (iOS image series). The Digital Corpora
  S3 bucket is public under the **AWS Open Data Sponsorship** program.
- **Original download:** <https://digitalcorpora.s3.amazonaws.com/corpora/mobile/ios_13_3_1/ios_13_3_1.zip>
  (verified: served the exact 8,927,183,592-byte object).
- **File:** `ios_13_3_1.zip` (8.31 GB / 8,927,183,592 bytes; valid zip). Unpacks to a **16.3 GB
  `iOS 13.3.1 Extraction/Extraction/13-3-1.tar`** full file-system image, plus an iTunes backup and
  sysdiagnose logs.
  - **SHA-256:** `f194e8bbfb950a5a31d5308e8131a14ec602f12d6a3d9f2841d15f47d34b2643`
  - **MD5:** `6641ce1395d392661921cb0ca321e4b7`
- **Key artifact:** inside the tar at
  `…/private/var/mobile/Containers/Shared/AppGroup/BAF442BF-69A8-4336-86BC-37604B5C9A7C/ChatStorage.sqlite`
  (336 KB) — a real WhatsApp message store (`ZWAMESSAGE` table, Cocoa `ZMESSAGEDATE`).
  - `ChatStorage.sqlite` **SHA-256:** `e5f6559b278cc219eff09ae9b8303a69aab3a751c8ee35b8d154496ae830f4a9`
  - `ChatStorage.sqlite` **MD5:** `8a597e2c9aa5e024661bd56ce5eef4a6`
- **Use case (`timeglyph`):** real-world WhatsApp `ChatStorage.sqlite` timestamps as a tier-1 decoding
  oracle for the Cocoa family — e.g. `608322295` → timeglyph ranks `cocoa` = `2020-04-11T18:24:55Z`,
  consistent with the image's April 2020 creation. Stream just `ChatStorage.sqlite` out of the tar to
  `/tmp` (never under `~/src`): `unzip -p ios_13_3_1.zip "*/13-3-1.tar" | tar xf - -C /tmp/ios13-whatsapp '*ChatStorage.sqlite*'`.
- **Redistribution:** Digital Corpora / AWS Open Data — free for research/testing with attribution.
  Belongs to **issen** (large, gitignored); `timeglyph` reads it in place via an env var.

### Root (self-collected, no challenge affiliation)

#### Collection-A380_localdomain-2025-08-10T03_41_20Z.zip (2.2 GB)

- **Source:** Self-collected from host `A380` (Windows 11 Pro 24H2, standalone workstation), August 10, 2025
- **Tool:** Velociraptor offline collector v0.74.5 — artifact `Windows.KapeFiles.Targets` (`_SANS_Triage` target set). **Not UAC** — the earlier "UAC" label was incorrect (verified by inspecting the archive: `client_info.json` / `collection_context.json`, 2026-06-09).
- **Contents:** Disk-artifact triage only — registry hives, EVTX, prefetch, `$MFT`, browser artifacts (2,952 files). **No memory dump.** Benign baseline (real daily-driver host), not an intrusion scenario.
- **Use case:** Velociraptor parser integration tests (`issen-parser-velociraptor`, `issen-navigator`)
- **Note:** Contains real personal artifacts — sanitize before any external sharing.

## Examining E01 Images

These tools are useful for inspecting E01 contents (install via Homebrew: `brew install libewf sleuthkit`):

```bash
# Image metadata
ewfinfo MaxPowersCDrive.E01

# Partition table
mmls -i ewf MaxPowersCDrive.E01

# List root directory (use partition offset from mmls)
fls -i ewf -o 1026048 MaxPowersCDrive.E01

# Search for a specific file
fls -i ewf -o 1026048 MaxPowersCDrive.E01 | grep -i hiberfil

# Extract a file by inode (e.g., hiberfil.sys from PC-MUS-001)
icat -i ewf -o 239616 PC-MUS-001.E01 54-128-1 > hiberfil.sys
```

#### josh-hickman-ios17-biome-segb/iOS_17_Public_Image.tar.gz (22 GB)

- **Source:** Joshua Hickman ("The Binary Hick"), hosted by DigitalCorpora — public iOS forensic
  reference image, freely licensed for training/education/testing/research.
- **Identity:** iPhone 11 (A2111), iOS 17.3 build 21D50, Cellebrite UFED full file-system extraction;
  synthetic persona `thisisdfir@gmail.com`.
- **Writeup:** <https://thebinaryhick.blog/2024/09/14/triple-trouble-ios-16-android-14-and-ios-17-images-now-available/>
- **Original download:** <https://digitalcorpora.s3.amazonaws.com/corpora/mobile/iOS17/iOS_17_Public_Image.tar.gz>
  (image-creation doc with hashes: <https://digitalcorpora.s3.amazonaws.com/corpora/mobile/iOS17/iOS17-ImageCreation.pdf>)
- **MD5:** `e115f051d15178fa1334489e24c9f0fd` (22,132,295,131 bytes).
- **Structure:** Cellebrite UFED package — the full file system is the nested
  `iOS_17/Cellebrite_Extraction/.../EXTRACTION_FFS 01/EXTRACTION_FFS.zip`; biome streams are inside it
  at `private/var/db/biome/streams/restricted/*/local` and `private/var/mobile/.../Library/Biome/`
  (same SEGB v1/v2 container macOS uses). Extract the biome subset from the nested zip; only that
  subset is kept on disk.
- **Used by:** `segb-core` — **public/reproducible validation**: across all **401** real iOS 17 Biome
  SEGB files (139 v1 + 262 v2), segb-core's record counts match the ccl-segb reference exactly —
  **401 PASS / 0 MISMATCH** (2026-06-14). The stream dirs unzip with restrictive Apple modes (0700);
  `chmod -R u+rwX` before scanning. `App.MenuItem` is macOS-Tahoe-26-only and absent here (this is the
  container validation; the App.MenuItem protobuf field mapping still awaits a Tahoe 26 image).

#### josh-hickman-mac-bigsur/macOS - BigSur.zip (32 GiB zip → 80 GB image)

- **Source:** Joshua Hickman ("The Binary Hick") — public macOS Big Sur forensic reference image,
  freely licensed for training / education / testing / research (attribution).
- **Identity:** macOS Big Sur install on **APFS**; 80 GB virtual disk (167,772,160 × 512-byte sectors);
  acquired Sat 2021-02-20 with AccessData FTK Imager 4.5.0.3 from an Arsenal-mounted VM disk
  ("Arsenal Virtual SCSI Disk Device", serial `{77ed1df2-737f-11eb-999e-f01898863f52}`).
- **Writeup:** <https://thebinaryhick.blog/2021/02/20/ios-14-macos-big-sur-lots-of-images/>
  (series index <https://thebinaryhick.blog/images/>) — documented + hashed on the source post.
- **Zip MD5:** `1047921dcc695be98fa648ad54a111d6` (34,408,655,935 bytes).
- **Image hashes** (from the embedded `macOS-BigSur.E01.txt`, computed by FTK Imager at acquisition):
  MD5 `768785635426d008df76200fbc421063`, SHA1 `e3a73cd1b750a851c12c7b608e95edbef1606504`.
- **Structure:** split EWF/E01 — `macOS/macOS-BigSur.E01`–`.E22` (~1.57 GB segments, **Deflated** zip
  entries) + `macOS-BigSur.E01.txt` (acquisition metadata). Pass the first segment (`.E01`) to `ewf`;
  it follows `.E02…` automatically.
- **Used by:** macOS / APFS forensic testing (apfs-forensic, planned), and a real **multi-segment
  E01-inside-a-zip** that exercises issen's EWF zip-direct path + the `DeflateSeekReader` (zran)
  seekable-DEFLATE backing — the segments are Deflated, so this is the live regression for that wiring.

#### loghub-openssh/OpenSSH_2k.log (220 KB)

- **Source:** loghub (logpai), the LogPAI OpenSSH dataset — real, unsanitized SSH server auth events
  from a `LabSZ` host (genuine attacker IPs, brute-force `Failed password` floods, invalid users).
  Pre-journald **text** `auth.log` syslog format. Cite: Zhu et al., *Loghub*, ISSRE 2023.
- **Identity:** the 2k-line sample slice (1999 lines) of the OpenSSH dataset.
- **Original download:** <https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log>
  (dataset: <https://github.com/logpai/loghub/tree/master/OpenSSH>)
- **MD5:** `72efdaaf373b8d6c8a809cc86b2a951f` (225,216 bytes).
- **Used by:** `issen-parser-linux` to validate `parse_auth_log` against **real** evidence — the Hal
  Linux UAC corpus is journald-only (no text `auth.log`), so this fills that gap. Copy/rename to
  `auth.log` and ingest → **519 LoginHistory events** (1 Accepted + 518 Failed), exact match to an
  independent grep oracle. See catalog §A8.

## Test path references

Tests reference these files relative to the crate root (e.g., `../../tests/data/...`).
If you add a new file or subfolder, update the corresponding integration test and this README.

| Test file | Archive referenced |
|-----------|-------------------|
| `crates/parsers/issen-parser-uac/tests/integration_test.rs` | `hal-linux-dfir-challenge/uac-vbox-linux-20260324193807.tar.gz` |
| `crates/parsers/issen-parser-velociraptor/tests/integration_test.rs` | `Collection-A380_localdomain-2025-08-10T03_41_20Z.zip` |
| `crates/issen-navigator/tests/collection_loading.rs` | Both of the above |
