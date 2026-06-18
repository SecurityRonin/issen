# Fleet Corpus Catalog

Single source of truth for **all forensic test corpus across the SecurityRonin fleet** — what
each artifact is, where real data came from, and how synthetic data was made. Lives in `issen`
(the orchestration repo) because it spans every crate.

_Compiled 2026-06-09. Sizes are on-disk (`du`). Most large real datasets are **gitignored** —
download/regenerate per the provenance notes; they are not committed._

## Legend & classification

| Class | Meaning |
|---|---|
| **REAL — external** | Captured/published by a third party (CTF, vendor, lab). Carries source license. |
| **REAL — self-collected** | Genuine OS artifacts we collected from a real/controlled host (UAC, Velociraptor, `hdiutil`, `qemu`). Real telemetry, not fabricated. |
| **SYNTHETIC** | Fixture the code/tooling builds (hand-written bytes, `mkfs`/`qemu-img`/`hdiutil`-generated empties, reference-compressor round-trips). |
| **VENDORED** | Third-party corpus copied in for coverage (attack-sample repos, format standard suites). Not ours. |
| **FUZZ** | Coverage-guided libFuzzer corpora — machine-evolved mutations, not curated samples. |

**Provenance confidence:** ✓ confirmed (documented in-repo or inspected this session) · ~ inferred
(agent reasoned from filenames/test code, not explicitly documented) · ? undetermined.

---

## Summary — the big real datasets (issen/tests/data)

| Dataset | Size | Class | Source |
|---|---|---|---|
| Magnet Virtual Summit 2023 CTF — Win11 (`PC-MUS-001.E01`) | 49 GB | REAL-ext | Magnet/Champlain DFA |
| DEF CON DFIR CTF 2018 (`MaxPowersCDrive.E01`) | 29 GB | REAL-ext | DEF CON / D. Cowen |
| Josh Hickman iOS 17.3 image (Apple Biome **SEGB** streams) | 22 GB (.tar.gz) | REAL-ext | Joshua Hickman / DigitalCorpora |
| DFIR Madness "Stolen Szechuan Sauce" Case 001 (both hosts, full) | ~13 GB | REAL-ext | dfirmadness.com |
| Hal Pomeranz "Linux Forensic Scenario" (UAC, incl. `avml.lime`) | 5.9 GB | REAL-ext | Hal Pomeranz / righteousit.com |
| Collection-A380 (**Velociraptor**, Win11 24H2) | 2.2 GB | REAL-self | self, Velociraptor offline collector |
| SecurityNik TOTAL RECALL 2024 (memory) | 1.2 GB | REAL-ext | Nik Alleyne — securitynik.com / github.com/SecurityNik/CTF |
| CyberSpace CTF 2024 — "Memory" (memory) | 671 MB | REAL-ext | CyberSpace CTF 2024 (CTFtime #2428) |
| CyberDefenders lab #78 "DeepDive" (memory) | 537 MB | REAL-ext | cyberdefenders.org |
| Volatility `cridex.vmem` | 38 MB | REAL-ext | Volatility Foundation public sample |
| LogHub `OpenSSH_2k.log` — real sshd `auth.log` | 220 KB | REAL-ext | logpai/loghub (ISSRE'23) |

---

## A. Real case & CTF datasets — `issen/tests/data/`

### A1 · DEF CON DFIR CTF 2018 — `MaxPowersCDrive.E01` (29 GB) · REAL-ext ✓
C: drive of user `mpowers`. EWF case "MaxPowers-1", examiner "Professor Frink", acquired 2018-05-05
via f-response. **MD5** `10c1fbc9c01d969789ada1c67211b89f`. Has pagefile/swapfile, no hiberfil.
Source: hecfblog Daily Blog 451; writeup or10nlabs.tech. **Used by** `ntfs-forensic` boot-sector
ground-truth (see C-layer). Redistribution: DEF CON public CTF — non-commercial.
**Download:** <https://www.hecfblog.com/2018/08/daily-blog-451-defcon-dfir-ctf-2018.html> (Image 3;
original `https://www.dropbox.com/s/jvaqb4rfi3jojbk/Image3.7z` may be expired).

### A2 · Magnet Virtual Summit 2023 CTF — `PC-MUS-001.E01` (49 GB) · REAL-ext ✓
Win11 physical drive. By Jessica Hyde + Champlain College DFA for Magnet. EnCase 6, acquired
2023-01-07. **MD5** `522df9db8289f4f8132cf47b14d20fb8`. Contains `hiberfil.sys` (MFT #54, 3.37 GB)
— real corpus for the `memf-format` hiberfil provider. Redistribution: Magnet/Champlain — verify.
**Download:** <https://getdataforensics.com/capture-the-flag/> (Magnet Virtual Summit 2023 — Win11).

### A3 · DFIR Madness "Stolen Szechuan Sauce" Case 001 (~13 GB) · REAL-ext ✓
Folder: `tests/data/DFIR Madness "Stolen Szechuan Sauce" Case 001 — Windows 10/` (name predates the
DC host; now holds **both**). By James Smith (dfirmadness.com). **Downloaded in full**
(2026-06-09) — all 11 files:

| File | Size | Note |
|---|---|---|
| `DESKTOP-E01.zip` | 6.4 GB | Win10 desktop disk · MD5 `71C5C3509331F472ABCDF81EB6EFFF07` |
| `DC01-E01.zip` | 4.84 GB | Server 2012R2 DC disk |
| `DESKTOP-SDN1RPT-memory.zip` | 766 MB | desktop RAM |
| `DC01-memory.zip` | 535 MiB | DC RAM |
| `Desktop-SDN1RPT-pagefile.zip` | 212 MB | desktop pagefile |
| `DC01-pagefile.zip` | 13 MB | DC pagefile |
| `case001-pcap.zip` | 151 MB | network capture |
| `DESKTOP-SDN1RPT-Protected Files.zip` | 17 MB | pre-extracted |
| `DC01-ProtectedFiles.zip` | 12 MB | pre-extracted |
| `DESKTOP-SDN1RPT-autorunsc.zip` | 279 KB | autoruns |
| `DC01-autorunsc.zip` | 177 KB | autoruns |

**Download:** case page <https://dfirmadness.com/the-stolen-szechuan-sauce/> · direct per-file
hotlinks `https://dfirmadness.com/case001/<file>` (e.g.
<https://dfirmadness.com/case001/DC01-E01.zip>, `…/DESKTOP-E01.zip`, `…/case001-pcap.zip` — every
filename in the table above). **Used by** `usnjrnl-forensic` integration tests (`#[ignore]`, desktop
E01). Redistribution: dfirmadness.com — educational/research.

#### A3a · Prefetch fixtures derived from A3 (committed in two repos) · SYNTHETIC-from-REAL ✓

Three Win10 `.pf` files extracted from the Case 001 **Desktop** image above, small enough to commit
(provenance confirmed by parsing, not filename). Cross-ref the per-repo `tests/data/README.md`; do
not re-download — they come from `DESKTOP-E01.zip`.

| File | MD5 | Committed in | Decompressed |
|---|---|---|---|
| `COREUPDATER.EXE-157C54BB.pf` | `d3db6935c7ad9f93964b0893997af049` | `prefetch-forensic/tests/data/` | 24316 B, SCCA v30, the implant |
| `AUDIODG.EXE-AB22E9A6.pf` | `18bcdd9d31865769309053816e812811` | `prefetch-forensic/tests/data/` | 35954 B, run count 8 |
| `AM_DELTA.EXE-78CA83B0.pf` | `0d48c5b117a3c9e71b66d51fad454354` | `prefetch-forensic/tests/data/` | 6948 B |

`xpress-huffman/tests/data/` commits the Xpress-Huffman **codec** test vectors carved from two of
these (the `MAM\x04` payload with the 8-byte header stripped, plus the decompressed bytes):
`am_delta.xhuff` (md5 `f3548390c17ed5af3845ea830ea66d48`) / `am_delta.expected`
(`193b1fc2f87f4fac2afeea27aaaeb085`), and `audiodg.xhuff` / `audiodg.expected`. Generators + the
external-oracle validation (dissect.util byte-identical, windowsprefetch field-match) live in each
repo's `tests/data/README.md` and `docs/validation.md`.

### A4 · Hal Pomeranz "Linux Forensic Scenario" (Righteous IT) (5.9 GB) · REAL-ext ✓
Published challenge by **Hal Pomeranz** (Righteous IT), "Linux Forensic Scenario" contest
(2026-03-27): a Linux CI/CD-pipeline worker VM deliberately compromised (planted malware, hidden
high-CPU process, reverse shell on 22/tcp; single `worker` account with NOPASSWD sudo; jump host
192.168.4.35), then captured with **UAC** (github.com/tclahr/uac). Our `…234043.tar.gz` (5.9 GB,
incl. `memory_dump/avml.lime` ~5.5 GB) **is Hal's published download**; `…193807.tar.gz` (143 MB,
fs-only, CI) is a smaller companion capture. **Used by** `rt-parser-uac`, `rt-navigator`, AVML
provider + Linux process/module/network walking.
**Download:** scenario <https://righteousit.com/2026/03/27/linux-forensic-scenario/> · image (the
5.9 GB `…234043.tar.gz`)
<https://deerrunassoc-my.sharepoint.com/:u:/g/personal/hal_deer-run_com/IQAGrMUqVLwEQ4Ceus_70Pn0AVxMaWSs7POONKw6ss103Bc?e=4N5uje>
· class <https://archive.org/details/HalLinuxForensics/>. Redistribution: Hal Pomeranz / Righteous
IT — credit the author.

### A5 · Collection-A380 — **Velociraptor** (2.2 GB) · REAL-self ✓
`Collection-A380_localdomain-2025-08-10T03_41_20Z.zip`. Velociraptor offline collector v0.74.5,
artifact `Windows.KapeFiles.Targets` (`_SANS_Triage`). Host `A380` / Win11 Pro 24H2 / standalone /
operator `4n6h4x0r`, 2025-08-10. Disk-artifact triage only (no RAM), 2,952 files. Benign baseline
(real daily-driver host), **not** an intrusion scenario; virtualization undetected (may be bare
metal). **Used by** `rt-parser-velociraptor`, `rt-navigator`. Redistribution: self-generated
(contains personal artifacts — sanitize before external sharing).
**Download:** none — self-collected, not publicly hosted (regenerate with the Velociraptor offline
collector, `Windows.KapeFiles.Targets` + `_SANS_Triage`, on any Windows host).

### A6 · Memory-forensics CTFs · REAL-ext ✓
All four **confirmed** 2026-06-09 by inspecting the archive contents + web corroboration (not just
filenames). Not yet referenced by a committed test.

- **SecurityNik — TOTAL RECALL 2024** (1.2 GB zip): `SECURITYNIK-WIN-20231116-235706.dmp` (4.29 GB
  Win11 build 22621 crash dump; acquired with **DumpIt 3.0**; host `SECURITYNIK-WIN`, user
  `securitynik`) + sidecar `.json`. **SHA256**
  `cabe2fd543eac1cd2eab9ccd0a840d83481a3f00e16015287323b2cb44fe0686`. By Nik Alleyne.
  **Download:** <https://github.com/SecurityNik/CTF> · write-up
  <https://www.securitynik.com/2024/03/total-recall-2024-memory-forensics-self.html>.
- **CyberDefenders — lab #78 "DeepDive"** (537 MB zip): `banking-malware.vmem` (2.0 GB, Win7SP1x64).
  **Emotet** banking trojan, DKOM-hidden `vds_ps.exe`.
  **Download:** <https://cyberdefenders.org/blueteam-ctf-challenges/deepdive/> (free account).
- **CyberSpace CTF 2024 — "Memory"** (671 MB zip): `mem.dmp` (2.0 GB, MS Win x64 crash dump).
  recover-deleted-`flag.jpg` via PowerShell/AES/env-vars.
  **Download:** event <https://ctftime.org/event/2428> (30 Aug–01 Sep 2024; challenge files via the
  event / published write-ups).
- **Volatility Foundation — Cridex** (38 MB zip): `cridex.vmem` (512 MB, WinXP) — the canonical
  public Memory Sample. **Download:**
  <https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples> (Cridex row; original
  `files.sempersecurus.org` mirror now returns 403).

Redistribution: SecurityNik & Volatility public; CyberDefenders educational license; CyberSpace CTF
event terms — verify before redistribution.

---

### A7 · Josh Hickman iOS 17.3 image — Apple Biome **SEGB** streams (22 GB `.tar.gz`) · REAL-ext ✓

Public iOS file-system image by **Joshua Hickman** (The Binary Hick), hosted by **DigitalCorpora** —
a synthetic test persona (`thisisdfir@gmail.com`), freely licensed for training/education/testing/
research. iPhone 11 (A2111), **iOS 17.3 build 21D50**, Cellebrite UFED full-file-system extraction.
Download (key-free S3):
<https://digitalcorpora.s3.amazonaws.com/corpora/mobile/iOS17/iOS_17_Public_Image.tar.gz> (22 GB);
image-creation doc (hashes, app list):
<https://digitalcorpora.s3.amazonaws.com/corpora/mobile/iOS17/iOS17-ImageCreation.pdf>; announcement
<https://thebinaryhick.blog/2024/09/14/triple-trouble-ios-16-android-14-and-ios-17-images-now-available/>.

- **Why it's here:** the **only public, committable-provenance source of real Apple Biome SEGB files**.
  iOS uses the *same* SEGB v1/v2 container as macOS (`/private/var/db/biome/streams/restricted/*/local`
  and `/private/var/mobile/Library/Biome/...`). **Used by** `segb-core` to validate its SEGB container
  reader against real Apple data + the ccl-segb reference oracle, publicly and reproducibly.
- **VALIDATED (2026-06-14):** segb-core reconciles **exactly** with the ccl-segb reference across
  **all 401 real iOS 17 Biome SEGB files** in this image (139 SEGB **v1** + 262 SEGB **v2**) — record
  counts match on every file, **401 PASS / 0 MISMATCH**. Streams include `_DKEvent.Safari.History`,
  `_DKEvent.Device.BatteryPercentage`, `MicroLocationVisit`, `Siri.SelfTriggerSuppression`,
  DuetActivityScheduler app-launch/kill, `unifiedMessageStream`, etc. The SEGB files live in
  `private/var/db/biome/streams/restricted/*/local/*` and
  `private/var/mobile/Library/.../Biome/.../local/*` — note these dirs unzip with restrictive Apple
  modes (0700), so `chmod -R u+rwX` is needed before scanning. (A prior macOS 15.7 private-stream
  check also matched 785/785; this iOS image is the public, reproducible, **both-variant** validation.)
- **macOS 26.5 (Tahoe) committed regression:** `segb-forensic/tests/data/biome/Device.Display.Backlight.tahoe26.v2.segb`
  — a real SEGB **v2** stream from Tahoe (build 25F71) whose post-magic header field is `0x08` vs iOS 17 v2's
  `0x07`; the v2 reader parses it (8 records, every CRC valid). Captured from a read-only mount of a
  `macos-tahoe-base` (cirruslabs, public) VM disk. Asserted in `core/tests/real_fixtures.rs::real_tahoe26_segb_v2_backlight`.
- **`iOS_17_Public_Image.tar.gz` MD5:** `e115f051d15178fa1334489e24c9f0fd` (22,132,295,131 bytes).
- **Structure:** a Cellebrite UFED package — `iOS_17/Cellebrite_Extraction/.../EXTRACTION_FFS 01/
  EXTRACTION_FFS.zip` (the full file system; biome streams live under
  `private/var/db/biome/streams/restricted/*/local` and
  `private/var/mobile/.../Library/Biome/`), plus an iTunes `Backup/…zip` and a `sysdiagnose/…tar.gz`.
  Extract the biome subset from the nested FFS zip (zip random access), then reconcile segb-core vs
  `ccl_segb_cli.py`. Stored under `issen/tests/data/Josh Hickman iOS 17 (Biome SEGB)/` (gitignored;
  only the biome subset kept on disk). Note: `App.MenuItem` is macOS-Tahoe-26-only, so it is **not**
  in this iOS image — this validates the SEGB *container*, not the App.MenuItem protobuf field mapping.

### A8 · LogHub `OpenSSH_2k.log` — real sshd `auth.log` (220 KB) · REAL-ext ✓

Pre-journald **real** Linux SSH auth events (text `auth.log` syslog format) from a real `LabSZ`
server — unsanitized, with genuine attacker IPs / brute-force `Failed password` floods / invalid
users. 1999 lines, **md5** `72efdaaf373b8d6c8a809cc86b2a951f`. The 2k-sample slice of the loghub
OpenSSH dataset (ISSRE'23). **Used by** `issen-parser-linux` to validate `parse_auth_log` against
real evidence (the Hal Linux UAC corpus is journald-only, so it has no text `auth.log`): ingested as
`auth.log` → **519 events** (1 Accepted + 518 Failed), exact match to an independent grep oracle.
Stored at `tests/data/loghub-openssh/OpenSSH_2k.log`; rename/copy to `auth.log` to exercise discovery.
Redistribution: freely available for research; cite loghub (Zhu et al., ISSRE 2023).
**Download:** <https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log>
(dataset: <https://github.com/logpai/loghub/tree/master/OpenSSH>)

## B. Disk-image / container-format fixtures

### B1 · qcow2-forensic — `core/tests/data/cirros-0.6.3-x86_64-disk.img` (21 MB) · REAL-ext ✓
CirrOS 0.6.3. Also synthetic qemu-img variants (backing file, snapshot, encryption) per
`docs/validation.md`. Redistribution: CirrOS permissive.
**Download:** <https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img>.

### B2 · ewf-forensic — `tests/data/` · SYNTHETIC + VENDORED ✓
Synthetic E01/Ex01 built with `ewfacquire`, exact recipes in `tests/data/README.md`:
```bash
# zeros_128s.Ex01
dd if=/dev/zero bs=512 count=128 | ewfacquirestream -f encase7-v2 -d sha1 -d sha256 -t /tmp/test_ex01
# multiseg_v1.E01..E08  (segmented)
dd if=/dev/urandom bs=1M count=10 of=urandom_10m.img
ewfacquire -u -f encase6 -S 1500000 -c none -t multiseg_v1 -d md5 -d sha1 urandom_10m.img
# ewfacquire_clean.E01
dd if=/dev/zero bs=512 count=8192 of=blank_4mb.img
ewfacquire -u -f encase6 -c none -t ewfacquire_clean -d md5 -d sha1 blank_4mb.img
```
VENDORED error-path blobs from sleuthkit `test/data`: `bogus.E01`/`E02` (0-byte), `gpt_130_partitions.E01`.
`zeros_128s_compressed.Ex01` hand-built via Python `zlib.compress(level=1)` (structure documented,
command not scripted). Fuzz corpus 188 KB / 1.1 MB.

### B3 · vmdk-forensic — `core/tests/data/` (6.8 MB) · SYNTHETIC ✓
`qemu-img`, per `core/tests/data/README.md`:
```bash
qemu-img create -f vmdk minimal.vmdk 1M
qemu-img create -f vmdk -o subformat=streamOptimized   stream_opt.vmdk 1M
qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat flat.vmdk 1M
```
Fuzz corpus 111 MB (coverage-guided).

### B4 · vhdx-forensic — `*/tests/data` (~121 MB) · SYNTHETIC ✓ / ~
`qemu-img`, per `docs/validation.md`:
```bash
qemu-img create -f vhdx                  qemu_empty_dynamic.vhdx 16M
qemu-img create -f vhdx -o subformat=fixed qemu_fixed.vhdx        8M
```
`fat-parent.vhdx` + `fat-differential.vhdx` (Hyper-V parent/differential chain) and `ext2.vhd` are
committed without a scripted command — provenance **~** (Hyper-V tooling, not recorded).
`_archived/vhdx-core` holds the pre-split legacy copies (86 MB).

### B5 · vhd — `vhd/tests/data/` (5 MB) · SYNTHETIC ✓
`qemu-img`, per `vhd/tests/data/README.md`:
```bash
qemu-img create -f vpc                  minimal.vhd 1M
qemu-img create -f vpc -o subformat=fixed fixed.vhd 1M
```

### B6 · dd — `dd/dd/tests/data/` (16 MB) · SYNTHETIC ~  ·  dmg — `dmg/dmg/tests/data/` (840 KB) · REAL-self ~
dmg fixtures via macOS `hdiutil`; dd raw images for the flat provider. **Generators not scripted in
the repos** — provenance ~ (regenerate dd via `dd if=… of=…`; dmg via `hdiutil create`).

### B7 · aff4 — `aff4/tests/data/` (14 MB) · REAL-ext + VENDORED ✓
Evimetry/AFF4 sample images; **VENDORED** AFF4 Canonical Images from github.com/aff4/Standard.
Redistribution: AFF4 standard suite license.

### B8 · iso9660-forensic — `iso/tests/data/` (1.7 GB) · REAL-ext + SYNTHETIC ✓
Synthetic ISOs via `xorriso`/`hdiutil` + real downloads, per `docs/validation.md` (`SRC` = a
populated source dir):
```bash
xorriso -as mkisofs -o rock_ridge.iso -V ROCK_RIDGE -r "$SRC"
xorriso -as mkisofs -o joliet.iso     -V JOLIET     -J "$SRC"
xorriso -as mkisofs -o eltorito.iso   -V EL_TORITO -b boot.img -c boot.catalog -no-emul-boot -r -J \
        -graft-points boot.img=/tmp/boot.img "$SRC"
hdiutil makehybrid -o udf_bridge.iso -iso -joliet -udf "$SRC"            # macOS
curl -L https://github.com/log2timeline/dfvfs/raw/main/test_data/iso9660.raw -o dfvfs_plain.iso
curl -L https://github.com/exiftool/exiftool/raw/master/t/images/ISO.iso       -o truncated.iso
```
Real OS ISOs (**gitignored, user-downloaded**): `debian-13.5.0-amd64-netinst.iso` (755 MB, GPL),
Windows Server `17763.1.*.iso` (335 MB — MS license, do not redistribute). **issen mirror:**
`crates/issen-iso/tests/data/ubuntu-20.04-mini.iso` (74 MB, Canonical).

### B9 · udf-forensic · empty
No committed test data (`tests/data` is 0 B) — tests are in-memory synthetic.

---

## C. Filesystem / partition / compression fixtures

### C1 · ntfs-forensic — `core/tests/data/defcon2018_cdrive_boot.bin` (4 KB) · REAL-ext ✓
NTFS boot sector extracted from the **DEF CON 2018** `MaxPowers` E01 via TSK
`fsstat -o 1026048`. Ground-truth values asserted in `core/tests/real_image.rs`. Redistribution:
DEF CON CTF.

### C2 · mft — `samples/MFT` (13 MB) + `samples/entry_*` + `testdata/*` · REAL ? 
A full real `$MFT` plus hand-picked single records exercising fixup/data-run/ADS edge cases
(`entry_102130_fixup_issue`, `entry_long_name_and_res_ads_002`, …), extracted via `icat`. **Source
image not documented — provenance undetermined; likely private casework.** Flag for redistribution
review before any external release.

### C3 · ext4fs-forensic — `tests/data/{minimal,forensic}.img` (10 MB) · SYNTHETIC ✓
Built by committed scripts `tests/create-minimal-image.sh` and `tests/create-forensic-img.sh`
(the latter in a `--privileged debian:bookworm-slim` container):
```bash
# minimal.img
dd if=/dev/zero of=minimal.img bs=1M count=4
mkfs.ext4 -F -b 4096 -O extents,metadata_csum,64bit,extra_isize -L test-ext4 minimal.img
mount -o loop minimal.img /mnt; echo -n 'Hello, ext4!' > /mnt/hello.txt; mkdir /mnt/subdir; umount /mnt
# forensic.img
dd if=/dev/zero of=forensic.img bs=1M count=32
mkfs.ext4 -F -L forensic-test -O has_journal,metadata_csum,64bit,extents -b 4096 forensic.img
# mount → write files + symlinks + setfattr xattrs → create deleted-file.txt/deleted-large.txt,
# save their inode #s to deleted-ino.txt (stat -c %i), then rm them and umount  (deleted-inode recovery)
```

### C4 · hfsplus-forensic — `tests/data/hfs_plus_*.bin` (1.6 MB) · REAL-self ✓
HFS+ volumes created via macOS `hdiutil create -layout SPUD`; real Apple filesystem structures
with known files (`HELLO.TXT` = "hello hfs"). Asserted in `tests/catalog.rs`.

### C4b · hfsplus-forensic decmpfs — `tests/data/decmpfs/` (~4.3 MB) · REAL-self ✓
HFS+/APFS transparent-compression (`decmpfs`) fixtures — **every codec validated against REAL
macOS-produced bytes** (oracle = the original file). **LZVN (7/8):** `lzvn.rsrc`+`lzvn.expected`
(`ditto --hfsCompression`, type-8, 2×64 KiB, 80000 B) and `hfs_decmpfs_volume.bin` (4 MiB layout-NONE
HFS+ volume: `comp.bin` = type-8 LZVN 262144 B + `plain.bin` uncompressed control; payload = LCG block
×32 regenerated in-test). **zlib (3/4) + LZFSE (11/12):** `real_{zlib,lzfse}_rsrc.rsrc` and
`real_{zlib,lzfse}_inline.payload`, minted via `afsctool -c -T ZLIB|LZFSE` (Apple's real compressor —
macOS ships only LZVN). Only synthetic fixture: `zlib_type3_stored.payload` (the `0xFF` "stored" marker,
which the real compressor never emits). macOS hides `com.apple.decmpfs`; type read via
`getxattr(..., XATTR_SHOWCOMPRESSION)`. Real data caught 2 bugs synthetic fixtures masked (zlib offset
base = headerSize+4; LZFSE zero-padded chunk table). Generators in `hfsplus-forensic/tests/data/README.md`.
Asserted in `core` lib tests + `tests/decmpfs_integration.rs`.
**Tahoe (macOS 26.5, build 25F71) regression:** `tahoe_type8.rsrc`+`.expected` (a real type-8 LZVN
resource fork that carries 80–300 trailing bytes *after* the end-of-stream opcode) and
`tahoe_type9.decmpfs`+`.expected` (a real type-9 uncompressed-inline xattr with its 1-byte `0xCC`
storage marker). Captured by mounting a `macos-tahoe-vanilla` VM disk read-only on the host and reading
`com.apple.decmpfs`/`com.apple.ResourceFork` via `getxattr(..., XATTR_SHOWCOMPRESSION=0x20)`; oracle =
Apple `COMPRESSION_LZVN` (`0x900`) + the kernel's transparent read. Exposed 2 bugs synthetic `ditto`
fixtures masked — type-8 strict-trailing reject (fixed via the `lzvn` crate) and type-9 unstripped
marker — taking real-sample decoding from **0/35 → 35/35**.

### C5 · apm-partition-forensic — `forensic/tests/data/apm_map.bin` (2 KB) · REAL-self ✓
Apple Partition Map + DDM from an `hdiutil` HFS+ image (2 partitions). `forensic/tests/map.rs`.

### C6 · usnjrnl-forensic — feature-gated `tests/data/` · REAL-ext ✓ (external)
Uses the **Szechuan Sauce desktop E01** (A3) for `image_integration.rs` / `precision_recall.rs`
(`#[ignore]`, manual placement). Own committed `tests/data` is 0 B (report tests are synthetic).

### C7 · dar-forensic — `forensic/tests/data/v7..v11_hello.dar` (5 files) · SYNTHETIC ✓
Each archive built with the matching upstream `dar` release (2.3.12→2.8.5 = format 7→11; v7 in a
`gcc:4.9` container), per `forensic/tests/data/README.md`:
```bash
mkdir -p /tmp/corpus/files && printf 'hello format 7\n' > /tmp/corpus/files/hello.txt
<dar-2.3.12>/dar -Q -c /tmp/archive -R /tmp/corpus -g files/hello.txt && cp /tmp/archive.1.dar v7_hello.dar
# then dar 2.4.24 → v8, 2.5.3 → v9, 2.6.16 → v10, 2.8.5 → v11 (same shape, version-specific text)
```

### C8 · lzo — `tests/data/*.{raw,lzo}` (8 pairs) · SYNTHETIC + REAL ✓
`.lzo` produced by the reference `liblzo2` via `validation/lzo_compress.c`, per `docs/validation.md`:
```bash
cc -O2 -I"$(brew --prefix lzo)/include" validation/lzo_compress.c -L"$(brew --prefix)/lib" -llzo2 -o /tmp/lzo_compress
/tmp/lzo_compress 1   empty.raw  empty.lzo     # lzo1x_1 opcode probes: empty/hello/run_a/pattern/incompressible
/tmp/lzo_compress 999 readme.raw readme.lzo    # lzo1x_999 on REAL content: README.md, src/lib.rs
```
`.raw` inputs = hand-crafted probes + the project's own `README.md`/`src/lib.rs`.

### C8b · lzvn (`SecurityRonin/lzvn`, crate `lzvn-core`) — `tests/data/*.{lzvn,expected}` (4 pairs) · SYNTHETIC (Apple-encoded) ✓
`.lzvn` = real Apple LZVN streams from Apple's own `compression_encode_buffer(COMPRESSION_LZVN, 0x900)`
over synthetic inputs (`text_small`, `text_repeats` = heavy match/overlap, `mixed`, `near_random`), each
padded with trailing bytes after end-of-stream to exercise length-tolerance (the `decmpfs` block shape).
Inputs are synthetic so the fixtures are freely redistributable. The decoder was additionally validated
against the 25 real macOS 26.5 type-8 blocks above (C4b `tahoe_type8.*`) vs the same Apple oracle. Generator
in `lzvn/docs/validation.md`; fuzz target `decode` (clean over 1.37M runs).

### C9 · gpt- / mbr-partition-forensic, ntfs/usnjrnl records · SYNTHETIC ✓
No committed images — fixtures are constructed **byte-by-byte by Rust builders in the tests** (no
shell): gpt `header_sector()`/`entry_bytes()`/`build()` (`forensic/tests/reconcile_tests.rs`), mbr
`windows7_boot()`/`disk_with_boot_and_serial()` (`forensic/tests/disk_signature_tests.rs`), and the
ntfs/usnjrnl USN+MFT record constructors in unit tests. Fuzz corpora harness-seeded.

### C10 · 4n6mount — `fuzz/corpus/session_deserialize/` (23 MB) · FUZZ
Coverage-guided session-deserialization corpus; no curated seeds.

---

## D. Log / memory / application-artifact corpora

### D1 · winevt-forensic — `tests/data/` (1.4 GB) · REAL-ext + VENDORED ✓
- **CyberDefenders "CorporateSecrets" Lab** — `…/evtx/*.evtx` (~101 real Windows EVTX channels).
  cyberdefenders.org (educational license).
- **Fox-IT DanderSpritz** — `fox-it-danderspritz/pre-Security.evtx` (+ pair). Publicly published;
  the **differential-parity oracle** in `tests/real_corpus_parity.rs` (decoder vs omerbenamram).
- **DEF CON DFIR CTF 2018** EVTX subset.
- **VENDORED attack samples:** `EVTX-ATTACK-SAMPLES` (markbaggett, ~278), Hayabusa
  (Yamato-Security, ~292), MITRE samples, DFIRArtifactMuseum. Attribution required on derivatives.

### D2 · srum-forensic — `tests/data/` (16 MB) · REAL ~
`SRUDB.dat` ESE database sample(s) for the SRUM parser. Source not explicitly documented — confirm
before redistribution.

### D3 · memory-forensic — `tests/data/` (24 KB) · SYNTHETIC ✓
Small synthetic structures only. **The large memory CTFs (Cridex, TOTAL_RECALL, CyberSpace,
DeepDive) physically live in `issen/tests/data` (A6), not here** — referenced cross-repo.

### D4 · brave-browser-sessions (snss-core) — `crates/snss-core/tests/fixtures` (4.3 MB) · REAL-self ✓
Real Chromium/Brave SNSS session-restore snapshots (3). Contain real browsing state — sanitize
before external sharing.

### D5 · chat4n6 — plugin `tests/fixtures` · SYNTHETIC ~ / UNDETERMINED ?
WhatsApp/Telegram/Signal/iOS SQLite **schema DDL** fixtures (synthetic schemas). Some android/social
fixture dirs present but contents not enumerable — undetermined.

### D6 · ufed — `ufed/tests/data` (1 MB) · SYNTHETIC ✓
Deterministic xorshift-PRNG corpus (regenerable from seed `0xDEADBEEF`).

### D7 · RapidCollect — `crates/*/tests/fixtures` · SYNTHETIC ~ / UNDETERMINED ?
Integration-manifest roundtrip fixture (synthetic); android/twitter/instagram fixture dirs
undetermined.

### D8 · sqlite-forensic text-encoding fixtures — `sqlite-forensic/tests/data/` · REAL-self ✓
Genuine `sqlite3`-engine output validating per-encoding TEXT decode (header byte 56).
Generators (the `PRAGMA encoding` must precede any table):
```
sqlite3 utf8.sqlite    "PRAGMA page_size=512; PRAGMA encoding='UTF-8';    CREATE TABLE t(s TEXT); INSERT INTO t VALUES('héllo wörld');"
sqlite3 utf16le.sqlite "PRAGMA page_size=512; PRAGMA encoding='UTF-16le'; CREATE TABLE t(s TEXT); INSERT INTO t VALUES('héllo wörld');"
sqlite3 utf16be.sqlite "PRAGMA page_size=512; PRAGMA encoding='UTF-16be'; CREATE TABLE t(s TEXT); INSERT INTO t VALUES('héllo wörld');"
```
MD5: `utf8` 1d0923bb2ad0fee1c6f8cd8140a9ac61 · `utf16le` f2c418e5a1e14ce7f56e28b0e2266f9f ·
`utf16be` 8f260ddb30f34b7de3c9e13a23f7981a. Consumed by `core/tests/utf16_text_tests.rs`
(skip-if-absent). Header byte 56 = 1/2/3 respectively.

### D9 · peripheral-forensic — `tests/data/` (committed) · SYNTHETIC (spec-exact) ✓
External-device (peripheral) connection forensics. Hand-authored `setupapi.dev.log` / `setupapi.log`
fixtures matching the Microsoft SetupAPI text-log grammar — NO generator command (spec-exact bytes;
the build host is macOS and has no real log). Consumed by `forensic/tests/real_data.rs`.
- **Spec citations:** *SetupAPI Text Logs* + *Format of a Text Log Section Header*
  (learn.microsoft.com/.../setupapi-text-logs); USB id grammar `USB\VID_v(4)&PID_d(4)&REV_r(4)`
  (.../standard-usb-identifiers); OS-generated-serial rule (instance-id 2nd char `&`)
  (.../instance-ids).
- **Real-capture path:** mount a USB/FireWire/Thunderbolt device on a Windows VM, copy
  `C:\Windows\INF\setupapi.dev.log` (Vista+) / `C:\Windows\setupapi.log` (XP). Never commit a real
  person's log — it embeds every device serial they ever attached.
- MD5: `setupapi.dev.log` 8e86d3a0c7e5d1209a4d7c81d3b0a023 ·
  `setupapi_xp.log` d1bdd7199b5f134421143ce5dc445474.

### D10 · useract-forensic — `tests/data/real_bash_history` (committed) · REAL-self ✓
User-activity correlation layer (merges `shellhist-core` + `peripheral-core` into one `UserActivity`
timeline). The one fixture is a genuine `.bash_history` authored by the `bash` shell's own history
writer (`history -s` + `history -w`, `HISTTIMEFORMAT` set so bash emits `#<epoch>` lines), with a
planted `curl … | sh` and `unset HISTFILE`; the device side of the test is a real
`peripheral_core::DeviceConnection` built in-code (no fixture). Full per-file detail + verbatim
generator command in
[`useract-forensic/tests/data/README.md`](https://github.com/SecurityRonin/useract-forensic/blob/main/tests/data/README.md).
- MD5: `real_bash_history` 2a4ead0e64d175c7414bb37f23dbed73 (epoch values differ per run; structure
  fixed).

### D11 · lnk-forensic — `tests/data/` (committed) · SYNTHETIC (spec-exact) ✓
Windows Shell Link (`.lnk`) + Jump List forensics. Four hand-authored fixtures (the build host is
macOS and cannot author a real `.lnk`/Jump List); full per-file detail + the generators in
[`lnk-forensic/tests/data/README.md`](https://github.com/SecurityRonin/lnk-forensic/blob/main/tests/data/README.md).
- **`.lnk` fixtures** (`gen_lnk.rs`, dependency-free `rustc`): `removable_media.lnk`
  (DRIVE_REMOVABLE, serial 0xDEADBEEF, label KINGSTON USB, TrackerDataBlock ANALYST-PC) +
  `network_share.lnk` (CommonNetworkRelativeLink `\\SERVER\share`).
- **Jump List fixtures** (`core/examples/gen_jumplist.rs`, needs the `cfb` crate — run
  `cargo run --example gen_jumplist -p lnk-core`): `pinned_removable.automaticDestinations-ms` — a
  real OLE/CFB compound file, DestList v2 (Win10) one pinned entry (hostname OTHER-PC, access count 7,
  path `E:\report.docx`) + a hex-named LNK sub-stream (removable serial 0xDEADBEEF); and
  `tasks.customDestinations-ms` — flat version-2 file, one user-tasks category, embedded LNK split by
  the LNK CLSID + 0xBABFFBAB footer. All hostnames/serials/paths are synthetic placeholders; no real
  user's `.lnk`/Jump List committed.
- **Spec citations:** `[MS-SHLLINK]` (Shell Link); libyal `dtformats` *Jump lists format* (DestList /
  CustomDestinations); kacos2000 `Jumplist-Browser` `AppIdlist.csv` (AppID map).
- MD5: `removable_media.lnk` ba3dbe2429bdfa93d8a0a9be80ca0fbe · `network_share.lnk`
  547e0d2686e6652d8d144fb1b767bf9a · `tasks.customDestinations-ms`
  1a6d7de2e2e1be2ba8e8dd11531a5ac3 · `pinned_removable.automaticDestinations-ms`
  b5683aa75b5425724b656681fe780906.

---

## E. issen-internal & misc

- `issen/crates/issen-dd/tests/data/ext4.raw` (4 MB) · **REAL-ext** — downloaded from log2timeline
  dfvfs (per `crates/issen-dd/docs/corpus-validation.md`):
  `curl -L https://github.com/log2timeline/dfvfs/raw/main/test_data/ext4.raw -o ext4.raw`. (Apache-2.0.)
- `issen/crates/issen-iso/tests/data/ubuntu-20.04-mini.iso` (74 MB) · REAL-ext — Canonical
  (<https://old-releases.ubuntu.com/releases/20.04/>; mini netboot ISO).
- `issen/crates/issen-remote-access/tests/fixtures/lolrmm/*.yaml` (~30 KB) · SYNTHETIC — RMM rule fixtures.
- `disk-forensic/tests/data/` (21 MB) · SYNTHETIC — multi-format mini images (`df.qcow2`, `df.vhdx`,
  `df.iso`, `gpt_130_partitions.E01`, …) for the container/normalize tests. `ntfs.vmdk` wraps the
  **real** NTFS boot region from the DEF CON 2018 `MaxPowers` E01 (per `docs/VALIDATION.md`;
  hand-constructed, no scripted command).
- `blazehash/tests/data/nps-2010-emails.E01` (508 KB) · REAL-ext — NIST/NPS **nps-2010-emails**
  reference corpus (Garfinkel real-data corpus; public).

---

## F. Fuzz corpora (machine-evolved — not curated samples)

libFuzzer corpora across the fleet, coverage-guided mutations (no hand-curated seeds unless noted):
`vmdk-forensic` 111 MB · `vhdx-forensic` build dirs · `4n6mount` 23 MB · `ntfs-forensic` 3.9 MB ·
`dar-forensic` 4.4 MB · `usnjrnl-forensic` 1.4 MB · `ewf-forensic` 1.1 MB · `ext4fs-forensic` 268 KB
· `iso9660`/`aff4`/`dd`/`dmg`/`qcow2`/`vhd`/`apm`/`gpt`/`mbr` (seeded by harness). Reproducible by
re-running `cargo fuzz`; safe to regenerate/delete.

---

## G. Provenance caveats & actions

1. **Undetermined real sources to resolve:** `mft/samples/MFT` (13 MB) and `srum-forensic` SRUDB
   lack in-repo source documentation. Resolve before any redistribution.
2. **Do-not-redistribute:** Windows Server ISO (B8, MS license); anything with real personal data
   (`Collection-A380`, Brave SNSS, `mft/samples/MFT` if casework) — sanitize/verify first.
3. **Integrity:** every corpus file MD5-verified 2026-06-09 (manifest in §H). `DESKTOP-E01.zip`
   matches DFIR Madness's published MD5 exactly. The DEFCON/Magnet "MD5" values quoted above are EWF
   *media* hashes (`ewfinfo` — the imaged drive), **not** container-file hashes, so the file-MD5s in
   §H correctly differ. Re-verify with `md5` / `Get-FileHash` for evidence-grade use.

---

## H. MD5 manifest

File hashes of every downloadable corpus artifact (`md5`, 2026-06-09). `tests/data/` is gitignored,
so these are recorded here. Verify a download with `md5 <file>` (macOS) / `md5sum <file>` (Linux) /
`Get-FileHash -Algorithm MD5 <file>` (PowerShell). `Szechuan/` = the
`DFIR Madness "Stolen Szechuan Sauce" Case 001 — Windows 10/` folder.

| File | Size (bytes) | MD5 |
|---|---|---|
| `loghub-openssh/OpenSSH_2k.log` | 225216 | `72efdaaf373b8d6c8a809cc86b2a951f` |
| `DEF CON DFIR CTF 2018/MaxPowersCDrive.E01` | 31577797290 | `bed3b3ddece20d136a56aa653f0de608` |
| `Magnet Virtual Summit 2023 … Windows 11/PC-MUS-001.E01` | 52629766482 | `8cf0c007391f4a72ddc12a570a115b46` |
| `Szechuan/DESKTOP-E01.zip` | 6843484923 | `71c5c3509331f472abcdf81eb6efff07` |
| `Szechuan/DC01-E01.zip` | 4836649413 | `e57fc636e833c5f1ab58dface873bbde` |
| `Szechuan/DESKTOP-SDN1RPT-memory.zip` | 802767348 | `cf31e2635c77811aaa1bb04a92a721e2` |
| `Szechuan/DC01-memory.zip` | 561424278 | `64a4e2cb47138084a5c2878066b2d7b1` |
| `Szechuan/Desktop-SDN1RPT-pagefile.zip` | 222055350 | `45c096f2688a0b5de0346fb72391b245` |
| `Szechuan/DC01-pagefile.zip` | 13540216 | `964eeaf0009d08cc101de4a83a4e5d23` |
| `Szechuan/case001-pcap.zip` | 151610116 | `422046b753cf8a4df49d2c4ce892db16` |
| `Szechuan/DESKTOP-SDN1RPT-Protected Files.zip` | 17127742 | `3e1a358d50003a9351ac2160ae6f0495` |
| `Szechuan/DC01-ProtectedFiles.zip` | 12297759 | `ad29830a583efe49c8c1c35faffd264f` |
| `Szechuan/DESKTOP-SDN1RPT-autorunsc.zip` | 278645 | `3627dcafa54e1365489a4ec0cc3d6a1c` |
| `Szechuan/DC01-autorunsc.zip` | 177298 | `964f2d710687d170c77c94947da29e66` |
| `Hal Linux DFIR Challenge/uac-vbox-linux-20260324193807.tar.gz` | 149915196 | `a76f795aa8e35218f93bb44801023009` |
| `Hal Linux DFIR Challenge/uac-vbox-linux-20260324234043.tar.gz` | 6205082254 | `ddc894d978fffd4f722539dd52dfd00f` |
| `Collection-A380_localdomain-2025-08-10T03_41_20Z.zip` | 2352737548 | `8294ee2768f934e84d5a8b8b150a6138` |
| `CyberDefenders/78-DeepDive.zip` | 562807907 | `2c6d06eef52cae743e16633fe4ee1734` |
| `CyberSpace CTF 2024/csctf-2024_forensics_memory.zip` | 703693665 | `c4821afa54754127a3a2161bafccea90` |
| `SecurityNik/TOTAL_RECALL_memory_forensics_CHALLENGE.zip` | 1317299287 | `7dceb1fcae2ed8beacc8f81f85bf935c` |
| `Volatility/cridex_memdump.zip` | 40352364 | `ebcbb798f7fa5df87375dbc4ee329209` |

(The inner `…-235706.dmp` carries its own published SHA256 — see §A6.)
