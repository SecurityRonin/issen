# Test Data — Issen

Forensic disk images, UAC collections, and other test artifacts.
These files are large and not tracked in git — download them manually.

Files are organized into per-challenge or per-source subfolders.

## Directory Layout

```
tests/data/
├── DEF CON DFIR CTF 2018/
│   └── MaxPowersCDrive.E01
├── DFIR Madness "Stolen Szechuan Sauce" Case 001 — Windows 10/
│   └── DESKTOP-E01.zip
├── Hal Linux DFIR Challenge/
│   ├── uac-vbox-linux-20260324193807.tar.gz    (143 MB — no memory dump)
│   └── uac-vbox-linux-20260324234043.tar.gz    (5.9 GB — includes avml.lime)
├── Magnet Virtual Summit 2023 CTF — Windows 11/
│   └── PC-MUS-001.E01
└── Collection-A380_localdomain-2025-08-10T03_41_20Z.zip   (2.2 GB — root)
```

## Files

### DEF CON DFIR CTF 2018/

#### MaxPowersCDrive.E01

- **Source:** DEFCON DFIR CTF 2018, organized by David Cowen
- **Identity:** Image 3 (Desktop) — C: drive of user `mpowers` (Max Powers)
- **EWF metadata:** Case "MaxPowers-1", examiner "Professor Frink", linen 5 format, acquired May 5, 2018 with f-response
- **Blog:** <https://www.hecfblog.com/2018/08/daily-blog-451-defcon-dfir-ctf-2018.html>
- **Writeup:** <https://or10nlabs.tech/defcon-dfir-ctf-2018/>
- **Original download:** <https://www.dropbox.com/s/jvaqb4rfi3jojbk/Image3.7z> (may be expired)
- **MD5:** `10c1fbc9c01d969789ada1c67211b89f`
- **Notable contents:** Has `pagefile.sys` and `swapfile.sys` but NO `hiberfil.sys` (hibernation was disabled)

### DFIR Madness "Stolen Szechuan Sauce" Case 001 — Windows 10/

#### DESKTOP-E01.zip

- **Source:** DFIR Madness — "The Case of the Stolen Szechuan Sauce" (Case 001)
- **Created by:** James Smith (DFIR Madness)
- **Description:** Windows 10 desktop disk image; part of a multi-artifact case (also includes DC01 server, memory dumps, PCAP, pagefiles)
- **Site:** <https://dfirmadness.com/the-stolen-szechuan-sauce/> (may be down)
- **Mirror:** <https://mimircyber.com/the-case-of-the-stolen-szechuan-sauce/>
- **MD5:** `71C5C3509331F472ABCDF81EB6EFFF07`

### Hal Linux DFIR Challenge/

Used by automated tests in `rt-parser-uac` and `rt-navigator`. The small archive runs in CI; the large one is `#[ignore]`d unless explicitly requested.

#### uac-vbox-linux-20260324193807.tar.gz (143 MB)

- **Source:** Self-collected using UAC on a Linux VirtualBox VM, March 24, 2026
- **Tool:** [UAC — Unix-like Artifacts Collector](https://github.com/tclahr/uac)
- **Contents:** Filesystem artifacts only (no memory dump) — bodyfile, network, processes, system info, etc.
- **Use case:** UAC parser integration tests (`rt-parser-uac`, `rt-navigator`)

#### uac-vbox-linux-20260324234043.tar.gz (5.9 GB)

- **Source:** Self-collected using UAC on a Linux VirtualBox VM, March 24, 2026
- **Tool:** [UAC](https://github.com/tclahr/uac) with AVML memory acquisition
- **Contents:** Full UAC collection including `memory_dump/avml.lime` (~5.5 GB AVML-format memory dump)
- **Use case:** End-to-end UAC pipeline tests including memory dump detection, AVML format provider, Linux process/module/network walking

### Magnet Virtual Summit 2023 CTF — Windows 11/

#### PC-MUS-001.E01 (50 GB)

- **Source:** Magnet Virtual Summit 2023 CTF — Windows 11 challenge
- **Created by:** Jessica Hyde and Champlain College Digital Forensic Association (DFA) for Magnet Forensics
- **EWF metadata:** Case "1", evidence "PhysicalDrive0", EnCase 6 format, acquired Jan 7, 2023
- **Writeups:**
  - <https://www.stark4n6.com/2023/03/magnet-virtual-summit-2023-ctf-windows.html>
  - <https://download.getdata.com/support/documents/ctf/Magnet%20Virtual%20Summit%202023%20CTF%20-%20Windows%2011.pdf>
  - <https://getdataforensics.com/capture-the-flag/>
- **MD5:** `522df9db8289f4f8132cf47b14d20fb8`
- **Notable contents:** Contains `hiberfil.sys` (MFT entry 54, 3.37 GB allocated) — usable as real test data for `memf-format` hiberfil provider

### Root (self-collected, no challenge affiliation)

#### Collection-A380_localdomain-2025-08-10T03_41_20Z.zip (2.2 GB)

- **Source:** Self-collected using UAC from host `A380_localdomain`, August 10, 2025
- **Tool:** [UAC](https://github.com/tclahr/uac)
- **Use case:** Velociraptor parser integration tests (`rt-parser-velociraptor`, `rt-navigator`)

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

## Test path references

Tests reference these files relative to the crate root (e.g., `../../tests/data/...`).
If you add a new file or subfolder, update the corresponding integration test and this README.

| Test file | Archive referenced |
|-----------|-------------------|
| `crates/parsers/rt-parser-uac/tests/integration_test.rs` | `Hal Linux DFIR Challenge/uac-vbox-linux-20260324193807.tar.gz` |
| `crates/parsers/rt-parser-velociraptor/tests/integration_test.rs` | `Collection-A380_localdomain-2025-08-10T03_41_20Z.zip` |
| `crates/rt-navigator/tests/collection_loading.rs` | Both of the above |
