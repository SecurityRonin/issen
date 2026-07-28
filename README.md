<p align="center">
  <img src="assets/issen-banner.png#gh-dark-mode-only"
       alt="Issen — point it at the case on your desk and read the attack story" width="640" />
  <img src="assets/issen-banner-light.png#gh-light-mode-only"
       alt="Issen — point it at the case on your desk and read the attack story" width="640" />
</p>

<p align="center">
  <a href="https://github.com/SecurityRonin/issen/releases"><img src="https://img.shields.io/github/v/release/SecurityRonin/issen?style=flat-square" alt="Release"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"/></a>
  <a href="https://github.com/SecurityRonin/issen/actions/workflows/ci.yml"><img src="https://github.com/SecurityRonin/issen/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.80%2B-orange.svg" alt="Rust 1.80+"/></a>
  <a href="#install"><img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg" alt="Platform"/></a>
  <a href="https://github.com/sponsors/h4x0r"><img src="https://img.shields.io/badge/sponsor-h4x0r-ff69b4.svg?logo=github-sponsors" alt="Sponsor"/></a>
</p>

**The image is on your desk. The clock is running. Point Issen at it — read the attack story.**

You have an acquisition and no time. Issen takes it from raw evidence to a correlated,
ATT&CK-mapped attack narrative in **one command** — no Python env, no dependency hell,
no config, nothing to set up. One static binary.

```bash
# You have evidence. Run this. That's the whole setup.
issen evidence.E01 memory.raw -o case.duckdb && issen report case.duckdb
```

It auto-detects the container (E01/EWF/VMDK/raw), triages the filesystem for the
artifacts that matter, walks the memory dump for process / network / injection state,
and correlates disk + memory + logs into one timeline — then hands you the findings,
ranked by severity, each with its full evidence chain. You don't write a query.

---

## What one command hands back

A real run — an AnyDesk RAT dropped through a service-account pivot, found and
MITRE-mapped without a single query written:

```
$ issen collection-WIN10-CORP-20260401.zip

  Host : WIN10-CORP | Windows 10 22H2 | collected 2026-04-01T14:32:07Z
  Parsed 1,247,831 MFT entries, 48 EVTX logs (312,406 events), 4 hives — 5.4s

+- CORRELATION FINDINGS ──────────────────────────────────

  [CRITICAL] LOLRMM with non-vendor C2 infrastructure          T1219, T1543.003
    AnyDesk under C:\ProgramData\Temp\Support\  (not Program Files)
    -> 194.36.28.117:7070  (AS 208323, RU — outside AnyDesk's relay network)
    evidence: MFT create + EVTX 7045 service + EVTX 5156 netconn + Run key

  [HIGH] Lateral movement via service account                  T1021.002
    Type-3 logon CORP\svc_backup from 10.20.5.44 (WIN-RUNBOOK)
    -> file drop + service install within 120s of logon

  2 findings | 1 critical, 1 high | 4 artifact sources correlated
```

Most tools hand you indicators and let you connect them. Issen joins the evidence
*across* sources — a network connection is not a finding on its own; combined with a
relocated RMM binary, a service install, and a logon from an internal host, it is the
attack. That is the whole point: it finds the **pattern**, not just the pieces.

---

## Install

```bash
# Prebuilt binaries — Windows .exe/.msi, Apple-silicon .dmg, Linux — on the Releases page:
#   https://github.com/SecurityRonin/issen/releases

# …or build from source (uses the pinned toolchain in rust-toolchain.toml)
cargo install --git https://github.com/SecurityRonin/issen issen-cli

issen --version
```

## Two minutes to your first timeline

```bash
# Point it at any mix of disk images and memory dumps. -o names the case database.
issen DC01.E01 DESKTOP.E01 DC01-memory.raw -o case.duckdb

# Read the result — correlated findings as text, or a self-contained HTML report
issen report case.duckdb --format text
issen report case.duckdb -o report.html
```

**Resumable by default — a long case is never lost.** Ingest fingerprints each artifact
by content, so re-running only re-parses what changed. A crash, an added source, or a
repeat run picks up where it stopped instead of redoing the case: an unchanged warm
re-ingest drops from **7.36 s → 0.20 s** (~37×).

---

## The commands you'll actually use

| Command | What it does |
|---|---|
| `issen <evidence…>` | **The default pipeline** — ingest disk + memory, correlate, scan, analyse memory, in one resumable pass (`-o` names the case DB) |
| `issen report <db>` | Correlated findings as text, or a self-contained HTML report |
| `issen timeline <db>` | Query/export the timeline (text, JSON, CSV, bodyfile; `--flagged --min-severity high`) |
| `issen memory <dump>` | Deep-analyse one memory dump (LiME/AVML/crash/raw) — processes, netstat, injection, creds |
| `issen scan <path>` | Files/indicators vs. threat-intel (YARA / Sigma / hash / STIX / Suricata) |
| `issen rules` · `issen feed update` | List bundled detections · refresh threat-intel feeds |

```bash
issen timeline case.duckdb --flagged --min-severity high   # only what matters, worst first
issen timeline case.duckdb --format bodyfile               # hand off to your timeline tool
issen memory dump.lime --command all                       # full memory triage
issen scan evidence/ --auto-feeds                          # YARA/Sigma/STIX sweep
```

---

## It stays fast on real evidence — measured, not asserted

- **Bounded RAM at any size.** Reads an **80 GB** macOS image straight from its
  deflate-compressed zip at **304 MB** peak RSS — RAM doesn't scale with image size.
- **Selective by design.** E01/EWF chunk-indexing and a pure-Rust DEFLATE index mean it
  decodes only the blocks a triage actually touches — no whole-image inflate.
- **Parallel and deterministic.** Sources and artifacts parse concurrently; the timeline
  is byte-identical regardless of which finishes first.
- **Columnar bulk-load.** Events land through DuckDB's columnar appender — the insert
  phase runs **~11× faster** (194 s → 17 s).

> **Tip:** it ingests fastest from randomly-accessible containers — **E01/EWF** (the
> recommended default), raw `.dd`, or a `.E01.zip`. Avoid `.tar.gz`/`.7z` for the working
> copy (no random access → full decompress first).

---

## What it reads, and what it finds

| | |
|---|---|
| **Disk images** | E01/EWF, raw DD (split), VMDK, VHD/VHDX, QCOW2, ISO9660 — auto-detected |
| **Filesystems** | NTFS (MFT / USN / hives / `$I$R`), ext4, APFS *(planned)* |
| **Memory** | LiME, AVML, WinPMEM, crash dump (DMP), hiberfil.sys |
| **Logs** | EVTX, Zeek `conn.log`, Suricata EVE, journald *(planned)*, Unified Log *(planned)* |
| **Artifacts** | MFT, USN, EVTX, registry (Shimcache/UserAssist/network), Amcache, Prefetch, LNK/Jump Lists, Recycle Bin, browser, SRUM, Apple Biome |
| **Detections** | YARA, Sigma, STIX 2.1 IOCs, hash IOCs, Suricata, **LOLRMM** (400+ RMM/RAT tools), CTID Attack Flow v3.0.0 |
| **Output** | terminal, JSON, HTML/PDF report, STIX 2.1 Attack Flow, `.afb`, Mermaid, DOT/PNG, CSV, bodyfile, DuckDB |

### Recover what was deleted

Live-file triage only sees what the filesystem still references. Add `--unallocated` to
carve the space *outside* live files — residual SQLite DBs, EVTX chunks, and registry
hives no directory entry points to any more. It works uniformly across E01/VMDK/QCOW2/
VHDX/DMG/ISO/raw (no extract step, even for a compressed `.E01`) and tags every recovered
item `recovery:unallocated-carve` in the same timeline.

```bash
issen DC01.E01 -o case.duckdb --unallocated
```

### Make it find *your* patterns

Detections are **data, not code** — versionable, shareable, reviewable in a PR:

```yaml
id: correlation.miner.rootkit-concealment
severity: critical
within_seconds: 300
clauses:
  - { source: artifact, required_tag: rootkit_indicator }
  - { source: memory,   required_tag: miner_thread }
  - { source: memory,   required_tag: mining_pool }
```

Drop YAML rules in `~/.config/issen/rules/`; they compose with the built-ins (miners,
rootkits, SSH tunnels, LD_PRELOAD persistence, hidden processes, LOLRMM) and every
`issen <evidence>` pass evaluates all of them. Ship them with your team.

---

## Trust but verify

Run end-to-end against a real **29 GB DEF CON E01** acquisition: Issen auto-detected the
container, triaged the NTFS volume, and parsed **843 artifacts** into a
**431,863-event** timeline. Synthetic fixtures miss real-world quirks — validation
against genuine acquired evidence is part of the development discipline.

---

## Part of a fleet

Issen is the thin **front door** to the **SecurityRonin forensic fleet** — 86
standalone, pure-Rust forensic libraries, each a deep expert in one artifact family and
each usable on its own in your tooling (input-fuzzed, panic-free by lint, single static
binary). The architecture, the five navigation primitives that unify
disk / memory / log / live-query / content-addressed evidence, and the full component
map live in the fleet umbrella:

**→ [ronin-issen](https://github.com/SecurityRonin/ronin-issen) — the fleet architecture, ADRs, and component map.**

---

## Acknowledgements

**Hal Pomeranz**, whose Linux forensics training documented the ext4 inode/block
internals informing the filesystem layer. **Yogesh Khatri** (@SwiftForensics), whose
[srum-dump](https://github.com/MarkBaggett/srum-dump) proved SRUM's forensic value and
documented the ESE schemas. **Yamato Security** and the
[hayabusa](https://github.com/Yamato-Security/hayabusa) team for pioneering fast
rule-based EVTX triage in Rust. The
[Volatility Foundation](https://github.com/volatilityfoundation/volatility3) for
open-sourcing the memory-forensics algorithms and kernel offsets. The
[Plaso](https://github.com/log2timeline/plaso) / log2timeline team for the super-timeline
model Issen builds on.

---

[Privacy Policy](https://securityronin.github.io/issen/privacy/) · [Terms of Service](https://securityronin.github.io/issen/terms/) · © 2026 Security Ronin Ltd.
