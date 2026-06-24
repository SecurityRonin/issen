# DFIR at Machine Speed — Gamma Deck Script

> **How to use this file.** Paste the content below (everything under the first `---`)
> into Gamma → *Create new* → *Paste in text* → *Cards (one per `---`)*.
> Each `---` is a new card; the `#` line is the card title; bullets become the card body.
> Suggested Gamma settings: **dark theme**, **16:9**, accent = teal/amber, "punchy" text density.
> Mermaid code-fences render natively in Gamma — leave them as-is.
>
> Status: **opening + fundamentals draft** (covers the front third of the 3-hour run-of-show:
> frame → architecture → pipeline fundamentals). Modules 2–5 (the hands-on hunt) follow the
> `DESIGN.md` run-of-show and get their own cards once the lab steps are frozen.
> Capability claims tracked against the current command-by-command walkthrough
> (`../szechuan-sauce-quickstart.md`) and the answer-pass log (`../tasks/STATUS.md`) — concept
> slides teach the artifact; the hands-on cards cite what the tool produces today.

---

# DFIR at Machine Speed

### One Rust-native toolchain, from raw image to board-ready narrative

**BSidesHK 2026 · Blue-Team Workshop · 3 hours, hands-on**

Albert Hui — Security Ronin · TA: Josiah Wu

*Case 001 — "The Stolen Szechuan Sauce" · disk + RAM only · two real Windows hosts*

---

# The Scenario

A Windows estate breached on **19 September 2020**:

- Attacker **brute-forces RDP** into a Domain Controller
- Drops **Meterpreter / `coreupdater.exe`**, injects into `spoolsv.exe`
- Beacons to a **C2 in Thailand** (`203.78.103.109:443`)
- Moves laterally **DC → Win10 desktop**, stages and **exfiltrates secrets**
- **Time-stomps a decoy** — and is *still interactive* at the moment of capture

You are the IR analyst. You receive the evidence cold. **Build the story.**

---

# The Evidence You Receive

Two victim hosts on domain **C137** (`10.42.85.0/24`):

| Host | Role | OS | Disk image | Memory |
|---|---|---|---|---|
| **CitadelDC01** `.10` | Domain Controller | Server 2012 R2 | `…CDrive.E01` | `citadeldc01.mem` |
| **DESKTOP-SDN1RPT** `.115` | Workstation | Win 10 Enterprise | `…SDN1RPT.E01` | `DESKTOP-SDN1RPT.mem` |

≈ **12.8 GB** total. Pre-staged on your USB stick / download link.

---

# The Full Case 001 Artifact Set

Everything DFIR Madness publishes for this case (`https://dfirmadness.com/case001/`):

**Domain Controller (CitadelDC01)**
- `DC01-E01.zip` — disk image · `DC01-memory.zip` — RAM · `DC01-pagefile.zip`
- `DC01-autorunsc.zip` · `DC01-ProtectedFiles.zip`

**Workstation (DESKTOP-SDN1RPT)**
- `DESKTOP-E01.zip` · `DESKTOP-SDN1RPT-memory.zip` · `Desktop-SDN1RPT-pagefile.zip`
- `DESKTOP-SDN1RPT-autorunsc.zip` · `DESKTOP-SDN1RPT-Protected Files.zip`

**Network**
- `case001-pcap.zip`

---

# What We Use Today — and Why

✅ **In scope:** **disk image + RAM dump** for *both* hosts. Nothing else.

This is **not** us simplifying the case. It is us **mimicking real post-incident IR**:

- In a real engagement you almost always get **a dead disk and (if you're lucky) a memory capture** — pulled after the fact.
- Everything else on that download page is a **convenience the CTF pre-cooked for you.** We refuse the convenience on purpose.

> The skill we are training is *working from what you actually get*, not from a tidy artifact bundle.

---

# Why No PCAP

`case001-pcap.zip` is **excluded** — deliberately.

- Full packet capture means **someone was already recording the wire** before/at the breach. In the field that is **rare** — most orgs have no retained PCAP at the moment that matters.
- Relying on PCAP teaches a habit that **breaks the day you don't have it.**
- The *outcomes* PCAP would show — the brute force, the C2 — are **independently provable** from disk (EVTX 4625/4624) and memory (netstat). We reconstruct them from artifacts that **survive**.

PCAP-only details (an NMAP 3389 probe at 02:19) become a **footnote**, not an assessable question.

---

# Why We Extract the System Files Ourselves

`*-autorunsc.zip` and `*-ProtectedFiles.zip` are **excluded** — also deliberately.

- Those are **pre-extracted hives, autoruns, locked files** — work a tool already did *in the lab*.
- Pulling `SYSTEM` / `SOFTWARE` / `SAM`, `$MFT`, EVTX, `SRUDB.dat` **out of the E01 by path** is a **core lab step** — so we do it ourselves, live.
- Locked/"protected" files (loaded hives, `pagefile.sys`) can't be copied off a live box normally — but on a **dead image every byte is reachable.** That's the lesson.

> Extraction *is* the exercise. You leave knowing how the sausage is made.

---

# One Trap to Internalize: The Clock

The victim VMs were **mis-configured to UTC−7**. The (excluded) PCAP router was **UTC−6**.

- Disk / EVTX / memory timestamps read **~1 hour ahead** of the network-clock narration in the official key.
- The key's `02:24:06` download = your tooling's **`03:24:06Z`** — *same instant, different clock.*

**Always establish clock provenance before you trust a timeline.** Issen surfaces this via `ClockProvenance` so the skew is a labeled fact, not a silent error.

---

# The Real Point of This Workshop

Knowing *which tool* and *where the artifact lives* feels like expertise. It is a **fake moat**:

- It is **mechanical** — lookup-table knowledge.
- In the age of AI it is being **unified, normalized, and automated away.**

The **real moat** is the **investigative mindset**:

- Reading what the output **means**
- Building the **attack narrative**
- **Presenting it** to a board with intellectual honesty

> We spend the *mechanical* time in **one** tool so the *cognitive* time goes where it counts.

---

# Why Issen Is Different

The traditional path: **FTK Imager + Volatility + Eric Zimmerman tools + KAPE** — four ecosystems, three languages, two OSes, glue scripts in between.

Issen's bet:

- **One cross-platform binary.** Native macOS / Windows / Linux. Rust. `cargo install`, no runtime.
- **One address space for the whole case** — disk, memory, logs converge into a single timeline.
- **Forensically paranoid by construction** — panic-free parsers, never trust a length field, fail loud on the unknown.
- **Findings, not verdicts** — every output is *"consistent with"*, leaving the conclusion to you.

---

# It's Not One Tool — It's a Fleet

Issen is a thin **orchestration layer** over a family of standalone, single-purpose forensic libraries.

- Each library is a **deep expert** in one artifact family (NTFS, EVTX, SRUM, memory paging…).
- Issen **wires them together** and correlates across them.
- Every library emits the **same normalized finding model**, so one report renders them uniformly.

The architecture is organized around **how an analyst navigates evidence** — five fundamental primitives.

---

# The Five Navigation Primitives

Every piece of evidence is reached by exactly one of five "navigation verbs":

| | Primitive | You navigate by… |
|---|---|---|
| **[P]** | **Disk** | `name → inode → block` (walk the filesystem tree) |
| **[M]** | **Memory** | `PID → EPROCESS → virtual addr → physical addr` |
| **[L]** | **Log** | `timestamp / record-# → boundary → field` |
| **[Q]** | **Live Query** | `endpoint, query, cursor → result rows` |
| **[C]** | **Content-addressed** | `hash → blob → Merkle graph` |

**Today we live in [P] and [M]** — disk and memory. ([L] logs live *on* the disk; [Q]/[C] are for live and CAS evidence.)

---

# The Fleet, Layered

```mermaid
flowchart TB
  K["KNOWLEDGE — forensicnomicon<br/>format specs, magic bytes, the report vocabulary"]
  C["CONTAINER — ewf / vmdk / vhdx / dd / memf-format<br/>raw image → addressable stream"]
  F["FILESYSTEM — ntfs / ext4 / apfs<br/>name → inode → block"]
  PG["PAGING + OS STRUCTURE — memf-hw / memf-windows<br/>VA → PA, EPROCESS, VAD, netstat"]
  L["LOG FORMAT — winevt (EVTX), journald<br/>seek by timestamp / record-id"]
  PA["PARSER — registry / srum / browser / prefetch<br/>records → forensic meaning"]
  O["ORCHESTRATION — Issen<br/>wire all paths, correlate, report"]
  K --> C --> F --> PA
  C --> PG --> PA
  C --> L --> PA
  PA --> O
  PG --> O
  L --> O
```

**Dependencies point down to KNOWLEDGE; evidence flows up to ORCHESTRATION.**

---

# The IR Analyst's Journey

We'll walk the **pipeline in the order you actually meet the evidence** — outside-in:

1. **Container** — the image format on your desk (E01, VMDK…)
2. **Partition table** — where are the volumes?
3. **File system** — NTFS: turn paths into bytes
4. **Filesystem timeline** — `$MFT`, USN journal, `$LogFile`
5. **Event logs** — EVTX
6. **Registry & SRUM** — system state and the usage ledger
7. **Memory** — the live truth the disk can't show
8. **Correlation → narrative → report**

> Each is a *fundamental* — learn it once, recognize it everywhere.

---

# 1 · Containers — What Lands on Your Desk

You never get "a disk." You get a **container**: a file that wraps the raw sectors.

| Format | Where it comes from | Issen reader |
|---|---|---|
| **E01 / EWF** | FTK Imager, EnCase — the IR standard. Compressed, hashed, segmented (`.E01`, `.E02`…) | `ewf` |
| **VMDK** | VMware virtual disks — half of all "servers" are VMs | `vmdk` |
| **VHD / VHDX** | Hyper-V, Azure | `vhdx` |
| **raw / dd / img** | `dd`, FTK "raw", Linux | `dd` |

**Job of this layer:** hand everything above it **one flat, addressable sector stream** — the container format becomes invisible.

> Our two case files are **E01** sets. Note the segments: `…E01` + `…E02` are *one* image.

---

# Container Gotchas Worth Knowing

- **E01 is a *set*, not a file.** `image.E01`, `image.E02`, … must travel together — they're one logical disk split for portability. Point the tool at the **first** segment; it finds the rest.
- **E01 carries its own hashes.** Acquisition stored an MD5/SHA. Verify it before you trust a single byte — chain of custody starts here.
- **Compression is transparent.** EWF is zlib-compressed under the hood; the reader inflates on the fly. You address sectors, not compressed blocks.

`issen ingest <first.E01>` opens the container for you — the rest of the pipeline never sees EWF again.

---

# 2 · Partition Tables — Finding the Volumes

A raw sector stream is not yet a filesystem. First: **where do the volumes start?**

- **MBR** (legacy) — 4 primary partitions, 32-bit LBA, the classic `0x55AA` boot signature at offset 510.
- **GPT** (modern) — 128 entries, 64-bit LBA, CRC-protected header, a protective MBR up front.

**What forensics looks for here:**
- Partition **boundaries** (so we mount the right NTFS volume)
- **Overlaps / gaps / hidden partitions** — a classic place to stash data
- A boot signature that **doesn't parse** → surface the raw bytes, don't guess

> The Windows system volume is the one we want — that's where `\Windows\System32` and the hives live.

---

# 3 · File Systems — Paths Into Bytes

NTFS is the navigation engine for `[P]`: **`name → inode → block`**.

- Everything is a file — even the metadata. The master record is **`$MFT`**.
- Each file = an MFT record of **attributes**: `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA`, `$INDEX`…
- **Resident vs non-resident:** small files live *inside* the MFT record; large files point out to **data runs** (cluster lists).
- **Deleted ≠ gone.** The MFT record and its runs often survive until overwritten — that's how we **carve**.

**Our job:** resolve `C:\Windows\System32\coreupdater.exe` → MFT record → clusters → bytes, with **zero trust** in any length field along the way.

---

# The Two Timestamps That Catch Liars

Every NTFS file carries **two** sets of MAC times:

- **`$SI` — `$STANDARD_INFORMATION`** — what Explorer shows. **User-writable** via the Windows API.
- **`$FN` — `$FILE_NAME`** — kernel-maintained, **much harder to forge.**

**Timestomping** rewrites `$SI` to hide when malware really landed. The tell:

> `$SI.modified` **earlier than** `$FN.created` → physically impossible → **manipulation.**

In our case the attacker stomps **`Beth_Secret.txt`**. The `$SI`/`$FN` split is how we prove it — a finding flagged *Info → lead*, because the heuristic has false positives and the analyst confirms.

---

# 4 · The Filesystem Timeline — Change History

NTFS journals its own changes. Three artifacts reconstruct *what happened to files, when*:

| Artifact | What it records | Why it matters here |
|---|---|---|
| **`$MFT`** | Current state + `$SI`/`$FN` MAC times | When `coreupdater.exe` first appeared; the timestomp |
| **`$UsnJrnl:$J`** | A rolling log of **every** create / delete / rename / write | `secret.zip`, `loot.zip` **staged and deleted** — even after the file is gone |
| **`$LogFile`** | Transaction log (metadata replay) | Lowest-level corroboration / recovery |

> USN is the hero of exfil hunting: it remembers the `loot.zip` that the attacker **created and then deleted** to cover tracks.

---

# 5 · Event Logs — EVTX (the [L] Path)

Windows event logs are the **[L]og** primitive: seek by **record-id / timestamp → field**.

- Binary **EVTX** format, BinXML-encoded — not text. We decode chunks → typed `EventRecord`.
- Extracted **from the disk** by path: `…\Security.evtx`, `System.evtx`.

**The story lives in a handful of Event IDs:**

| EID | Meaning | In this case |
|---|---|---|
| **4625** | Logon **failure** | The RDP brute-force **flood** |
| **4624** | Logon **success** (type 10 = RDP) | Compromise: `Administrator` from `194.61.24.102` |
| **7045** | **Service installed** | `coreupdater` persistence |
| **4634/4647** | Logoff | Last adversary contact |

> 4625-flood → 4624-success is the *entire entry story*, written down by Windows itself.

---

# 6 · Registry Hives — System State

The registry is a **parser** target — and it's **locked on a live box**, so we extract it from the E01.

- **`SYSTEM`** → current control set, **TimeZoneInformation** (the clock truth!), services, network interfaces.
- **`SOFTWARE`** → **OS version**, installed software, Run keys (persistence).
- **`SAM`** + `SYSTEM` → local account hashes → (offline) crack to passwords.
- Per-user **`NTUSER.DAT`** / **`UsrClass.dat`** → RecentDocs, typed paths, user activity.

> "Locked file" is a *live-system* problem. On a dead image, the hive is just bytes at a path — extract and parse.

---

# SRUM — The Usage Ledger That Outlives Deletion

**SRUM** (`SRUDB.dat`, an ESE database) silently logs per-process resource usage Windows uses for the battery UI:

- **Bytes sent / received per application** — an exfil ledger.
- **Which executables ran, and when** — even after the binary is deleted.

It's an **ESE B-tree** (same engine as Exchange/AD) — a parser job, not a casual read.

> When the attacker deletes the malware, SRUM may still hold *"this process moved N bytes out at time T."* That's how you quantify the theft.

---

# 7 · Memory — The Live Truth

The disk shows what was **stored**. Memory shows what was **running**. This is the **[M]** primitive.

**`PID → EPROCESS → virtual address → physical address`** — a page-table walk.

- **PAGING (`memf-hw`)** — OS-agnostic hardware: CR3/DTB, PML4 / PAE / AArch64 page walks. Turns a VA into a physical offset in the dump.
- **OS STRUCTURE (`memf-windows`)** — walks the `EPROCESS` list, VAD tree, network tables, credential caches.
- **Symbol-driven:** it resolves the kernel's PDB (GUID-matched, auto-downloaded) so struct offsets are exact for *this* build — not guessed.

> Memory is where the **C2 IP, the live malicious process, and the `spoolsv` injection** live — none of which the disk can show you.

---

# What Memory Recovers Here

Walking `citadeldc01.mem` / `DESKTOP-SDN1RPT.mem`:

- **`ps` / process list** — `coreupdater.exe` running, parentage, the migration into `spoolsv.exe`.
- **`netstat`** — the live socket to **`203.78.103.109:443`** (the Thailand C2), reconstructed by scanning TCP endpoint pool tags — *without* the PCAP we threw away.
- **`scan` / malfind** — injected, executable-but-private memory regions (the injection signature).

Mapped to ATT&CK: **T1055** (injection), **T1071/T1573** (C2 over encrypted channel).

> Same instant the brute force succeeded on disk — now corroborated by what's *live in RAM*.

---

# 8 · Correlation — One Timeline, Many Sources

Each layer above produces events in **its own** address space. Correlation **merges them into one super-timeline** — with **per-event source attribution**.

- Disk `$MFT` + USN + EVTX + Registry + SRUM + Memory → **one ordered narrative**.
- Each row carries **where it came from** (`source = EVTX | MFT | USN | memory | SRUM`).
- Clock skew normalized once (`ClockProvenance`), so every source lands on the **same wall clock**.

> The breach isn't proven by one artifact — it's proven by **five independent sources agreeing** on the same minute.

---

# The Climax — ATT&CK Narrative & The Report

The deliverable is not a tool dump. It's an **attack-chain narrative** a board can read:

`T1110` brute force → `T1021.001` RDP → `T1543.003` service persistence → `T1055` injection → `T1071/T1573` C2 → `T1070.006` timestomp → `T1560/T1041` stage & exfil.

Built from **graded findings**, each tagged *"consistent with"* — never a verdict.

---

# Present It Like an Expert Witness

The discipline that separates an analyst from a technician — **three epistemic layers:**

1. **Observed fact** — *"200 KB left the host to 203.78.103.109 at 02:24."* → state it.
2. **Forensic inference** — *"consistent with C2 exfiltration."* → "consistent with", never "proves".
3. **Legal conclusion** — *"this was theft."* → **not yours.** *"The tribunal may draw its own conclusions."*

> Tools find the bytes. **Judgment** decides what they mean — and **restraint** decides what you're entitled to say.

---

# The Takeaway

- The **mechanics** — containers, partition tables, NTFS, EVTX, registry, SRUM, memory — are **fundamentals you now recognize anywhere.**
- The **tooling** — one Rust-native fleet — collapses four ecosystems into one address space, so the friction stops stealing your thinking time.
- The **moat** — and your career — is the **mindset**: read the meaning, build the narrative, present with honesty.

**Now let's open the image.** → *Module 1: crack the container.*

---

# Backup / Reference

- Case: **DFIR Madness Case 001** — `https://dfirmadness.com/the-stolen-szechuan-sauce/`
- Answer key: `https://dfirmadness.com/answers-to-szechuan-case-001/`
- Workshop design + command walkthrough: `DESIGN.md`, `ctf-yardstick.md`, `../szechuan-sauce-quickstart.md`
- Clock: victim VMs **UTC−7**; key narrates **UTC−6** → host artifacts read **+1h**.
