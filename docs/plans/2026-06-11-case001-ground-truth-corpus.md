# Case 001 ("Stolen Szechuan Sauce") — Union Ground-Truth Corpus (Task #74)

Research-synthesis input for the v5 `issen correlate` capstone. **Companion to** —
not a replacement for — `2026-06-11-issen-correlate-capstone.md` (under Codex review;
not modified here). That memo defines findings **F1–F25** from the single walshcat
write-up; this document aggregates **every downloadable published write-up found**,
corroborates F1–F25, and adds the **memory-analysis (Volatility) findings F26–F44**
that walshcat's write-up entirely lacks.

---

## Executive Summary

**BLUF.** The walshcat-grounded F1–F25 set in the capstone memo is a *lower bound*: its
author performed **zero memory analysis**. Across the broader write-up corpus — most
importantly DFIR Madness's own canonical **Memory Analysis** lab — the **memory leg is
where the richest un-captured findings live**, and it is the leg where the issen fleet's
`memf` walkers **already detect the same core IOCs from RAM** (orphaned malware process,
the C2 connection, the RWX private-injection region) as every published write-up. They do
**not** yet *exceed* those analyses end-to-end: two sub-capabilities the headline once
claimed are **not built yet** (verified against source 2026-06-11) — the C2-port
annotation does **not** flag `:443` (`is_suspicious_remote_port` matches only `4444`, so
the Szechuan C2 surfaces as `external-established`, not `suspicious-c2-port`), and malfind
**MZ sub-classification cannot fire** because `WinMalfindInfo.first_bytes` is a `Vec::new()`
placeholder (the region is correctly flagged as injected but defaults to *shellcode*, never
*injected-PE*). So the memory leg is **partly wiring, partly build** — not pure wiring.

- **Write-ups retrieved (11):** the DFIR Madness official answer key + 5 of its own
  Case-001 lab posts (memory, pcap, triage-disk, super-timeline, autoruns), walshcat
  (already in the memo), g4rud4, nathan-out (CyberDefenders variant), iblue.team, and 3
  substantive GitHub investigation repos (Herdomain, Dorakhris, AdhamElgarhy). All
  reachable; provenance and reachability per write-up in §1.
- **Corroboration:** every walshcat finding F1–F25 is corroborated by ≥1 additional
  write-up (most by 4–6). No F1–F25 conclusion was contradicted; only the documented
  host/IP label swap and the article's IP typo recur (the corpus canon resolves both).
- **New findings (F26–F44, 19 net-new):** F26–F37 are **memory/Volatility** findings
  (process list, C2 netscan, malfind injection into `spoolsv.exe`, process migration,
  in-RAM registry/KDBG OS confirmation, memory-resident ShimCache). F38–F44 are
  non-memory findings the broader corpus adds (Hydra named as the brute tool; NMAP/Snort
  IDS + ICMP probe; 4776 NTLM + Kali attacker hostname; whois→Thailand/Netway for the C2;
  recycle-bin recovery of Beth's file content; the second/re-migrated Meterpreter session).
- **Fleet posture:** the **memory column is issen's strongest** — `memf netstat` surfaces
  the C2 **locally from RAM** (a *route* the write-ups reach only via the VirusTotal pivot;
  issen flags it as `external-established`, not yet as a named C2 port), and `memf scan`
  already flags the `spoolsv.exe` RWX injection (malfind-equivalent), though it labels the
  region *shellcode* until byte-capture lands (see F28). The genuine gaps are **pcap (OUT —
  no parser)**, **ESE/IE-WebCache (OUT)**, the **dead-code disk parsers**
  (amcache/lnk/prefetch/shimcache — PRE-5), **wiring** (`memf` is profile/CR3-gated and not
  persisted to the timeline — PRE-1 + the B1–B4 workstream), and **two genuine builds**:
  malfind first-byte capture (for MZ/PE sub-classification) and a C2-port heuristic that
  covers `:443`-on-odd-local-port, not just `4444`.

**Top recommendation for v5:** treat the memory findings F26–F37 as a **second oracle
block** alongside F1–F25. Most map to memf capabilities that *exist*, so the bulk of the
capstone's memory leg is a **wiring problem (PRE-1, B1–B4)** — with **two scoped builds**
(malfind first-byte capture; `:443` C2 heuristic) and `memf creds`/`memf timeline`
validation before issen can claim to *match*, let alone exceed, the published human
analyses end-to-end. It is the highest-leverage block; it is not free.

---

## 1 · Write-up inventory

All retrieved 2026-06-11 (WebFetch was blocked by a model-side safety filter for DFIR
search terms; discovery ran through DuckDuckGo HTML + the GitHub API in a sandbox, fetch
via `ctx_fetch_and_index`). "Mem?" = does it perform memory/Volatility analysis.

| # | Source | Author | URL | Down­load­able | Mem? | Volatility plugins run | Scope |
|---|---|---|---|---|---|---|---|
| W0 | walshcat (the memo's oracle) | walshcat | <https://walshcat.medium.com/case-write-up-the-stolen-szechuan-sauce-2409344264c3> (403 to bots; via [archive](https://web.archive.org/web/20250911141030/https://walshcat.medium.com/case-write-up-the-stolen-szechuan-sauce-2409344264c3)) | yes (archive) | **no** | — | disk/EVTX/registry/USN/MFT/pcap/webcache/Amcache/LNK/recycle |
| W1 | **DFIR Madness — Memory Analysis** (canonical) | James Smith | <https://dfirmadness.com/case-001-memory-analysis/> | yes | **YES** | `netscan`, `malfind` (+ `-D` dump), `pstree -v`; mentions `handles`, `hollowfind`, `timeliner`, vol3 | memory (DC + Desktop) |
| W2 | DFIR Madness — Official Answers | James Smith | <https://dfirmadness.com/answers-to-szechuan-case-001/> | yes | partial (refs memory IOCs) | — | all sources, answer key |
| W3 | DFIR Madness — PCAP Analysis | James Smith | <https://dfirmadness.com/case-001-pcap-analysis/> | yes | no | — | pcap (tcpdump, Snort, NMAP-signature lab) |
| W4 | DFIR Madness — Triage Disk Analysis | James Smith | <https://dfirmadness.com/triage-disk-analysis-case-001/> | yes | refs `timeliner` | (timeliner) | disk (FLS bodyfile, E01 mount) |
| W5 | DFIR Madness — Super Timeline Analysis | James Smith | <https://dfirmadness.com/case-001-super-timeline-analysis/> | yes | **YES** | `timeliner.Timeliner --create-bodyfile` (vol2 + vol3) | super-timeline (plaso + memory body) |
| W6 | DFIR Madness — AutoRuns Analysis | James Smith | <https://dfirmadness.com/case-001-autoruns-analysis/> | yes | no | — | disk/registry autoruns + service |
| W7 | g4rud4 | g4rud4 | <https://g4rud4.gitlab.io/2023/Case-001-DFIR-Madness-The-Stolen-Szechuan-Sauce/> | yes | **YES** | `pslist`, `netscan`, `malfind -D` (→ clamscan/FLOSS) | pcap + memory + DC disk |
| W8 | nathan-out (CyberDefenders "Szechuan Sauce" variant) | nathan.out | <https://nathan-out.github.io/write-up/cyberdefenders-digital-forensics-szechuan-sauce/> | yes | **YES** (vol3) | `pstree`, `netscan` (windows.* implied), recycle-bin carving | memory + disk + pcap, 18-Q CyberDefenders set |
| W9 | iblue.team | iblue.team | <https://www.iblue.team/ctf-challenges/dfir-madness-ctf-challenges/case-001-szechuan-sauce> | yes | **YES** (vol2) | `imageinfo`/`kdbgscan`, `filescan`, `printkey`, `netscan` (+ Magnet AXIOM) | memory + pcap + disk |
| W10 | Herdomain (GitHub) | Herdomain | <https://github.com/Herdomain/digital-forensics-szechuan-sauce-investigation> | yes | **YES** (vol3) | `windows.pslist`; netstat-style C2 | full investigation report |
| W11 | Dorakhris (GitHub) | Dorakhris | <https://github.com/Dorakhris/Forensics-Analysis-The-Stolen-Szechuan-Sauce> | yes | mentions `.vmem` | — (Autopsy/Wireshark/RegExplorer) | disk + pcap + registry |
| W12 | AdhamElgarhy (GitHub) | Adham Elgarhy | <https://github.com/AdhamElgarhy-33/DFIR-Project-The-Stolen-Szechuan-Sauce-/> | yes | no | — | disk/EVTX/registry/pcap (+ several **single-source** claims, §2.4) |
| — | mimircyber (mirror of W2) | — | <https://www.mimircyber.com/answers-to-the-case-of-the-stolen-szechuan-sauce-case-001/> | yes | — | — | verbatim copy of W2 (retention mirror) |

Not located: a dedicated **13Cubed** Case-001 video/notes (searches returned only
cooking-channel noise; if one exists it was not surfaced — see open questions). The
walshcat **F9 SHA256** appears only in a screenshot there, but **W7 (g4rud4) supplies it as
text** (verified in the local capture), as do Netresec's PCAP walkthrough and the ds4n6 ODSC
notebook: SHA256 `10f3b92002bb98467334161cf85d0b1730851f9256f83c27db125e9a0c1cfda6` (VT 59/71).
(W10/Herdomain is listed in the inventory but was not part of the local download set.)

---

## 2 · The union finding set

### 2.0 Conventions
Findings are observations, never legal conclusions. "consistent with" is used for
threat/attribution narration. **F1–F25 are defined in the capstone memo** — here they get
a one-line *corroboration* note (which additional write-ups reach the same conclusion),
**not** a re-statement and **not** a renumbering. **F26+ are net-new.** Memory findings
name the exact Volatility plugin and the issen `memf` equivalent.

### 2.1 F1–F25 — corroboration of the walshcat oracle (no renumber)

| F | Conclusion (abridged) | Corroborating write-ups (beyond walshcat) | Notes |
|---|---|---|---|
| F1 | DC OS = Win Server 2012 (R2, build 9600) | W2, W7, W9, W11; **W1/W9 confirm from RAM** (KDBG `Win2012R2x64_18340`, in-memory SOFTWARE hive) | memory route is net-new evidence (→ F35) |
| F2 | Desktop OS = Win 10 (Enterprise, build 19041) | W2, W9, W11 | |
| F3 | DC tz misconfigured Pacific/-8 vs Mountain/-6 → clock skew | W2 (states the −7 VM vs −6 router offset explicitly), W3, W12 | the VM/router offset is the precise mechanism |
| F4 | A breach occurred | all write-ups | |
| F5 | 4625 failed-logon brute-force burst vs Administrator (Kali host) | W2, W7, W9, W10, W12 | issen **TODAY** (burst @ 03:21:25) |
| F6 | 4624 success from `194.61.24.102` follows the burst → RDP brute initial access | W2, W3, W7, W9, W10, W11, W12 | Hydra named in W2 (→ F38) |
| F7 | pcap: ICMP probe then RDP brute traffic | W3 (adds NMAP service-scan signature + Snort) | OUT (no pcap); see F39 |
| F8 | `coreupdater.exe` fetched via HTTP GET from `194.61.24.102` (Python SimpleHTTPServer) | W2, W3, W7, W11 | delivery *mechanism* is pcap-only |
| F9 | SHA256 of carved binary, VT-flagged | **W7 (g4rud4) gives the hash as text** — verified in the local capture; also carried as text by Netresec's PCAP walkthrough and the ds4n6 ODSC notebook. (W10/Herdomain is inventory-only; no local copy in the download set) | hash corroborated outside a screenshot by ≥2 locally-held sources |
| F10 | Download corroborated by webcache + Amcache | W2 (autoruns/Amcache), W9 (AXIOM) | IE WebCache = ESE (OUT) |
| F11 | `194.61.24.102` = payload-delivery IP | W2, W7, W9, W10, W11 | |
| F12 | C2 = `203.78.103.109` | **W1, W7, W8, W9 confirm from RAM netscan** | issen route is RAM-local & **stronger** (→ F27) |
| F13 | coreupdater first on DC 2020-09-19 03:24:(06–12) UTC (MFT+USN) | W2 ("02:24:06" pcap-clock = 03:24:06 UTC), W5 (super-timeline pivot) | issen **TODAY** (MFT) |
| F14 | File moved Downloads→System32 (DC + Desktop), USN parent analysis | W2, W7 (USN zip/parent), W11 | |
| F15 | Malware = Meterpreter/Metasploit | **W1/W7 confirm via malfind-dump + ClamScan/FLOSS in RAM** (not just VT) | memory route = net-new (→ F30) |
| F16 | Metasploit is open-source / easily obtained | W2 | OUT (not evidence-derived) |
| F17 | Persistence on both: `coreupdater` service (7045) + Run key | W2, W6 (autoruns + `ControlSet\Services`), W7, W11 (`ControlSet001\Services\coreupdater`), W12 | issen 7045 **TODAY**; reg value = PRE-3 |
| F18 | OSINT: `194.61.24.102` CVE-2015-1635 / RDP-brute infra; `203.78.103.109` AlienVault Meterpreter | W2 (adds happydoghappycat-th.com link, later retracted) | OUT (pure OSINT); whois→TH is corpus-derivable (→ F42) |
| F19 | Lateral movement: RDP DC→Desktop ~03:36 UTC, Administrator | W2, W7, W8, W10, W11 | issen Desktop 4624 **TODAY** |
| F20 | Administrator accessed all files in the "Secret" share (both hosts) | W2, W7, W8, W11 | issen MFT **TODAY** |
| F21 | Staging zips: `loot.zip` (Desktop) + `secret.zip` (DC); `Loot.lnk`/`Secret.lnk`; webcache | W2, W7 (USN created+deleted zips both hosts) | LNK = PRE-5 (dead code) |
| F22 | Net layout: domain C137; CITADEL-DC01 + DESKTOP-SDN1RPT on 10.42.85.0/24 | W2, W7, W10, W11 | reg/EVTX; label-swap noted in memo |
| F23 | The sauce was stolen (rides F20/F21) | W2 (recipe exfil), all | aggregate |
| F24 | `SECRET_beth.txt` deleted ~03:32, copy `Beth_Secret.txt` ~03:38; recycle-bin confirms | W2, **W8 recovers the content from `$Recycle.Bin\S-1-…-500`** | content-diff = OUT; recycle carving → F43 |
| F25 | Last adversary contact: last DC logoff ~"2:57" pcap-clock | W2 (logout → un-migrated meterpreter died → 2nd login) | issen logoff **TODAY**; 2nd session → F44 |

### 2.2 F26–F37 — MEMORY / Volatility findings (the net-new core; walshcat = none)

Plugin column = the Volatility plugin the write-up ran; "issen memf" = the equivalent
capability and whether it exists. Confirmation sources are corroboration counts.

| F | Conclusion | Vol plugin → what it shows | Sources | issen `memf` equivalent | Status |
|---|---|---|---|---|---|
| **F26** | **`coreupdater.exe` is present as a process object, PID 3644, already exited** — **0 threads (dead), no live parent** (PPID 2244 absent), started ~03:56 vol-clock ≈ 02:56 UTC | `pslist`/`pstree -v` — orphaned, dead process | W1, W7, W8, W10 | `memf ps` (`dispatch_windows_ps`; `walk_processes` ActiveProcessLinks) | **TODAY (wiring-gated)** — walker exists; CR3/profile + persistence = PRE-1/B1–B2 |
| **F27** | **C2: coreupdater (PID 3644) had an ESTABLISHED TCP connection to `203.78.103.109:443`** (local port `62613` is **image-derived** — appears in a write-up screenshot, not scraped text) | `netscan` — established external on 443 tied to malware PID | W1, W7, W8, W9 | `memf netstat` (`dispatch_windows_netstat`) + `classify_connection` → `Note="external-established"` | **TODAY (wiring) + build** — issen surfaces the C2 *locally from RAM*; **but `classify_connection` does NOT flag `:443` as a C2 port** (`is_suspicious_remote_port` matches only `4444`), so it shows as `external-established`, not `suspicious-c2-port`. Pool-scan completion = B3; a `:443`-on-odd-local-port heuristic is a scoped **build** |
| **F28** | **`spoolsv.exe` (PID 3724) is injected** — VAD region `PAGE_EXECUTE_READWRITE`, **`MZ` header present** = injected PE (Meterpreter) | `malfind` (+`-D` dump) — RWX private + MZ | W1, W7 | `memf scan` → `vad::walk_malfind` + `classify_malfind_region` | **TODAY (detect) + build (sub-classify)** — the RWX-private region IS flagged, **but MZ vs shellcode cannot fire**: `WinMalfindInfo.first_bytes` is a `Vec::new()` placeholder (`vad.rs:135` "would read from process VA space"), so `classify_malfind_region(&[])` defaults to *shellcode*. First-byte capture from the VA region is a scoped **build**; needs `scan` wired + CR3 (B4) |
| **F29** | **Process migration: Meterpreter migrated `coreupdater` → `spoolsv`** — spoolsv active (13 threads) while coreupdater is dead (0); both tied to the same C2 | `pstree`+`netscan`+`malfind` correlated | W1, W7, W8 | cross-source: ps (dead+orphan) ∧ scan (spoolsv injected) ∧ netstat (both→C2) | **DESIGN** — a *memory-internal correlation rule* (candidate `CORR-PROC-MIGRATION`); members exist, the join is new |
| **F30** | **The injected region in spoolsv classifies as Meterpreter** (ClamScan/FLOSS on the malfind dump; FLOSS recovers the C2 string from the region) | `malfind -D` → clamscan/FLOSS/strings | W1, W7 | `memf scan` dumps region; ClamScan/YARA/strings is an external/`memf-strings` step | **PARTIAL** — issen flags the region (F28) and can dump+string it; "name the family = Meterpreter" is YARA/AV-rule territory (memf has `yara_scan.rs`) |
| **F31** | **spoolsv also LISTENING on 62475** (TCPv4+TCPv6) under the injected process (the port `62475` is **image-derived** — screenshot, not scraped text) | `netscan` — listeners under injected PID | W8 (explicit), W1 | `memf netstat` lists listeners | **TODAY (wiring)** — netstat returns LISTENING rows |
| **F32** | **Malware ran at SYSTEM/LocalSystem** → domain credential exposure inferred (DC-wide) | inferred from migration + DC context | W1 (hypothesis), W12 (LocalSystem service) | inference layer; `memf creds` (hashdump/lsadump) would *test* it | **DESIGN** — issen has `hashdump.rs`/`lsadump.rs`/`sam.rs` walkers (memf-windows) but `memf creds` is not wired/validated on this dump |
| **F33** | **Desktop memory image would not parse cleanly in Volatility/Rekall**; analysts pivoted to FLOSS+strings+grep over 18.1M lines and still hit the IOCs (coreupdater, 203.78.103.109). **Caveat:** because structured parse failed, the *Desktop* memory conclusions carry only **FLOSS "likely/probable" confidence** (W1 ~line 614), not the structured certainty the *DC* findings (F26–F32) have | (vol failure) + strings/grep IOC sweep | W1 | `memf strings` (`memf-strings`) + IOC match; raw-dump robustness | **PARTIAL/DESIGN** — issen's strings + hashdb IOC path can sweep a raw dump even when structured parse fails; a documented robustness target. The corpus must label Desktop-memory findings as lower-confidence than DC-memory findings |
| **F34** | **In-RAM netscan is noisy on a DC** (e.g. `dns.exe` dominates); triage = subtract known-noise, keep external-established on odd ports | analyst technique on `netscan` output | W1 | `classify_connection` mechanizes the loopback/wildcard/listening-vs-`external-established` split (the `Note` column) | **TODAY** — issen mechanizes the external-vs-noise triage; it does **not** yet score the C2 port itself (that is the F27 `:443` build), so this *matches* the analyst's first pass, it does not exceed it |
| **F35** | **OS/build confirmable from memory** — KDBG profile `Win2012R2x64_18340` (text-confirmed in W7's Volatility command); **`NtBuildLab 9600.17031`, "40 procs / 154 modules", in-RAM SOFTWARE-hive `printkey` are image-derived** in W9 (do not assert as text-corroborated) | `imageinfo`/`kdbgscan` + `printkey` | W9, W7 | `memf info`/profile resolution; in-RAM registry walk (`memf-windows::registry`) | **PARTIAL** — profile/KDBG resolution is B1's job; in-RAM `printkey` exists as a walker but isn't a wired memf subcommand |
| **F36** | **ShimCache/evidence-of-execution lives in memory before it is flushed to the registry at shutdown** — pulled into the super-timeline from RAM | `timeliner` / shimcache-in-memory | W1, W5 | `memf-windows::shimcache.rs` walker exists | **DESIGN** — memory ShimCache walker present; not wired to timeline/supertimeline |
| **F37** | **Memory body-file feeds the super-timeline** — `timeliner.Timeliner --create-bodyfile` merged with the plaso disk timeline materially enriches it | `timeliner` (vol2 + vol3) bodyfile | W5, W4 | `memf timeline` (`MemfCommand::Timeline`) is **declared but "not yet wired for this OS"** | **DESIGN** — the subcommand stub exists; producing a memory bodyfile + merging into the case DuckDB is PRE-1-adjacent |

### 2.3 F38–F44 — non-memory findings the broader corpus adds

| F | Conclusion | Evidence source / producing artifact | Sources | issen status |
|---|---|---|---|---|
| **F38** | **The brute-force tool was Hydra** | named in the official summary (W2) | W2 | OUT-as-named (tool attribution from behaviour); F5/F6 reach "RDP brute" without naming the tool |
| **F39** | **Pre-attack recon: ICMP probe + an NMAP service-scan of TCP 3389**, raising a **Snort/IDS NMAP alert** | pcap (tcpdump) + Snort signature, lab-reproduced | W3 | **OUT** — no pcap parser; no bundled IDS rule consumer |
| **F40** | **Attacker host is a Kali machine; its hostname is recoverable via EVTX 4776 (NTLM) and/or LLMNR in pcap** | EVTX 4776 / Terminal-Services logs; LLMNR | W2 (4776 hint), W8 (LLMNR), W10 (4776 NTLM from Kali) | **PARTIAL/DESIGN** — issen parses EVTX; 4776 is not a mapped event type yet (PRE-3-style EVTX extension); LLMNR leg is pcap-OUT |
| **F41** | **The attacker re-used the compromised Administrator creds for the DC→Desktop RDP pivot** (single credential, two hosts) | EVTX 4624 logon-id / account reuse across hosts | W2, W8, W10, W11 | **DESIGN** — exactly `CORR-LATERAL-MOVE` (Tier D); the corpus strengthens its assertion |
| **F42** | **C2 `203.78.103.109` geolocates to Netway Communications, Bangkok, Thailand** (RIR/whois) | whois/RIR lookup on the netscan IP | W1 (Thailand), W9 (full APNIC record) | **OUT (enrichment)** — issen surfaces the IP (F27); whois is online enrichment, not promised |
| **F43** | **Beth's secret-file *content* was recovered from `$Recycle.Bin\S-1-…-500`** (the deleted `SECRET_beth.txt` ⇒ `$R…` data stream) | recycle-bin `$I`/`$R` carving + file content | W8 (recovers it), W2 | **OUT/PARTIAL** — issen recognizes recycle paths in heuristics but has no `$I`/`$R` content-carver; F24's content-diff leg stays OUT |
| **F44** | **A *second* adversary session**: after the first logoff an un-migrated Meterpreter died; the attacker logged in again, restarted+migrated the session, then exited | EVTX logon/logoff sequence + memory migration state | W2 | **DESIGN** — session-envelope + F29 migration; the "two sessions" shape is a report/sessionization concern |

### 2.4 Single-source / unverified — flagged (Doer-Checker)

These appear in **exactly one** write-up and were **not** corroborated; treat as leads,
not ground truth. All are from **W12 (AdhamElgarhy)**, a university project that states it
"independently reconstructs … without consulting public walkthroughs" — high-effort but
uncorroborated on these specifics:

- **U1 — "Impacket SMBexec used to issue remote commands."** Plausible (SMBexec leaves a
  `$` service + 7045/named-pipe trail) but no other write-up asserts it; not in the
  official key. *Unverified.*
- **U2 — "Security audit log (1102) cleared on a second compromised internal host."** No
  other source mentions a 1102 clear; the official narrative has the meterpreter session
  simply dying, not log-clearing. *Unverified — possibly conflated.*
- **U3 — "~14 MB exfiltrated via the encrypted RDP screen back-channel."** A specific byte
  figure with no corroboration; the official answer says exfil rode "meterpreter + the RDP
  GUI session" without a volume. *Unverified.*
- **U4 — "95 brute-force attempts in under 2 seconds."** A precise count; others say only
  "a large/high-frequency burst." Directionally consistent with F5 but the exact figure is
  *single-source*.

Also note **W2's own retraction**: the `203.78.103.109 → happydoghappycat-th.com / APT`
link in F18 was *withdrawn* by the author ("has since been reported as not being
involved") — do not assert APT attribution.

---

## 3 · Fleet-capability matrix (v4 columns, extended to the union)

Columns mirror the capstone v4 matrix. **Status:** TODAY / DESIGN / PARTIAL / OUT.
`memf` capability file refs are in `~/src/issen/crates/issen-mem/src/dispatch.rs` and
`~/src/memory-forensic/crates/memf-windows/src/`.

### 3.1 Memory leg (the new column — lean here)

| F | Evidence | Producing capability (memf plugin-equiv) | Status → gap |
|---|---|---|---|
| F26 | memory | `memf ps` = `dispatch_windows_ps` → `walk_processes` (ActiveProcessLinks) | **TODAY-gated** — gap = CR3/auto-profile (B1) + persist to timeline (PRE-1/B2) |
| F27 | memory | `memf netstat` = `dispatch_windows_netstat` + `classify_connection` (`external-established`) | **TODAY + build** — gap = complete `pool_scan` TcpE/UdpA (B3); surfaces the C2 from RAM but flags `:443` as `external-established`, **not** `suspicious-c2-port` (matches `4444` only) — a `:443` heuristic is a scoped build |
| F28 | memory | `memf scan` → `vad::walk_malfind` (detect) + `classify_malfind_region` (sub-classify) | **TODAY (detect) + build (sub-classify)** — RWX-private region flagged; **MZ/PE sub-classification blocked** on `first_bytes` capture (`vad.rs:135` placeholder); gap = wire `walk_malfind` into `scan` (B4) + CR3 + byte-capture build |
| F29 | memory (corr) | new `CORR-PROC-MIGRATION` over ps∧scan∧netstat | **DESIGN** — members exist; the in-memory join rule is net-new |
| F30 | memory | `memf scan` dump + `memf-windows::yara_scan` / `memf strings` | **PARTIAL** — region flagged; family-naming = YARA/AV rule |
| F31 | memory | `memf netstat` LISTENING rows | **TODAY-gated** (same wiring as F27) |
| F32 | memory | `memf creds` = `hashdump.rs`/`lsadump.rs`/`sam.rs` walkers | **DESIGN** — walkers exist, `creds` not wired/validated |
| F33 | memory (raw) | `memf strings` (`memf-strings`) + `forensic-hashdb` IOC sweep | **PARTIAL/DESIGN** — robustness target for unparseable dumps |
| F34 | memory | `classify_connection` Note column (noise triage mechanized) | **EXCEEDS** |
| F35 | memory | `memf info` profile/KDBG + in-RAM `registry` printkey | **PARTIAL** — KDBG=B1; printkey walker not a wired subcommand |
| F36 | memory | `memf-windows::shimcache` (memory-resident) | **DESIGN** — walker exists, unwired |
| F37 | memory | `memf timeline` (`MemfCommand::Timeline`, "not yet wired for this OS") | **DESIGN** — stub exists; bodyfile→DuckDB merge needed |

### 3.2 Disk / EVTX / registry / correlation (F1–F25 + F38–F44 deltas)

Unchanged from the capstone's §2 matrix for F1–F25 (TODAY 4 / DESIGN 13 / PARTIAL 5 /
OUT 3); the corroboration in §2.1 raises confidence but not status. Deltas the union adds:

| F | Evidence | Producing capability | Status → gap |
|---|---|---|---|
| F38 | EVTX (behaviour) | tool-name attribution from brute pattern | **OUT-as-named** — F5/F6 produce "RDP brute" without naming Hydra (correct epistemic ceiling) |
| F39 | pcap + IDS | none | **OUT** — no pcap parser; future `zeek-forensic`/pcap leg |
| F40 | EVTX 4776 / LLMNR | EVTX mapper extension for 4776 | **PARTIAL/DESIGN** — add 4776→`NtlmAuth` mapping (PRE-3-style); LLMNR is pcap-OUT |
| F41 | EVTX 4624 cross-host | `CORR-LATERAL-MOVE` (Tier D) | **DESIGN** — corpus strengthens the assertion |
| F42 | whois on netscan IP | none (online enrichment) | **OUT** — IP surfaced (F27); geo is enrichment |
| F43 | recycle `$I`/`$R` | none (no content carver) | **OUT/PARTIAL** — paths recognized; no `$R` carve |
| F44 | EVTX + memory | session-envelope + `CORR-PROC-MIGRATION` | **DESIGN** — "two sessions" sessionization |

### 3.3 Scorecard (union)

- **Memory (F26–F37, 12 findings):** 3 **TODAY (wiring-gated)** (F26, F31, F34 — walker/
  classifier code exists, blocked only on CR3/profile/persist wiring); 2 **TODAY-detect +
  scoped-build** (F27 needs a `:443` C2 heuristic; F28 needs malfind `first_bytes` capture
  for MZ/PE sub-classification — both verified missing in source 2026-06-11); 5 **DESIGN**
  (F29, F32, F36, F37, + family-name half of F30); 2 **PARTIAL** (F30, F33, F35 straddle).
  **Headline (corrected): issen's memory leg already *detects the same core IOCs from RAM*
  as every published write-up (orphan process, C2 connection, RWX injection); reaching
  parity end-to-end is mostly wiring (PRE-1, B1–B4) plus two scoped builds (`:443` C2
  heuristic, malfind byte-capture) and `creds`/`timeline` validation — not pure wiring, and
  not yet a claim to *exceed*.**
- **Non-memory deltas (F38–F44):** 1 **DESIGN** (F41), 1 **PARTIAL/DESIGN** (F40), 1
  **OUT-as-named** (F38), 4 **OUT** (F39, F42, F43, plus content-diff of F24).
- **F1–F25:** unchanged status; every finding now corroborated ≥1×, none contradicted.

---

## 4 · Enhancement roadmap (gaps → candidate tasks)

Grouped; **(cheap)** = wiring/extension on existing code, **(deep)** = new parser/leg.

**A. Memory wiring — the highest-leverage block (mostly cheap; the long pole is B1).**
Maps 1:1 to the existing B1–B4 workstream and serves F26–F37.
- A1 **(deep-ish)** — CR3/DTB + auto-profile into `build_reader` (B1): low_stub/KPCR DTB
  discovery + RSDS-GUID → ISF. Unblocks F26/F27/F28/F31/F35. *The one non-trivial item.*
- A2 **(cheap)** — route Windows-profiled raw dumps to `walk_processes`; wire `memf ps`
  rows (B2). Serves F26.
- A3 **(cheap)** — complete the stubbed `pool_scan` TcpE/UdpA so `memf netstat` returns
  endpoints (B3). Serves F27/F31/F34 (`classify_connection` already done).
- A4 **(cheap)** — wire `vad::walk_malfind` into `memf scan` (B4). Serves F28/F30.
- A5 **(cheap)** — PRE-1: `memory_events(...) -> Vec<TimelineEvent>` so ps/netstat/scan
  rows persist into the case DuckDB with acquisition timestamps. Serves all memory findings
  reaching the timeline + F12/F27 correlation.

**B. Memory features beyond wiring (deep).**
- B1 — `memf creds` validated (hashdump/lsadump/sam already present) → F32.
- B2 — `memf timeline` produce a memory bodyfile and merge into the case DB → F37; pull
  memory-resident ShimCache → F36.
- B3 — `CORR-PROC-MIGRATION` rule (ps-orphan ∧ scan-injected ∧ shared-C2 netstat) → F29,
  and the two-session envelope → F44.
- B4 — YARA/AV family-naming over malfind dumps (`memf-windows::yara_scan`) → F30.

**C. Disk parser wiring (cheap — code exists, dead in the binary).**
- C1 — PRE-5 force-link amcache/lnk/prefetch/shimcache; add the `.lnk` discovery arm →
  F10 (Amcache), F21 (LNK), F36 corroboration on disk.
- C2 — PRE-6 flagged-exec extract+hash+known-bad match → F9 (now corroborated text hash).

**D. EVTX/registry extensions (cheap).**
- D1 — PRE-3 named-value registry table (OS/tz/computer/interfaces/services/Run) → F1, F2,
  F3, F17-value, F22.
- D2 — map EVTX 4776 → `NtlmAuth` (attacker hostname) → F40 (EVTX half).

**E. Out-of-reach legs (deep / future; honest OUT).**
- E1 — **pcap** (`zeek-forensic`/pcap leg): F7, F8-mechanism, F39 (NMAP/Snort/ICMP), F40
  LLMNR half, F42 source traffic. Biggest single gap; whole new leg.
- E2 — **ESE/IE WebCache** reader (ride srum-forensic's ESE engine): F10 webcache, F14
  webcache corroboration.
- E3 — **Recycle-bin `$I`/`$R` carver** + content-diff: F24 content, F43.
- E4 — **online enrichment** (VT/whois/AlienVault): F18, F42 — deliberately *not* promised;
  issen's local routes (F9 hash-IOC, F27 RAM C2) are the in-scope equivalents.

**Cheap-vs-deep summary:** A2–A5, C1–C2, D1–D2 are all **cheap** (wiring/extension on
extant code) and collectively unlock the bulk of F26–F37 + the F1–F25 DESIGN rows. A1
(CR3/profile) is the **one moderately deep prerequisite** that gates the whole memory leg.
E1–E3 are **deep new legs** and stay honestly OUT for v5.

**Prerequisite blockers (re-verify on the actual Case 001 image before trusting any
TODAY/DESIGN label).** The capstone memo recorded two pipeline failures on this image — a
**DC01 ingest killed at ~23 min** (DuckDB insert) and **Desktop `$MFT` parsing to only ~31
records**. Tasks #23 (batched-insert ingest), #26 (Desktop `$MFT` under-parse), and #61
(ntfs-core `$ATTRIBUTE_LIST` full-runlist) are all marked *completed* and are expected to
have closed these — but the corpus has **not** re-run end-to-end on the Case 001 E01s since.
Several disk-leg TODAY/DESIGN rows (F5/F6/F13/F19/F20 MFT+EVTX) silently assume those fixes
hold at this image's scale. **v5 must gate those labels on a fresh end-to-end run of the DC
+ Desktop images**, not on the unit-level fix being merged. Treat them as *expected-TODAY,
unconfirmed-at-scale* until that run passes.

---

## 5 · Open questions for Codex to attack

1. **13Cubed.** A dedicated 13Cubed Case-001 video/show-notes could not be surfaced
   (search returned only cooking content; DFIR search terms were also blocked model-side).
   If one exists it may add memory findings — *unretrieved, flag as a gap.*
2. **F29 `CORR-PROC-MIGRATION` shape.** Is process migration best a *memory-internal*
   correlation rule, or a single-artifact "injected + orphaned + shared-C2" finding
   surfaced by `memf scan`? It is the one genuinely new *memory* correlation the union
   demands; the capstone's 10 rules don't cover it.
3. **F33 robustness target.** The desktop dump defeated Volatility/Rekall in W1. Should
   issen *guarantee* a strings+IOC fallback path when structured memory parse fails, and is
   that a tested requirement or best-effort? (Affects the "never silently wrong" posture.)
4. **W12 single-source claims (U1–U4).** Impacket-SMBexec, a 1102 log-clear on a second
   host, ~14 MB exfil, and "95 attempts in <2 s" are *uncorroborated*. Worth attempting to
   independently confirm against the corpus (the SMBexec service trail and any 1102 are
   disk/EVTX-checkable) before letting any of them influence rule design.
5. **F40 hostname route.** Confirm the attacker Kali hostname is recoverable from EVTX 4776
   / Terminal-Services logs *without* pcap, and whether issen's EVTX parser already carries
   the field (only the LLMNR route is truly pcap-bound).
6. **F35/F37 timeline merge semantics.** Memory-resident ShimCache (F36) and the memory
   bodyfile (F37) carry *acquisition-time* not event-time provenance; how should they slot
   into the DuckDB super-timeline without polluting the wall-clock ordering? (Ties to the
   capstone's §5.6 memory-timestamp policy.)

**Sources** (all cited inline; primary): W1 <https://dfirmadness.com/case-001-memory-analysis/> ·
W2 <https://dfirmadness.com/answers-to-szechuan-case-001/> · W3 <https://dfirmadness.com/case-001-pcap-analysis/> ·
W4 <https://dfirmadness.com/triage-disk-analysis-case-001/> · W5 <https://dfirmadness.com/case-001-super-timeline-analysis/> ·
W6 <https://dfirmadness.com/case-001-autoruns-analysis/> · W7 <https://g4rud4.gitlab.io/2023/Case-001-DFIR-Madness-The-Stolen-Szechuan-Sauce/> ·
W8 <https://nathan-out.github.io/write-up/cyberdefenders-digital-forensics-szechuan-sauce/> ·
W9 <https://www.iblue.team/ctf-challenges/dfir-madness-ctf-challenges/case-001-szechuan-sauce> ·
W10 <https://github.com/Herdomain/digital-forensics-szechuan-sauce-investigation> ·
W11 <https://github.com/Dorakhris/Forensics-Analysis-The-Stolen-Szechuan-Sauce> ·
W12 <https://github.com/AdhamElgarhy-33/DFIR-Project-The-Stolen-Szechuan-Sauce-/> ·
W0 walshcat (via archive, per capstone §1.1).
