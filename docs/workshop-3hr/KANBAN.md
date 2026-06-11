# Workshop Kanban — BSidesHK 2026

**Hard deadline:** Josiah's by-hand CTF baseline → **Mon 15 Jun 2026, 09:00 HKT.**
Update daily: move cards, note blockers, ping instructor on bottlenecks.

_Last updated: 2026-06-09 (initial board)._

---

## Backlog
- [ ] TOOL-1 `issen correlate <case-dir>` unified five-source command (makes flyer true)
- [ ] TOOL-2 ATT&CK tags on raw events (4625→T1110, 4624/type10→T1021, 7045→T1543.003, timestomp→T1070.006)
- [ ] TOOL-3 SRUM ESE B-tree extraction (currently stub) → bytes-exfiltrated ledger
- [ ] TOOL-4 Memory C2/injection as graded findings (coreupdater→203.78.103.109, spoolsv migration)
- [ ] TOOL-5 Confirm MFT $SI/$FN timestomp finding fires on Beth_Secret.txt
- [ ] TOOL-6 Hive extraction + 7045/Run persistence parse (re-route question 6.i)
- [ ] TOOL-7 SAM/SYSTEM cred extraction or lsass-from-RAM (re-route B6; optional)
- [ ] WS-1 Module 0–5 facilitator scripts (minute-by-minute)
- [ ] WS-2 Student lab handout (commands + expected output per module)
- [ ] WS-3 Pre-flight: dataset download mirror + install verifier + canned mini-sample
- [ ] WS-4 "Brief the board" template (3-layer epistemic discipline + exec-summary-first)

## Doing
- [ ] CTF-BASELINE Josiah: finish Case 001 by hand (FTK/Vol3/EZ/KAPE) → ground-truth answer key
- [ ] CTF-YARDSTICK Run Issen per question, fill verdict column (drives TOOL backlog)

## Review

## Done
- [x] Audit real Issen CLI capability vs flyer claims (2026-06-09)
- [x] Map CTF question set → disk+RAM artifacts → ATT&CK (2026-06-09)
- [x] Workshop DESIGN.md run-of-show (2026-06-09)

---

## Data prerequisites (Case 001, disk+RAM only)

Location: `~/src/issen/tests/data/DFIR Madness "Stolen Szechuan Sauce" Case 001 — Windows 10/`
(folder name predates the DC host — covers both hosts now; rename deferred to avoid breaking
README/test path refs).

| Host | Disk E01 | Memory | Pagefile | Status |
|---|---|---|---|---|
| DESKTOP-SDN1RPT (Win10, .115) | 6.4 GB ✅ | 766 MB ✅ | 212 MB ✅ | **HAVE** |
| CitadelDC01 (Srv2012R2, .10) | 4.84 GB ✅ | 535 MB ✅ | 13 MB ✅ | **HAVE** (E01 byte-verified) |

**Full case now local** (2026-06-09): both hosts + `case001-pcap.zip` (151 MB) + both
`*-autorunsc.zip` + both protected-files zips. Workshop still *uses* only disk+RAM; the pcap /
autoruns / protected-files are downloaded for completeness but excluded from the lab by design.
Provenance recorded in `issen/docs/corpus-catalog.md` (§A3).

## Daily log

### 2026-06-09
- Reality check complete: no `issen correlate` yet; SRUM/memory-injection/ATT&CK-on-raw are
  GAP/PARTIAL. Scenario is fully disk+RAM-answerable. Design drafted; sprint backlog set.
- **Decisions made:** sprint = *build it true* (TOOL-1..5); scope = *both hosts in-room*;
  first move = *validate yardstick on real data*.
- **Role boundary set:** this session = workshop materials + tool-dev **handover MD plans only**;
  a separate Issen-tool-dev Claude session executes code changes.
- Data: have full DESKTOP host; **DC01 (5.4 GB) downloading in background** (was entirely absent).
