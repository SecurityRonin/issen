# Case 001 "Stolen Szechuan Sauce" — published write-ups (ground-truth corpus)

Downloaded published analyses of DFIR Madness **Case 001** (James Smith / dfirmadness.com),
used as the **union ground truth** the fleet validates toward (drives the `issen correlate`
capstone acceptance oracle and the comprehensive finding corpus). Each write-up is a *lower
bound* on findability; the union across all of them — especially the memory/Volatility ones —
approximates the true findable set.

**Copyright / tracking:** the write-up files (`*.html`, `*.ipynb`) are third-party published
content, kept **local only** (this folder is under the gitignored `tests/data/`). Only this
manifest is committed (force-added), recording provenance per the corpus-catalog standard.
Re-fetch from the source URLs below.

Downloaded 2026-06-11 (UTC). `★` = includes memory analysis (Volatility).

| File | Source | Author | Scope | MD5 (first 16) |
|---|---|---|---|---|
| `dfirmadness-answers-to-szechuan-case-001.html` | https://dfirmadness.com/answers-to-szechuan-case-001/ | James Smith (DFIR Madness) | **official answer key** + attack timeline | `05b5f7b5851d4289` |
| `dfirmadness-case-001-memory-analysis.html` ★ | https://dfirmadness.com/case-001-memory-analysis/ | James Smith | **official memory analysis** (Volatility: pslist/pstree/netscan/malfind → coreupdater, C2 203.78.103.109, spoolsv/explorer injection) | `71b7d8d57e8af0af` |
| `dfirmadness-case-001-pcap-analysis.html` | https://dfirmadness.com/case-001-pcap-analysis/ | James Smith | official PCAP analysis | `779646d94c085201` |
| `dfirmadness-case-001-super-timeline-analysis.html` | https://dfirmadness.com/case-001-super-timeline-analysis/ | James Smith | official super-timeline (plaso) | `c328eeeecbba9d48` |
| `dfirmadness-case-001-autoruns-analysis.html` | https://dfirmadness.com/case-001-autoruns-analysis/ | James Smith | official autoruns/persistence | `138aedf828a5fb40` |
| `dfirmadness-case-001-the-timing-of-it-all.html` | https://dfirmadness.com/case-001-the-timing-of-it-all/ | James Smith | official clock-skew / timeline reconciliation | `945dd0f43a74de4c` |
| `dfirmadness-case.html` | https://dfirmadness.com/the-stolen-szechuan-sauce/ | James Smith | case overview + artifact inventory | `5ad66a0d997ebd79` |
| `dfirmadness-mounting-case001-e01-files.html` | https://dfirmadness.com/mounting-case001-e01-files/ | James Smith | E01 mounting how-to | `9d00588443b15cc4` |
| `iblue-team-memory.html` ★ | https://www.iblue.team/ctf-challenges/dfir-madness-ctf-challenges/case-001-szechuan-sauce | iblue.team | full memory-forensics walkthrough (kdbgscan → Volatility) | `d262d06abac64ffc` |
| `nihith-gitlab.html` ★ | https://g4rud4.gitlab.io/2023/Case-001-DFIR-Madness-The-Stolen-Szechuan-Sauce/ | Nihith | disk + memory + RDP-log (4624/4625) walkthrough, Volatility cmds | `faf529a7d9b9efb0` |
| `devto-evilcel3ri.html` ★ | https://dev.to/evilcel3ri/the-case-of-the-missing-szechuan-sauce-investigation-notes-1di7 | evilcel3ri | memory + network (Brim) investigation notes | `fc1f5b713117f014` |
| `ds4n6-odsc-notebook.ipynb` ★ | https://github.com/ds4n6/odsc_notebooks_binder (ODSC_TheStolenSzechuanSauceCase.ipynb) | ds4n6 | data-science DFIR Jupyter notebook | `4407a28ef6dd2cfe` |
| `netresec-pcap.html` | https://www.netresec.com/?page=Blog&month=2021-07&post=Walkthrough-of-DFIR-Madness-PCAP | Netresec | PCAP walkthrough (CapLoader/NetworkMiner) | `c7ecd09398fa897f` |
| `mimircyber-answers.html` | https://mimircyber.com/answers-to-the-case-of-the-stolen-szechuan-sauce-case-001/ | Mimir Cyber | answer-key mirror / timeline | `8d1b039c07202569` |
| `walshcat-medium.html` | https://walshcat.medium.com/case-write-up-the-stolen-szechuan-sauce-2409344264c3 (via web.archive.org 20250911141030) | walshcat | disk-focused write-up (no memory analysis) | `99b9bc8f96661584` |

## Not retrieved (login-walled / blocked — URLs recorded for completeness)
- Medium — Mohamed Mostafa: https://medium.com/@0xHimmler/case-001-the-stolen-szechuan-sauce-9e21c260aeb9 (Medium member-only wall; no Wayback capture)
- Medium — Jimoharamide: https://medium.com/@jimoharamide02/digital-forensics-investigation-the-stolen-szechuan-sauce-9b55c39572a7 (Medium wall; no Wayback capture)
- blueteam.news mirror: https://www.blueteam.news/2020/11/case-001-stolen-szechuan-sauce-dfir.html (fetch refused)
- 13Cubed (Richard Davis) walkthrough is YouTube-only (video; no downloadable transcript located)

## Authoritative anchors
- **Ground-truth answer key:** `dfirmadness-answers-to-szechuan-case-001.html` (the case author's own solution).
- **Memory ground truth:** `dfirmadness-case-001-memory-analysis.html` (Volatility) — the leg the walshcat write-up entirely omits.
- Canonical IOCs across sources: attacker `194.61.24.102` (Hydra brute force → Administrator on DC `10.42.85.10`); malware `coreupdater.exe` (Metasploit/Meterpreter); C2 `203.78.103.109`; injection into `spoolsv.exe`/`explorer.exe`; lateral RDP to `Desktop-SDN1RPT` (`10.42.85.115`); `loot.zip` exfil; clock-skew VM UTC-7 vs router UTC-6.
