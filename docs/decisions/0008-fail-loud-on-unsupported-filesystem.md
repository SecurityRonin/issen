# 0008. Fail loud on an unsupported filesystem; never a silent empty result

- Status: Accepted
- Date: 2026-06
- Deciders: SecurityRonin

## Context

The most expensive bug class in a forensic tool is a bootstrap failure absorbed
into an empty result. If issen is handed an APFS disk (a filesystem it does not
yet walk) and returns `✔ 0 events`, that output is **indistinguishable from a
genuinely clean NTFS image** — the examiner sees "nothing here" and moves on,
never learning that the disk was simply never read. A partition or filesystem the
pipeline cannot mount is a prerequisite failure, not a per-file miss, and must be
surfaced loudly.

## Decision

The disk pipeline **detects the filesystem by magic and fails loud** when no
supported volume is found, instead of degrading to an empty timeline.
`classify_partitions` walks the partition table and, for each partition,
`detect_filesystem` reads known filesystem magic. A partition that is a real,
recognized filesystem the pipeline does not support (e.g. APFS) records a named
`ExtractionLimit::UnsupportedFilesystem { filesystem, offset }` diagnostic
carrying the filesystem identity and its offset. The diagnostic travels with the
extraction result, so a non-empty `limits` list is itself a forensic finding, not
a warning that scrolled past.

## Consequences

An examiner given an unsupported disk gets a named, located diagnostic ("APFS at
offset N was not extracted") rather than a false all-clear — the failure is
attributable and shows the offending value, per the fleet's fail-loud and
"show the unrecognized value" disciplines. Degrade-to-empty remains legitimate
only for a per-artifact miss *after* a validated volume is mounted.

The cost is that adding filesystem support means teaching the detector new magic
and a new supported path; until then, evidence on that filesystem is explicitly
reported as unread rather than silently skipped. The diagnostics are asserted in
tests (an APFS-only disk must record `UnsupportedFilesystem`).

## References

- Fleet robustness posture — `CLAUDE.md` "Security & Robustness Standard — Paranoid Gatekeeper". The specific rule applied here — a bootstrap/prerequisite failure surfaces loudly, never as a silent empty result, and the offending value is shown — is stated in the Decision above.
- Crate: `crates/issen-disk` (`classify_partitions`, `detect_filesystem`, `ExtractionLimit::UnsupportedFilesystem`)
