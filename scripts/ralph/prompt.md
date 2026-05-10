# Ralph Agent Task — Issen (Rust)

You are running inside the git worktree at the current working directory.
This is a **Rust workspace** — use `cargo`, never `bun run` or `npm`.

## Workflow Per Iteration

1. Read `scripts/ralph/log.md` to understand what previous iterations completed.

2. Search `docs/user-stories/` for features with `"passes": false`.

3. If no features remain with `"passes": false`:
   - Output: <promise>FINISHED</promise>

4. Pick ONE feature — the highest-priority non-passing feature based on logical dependency order. Do not skip ahead; earlier tasks often define types needed by later ones.

5. Implement the feature following **strict TDD (Red-Green-Refactor)**:
   - **RED commit first**: Write the failing tests, run `cargo test -p <crate>` to confirm they fail, then commit with message `"test(red): <description>"`.
   - **GREEN commit second**: Write the minimal implementation, run `cargo test --workspace` to confirm all pass, then commit with message `"feat: GREEN — <description>"`.
   - Never implement before writing tests. Never combine RED and GREEN into one commit.

6. Verify after GREEN commit:
   - Run: `cargo test --workspace`
   - Run: `cargo clippy --workspace -- -D warnings` (fix any errors)
   - Run: `cargo build --workspace`
   - All must succeed with 0 errors.

7. If verification fails, debug and fix. Keep tests green at all times.

8. Once verified:
   - Update the user story's `passes` property to `true` in the JSON file.
   - Append a short entry to `scripts/ralph/log.md`.
   - Commit: `git add docs/user-stories/ scripts/ralph/log.md && git commit -m "chore: mark <story> as passing"`

9. The iteration ends here. Output the completion summary and stop.

## Critical Rules

- GITSIGN_CREDENTIAL_CACHE is set in the environment — git commit will work without browser prompts.
- **Never** run multiple `cargo test` processes concurrently — system RAM constraint.
- **Never** run `cargo test` without `-p` flag or `--workspace` — always one at a time.
- **Never** write implementation before tests (TDD is mandatory, not optional).
- **Never** combine RED and GREEN commits.
- Tests must use in-memory state, tempfiles, or fixtures — never real system artifacts.
- Clippy pedantic `-D warnings` must stay clean for all workspace crates.

## Rust Workspace Structure

```
crates/
  rt-core/            — TimelineEvent, Evidence, ArtifactType, error types
  rt-correlation/     — CorrelationRule YAML, PivotRule, engine, render, temporal_rule
  rt-timeline/        — temporal correlation primitives (EntityIndex, temporal_join)
  rt-evtx/            — winevt-forensic integration (session, analyze, handlers)
  rt-cli/             — Binary `rt` with subcommands: analyse, supertimeline, srum, pivot, feed
  rt-browser/         — browser-forensic integration
  rt-mem/             — memory-forensic integration
  rt-report/          — report generation
  rt-signatures/      — YARA/signature matching
  forensic-pivot/     — Evidence adapters (sigma, suricata, zeek), feed registry, downloader
  parsers/
    rt-parser-uac/    — UAC collection parser (ps, netstat, sockstat, chkrootkit)
    rt-parser-linux/  — Linux log parsers (auth.log, syslog, cron, bash_history)
    rt-parser-macos/  — macOS Unified Log + FSEvents
    rt-parser-evtx/   — EVTX parser integration
    rt-parser-mft/    — MFT parser
    rt-parser-lnk/    — LNK file parser
    rt-parser-prefetch/ — Prefetch parser
    rt-parser-registry/ — Registry hive parser
    rt-parser-amcache/  — Amcache.hve parser
    rt-parser-shimcache/ — Shimcache parser
    rt-parser-shellbags/ — Shellbags parser
    rt-parser-setupapi/ — SetupAPI log parser
    rt-parser-srum/   — SRUM parser integration
```

## Key Technical Facts

- Evidence Truth Model: `AssertionLevel` = Observed / Correlated / Inferred
- Correlation rules: YAML files in `crates/rt-correlation/rules/*.yml`
- `PivotRule` struct fields: `id`, `title`, `severity`, `assertion_level`, `default_confidence`, `summary_template`, `explanation_template`, `clauses`
- CLI binary is `rt` built from `crates/rt-cli/src/main.rs`
- Integration tests use `assert_cmd::Command` + `predicates`
- Temporal rules: `TemporalRule` struct in `crates/rt-correlation/src/temporal_rule.rs`

## Completion

When ALL user stories have `"passes": true`, output:

<promise>FINISHED</promise>
