# Contributing

PRs welcome. The most valuable contributions right now:

- **Correlation Rules** — add YAML files to `crates/rt-correlation/rules/`
- **Artifact parsers** — implement the `rt-plugin-sdk` trait
- **Platform-specific memory analysis** improvements

Please open an issue before large changes so we can align on approach.

## Getting started

```bash
git clone https://github.com/SecurityRonin/issen
cd issen
just setup          # enable the pre-commit hook (fmt + clippy) — do this first
cargo test --workspace
```

`just setup` points git at `.githooks/`, so `cargo fmt --check` and clippy run
before every commit. Without it the hook is dormant and formatting can drift
into `main` (CI only catches it after the fact).

All crates follow strict TDD — write failing tests first, then the implementation. See the test patterns in any existing crate for examples.

## Pull request checklist

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` clean
- [ ] `cargo fmt --check` passes
- [ ] New behaviour has tests

## Correlation Rules

Rules live in `crates/rt-correlation/rules/` as YAML files:

```yaml
id: correlation.your-rule-id
severity: high          # info | low | medium | high | critical
description: One sentence describing what this detects
within_seconds: 300
references:
  - https://example.com/relevant-writeup
clauses:
  - source: artifact
    required_tag: some_tag
  - source: memory
    required_tag: another_tag
```

## Parser plugins

Parsers implement the `ArtifactParser` trait from `rt-plugin-sdk` and register themselves at link time via `inventory::submit!`. See `crates/parsers/rt-parser-mft` for a complete example.
