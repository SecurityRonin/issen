# 0009. Batteries-included single static binary

- Status: Accepted
- Date: 2026-06
- Deciders: SecurityRonin

## Context

A forensic tool runs in the field on an evidence workstation where the analyst
cannot `cargo build --features gpu,cloud` to turn on a capability. A capability
that is not compiled in is a capability that is not there when it matters. The
tempting instinct — slimming the dependency graph with `default-features = false`,
or amputating a feature to dodge a `cargo deny` license gate — ships a tool that
silently cannot do the job.

## Decision

issen and every fleet app/CLI is **batteries-included: a single static binary with
all capabilities compiled in.** Using `default-features = false` to slim a fleet
dependency is banned. When full features trip a gate, the **gate** is fixed, not
the feature set — for example, `blazehash` pulls `xxhash-rust` (BSL-1.0), so
BSL-1.0 is allowed in the fleet `deny.toml` rather than dropping every other hash
algorithm. `Cargo.lock` is committed in every binary/app repo so CI resolves the
same graph the analyst ships.

The reconciling mechanism is the **lean-library / full-binary split**: a capability
crate that fleet *libraries* also link for one primitive is split into a lean
`<x>-core` (just the primitives) and the full `<x>` app. Libraries depend on the
lean `-core` (so no `default-features = false` is ever needed); binaries and the
tool itself stay batteries-included. Reference: `blazehash-core` (lean) +
`blazehash` (full).

## Consequences

The analyst gets one binary that hashes, carves, decompresses, queries, and
reports with no rebuild and no runtime dependencies — the zero-configuration path
is the capable one. License and supply-chain problems are solved once, centrally,
in `deny.toml` and the committed lock, rather than scattered as per-crate feature
amputations.

The trade-off is a larger dependency tree and bigger binary, and a heavier
compile — the bundled-DuckDB MSVC path in particular is the long pole in release
builds. The single documented exception is a genuinely optional, rarely-wanted
heavy subsystem, which may be a named non-default feature *provided the shipping
binary turns it on*; the slim path exists only for outside consumers, never for
our own tools.

## References

- `CLAUDE.md` — "Batteries-Included — Compile Everything In", lean-core/full-binary rule
- Fleet `deny.toml` — BSL-1.0 allowed (xxhash via blazehash), the license-gate fix that preserves the full feature set (see the Batteries-Included consequences above).
- Reference: `blazehash-core` (lean lib) + `blazehash` (full binary)
