#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Dark-parser gate (issen #114, silent-omission killer — complements
//! `producer_coverage`).
//!
//! A "dark parser" is a `ForensicParser` that is registered and advertises
//! `ArtifactType`s but whose `parse()` ignores its emitter — so matching
//! artifacts are discovered, "parsed" into **zero** events, and silently vanish
//! from the timeline. `producer_coverage` proves every classified type *has* a
//! producer; this proves the producers actually *produce*.
//!
//! Detection is static (the `inventory` registry is empty outside the `issen`
//! binary): the strongest signal Rust gives for an ignored parameter is an
//! underscore-prefixed name, so a `parse()` whose `&dyn EventEmitter` parameter
//! is `_`-prefixed is definitively a stub. New dark parsers fail this gate; the
//! known-unimplemented ones are tracked in `KNOWN_DARK_PARSERS` until their
//! parsers land — wiring one is a "good failure" here (drop it from the list).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Parsers whose `ForensicParser::parse()` is still a stub, tracked as #114
/// debt. Once a parser's `parse()` is wired to emit, REMOVE it here — the gate
/// fails until you do (the intended ratchet, so the list reflects reality).
///
/// Empty: every registered parser's `parse()` now emits via its core. lnk,
/// setupapi, and the linux (auth/syslog/cron/bash) + macos (unified/fsevents)
/// parsers were all wired in #114.
const KNOWN_DARK_PARSERS: &[&str] = &[];

fn concat_rs(dir: &Path, out: &mut String) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            concat_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(text) = fs::read_to_string(&path) {
                out.push_str(&text);
                out.push('\n');
            }
        }
    }
}

/// True when a parser source has an `impl ForensicParser` *and* a `parse()`
/// whose `&dyn EventEmitter` parameter is underscore-prefixed (ignored) — i.e.
/// the parse cannot emit anything.
fn is_dark(src: &str) -> bool {
    src.contains("impl ForensicParser") && has_unused_emitter_param(src)
}

/// Does any `&dyn EventEmitter` parameter have an underscore-prefixed name?
/// (`_emitter: &dyn EventEmitter` / `_: &dyn EventEmitter` → unused.)
fn has_unused_emitter_param(src: &str) -> bool {
    // Look at the identifier immediately preceding each `&dyn EventEmitter`.
    let mut idx = 0;
    while let Some(found) = src[idx..].find("&dyn EventEmitter") {
        let at = idx + found;
        let before = src[..at].trim_end();
        // expect `... <name> :` just before the type
        if let Some(stripped) = before.strip_suffix(':') {
            let name = stripped
                .trim_end()
                .rsplit(|c: char| c.is_whitespace() || c == '(' || c == ',')
                .next()
                .unwrap_or("");
            if name.starts_with('_') {
                return true;
            }
        }
        idx = at + "&dyn EventEmitter".len();
    }
    false
}

fn dark_parsers(workspace: &Path) -> BTreeSet<String> {
    let mut dark = BTreeSet::new();
    let parsers = workspace.join("crates/parsers");
    let Ok(entries) = fs::read_dir(&parsers) else {
        panic!("read crates/parsers");
    };
    for entry in entries.flatten() {
        let crate_dir = entry.path();
        if !crate_dir.is_dir() {
            continue;
        }
        let name = crate_dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut src = String::new();
        concat_rs(&crate_dir.join("src"), &mut src);
        if is_dark(&src) {
            dark.insert(name);
        }
    }
    dark
}

#[test]
fn no_unexpected_dark_parsers() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dark = dark_parsers(&workspace);
    let allowed: BTreeSet<String> = KNOWN_DARK_PARSERS
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let unexpected: Vec<&String> = dark.difference(&allowed).collect();
    assert!(
        unexpected.is_empty(),
        "NEW dark parser(s) — registered + advertising ArtifactTypes but parse() \
         ignores its emitter, so matching artifacts emit nothing and vanish from \
         the timeline: {unexpected:?}. Wire parse() to emit, or (if intentional) \
         add it to KNOWN_DARK_PARSERS with a tracking note."
    );

    // Ratchet the other direction: a parser that is no longer dark must be
    // removed from the allowlist (so the list reflects reality).
    let stale: Vec<&String> = allowed.difference(&dark).collect();
    assert!(
        stale.is_empty(),
        "KNOWN_DARK_PARSERS lists parser(s) that are no longer dark — their \
         parse() now emits. Remove them from the allowlist: {stale:?}"
    );
}

#[test]
fn detector_distinguishes_stub_from_wired() {
    // Teeth: the underscore-emitter signal flags a stub and clears a wired impl.
    let stub = "impl ForensicParser for X { fn parse(&self, _i: &dyn DataSource, _emitter: &dyn EventEmitter) -> R { Ok(()) } }";
    let wired = "impl ForensicParser for X { fn parse(&self, input: &dyn DataSource, emitter: &dyn EventEmitter) -> R { emitter.emit(e) } }";
    assert!(
        is_dark(stub),
        "an ignored `_emitter` param must read as dark"
    );
    assert!(!is_dark(wired), "a used `emitter` param must read as wired");

    // And the just-wired LNK parser must NOT be flagged.
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(
        !dark_parsers(&workspace).contains("issen-parser-lnk"),
        "issen-parser-lnk was wired in #114 and must not read as dark"
    );
}
