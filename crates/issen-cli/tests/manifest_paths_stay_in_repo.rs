//! Single-checkout buildability gate.
//!
//! Every fleet repo is cloned on its own in CI. A `path = "..."` dependency that
//! resolves *outside* this repository therefore points at a directory the runner
//! does not have, and `cargo metadata` fails before any check gets to run — so
//! fmt, clippy, test, deny, vet and the doc build all go red together with an
//! error that names none of them.
//!
//! The failure is invisible on a developer machine, because the whole fleet is
//! checked out side by side and the escaping path resolves happily. That
//! asymmetry is the entire reason this gate exists: it makes a single-checkout
//! property observable from inside a full-fleet checkout.
//!
//! There is no exemption list. A path dependency reaching outside the repository
//! is never buildable from a lone clone, so "reviewed and intentional" is not a
//! state it can be in — publish the dependency and depend on the registry
//! version instead (ADR-0006 bottom-up release order, ADR-0010 prefer our own
//! crates).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Component, Path, PathBuf};

/// Workspace root (two levels up from `crates/issen-cli`).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Resolve `.` and `..` lexically, without touching the filesystem.
///
/// Deliberately not `canonicalize`: that requires the target to exist, and a
/// path escaping the repo is exactly the case where it may not. It also follows
/// symlinks, and `.claude/worktrees/` holds symlinks to the pre-reorg repo
/// locations — resolving through those would compare two unrelated roots.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Every `Cargo.toml` in the repository, skipping build output and worktrees.
fn manifests(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if matches!(name.to_str(), Some("target" | ".git" | ".claude")) {
                continue;
            }
            manifests(&path, found);
        } else if name == "Cargo.toml" {
            found.push(path);
        }
    }
}

/// Collect `(dependency name, declared path)` for every path dependency in a
/// manifest, across `[dependencies]`, `[dev-dependencies]`,
/// `[build-dependencies]`, `[workspace.dependencies]` and the per-target
/// `[target.<cfg>.dependencies]` forms.
fn path_dependencies(value: &toml::Value, under_deps: bool, out: &mut Vec<(String, String)>) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, child) in table {
        let is_deps = key.ends_with("dependencies");
        if under_deps && !is_deps {
            // `child` is a single dependency's specification table.
            if let Some(p) = child.get("path").and_then(toml::Value::as_str) {
                out.push((key.clone(), p.to_owned()));
            }
        }
        path_dependencies(child, under_deps || is_deps, out);
    }
}

#[test]
fn no_path_dependency_escapes_the_repository() {
    let root = normalize(&workspace_root());
    let mut found = Vec::new();
    manifests(&root, &mut found);
    assert!(
        found.len() > 1,
        "walked {} manifests under {} — the walker found nothing to check, \
         so a green result here would prove nothing",
        found.len(),
        root.display()
    );

    let mut escaping = Vec::new();
    let mut checked = 0_usize;
    for manifest in &found {
        let text = fs::read_to_string(manifest).unwrap();
        let Ok(value) = text.parse::<toml::Value>() else {
            continue;
        };
        let mut deps = Vec::new();
        path_dependencies(&value, false, &mut deps);
        let dir = manifest.parent().unwrap();
        for (name, declared) in deps {
            checked += 1;
            let resolved = normalize(&dir.join(&declared));
            if !resolved.starts_with(&root) {
                escaping.push(format!(
                    "  {}\n     {name} = {{ path = \"{declared}\" }}\n     resolves to {}",
                    manifest.strip_prefix(&root).unwrap_or(manifest).display(),
                    resolved.display(),
                ));
            }
        }
    }

    assert!(
        checked > 0,
        "found {} manifests but zero path dependencies — the extractor is not \
         reading dependency tables, so this gate is inert",
        found.len()
    );
    assert!(
        escaping.is_empty(),
        "{} of {checked} path dependencies resolve outside {}.\n\
         A lone clone of this repo cannot satisfy them, so `cargo metadata` \
         fails in CI before any check runs:\n\n{}\n\n\
         Publish the crate and depend on the registry version instead.",
        escaping.len(),
        root.display(),
        escaping.join("\n\n"),
    );
}
