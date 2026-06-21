//! Parser DEPTH gate (the third axis, after reachability + collection).
//!
//! `selector_gate` / `disk_collection_gate` / `classifier_differential` prove a
//! parser is *reached* — classified, collected, and its trait fires. None of
//! them check WHAT it surfaces. A parser can pass every reachability gate while
//! dropping the single most important field on the disk (the registry wrapper
//! emitted the `...\Run` key's write timestamp for years while discarding the
//! `coreupdate` persistence command under it — present-looking, hollow).
//!
//! This gate closes that axis: each parser declares the forensic fields it MUST
//! surface (its depth manifest), and a real-data fixture is driven through the
//! parser to assert those keys actually appear in emitted `TimelineEvent`
//! metadata — plus, for high-signal cases, that a known real IOC reaches the
//! description. The declared set is the *current* depth; deepening a parser adds
//! to it (ratchet), and a refactor that silently drops a field fails here.
//!
//! Teeth vs fixtures: cases backed by a committed fixture always run (real CI
//! teeth); cases backed by the gitignored real-corpus skip-loud when it is
//! absent, so the gate is as strong as the data present in the running
//! environment. The decision logic ([`missing_keys`]) is unit-tested
//! independently of any fixture, so the gate's failure-detection is proven even
//! where the corpus is absent (Humble Object).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use issen_core::timeline::event::TimelineEvent;

/// The pure decision core: which of `required` metadata keys appear in NO event.
/// Returns them in the order declared (deterministic) so a failure names exactly
/// what regressed. This is the Humble Object — fixture-free and unit-tested.
fn missing_keys(events: &[TimelineEvent], required: &[&str]) -> Vec<String> {
    let present: std::collections::HashSet<&str> = events
        .iter()
        .flat_map(|e| e.metadata.keys().map(String::as_str))
        .collect();
    required
        .iter()
        .filter(|k| !present.contains(**k))
        .map(|k| (*k).to_string())
        .collect()
}

// ── Depth manifest: the declared current depth of each parser ────────────────

use std::path::{Path, PathBuf};

/// One parser's declared depth, checked against a real fixture.
struct DepthCase {
    label: &'static str,
    /// Fixture path, relative to this crate's manifest dir.
    fixture: &'static str,
    /// `true` = committed fixture (absence is a hard failure, real CI teeth);
    /// `false` = gitignored real-corpus (absence skips-loud).
    committed: bool,
    /// Drive the parser over the fixture into timeline events.
    drive: fn(&Path) -> Vec<TimelineEvent>,
    /// Metadata keys that MUST appear across the emitted events.
    required_keys: &'static [&'static str],
    /// Real-IOC substrings that MUST appear in some event's description or
    /// metadata value — catches the "hollow shell" regression (the container
    /// key is present but the forensic value under it was dropped).
    required_iocs: &'static [&'static str],
}

fn drive_prefetch(p: &Path) -> Vec<TimelineEvent> {
    issen_parser_prefetch::parser::parse_prefetch(p, "depth-gate").unwrap()
}
fn drive_lnk(p: &Path) -> Vec<TimelineEvent> {
    issen_parser_lnk::parser::parse_lnk(p, "depth-gate").unwrap()
}
fn drive_hive(p: &Path) -> Vec<TimelineEvent> {
    issen_parser_registry::parser::parse_hive(p, "depth-gate").unwrap()
}
fn drive_jumplist(p: &Path) -> Vec<TimelineEvent> {
    let bytes = std::fs::read(p).unwrap();
    let filename = p.file_name().unwrap().to_string_lossy();
    issen_parser_lnk::jumplist::parse_jumplist_bytes(&bytes, &filename, "depth-gate")
}

const HIVES: &str = "../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives";

fn manifest() -> Vec<DepthCase> {
    vec![
        // ── Committed fixtures (always run) ──
        DepthCase {
            label: "prefetch loaded-file list",
            fixture: "../parsers/issen-parser-prefetch/tests/data/COREUPDATER.EXE-157C54BB.pf",
            committed: true,
            drive: drive_prefetch,
            required_keys: &[
                "loaded_files",
                "loaded_file_count",
                "executable",
                "run_count",
            ],
            required_iocs: &["WS2_32.DLL", "NTDLL.DLL"],
        },
        DepthCase {
            label: "lnk UNC network origin",
            fixture: "../parsers/issen-parser-lnk/tests/data/network_share.lnk",
            committed: true,
            drive: drive_lnk,
            required_keys: &["unc_path", "network_device", "target_path"],
            required_iocs: &[r"\\SERVER\share"],
        },
        DepthCase {
            label: "lnk USB removable origin",
            fixture: "../parsers/issen-parser-lnk/tests/data/removable_media.lnk",
            committed: true,
            drive: drive_lnk,
            required_keys: &["drive_serial", "drive_type", "target_path"],
            required_iocs: &["payload.exe"],
        },
        DepthCase {
            label: "lnk command-line arguments + working dir",
            fixture: "../parsers/issen-parser-lnk/tests/data/command_args.lnk",
            committed: true,
            drive: drive_lnk,
            required_keys: &["arguments", "working_dir", "comment"],
            required_iocs: &["-enc", "hidden"],
        },
        DepthCase {
            label: "jumplist automatic destinations",
            fixture:
                "../parsers/issen-parser-lnk/tests/data/pinned_removable.automaticDestinations-ms",
            committed: true,
            drive: drive_jumplist,
            required_keys: &["target_path", "hostname", "pinned"],
            required_iocs: &["report.docx", "OTHER-PC"],
        },
        // The custom (`.customDestinations-ms`) form: no DestList, so no
        // hostname/pinned — its depth is the per-application target, the AppID,
        // and the `Custom` kind discriminator that separates it from the
        // automatic form.
        DepthCase {
            label: "jumplist custom destinations",
            fixture: "../parsers/issen-parser-lnk/tests/data/tasks.customDestinations-ms",
            committed: true,
            drive: drive_jumplist,
            required_keys: &["target_path", "jumplist_kind", "app_id"],
            required_iocs: &["report.docx", "Custom"],
        },
        // ── Gitignored real corpus (skip-loud when absent) ──
        DepthCase {
            label: "registry SOFTWARE: run-key persistence + OS version",
            fixture: "SOFTWARE",
            committed: false,
            drive: drive_hive,
            required_keys: &["command", "value_name", "product_name"],
            required_iocs: &["coreupdate"],
        },
        DepthCase {
            label: "registry NTUSER.DAT: userassist + typed URLs",
            fixture: "NTUSER.DAT",
            committed: false,
            drive: drive_hive,
            required_keys: &["program", "run_count", "url"],
            required_iocs: &["coreupdater.exe", "194.61.24.102"],
        },
        DepthCase {
            label: "registry SYSTEM: shimcache + timezone",
            fixture: "SYSTEM",
            committed: false,
            drive: drive_hive,
            required_keys: &["path", "entry_index", "timezone"],
            required_iocs: &["vcredist"],
        },
        DepthCase {
            label: "registry SAM: local accounts",
            fixture: "SAM",
            committed: false,
            drive: drive_hive,
            required_keys: &["username", "rid", "login_count"],
            required_iocs: &["Administrator"],
        },
        DepthCase {
            label: "registry SECURITY: LSA secrets",
            fixture: "SECURITY",
            committed: false,
            drive: drive_hive,
            required_keys: &["secret_name", "has_current", "has_old"],
            required_iocs: &["$MACHINE.ACC"],
        },
    ]
}

/// All searchable text of an event: its description plus every metadata value.
fn searchable(e: &TimelineEvent) -> String {
    let mut s = e.description.clone();
    for v in e.metadata.values() {
        s.push(' ');
        s.push_str(&v.to_string());
    }
    s.to_lowercase()
}

/// The ratchet: every parser must surface its declared depth on real data. A
/// committed-fixture case always runs; a corpus-backed case skips-loud when the
/// gitignored data is absent. A dropped key OR a dropped IOC fails here.
#[test]
fn parsers_surface_declared_depth() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut failures: Vec<String> = Vec::new();

    for case in manifest() {
        let fixture = if case.committed {
            base.join(case.fixture)
        } else {
            base.join(HIVES).join(case.fixture)
        };
        if !fixture.exists() {
            assert!(
                !case.committed,
                "committed depth fixture missing: {} ({})",
                case.label,
                fixture.display()
            );
            eprintln!(
                "SKIP depth case '{}': corpus fixture absent ({}); see docs/corpus-catalog.md",
                case.label,
                fixture.display()
            );
            continue;
        }

        let events = (case.drive)(&fixture);
        for key in missing_keys(&events, case.required_keys) {
            failures.push(format!("[{}] dropped metadata key '{key}'", case.label));
        }
        let blob: String = events.iter().map(searchable).collect::<Vec<_>>().join("  ");
        for ioc in case.required_iocs {
            if !blob.contains(&ioc.to_lowercase()) {
                failures.push(format!(
                    "[{}] dropped forensic value '{ioc}' (key present but value hollow?)",
                    case.label
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "parser depth regressed — a parser stopped surfacing a declared field:\n{}",
        failures.join("\n")
    );
}

#[test]
fn flags_dropped_metadata_key() {
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::EventType;

    let mk = |k: &str, v: &str| {
        TimelineEvent::new(
            0,
            String::new(),
            EventType::RegistryModify,
            ArtifactType::Registry,
            "p".into(),
            "d".into(),
            "s".into(),
        )
        .with_metadata(k, serde_json::json!(v))
    };
    // Events collectively carry {a, b}; requiring {a, b, c} must flag exactly c.
    let events = vec![mk("a", "1"), mk("b", "2")];
    assert_eq!(
        missing_keys(&events, &["a", "b", "c"]),
        vec!["c".to_string()],
        "the gate must flag a required key that appears in no event"
    );
    assert!(
        missing_keys(&events, &["a", "b"]).is_empty(),
        "a fully-surfaced manifest must pass"
    );
}

/// Ratchet: the depth manifest must lock the *custom*-destinations Jump List form
/// alongside the automatic one. Custom `.customDestinations-ms` files have no
/// DestList (no `hostname`/`pinned`), so their depth is a distinct slice — the
/// per-application target + the `Custom` kind discriminator + the AppID. This
/// fails until a custom case is added, so a refactor that silently drops custom
/// support (or merges it into the automatic case and loses the kind) regresses
/// here.
#[test]
fn manifest_locks_custom_jumplist_depth() {
    let custom = manifest()
        .into_iter()
        .find(|c| c.fixture.ends_with(".customDestinations-ms"))
        .expect("depth manifest must declare a *custom*-destinations Jump List case");

    assert!(
        custom.committed,
        "the custom Jump List case must be backed by a committed fixture (real CI teeth)"
    );
    for k in ["target_path", "jumplist_kind", "app_id"] {
        assert!(
            custom.required_keys.contains(&k),
            "custom Jump List depth must lock the '{k}' field"
        );
    }
    assert!(
        custom
            .required_iocs
            .iter()
            .any(|i| i.eq_ignore_ascii_case("Custom")),
        "custom Jump List depth must assert the 'Custom' kind discriminator reaches the event \
         (distinguishes it from the automatic form)"
    );
}
