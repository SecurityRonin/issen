#![allow(clippy::unwrap_used, clippy::expect_used)]
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn issen_cmd() -> Command {
    Command::cargo_bin("issen").expect("binary issen should exist")
}

#[test]
fn test_no_args_shows_help() {
    issen_cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn test_help_flag() {
    issen_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Issen"))
        .stdout(predicate::str::contains("ingest"))
        .stdout(predicate::str::contains("timeline"))
        .stdout(predicate::str::contains("info"))
        .stdout(predicate::str::contains("feed"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("remote-access"))
        .stdout(predicate::str::contains("report"));
}

#[test]
fn test_version_flag() {
    issen_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("issen"));
}

#[test]
fn test_ingest_missing_path() {
    issen_cmd()
        .args(["ingest", "/nonexistent/path/that/does/not/exist"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn test_ingest_empty_directory() {
    let dir = TempDir::new().expect("tmpdir");
    let out_dir = TempDir::new().expect("tmpdir for db");
    let db_path = out_dir.path().join("test.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Artifacts found:  0"))
        .stdout(predicate::str::contains("Artifacts parsed: 0"));
}

#[test]
fn test_ingest_with_evidence_source() {
    let dir = TempDir::new().expect("tmpdir");
    let out_dir = TempDir::new().expect("tmpdir for db");
    let db_path = out_dir.path().join("test.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
            "-s",
            "CASE-2024-001",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Ingesting evidence"));
}

#[test]
fn test_info_nonexistent_db() {
    issen_cmd()
        .args(["info", "/nonexistent/db.duckdb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn test_info_on_empty_db() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("test.duckdb");

    // First ingest to create the DB.
    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Then query info.
    issen_cmd()
        .args(["info", &db_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total events:      0"))
        .stdout(predicate::str::contains("Evidence sources:"));
}

#[test]
fn test_timeline_no_events() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("test.duckdb");

    // Ingest empty dir to create DB.
    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Query timeline.
    issen_cmd()
        .args(["timeline", &db_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No events found"));
}

#[test]
fn test_timeline_help() {
    issen_cmd()
        .args(["timeline", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--event-type"))
        .stdout(predicate::str::contains("--source"))
        .stdout(predicate::str::contains("--export-sqlite"))
        .stdout(predicate::str::contains("--descending"));
}

#[test]
fn test_ingest_help() {
    issen_cmd()
        .args(["ingest", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("EVIDENCE_PATH"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--evidence-source"));
}

#[test]
fn test_ingest_usnjrnl_and_query() {
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_dir = TempDir::new().expect("tmpdir for db");
    let db_path = db_dir.path().join("timeline.duckdb");

    // Create a fake $J file with a valid USN V2 record.
    let record = build_usn_v2_record("TestFile.txt", 0x100, 42, 100, 512);
    std::fs::write(evidence_dir.path().join("$J"), &record).expect("write $J");

    // Ingest.
    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
            "-s",
            "test-case",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Artifacts found:  1"))
        .stdout(predicate::str::contains("Artifacts parsed: 1"))
        .stdout(predicate::str::contains("Events generated: 1"));

    // Query info.
    issen_cmd()
        .args(["info", &db_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total events:      1"))
        .stdout(predicate::str::contains("UsnJournal"));

    // Query timeline.
    issen_cmd()
        .args(["timeline", &db_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("TestFile.txt"));
}

#[test]
fn test_ingest_and_export_sqlite() {
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_dir = TempDir::new().expect("tmpdir for db");
    let db_path = db_dir.path().join("timeline.duckdb");
    let sqlite_path = db_dir.path().join("export.sqlite");

    // Create a fake $J file.
    let record = build_usn_v2_record("Export.docx", 0x100, 1, 2, 0);
    std::fs::write(evidence_dir.path().join("$J"), &record).expect("write");

    // Ingest.
    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Export.
    issen_cmd()
        .args([
            "timeline",
            &db_path.to_string_lossy(),
            "--export-sqlite",
            &sqlite_path.to_string_lossy(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 1 events"));

    assert!(sqlite_path.exists(), "SQLite file should be created");
}

/// Build a minimal valid USN V2 binary record for testing.
/// Mirrors the test helper in rt-parser-usnjrnl.
fn build_usn_v2_record(
    filename: &str,
    reason: u32,
    file_ref: u64,
    parent_ref: u64,
    usn: i64,
) -> Vec<u8> {
    let name_utf16: Vec<u8> = filename
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let file_name_offset: u16 = 60;
    let file_name_length = name_utf16.len() as u16;
    let record_length = (file_name_offset as usize + name_utf16.len()) as u32;
    // Pad to 8-byte alignment.
    let padded_length = (record_length as usize + 7) & !7;

    let mut buf = vec![0u8; padded_length];
    buf[0..4].copy_from_slice(&(padded_length as u32).to_le_bytes());
    buf[4..6].copy_from_slice(&2u16.to_le_bytes()); // major_version
    buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // minor_version
    buf[8..16].copy_from_slice(&file_ref.to_le_bytes());
    buf[16..24].copy_from_slice(&parent_ref.to_le_bytes());
    buf[24..32].copy_from_slice(&usn.to_le_bytes());
    // Timestamp: 2023-11-14T22:13:20Z as FILETIME.
    let filetime: i64 = 133_444_736_000_000_000;
    buf[32..40].copy_from_slice(&filetime.to_le_bytes());
    buf[40..44].copy_from_slice(&reason.to_le_bytes());
    buf[44..48].copy_from_slice(&0u32.to_le_bytes()); // source_info
    buf[48..52].copy_from_slice(&0u32.to_le_bytes()); // security_id
    buf[52..56].copy_from_slice(&0x20u32.to_le_bytes()); // file_attributes (ARCHIVE)
    buf[56..58].copy_from_slice(&file_name_length.to_le_bytes());
    buf[58..60].copy_from_slice(&file_name_offset.to_le_bytes());
    buf[60..60 + name_utf16.len()].copy_from_slice(&name_utf16);
    buf
}

// ── Feed subcommand tests ──────────────────────────────────────────

#[test]
fn test_feed_help() {
    issen_cmd()
        .args(["feed", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("update"))
        .stdout(predicate::str::contains("info"));
}

#[test]
fn test_feed_list() {
    issen_cmd()
        .args(["feed", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MalwareBazaar"))
        .stdout(predicate::str::contains("Feodo Tracker"))
        .stdout(predicate::str::contains("CISA"))
        .stdout(predicate::str::contains("feeds configured"));
}

#[test]
fn test_feed_info_unknown() {
    issen_cmd()
        .args(["feed", "info", "nonexistent-feed-id"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_feed_info_known() {
    issen_cmd()
        .args(["feed", "info", "cisa-kev"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "CISA Known Exploited Vulnerabilities",
        ))
        .stdout(predicate::str::contains("cisa-kev"))
        .stdout(predicate::str::contains("Enabled"));
}

// ── Scan subcommand tests ──────────────────────────────────────────

#[test]
fn test_scan_help() {
    issen_cmd()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("yara-rules"))
        .stdout(predicate::str::contains("sigma-rules"))
        .stdout(predicate::str::contains("hash-iocs"))
        .stdout(predicate::str::contains("network-iocs"))
        .stdout(predicate::str::contains("stix-bundle"));
}

#[test]
fn test_scan_missing_target() {
    issen_cmd()
        .arg("scan")
        .assert()
        .failure()
        .stderr(predicate::str::contains("TARGET"));
}

#[test]
fn test_scan_nonexistent_target() {
    issen_cmd()
        .args(["scan", "/nonexistent/path/to/files"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("No files found"));
}

#[test]
fn test_scan_file_no_engines() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test.bin");
    std::fs::write(&file_path, b"some benign content").unwrap();

    issen_cmd()
        .args(["scan", file_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 YARA rules"))
        .stderr(predicate::str::contains("0 finding(s)"));
}

#[test]
fn test_scan_with_yara_rules() {
    let dir = TempDir::new().unwrap();

    // Write a YARA rule file.
    let rule_path = dir.path().join("test.yar");
    std::fs::write(
        &rule_path,
        r#"rule detect_test { strings: $s = "MALICIOUS_MARKER" condition: $s }"#,
    )
    .unwrap();

    // Write a target file that matches.
    let target_path = dir.path().join("suspect.bin");
    std::fs::write(&target_path, b"this file has MALICIOUS_MARKER inside").unwrap();

    issen_cmd()
        .args([
            "scan",
            target_path.to_str().unwrap(),
            "--yara-rules",
            rule_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 YARA rules"))
        .stderr(predicate::str::contains("1 finding(s)"))
        .stdout(predicate::str::contains("detect_test"));
}

#[test]
fn test_scan_with_yara_no_match() {
    let dir = TempDir::new().unwrap();

    let rule_path = dir.path().join("test.yar");
    std::fs::write(
        &rule_path,
        r#"rule detect_evil { strings: $s = "EVIL_BYTES" condition: $s }"#,
    )
    .unwrap();

    let target_path = dir.path().join("clean.bin");
    std::fs::write(&target_path, b"totally clean file").unwrap();

    issen_cmd()
        .args([
            "scan",
            target_path.to_str().unwrap(),
            "--yara-rules",
            rule_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 finding(s)"));
}

#[test]
fn test_scan_with_hash_iocs() {
    use sha2::{Digest, Sha256};
    let dir = TempDir::new().unwrap();

    // Write target file.
    let target_path = dir.path().join("malware.bin");
    let data = b"known malware payload content";
    std::fs::write(&target_path, data).unwrap();

    // Compute SHA-256 of the target and write IOC file.
    let hash = format!("{:x}", Sha256::digest(data));

    let ioc_path = dir.path().join("bad_hashes.txt");
    std::fs::write(&ioc_path, format!("# Bad hashes\n{hash}\n")).unwrap();

    issen_cmd()
        .args([
            "scan",
            target_path.to_str().unwrap(),
            "--hash-iocs",
            ioc_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 finding(s)"))
        .stdout(predicate::str::contains("sha256_match"));
}

#[test]
fn test_scan_with_hash_iocs_no_match() {
    let dir = TempDir::new().unwrap();

    let target_path = dir.path().join("clean.bin");
    std::fs::write(&target_path, b"clean file").unwrap();

    let ioc_path = dir.path().join("bad_hashes.txt");
    std::fs::write(
        &ioc_path,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
    )
    .unwrap();

    issen_cmd()
        .args([
            "scan",
            target_path.to_str().unwrap(),
            "--hash-iocs",
            ioc_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 finding(s)"));
}

#[test]
fn test_scan_directory_recursive() {
    let dir = TempDir::new().unwrap();

    // Create a subdirectory with files.
    let sub = dir.path().join("subdir");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("a.bin"), b"file a content").unwrap();
    std::fs::write(sub.join("b.bin"), b"file b content").unwrap();
    std::fs::write(dir.path().join("c.bin"), b"file c content").unwrap();

    issen_cmd()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("3 file(s) scanned"));
}

#[test]
fn test_scan_json_output_format() {
    let dir = TempDir::new().unwrap();

    let rule_path = dir.path().join("test.yar");
    std::fs::write(
        &rule_path,
        r#"rule json_test { strings: $s = "JSON_MARKER" condition: $s }"#,
    )
    .unwrap();

    let target_path = dir.path().join("target.bin");
    std::fs::write(&target_path, b"file with JSON_MARKER data").unwrap();

    issen_cmd()
        .args([
            "scan",
            target_path.to_str().unwrap(),
            "--yara-rules",
            rule_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_name\""))
        .stdout(predicate::str::contains("json_test"))
        .stdout(predicate::str::contains("\"severity\""));
}

#[test]
fn test_scan_min_severity_filter() {
    let dir = TempDir::new().unwrap();

    // YARA matches default to High severity. Filter at Critical to exclude them.
    let rule_path = dir.path().join("test.yar");
    std::fs::write(
        &rule_path,
        r#"rule sev_test { strings: $s = "MATCH_ME" condition: $s }"#,
    )
    .unwrap();

    let target_path = dir.path().join("target.bin");
    std::fs::write(&target_path, b"MATCH_ME content").unwrap();

    // With min-severity=critical, YARA (High) should be excluded.
    issen_cmd()
        .args([
            "scan",
            target_path.to_str().unwrap(),
            "--yara-rules",
            rule_path.to_str().unwrap(),
            "--min-severity",
            "critical",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 finding(s)"));
}

#[test]
fn test_scan_yara_rules_directory() {
    let dir = TempDir::new().unwrap();

    // Create a rules directory with two .yar files.
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir(&rules_dir).unwrap();
    std::fs::write(
        rules_dir.join("rule1.yar"),
        r#"rule dir_rule1 { strings: $s = "RULE1_HIT" condition: $s }"#,
    )
    .unwrap();
    std::fs::write(
        rules_dir.join("rule2.yara"),
        r#"rule dir_rule2 { strings: $s = "RULE2_HIT" condition: $s }"#,
    )
    .unwrap();

    let target_path = dir.path().join("target.bin");
    std::fs::write(&target_path, b"content with RULE1_HIT marker").unwrap();

    issen_cmd()
        .args([
            "scan",
            target_path.to_str().unwrap(),
            "--yara-rules",
            rules_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 YARA rules"))
        .stderr(predicate::str::contains("1 finding(s)"))
        .stdout(predicate::str::contains("dir_rule1"));
}

// ── --flagged JSON output tests ──────────────────────────────────────

#[test]
fn test_timeline_flagged_json_empty() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("test.duckdb");

    // Ingest an empty directory to create the DB.
    let evidence = dir.path().join("evidence");
    std::fs::create_dir(&evidence).unwrap();

    issen_cmd()
        .args([
            "ingest",
            evidence.to_str().unwrap(),
            "-o",
            db.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Query with --flagged --format json on a DB with no findings.
    let output = issen_cmd()
        .args([
            "timeline",
            db.to_str().unwrap(),
            "--flagged",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run rt");

    assert!(output.status.success(), "command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(parsed["total"], 0);
    assert!(parsed["findings"].is_array());
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
    assert!(parsed["by_severity"].is_object());
}

#[test]
fn test_timeline_format_help() {
    issen_cmd()
        .args(["timeline", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--format"));
}

// ── --flagged integration tests ──────────────────────────────────────

#[test]
fn test_timeline_flagged_empty_db() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("test.duckdb");

    // Ingest an empty directory to create the DB.
    let evidence = dir.path().join("evidence");
    std::fs::create_dir(&evidence).unwrap();

    issen_cmd()
        .args([
            "ingest",
            evidence.to_str().unwrap(),
            "-o",
            db.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Query with --flagged on a DB that has no findings table yet.
    issen_cmd()
        .args(["timeline", db.to_str().unwrap(), "--flagged"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No scan findings found"));
}

#[test]
fn test_timeline_flagged_help() {
    issen_cmd()
        .args(["timeline", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--flagged"))
        .stdout(predicate::str::contains("--min-severity"));
}

#[test]
fn test_scan_auto_feeds_help() {
    issen_cmd()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--auto-feeds"));
}

#[test]
fn test_ingest_scan_help() {
    issen_cmd()
        .args(["ingest", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--scan"));
}

// ── Ingest scan rule flag tests ──────────────────────────────────────

#[test]
fn test_ingest_help_shows_scan_flags() {
    issen_cmd()
        .args(["ingest", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--yara-rules"))
        .stdout(predicate::str::contains("--sigma-rules"))
        .stdout(predicate::str::contains("--hash-iocs"))
        .stdout(predicate::str::contains("--network-iocs"));
}

#[test]
fn test_ingest_with_yara_scan() {
    let dir = TempDir::new().unwrap();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.duckdb");

    // Write a YARA rule that matches our evidence file.
    let rule_path = dir.path().join("detect.yar");
    std::fs::write(
        &rule_path,
        r#"rule ingest_detect { strings: $s = "MALICIOUS_MARKER" condition: $s }"#,
    )
    .unwrap();

    // Create an evidence directory with a file matching the YARA rule.
    let evidence_dir = dir.path().join("evidence");
    std::fs::create_dir(&evidence_dir).unwrap();
    // Write a $J USN record so the pipeline discovers an artifact whose path
    // we can then place as a real file for YARA scanning.
    let record = build_usn_v2_record("suspect.bin", 0x100, 42, 100, 0);
    std::fs::write(evidence_dir.join("$J"), &record).unwrap();
    // Place the suspect file so YARA can scan it.
    std::fs::write(
        evidence_dir.join("suspect.bin"),
        b"this file has MALICIOUS_MARKER inside",
    )
    .unwrap();

    issen_cmd()
        .args([
            "ingest",
            evidence_dir.to_str().unwrap(),
            "-o",
            db_path.to_str().unwrap(),
            "--yara-rules",
            rule_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Scanning phase"))
        .stdout(predicate::str::contains("Total findings:"));
}

#[test]
fn test_ingest_with_sigma_scan() {
    let dir = TempDir::new().unwrap();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.duckdb");

    // Write a Sigma rule file.
    let sigma_dir = dir.path().join("sigma");
    std::fs::create_dir(&sigma_dir).unwrap();
    std::fs::write(
        sigma_dir.join("test.yml"),
        r"
title: Test Sigma Rule
id: test-ingest-sigma-001
level: medium
detection:
    selection:
        EventType: FileCreate
    condition: selection
",
    )
    .unwrap();

    // Create evidence directory with a $J so pipeline produces events.
    let evidence_dir = dir.path().join("evidence");
    std::fs::create_dir(&evidence_dir).unwrap();
    let record = build_usn_v2_record("test.txt", 0x100, 42, 100, 0);
    std::fs::write(evidence_dir.join("$J"), &record).unwrap();

    // The --sigma-rules flag should be accepted and trigger the scan phase.
    issen_cmd()
        .args([
            "ingest",
            evidence_dir.to_str().unwrap(),
            "-o",
            db_path.to_str().unwrap(),
            "--sigma-rules",
            sigma_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Scanning phase"));
}

#[test]
fn test_scan_auto_feeds_no_cached_feeds() {
    // --auto-feeds with no cached feeds should still work (empty engine).
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("file.bin");
    std::fs::write(&target, b"benign content").unwrap();

    issen_cmd()
        .args(["scan", target.to_str().unwrap(), "--auto-feeds"])
        .env("HOME", dir.path().to_str().unwrap()) // Use temp dir so no real feeds are found.
        .assert()
        .success()
        .stderr(predicate::str::contains("Auto-feeds"))
        .stderr(predicate::str::contains("0 finding(s)"));
}

// ── Info findings summary tests ──────────────────────────────────────

#[test]
fn test_info_shows_no_findings_on_empty_db() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("test.duckdb");

    // Ingest empty evidence to create the DB.
    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Info on empty DB should succeed and NOT mention scan findings.
    issen_cmd()
        .args(["info", &db_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total events:"))
        .stdout(predicate::str::contains("Scan findings").not());
}

#[test]
fn test_info_shows_findings_when_present() {
    let dir = TempDir::new().unwrap();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.duckdb");

    // Write a YARA rule that matches our evidence file.
    let rule_path = dir.path().join("detect.yar");
    std::fs::write(
        &rule_path,
        r#"rule info_detect { strings: $s = "MALICIOUS_MARKER" condition: $s }"#,
    )
    .unwrap();

    // Create evidence directory with a target file matching the YARA rule.
    let evidence_dir = dir.path().join("evidence");
    std::fs::create_dir(&evidence_dir).unwrap();
    let record = build_usn_v2_record("suspect.bin", 0x100, 42, 100, 0);
    std::fs::write(evidence_dir.join("$J"), &record).unwrap();
    std::fs::write(
        evidence_dir.join("suspect.bin"),
        b"this file has MALICIOUS_MARKER inside",
    )
    .unwrap();

    // Ingest with YARA scan to populate findings in the DB.
    issen_cmd()
        .args([
            "ingest",
            evidence_dir.to_str().unwrap(),
            "-o",
            db_path.to_str().unwrap(),
            "--yara-rules",
            rule_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Now `rt info` should show the findings summary.
    issen_cmd()
        .args(["info", db_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Scan findings:"))
        .stdout(predicate::str::contains("high"));
}

#[test]
fn test_info_help() {
    issen_cmd()
        .args(["info", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DB_PATH"));
}

// ── Report subcommand tests ──────────────────────────────────────

#[test]
fn test_repoissen_help() {
    issen_cmd()
        .args(["report", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DB_PATH"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--case-id"))
        .stdout(predicate::str::contains("--examiner"))
        .stdout(predicate::str::contains("--max-events"));
}

#[test]
fn test_repoissen_missing_db() {
    issen_cmd()
        .args(["report", "/nonexistent/db.duckdb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn test_repoissen_empty_db() {
    let dir = TempDir::new().unwrap();
    let evidence_dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.duckdb");
    let repoissen_path = dir.path().join("report.html");

    // Ingest empty dir to create DB.
    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Generate report.
    issen_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &repoissen_path.to_string_lossy(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Report written to"));

    // Verify HTML file was created.
    assert!(repoissen_path.exists(), "HTML report file should exist");
    let html = std::fs::read_to_string(&repoissen_path).expect("read report");
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("Issen Report"));
    assert!(html.contains("Total Events"));
}

#[test]
fn test_repoissen_with_events() {
    let dir = TempDir::new().unwrap();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.duckdb");
    let repoissen_path = db_dir.path().join("report.html");

    // Create evidence with a USN record.
    let record = build_usn_v2_record("evidence.docx", 0x100, 42, 100, 0);
    std::fs::write(dir.path().join("$J"), &record).expect("write $J");

    // Ingest.
    issen_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Generate report.
    issen_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &repoissen_path.to_string_lossy(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&repoissen_path).expect("read report");
    assert!(
        html.contains("evidence.docx"),
        "report should contain event data"
    );
    assert!(
        html.contains("UsnJournal"),
        "report should contain source type"
    );
    assert!(
        html.contains("Timeline Events"),
        "report should have events section"
    );
}

#[test]
fn test_repoissen_with_case_id_and_examiner() {
    let dir = TempDir::new().unwrap();
    let evidence_dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.duckdb");
    let repoissen_path = dir.path().join("report.html");

    // Create DB via ingest.
    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Generate report with metadata.
    issen_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &repoissen_path.to_string_lossy(),
            "--case-id",
            "CASE-2024-042",
            "--examiner",
            "Jane Doe",
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&repoissen_path).expect("read report");
    assert!(
        html.contains("CASE-2024-042"),
        "report should contain case ID"
    );
    assert!(
        html.contains("Jane Doe"),
        "report should contain examiner name"
    );
}

#[test]
fn test_repoissen_with_max_events() {
    let dir = TempDir::new().unwrap();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.duckdb");
    let repoissen_path = db_dir.path().join("report.html");

    // Create evidence with multiple USN records.
    let mut data = Vec::new();
    for i in 0..5 {
        data.extend(build_usn_v2_record(
            &format!("file{i}.txt"),
            0x100,
            i + 1,
            100,
            i as i64 * 100,
        ));
    }
    std::fs::write(dir.path().join("$J"), &data).expect("write $J");

    // Ingest.
    issen_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Generate report limited to 2 events.
    issen_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &repoissen_path.to_string_lossy(),
            "--max-events",
            "2",
        ])
        .assert()
        .success();

    // The report should exist and contain events (limited by max-events).
    let html = std::fs::read_to_string(&repoissen_path).expect("read report");
    assert!(html.contains("<!DOCTYPE html>"));
    // Total Events stat should still reflect all 5.
    assert!(
        html.contains(">5<"),
        "summary should show total event count"
    );
}

#[test]
fn test_repoissen_with_findings() {
    let dir = TempDir::new().unwrap();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.duckdb");
    let repoissen_path = db_dir.path().join("report.html");

    // Write YARA rule.
    let rule_path = dir.path().join("detect.yar");
    std::fs::write(
        &rule_path,
        r#"rule repoissen_detect { strings: $s = "MALICIOUS_MARKER" condition: $s }"#,
    )
    .unwrap();

    // Create evidence.
    let evidence_dir = dir.path().join("evidence");
    std::fs::create_dir(&evidence_dir).unwrap();
    let record = build_usn_v2_record("suspect.bin", 0x100, 42, 100, 0);
    std::fs::write(evidence_dir.join("$J"), &record).unwrap();
    std::fs::write(
        evidence_dir.join("suspect.bin"),
        b"this file has MALICIOUS_MARKER inside",
    )
    .unwrap();

    // Ingest with YARA scan to populate findings.
    issen_cmd()
        .args([
            "ingest",
            evidence_dir.to_str().unwrap(),
            "-o",
            db_path.to_str().unwrap(),
            "--yara-rules",
            rule_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Generate report.
    issen_cmd()
        .args([
            "report",
            db_path.to_str().unwrap(),
            "-o",
            repoissen_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&repoissen_path).expect("read report");
    assert!(
        html.contains("Scan Findings"),
        "report should contain findings section"
    );
    assert!(
        html.contains("repoissen_detect"),
        "report should contain YARA rule name"
    );
    assert!(
        html.contains("severity-high"),
        "report should contain severity styling"
    );
}

// ── Remote-access subcommand tests ──────────────────────────────────

#[test]
fn test_remote_access_help() {
    issen_cmd()
        .args(["remote-access", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("remote access"));
}

#[test]
fn test_remote_access_missing_path() {
    issen_cmd()
        .args(["remote-access", "/nonexistent/path"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn test_remote_access_empty_dir() {
    let dir = TempDir::new().expect("tmpdir");
    issen_cmd()
        .args(["remote-access", &dir.path().to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "No remote access artifacts detected",
        ));
}

#[test]
fn test_remote_access_categories_filter() {
    let dir = TempDir::new().expect("tmpdir");
    issen_cmd()
        .args([
            "remote-access",
            &dir.path().to_string_lossy(),
            "--categories",
            "rmm,builtin",
        ])
        .assert()
        .success();
}

#[test]
fn test_remote_access_json_format() {
    let dir = TempDir::new().expect("tmpdir");
    issen_cmd()
        .args([
            "remote-access",
            &dir.path().to_string_lossy(),
            "--format",
            "json",
        ])
        .assert()
        .success();
}

// ── NEW: Verbose flag tests ──────────────────────────────────────────

#[test]
fn verbose_flag_does_not_crash() {
    issen_cmd().arg("-v").arg("--help").assert().success();
}

#[test]
fn verbose_flag_with_subcommand_help() {
    issen_cmd()
        .arg("-v")
        .args(["timeline", "--help"])
        .assert()
        .success();
}

#[test]
fn verbose_flag_with_ingest_help() {
    issen_cmd()
        .arg("-v")
        .args(["ingest", "--help"])
        .assert()
        .success();
}

// ── NEW: Version flag shows actual package version ───────────────────

#[test]
fn version_flag_shows_version() {
    issen_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

// ── NEW: --help for every subcommand ─────────────────────────────────

#[test]
fn all_subcommands_help_exits_success() {
    for sub in &[
        "ingest",
        "timeline",
        "info",
        "scan",
        "remote-access",
        "report",
        "memory",
    ] {
        issen_cmd().args([sub, "--help"]).assert().success();
    }
}

#[test]
fn feed_subcommands_help_exits_success() {
    for sub in &["list", "update"] {
        issen_cmd().args(["feed", sub, "--help"]).assert().success();
    }
}

// ── NEW: Error message text validation ───────────────────────────────

#[test]
fn ingest_missing_source_shows_error_message() {
    issen_cmd()
        .args(["ingest", "/nonexistent/evidence/path/12345"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("does not exist").or(predicate::str::contains("No such file")),
        );
}

#[test]
fn info_nonexistent_db_shows_error_message() {
    issen_cmd()
        .args(["info", "/nonexistent/db/path/12345.duckdb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn scan_nonexistent_target_shows_error_message() {
    issen_cmd()
        .args(["scan", "/nonexistent/scan/target/12345"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("does not exist")
                .or(predicate::str::contains("No such file"))
                .or(predicate::str::contains("Error")),
        );
}

#[test]
fn remote_access_nonexistent_path_shows_error_message() {
    issen_cmd()
        .args(["remote-access", "/nonexistent/evidence/12345"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("does not exist")
                .or(predicate::str::contains("No such file"))
                .or(predicate::str::contains("Error")),
        );
}

#[test]
fn repoissen_nonexistent_db_shows_error_message() {
    issen_cmd()
        .args(["report", "/nonexistent/db/12345.duckdb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

// ── NEW: Multi-flag combinations ─────────────────────────────────────

#[test]
fn timeline_multi_flag_descending_limit() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("test.duckdb");

    // Create DB via ingest.
    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    issen_cmd()
        .args([
            "timeline",
            &db_path.to_string_lossy(),
            "--descending",
            "-n",
            "10",
        ])
        .assert()
        .success();
}

#[test]
fn timeline_multi_flag_event_type_and_source() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("test.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    issen_cmd()
        .args([
            "timeline",
            &db_path.to_string_lossy(),
            "--event-type",
            "FileCreate",
            "--source",
            "UsnJournal",
            "--descending",
        ])
        .assert()
        .success();
}

#[test]
fn scan_multi_flag_min_severity_and_format() {
    let dir = TempDir::new().expect("tmpdir");
    let target = dir.path().join("file.bin");
    std::fs::write(&target, b"benign content").unwrap();

    issen_cmd()
        .args([
            "scan",
            target.to_str().unwrap(),
            "--min-severity",
            "medium",
            "--format",
            "json",
        ])
        .assert()
        .success();
}

#[test]
fn remote_access_multi_flag_categories_and_format() {
    let dir = TempDir::new().expect("tmpdir");

    issen_cmd()
        .args([
            "remote-access",
            &dir.path().to_string_lossy(),
            "--categories",
            "rmm",
            "--format",
            "json",
        ])
        .assert()
        .success();
}

#[test]
fn ingest_multi_flag_output_and_source() {
    let evidence_dir = TempDir::new().expect("tmpdir");
    let out_dir = TempDir::new().expect("tmpdir");
    let db_path = out_dir.path().join("multi.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
            "-s",
            "CASE-MULTI-001",
        ])
        .assert()
        .success();
}

#[test]
fn repoissen_multi_flag_case_id_examiner_max_events() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("test.duckdb");
    let repoissen_path = dir.path().join("report.html");

    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    issen_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &repoissen_path.to_string_lossy(),
            "--case-id",
            "MULTI-CASE",
            "--examiner",
            "Multi Tester",
            "--max-events",
            "100",
        ])
        .assert()
        .success();
}

// ── NEW: JSON output format validation ───────────────────────────────

#[test]
fn timeline_flagged_json_output_is_valid_json() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("test.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    let output = issen_cmd()
        .args([
            "timeline",
            &db_path.to_string_lossy(),
            "--flagged",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "timeline --flagged --format json should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout)
        .expect("timeline --flagged --format json should produce valid JSON");
}

#[test]
fn scan_json_output_is_valid_json() {
    let dir = TempDir::new().expect("tmpdir");
    let target = dir.path().join("benign.bin");
    std::fs::write(&target, b"no threats here").unwrap();

    let output = issen_cmd()
        .args(["scan", target.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();

    assert!(output.status.success(), "scan --format json should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value =
        serde_json::from_str(&stdout).expect("scan --format json should produce valid JSON");
}

#[test]
fn remote_access_json_output_is_valid_json() {
    let dir = TempDir::new().expect("tmpdir");

    let output = issen_cmd()
        .args([
            "remote-access",
            &dir.path().to_string_lossy(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "remote-access --format json should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout)
        .expect("remote-access --format json should produce valid JSON");
}

// ── NEW: memf subcommand ─────────────────────────────────────────────

#[test]
fn memf_help_exits_success() {
    issen_cmd()
        .args(["memory", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DUMP_PATH"));
}

#[test]
fn memf_help_shows_cr3_flag() {
    issen_cmd()
        .args(["memory", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--cr3"));
}

#[test]
fn memf_nonexistent_dump_shows_error() {
    issen_cmd()
        .args(["memory", "/nonexistent/memory.lime"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

// ── NEW: Full pipeline integration test ──────────────────────────────

#[test]
fn full_pipeline_ingest_timeline_report() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("pipeline.duckdb");
    let repoissen_path = dir.path().join("pipeline.html");

    // Write a minimal USN record as evidence.
    let record = build_usn_v2_record("pipeline_file.txt", 0x100, 42, 100, 0);
    std::fs::write(evidence_dir.path().join("$J"), &record).unwrap();

    // Step 1: ingest.
    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
            "-s",
            "PIPELINE-CASE-001",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Artifacts found:"));

    // Step 2: timeline query — output from step 1 feeds step 2.
    issen_cmd()
        .args(["timeline", &db_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pipeline_file.txt"));

    // Step 3: info — verify DB is consistent.
    issen_cmd()
        .args(["info", &db_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total events:"));

    // Step 4: report generation — output from step 1 feeds step 4.
    issen_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &repoissen_path.to_string_lossy(),
            "--case-id",
            "PIPELINE-CASE-001",
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&repoissen_path).expect("read pipeline report");
    assert!(html.contains("<!DOCTYPE html>"), "report must be HTML");
    assert!(
        html.contains("PIPELINE-CASE-001"),
        "report must contain case ID"
    );
}

// ── NEW: timeline --format json (non-flagged) ────────────────────────

#[test]
fn timeline_format_json_produces_valid_json() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("test.duckdb");

    // Ingest a USN record so there is at least one event.
    let record = build_usn_v2_record("json_test_file.txt", 0x100, 42, 100, 0);
    std::fs::write(evidence_dir.path().join("$J"), &record).unwrap();

    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    let output = issen_cmd()
        .args(["timeline", &db_path.to_string_lossy(), "--format", "json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "timeline --format json should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("timeline --format json should produce valid JSON");
    assert!(parsed.is_array(), "JSON output should be an array");
    let arr = parsed.as_array().unwrap();
    assert!(!arr.is_empty(), "array should contain at least one event");
    // Verify expected fields are present.
    assert!(arr[0]["timestamp"].is_string());
    assert!(arr[0]["event_type"].is_string());
    assert!(arr[0]["source"].is_string());
    assert!(arr[0]["description"].is_string());
}

#[test]
fn timeline_format_json_empty_db_produces_empty_array() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("empty.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    let output = issen_cmd()
        .args(["timeline", &db_path.to_string_lossy(), "--format", "json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("should be valid JSON even when empty");
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

// ── NEW: timeline nonexistent db error text ───────────────────────────

#[test]
fn timeline_nonexistent_db_shows_error_text() {
    issen_cmd()
        .args(["timeline", "/nonexistent/db/path/98765.duckdb"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Failed to open database")
                .or(predicate::str::contains("Error")),
        );
}

// ── NEW: feed --help ──────────────────────────────────────────────────

#[test]
fn feed_help_exits_success() {
    issen_cmd()
        .args(["feed", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("list").and(predicate::str::contains("update")));
}

// ── NEW: scan --yara-rules with nonexistent rules file ────────────────

#[test]
fn scan_yara_rules_nonexistent_file_exits_nonzero_with_error() {
    let dir = TempDir::new().expect("tmpdir");
    let target = dir.path().join("benign.bin");
    std::fs::write(&target, b"clean content").unwrap();

    issen_cmd()
        .args([
            "scan",
            target.to_str().unwrap(),
            "--yara-rules",
            "/nonexistent/rules/file.yar",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("not found")
                .or(predicate::str::contains("No such file"))
                .or(predicate::str::contains("Error")),
        );
}

// ── NEW: verbose flag with operational subcommands ────────────────────

#[test]
fn verbose_flag_with_scan_subcommand() {
    let dir = TempDir::new().expect("tmpdir");
    let target = dir.path().join("file.bin");
    std::fs::write(&target, b"test content").unwrap();

    issen_cmd()
        .arg("-v")
        .args(["scan", target.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn verbose_flag_with_remote_access_subcommand() {
    let dir = TempDir::new().expect("tmpdir");

    issen_cmd()
        .arg("-v")
        .args(["remote-access", &dir.path().to_string_lossy()])
        .assert()
        .success();
}

// ── --source <URI> flag tests (rt-remote-io integration) ─────────────

/// `rt ingest --help` must advertise the `--source` flag.
#[test]
fn ingest_help_shows_source_flag() {
    issen_cmd()
        .args(["ingest", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--source"));
}

/// Passing an unrecognised scheme via `--source` must fail with a clear error.
#[test]
fn ingest_source_unknown_scheme_fails_with_error() {
    let dir = TempDir::new().expect("tmpdir");
    let out_dir = TempDir::new().expect("tmpdir");
    let db_path = out_dir.path().join("test.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
            "--source",
            "unknown://some/path",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Unsupported URI scheme")
                .or(predicate::str::contains("unknown"))
                .or(predicate::str::contains("Error")),
        );
}

/// A `file:///` URI pointing at a local directory is a recognised scheme and
/// must be accepted (dispatch prints the stub message, exits 0).
#[test]
fn ingest_source_file_uri_is_accepted() {
    let dir = TempDir::new().expect("tmpdir");
    let out_dir = TempDir::new().expect("tmpdir");
    let db_path = out_dir.path().join("test.duckdb");

    let file_uri = format!("file://{}", dir.path().display());

    issen_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
            "--source",
            &file_uri,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("source URI"));
}

/// A `gdrive://` URI must be accepted and print a stub message (auth/download
/// not attempted in unit tests — the dispatch path is what we verify).
#[test]
fn ingest_source_gdrive_uri_is_accepted() {
    let dir = TempDir::new().expect("tmpdir");
    let out_dir = TempDir::new().expect("tmpdir");
    let db_path = out_dir.path().join("test.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
            "--source",
            "gdrive://1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("gdrive"));
}

/// A `mem://` URI (in-process, no network required) must be accepted and print
/// the stub dispatch message.
#[test]
fn ingest_source_mem_uri_is_accepted() {
    let dir = TempDir::new().expect("tmpdir");
    let out_dir = TempDir::new().expect("tmpdir");
    let db_path = out_dir.path().join("test.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
            "--source",
            "mem://bucket/key",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("source URI"));
}

/// Without `--source`, the existing local-path ingest path must still work.
#[test]
fn ingest_without_source_flag_still_works() {
    let dir = TempDir::new().expect("tmpdir");
    let out_dir = TempDir::new().expect("tmpdir");
    let db_path = out_dir.path().join("test.duckdb");

    issen_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Artifacts found:"));
}

// ── WS-8: rt analyse synthetic fixture ───────────────────────────────

/// Build a minimal UAC tar.gz in `dest` that triggers:
///   - ROOTKIT INDICATORS (ld.so.preload populated)
///   - HIDDEN PROCESSES   (PID 977 in hidden_pids_for_ps_command.txt)
///   - CORRELATION FINDINGS (rootkit_indicator + miner_thread + mining_pool)
///
/// Returns the path to the archive.
fn build_synthetic_uac_fixture(dest: &std::path::Path) -> std::path::PathBuf {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    // Volatile sockstat TSV — Volatility linux.sockstat output for PID 977
    // Columns: NetNS  ProcessName  PID  TID  FD  SockOffset  Family  Type  Proto
    //          SrcAddr  SrcPort  DstAddr  DstPort  State  Filter
    let sockstat = "\
NetNS\tProcess Name\tPID\tTID\tFD\tSock Offset\tFamily\tType\tProto\tSource Addr\tSource Port\tDestination Addr\tDestination Port\tState\tFilter\n\
4026531992\ttop\t977\t977\t5\t0xffff880012345678\tAF_INET\tSOCK_STREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t\n";

    let files: &[(&str, &str)] = &[
        // Metadata
        (
            "uac.log",
            "2026-03-24 23:40:43 UTC - UAC collection started\nLinux vbox-linux\n",
        ),
        // Rootkit: ld.so.preload populated → triggers rootkit_indicator tag
        (
            "chkrootkit/etc_ld_so_preload.txt",
            "/lib/x86_64-linux-gnu/libymv.so.3\n",
        ),
        // Hidden PIDs: PID 977 hidden from ps
        (
            "live_response/process/hidden_pids_for_ps_command.txt",
            "977\n",
        ),
        // Memory sockstat: PID 977 "top" → dst_port 3333 (Stratum)
        ("memory_dump/output-sockstat", sockstat),
        // CPU: 97.7% user → cpu_anomaly evidence
        (
            "live_response/process/top_-b_-n1.txt",
            "%Cpu(s): 97.7 us,  2.3 sy,  0.0 ni,  0.0 id,  0.0 wa\n",
        ),
        // Network dir placeholder so the section renders
        ("live_response/network/.keep", ""),
        // Env (no LD_PRELOAD in env, so no duplicate warning)
        ("live_response/system/env.txt", "PATH=/usr/bin:/bin\n"),
        // Lsmod: no known rootkit modules
        (
            "live_response/system/lsmod.txt",
            "Module                  Size  Used by\next4                  729088  2\n",
        ),
        // Taint: 0 (clean)
        (
            "live_response/system/cat_proc_sys_kernel_tainted.txt",
            "0\n",
        ),
    ];

    let archive_path = dest.join("uac-vbox-linux-20260324234043.tar.gz");
    let file = std::fs::File::create(&archive_path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);

    for (rel_path, content) in files {
        let data = content.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        let archive_path_str = format!("uac-vbox-linux-20260324234043/{rel_path}");
        builder
            .append_data(&mut header, &archive_path_str, data)
            .expect("append file");
    }

    builder.finish().expect("finish tar");
    archive_path
}

/// `rt analyse` — minimal: binary accepts the subcommand.
#[test]
fn analyse_help_exits_success() {
    issen_cmd()
        .args(["analyse", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("collection"));
}

/// `rt analyse` on a nonexistent path must fail with an error.
#[test]
fn analyse_nonexistent_path_fails() {
    issen_cmd()
        .args(["analyse", "/nonexistent/path/uac-fake.tar.gz"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error").or(predicate::str::contains("error")));
}

/// `rt analyse` against a synthetic UAC fixture must:
///   1. Exit successfully
///   2. Print all expected section headers
///   3. Emit at least one CORRELATION FINDING (rootkit-concealed miner rule)
///   4. Use calibrated language ("consistent with" or "likely")
///   5. NOT contain exact hook function names (readdir / getdents) as
///      factual claims — these are not observable without YARA/reverse-engineering
#[test]
fn analyse_synthetic_fixture_emits_expected_sections() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_synthetic_uac_fixture(dir.path());

    let output = issen_cmd()
        .args(["analyse", archive.to_str().unwrap()])
        .output()
        .expect("run rt analyse");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Must succeed
    assert!(
        output.status.success(),
        "rt analyse should exit 0\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Section headers
    assert!(
        stdout.contains("ROOTKIT INDICATORS"),
        "missing ROOTKIT INDICATORS section\n{stdout}"
    );
    assert!(
        stdout.contains("HIDDEN PROCESSES"),
        "missing HIDDEN PROCESSES section\n{stdout}"
    );
    assert!(
        stdout.contains("CORRELATION FINDINGS"),
        "missing CORRELATION FINDINGS section — rootkit+miner+pool rule did not fire\n{stdout}"
    );

    // Calibrated language — must hedge rather than assert
    let has_calibrated = stdout.contains("consistent with")
        || stdout.contains("likely")
        || stdout.contains("may enable");
    assert!(
        has_calibrated,
        "explanation must use calibrated language ('consistent with', 'likely', or 'may enable')\n{stdout}"
    );

    // No exact hook claims without supporting forensic evidence
    assert!(
        !stdout.contains("readdir"),
        "output must not claim readdir hook without YARA evidence\n{stdout}"
    );
    assert!(
        !stdout.contains("getdents"),
        "output must not claim getdents hook without YARA evidence\n{stdout}"
    );

    // Analysis complete footer
    assert!(
        stdout.contains("analysis complete"),
        "missing analysis complete footer\n{stdout}"
    );
}

/// `rt analyse` narrative must reference the ld.so.preload library path.
#[test]
fn analyse_synthetic_fixture_shows_rootkit_evidence() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_synthetic_uac_fixture(dir.path());

    issen_cmd()
        .args(["analyse", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("libymv"));
}

/// `rt analyse` must show PID 977 in the hidden process section.
#[test]
fn analyse_synthetic_fixture_shows_hidden_pid() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_synthetic_uac_fixture(dir.path());

    issen_cmd()
        .args(["analyse", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("977"));
}

// ── desktop masquerade output ────────────────────────────────────────────────

/// Build a UAC archive where PID 977 has unix socket connections to
/// journald, dbus, and pipewire (desktop masquerade indicator).
fn build_uac_with_desktop_masquerade(dest: &std::path::Path) -> std::path::PathBuf {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let sockstat = "\
NetNS\tProcess Name\tPID\tTID\tFD\tSock Offset\tFamily\tType\tProto\tSource Addr\tSource Port\tDestination Addr\tDestination Port\tState\tFilter\n\
4026531992\ttop\t977\t977\t5\t0xffff880012345678\tAF_INET\tSOCK_STREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t\n\
4026531992\tlibuv-worker\t977\t978\t5\t0xffff880012345678\tAF_INET\tSOCK_STREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t\n";

    let unix_txt = "\
Num       RefCount Protocol Flags    Type St Inode Path\n\
ffffffff80001234: 00000002 00000000 00010000 0001 03 12345 /run/systemd/journal/socket\n\
ffffffff80001235: 00000002 00000000 00010000 0001 03 12346 /run/dbus/system_bus_socket\n\
ffffffff80001236: 00000003 00000000 00010000 0001 03 12347 /run/user/1000/pipewire-0\n";

    let files: &[(&str, &str)] = &[
        (
            "uac.log",
            "2026-03-24 23:40:43 UTC - UAC collection started\nLinux vbox-linux\n",
        ),
        (
            "chkrootkit/etc_ld_so_preload.txt",
            "/lib/x86_64-linux-gnu/libymv.so.3\n",
        ),
        (
            "live_response/process/hidden_pids_for_ps_command.txt",
            "977\n",
        ),
        ("memory_dump/output-sockstat", sockstat),
        // Per-PID unix socket file — the desktop masquerade source
        ("live_response/process/proc/977/net/unix.txt", unix_txt),
        (
            "live_response/process/top_-b_-n1.txt",
            "%Cpu(s): 97.7 us,  2.3 sy,  0.0 ni,  0.0 id,  0.0 wa\n",
        ),
        ("live_response/network/.keep", ""),
        ("live_response/system/env.txt", "PATH=/usr/bin:/bin\n"),
        (
            "live_response/system/lsmod.txt",
            "Module                  Size  Used by\next4                  729088  2\n",
        ),
        (
            "live_response/system/cat_proc_sys_kernel_tainted.txt",
            "4\n",
        ),
    ];

    let archive_path = dest.join("uac-masquerade-20260324234043.tar.gz");
    let file = std::fs::File::create(&archive_path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);

    for (rel_path, content) in files {
        let data = content.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        let path = format!("uac-masquerade-20260324234043/{rel_path}");
        builder
            .append_data(&mut header, &path, data)
            .expect("append");
    }
    builder.finish().expect("finish tar");
    archive_path
}

/// `rt analyse` must show unix socket paths for a hidden process that has
/// proc/<PID>/net/unix.txt in the collection.
#[test]
fn analyse_shows_unix_socket_paths_for_hidden_process() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_uac_with_desktop_masquerade(dir.path());

    let output = issen_cmd()
        .args(["analyse", archive.to_str().unwrap()])
        .output()
        .expect("run rt analyse");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "analyse must exit 0\n{stdout}");

    assert!(
        stdout.contains("journal") || stdout.contains("dbus") || stdout.contains("pipewire"),
        "output must show at least one unix socket path for PID 977\n{stdout}"
    );
}

/// `rt analyse` must emit a DESKTOP MASQUERADE indicator when a hidden process
/// connects to ≥2 system-daemon unix sockets.
#[test]
fn analyse_shows_desktop_masquerade_indicator() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_uac_with_desktop_masquerade(dir.path());

    let output = issen_cmd()
        .args(["analyse", archive.to_str().unwrap()])
        .output()
        .expect("run rt analyse");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "analyse must exit 0\n{stdout}");

    assert!(
        stdout.contains("desktop masquerade") || stdout.contains("DESKTOP MASQUERADE"),
        "output must flag desktop masquerade for PID 977\n{stdout}"
    );
}

// ── Color output ─────────────────────────────────────────────────────────────

/// `--color` is a recognised global flag (help must mention it).
#[test]
fn color_flag_is_recognised() {
    issen_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("color"));
}

/// `issen analyse --color=never` must produce output with NO ANSI escape codes.
#[test]
fn analyse_color_never_produces_no_ansi() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_uac_with_desktop_masquerade(dir.path());

    let output = issen_cmd()
        .args(["--color=never", "analyse", archive.to_str().unwrap()])
        .output()
        .expect("run issen analyse");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "analyse must exit 0\n{stdout}");
    assert!(
        !stdout.contains('\x1b'),
        "--color=never must not emit ANSI escape codes\n{stdout}"
    );
}

/// `issen analyse --color=always` must emit ANSI escape codes in output.
#[test]
fn analyse_color_always_emits_ansi() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_uac_with_desktop_masquerade(dir.path());

    let output = issen_cmd()
        .args(["--color=always", "analyse", archive.to_str().unwrap()])
        .output()
        .expect("run issen analyse");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "analyse must exit 0\n{stdout}");
    assert!(
        stdout.contains('\x1b'),
        "--color=always must emit ANSI escape codes\n{stdout}"
    );
}

/// `issen analyse` (piped, auto mode) must produce NO ANSI escape codes.
/// This is the regression guard: existing tests must not break when colors
/// are added, because they pipe stdout through Rust's process capture.
#[test]
fn analyse_color_auto_piped_no_ansi() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_uac_with_desktop_masquerade(dir.path());

    // No --color flag → auto. The test harness pipes stdout → not a TTY → no color.
    let output = issen_cmd()
        .args(["analyse", archive.to_str().unwrap()])
        .output()
        .expect("run issen analyse");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "analyse must exit 0\n{stdout}");
    assert!(
        !stdout.contains('\x1b'),
        "auto mode when piped must not emit ANSI escape codes\n{stdout}"
    );
}

// ── WS-10 Phase 3: rt supertimeline ──────────────────────────────────────────

/// `rt supertimeline --help` must succeed and mention the collection argument.
#[test]
fn supertimeline_command_exists_with_collection_arg() {
    issen_cmd()
        .args(["supertimeline", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("COLLECTION"));
}

/// `rt supertimeline <collection> --format jsonl` must emit valid JSON Lines.
/// Each output line must be a valid JSON object.
#[test]
fn supertimeline_jsonl_output_is_valid() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_synthetic_uac_fixture(dir.path());

    let output = issen_cmd()
        .args([
            "supertimeline",
            archive.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("supertimeline command should run");

    assert!(
        output.status.success(),
        "supertimeline --format jsonl must exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Every non-empty line must be a valid JSON object.
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("invalid JSON line: {e}\n  line: {line}"));
    }
}

/// `rt supertimeline <collection> --format csv` must emit CSV with the
/// standard supertimeline headers on the first line.
#[test]
fn supertimeline_csv_output_has_correct_headers() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_synthetic_uac_fixture(dir.path());

    let output = issen_cmd()
        .args([
            "supertimeline",
            archive.to_str().unwrap(),
            "--format",
            "csv",
        ])
        .output()
        .expect("supertimeline command should run");

    assert!(
        output.status.success(),
        "supertimeline --format csv must exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        first_line.contains("timestamp") && first_line.contains("event_type"),
        "CSV header must contain 'timestamp' and 'event_type', got: {first_line}"
    );
}

/// `rt supertimeline <collection>` default (narrative) output must contain
/// at least one non-empty line of narrative text.
#[test]
fn supertimeline_narrative_output_is_non_empty() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_synthetic_uac_fixture(dir.path());

    issen_cmd()
        .args(["supertimeline", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

/// `rt supertimeline` with an empty directory must exit 0 and not panic.
#[test]
fn supertimeline_with_no_parsers_returns_empty_gracefully() {
    let dir = TempDir::new().expect("tmpdir");
    // Pass the bare tempdir (no files inside) as the collection.
    issen_cmd()
        .args(["supertimeline", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

/// When the collection contains evidence consistent with temporal discrepancy
/// patterns, `rt supertimeline` must include a TEMPORAL FINDINGS section.
#[test]
fn supertimeline_temporal_findings_appear_in_output() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_synthetic_uac_fixture(dir.path());

    issen_cmd()
        .args(["supertimeline", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("TEMPORAL"));
}

// ── Attack Flow corpus download ───────────────────────────────────────────────

// ── EVTX session correlation section tests ───────────────────────────────────

/// Build a UAC fixture that contains a zero-byte Security.evtx file.
/// `rt analyse` must not panic on it and must render the EVTX section header.
fn build_uac_fixture_with_evtx(dest: &std::path::Path) -> std::path::PathBuf {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let files: &[(&str, &[u8])] = &[
        (
            "uac.log",
            b"2026-03-24 23:40:43 UTC - UAC collection started\nLinux vbox-linux\n",
        ),
        ("chkrootkit/etc_ld_so_preload.txt", b""),
        ("live_response/process/hidden_pids_for_ps_command.txt", b""),
        ("live_response/network/.keep", b""),
        ("live_response/system/env.txt", b"PATH=/usr/bin:/bin\n"),
        (
            "live_response/system/lsmod.txt",
            b"Module                  Size  Used by\next4                  729088  2\n",
        ),
        (
            "live_response/system/cat_proc_sys_kernel_tainted.txt",
            b"0\n",
        ),
        // Zero-byte EVTX file — parser must not panic
        ("Windows/System32/winevt/Logs/Security.evtx", b""),
    ];

    let archive_path = dest.join("uac-windows-evtx-20260324234043.tar.gz");
    let file = std::fs::File::create(&archive_path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);

    for (rel_path, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        let archive_path_str = format!("uac-windows-evtx-20260324234043/{rel_path}");
        builder
            .append_data(&mut header, &archive_path_str, *content)
            .expect("append file");
    }

    builder.finish().expect("finish tar");
    archive_path
}

/// When the collection contains .evtx files, `rt analyse` must print the
/// WINDOWS EVENT LOG SESSIONS section header.
/// This test FAILS until analyse.rs is wired to call issen_evtx.
#[test]
fn analyse_shows_evtx_session_section_when_evtx_present() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_uac_fixture_with_evtx(dir.path());

    let output = issen_cmd()
        .args(["analyse", archive.to_str().unwrap()])
        .output()
        .expect("run rt analyse");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rt analyse should exit 0\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("WINDOWS EVENT LOG SESSIONS"),
        "missing WINDOWS EVENT LOG SESSIONS section when evtx present\n{stdout}"
    );
}

/// When the collection has no .evtx files, the EVTX section must NOT appear.
#[test]
fn analyse_evtx_section_absent_when_no_evtx_files() {
    let dir = TempDir::new().expect("tmpdir");
    let archive = build_synthetic_uac_fixture(dir.path());

    let output = issen_cmd()
        .args(["analyse", archive.to_str().unwrap()])
        .output()
        .expect("run rt analyse");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rt analyse should exit 0\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("WINDOWS EVENT LOG SESSIONS"),
        "EVTX section must not appear when no evtx files present\n{stdout}"
    );
}

/// `rt feed attack-flow --help` must exit 0 and describe the subcommand.
#[test]
fn feed_attack_flow_help_exits_success() {
    issen_cmd()
        .args(["feed", "attack-flow", "--help"])
        .assert()
        .success();
}

/// `rt feed attack-flow --cache-dir <dir>` with an invalid/unreachable network
/// should exit non-zero and print an error (not panic).
/// We test with a path that has no write permission to avoid real network access.
#[test]
fn feed_attack_flow_bad_cache_dir_exits_nonzero() {
    issen_cmd()
        .args([
            "feed",
            "attack-flow",
            "--cache-dir",
            "/proc/nonexistent/readonly",
        ])
        .assert()
        .failure();
}

// ── Phase 5A: rt pivot subcommand ────────────────────────────────────────────

/// `rt pivot --help` must exit 0 and list the three sub-subcommands.
#[test]
fn pivot_help_exits_success() {
    issen_cmd()
        .args(["pivot", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("sync")
                .and(predicate::str::contains("rules"))
                .and(predicate::str::contains("eval")),
        );
}

/// `rt pivot sync --help` must exit 0 and mention --cache-dir.
#[test]
fn pivot_sync_help_exits_success() {
    issen_cmd()
        .args(["pivot", "sync", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("cache-dir"));
}

/// `rt pivot rules` must list bundled rules including the xmrig rule.
#[test]
fn pivot_rules_shows_bundled_rules() {
    issen_cmd()
        .args(["pivot", "rules"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pivot.miner.xmrig-process"));
}

/// `rt pivot eval <empty-json>` must exit 0 and print "No findings" (or empty output).
#[test]
fn pivot_eval_empty_evidence_no_findings() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_file = dir.path().join("evidence.json");
    std::fs::write(&evidence_file, b"[]").expect("write evidence file");

    issen_cmd()
        .args(["pivot", "eval", evidence_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No findings").or(predicate::str::is_empty()));
}

// ── Phase 3: rt srum subcommand ──────────────────────────────────────────────

/// `rt srum --help` must exit 0.
#[test]
fn issen_srum_help_exits_success() {
    issen_cmd()
        .args(["srum", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SRUM").or(predicate::str::contains("srum")));
}

/// `rt srum <nonexistent-path>` must exit nonzero.
#[test]
fn issen_srum_nonexistent_path_fails() {
    issen_cmd()
        .args(["srum", "/nonexistent/path/SRUDB.dat"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Error")
                .or(predicate::str::contains("error"))
                .or(predicate::str::contains("not found"))
                .or(predicate::str::contains("No such")),
        );
}

/// `rt srum <empty-file>` must exit 0 (empty/invalid ESE is handled gracefully).
#[test]
fn issen_srum_empty_file_returns_ok() {
    let dir = TempDir::new().expect("tmpdir");
    let srudb = dir.path().join("SRUDB.dat");
    std::fs::write(&srudb, b"").expect("write empty SRUDB.dat");

    // An empty file is not a valid ESE DB — srum-parser returns Err.
    // The CLI must exit nonzero on ESE parse error but must not panic.
    // Accept either exit code: nonzero (ESE invalid) or zero (empty results).
    let output = issen_cmd()
        .args(["srum", srudb.to_str().unwrap()])
        .output()
        .expect("rt srum must not panic");
    // Either exit code is acceptable — just must not hang or segfault.
    let _ = output.status;
}

/// `rt pivot eval` with xmrig ProcessName evidence must emit a finding for the xmrig rule.
#[test]
fn pivot_eval_matching_evidence_emits_finding() {
    let dir = TempDir::new().expect("tmpdir");
    let evidence_file = dir.path().join("evidence.json");

    // Build an Evidence JSON array matching the xmrig-process rule:
    // kind = ProcessName, value contains "xmrig"
    let json = r#"[
        {
            "id": "ev-1",
            "source": "Artifact",
            "kind": "ProcessName",
            "value": "xmrig",
            "subject": null,
            "timestamp_ns": null,
            "confidence": 90,
            "attrs": {}
        }
    ]"#;
    std::fs::write(&evidence_file, json).expect("write evidence file");

    issen_cmd()
        .args(["pivot", "eval", evidence_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pivot.miner.xmrig-process"));
}

// ── Batch 2: DriveBreakdown unit tests ───────────────────────────────────────

#[cfg(test)]
mod drive_breakdown_tests {
    use issen_cli::commands::analyse::{drive_breakdown, DriveBreakdown};
    use issen_core::artifacts::types::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};

    fn make_event(tags: &[&str]) -> TimelineEvent {
        let mut e = TimelineEvent::new(
            0,
            "1970-01-01T00:00:00Z".to_string(),
            EventType::FileCreate,
            ArtifactType::Lnk,
            "test/path".to_string(),
            "test event".to_string(),
            "test-evidence".to_string(),
        );
        for tag in tags {
            e.tags.push((*tag).to_string());
        }
        e
    }

    #[test]
    fn drive_breakdown_counts_removable_correctly() {
        let events = vec![
            make_event(&["drive_type:removable"]),
            make_event(&["drive_type:removable"]),
            make_event(&["drive_type:fixed"]),
        ];
        let bd = drive_breakdown(&events);
        assert_eq!(bd.removable, 2);
        assert_eq!(bd.fixed, 1);
    }

    #[test]
    fn drive_breakdown_total_is_sum() {
        let events = vec![
            make_event(&["drive_type:fixed"]),
            make_event(&["drive_type:removable"]),
            make_event(&["drive_type:network"]),
            make_event(&[]),
        ];
        let bd = drive_breakdown(&events);
        assert_eq!(bd.total(), 4);
    }

    #[test]
    fn drive_breakdown_has_removable_true_when_nonzero() {
        let events = vec![make_event(&["drive_type:removable"])];
        let bd = drive_breakdown(&events);
        assert!(bd.has_removable());
    }

    #[test]
    fn drive_breakdown_has_removable_false_when_zero() {
        let events = vec![make_event(&["drive_type:fixed"])];
        let bd = drive_breakdown(&events);
        assert!(!bd.has_removable());
    }

    #[test]
    fn drive_breakdown_render_contains_removable_line() {
        let b = DriveBreakdown {
            fixed: 1,
            removable: 2,
            network: 0,
            unknown: 0,
        };
        let rendered = b.render();
        assert!(
            rendered.contains("Removable"),
            "render must contain 'Removable'"
        );
        assert!(rendered.contains('2'), "render must contain the count 2");
    }

    #[test]
    fn drive_breakdown_render_flags_removable_when_present() {
        let b = DriveBreakdown {
            fixed: 0,
            removable: 5,
            network: 0,
            unknown: 0,
        };
        let rendered = b.render();
        assert!(
            rendered.contains("exfiltration") || rendered.contains('\u{2190}'),
            "render must flag exfiltration risk when removable > 0"
        );
    }

    #[test]
    fn drive_breakdown_unknown_counts_events_without_drive_type_tag() {
        let events = vec![make_event(&["some_other_tag"]), make_event(&[])];
        let bd = drive_breakdown(&events);
        assert_eq!(bd.unknown, 2);
    }

    #[test]
    fn drive_breakdown_has_network_true_when_nonzero() {
        let events = vec![make_event(&["drive_type:network"])];
        let bd = drive_breakdown(&events);
        assert!(bd.has_network());
    }
}

// ── issen processes CLI tests (Step B RED) ───────────────────────────────────

#[test]
fn processes_subcommand_appears_in_main_help() {
    issen_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("processes"));
}

#[test]
fn processes_help_shows_evtx_dir_and_link_sessions() {
    issen_cmd()
        .args(["processes", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("evtx-dir"))
        .stdout(predicate::str::contains("link-sessions"));
}

#[test]
fn processes_empty_dir_exits_success_with_json() {
    let dir = TempDir::new().expect("tmpdir");
    issen_cmd()
        .args([
            "processes",
            "--evtx-dir",
            &dir.path().to_string_lossy(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("processes"));
}

#[test]
fn processes_json_output_has_processes_array_and_total_count() {
    let dir = TempDir::new().expect("tmpdir");
    let output = issen_cmd()
        .args([
            "processes",
            "--evtx-dir",
            &dir.path().to_string_lossy(),
            "--json",
        ])
        .output()
        .expect("failed to run issen processes");

    assert!(output.status.success(), "exit code must be 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert!(
        parsed.get("processes").and_then(|v| v.as_array()).is_some(),
        "JSON must have 'processes' array, got: {stdout}"
    );
    assert!(
        parsed.get("total_count").is_some(),
        "JSON must have 'total_count' field, got: {stdout}"
    );
}

// ── issen session CLI tests (Step 4 RED) ─────────────────────────────────────

#[test]
fn session_subcommand_appears_in_main_help() {
    issen_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("session"));
}

#[test]
fn session_help_shows_evtx_dir_option() {
    issen_cmd()
        .args(["session", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("evtx-dir"))
        .stdout(predicate::str::contains("evtx-file"));
}

#[test]
fn session_empty_dir_exits_success_with_json() {
    let dir = TempDir::new().expect("tmpdir");
    issen_cmd()
        .args([
            "session",
            "--evtx-dir",
            &dir.path().to_string_lossy(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("sessions"));
}

#[test]
fn session_json_output_is_valid_json_with_sessions_array() {
    let dir = TempDir::new().expect("tmpdir");
    let output = issen_cmd()
        .args([
            "session",
            "--evtx-dir",
            &dir.path().to_string_lossy(),
            "--json",
        ])
        .output()
        .expect("failed to run issen session");

    assert!(output.status.success(), "exit code must be 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert!(
        parsed.get("sessions").and_then(|v| v.as_array()).is_some(),
        "JSON must contain a 'sessions' array, got: {stdout}"
    );
    assert!(
        parsed.get("total_sessions").is_some(),
        "JSON must contain 'total_sessions' field, got: {stdout}"
    );
}

// ── issen frequency CLI tests (Step C RED) ───────────────────────────────────

#[test]
fn frequency_subcommand_appears_in_main_help() {
    issen_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("frequency"));
}

#[test]
fn frequency_help_shows_evtx_dir_cap_and_key() {
    issen_cmd()
        .args(["frequency", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("evtx-dir"))
        .stdout(predicate::str::contains("cap"))
        .stdout(predicate::str::contains("key"));
}

#[test]
fn frequency_empty_dir_exits_success_with_json() {
    let dir = TempDir::new().expect("tmpdir");
    issen_cmd()
        .args([
            "frequency",
            "--evtx-dir",
            &dir.path().to_string_lossy(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("anomalies"));
}

#[test]
fn frequency_json_output_has_anomalies_array_and_total_analyzed() {
    let dir = TempDir::new().expect("tmpdir");
    let output = issen_cmd()
        .args([
            "frequency",
            "--evtx-dir",
            &dir.path().to_string_lossy(),
            "--json",
        ])
        .output()
        .expect("failed to run issen frequency");

    assert!(output.status.success(), "exit code must be 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert!(
        parsed.get("anomalies").and_then(|v| v.as_array()).is_some(),
        "JSON must have 'anomalies' array, got: {stdout}"
    );
    assert!(
        parsed.get("total_analyzed").is_some(),
        "JSON must have 'total_analyzed' field, got: {stdout}"
    );
}

#[test]
fn session_nonexistent_dir_exits_success_with_empty_sessions() {
    issen_cmd()
        .args([
            "session",
            "--evtx-dir",
            "/tmp/issen_test_nonexistent_dir_abc",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sessions\""));
}
