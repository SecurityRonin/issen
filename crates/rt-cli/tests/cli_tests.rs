use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn rt_cmd() -> Command {
    Command::cargo_bin("rt").expect("binary rt should exist")
}

#[test]
fn test_no_args_shows_help() {
    rt_cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn test_help_flag() {
    rt_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("RapidTriage"))
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
    rt_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("rt"));
}

#[test]
fn test_ingest_missing_path() {
    rt_cmd()
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

    rt_cmd()
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

    rt_cmd()
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
    rt_cmd()
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
    rt_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Then query info.
    rt_cmd()
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
    rt_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Query timeline.
    rt_cmd()
        .args(["timeline", &db_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No events found"));
}

#[test]
fn test_timeline_help() {
    rt_cmd()
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
    rt_cmd()
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
    rt_cmd()
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
    rt_cmd()
        .args(["info", &db_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total events:      1"))
        .stdout(predicate::str::contains("UsnJournal"));

    // Query timeline.
    rt_cmd()
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
    rt_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Export.
    rt_cmd()
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
        .flat_map(|c| c.to_le_bytes())
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
    rt_cmd()
        .args(["feed", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("update"))
        .stdout(predicate::str::contains("info"));
}

#[test]
fn test_feed_list() {
    rt_cmd()
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
    rt_cmd()
        .args(["feed", "info", "nonexistent-feed-id"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_feed_info_known() {
    rt_cmd()
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
    rt_cmd()
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
    rt_cmd()
        .arg("scan")
        .assert()
        .failure()
        .stderr(predicate::str::contains("TARGET"));
}

#[test]
fn test_scan_nonexistent_target() {
    rt_cmd()
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

    rt_cmd()
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

    rt_cmd()
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

    rt_cmd()
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
    let dir = TempDir::new().unwrap();

    // Write target file.
    let target_path = dir.path().join("malware.bin");
    let data = b"known malware payload content";
    std::fs::write(&target_path, data).unwrap();

    // Compute SHA-256 of the target and write IOC file.
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(data));

    let ioc_path = dir.path().join("bad_hashes.txt");
    std::fs::write(&ioc_path, format!("# Bad hashes\n{}\n", hash)).unwrap();

    rt_cmd()
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

    rt_cmd()
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

    rt_cmd()
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

    rt_cmd()
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
    rt_cmd()
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

    rt_cmd()
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

    rt_cmd()
        .args([
            "ingest",
            evidence.to_str().unwrap(),
            "-o",
            db.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Query with --flagged --format json on a DB with no findings.
    let output = rt_cmd()
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
    rt_cmd()
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

    rt_cmd()
        .args([
            "ingest",
            evidence.to_str().unwrap(),
            "-o",
            db.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Query with --flagged on a DB that has no findings table yet.
    rt_cmd()
        .args(["timeline", db.to_str().unwrap(), "--flagged"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No scan findings found"));
}

#[test]
fn test_timeline_flagged_help() {
    rt_cmd()
        .args(["timeline", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--flagged"))
        .stdout(predicate::str::contains("--min-severity"));
}

#[test]
fn test_scan_auto_feeds_help() {
    rt_cmd()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--auto-feeds"));
}

#[test]
fn test_ingest_scan_help() {
    rt_cmd()
        .args(["ingest", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--scan"));
}

// ── Ingest scan rule flag tests ──────────────────────────────────────

#[test]
fn test_ingest_help_shows_scan_flags() {
    rt_cmd()
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

    rt_cmd()
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
        r#"
title: Test Sigma Rule
id: test-ingest-sigma-001
level: medium
detection:
    selection:
        EventType: FileCreate
    condition: selection
"#,
    )
    .unwrap();

    // Create evidence directory with a $J so pipeline produces events.
    let evidence_dir = dir.path().join("evidence");
    std::fs::create_dir(&evidence_dir).unwrap();
    let record = build_usn_v2_record("test.txt", 0x100, 42, 100, 0);
    std::fs::write(evidence_dir.join("$J"), &record).unwrap();

    // The --sigma-rules flag should be accepted and trigger the scan phase.
    rt_cmd()
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

    rt_cmd()
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
    rt_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Info on empty DB should succeed and NOT mention scan findings.
    rt_cmd()
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
    rt_cmd()
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
    rt_cmd()
        .args(["info", db_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Scan findings:"))
        .stdout(predicate::str::contains("high"));
}

#[test]
fn test_info_help() {
    rt_cmd()
        .args(["info", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DB_PATH"));
}

// ── Report subcommand tests ──────────────────────────────────────

#[test]
fn test_report_help() {
    rt_cmd()
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
fn test_report_missing_db() {
    rt_cmd()
        .args(["report", "/nonexistent/db.duckdb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn test_report_empty_db() {
    let dir = TempDir::new().unwrap();
    let evidence_dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.duckdb");
    let report_path = dir.path().join("report.html");

    // Ingest empty dir to create DB.
    rt_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Generate report.
    rt_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &report_path.to_string_lossy(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Report written to"));

    // Verify HTML file was created.
    assert!(report_path.exists(), "HTML report file should exist");
    let html = std::fs::read_to_string(&report_path).expect("read report");
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("RapidTriage Report"));
    assert!(html.contains("Total Events"));
}

#[test]
fn test_report_with_events() {
    let dir = TempDir::new().unwrap();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.duckdb");
    let report_path = db_dir.path().join("report.html");

    // Create evidence with a USN record.
    let record = build_usn_v2_record("evidence.docx", 0x100, 42, 100, 0);
    std::fs::write(dir.path().join("$J"), &record).expect("write $J");

    // Ingest.
    rt_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Generate report.
    rt_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &report_path.to_string_lossy(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&report_path).expect("read report");
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
fn test_report_with_case_id_and_examiner() {
    let dir = TempDir::new().unwrap();
    let evidence_dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.duckdb");
    let report_path = dir.path().join("report.html");

    // Create DB via ingest.
    rt_cmd()
        .args([
            "ingest",
            &evidence_dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Generate report with metadata.
    rt_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &report_path.to_string_lossy(),
            "--case-id",
            "CASE-2024-042",
            "--examiner",
            "Jane Doe",
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&report_path).expect("read report");
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
fn test_report_with_max_events() {
    let dir = TempDir::new().unwrap();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.duckdb");
    let report_path = db_dir.path().join("report.html");

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
    rt_cmd()
        .args([
            "ingest",
            &dir.path().to_string_lossy(),
            "-o",
            &db_path.to_string_lossy(),
        ])
        .assert()
        .success();

    // Generate report limited to 2 events.
    rt_cmd()
        .args([
            "report",
            &db_path.to_string_lossy(),
            "-o",
            &report_path.to_string_lossy(),
            "--max-events",
            "2",
        ])
        .assert()
        .success();

    // The report should exist and contain events (limited by max-events).
    let html = std::fs::read_to_string(&report_path).expect("read report");
    assert!(html.contains("<!DOCTYPE html>"));
    // Total Events stat should still reflect all 5.
    assert!(
        html.contains(">5<"),
        "summary should show total event count"
    );
}

#[test]
fn test_report_with_findings() {
    let dir = TempDir::new().unwrap();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.duckdb");
    let report_path = db_dir.path().join("report.html");

    // Write YARA rule.
    let rule_path = dir.path().join("detect.yar");
    std::fs::write(
        &rule_path,
        r#"rule report_detect { strings: $s = "MALICIOUS_MARKER" condition: $s }"#,
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
    rt_cmd()
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
    rt_cmd()
        .args([
            "report",
            db_path.to_str().unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&report_path).expect("read report");
    assert!(
        html.contains("Scan Findings"),
        "report should contain findings section"
    );
    assert!(
        html.contains("report_detect"),
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
    rt_cmd()
        .args(["remote-access", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("remote access"));
}

#[test]
fn test_remote_access_missing_path() {
    rt_cmd()
        .args(["remote-access", "/nonexistent/path"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn test_remote_access_empty_dir() {
    let dir = TempDir::new().expect("tmpdir");
    rt_cmd()
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
    rt_cmd()
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
    rt_cmd()
        .args([
            "remote-access",
            &dir.path().to_string_lossy(),
            "--format",
            "json",
        ])
        .assert()
        .success();
}
