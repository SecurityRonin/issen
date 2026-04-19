pub mod engine;
pub mod skew;
pub mod enrich;
pub mod feeds;
pub mod model;
pub mod render;
pub mod rules;
pub mod sync;
pub mod warninglist;
pub mod zeek_intel;

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::{TimeZone, Utc};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    use crate::engine::CorrelationEngine;
    use crate::enrich::enrich_evidence;
    use crate::model::{
        CorrelationRule, Evidence, EvidenceKind, EvidenceSource, FeedKind, FeedSpec,
        RuleAttrPredicate, RuleClause, SubjectRef,
    };
    use crate::rules::{bundled_rule_dir, load_rule_file, load_rule_pack, load_rule_sources};
    use crate::sync::{
        load_sync_manifest, materialize_download, persist_sync_manifest, render_feed_url,
        SyncOptions, SyncResult,
    };

    #[test]
    fn enriches_command_and_port_evidence_from_forensic_indicators() {
        let command = Evidence::new(
            "cmd-1",
            EvidenceSource::Artifact,
            EvidenceKind::Command,
            Some(SubjectRef::Process(4242)),
        )
        .with_attr(
            "command",
            "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
        );

        let network = Evidence::new(
            "net-1",
            EvidenceSource::Zeek,
            EvidenceKind::Network,
            Some(SubjectRef::Process(4242)),
        )
        .with_attr("dst_port", "4444");

        let enriched = enrich_evidence(vec![command, network]);

        assert_eq!(enriched.len(), 2);
        assert!(enriched[0].tags.contains(&"reverse_shell".to_string()));
        assert!(enriched[1].tags.contains(&"suspicious_port".to_string()));
    }

    #[test]
    fn correlates_cross_source_evidence_into_a_single_finding() {
        let ts = Utc.with_ymd_and_hms(2026, 4, 16, 0, 0, 0).unwrap();
        let rule = CorrelationRule {
            id: "pivot.reverse-shell".into(),
            title: "Reverse shell over suspicious port".into(),
            severity: "high".into(),
            description: None,
            within_seconds: Some(300),
            references: Vec::new(),
            clauses: vec![
                RuleClause::tagged(EvidenceSource::Artifact, "reverse_shell"),
                RuleClause::tagged(EvidenceSource::Zeek, "suspicious_port"),
            ],
        };

        let command = Evidence::new(
            "cmd-1",
            EvidenceSource::Artifact,
            EvidenceKind::Command,
            Some(SubjectRef::Process(4242)),
        )
        .with_timestamp(ts)
        .with_tag("reverse_shell");

        let network = Evidence::new(
            "net-1",
            EvidenceSource::Zeek,
            EvidenceKind::Network,
            Some(SubjectRef::Process(4242)),
        )
        .with_timestamp(ts + chrono::Duration::seconds(30))
        .with_tag("suspicious_port");

        let findings = CorrelationEngine::default().evaluate(&[rule], &[command, network]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "pivot.reverse-shell");
        assert_eq!(
            findings[0].evidence_ids,
            vec!["cmd-1".to_string(), "net-1".to_string()]
        );
    }

    #[test]
    fn exposes_default_latest_feed_registry() {
        let feeds = FeedSpec::default_registry();

        assert!(feeds
            .iter()
            .any(|f| { f.name == "sigmahq/sigma" && matches!(f.kind, FeedKind::GitArchive) }));
        assert!(feeds.iter().any(|f| {
            f.name == "neo23x0/signature-base" && matches!(f.kind, FeedKind::GitArchive)
        }));
        assert!(feeds
            .iter()
            .any(|f| { f.name == "et/open" && matches!(f.kind, FeedKind::SuricataUpdate) }));
        assert!(feeds
            .iter()
            .any(|f| { f.name == "zeek/packages" && matches!(f.kind, FeedKind::GitArchive) }));
    }

    #[test]
    fn renders_suricata_url_from_sync_options() {
        let feed = FeedSpec::default_registry()
            .into_iter()
            .find(|feed| feed.name == "et/open")
            .expect("et/open feed");

        let rendered = render_feed_url(
            &feed,
            &SyncOptions {
                suricata_version: Some("8.0".into()),
                ..SyncOptions::default()
            },
        );

        assert_eq!(
            rendered,
            "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz"
        );
    }

    #[test]
    fn materializes_git_archive_zip_into_destination() {
        let tmp = tempdir().expect("tempdir");
        let archive_path = tmp.path().join("sigma.zip");
        let mut writer =
            zip::ZipWriter::new(std::fs::File::create(&archive_path).expect("create zip archive"));
        writer
            .start_file("sigma-master/rules/test.yml", SimpleFileOptions::default())
            .expect("start zip entry");
        std::io::Write::write_all(&mut writer, b"title: Test Rule\n").expect("write zip entry");
        writer.finish().expect("finish zip archive");

        let dest = tmp.path().join("out");
        materialize_download(
            &FeedSpec {
                name: "sigmahq/sigma".into(),
                kind: FeedKind::GitArchive,
                url: "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip".into(),
            },
            &fs::read(&archive_path).expect("read zip archive"),
            &dest,
        )
        .expect("materialize zip");

        assert!(dest.join("sigma-master/rules/test.yml").exists());
    }

    #[test]
    fn materializes_suricata_tarball_into_destination() {
        let tmp = tempdir().expect("tempdir");
        let archive_path = tmp.path().join("emerging.rules.tar.gz");
        let tar_gz = std::fs::File::create(&archive_path).expect("create tar.gz");
        let encoder = GzEncoder::new(tar_gz, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let content = b"alert tcp any any -> any any (msg:\"test\"; sid:1; rev:1;)";

        let mut header = tar::Header::new_gnu();
        header.set_path("emerging.rules").expect("set path");
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append(&header, &content[..])
            .expect("append tar entry");
        let encoder = builder.into_inner().expect("finish tar");
        encoder.finish().expect("finish gzip");

        let dest = tmp.path().join("out");
        materialize_download(
            &FeedSpec {
                name: "et/open".into(),
                kind: FeedKind::SuricataUpdate,
                url: "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz"
                    .into(),
            },
            &fs::read(&archive_path).expect("read tar.gz"),
            &dest,
        )
        .expect("materialize tar.gz");

        assert!(dest.join("emerging.rules").exists());
    }

    #[test]
    fn loads_correlation_rule_from_yaml_file() {
        let tmp = tempdir().expect("tempdir");
        let rule_path = tmp.path().join("rule.yml");
        fs::write(
            &rule_path,
            r#"id: correlation.reverse-shell
title: Reverse shell over suspicious port
severity: high
within_seconds: 300
references:
  - https://redcanary.com/threat-detection-report/trends/linux-coinminers/
clauses:
  - source: artifact
    required_tag: reverse_shell
  - source: zeek
    required_tag: suspicious_port
"#,
        )
        .expect("write rule");

        let rule = load_rule_file(&rule_path).expect("load rule");

        assert_eq!(rule.id, "correlation.reverse-shell");
        assert_eq!(rule.references.len(), 1);
        assert_eq!(rule.clauses.len(), 2);
        assert_eq!(
            rule.clauses[0],
            RuleClause::tagged(EvidenceSource::Artifact, "reverse_shell")
        );
    }

    #[test]
    fn loads_bundled_rule_pack_with_miner_rules() {
        let rules = load_rule_pack(&bundled_rule_dir()).expect("load bundled rules");

        assert!(!rules.is_empty());
        assert!(rules
            .iter()
            .any(|rule| rule.id == "correlation.miner.rootkit-concealment"));
        assert!(rules
            .iter()
            .any(|rule| rule.id == "correlation.miner.ssh-stratum-tunnel"));
    }

    #[test]
    fn evaluates_loaded_miner_rule_without_hardcoded_strings_in_engine() {
        let rules = load_rule_pack(&bundled_rule_dir()).expect("load bundled rules");
        let rule = rules
            .into_iter()
            .find(|rule| rule.id == "correlation.miner.rootkit-concealment")
            .expect("miner rule");
        let ts = Utc.with_ymd_and_hms(2026, 4, 16, 0, 0, 0).unwrap();

        let rootkit = Evidence::new(
            "rootkit-1",
            EvidenceSource::Artifact,
            EvidenceKind::Artifact,
            Some(SubjectRef::Process(31337)),
        )
        .with_timestamp(ts)
        .with_tag("rootkit_indicator");

        let hidden = Evidence::new(
            "proc-1",
            EvidenceSource::Memory,
            EvidenceKind::Process,
            Some(SubjectRef::Process(31337)),
        )
        .with_timestamp(ts + chrono::Duration::seconds(5))
        .with_tag("miner_thread"); // libuv-worker threads confirm XMRig; more specific than hidden_process

        // Hidden-process network evidence comes from Volatility (memory),
        // not Zeek — Zeek can't see loopback/hidden-process traffic.
        let network = Evidence::new(
            "net-1",
            EvidenceSource::Memory,
            EvidenceKind::Network,
            Some(SubjectRef::Process(31337)),
        )
        .with_timestamp(ts + chrono::Duration::seconds(10))
        .with_tag("mining_pool");

        let findings = CorrelationEngine::default().evaluate(&[rule], &[rootkit, hidden, network]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "correlation.miner.rootkit-concealment");
        assert_eq!(
            findings[0].evidence_ids,
            vec![
                "rootkit-1".to_string(),
                "proc-1".to_string(),
                "net-1".to_string()
            ]
        );
    }

    #[test]
    fn merges_bundled_and_custom_rule_sources_by_id() {
        let tmp = tempdir().expect("tempdir");
        let custom_dir = tmp.path().join("custom");
        fs::create_dir_all(&custom_dir).expect("create custom dir");
        fs::write(
            custom_dir.join("custom.yml"),
            r#"id: correlation.custom.test
title: Custom test correlation
severity: medium
within_seconds: 60
clauses:
  - source: artifact
    required_tag: persistence_artifact
"#,
        )
        .expect("write custom rule");

        let rules =
            load_rule_sources(&[bundled_rule_dir(), custom_dir]).expect("load merged rules");

        assert!(rules
            .iter()
            .any(|rule| rule.id == "correlation.custom.test"));
        let bundled_count = rules
            .iter()
            .filter(|rule| rule.id == "correlation.miner.rootkit-concealment")
            .count();
        assert_eq!(bundled_count, 1);
    }

    #[test]
    fn persists_sync_manifest_round_trip() {
        let tmp = tempdir().expect("tempdir");
        let records = vec![SyncResult {
            feed_name: "sigmahq/sigma".into(),
            source_url: "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip".into(),
            archive_path: tmp.path().join("sigma.zip"),
            extracted_to: tmp.path().join("sigma"),
        }];

        persist_sync_manifest(tmp.path(), &records).expect("persist manifest");
        let loaded = load_sync_manifest(tmp.path()).expect("load manifest");

        assert_eq!(loaded, records);
    }

    #[test]
    fn matches_rule_clause_against_evidence_attributes() {
        let ts = Utc.with_ymd_and_hms(2026, 4, 16, 0, 0, 0).unwrap();
        let rule = CorrelationRule {
            id: "correlation.miner.attr-driven".into(),
            title: "Attribute-driven miner correlation".into(),
            severity: "high".into(),
            description: None,
            within_seconds: Some(600),
            references: Vec::new(),
            clauses: vec![
                RuleClause {
                    source: EvidenceSource::Artifact,
                    required_tag: String::new(),
                    attr_predicates: vec![RuleAttrPredicate::Equals {
                        key: "process_name".into(),
                        value: "xmrig".into(),
                    }],
                },
                RuleClause {
                    source: EvidenceSource::Zeek,
                    required_tag: String::new(),
                    attr_predicates: vec![RuleAttrPredicate::AnyOf {
                        key: "dst_port".into(),
                        values: vec!["3333".into(), "4444".into()],
                    }],
                },
            ],
        };

        let process = Evidence::new(
            "proc-1",
            EvidenceSource::Artifact,
            EvidenceKind::Process,
            Some(SubjectRef::Process(1337)),
        )
        .with_timestamp(ts)
        .with_attr("process_name", "xmrig");

        let network = Evidence::new(
            "net-1",
            EvidenceSource::Zeek,
            EvidenceKind::Network,
            Some(SubjectRef::Process(1337)),
        )
        .with_timestamp(ts + chrono::Duration::seconds(10))
        .with_attr("dst_port", "3333");

        let findings = CorrelationEngine::default().evaluate(&[rule], &[process, network]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "correlation.miner.attr-driven");
    }

    #[test]
    fn loads_bundled_attr_driven_tunnel_rule() {
        let rules = load_rule_pack(&bundled_rule_dir()).expect("load bundled rules");
        let rule = rules
            .into_iter()
            .find(|rule| rule.id == "correlation.miner.ssh-stratum-tunnel")
            .expect("attr-driven tunnel rule");

        assert!(rule
            .clauses
            .iter()
            .any(|clause| !clause.attr_predicates.is_empty()));
    }

    // ── IntelKind / IndicatorType model ──────────────────────────────────────

    #[test]
    fn intel_kind_variants_are_defined() {
        use crate::model::{IndicatorType, IntelKind};
        let _kinds = [
            IntelKind::ContentSignature,
            IntelKind::EventRule,
            IntelKind::NetworkSignature,
            IntelKind::AtomicIndicator,
            IntelKind::IntelGraph,
            IntelKind::ReferenceDataset,
            IntelKind::CorrelationRule,
        ];
        let _types = [
            IndicatorType::IpAddr,
            IndicatorType::Domain,
            IndicatorType::Url,
            IndicatorType::FileHash,
            IndicatorType::Email,
            IndicatorType::Mutex,
            IndicatorType::Ja3Fingerprint,
            IndicatorType::Ja4Fingerprint,
            IndicatorType::TlsCertHash,
            IndicatorType::Cve,
            IndicatorType::RegistryKey,
            IndicatorType::FilePath,
        ];
    }

    // ── FeedTransport / ArchiveFormat ─────────────────────────────────────────

    #[test]
    fn feed_transport_variants_are_defined() {
        use crate::feeds::{ArchiveFormat, AuthConfig, FeedTransport};
        let _git = FeedTransport::Git {
            repo_url: "https://github.com/SigmaHQ/sigma".into(),
            branch: Some("master".into()),
        };
        let _archive = FeedTransport::HttpArchive {
            url: "https://example.com/rules.tar.gz".into(),
            format: ArchiveFormat::TarGz,
        };
        let _json = FeedTransport::HttpJson {
            url: "https://example.com/feed.json".into(),
            auth: None,
        };
        let _taxii = FeedTransport::Taxii {
            discovery_url: "https://taxii.example.com/".into(),
            collection_id: "collection-1".into(),
            auth: Some(AuthConfig::Bearer {
                token: "tok".into(),
            }),
        };
        let _misp = FeedTransport::MispApi {
            base_url: "https://misp.example.com".into(),
            auth_key: "key".into(),
        };
    }

    // ── FeedManifest / ParseStatus ────────────────────────────────────────────

    #[test]
    fn feed_manifest_round_trips_through_json() {
        use crate::feeds::{ArchiveFormat, FeedManifest, FeedTransport, ParseStatus, SchemaFamily};
        use std::path::PathBuf;

        let manifest = FeedManifest {
            source_id: "sigmahq/sigma".into(),
            schema_family: SchemaFamily::Sigma,
            transport: FeedTransport::HttpArchive {
                url: "https://example.com/sigma.zip".into(),
                format: ArchiveFormat::Zip,
            },
            version: Some("abc123".into()),
            taxii_cursor: None,
            fetched_at: chrono::Utc::now(),
            local_cache_path: PathBuf::from("/tmp/sigma"),
            parse_status: ParseStatus::Ok { rule_count: 42 },
        };

        let json = serde_json::to_string(&manifest).expect("serialize");
        let restored: FeedManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.source_id, "sigmahq/sigma");
        assert_eq!(restored.version, Some("abc123".into()));
        match restored.parse_status {
            ParseStatus::Ok { rule_count } => assert_eq!(rule_count, 42),
            other => panic!("unexpected parse_status: {other:?}"),
        }
    }

    #[test]
    fn parse_status_partial_error_carries_errors() {
        use crate::feeds::ParseStatus;
        let status = ParseStatus::PartialError {
            rule_count: 10,
            errors: vec!["parse failure on line 3".into()],
        };
        let json = serde_json::to_string(&status).expect("serialize");
        let restored: ParseStatus = serde_json::from_str(&json).expect("deserialize");
        match restored {
            ParseStatus::PartialError { rule_count, errors } => {
                assert_eq!(rule_count, 10);
                assert_eq!(errors[0], "parse failure on line 3");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── MISP warninglist importer ─────────────────────────────────────────────

    #[test]
    fn warninglist_matches_known_domain() {
        use crate::warninglist::parse_warninglist;
        let wl =
            parse_warninglist(r#"{"name":"Test","type":"hostname","list":["evil.com","bad.org"]}"#)
                .expect("parse warninglist");
        assert!(wl.contains("evil.com"));
        assert!(!wl.contains("good.com"));
    }

    #[test]
    fn warninglist_is_fp_candidate_returns_true_for_listed_value() {
        use crate::warninglist::parse_warninglist;
        let wl = parse_warninglist(
            r#"{"name":"Alexa Top 1000","type":"hostname","list":["google.com","facebook.com"]}"#,
        )
        .expect("parse warninglist");
        assert!(wl.is_fp_candidate("google.com"));
        assert!(!wl.is_fp_candidate("evil.com"));
    }

    #[test]
    fn warninglist_name_and_type_are_preserved() {
        use crate::warninglist::parse_warninglist;
        let wl =
            parse_warninglist(r#"{"name":"Top Domains","type":"hostname","list":["example.com"]}"#)
                .expect("parse warninglist");
        assert_eq!(wl.name, "Top Domains");
        assert_eq!(wl.list_type, "hostname");
    }

    // ── Zeek intel importer ───────────────────────────────────────────────────

    #[test]
    fn zeek_intel_parses_domain_row() {
        use crate::zeek_intel::parse_zeek_intel;
        let tsv =
            "#fields\tindicator\tindicator_type\tmeta.source\nevil.com\tIntel::DOMAIN\ttest_feed\n";
        let indicators = parse_zeek_intel(tsv).expect("parse zeek intel");
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].value, "evil.com");
    }

    #[test]
    fn zeek_intel_parses_ip_addr_row() {
        use crate::model::IndicatorType;
        use crate::zeek_intel::parse_zeek_intel;
        let tsv = "#fields\tindicator\tindicator_type\tmeta.source\n1.2.3.4\tIntel::ADDR\tfeed1\n";
        let indicators = parse_zeek_intel(tsv).expect("parse zeek intel");
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].value, "1.2.3.4");
        assert!(matches!(
            indicators[0].indicator_type,
            IndicatorType::IpAddr
        ));
    }

    #[test]
    fn zeek_intel_parses_sha256_row() {
        use crate::model::IndicatorType;
        use crate::zeek_intel::parse_zeek_intel;
        let hash = "e3b0c44298fc1c149afb";
        let tsv = format!(
            "#fields\tindicator\tindicator_type\tmeta.source\n{hash}\tIntel::SHA256\tfeed1\n"
        );
        let indicators = parse_zeek_intel(&tsv).expect("parse zeek intel");
        assert_eq!(indicators.len(), 1);
        assert!(matches!(
            indicators[0].indicator_type,
            IndicatorType::FileHash
        ));
    }

    #[test]
    fn zeek_intel_skips_comment_lines_and_empty_lines() {
        use crate::zeek_intel::parse_zeek_intel;
        let tsv = "#separator \\t\n#fields\tindicator\tindicator_type\tmeta.source\n\nevil.com\tIntel::DOMAIN\tfeed1\n";
        let indicators = parse_zeek_intel(tsv).expect("parse zeek intel");
        assert_eq!(indicators.len(), 1);
    }

    #[test]
    fn zeek_intel_preserves_source_metadata() {
        use crate::zeek_intel::parse_zeek_intel;
        let tsv =
            "#fields\tindicator\tindicator_type\tmeta.source\nevil.com\tIntel::DOMAIN\tmy_feed\n";
        let indicators = parse_zeek_intel(tsv).expect("parse zeek intel");
        assert_eq!(indicators[0].source, "my_feed");
    }

    // ── Bundled rule: SSH tunnel stratum ──────────────────────────────────────

    #[test]
    fn bundled_rules_include_ssh_tunnel_stratum() {
        let rules = load_rule_pack(&bundled_rule_dir()).expect("load bundled rules");
        assert!(
            rules
                .iter()
                .any(|r| r.id == "correlation.network.ssh-tunnel-stratum"),
            "expected correlation.network.ssh-tunnel-stratum in bundled rules"
        );
    }

    #[test]
    fn bundled_rules_include_ld_preload_persistence() {
        let rules = load_rule_pack(&bundled_rule_dir()).expect("load bundled rules");
        assert!(
            rules
                .iter()
                .any(|r| r.id == "correlation.persistence.ld-preload"),
            "expected correlation.persistence.ld-preload in bundled rules"
        );
    }

    #[test]
    fn bundled_rules_include_hidden_process_no_memory() {
        let rules = load_rule_pack(&bundled_rule_dir()).expect("load bundled rules");
        assert!(
            rules
                .iter()
                .any(|r| r.id == "correlation.process.hidden-no-memory"),
            "expected correlation.process.hidden-no-memory in bundled rules"
        );
    }
}
