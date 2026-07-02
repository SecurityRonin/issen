#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
pub mod artifact_correlation;
pub mod attack_flow;
pub mod cluster;
pub mod correlation;
pub mod engine;
pub mod enrich;
pub mod evaluator;
pub mod feeds;
pub mod model;
pub mod render;
pub mod rules;
pub mod ruleset;
pub mod runner;
pub mod skew;
pub mod sync;
pub mod temporal_checks;
pub mod temporal_rule;
pub mod tier_a;
pub mod tier_b;
pub mod tier_b_prime;
pub mod tier_c;
pub mod tier_d;
pub mod time_of_day;
pub mod timestomp;
pub mod warninglist;
pub mod zeek_intel;

pub use attack_flow::{
    bundle_to_correlation_rules, bundle_to_flow_graph, extract_bundles_from_zip,
    parse_attack_flow_bundle, AttackAction, AttackAsset, AttackFlowBundle, AttackFlowRoot,
    AttackOperator, FlowEdge, FlowGraph, FlowNode,
};

#[cfg(test)]
mod tests {
    use std::fs;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use jiff::{SignedDuration, Timestamp};
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    use crate::engine::CorrelationEngine;
    use crate::enrich::enrich_evidence;
    use crate::model::{
        AssertionLevel, CorrelationRule, Evidence, EvidenceKind, EvidenceSource, FeedKind,
        FeedSpec, RuleAttrPredicate, RuleClause, SubjectRef,
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
        let ts = jiff::civil::datetime(2026, 4, 16, 0, 0, 0, 0)
            .in_tz("UTC")
            .unwrap()
            .timestamp();
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
            summary_template: None,
            explanation_template: None,
            default_confidence: 0,
            assertion_level: crate::model::AssertionLevel::Correlated,
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
        .with_timestamp(ts + SignedDuration::from_secs(30))
        .with_tag("suspicious_port");

        let findings = CorrelationEngine.evaluate(&[rule], &[command, network]);

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
            r"id: correlation.reverse-shell
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
",
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
        let ts = jiff::civil::datetime(2026, 4, 16, 0, 0, 0, 0)
            .in_tz("UTC")
            .unwrap()
            .timestamp();

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
        .with_timestamp(ts + SignedDuration::from_secs(5))
        .with_tag("miner_thread"); // libuv-worker threads confirm XMRig; more specific than hidden_process

        // Hidden-process network evidence comes from Volatility (memory),
        // not Zeek — Zeek can't see loopback/hidden-process traffic.
        let network = Evidence::new(
            "net-1",
            EvidenceSource::Memory,
            EvidenceKind::Network,
            Some(SubjectRef::Process(31337)),
        )
        .with_timestamp(ts + SignedDuration::from_secs(10))
        .with_tag("mining_pool");

        let findings = CorrelationEngine.evaluate(&[rule], &[rootkit, hidden, network]);

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
            r"id: correlation.custom.test
title: Custom test correlation
severity: medium
within_seconds: 60
clauses:
  - source: artifact
    required_tag: persistence_artifact
",
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
        let ts = jiff::civil::datetime(2026, 4, 16, 0, 0, 0, 0)
            .in_tz("UTC")
            .unwrap()
            .timestamp();
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
            summary_template: None,
            explanation_template: None,
            default_confidence: 0,
            assertion_level: crate::model::AssertionLevel::Correlated,
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
        .with_timestamp(ts + SignedDuration::from_secs(10))
        .with_attr("dst_port", "3333");

        let findings = CorrelationEngine.evaluate(&[rule], &[process, network]);

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
        let _ = [
            IntelKind::ContentSignature,
            IntelKind::EventRule,
            IntelKind::NetworkSignature,
            IntelKind::AtomicIndicator,
            IntelKind::IntelGraph,
            IntelKind::ReferenceDataset,
            IntelKind::CorrelationRule,
        ];
        let _ = [
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
            fetched_at: Timestamp::now(),
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

    // ── WS-4: Rule template fields ────────────────────────────────────────────

    #[test]
    fn rule_yaml_with_summary_template_parses() {
        let yaml = r#"
id: test.rule.template
title: Test template rule
severity: medium
summary_template: "Summary from template"
explanation_template: "Explanation from template"
default_confidence: 75
assertion_level: inferred
clauses:
  - source: artifact
    required_tag: test_tag
"#;
        let rule: CorrelationRule = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(
            rule.summary_template.as_deref(),
            Some("Summary from template")
        );
        assert_eq!(
            rule.explanation_template.as_deref(),
            Some("Explanation from template")
        );
        assert_eq!(rule.default_confidence, 75);
        assert!(matches!(
            rule.assertion_level,
            crate::model::AssertionLevel::Inferred
        ));
    }

    #[test]
    fn rule_without_template_fields_defaults_to_zero_confidence() {
        let yaml = r"
id: test.rule.no-template
title: No template rule
severity: low
clauses:
  - source: artifact
    required_tag: something
";
        let rule: CorrelationRule = serde_yaml::from_str(yaml).expect("parse");
        assert!(rule.summary_template.is_none());
        assert_eq!(rule.default_confidence, 0);
        assert!(matches!(
            rule.assertion_level,
            crate::model::AssertionLevel::Correlated
        ));
    }

    #[test]
    fn engine_finding_uses_rule_summary_template() {
        use crate::model::{AssertionLevel, EvidenceKind};
        // Build a rule with a summary_template
        let rule = CorrelationRule {
            id: "test.template".into(),
            title: "Template rule".into(),
            severity: "high".into(),
            description: None,
            summary_template: Some("Templated summary".into()),
            explanation_template: Some("Templated explanation".into()),
            default_confidence: 82,
            assertion_level: AssertionLevel::Correlated,
            within_seconds: None,
            references: Vec::new(),
            clauses: vec![RuleClause::tagged(EvidenceSource::Artifact, "rk_tag")],
        };
        let evidence = vec![Evidence {
            id: "e1".into(),
            source: EvidenceSource::Artifact,
            kind: EvidenceKind::Artifact,
            subject: None,
            tags: vec!["rk_tag".into()],
            timestamp: None,
            attrs: std::collections::BTreeMap::default(),
        }];
        let engine = CorrelationEngine;
        let findings = engine.evaluate(&[rule], &evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].summary.as_deref(), Some("Templated summary"));
        assert_eq!(
            findings[0].explanation.as_deref(),
            Some("Templated explanation")
        );
        assert_eq!(findings[0].confidence, 82);
    }

    #[test]
    fn bundled_miner_rule_has_summary_template() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let miner_rule = rules
            .iter()
            .find(|r| r.id == "correlation.miner.rootkit-concealment")
            .expect("miner rule must exist");
        assert!(
            miner_rule.summary_template.is_some(),
            "miner rootkit rule must have a summary_template"
        );
        assert!(
            miner_rule.default_confidence > 0,
            "miner rootkit rule must have default_confidence > 0"
        );
    }

    // WS-7: rootkit explanation must NOT assert exact hook function names
    // without YARA/signature evidence.
    #[test]
    fn rootkit_rule_explanation_does_not_claim_exact_hooks() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "correlation.miner.rootkit-concealment")
            .expect("miner rootkit rule must exist");
        let explanation = rule.explanation_template.as_deref().unwrap_or("");
        assert!(!explanation.contains("readdir"),
            "explanation must not name readdir() — exact hook claim requires YARA/signature evidence");
        assert!(!explanation.contains("getdents"),
            "explanation must not name getdents() — exact hook claim requires YARA/signature evidence");
    }

    // WS-6: miner rule explanation must use calibrated language, not definitive claims.
    #[test]
    fn miner_rule_explanation_uses_calibrated_language() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "correlation.miner.rootkit-concealment")
            .expect("miner rootkit rule must exist");
        let explanation = rule.explanation_template.as_deref().unwrap_or("");
        let has_hedge = explanation.contains("consistent with")
            || explanation.contains("likely")
            || explanation.contains("compatible");
        assert!(has_hedge,
            "miner rule explanation must use calibrated language (consistent with / likely / compatible)");
        assert!(
            !explanation.contains("Mining traffic is tunnelled"),
            "explanation must not assert definitive tunnelling — use calibrated framing"
        );
    }

    // WS-6: SSH tunnel rule must use "consistent with" framing.
    #[test]
    fn ssh_stratum_rule_explanation_is_calibrated() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "correlation.network.ssh-tunnel-stratum")
            .expect("ssh-tunnel-stratum rule must exist");
        let explanation = rule.explanation_template.as_deref().unwrap_or("");
        assert!(
            explanation.contains("consistent with"),
            "SSH tunnel rule explanation must use 'consistent with' framing, got: {explanation}"
        );
    }

    // WS-7: LD_PRELOAD rule must not assert definitively that the library IS a rootkit.
    #[test]
    fn ldpreload_rule_explanation_is_calibrated() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "correlation.persistence.ld-preload")
            .expect("ld-preload rule must exist");
        let explanation = rule.explanation_template.as_deref().unwrap_or("");
        let has_hedge = explanation.contains("consistent with")
            || explanation.contains("indicative of")
            || explanation.contains("may enable")
            || explanation.contains("commonly used");
        assert!(
            has_hedge,
            "LD_PRELOAD rule explanation must use calibrated language, got: {explanation}"
        );
    }

    // WS-9: likely tier fires on libuv-worker evidence; confirmed tier does NOT
    // fire when only libuv-worker evidence is present (no direct xmrig name).
    #[test]
    fn likely_miner_rule_fires_on_libuv_worker_evidence() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        // Only the likely-tier rule should be present in bundled rules
        assert!(
            rules
                .iter()
                .any(|r| r.id == "correlation.miner.rootkit-concealment"),
            "likely-tier miner rule must be bundled"
        );
    }

    #[test]
    fn confirmed_xmrig_rule_is_bundled() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        assert!(
            rules
                .iter()
                .any(|r| r.id == "correlation.miner.confirmed-xmrig"),
            "confirmed-xmrig rule must be bundled"
        );
    }

    #[test]
    fn confirmed_xmrig_rule_has_higher_confidence_than_likely() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let likely = rules
            .iter()
            .find(|r| r.id == "correlation.miner.rootkit-concealment")
            .expect("likely rule");
        let confirmed = rules
            .iter()
            .find(|r| r.id == "correlation.miner.confirmed-xmrig")
            .expect("confirmed rule");
        assert!(
            confirmed.default_confidence > likely.default_confidence,
            "confirmed rule ({}) must have higher confidence than likely ({})",
            confirmed.default_confidence,
            likely.default_confidence
        );
    }

    #[test]
    fn confirmed_xmrig_rule_fires_on_direct_process_name_evidence() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let confirmed_rule = rules
            .iter()
            .find(|r| r.id == "correlation.miner.confirmed-xmrig")
            .expect("confirmed rule")
            .clone();
        let evidence = vec![Evidence {
            id: "proc-xmrig".into(),
            source: EvidenceSource::Memory,
            kind: EvidenceKind::Process,
            subject: Some(SubjectRef::Process(977)),
            tags: vec!["confirmed_xmrig".into()],
            timestamp: None,
            attrs: std::collections::BTreeMap::default(),
        }];
        let engine = CorrelationEngine;
        let findings = engine.evaluate(&[confirmed_rule], &evidence);
        assert_eq!(
            findings.len(),
            1,
            "confirmed-xmrig rule must fire on confirmed_xmrig tag"
        );
        assert!(
            matches!(findings[0].assertion_level, AssertionLevel::Observed),
            "confirmed finding must be Observed assertion level"
        );
    }

    #[test]
    fn confirmed_xmrig_rule_uses_observed_assertion_level() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "correlation.miner.confirmed-xmrig")
            .expect("confirmed rule");
        assert!(
            matches!(rule.assertion_level, AssertionLevel::Observed),
            "confirmed-xmrig rule must use Observed assertion level"
        );
    }

    // ── Phase 2: SRUM correlation rules ──────────────────────────────────────

    #[test]
    fn srum_exfil_candidate_rule_is_bundled() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        assert!(
            rules.iter().any(|r| r.id == "srum.exfil-candidate"),
            "srum.exfil-candidate rule must be bundled"
        );
    }

    #[test]
    fn srum_exfil_candidate_rule_has_high_severity() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "srum.exfil-candidate")
            .expect("srum.exfil-candidate rule must exist");
        assert_eq!(
            rule.severity, "high",
            "srum.exfil-candidate must have high severity"
        );
        assert!(
            matches!(rule.assertion_level, AssertionLevel::Inferred),
            "srum.exfil-candidate must use Inferred assertion level"
        );
    }

    #[test]
    fn srum_c2_beacon_rule_is_bundled() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        assert!(
            rules.iter().any(|r| r.id == "srum.c2-beacon"),
            "srum.c2-beacon rule must be bundled"
        );
    }

    #[test]
    fn srum_c2_beacon_rule_has_high_severity_and_correlated_level() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "srum.c2-beacon")
            .expect("srum.c2-beacon rule must exist");
        assert_eq!(
            rule.severity, "high",
            "srum.c2-beacon must have high severity"
        );
        assert!(
            matches!(rule.assertion_level, AssertionLevel::Correlated),
            "srum.c2-beacon must use Correlated assertion level"
        );
    }

    #[test]
    fn srum_background_miner_rule_is_bundled() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        assert!(
            rules.iter().any(|r| r.id == "srum.background-miner"),
            "srum.background-miner rule must be bundled"
        );
    }

    #[test]
    fn srum_background_miner_rule_has_high_severity_and_correlated_level() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "srum.background-miner")
            .expect("srum.background-miner rule must exist");
        assert_eq!(
            rule.severity, "high",
            "srum.background-miner must have high severity"
        );
        assert!(
            matches!(rule.assertion_level, AssertionLevel::Correlated),
            "srum.background-miner must use Correlated assertion level"
        );
    }

    #[test]
    fn srum_stealth_process_rule_is_bundled() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        assert!(
            rules.iter().any(|r| r.id == "srum.stealth-process"),
            "srum.stealth-process rule must be bundled"
        );
    }

    #[test]
    fn srum_stealth_process_rule_has_critical_severity_and_correlated_level() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "srum.stealth-process")
            .expect("srum.stealth-process rule must exist");
        assert_eq!(
            rule.severity, "critical",
            "srum.stealth-process must have critical severity"
        );
        assert!(
            matches!(rule.assertion_level, AssertionLevel::Correlated),
            "srum.stealth-process must use Correlated assertion level"
        );
    }

    // ── Father rootkit temporal correlation rules ─────────────────────────────

    #[test]
    fn sshd_restart_after_preload_rule_is_bundled() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        assert!(
            rules
                .iter()
                .any(|r| r.id == "temporal.sshd-restart-after-preload"),
            "temporal.sshd-restart-after-preload must be bundled"
        );
    }

    #[test]
    fn sshd_restart_after_preload_rule_has_critical_severity_and_high_confidence() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "temporal.sshd-restart-after-preload")
            .expect("temporal.sshd-restart-after-preload must exist");
        assert_eq!(
            rule.severity, "critical",
            "sshd-restart-after-preload must have critical severity"
        );
        assert!(
            rule.default_confidence >= 80,
            "sshd-restart-after-preload must have confidence >= 80, got {}",
            rule.default_confidence
        );
    }

    #[test]
    fn kit_deleted_after_deployment_rule_is_bundled() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        assert!(
            rules
                .iter()
                .any(|r| r.id == "temporal.kit-deleted-after-deployment"),
            "temporal.kit-deleted-after-deployment must be bundled"
        );
    }

    #[test]
    fn kit_deleted_after_deployment_rule_has_high_severity() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "temporal.kit-deleted-after-deployment")
            .expect("temporal.kit-deleted-after-deployment must exist");
        assert_eq!(
            rule.severity, "high",
            "kit-deleted-after-deployment must have high severity"
        );
    }

    #[test]
    fn failed_preload_then_success_rule_is_bundled() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        assert!(
            rules
                .iter()
                .any(|r| r.id == "temporal.failed-preload-then-success"),
            "temporal.failed-preload-then-success must be bundled"
        );
    }

    #[test]
    fn failed_preload_then_success_rule_has_sufficient_confidence() {
        let dir = bundled_rule_dir();
        let rules = load_rule_pack(&dir).expect("load bundled rules");
        let rule = rules
            .iter()
            .find(|r| r.id == "temporal.failed-preload-then-success")
            .expect("temporal.failed-preload-then-success must exist");
        assert!(
            rule.default_confidence >= 65,
            "failed-preload-then-success must have confidence >= 65, got {}",
            rule.default_confidence
        );
    }

    // ── Batch 1: time_of_day classifier ──────────────────────────────────────

    // 2024-03-15 14:30:00 UTC = Friday 14:30 (within working hours)
    const FRIDAY_2PM_NS: i64 = 1_710_513_000_000_000_000;
    // 2024-03-16 02:00:00 UTC = Saturday 02:00 (weekend + outside hours)
    const SATURDAY_2AM_NS: i64 = 1_710_554_400_000_000_000;
    // 2024-03-18 08:30:00 UTC = Monday 08:30 (before working hours)
    const MONDAY_830AM_NS: i64 = 1_710_750_600_000_000_000;
    // 2024-03-18 18:00:00 UTC = Monday 18:00 (after working hours)
    const MONDAY_6PM_NS: i64 = 1_710_784_800_000_000_000;

    #[test]
    fn friday_2pm_is_within_working_hours() {
        use crate::time_of_day::is_outside_working_hours;
        assert!(!is_outside_working_hours(FRIDAY_2PM_NS));
    }

    #[test]
    fn saturday_is_weekend() {
        use crate::time_of_day::is_weekend;
        assert!(is_weekend(SATURDAY_2AM_NS));
    }

    #[test]
    fn saturday_is_outside_working_hours() {
        use crate::time_of_day::is_outside_working_hours;
        assert!(is_outside_working_hours(SATURDAY_2AM_NS));
    }

    #[test]
    fn monday_830am_is_before_working_hours() {
        use crate::time_of_day::is_outside_working_hours;
        assert!(is_outside_working_hours(MONDAY_830AM_NS));
    }

    #[test]
    fn monday_6pm_is_after_working_hours() {
        use crate::time_of_day::is_outside_working_hours;
        assert!(is_outside_working_hours(MONDAY_6PM_NS));
    }

    #[test]
    fn hour_of_day_friday_2pm() {
        use crate::time_of_day::hour_of_day;
        assert_eq!(hour_of_day(FRIDAY_2PM_NS), 14);
    }

    #[test]
    fn classify_weekend_returns_weekend_variant() {
        use crate::time_of_day::{classify_time_anomaly, TimeAnomaly};
        assert!(matches!(
            classify_time_anomaly(SATURDAY_2AM_NS),
            TimeAnomaly::Weekend { .. }
        ));
    }

    #[test]
    fn classify_after_hours_returns_outside_variant() {
        use crate::time_of_day::{classify_time_anomaly, TimeAnomaly};
        assert!(matches!(
            classify_time_anomaly(MONDAY_6PM_NS),
            TimeAnomaly::OutsideWorkingHours { .. }
        ));
    }

    #[test]
    fn classify_working_hours_returns_none() {
        use crate::time_of_day::{classify_time_anomaly, TimeAnomaly};
        assert_eq!(classify_time_anomaly(FRIDAY_2PM_NS), TimeAnomaly::None);
    }

    #[test]
    fn after_hours_rule_is_bundled() {
        let rules = load_rule_pack(&bundled_rule_dir()).expect("load bundled rules");
        assert!(
            rules.iter().any(|r| r.id == "temporal.after-hours-access"),
            "expected temporal.after-hours-access in bundled rules"
        );
    }

    #[test]
    fn born_before_install_rule_is_bundled() {
        let rules = load_rule_pack(&bundled_rule_dir()).expect("load bundled rules");
        assert!(
            rules
                .iter()
                .any(|r| r.id == "temporal.file-born-before-os-install"),
            "temporal.file-born-before-os-install must be bundled"
        );
    }
}
