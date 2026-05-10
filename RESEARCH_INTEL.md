# Threat Intel Schema Research

## Why This Exists

Issen originally set out to scan against YARA, Sigma, and STIX threat intelligence. That is still correct, but it is incomplete.

The right direction is the union of:

- executable detection formats
- indicator exchange formats
- network signature formats
- threat knowledge / taxonomy formats
- Issen proprietary correlation rules

This document maps the adjacent schema landscape, recommends what Issen should support, and defines how feeds should be downloaded and kept current.

## Executive Summary

### Keep As First-Class

- `YARA` / `YARA-X`
- `Sigma`
- `Sigma correlation rules`
- `STIX 2.1`
- `TAXII 2.1`
- `Suricata`
- `Zeek intel files`
- `MISP feeds / events / exports`
- `MISP warninglists`
- `MISP galaxies`
- `MISP taxonomies`
- `MISP objects`
- `MITRE ATT&CK STIX`

### Support Via Adapters, Not Native Execution

- `OpenIOC`
- `MITRE CAR`
- `OpenCTI feeds`

### Treat As Normalization / Enrichment, Not Intel Rules

- `OCSF`
- `ATT&CK Data Model`

### Out Of Scope For V1

- `CACAO` playbooks as an execution language
- vendor-specific cloud rule DSLs such as `YARA-L`

## Recommended Internal Model

Issen should not keep adding one-off parsers everywhere. It should ingest external schemas into a small number of internal types:

- `ContentSignature`
  - byte/content matching
  - examples: YARA
- `EventRule`
  - log/event matching
  - examples: Sigma, Sigma correlation
- `NetworkSignature`
  - packet/protocol signature
  - examples: Suricata
- `AtomicIndicator`
  - IP, domain, URL, hash, email, mutex, JA3/JA4, string
  - examples: STIX indicator, MISP attribute, Zeek intel file, OpenIOC leaf
- `IntelGraph`
  - actor, malware, campaign, technique, relationships
  - examples: STIX bundles, ATT&CK STIX, MISP events/galaxies/objects
- `ReferenceDataset`
  - false-positive suppression, taxonomies, catalogs, whitelists
  - examples: MISP warninglists, MISP taxonomies, forensic-catalog
- `CorrelationRule`
  - proprietary Issen cross-artifact logic
  - examples: miner concealment, SSH-tunneled stratum, persistence stacks

This lets Issen support many external schemas without making every downstream feature schema-aware.

## Schema Landscape

### 1. YARA / YARA-X

What it is:
- content-signature language for files, memory, and extracted strings

Why it matters:
- still the best common format for file and memory signatures
- directly aligned with Issen’s existing scanning model

Support strategy:
- keep native execution
- ingest rule metadata into `ContentSignature`
- preserve namespaces, tags, metadata, and source provenance

Feed/update strategy:
- no single official “YARA feed” exists
- support curated Git sources as feed registries

Recommended feeds:
- Neo23x0 `signature-base`: https://github.com/Neo23x0/signature-base
- YARA Rules project: https://github.com/Yara-Rules/rules
- YARA-X docs: https://virustotal.github.io/yara-x/docs/
- YARA-X overview: https://virustotal.github.io/yara-x/

Implementation note:
- continue using `yara-x`
- sync by Git snapshot or archive download
- maintain a per-feed manifest with commit hash / fetched timestamp / local cache path

### 2. Sigma

What it is:
- YAML rule format for event/log detection

Why it matters:
- best open standard for event detection content
- large community rule corpus

Support strategy:
- keep native support
- continue compiling/evaluating Sigma detections
- ingest rule metadata into `EventRule`

Recommended feeds:
- Sigma main repo: https://github.com/SigmaHQ/sigma
- Sigma docs: https://sigmahq.io/docs/basics/rules.html

Update strategy:
- Git snapshot / archive download from SigmaHQ
- preserve rule path, rule id, status, level, tags, and references

### 3. Sigma Correlation Rules

What it is:
- Sigma’s standardized multi-event correlation format

Why it matters:
- overlaps directly with Issen’s proprietary correlation direction
- useful for log-native temporal/grouped detections

Support strategy:
- support as an import format into internal `CorrelationRule`
- do not let it replace Issen’s richer host/network/forensic correlation model
- translate supported fields:
  - `rules`
  - `group-by`
  - `timespan`
  - `condition`
  - `aliases`
- reject or mark partial support where backend assumptions do not map cleanly

Official spec:
- https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html

Recommendation:
- build a Sigma-correlation adapter, not a separate runtime

### 4. STIX 2.1

What it is:
- CTI object model and serialization format

Why it matters:
- standard for exchanging indicators, malware, campaigns, infrastructure, relationships
- the right way to ingest structured threat context

Support strategy:
- keep native parsing
- map STIX `indicator`, `observed-data`, `malware`, `campaign`, `infrastructure`, `tool`, `intrusion-set`, `relationship` into `AtomicIndicator` and `IntelGraph`
- preserve object ids and relationship graph

Official sources:
- STIX 2.1 announcement: https://www.oasis-open.org/news/announcements/stix-version-2-1-from-cti-tc-approved-as-a-committee-specification
- STIX/TAXII docs hub: https://oasis-open.github.io/cti-documentation/

Update strategy:
- direct bundle downloads
- TAXII polling
- MISP/OpenCTI export ingestion

### 5. TAXII 2.1

What it is:
- protocol for exchanging CTI, usually STIX

Why it matters:
- this is how many live intel feeds are actually delivered

Support strategy:
- add a `taxii` sync adapter
- support:
  - discovery
  - API roots
  - collections
  - incremental polling
  - manifest persistence

Official spec:
- https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html

Important feeds:
- MITRE ATT&CK official TAXII: https://attack.mitre.org/resources/attack-data-and-tools/
- CISA AIS TAXII guidance: https://www.cisa.gov/resources-tools/resources/cisa-automated-indicator-sharing-ais-taxii-server-connection-guide

Recommendation:
- TAXII is not a schema to “scan with”; it is a transport Issen must support

### 6. MITRE ATT&CK STIX / ATT&CK Data

What it is:
- ATT&CK distributed in STIX 2.1 and TAXII

Why it matters:
- essential for enrichment, mapping, detection context, and reporting

Support strategy:
- ingest as `IntelGraph`
- use for:
  - technique mapping
  - software/group/campaign enrichment
  - correlation rule references
- do not treat ATT&CK as a detection feed by itself

Official sources:
- ATT&CK data access page: https://attack.mitre.org/resources/attack-data-and-tools/
- ATT&CK STIX data repo: https://github.com/mitre-attack/attack-stix-data
- ATT&CK Data Model / spec: https://mitre-attack.github.io/attack-data-model/schemas/

Recommendation:
- sync ATT&CK regularly for enrichment and reporting
- keep it separate from executable rule packs

### 7. Suricata

What it is:
- network IDS/IPS signature language

Why it matters:
- strong open ecosystem for protocol-aware network signatures
- useful both for packet matching and IOC extraction

Support strategy:
- keep parser/import support
- represent imported Suricata content as:
  - `NetworkSignature` where semantics are preserved
  - extracted `AtomicIndicator` when only IOC fields are usable
- long term: add packet/flow execution if Issen grows deeper PCAP support

Official docs:
- rule format: https://docs.suricata.io/en/latest/rules/intro.html
- rule management: https://docs.suricata.io/en/latest/rule-management/suricata-update.html

Update strategy:
- prefer `suricata-update`-compatible source sync
- pull source index and enabled sources
- store vendor/source metadata and rule revisions

Key operational detail:
- `suricata-update` is the official rule-management path and can enumerate available sources via `update-sources` and `list-sources`

### 8. Zeek Intel Files

What it is:
- Zeek’s atomic intelligence format loaded into the Zeek Intelligence Framework

Why it matters:
- very easy way to ingest network indicators with source metadata
- directly useful as atomic IOC content

Support strategy:
- add a native importer
- map Zeek intel rows into `AtomicIndicator`
- preserve indicator type and source metadata

Official docs:
- Zeek Intelligence Framework: https://docs.zeek.org/en/current/frameworks/intel.html

Important format details:
- tab-separated text
- key fields include `indicator`, `indicator_type`, `meta.source`, optional metadata

Recommendation:
- first-class importer
- good fit for quick network IOC ingestion

### 9. Zeek Packages

What it is:
- Git-backed package ecosystem for Zeek scripts/plugins

Why it matters:
- useful source of network detections and analyzers
- but not a direct “intel feed schema”

Support strategy:
- do not try to auto-execute arbitrary Zeek packages inside Issen
- support package-source sync for metadata harvesting only
- optionally curate selected packages into Issen adapters later

Official sources:
- package source docs: https://docs.zeek.org/projects/package-manager/en/stable/source.html
- default package source repo: https://github.com/zeek/packages
- package browser: https://packages.zeek.org/

Recommendation:
- treat Zeek packages as a discovery source, not as an automatic rule feed

### 10. MISP Events / Feeds / Exports

What it is:
- threat sharing platform with its own structured event model and feed system

Why it matters:
- one of the richest open CTI ecosystems
- supports feeds, correlations, exports, STIX, OpenIOC, IDS/SIEM consumption

Support strategy:
- add a MISP adapter
- support:
  - MISP feed JSON
  - MISP event exports
  - selected attribute/object ingestion
- map into `AtomicIndicator` and `IntelGraph`

Official sources:
- MISP project: https://github.com/MISP/MISP
- MISP site: https://misp.software/
- MISP default feeds: https://www.misp-project.org/feeds/

Recommendation:
- high priority
- this is one of the best adjacent ecosystems to ingest

### 11. MISP Warninglists

What it is:
- structured false-positive / suppression / known-good lists

Why it matters:
- ideal input to Issen suppression and confidence-lowering logic

Support strategy:
- native importer into `ReferenceDataset`
- use during finding post-processing, not primary detection

Official sources:
- https://github.com/MISP/misp-warninglists
- https://misp.github.io/misp-warninglists/

Recommendation:
- very high value, very low complexity

### 12. MISP Galaxies

What it is:
- structured clusters such as threat actors, malware families, ransomware, ATT&CK-aligned concepts

Why it matters:
- strong enrichment source for actors, malware, campaigns, tools

Support strategy:
- import as `IntelGraph` enrichment
- use to decorate findings and reports, not direct scanning

Official source:
- https://github.com/MISP/misp-galaxy

### 13. MISP Taxonomies

What it is:
- controlled vocabularies for classification and tagging

Why it matters:
- useful for consistent labeling, confidence, TLP-style metadata, analyst workflow

Support strategy:
- import as `ReferenceDataset`
- use for tagging and UI/reporting support

Official source:
- https://github.com/MISP/misp-taxonomies

### 14. MISP Objects

What it is:
- object templates for structured IOC combinations and richer event content

Why it matters:
- helpful bridge between flat indicators and richer graphs

Support strategy:
- import object templates as schema metadata
- map actual MISP object instances into `IntelGraph`

Official source:
- https://github.com/MISP/misp-objects

### 15. OpenIOC

What it is:
- Mandiant XML IOC schema with boolean criteria trees

Why it matters:
- still appears in legacy intel and exports

Support strategy:
- adapter only
- parse XML into internal boolean criteria / `AtomicIndicator` leaves
- no need for a standalone runtime beyond import

Official source:
- https://github.com/fireeye/OpenIOC_1.1

Recommendation:
- support for interoperability
- lower priority than STIX/MISP/TAXII

### 16. MITRE CAR

What it is:
- analytics repository with pseudocode, rationale, and tool-specific examples

Why it matters:
- excellent source of analytic ideas and correlation patterns
- but not a stable executable interchange format

Support strategy:
- manual or semi-automatic translation into `CorrelationRule`
- do not promise generic execution of CAR pseudocode

Official source:
- https://car.mitre.org/

Recommendation:
- use as research and rule-authoring input
- not as a direct feed runtime

### 17. OCSF

What it is:
- event normalization schema

Why it matters:
- useful if Issen ever normalizes external telemetry broadly

Support strategy:
- not a threat-intel feed
- use as optional event normalization target in the future

Official source:
- https://github.com/ocsf/ocsf-schema

Recommendation:
- not a near-term intel-ingestion priority

## Recommended Support Tiers

### Tier 1: First-Class Ingestion Or Execution

- YARA / YARA-X
- Sigma
- Sigma correlation
- STIX 2.1
- TAXII 2.1
- Suricata
- Zeek intel files
- MISP feeds / events
- MISP warninglists
- ATT&CK STIX

### Tier 2: Enrichment / Context

- MISP galaxies
- MISP taxonomies
- MISP objects
- ATT&CK Data Model

### Tier 3: Adapter For Interop

- OpenIOC
- OpenCTI feed exports

### Tier 4: Research Inputs, Not Runtime Feeds

- MITRE CAR
- CACAO
- OCSF

## Adapter Plan

### Native

Use native engines where Issen already has a real execution story:

- `YARA` -> native content scanning
- `Sigma` -> native event matching
- `Suricata` -> parse now, packet execution later
- `STIX` -> native CTI graph + indicator parsing
- `Zeek intel` -> native IOC import

### Translator

Use adapters when the external format is valuable but should map into Issen’s internal model:

- `Sigma correlation` -> `CorrelationRule`
- `OpenIOC` -> criteria tree -> `AtomicIndicator` / boolean matcher
- `MISP event / object` -> `IntelGraph`
- `MISP warninglists` -> `ReferenceDataset`
- `CAR` -> authoring input -> `CorrelationRule`

### Reference-Only

Support as catalogs or schema references, not executable feeds:

- `MISP taxonomies`
- `MISP galaxies`
- `ATT&CK ADM`
- `OCSF`

## Feed Download And Update Strategy

Issen should not hardcode one downloader per project in ad hoc fashion. It should use transport families.

### Transport Families

- `git`
  - pull repos or archive snapshots
  - use for Sigma, YARA repos, MISP repos, Zeek packages, ATT&CK STIX repo
- `taxii`
  - incremental polling by collection
  - use for ATT&CK TAXII, CISA AIS, vendor TAXII feeds
- `http_archive`
  - zip, tar.gz, plain files
  - use for Suricata rule bundles, direct feed exports
- `http_json`
  - MISP feed manifests, warninglist metadata, vendor JSON indexes
- `misp_api`
  - direct MISP event/feed sync when credentials exist

### Manifest Requirements

Every sync should persist:

- source id
- schema family
- transport type
- remote URL or API root
- auth mode
- version / commit / etag / last-modified / TAXII added_after cursor
- fetched_at
- local cache path
- parse status

### Update Cadence

- Sigma, YARA, MISP repos, ATT&CK repo: daily or on-demand
- TAXII collections: incremental, ideally hourly or user-configurable
- Suricata sources: daily or on-demand
- Zeek package source metadata: daily
- warninglists/taxonomies/galaxies: daily or weekly

## What Issen Should Build Next

### Phase 1

- keep `YARA`, `Sigma`, `STIX`, `Suricata`, and `rt-correlation`
- add `Zeek intel` importer
- add `MISP warninglists` importer
- add `ATT&CK STIX` sync/import
- add generic `git` and `taxii` sync transports

### Phase 2

- add `MISP event/feed` adapter
- add `Sigma correlation` importer into `CorrelationRule`
- add `OpenIOC` importer
- add `MISP galaxies/taxonomies/objects` enrichment ingest

### Phase 3

- use `CAR` as source material for curated proprietary `CorrelationRule` packs
- add packet/flow-native Suricata execution if PCAP ambitions expand
- consider optional `OCSF` normalization for imported event telemetry

## Bottom Line

Issen should not choose between “classical rule engines” and “correlation.”

It should support:

- open detection and network intel formats: `YARA`, `Sigma`, `Suricata`, `Zeek intel`
- open CTI formats and transports: `STIX`, `TAXII`, `MISP`, `OpenIOC`
- open enrichment datasets: `ATT&CK`, `MISP warninglists`, `galaxies`, `taxonomies`, `objects`
- proprietary end-to-end logic: `rt-correlation`

That is the correct union.
