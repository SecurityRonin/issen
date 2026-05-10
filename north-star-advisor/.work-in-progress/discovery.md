# Discovery Session

## Date
2026-03-20T00:00:00Z

## Exploration Summary

### What
Issen is an integrated forensic triage platform with a plugin-based extensible architecture. It combines modular data source readers (E01, Velociraptor, mobile formats), modular artifact parsers (USN Journal, MFT, Prefetch, LNK, Amcache, etc.), a unified timeline, correlation engine, and attorney-ready report generation.

The platform ingests forensic collections from any source through a unified pipeline, processes them through pluggable artifact parsers exposing a common interface, correlates findings across sources and artifact types, and produces output that attorneys can actually use — interactive HTML reports for exploration and polished Word/PDF reports for the record.

### Why
IR practitioners are trapped in a forensic-to-legal translation gap. The actual forensic analysis consumes ~20% of engagement cost. The remaining ~80% is spent on manual report writing, evidence reprocessing, de-duplication, contextualizing technical findings for non-technical audiences, and iterating with attorneys who ask follow-up questions that require re-examination.

Every forensic tool on the market produces engineer-oriented output: CSVs, hex views, registry paths, raw timelines. None of them produce output that an attorney can use without calling the examiner back for interpretation. This manual translation workflow is repeated on every engagement — IR, litigation support, and regulatory compliance alike.

### Who
- **Primary**: IR practitioners and forensic examiners who conduct investigations and need to produce deliverables for legal teams
- **Secondary**: Litigation support teams who bridge between technical forensics and legal proceedings
- **Downstream beneficiaries**: Attorneys, in-house counsel, and compliance officers who consume forensic findings

These users work across engagement types: incident response (breach, ransomware, insider threat), litigation support/eDiscovery (civil litigation, employment disputes, IP theft), and regulatory/compliance (GDPR, SEC, HIPAA).

### Differentiator
Attorney-ready output. Every competitor (Magnet AXIOM, Autopsy, X-Ways, Cellebrite, EnCase, FTK, Belkasoft, plaso) produces technical output for technical users. Issen produces:
1. **Interactive HTML reports** — clickable timelines, drill-down evidence, hyperlinked exhibits. Attorneys can explore findings themselves.
2. **Polished Word/PDF reports** — traditional expert witness format with narrative, exhibits, appendices, methodology section. Ready to file.

The platform differentiator is deeper: plugin-based extensibility with a unified data pipeline, open-source components as community adoption funnel, and the integration of triage speed with forensic depth.

### Key Quotes
> "The real pain is the forensic-to-legal translation. Export, reprocess, write narrative, send to attorney, get questions, re-examine, repeat. Each case takes 3-5x longer than the actual forensic analysis."

> "Opposing side generally have the same raw data, why are we doing their job?" (on full evidence packages for opposing counsel)

> "I envisage myself as the future Magnet Forensics. They began with IEF, a browser history parser. I began with usnjrnl-forensic, a Windows system activity parser."

> "By IR practitioners, for IR practitioners."

## Strategic Decisions

### Licensing Strategy
After initially considering AGPL + Commercial dual licensing, decided on **Apache 2.0 / MIT for open-source components** (keeping existing licenses). Rationale:
- Maximizes community adoption, which is the primary growth metric
- AGPL scares away corporate contributors and users (Google bans it)
- The moat is integration + report generation, not individual parsers
- A competitor can take an Apache 2.0 USN Journal parser but still needs to build everything around it
- Every user of an open-source parser is a potential Issen customer

### Business Model Tiers
| Tier | License | Components |
|------|---------|------------|
| Open Source (Apache 2.0 / MIT) | Permissive | Individual parsers, data source readers, low-level libraries |
| Proprietary (free tier possible) | Closed source | Integration layer, unified pipeline, report engine, UI |
| Enterprise | Closed source + paid | SSO, teams collaboration, admin & audit, priority support |

### Architecture Vision
- Plugin-based extensible architecture with abstract interfaces
- Unified data source pipeline (E01, Velociraptor, mobile, cloud, etc.)
- Unified timeline (supertimeline concept)
- Unified logical concepts (e.g., "startup activities" mapped across OS types)
- OSINT / CTI / dark web / infostealer intelligence integration
- Correlation and visualization engine
- Configurable report generation per engagement type

## Open Questions
- Monorepo vs multi-repo for mixed open-source and proprietary code
- GUI technology (TUI exists in tl; need desktop/web GUI for attorneys?)
- How to handle the "fused filesystem" concept (Velociraptor raw+ntfs fusion, iOS backup + logical + keychain fusion)
- Mobile forensics scope (commercial features like .dar, .ufdx, iOS backup)
- Pricing model for commercial tiers
- Community governance model for open-source components
