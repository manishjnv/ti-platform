# Feed & Integration Requirements

> **Living document** — updated as new connectors and data sources are integrated.
> This is the functional specification for all external intelligence sources the platform must support.

---

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [Integration Status](#integration-status)
- [Core Enterprise CTI Platforms](#-core-enterprise-cti-platforms)
- [Community / Global IOC Feeds](#-community--global-ioc-feeds)
- [IP / Domain / Reputation Intel](#-ip--domain--reputation-intel)
- [Malware & File Intel](#-malware--file-intel)
- [Vulnerability & Exploit Intel](#-vulnerability--exploit-intel)
- [Attack Surface / Situational Intel](#️-attack-surface--situational-intel)
- [Threat Actor / Campaign / TTP Intel](#-threat-actor--campaign--ttp-intel)
- [Phishing & Brand Intel](#-phishing--brand-intel)
- [Curated Multi-Feed Aggregators](#-curated-multi-feed-aggregators)
- [ISAC / Sector Sharing](#️-isac--sector-sharing)
- [Enterprise-Grade Free Feeds](#-enterprise-grade-feeds-that-are-actually-free)
- [Data Coverage Matrix](#-data-coverage-matrix)
- [Connector Implementation Standard](#-connector-implementation-standard)

---

## Design Philosophy

This platform aims to achieve **Recorded Future-style coverage** using **zero-cost, open-source intelligence sources**. Every integration follows the same pattern:

1. **Connector plugin** inherits from `api/app/services/feeds/base.py`
2. **Normalize** into the unified `intel_items` schema (severity, risk_score, feed_type, asset_type, tags, geo, CVEs)
3. **Score** via `services/scoring.py` (CVSS, EPSS, KEV, exploit availability, source reliability)
4. **Index** into PostgreSQL/TimescaleDB + OpenSearch
5. **Enrich** via cross-correlation with other feeds

Future phases will add **STIX/TAXII ingestion** for standards-compliant sharing.

---

## Integration Status

| Source | Category | Status | Connector File | API Key Required |
|--------|----------|--------|----------------|-----------------|
| CISA KEV | Vulnerability | ✅ **Live** | `feeds/kev.py` | No |
| URLhaus | IOC (URLs) | ✅ **Live** | `feeds/urlhaus.py` | No |
| NVD | Vulnerability | ✅ **Live** | `feeds/nvd.py` | Optional |
| AbuseIPDB | IP Reputation | ✅ **Live** | `feeds/abuseipdb.py` | Yes |
| AlienVault OTX | Multi-type | ✅ **Live** | `feeds/otx.py` | Yes |
| ThreatFox | Malware IOC | 🔲 Planned | — | No |
| MalwareBazaar | File Hashes | 🔲 Planned | — | No |
| Feodo Tracker | Botnet C2 | 🔲 Planned | — | No |
| Pulsedive | IOC Enrichment | 🔲 Planned | — | Free tier |
| GreyNoise | Scan Noise | 🔲 Planned | — | Free tier |
| Cisco Talos | IP/Domain | 🔲 Planned | — | No |
| VirusTotal | File/URL/IP | ✅ **Live** | `feeds/virustotal.py` | Free tier |
| ThreatMiner | Passive DNS | 🔲 Planned | — | No |
| VulnCheck | Exploit Intel | 🔲 Planned | — | Free tier |
| Exploit-DB | Exploits | 🔲 Planned | — | No |
| Shodan | CVE/Exploit | ✅ **Live** | `feeds/shodan.py` | Free (CVEDB) |
| Censys | Asset Exposure | 🔲 Planned | — | Free tier |
| MITRE ATT&CK | TTPs | 🔲 Planned | — | No |
| Malpedia | Malware Families | 🔲 Planned | — | No |
| OpenPhish | Phishing URLs | 🔲 Planned | — | No |
| PhishTank | Phishing URLs | 🔲 Planned | — | No |
| URLscan | URL Analysis | 🔲 Planned | — | Free tier |
| MISP | CTI Platform | 🔲 Phase 2 | — | Self-hosted |
| OpenCTI | CTI Platform | 🔲 Phase 2 | — | Self-hosted |
| Yeti | IOC Enrichment | 🔲 Phase 3 | — | Self-hosted |
| GOSINT | OSINT Collection | 🔲 Phase 3 | — | Self-hosted |

---

## 🏢 Core Enterprise CTI Platforms

These are not just feeds — they provide structured, STIX/TAXII-ready ingestion and serve as internal sharing and aggregation layers.

### 1. MISP (Malware Information Sharing Platform)

| Attribute | Detail |
|-----------|--------|
| Type | Open-source CTI sharing platform |
| API | REST + TAXII |
| Feed support | 40+ free feeds out of the box |
| Data model | MISP events + attributes (convertible to STIX) |
| Use case | Internal sharing hub + feed proxy |
| Integration plan | **Phase 2** — deploy as Docker service, sync via MISP API |

### 2. OpenCTI

| Attribute | Detail |
|-----------|--------|
| Type | Open-source CTI platform |
| API | GraphQL + REST |
| Data model | Native STIX 2.1 |
| Features | MITRE ATT&CK mapping, native connectors for most feeds |
| Integration plan | **Phase 2** — bidirectional sync via GraphQL API |

### 3. Yeti

| Attribute | Detail |
|-----------|--------|
| Type | IOC + observable enrichment platform |
| API | REST (API-first) |
| Use case | Enrich IOCs with context, relationships, and scoring |
| Integration plan | **Phase 3** — enrichment pipeline integration |

### 4. GOSINT

| Attribute | Detail |
|-----------|--------|
| Type | Automated OSINT collector |
| Use case | Collect and pre-process OSINT for pipeline ingestion |
| Integration plan | **Phase 3** — feed into worker pipeline |

---

## 🌍 Community / Global IOC Feeds

### AlienVault OTX ✅ Live

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://otx.alienvault.com/api/v1/pulses/subscribed` (with `/pulses/activity` fallback) |
| Data types | Pulses, malware, campaigns, IOCs (IP, domain, URL, hash) |
| API key | **Yes** (free registration) |
| Connector | `api/app/services/feeds/otx.py` |
| Strategy | Fetches subscribed pulses; falls back to `/pulses/activity` for public community intelligence |
| Status | **Implemented — live in production** |

### Abuse.ch Ecosystem

All abuse.ch feeds have REST APIs and are SOC-grade (used in enterprise SIEM/EDR).

#### ThreatFox — Malware IOCs

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://threatfox-api.abuse.ch/api/v1/` |
| Data types | Malware IOCs (C2, payload URLs, hashes) with malware family tags |
| API key | No |
| Status | 🔲 **Planned** |

#### MalwareBazaar — File Hashes & Samples

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://mb-api.abuse.ch/api/v1/` |
| Data types | SHA256, SHA1, MD5 hashes with malware family, signature, tags |
| API key | No |
| Status | 🔲 **Planned** |

#### URLhaus — Malicious URLs ✅ Live

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://urlhaus.abuse.ch/downloads/csv_recent/` |
| Data types | Malicious URLs with tags and threat type |
| API key | No |
| Connector | `api/app/services/feeds/urlhaus.py` |
| Status | **Implemented — live in production** |

#### Feodo Tracker — Botnet C2

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt` |
| Data types | Botnet C2 IPs (Dridex, Emotet, TrickBot, QakBot) |
| API key | No |
| Status | 🔲 **Planned** |

### Pulsedive

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://pulsedive.com/api/` |
| Data types | IOC enrichment, risk scoring, threat context |
| API key | Free tier available |
| Status | 🔲 **Planned** |

---

## 🧾 IP / Domain / Reputation Intel

### AbuseIPDB ✅ Live

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://api.abuseipdb.com/api/v2/blacklist` |
| Data types | IP reputation, confidence scoring, abuse reports |
| API key | **Yes** (free registration) |
| Connector | `api/app/services/feeds/abuseipdb.py` |
| Status | **Implemented — live in production** |

### GreyNoise (Community)

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://api.greynoise.io/v3/community/{ip}` |
| Data types | Internet scan noise filtering — identifies benign scanners vs. threats |
| API key | Free community tier |
| Use case | Reduce false positives by filtering known-benign scanner IPs |
| Status | 🔲 **Planned** |

### Cisco Talos Intelligence

| Attribute | Detail |
|-----------|--------|
| Source | `https://talosintelligence.com/` |
| Data types | IP/domain reputation, threat campaigns, enterprise-quality telemetry |
| API key | No (public intel) |
| Status | 🔲 **Planned** |

---

## 🧬 Malware & File Intel

### VirusTotal (Free API) ✅ Live

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://www.virustotal.com/api/v3/` |
| Data types | Hash/IP context, detection ratios, threat classification |
| API key | **Yes** — Free tier (4 req/min, 500 req/day) |
| Connector | `api/app/services/feeds/virustotal.py` |
| Strategy | Seeds from IPsum (malicious IPs) + MalwareBazaar (hashes), enriches via VT individual lookups |
| Rate limiting | 16s between calls, max 12 lookups/cycle, cursor-based rotation |
| Status | **Implemented — live in production** |

### ThreatMiner

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://api.threatminer.org/v2/` |
| Data types | Passive DNS, malware relationships, actor mapping, WHOIS |
| API key | No |
| Status | 🔲 **Planned** |

---

## 🧱 Vulnerability & Exploit Intel

### NVD (National Vulnerability Database) ✅ Live

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| Data types | CVE records, CVSS scores, CPE mapping, references |
| API key | Optional (higher rate limits with key) |
| Connector | `api/app/services/feeds/nvd.py` |
| Status | **Implemented — live in production** |

### CISA KEV (Known Exploited Vulnerabilities) ✅ Live

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| Data types | Actively exploited CVEs with remediation dates |
| API key | No |
| Connector | `api/app/services/feeds/kev.py` |
| Status | **Implemented — live in production** |

### VulnCheck (Community)

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://api.vulncheck.com/v3/` |
| Data types | Exploit intelligence, exploit availability, weaponization tracking |
| API key | Free tier |
| Status | 🔲 **Planned** |

### Exploit-DB

| Attribute | Detail |
|-----------|--------|
| Source | `https://www.exploit-db.com/` |
| Data types | Public exploit references, proof-of-concept code listings |
| API key | No (CSV/RSS feeds) |
| Status | 🔲 **Planned** |

---

## 🛰️ Attack Surface / Situational Intel

### Shodan CVEDB ✅ Live

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://cvedb.shodan.io/` (free, no auth) |
| Data types | CVEs with EPSS scores, KEV status, ransomware flags |
| API key | Not required (CVEDB is free) |
| Connector | `api/app/services/feeds/shodan.py` |
| Strategy | Fetches high-EPSS CVEs, KEV entries, and recent CVEs from Shodan CVEDB |
| Status | **Implemented — live in production** |

### Censys (Free Tier)

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://search.censys.io/api/` |
| Data types | Exposure intelligence, certificate transparency, host enumeration |
| API key | Free tier |
| Use case | Asset correlation and exposure monitoring |
| Status | 🔲 **Planned** |

---

## 👤 Threat Actor / Campaign / TTP Intel

### MITRE ATT&CK

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` |
| Protocol | STIX/TAXII |
| Data types | Techniques, tactics, groups, software, mitigations |
| API key | No |
| Use case | Map ingested intel to ATT&CK techniques for TTP coverage |
| Status | 🔲 **Planned** |

### Malpedia

| Attribute | Detail |
|-----------|--------|
| Source | `https://malpedia.caad.fkie.fraunhofer.de/` |
| Data types | Malware families, YARA rules, threat actor mapping |
| API key | No (public) |
| Status | 🔲 **Planned** |

---

## 📡 Phishing & Brand Intel

### OpenPhish (Community Feed)

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://openphish.com/feed.txt` |
| Data types | Active phishing URLs |
| API key | No |
| Status | 🔲 **Planned** |

### PhishTank

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://data.phishtank.com/data/online-valid.json` |
| Data types | Verified phishing URLs with target brand |
| API key | No (registration recommended) |
| Status | 🔲 **Planned** |

### URLscan (Free API)

| Attribute | Detail |
|-----------|--------|
| Endpoint | `https://urlscan.io/api/v1/` |
| Data types | URL screenshot, DOM analysis, network requests, verdicts |
| API key | Free tier |
| Status | 🔲 **Planned** |

---

## 🌐 Curated Multi-Feed Aggregators

### threatfeeds.io

| Attribute | Detail |
|-----------|--------|
| Source | `https://threatfeeds.io/` |
| Value | Direct download links for hundreds of feeds — huge time saver for discovery |
| Use case | Reference catalog for new feed sources |

### Open-Source-Threat-Intel-Feeds (GitHub)

| Attribute | Detail |
|-----------|--------|
| Source | `https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds` |
| Value | 100+ structured feeds organized by type (IP, URL, hash, CVE) |
| Use case | Curated reference for feed discovery and prioritization |

---

## 🏛️ ISAC / Sector Sharing

Membership-based sharing communities — design the platform to ingest via TAXII in later phases.

| Organization | Sector | Protocol |
|-------------|--------|----------|
| **FS-ISAC** | Financial Services | TAXII / STIX |
| **H-ISAC** | Healthcare | TAXII / STIX |
| **National CERTs** | Government | TAXII / custom |
| **CERT advisories** | Multi-sector | RSS / API |

> **Design note:** The platform's feed connector architecture is designed to support TAXII 2.1 ingestion. This will be implemented in Phase 2 alongside MISP/OpenCTI integration.

---

## ⭐ Enterprise-Grade Feeds That Are Actually Free

These feeds are used in real SOC environments and form the core of our zero-cost intelligence coverage:

| Feed | Data Quality | Coverage |
|------|-------------|----------|
| **AlienVault OTX** | ⭐⭐⭐⭐ | Multi-type IOCs, campaigns, malware |
| **Abuse.ch Suite** | ⭐⭐⭐⭐⭐ | Malware IOCs, C2, URLs, hashes — SOC-grade |
| **NVD** | ⭐⭐⭐⭐⭐ | CVE database — the authoritative source |
| **CISA KEV** | ⭐⭐⭐⭐⭐ | Actively exploited vulns — CISO-priority |
| **MITRE ATT&CK** | ⭐⭐⭐⭐⭐ | TTP framework — the industry standard |
| **Cisco Talos** | ⭐⭐⭐⭐ | IP/domain reputation, campaigns |
| **Malpedia** | ⭐⭐⭐⭐ | Malware families, YARA, actor intel |
| **ThreatMiner** | ⭐⭐⭐ | Passive DNS, relationships |

---

## 🧩 Data Coverage Matrix

With the feeds listed above, the platform covers:

| Data Type | Sources | Status |
|-----------|---------|--------|
| **IOCs** (IP, domain, URL, hash) | OTX, Abuse.ch, AbuseIPDB, URLhaus, ThreatFox | ✅ Partial / 🔲 Expanding |
| **Malware families** | MalwareBazaar, Malpedia, ThreatFox | 🔲 Planned |
| **Threat actors** | MITRE ATT&CK, Malpedia, OTX | 🔲 Planned |
| **Campaigns** | OTX, MITRE ATT&CK | 🔲 Planned |
| **CVEs** | NVD, CISA KEV | ✅ **Live** |
| **Exploit intelligence** | CISA KEV, Exploit-DB, VulnCheck | ✅ Partial |
| **Asset exposure** | Shodan, Censys | 🔲 Planned |
| **Reputation scoring** | AbuseIPDB, GreyNoise, Pulsedive | ✅ Partial |
| **Phishing intel** | OpenPhish, PhishTank, URLscan | 🔲 Planned |
| **TTPs** | MITRE ATT&CK | 🔲 Planned |

> **Goal:** Achieve Recorded Future-style coverage using zero-cost sources.

---

## 🔧 Connector Implementation Standard

Every new feed connector MUST follow this pattern:

### 1. Create connector file

```
api/app/services/feeds/{feed_name}.py
```

### 2. Inherit from base

```python
from api.app.services.feeds.base import BaseFeedConnector

class NewFeedConnector(BaseFeedConnector):
    FEED_NAME = "new_feed"
    FEED_URL = "https://api.example.com/feed"
    
    async def fetch(self) -> list[dict]:
        """Fetch raw data from external API."""
        ...
    
    async def normalize(self, raw: list[dict]) -> list[IntelItemCreate]:
        """Normalize into unified intel_items schema."""
        ...
```

### 3. Register in scheduler

```python
# worker/scheduler.py
scheduler.add_job(sync_feed, 'interval', args=['new_feed'], minutes=15)
```

### 4. Add to feed_sync_state

```sql
-- db/schema.sql
INSERT INTO feed_sync_state (feed_name) VALUES ('new_feed') ON CONFLICT DO NOTHING;
```

### 5. Add env var (if API key required)

```bash
# .env.example
NEW_FEED_API_KEY=
```

### 6. Update documentation

- Update this file's Integration Status table
- Update [ARCHITECTURE.md](ARCHITECTURE.md) if data flow changes
- Update `.env.example` if new env vars added

---

## Revision History

| Date | Change |
|------|--------|
| 2026-02-28 | VT connector rewritten for free tier (IPsum + MalwareBazaar seeds → VT enrichment lookups) |
| 2026-02-28 | OTX updated with `/pulses/activity` fallback for users without subscriptions |
| 2026-02-28 | All 7 feeds verified live: CISA KEV, URLhaus, NVD, AbuseIPDB, OTX, VirusTotal, Shodan CVEDB |
| 2026-02-24 | Production domain set to intelwatch.trendsmap.in |
| 2026-02-24 | Added VirusTotal & Shodan API key configuration; GitHub repo URL updated |
| 2026-02-23 | Initial integration requirements document created |
| 2026-02-23 | 5 connectors live: CISA KEV, URLhaus, NVD, AbuseIPDB, OTX |
