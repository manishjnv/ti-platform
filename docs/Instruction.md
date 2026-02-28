# IntelWatch — Engineering & Development Standards

> **Mandatory development contract.** All generated or modified code must comply with this document.
> This is the single source of truth for all development decisions.

---

## Table of Contents

- [Core Design Principles](#core-design-principles)
- [Configuration-Driven System](#%EF%B8%8F-configuration-driven-system)
- [Feature Implementation Standard](#-feature-implementation-standard-mandatory)
- [Data Freshness & Ordering](#-data-freshness--ordering)
- [Intel Enrichment Standards](#-intel-enrichment-standards)
- [Tooltip System](#-tooltip-system-mandatory)
- [Context-Aware Status Bar](#-context-aware-status-bar-persistent)
- [Data Pipeline Standard](#-data-pipeline-standard)
- [Security Requirements](#-security-requirements)
- [Observability](#-observability)
- [UX Standards](#-ux-standards)
- [Testing Requirements](#-testing-requirements)
- [Code Standards](#-code-standards)
- [Future Enhancement Readiness](#-future-enhancement-readiness)
- [Definition of Done](#-definition-of-done)
- [Instructions for AI Agents](#-instructions-for-ai-agents)

---

## Core Design Principles

### 1. Resilience First

The system must **never fail completely** due to external API failure, timeout, schema change, or partial data unavailability.

| Requirement | Detail |
|-------------|--------|
| Error handling | Centralized, with structured error types |
| Degradation | Graceful — show stale data, never blank screens |
| Retry | Exponential backoff (via `tenacity`) |
| Circuit breaker | For unstable/flaky external sources |
| Fallback | Cached responses for enrichment when API is down |

### 2. Performance by Design

- Async and non-blocking I/O for all collectors and enrichment
- **No duplicate API calls** — dedup at fetch and store layers
- Intelligent caching with configurable TTL (Redis)
- Lazy loading for heavy UI components
- Pagination / virtualization for large datasets

### 3. Modular & Replaceable Architecture

- No business logic inside UI — UI is a rendering layer only
- Source logic must stay inside its own adapter (`services/feeds/<source>.py`)
- Every module must be independently testable
- Base adapter pattern (`BaseFeedConnector`) for all data sources

---

## ⚙️ Configuration-Driven System

**Nothing must be hardcoded.** All of the following must be configurable via environment variables or database settings:

- API endpoints and base URLs
- Rate limits (per-source)
- Scoring logic weights
- Cache TTL values
- Feature flags
- Source priority / scheduling intervals

---

## 🆕 Feature Implementation Standard (MANDATORY)

### 🚫 Never Do

- Add logic into unrelated existing files
- Mix multiple features in one module
- Implement without tests and documentation

### ✅ Every New Feature MUST Create

| Layer | Required Artifacts |
|-------|--------------------|
| **Backend** | New service module, new route file, config entries, DB migration (if needed) |
| **Frontend** | New component(s), page (if needed), types, API client methods |
| **Shared** | Documentation update, test files |

### Feature Integration Checklist

Every feature must:

- [ ] Be **plug-and-play removable** — deleting the feature folder should not break anything
- [ ] Be **configuration-driven** — behavior controlled via config, not hardcoded
- [ ] Have **independent API routes** — own router prefix
- [ ] Have its **own state management scope** — no polluting shared stores
- [ ] **Not break existing modules** — zero regressions
- [ ] **Register itself** via a central feature registry

### Feature Registry

All new features must be registered in `core/feature_registry`. This enables:

- Dynamic loading / lazy initialization
- Feature flags (enable/disable without deploy)
- Future micro-frontend or microservice migration

---

## ⏱ Data Freshness & Ordering

- Latest intelligence always on top by default
- User-controlled sorting without triggering a refetch
- Every record must display:
  - **Source timestamp** — when the source published it
  - **First seen** — when IntelWatch first ingested it
  - **Last updated** — most recent update
  - **Relative time** — e.g., "2 hours ago"

---

## 🎯 Intel Enrichment Standards

### Impacted Asset Visibility

Always attempt to extract from ingested data:

- Product name
- Version
- Environment / platform
- CVE/CPE mapping

If any field is unavailable → display: `Not provided` (never leave blank).

---

## 🧠 Tooltip System (Mandatory)

Every data-driven UI element that shows a score, status, or enrichment value must have a tooltip displaying:

| Field | Example |
|-------|---------|
| Data source | "VirusTotal API v3" |
| Scoring logic | "5-factor weighted: KEV, severity, reliability, freshness, prevalence" |
| Confidence method | "Detection ratio: 45/72 engines" |
| Last enrichment time | "2026-02-28T10:22:00Z" |
| Normalization method | "VT APIv3 → unified intel_items schema" |

---

## 📱 Context-Aware Status Bar (Persistent)

The status bar must dynamically show (changing based on current page context):

- Active intel source(s)
- Record count in current view
- Last sync time
- API health indicator
- Cache status (hit/miss ratio)
- Active filters summary
- Background job progress
- Data freshness indicator
- Rate-limit usage (if applicable)

---

## 🧩 Data Pipeline Standard

```
Collector → Raw Storage → Normalization → Enrichment → Scoring → API → UI
```

### Pipeline Rules

1. **Store raw responses** — never discard original API data before normalization
2. **Maintain normalization versioning** — track schema changes over time
3. **Enrichment must be re-runnable** — idempotent, safe to retry

---

## 🔐 Security Requirements

| Area | Requirement |
|------|-------------|
| Secrets | Environment variables or vault — **never in code** |
| Input validation | At all layers (Pydantic schemas, SQL parameterization) |
| Output encoding | Sanitize all data rendered in UI |
| Authentication | All API endpoints require auth (except `/health`, `/auth/*`) |
| Audit logging | All mutations and enrichment calls logged to `audit_log` table |

---

## 📊 Observability

### Logging

- **Structured JSON logs** (via `structlog`)
- Correlation ID per request
- Error classification by type:

| Error Type | Example |
|------------|---------|
| `network` | Connection timeout, DNS failure |
| `parsing` | Malformed JSON, unexpected schema |
| `schema` | Missing required field, type mismatch |
| `rate_limit` | 429 response from external API |

### Metrics

| Metric | Purpose |
|--------|---------|
| Collector latency | Time to fetch from each external source |
| Enrichment latency | Time for enrichment pipeline per item |
| Cache hit ratio | Redis cache effectiveness |
| API response time | End-to-end request latency |

---

## 🎨 UX Standards

### Loading States

- **Skeleton loaders only** — no spinners, no full-screen blocking
- Show loading placeholders that match the layout of the expected content

### Data States

- **Never show empty screens** — always display:
  - Last available data (even if stale)
  - Stale data indicator (e.g., "Data from 2 hours ago")
  - Guidance text (e.g., "No results match your filters")

### Progressive Enrichment

- Render base intel data **immediately**
- Enrich asynchronously and update the UI progressively (no full-page reload)

---

## 🧪 Testing Requirements

Each module must include:

| Test Type | Scope |
|-----------|-------|
| **Unit tests** | Individual functions, normalization logic, scoring |
| **Integration tests** | API endpoint → database round-trip |
| **Schema validation tests** | Pydantic model validation, DB constraint checks |

---

## 📁 Code Standards

- **Strong typing required** — Python type hints everywhere, TypeScript strict mode
- **No magic values** — all constants must be named and configurable
- **Clear interface contracts** — abstract base classes for all extensible modules
- **Base adapter pattern** — all data sources inherit from `BaseFeedConnector`

---

## 🔄 Future Enhancement Readiness

The system must support:

- Plug-and-play intel sources (new connector = new file, register, done)
- Scoring engine replacement (swap algorithm without touching connectors)
- Schema evolution (migrations, backward compatibility)
- Multi-tenant architecture (future phase)

---

## 🚀 Definition of Done

A feature is **complete** only if:

- [ ] It follows this Instruction document
- [ ] It is modular and removable
- [ ] It includes tests
- [ ] It is observable (logs, metrics)
- [ ] It is configuration-driven
- [ ] It fails gracefully
- [ ] It does not degrade UI performance

---

## 🤖 Instructions for AI Agents

Before generating or modifying code:

1. **Read this `Instruction.md`** — validate the design against these standards
2. For every new feature:
   - Create new folder structure (don't bolt onto existing modules)
   - Create config entries
   - Create tests
   - Create documentation updates
3. **New module/feature implementation must not break existing modules**
4. Do not place feature logic in existing modules — create new files
5. Prefer extensibility over shortcuts
6. Ensure plug-and-play capability
7. **If a request violates these rules** → refactor the structure instead of forcing the implementation

> **This document is the mandatory development contract.**