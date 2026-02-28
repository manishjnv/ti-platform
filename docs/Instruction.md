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
- [Accessibility](#-accessibility-a11y)
- [Responsive Design](#-responsive-design)
- [API Versioning & Deprecation](#-api-versioning--deprecation)
- [Performance Budgets](#-performance-budgets)
- [Error Boundaries (UI)](#-error-boundaries-ui)
- [Rate Limiting (Own API)](#-rate-limiting-own-api)
- [Database Migration Strategy](#-database-migration-strategy)
- [Dependency Management](#-dependency-management)
- [Git & PR Conventions](#-git--pr-conventions)
- [Data Privacy](#-data-privacy)
- [Component Design System](#-component-design-system)
- [Graceful Shutdown](#-graceful-shutdown)
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

## ♿ Accessibility (a11y)

All UI must meet **WCAG 2.1 Level AA** compliance:

| Requirement | Standard |
|-------------|----------|
| Color contrast | Minimum 4.5:1 for normal text, 3:1 for large text |
| Keyboard navigation | All interactive elements reachable via Tab / Enter / Escape |
| ARIA labels | All icons, buttons, and interactive elements must have `aria-label` or `aria-labelledby` |
| Screen reader | Semantic HTML (`<nav>`, `<main>`, `<section>`, `<article>`) — no `<div>` soup |
| Focus indicators | Visible focus ring on all interactive elements |
| Alt text | All images and charts must have descriptive alt text or `aria-hidden` if decorative |
| Motion | Respect `prefers-reduced-motion` — disable animations when set |

---

## 📐 Responsive Design

| Breakpoint | Target | Min Width |
|------------|--------|----------|
| `sm` | Mobile | 640px |
| `md` | Tablet | 768px |
| `lg` | Desktop | 1024px |
| `xl` | Wide desktop | 1280px |
| `2xl` | Ultra-wide | 1536px |

- **Desktop-first** approach (analyst workstation is the primary device)
- Sidebar collapses to hamburger menu on `< lg`
- Charts and tables reflow to stacked layout on `< md`
- Touch targets minimum **44×44px** on mobile breakpoints
- Test all pages at each breakpoint before shipping

---

## 🔀 API Versioning & Deprecation

- All endpoints prefixed with `/api/v{N}` (currently `/api/v1`)
- **When to create a new version:**
  - Removing or renaming a field in a response
  - Changing response shape (e.g., nested → flat)
  - Changing authentication mechanism
- **Deprecation process:**
  1. Add `Deprecation` and `Sunset` HTTP headers to old endpoints
  2. Log usage of deprecated endpoints
  3. Minimum **90-day notice** before removal
  4. Document migration path in CHANGELOG
- **Non-breaking changes** (no new version needed): adding optional fields, new endpoints, new query parameters

---

## ⏱ Performance Budgets

All features must meet these measurable thresholds:

| Metric | Target | Hard Limit |
|--------|--------|------------|
| Page load (LCP) | < 1.5s | < 2.5s |
| API response (p95) | < 300ms | < 500ms |
| Time to Interactive | < 2s | < 3.5s |
| JS bundle (per route) | < 150KB gzipped | < 250KB gzipped |
| First Contentful Paint | < 1s | < 1.8s |
| Feed ingestion cycle | < 30s | < 60s |
| Database query (p95) | < 100ms | < 250ms |
| OpenSearch query (p95) | < 200ms | < 500ms |

- Monitor with Lighthouse CI or Web Vitals in production
- Performance regression = **blocker** — must fix before merge

---

## 🛡 Error Boundaries (UI)

- Every **page-level component** must be wrapped in a React Error Boundary
- Every **widget/card** should have its own error boundary — one failing card must not crash the page
- Error boundary UI must show:
  - A concise error message (not a stack trace)
  - A "Retry" button
  - Option to report the issue
- **Never show raw exceptions to users** — log them, display a friendly message
- Unhandled promise rejections must be caught globally and reported

---

## 🚦 Rate Limiting (Own API)

Protect IntelWatch's own API from abuse:

| Tier | Limit | Scope |
|------|-------|-------|
| Anonymous | Blocked (auth required) | — |
| Viewer | 60 req/min | Per user session |
| Analyst | 120 req/min | Per user session |
| Admin | 300 req/min | Per user session |
| Ingestion (internal) | Unlimited | Worker → API only |

- Return `429 Too Many Requests` with `Retry-After` header
- Rate limit state stored in Redis (sliding window)
- Exempt health check and auth endpoints

---

## 🗃 Database Migration Strategy

- All schema changes go through versioned migration files (`migrations/`)
- **Rules:**
  - Migrations must be **idempotent** — safe to run twice
  - Migrations must be **rollback-safe** — include a `DOWN` path
  - **Never** drop a column in the same release that stops using it — separate releases
  - Add new columns as `NULLABLE` or with defaults — zero-downtime compatibility
  - Large data migrations run as background jobs, not in migration scripts
- **Naming:** `YYYYMMDD_HHMMSS_description.sql` (e.g., `20260228_120000_add_attack_techniques.sql`)
- Test migrations against a copy of production data before deploying

---

## 📦 Dependency Management

| Practice | Tool |
|----------|------|
| Python deps | `pyproject.toml` with pinned versions |
| Node deps | `package.json` with lockfile (`package-lock.json`) |
| Vulnerability scanning | Dependabot or `pip-audit` / `npm audit` — run weekly |
| Update cadence | Patch updates: immediate. Minor: monthly. Major: evaluate in PR. |
| License compliance | Only permissive licenses (MIT, Apache 2.0, BSD). No GPL in runtime deps. |

- **Never** use `*` or `latest` for version specifiers
- Review and test dependency updates before merging
- Document breaking changes from dependency upgrades in CHANGELOG

---

## 🌿 Git & PR Conventions

### Branching Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready code — always deployable |
| `feature/<name>` | New features — branch from `main` |
| `fix/<name>` | Bug fixes — branch from `main` |
| `docs/<name>` | Documentation-only changes |

### Commit Message Format

```
<type>: <short description>

Types: feat, fix, docs, refactor, test, chore, perf
Examples:
  feat: add MITRE ATT&CK technique mapping
  fix: NVD date range causing RetryError
  docs: update INTEGRATION.md with VT status
```

### Code Review Requirements

- All PRs require **at least 1 reviewer** (when team grows)
- CI must pass (lint + build + tests)
- No force-pushes to `main`
- Squash merge preferred for feature branches

---

## 🔒 Data Privacy

- **No PII in logs** — mask email addresses, IP addresses in structured logs unless explicitly needed for security audit
- **Data minimization** — only collect and store data required for threat intelligence operations
- **Retention awareness** — all data must have a defined retention period (see Phase 3 retention policies)
- **User data:**
  - User accounts store only: email, name, role, last login
  - Session tokens expire after configurable TTL (default: 8 hours)
  - Deleted users → anonymize audit log entries
- **Third-party data:** respect TLP markings — never expose `TLP:RED` or `TLP:AMBER` data beyond authorized scope

---

## 🧱 Component Design System

### Naming Conventions

| Pattern | Example |
|---------|---------|
| Page components | `DashboardPage`, `IntelDetailPage` |
| Feature components | `FeedStatusPanel`, `ThreatLevelBar` |
| Primitive/UI components | `ui/button.tsx`, `ui/card.tsx`, `ui/badge.tsx` |
| Chart components | `charts/DonutChart`, `charts/TrendLineChart` |
| Layout components | `Sidebar`, `Header`, `PageContainer` |

### Component Rules

- **Single responsibility** — one component does one thing
- **Props over internal state** — prefer controlled components
- **Composition over inheritance** — use children/slots, not deep hierarchies
- **Co-locate** styles, types, and tests with the component
- All shared components go in `src/components/ui/` with documented prop contracts
- Feature-specific components live in their feature directory
- **No inline styles** — use Tailwind utility classes exclusively

---

## 🔌 Graceful Shutdown

All services must handle `SIGTERM` cleanly:

| Service | Shutdown Behavior |
|---------|-------------------|
| **API (Uvicorn)** | Stop accepting new requests, drain in-flight requests (30s timeout), close DB pool |
| **Worker (RQ)** | Finish current job (or checkpoint), then exit. Do not start new jobs. |
| **Scheduler** | Cancel pending timers, flush state, exit |
| **Redis / PostgreSQL / OpenSearch** | Managed by Docker — ensure `stop_grace_period` is set (default: 30s) |

- Docker Compose `stop_grace_period: 30s` on all app containers
- Workers must be **interruptible** — long jobs should checkpoint progress so they can resume
- Never leave orphaned locks in Redis on shutdown

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
- [ ] It meets accessibility standards (keyboard nav, ARIA labels, contrast)
- [ ] It meets performance budgets (LCP, bundle size, API latency)
- [ ] It has error boundaries at page and widget level
- [ ] Database changes have rollback-safe migrations
- [ ] No PII leaks in logs or API responses

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