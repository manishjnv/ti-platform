-- =============================================
-- IntelWatch TI Platform - PostgreSQL Schema
-- Requires: TimescaleDB extension
-- =============================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "timescaledb";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- =============================================
-- ENUM Types
-- =============================================
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info', 'unknown');
CREATE TYPE tlp_level AS ENUM ('TLP:RED', 'TLP:AMBER+STRICT', 'TLP:AMBER', 'TLP:GREEN', 'TLP:CLEAR');
CREATE TYPE feed_type AS ENUM ('vulnerability', 'ioc', 'malware', 'threat_actor', 'campaign', 'exploit', 'advisory');
CREATE TYPE asset_type AS ENUM ('ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email', 'cve', 'file', 'other');
CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer');
CREATE TYPE sync_status AS ENUM ('idle', 'running', 'success', 'failed');

-- =============================================
-- Users (synced from Cloudflare Zero Trust)
-- =============================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    role user_role NOT NULL DEFAULT 'viewer',
    avatar_url TEXT,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_users_email ON users(email);

-- =============================================
-- Unified Intel Items (core table)
-- =============================================
CREATE TABLE intel_items (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    summary TEXT,
    description TEXT,

    -- Timestamps
    published_at TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Classification
    severity severity_level NOT NULL DEFAULT 'unknown',
    risk_score SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence SMALLINT NOT NULL DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),

    -- Source
    source_name VARCHAR(100) NOT NULL,
    source_url TEXT,
    source_reliability SMALLINT NOT NULL DEFAULT 50 CHECK (source_reliability >= 0 AND source_reliability <= 100),
    source_ref VARCHAR(500),

    -- Categorisation
    feed_type feed_type NOT NULL,
    asset_type asset_type NOT NULL DEFAULT 'other',
    tlp tlp_level NOT NULL DEFAULT 'TLP:CLEAR',

    -- Arrays
    tags TEXT[] NOT NULL DEFAULT '{}',
    geo TEXT[] NOT NULL DEFAULT '{}',
    industries TEXT[] NOT NULL DEFAULT '{}',
    cve_ids TEXT[] NOT NULL DEFAULT '{}',
    affected_products TEXT[] NOT NULL DEFAULT '{}',

    -- Counters
    related_ioc_count INT NOT NULL DEFAULT 0,

    -- Exploitability
    is_kev BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_available BOOLEAN NOT NULL DEFAULT FALSE,
    exploitability_score REAL,

    -- AI
    ai_summary TEXT,
    ai_summary_at TIMESTAMPTZ,

    -- Dedup (unique index includes partition key, added after hypertable creation)
    source_hash VARCHAR(64) NOT NULL,

    -- Hypertable partition key
    PRIMARY KEY (id, ingested_at)
);

-- Convert to TimescaleDB hypertable for time-series performance
SELECT create_hypertable('intel_items', 'ingested_at', migrate_data => true);

-- Indexes for fast querying
CREATE INDEX idx_intel_severity ON intel_items(severity, ingested_at DESC);
CREATE INDEX idx_intel_risk ON intel_items(risk_score DESC, ingested_at DESC);
CREATE INDEX idx_intel_source ON intel_items(source_name, ingested_at DESC);
CREATE INDEX idx_intel_feed_type ON intel_items(feed_type, ingested_at DESC);
CREATE INDEX idx_intel_asset_type ON intel_items(asset_type, ingested_at DESC);
CREATE INDEX idx_intel_kev ON intel_items(is_kev) WHERE is_kev = TRUE;
CREATE INDEX idx_intel_tags ON intel_items USING GIN(tags);
CREATE INDEX idx_intel_cve ON intel_items USING GIN(cve_ids);
CREATE INDEX idx_intel_geo ON intel_items USING GIN(geo);
CREATE INDEX idx_intel_source_hash ON intel_items(source_hash, ingested_at DESC);
CREATE INDEX idx_intel_title_trgm ON intel_items USING GIN(title gin_trgm_ops);

-- =============================================
-- IOC (Indicators of Compromise)
-- =============================================
CREATE TABLE iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    value TEXT NOT NULL,
    ioc_type asset_type NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sighting_count INT NOT NULL DEFAULT 1,
    risk_score SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    tags TEXT[] NOT NULL DEFAULT '{}',
    geo TEXT[] NOT NULL DEFAULT '{}',
    source_names TEXT[] NOT NULL DEFAULT '{}',
    context JSONB DEFAULT '{}',
    -- IPinfo Lite enrichment
    asn VARCHAR(20),
    as_name VARCHAR(200),
    as_domain VARCHAR(200),
    country_code VARCHAR(5),
    country VARCHAR(100),
    continent_code VARCHAR(5),
    continent VARCHAR(50),
    enriched_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(value, ioc_type)
);

CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_risk ON iocs(risk_score DESC);
CREATE INDEX idx_iocs_value_trgm ON iocs USING GIN(value gin_trgm_ops);
CREATE INDEX idx_iocs_country_code ON iocs(country_code) WHERE country_code IS NOT NULL;
CREATE INDEX idx_iocs_asn ON iocs(asn) WHERE asn IS NOT NULL;
CREATE INDEX idx_iocs_enriched_at ON iocs(enriched_at) WHERE enriched_at IS NULL;

-- =============================================
-- Intel-IOC Link Table
-- =============================================
CREATE TABLE intel_ioc_links (
    intel_id UUID NOT NULL,
    intel_ingested_at TIMESTAMPTZ NOT NULL,
    ioc_id UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    relationship VARCHAR(50) NOT NULL DEFAULT 'associated',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (intel_id, intel_ingested_at, ioc_id),
    FOREIGN KEY (intel_id, intel_ingested_at) REFERENCES intel_items(id, ingested_at) ON DELETE CASCADE
);

-- =============================================
-- Feed Sync State
-- =============================================
CREATE TABLE feed_sync_state (
    feed_name VARCHAR(100) PRIMARY KEY,
    last_run TIMESTAMPTZ,
    last_success TIMESTAMPTZ,
    last_cursor TEXT,
    status sync_status NOT NULL DEFAULT 'idle',
    items_fetched INT NOT NULL DEFAULT 0,
    items_stored INT NOT NULL DEFAULT 0,
    error_message TEXT,
    run_count INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed feed state rows
INSERT INTO feed_sync_state (feed_name) VALUES
    ('nvd'), ('cisa_kev'), ('urlhaus'), ('abuseipdb'), ('otx'),
    ('virustotal'), ('shodan')
ON CONFLICT DO NOTHING;

-- =============================================
-- Audit Log
-- =============================================
CREATE TABLE audit_log (
    id BIGSERIAL,
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id TEXT,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
);

SELECT create_hypertable('audit_log', 'created_at', migrate_data => true);

-- =============================================
-- Risk Scoring Config
-- =============================================
CREATE TABLE scoring_config (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    weights JSONB NOT NULL DEFAULT '{
        "kev_presence": 25,
        "severity": 25,
        "source_reliability": 15,
        "freshness": 20,
        "ioc_prevalence": 15
    }',
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO scoring_config (name, is_active) VALUES ('default', TRUE)
ON CONFLICT DO NOTHING;

-- =============================================
-- MITRE ATT&CK Techniques
-- =============================================
CREATE TABLE attack_techniques (
    id VARCHAR(20) PRIMARY KEY,                    -- e.g. T1059, T1059.001
    name VARCHAR(255) NOT NULL,
    tactic VARCHAR(50) NOT NULL,                   -- e.g. execution, persistence
    tactic_label VARCHAR(100) NOT NULL,            -- e.g. Execution, Persistence
    description TEXT,
    url TEXT,
    platforms TEXT[] NOT NULL DEFAULT '{}',         -- e.g. {Windows, Linux, macOS}
    detection TEXT,
    is_subtechnique BOOLEAN NOT NULL DEFAULT FALSE,
    parent_id VARCHAR(20),                         -- e.g. T1059 for T1059.001
    data_sources TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_attack_tactic ON attack_techniques(tactic);
CREATE INDEX idx_attack_parent ON attack_techniques(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX idx_attack_name_trgm ON attack_techniques USING GIN(name gin_trgm_ops);

-- =============================================
-- Intel ↔ ATT&CK Link Table
-- =============================================
CREATE TABLE intel_attack_links (
    intel_id UUID NOT NULL,
    intel_ingested_at TIMESTAMPTZ NOT NULL,
    technique_id VARCHAR(20) NOT NULL REFERENCES attack_techniques(id) ON DELETE CASCADE,
    confidence SMALLINT NOT NULL DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
    mapping_type VARCHAR(30) NOT NULL DEFAULT 'auto',  -- auto | manual
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (intel_id, intel_ingested_at, technique_id),
    FOREIGN KEY (intel_id, intel_ingested_at) REFERENCES intel_items(id, ingested_at) ON DELETE CASCADE
);

CREATE INDEX idx_ial_technique ON intel_attack_links(technique_id);

-- =============================================
-- Entity Relationships (Graph)
-- =============================================
CREATE TABLE relationships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_id TEXT NOT NULL,              -- UUID or string ID of source entity
    source_type VARCHAR(30) NOT NULL,     -- intel | ioc | technique | cve
    target_id TEXT NOT NULL,              -- UUID or string ID of target entity
    target_type VARCHAR(30) NOT NULL,     -- intel | ioc | technique | cve
    relationship_type VARCHAR(50) NOT NULL DEFAULT 'related-to',  -- related-to | uses | indicates | targets | exploits | shares-ioc | shares-cve | co-occurs
    confidence SMALLINT NOT NULL DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
    auto_generated BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}',          -- extra context: shared IOC values, matching keywords, etc.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rel_source ON relationships(source_id, source_type);
CREATE INDEX idx_rel_target ON relationships(target_id, target_type);
CREATE INDEX idx_rel_type ON relationships(relationship_type);
CREATE INDEX idx_rel_confidence ON relationships(confidence DESC);
-- Prevent duplicate edges
CREATE UNIQUE INDEX idx_rel_unique_edge ON relationships(source_id, source_type, target_id, target_type, relationship_type);

-- =============================================
-- Notification Rules
-- =============================================
CREATE TABLE notification_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    description TEXT,
    rule_type VARCHAR(50) NOT NULL DEFAULT 'threshold',  -- threshold | keyword | feed_error | risk_change | correlation
    conditions JSONB NOT NULL DEFAULT '{}',
    -- Example conditions:
    -- {"severity": ["critical","high"], "min_risk_score": 80}
    -- {"cve_ids": ["CVE-2024-1234"], "match_mode": "any"}
    -- {"feed_names": ["nvd","cisa_kev"], "event": "error"}
    -- {"risk_change_min": 20}
    channels TEXT[] NOT NULL DEFAULT '{in_app}',  -- in_app, browser_push, webhook
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,   -- system-default rules (non-deletable)
    cooldown_minutes INT NOT NULL DEFAULT 15,   -- mins before same rule can fire again
    last_triggered_at TIMESTAMPTZ,
    trigger_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_nr_user ON notification_rules(user_id);
CREATE INDEX idx_nr_active ON notification_rules(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_nr_type ON notification_rules(rule_type);

-- =============================================
-- Notifications
-- =============================================
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES notification_rules(id) ON DELETE SET NULL,
    title VARCHAR(300) NOT NULL,
    message TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',     -- critical, high, medium, low, info
    category VARCHAR(50) NOT NULL DEFAULT 'alert',    -- alert, feed_error, risk_change, correlation, system
    entity_type VARCHAR(30),                          -- intel, ioc, feed, cve
    entity_id TEXT,                                   -- UUID or identifier of related entity
    metadata JSONB NOT NULL DEFAULT '{}',             -- extra context (risk scores, feed names, CVEs, etc.)
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notif_user ON notifications(user_id, created_at DESC);
CREATE INDEX idx_notif_unread ON notifications(user_id, is_read) WHERE is_read = FALSE;
CREATE INDEX idx_notif_category ON notifications(category, created_at DESC);
CREATE INDEX idx_notif_entity ON notifications(entity_type, entity_id) WHERE entity_id IS NOT NULL;

-- =============================================
-- Materialized Views for Dashboard
-- =============================================
CREATE MATERIALIZED VIEW mv_severity_distribution AS
SELECT
    severity,
    feed_type,
    COUNT(*) as count,
    AVG(risk_score) as avg_risk_score
FROM intel_items
WHERE ingested_at > NOW() - INTERVAL '30 days'
GROUP BY severity, feed_type;

CREATE UNIQUE INDEX idx_mv_severity ON mv_severity_distribution(severity, feed_type);

CREATE MATERIALIZED VIEW mv_top_risks AS
SELECT
    id, ingested_at, title, severity, risk_score,
    source_name, feed_type, asset_type, cve_ids,
    is_kev, tags, published_at
FROM intel_items
WHERE risk_score >= 70
ORDER BY risk_score DESC, ingested_at DESC
LIMIT 100;

CREATE UNIQUE INDEX idx_mv_top_risks ON mv_top_risks(id, ingested_at);

-- Refresh function
CREATE OR REPLACE FUNCTION refresh_dashboard_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_severity_distribution;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_top_risks;
END;
$$ LANGUAGE plpgsql;

-- ─── Reports ────────────────────────────────────────────

DO $$ BEGIN
    CREATE TYPE report_status AS ENUM ('draft','review','published','archived');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE report_type AS ENUM ('incident','threat_advisory','weekly_summary','ioc_bulletin','custom');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS reports (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title          VARCHAR(500) NOT NULL,
    summary        TEXT,
    content        JSONB NOT NULL DEFAULT '{}',
    report_type    report_type NOT NULL DEFAULT 'custom',
    status         report_status NOT NULL DEFAULT 'draft',
    severity       severity_level NOT NULL DEFAULT 'medium',
    tlp            tlp_level NOT NULL DEFAULT 'TLP:GREEN',
    author_id      UUID NOT NULL REFERENCES users(id),
    template       VARCHAR(50),
    linked_intel_count     INTEGER NOT NULL DEFAULT 0,
    linked_ioc_count       INTEGER NOT NULL DEFAULT 0,
    linked_technique_count INTEGER NOT NULL DEFAULT 0,
    tags           TEXT[] NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS report_items (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id       UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    item_type       VARCHAR(30) NOT NULL,
    item_id         TEXT NOT NULL,
    item_title      TEXT,
    item_metadata   JSONB NOT NULL DEFAULT '{}',
    added_by        UUID REFERENCES users(id),
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(report_id, item_type, item_id)
);

CREATE INDEX IF NOT EXISTS idx_reports_author   ON reports(author_id);
CREATE INDEX IF NOT EXISTS idx_reports_status   ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_type     ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_created  ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_tags     ON reports USING gin(tags);
CREATE INDEX IF NOT EXISTS idx_report_items_report ON report_items(report_id);
CREATE INDEX IF NOT EXISTS idx_report_items_type   ON report_items(item_type, item_id);

-- =============================================
-- User Settings (per-user preferences)
-- =============================================
CREATE TABLE IF NOT EXISTS user_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    preferences JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
