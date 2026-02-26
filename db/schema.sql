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
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(value, ioc_type)
);

CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_risk ON iocs(risk_score DESC);
CREATE INDEX idx_iocs_value_trgm ON iocs USING GIN(value gin_trgm_ops);

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
