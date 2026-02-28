-- =============================================
-- Phase 1.4: Report Generation
-- Tables: reports, report_items
-- =============================================

-- Report status enum
DO $$ BEGIN
    CREATE TYPE report_status AS ENUM ('draft', 'review', 'published', 'archived');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Report type enum
DO $$ BEGIN
    CREATE TYPE report_type AS ENUM ('incident', 'threat_advisory', 'weekly_summary', 'ioc_bulletin', 'custom');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- =============================================
-- Reports
-- =============================================
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(500) NOT NULL,
    summary TEXT,                                    -- Executive summary (can be AI-generated)
    content JSONB NOT NULL DEFAULT '{}',             -- Rich content as structured JSON
    -- Classification
    report_type report_type NOT NULL DEFAULT 'custom',
    status report_status NOT NULL DEFAULT 'draft',
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',  -- critical, high, medium, low, info
    tlp VARCHAR(30) NOT NULL DEFAULT 'TLP:GREEN',    -- TLP marking
    -- Ownership
    author_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Template
    template VARCHAR(50),                            -- template slug (incident, advisory, weekly, ioc_bulletin)
    -- Counters (denormalized for fast queries)
    linked_intel_count INT NOT NULL DEFAULT 0,
    linked_ioc_count INT NOT NULL DEFAULT 0,
    linked_technique_count INT NOT NULL DEFAULT 0,
    -- Tags
    tags TEXT[] NOT NULL DEFAULT '{}',
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_reports_author ON reports(author_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_tags ON reports USING GIN(tags);

-- =============================================
-- Report Items (linked entities)
-- =============================================
CREATE TABLE IF NOT EXISTS report_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    item_type VARCHAR(30) NOT NULL,          -- intel, ioc, technique, cve
    item_id TEXT NOT NULL,                   -- UUID or string ID of linked entity
    item_title TEXT,                         -- Cached title for display without joins
    item_metadata JSONB DEFAULT '{}',        -- Cached key data (severity, risk_score, etc.)
    added_by UUID REFERENCES users(id),
    notes TEXT,                              -- Analyst notes for this item in context of report
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ri_report ON report_items(report_id);
CREATE INDEX IF NOT EXISTS idx_ri_item ON report_items(item_type, item_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ri_unique ON report_items(report_id, item_type, item_id);
