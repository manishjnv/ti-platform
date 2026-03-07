-- =============================================
-- Enrichment Features Migration
-- 2026-03-07: Org profile, threat briefs, detection rules
-- =============================================

-- Organization profile stored in user_settings.preferences as JSON keys:
--   org_sector, org_region, org_tech_stack[], org_size
-- No new table needed — leverages existing user_settings table.

-- =============================================
-- Threat Briefings (AI-generated summaries)
-- =============================================
CREATE TABLE IF NOT EXISTS threat_briefings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    period VARCHAR(20) NOT NULL,            -- daily, weekly
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    title VARCHAR(500) NOT NULL,
    executive_summary TEXT NOT NULL,
    key_campaigns JSONB NOT NULL DEFAULT '[]',   -- [{name, severity, article_count, sectors, actors}]
    key_vulnerabilities JSONB NOT NULL DEFAULT '[]', -- [{cve_id, product, severity, exploit, kev}]
    key_actors JSONB NOT NULL DEFAULT '[]',      -- [{name, campaign_count, article_count}]
    sector_threats JSONB NOT NULL DEFAULT '{}',   -- {sector: [{campaign, severity}]}
    stats JSONB NOT NULL DEFAULT '{}',           -- {new_campaigns, new_cves, new_iocs, kev_added, articles_processed}
    recommendations TEXT[] NOT NULL DEFAULT '{}',
    raw_data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_briefings_period ON threat_briefings(period, period_start DESC);

-- =============================================
-- Detection Rules Library (aggregated from news)
-- =============================================
CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_type VARCHAR(20) NOT NULL,       -- yara, kql, sigma
    name VARCHAR(300) NOT NULL,
    content TEXT NOT NULL,
    source_news_id UUID REFERENCES news_items(id) ON DELETE SET NULL,
    campaign_name VARCHAR(300),
    technique_ids TEXT[] NOT NULL DEFAULT '{}',
    cve_ids TEXT[] NOT NULL DEFAULT '{}',
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    quality_score SMALLINT NOT NULL DEFAULT 50 CHECK (quality_score >= 0 AND quality_score <= 100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_type ON detection_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_detection_rules_campaign ON detection_rules(campaign_name) WHERE campaign_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_detection_rules_techniques ON detection_rules USING GIN(technique_ids);
CREATE INDEX IF NOT EXISTS idx_detection_rules_cves ON detection_rules USING GIN(cve_ids);
