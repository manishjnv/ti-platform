-- IPinfo Lite enrichment columns on iocs table
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS asn          VARCHAR(20);
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS as_name      VARCHAR(200);
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS as_domain    VARCHAR(200);
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS country_code VARCHAR(5);
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS country      VARCHAR(100);
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS continent_code VARCHAR(5);
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS continent    VARCHAR(50);
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS enriched_at  TIMESTAMPTZ;

-- Indexes for common filter/group-by patterns
CREATE INDEX IF NOT EXISTS idx_iocs_country_code ON iocs(country_code) WHERE country_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iocs_asn          ON iocs(asn)          WHERE asn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iocs_enriched_at  ON iocs(enriched_at)  WHERE enriched_at IS NULL;
