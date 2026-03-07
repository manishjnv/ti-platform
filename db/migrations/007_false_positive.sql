-- Add false positive flag to extraction tables
ALTER TABLE intel_vulnerable_products ADD COLUMN IF NOT EXISTS is_false_positive BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE intel_threat_campaigns ADD COLUMN IF NOT EXISTS is_false_positive BOOLEAN NOT NULL DEFAULT FALSE;
