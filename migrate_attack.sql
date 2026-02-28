CREATE TABLE IF NOT EXISTS attack_techniques (
  id VARCHAR(20) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  tactic VARCHAR(60) NOT NULL,
  tactic_label VARCHAR(80) NOT NULL DEFAULT '',
  description TEXT DEFAULT '',
  url TEXT DEFAULT '',
  platforms TEXT[] DEFAULT '{}',
  detection TEXT DEFAULT '',
  is_subtechnique BOOLEAN DEFAULT FALSE,
  parent_id VARCHAR(20),
  data_sources TEXT[] DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attack_tactic ON attack_techniques(tactic);
CREATE INDEX IF NOT EXISTS idx_attack_parent ON attack_techniques(parent_id);
CREATE TABLE IF NOT EXISTS intel_attack_links (
  intel_id UUID NOT NULL,
  intel_ingested_at TIMESTAMPTZ NOT NULL,
  technique_id VARCHAR(20) NOT NULL REFERENCES attack_techniques(id) ON DELETE CASCADE,
  confidence SMALLINT DEFAULT 50,
  mapping_type VARCHAR(20) DEFAULT 'auto',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (intel_id, intel_ingested_at, technique_id),
  FOREIGN KEY (intel_id, intel_ingested_at) REFERENCES intel_items(id, ingested_at) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ial_technique ON intel_attack_links(technique_id);
