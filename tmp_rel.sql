CREATE TABLE IF NOT EXISTS relationships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id       TEXT NOT NULL,
    source_type     VARCHAR(30) NOT NULL DEFAULT 'intel',
    target_id       TEXT NOT NULL,
    target_type     VARCHAR(30) NOT NULL DEFAULT 'intel',
    relationship_type VARCHAR(50) NOT NULL DEFAULT 'related-to',
    confidence      SMALLINT NOT NULL DEFAULT 50,
    auto_generated  BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships (source_id, source_type);
CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships (target_id, target_type);
CREATE INDEX IF NOT EXISTS idx_rel_type   ON relationships (relationship_type);
CREATE INDEX IF NOT EXISTS idx_rel_confidence ON relationships (confidence DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rel_unique_edge ON relationships (source_id, source_type, target_id, target_type, relationship_type);
