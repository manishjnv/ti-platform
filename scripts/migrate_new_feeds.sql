-- Migration: Add ThreatFox and MalwareBazaar to feed_sync_state
-- Run on live database after deploying the new connectors

INSERT INTO feed_sync_state (feed_name) VALUES
    ('threatfox'),
    ('malwarebazaar')
ON CONFLICT DO NOTHING;
