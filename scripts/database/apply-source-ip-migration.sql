-- Add source_ip to sensor_discoveries for external connection visibility.
-- Merged into schema.sql for fresh deploys; run this once on existing databases.
-- See: docsv4/development/features/third-party-and-external-connections.md

ALTER TABLE sensor_discoveries
  ADD COLUMN IF NOT EXISTS source_ip INET;

CREATE INDEX IF NOT EXISTS idx_sensor_discoveries_source_ip
  ON sensor_discoveries(tenant_id, source_ip) WHERE source_ip IS NOT NULL;
