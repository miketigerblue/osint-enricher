-- Migration: Add indexes on materialized view for performance

BEGIN;

-- Index on guid for fast lookup by unique ID
CREATE INDEX IF NOT EXISTS idx_enriched_mv_guid ON enriched_archive_analysis_mv (guid);

-- Index on severity_level for filtering by severity
CREATE INDEX IF NOT EXISTS idx_enriched_mv_severity ON enriched_archive_analysis_mv (severity_level);

-- Index on published date for time-based queries
CREATE INDEX IF NOT EXISTS idx_enriched_mv_published ON enriched_archive_analysis_mv (published);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_enriched_archive_analysis_mv_guid
ON enriched_archive_analysis_mv (guid);

COMMIT;