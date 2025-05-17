-- Migration: Create materialized and analytical views
-- This script creates the materialized view for enriched archive + analysis data,
-- and several analytical views for reporting and querying.

BEGIN;

-- 1. Materialized view: enriched_archive_analysis_mv
-- Joins archive and analysis tables, flattening JSON fields and including feed metadata.
CREATE MATERIALIZED VIEW IF NOT EXISTS enriched_archive_analysis_mv AS
SELECT 
    ar.guid,
    ar.title,
    ar.link,
    ar.published,
    ar.content,
    an.severity_level,
    -- Extract numeric confidence percentage from string (e.g. '87%')
    regexp_replace(an.confidence, '[^0-9]', '', 'g')::integer AS confidence_pct,
    an.historical_context,
    an.summary_impact,
    an.relevance,
    an.additional_notes,
    an.source_name,
    an.source_url,
    an.feed_title,
    an.feed_description,
    an.feed_language,
    an.feed_icon,
    an.feed_updated,
    an.analysed_at,
    COALESCE(an.recommended_actions, '[]'::json) AS recommended_actions,
    COALESCE(an."key_IOCs", '[]'::json) AS key_iocs,
    COALESCE(an.affected_systems_sectors, '[]'::json) AS affected_systems_sectors,
    COALESCE(an.mitigation_strategies, '[]'::json) AS mitigation_strategies,
    COALESCE(an.potential_threat_actors, '[]'::json) AS potential_threat_actors,
    COALESCE(an.cve_references, '[]'::json) AS cve_references,
    COALESCE(an.ttps, '[]'::json) AS ttps,
    COALESCE(an.attack_vectors, '[]'::json) AS attack_vectors,
    COALESCE(an.tools_used, '[]'::json) AS tools_used,
    COALESCE(an.malware_families, '[]'::json) AS malware_families,
    COALESCE(an.target_geographies, '[]'::json) AS target_geographies,
    COALESCE(an.exploit_references, '[]'::json) AS exploit_references
FROM archive ar
JOIN analysis an USING (guid);

-- 2. analyses_by_source
-- Counts analyses grouped by source_name (feed)
CREATE OR REPLACE VIEW analyses_by_source AS
SELECT
    source_name,
    COUNT(*) AS analysis_count
FROM analysis
GROUP BY source_name
ORDER BY analysis_count DESC;

-- 3. avg_publication_to_analysis
-- Average time in hours between published date and analysis date
CREATE OR REPLACE VIEW avg_publication_to_analysis AS
SELECT
    AVG(EXTRACT(EPOCH FROM (analysed_at - published)) / 3600) AS avg_hours_to_analysis
FROM analysis
JOIN archive USING (guid)
WHERE published IS NOT NULL AND analysed_at IS NOT NULL;

-- 4. daily_analysis_timeline
-- Number of analyses per day
CREATE OR REPLACE VIEW daily_analysis_timeline AS
SELECT
    DATE(analysed_at) AS analysis_date,
    COUNT(*) AS analyses_count
FROM analysis
GROUP BY analysis_date
ORDER BY analysis_date;

-- 5. pending_archive_entries
-- Archive entries with no corresponding analysis yet
CREATE OR REPLACE VIEW pending_archive_entries AS
SELECT *
FROM archive ar
WHERE NOT EXISTS (
    SELECT 1 FROM analysis an WHERE an.guid = ar.guid
);

-- 6. recent_critical_alerts
-- Recent analyses with severity CRITICAL in last 30 days
CREATE OR REPLACE VIEW recent_critical_alerts AS
SELECT *
FROM analysis
WHERE severity_level = 'CRITICAL'
  AND analysed_at >= NOW() - INTERVAL '30 days'
ORDER BY analysed_at DESC;

-- 7. recent_summaries
-- Recent summaries from last 7 days
CREATE OR REPLACE VIEW recent_summaries AS
SELECT guid, summary_impact, analysed_at
FROM analysis
WHERE analysed_at >= NOW() - INTERVAL '7 days'
ORDER BY analysed_at DESC;

-- 8. severity_distribution
-- Count of analyses per severity level
CREATE OR REPLACE VIEW severity_distribution AS
SELECT
    severity_level,
    COUNT(*) AS count
FROM analysis
GROUP BY severity_level
ORDER BY count DESC;

-- 9. threat_timeline
-- Number of analyses per day grouped by severity
CREATE OR REPLACE VIEW threat_timeline AS
SELECT
    DATE(analysed_at) AS date,
    severity_level,
    COUNT(*) AS count
FROM analysis
GROUP BY date, severity_level
ORDER BY date, severity_level;

-- 10. top_recommended_actions
-- Top recommended actions by frequency (top 20)
CREATE OR REPLACE VIEW top_recommended_actions AS
SELECT
    action,
    COUNT(*) AS frequency
FROM analysis,
     jsonb_array_elements_text(COALESCE(recommended_actions::jsonb, '[]'::jsonb)) AS action
GROUP BY action
ORDER BY frequency DESC
LIMIT 20;

-- 11. top_threat_actors
-- Top potential threat actors by frequency (top 20)
CREATE OR REPLACE VIEW top_threat_actors AS
SELECT
    actor,
    COUNT(*) AS frequency
FROM analysis,
     jsonb_array_elements_text(COALESCE(potential_threat_actors::jsonb, '[]'::jsonb)) AS actor
GROUP BY actor
ORDER BY frequency DESC
LIMIT 20;

-- 12. unique_iocs
-- Unique IOCs extracted from all analyses
CREATE OR REPLACE VIEW unique_iocs AS
SELECT DISTINCT ioc
FROM analysis,
     jsonb_array_elements_text(COALESCE("key_IOCs"::jsonb, '[]'::jsonb)) AS ioc
ORDER BY ioc;

COMMIT;