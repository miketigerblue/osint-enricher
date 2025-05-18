-- ============================================================
-- Migration Script: Create web_anon role and assign permissions
-- ============================================================

-- Step 1: Create the 'web_anon' role if it doesn't already exist.
-- This role is our friendly neighborhood anonymous user,
-- who can peek but not poke (NOLOGIN for safety).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = 'web_anon'
    ) THEN
        CREATE ROLE web_anon NOLOGIN;
        RAISE NOTICE 'Role "web_anon" created: anonymous but harmless.';
    ELSE
        RAISE NOTICE 'Role "web_anon" already exists: stealthy as ever.';
    END IF;
END
$$;

-- Step 2: Grant connect privileges on the database.
-- Because even anonymous users need to knock on the door before entering.
GRANT CONNECT ON DATABASE osint TO web_anon;

-- Step 3: Grant usage on the public schema.
-- This lets 'web_anon' see the furniture without moving it.
GRANT USAGE ON SCHEMA public TO web_anon;

-- Step 4: Grant SELECT on base tables.
-- Allow reading the raw data, but no funny business.
GRANT SELECT ON TABLE archive TO web_anon;
GRANT SELECT ON TABLE analysis TO web_anon;
GRANT SELECT ON TABLE current TO web_anon;

-- Step 5: Grant SELECT on views.
-- Views are like curated exhibits—safe to browse.
GRANT SELECT ON TABLE analyses_by_source TO web_anon;
GRANT SELECT ON TABLE avg_publication_to_analysis TO web_anon;
GRANT SELECT ON TABLE daily_analysis_timeline TO web_anon;
GRANT SELECT ON TABLE pending_archive_entries TO web_anon;
GRANT SELECT ON TABLE recent_critical_alerts TO web_anon;
GRANT SELECT ON TABLE recent_summaries TO web_anon;
GRANT SELECT ON TABLE severity_distribution TO web_anon;
GRANT SELECT ON TABLE threat_timeline TO web_anon;
GRANT SELECT ON TABLE top_recommended_actions TO web_anon;
GRANT SELECT ON TABLE top_threat_actors TO web_anon;
GRANT SELECT ON TABLE unique_iocs TO web_anon;

-- Step 6: Grant SELECT on materialized views.
-- Materialized views are big data snapshots—read-only, but powerful.
GRANT SELECT ON TABLE enriched_archive_analysis_mv TO web_anon;
GRANT SELECT ON TABLE mv_threat_grouped_by_source TO web_anon;


-- Bonus Step: For extra security, revoke all other privileges from web_anon.
-- Because principle of least privilege is our middle name.
REVOKE ALL ON SCHEMA public FROM web_anon;
REVOKE ALL ON DATABASE osint FROM web_anon;

-- And then re-grant only what we explicitly want:
GRANT CONNECT ON DATABASE osint TO web_anon;
GRANT USAGE ON SCHEMA public TO web_anon;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO web_anon;