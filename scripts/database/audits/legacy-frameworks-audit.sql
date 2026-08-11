-- Legacy compliance framework data audit (read-only).
--
-- Originally written to drive the retirement decision for the
-- compliance_frameworks / compliance_controls system (PR). After
-- retirement the script doubles as a sanity check: it reports the modern
-- framework system's row counts and confirms the legacy tables are gone
-- (or, on any cluster the retirement migration hasn't yet touched,
-- counts the rows that would block it).
--
-- Every query is gated on table existence via `to_regclass`, so the
-- script runs cleanly on both pre- and post-retirement clusters.
--
-- Usage:
--   psql -U <user> -d crypto_inventory -f legacy-frameworks-audit.sql
-- or, against the in-cluster Postgres:
--   kubectl -n vistaplatform exec -i <postgres-pod> -- \
--     psql -U crypto_user -d crypto_inventory \
--     < scripts/database/audits/legacy-frameworks-audit.sql
--
-- Read-only: every statement is SELECT or RAISE NOTICE. Safe on prod.

\echo '============================================================'
\echo ' VistaPlatform — Legacy compliance framework data audit'
\echo '============================================================'

-- ── Modern framework system (always exists post-platform-frameworks) ──
\echo ''
\echo '## Row counts — modern framework tables'

SELECT 'platform_frameworks'         AS table_name, COUNT(*) AS rows FROM public.platform_frameworks
UNION ALL
SELECT 'platform_framework_controls', COUNT(*) FROM public.platform_framework_controls
UNION ALL
SELECT 'tenant_frameworks',           COUNT(*) FROM public.tenant_frameworks
UNION ALL
SELECT 'tenant_framework_licenses',   COUNT(*) FROM public.tenant_framework_licenses
ORDER BY table_name;

-- ── Legacy tables: either retired (good) or still holding rows ──
\echo ''
\echo '## Legacy compliance tables — state per table'
\echo '   "retired" = dropped by PR #71'
\echo '   N        = still present, holds N rows (blocks retirement if > 0)'

DO $$
DECLARE
  cnt BIGINT;
  tbl TEXT;
BEGIN
  FOREACH tbl IN ARRAY ARRAY[
    'compliance_frameworks',
    'compliance_controls',
    'compliance_families',
    'compliance_control_keywords',
    'compliance_assessments'
  ] LOOP
    IF to_regclass('public.' || tbl) IS NULL THEN
      RAISE NOTICE '  % : retired', rpad(tbl, 32);
    ELSE
      EXECUTE format('SELECT COUNT(*) FROM public.%I', tbl) INTO cnt;
      RAISE NOTICE '  % : % rows', rpad(tbl, 32), cnt;
    END IF;
  END LOOP;
END $$;

-- ── compliance_overrides / compliance_scenarios framework_type breakdown ──
-- These tables survive but their framework_type enum was narrowed to
-- {'platform','tenant'} in PR. Any row still showing 'legacy' is a
-- pre-existing data quality issue.
\echo ''
\echo '## compliance_overrides by framework_type'

SELECT framework_type, COUNT(*) AS overrides
FROM public.compliance_overrides
GROUP BY framework_type
ORDER BY framework_type;

\echo ''
\echo '## compliance_scenarios by framework_type'

SELECT framework_type, COUNT(*) AS scenarios
FROM public.compliance_scenarios
GROUP BY framework_type
ORDER BY framework_type;

-- ── Orphaned FKs ──
-- Anything still pointing at compliance_frameworks/compliance_controls
-- after retirement is a bug. Pre-retirement, this is the "what blocks the
-- DROP" view.
\echo ''
\echo '## Foreign keys pointing at the legacy tables'
\echo '   (post-retirement: should be empty)'

SELECT
  conrelid::regclass        AS from_table,
  conname                   AS constraint_name,
  confrelid::regclass       AS to_table,
  pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE contype = 'f'
  AND confrelid::regclass::text IN ('compliance_frameworks', 'compliance_controls')
ORDER BY from_table, conname;

\echo ''
\echo '============================================================'
\echo ' END OF AUDIT'
\echo '============================================================'
