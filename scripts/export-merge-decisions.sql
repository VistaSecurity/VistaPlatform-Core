-- export-merge-decisions.sql — a tenant's resolved merge proposals, as matcher
-- training samples ( Phase 5).
--
-- Output: ONE JSON array in exactly the shape of
-- shared/identity/matcher/testdata/fixtures.json, ready for
--
--   go run ./cmd/train-matcher -decisions decisions.json -out weights.json
--
-- Run it as an operator, against the tenant's database, with the tenant set:
--
--   psql "$DATABASE_URL" -X -q -At -v tenant_id=<tenant-uuid> \
--        -f scripts/export-merge-decisions.sql > decisions.json
--
-- What makes it LOSSLESS: since matcher v2 every proposal row carries the
-- matcher's whole view of both sides at the moment it was opened —
-- `observation_identifiers` + `observation_context` for the sighting, and
-- `candidate_snapshots` (keyed by asset id) for each record it was compared
-- with. Nothing is reconstructed from `assets` after the fact. That matters
-- most for a MERGED proposal: the survivor now holds the observation's
-- identifiers, so a reconstruction would agree on everything and hand the model
-- its own label. Rows written before v2 carry none of those keys and are
-- skipped rather than guessed at.
--
-- The labels — a person's decision, and nothing else:
--   * `kept_separate`  → every candidate is `"match": false`;
--   * `merged`         → a candidate is `"match": true` when it is the survivor
--     (`merged_into`) or was itself merged into that survivor
--     (`assets.metadata.merged_into`). A candidate that is neither is not
--     labelled — its fate is not recorded on the row, and a guess is not an
--     answer;
--   * `pending`, `superseded` → not a label. An unanswered question fed in as
--     a negative teaches the model to agree with whatever the queue has not got
--     to yet;
-- * no `resolved_by` (a rule's merge, Phase 4) or `auto_accepted`
--     (the model's own) → skipped: training a model on its own decisions, or on
--     a rule's, is a feedback loop, not a label.
--
-- The file holds identifier VALUES (serials, MACs, names) because the feature
-- extractor compares them. It is tenant data: keep it under the tenant's
-- control and delete it after training.
--
-- The query between the EXPORT markers is also run by
-- TestIntegration_ExportMergeDecisions (shared/identity/postgres), which holds
-- it to the matcher's own parser and to the scores the proposal recorded.

\set ON_ERROR_STOP on
\set QUIET on
BEGIN READ ONLY;
SELECT set_config('app.tenant_id', :'tenant_id', true) \g /dev/null

-- EXPORT BEGIN
WITH decided AS (
    SELECT h.id, h.changes_json AS cj
      FROM public.asset_history h
     WHERE h.tenant_id = (:'tenant_id')::uuid
       AND h.action = 'merge_proposed'
       AND h.changes_json ->> 'kind' = 'merge_proposal'
       AND coalesce(h.changes_json ->> 'resolved_by', '') <> ''
       AND coalesce((h.changes_json ->> 'auto_accepted')::boolean, false) = false
       AND jsonb_typeof(h.changes_json -> 'observation_identifiers') = 'array'
       AND jsonb_typeof(h.changes_json -> 'candidate_snapshots') = 'array'
),
pairs AS (
    SELECT d.id,
           d.cj,
           snap.value AS snap,
           -- NULL is "not a label" and is dropped below.
           CASE d.cj ->> 'status'
               WHEN 'kept_separate' THEN false
               WHEN 'merged' THEN CASE
                   WHEN snap.value ->> 'asset_id' = d.cj ->> 'merged_into' THEN true
                   WHEN a.metadata ->> 'merged_into' = d.cj ->> 'merged_into' THEN true
               END
           END AS match
      FROM decided d
     CROSS JOIN LATERAL jsonb_array_elements(d.cj -> 'candidate_snapshots') AS snap(value)
      LEFT JOIN public.assets a
        ON a.tenant_id = (:'tenant_id')::uuid
       AND a.id::text = snap.value ->> 'asset_id'
),
samples AS (
    SELECT p.id,
           p.snap ->> 'asset_id' AS candidate_id,
           jsonb_build_object(
               'name', 'decision/' || p.id || '/' || (p.snap ->> 'asset_id'),
               'match', p.match,
               'observation', jsonb_strip_nulls(jsonb_build_object(
                   'name',        nullif(p.cj -> 'observation_context' ->> 'name', ''),
                   'class',       nullif(p.cj -> 'observation_context' ->> 'class', ''),
                   'segment',     nullif(p.cj -> 'observation_context' ->> 'segment', ''),
                   'vendor',      nullif(p.cj -> 'observation_context' ->> 'vendor', ''),
                   'model',       nullif(p.cj -> 'observation_context' ->> 'model', ''),
                   'source_kind', nullif(p.cj -> 'observation_context' ->> 'source_kind', ''),
                   'seen_at',     nullif(p.cj -> 'observation_context' ->> 'seen_at', ''),
                   'identifiers',         (SELECT jsonb_object_agg(k, v) FROM (
                        SELECT i ->> 'kind' AS k, jsonb_agg(DISTINCT i ->> 'value') AS v
                          FROM jsonb_array_elements(p.cj -> 'observation_identifiers') i GROUP BY 1) g),
                   'derived_identifiers', (SELECT jsonb_object_agg(k, v) FROM (
                        SELECT i ->> 'kind' AS k, jsonb_agg(DISTINCT i ->> 'value') AS v
                          FROM jsonb_array_elements(p.cj -> 'observation_identifiers') i
                         WHERE coalesce((i ->> 'derived')::boolean, false) GROUP BY 1) g),
                   'generic_names',       (SELECT jsonb_agg(DISTINCT i ->> 'value')
                          FROM jsonb_array_elements(p.cj -> 'observation_identifiers') i
                         WHERE coalesce((i ->> 'generic')::boolean, false))
               )),
               'candidate', jsonb_strip_nulls(jsonb_build_object(
                   'name',        nullif(p.snap ->> 'name', ''),
                   'class',       nullif(p.snap ->> 'class', ''),
                   'segment',     nullif(p.snap ->> 'segment', ''),
                   'vendor',      nullif(p.snap ->> 'vendor', ''),
                   'model',       nullif(p.snap ->> 'model', ''),
                   'source_kind', nullif(p.snap ->> 'source_kind', ''),
                   'seen_at',     nullif(p.snap ->> 'seen_at', ''),
                   'identifiers',         (SELECT jsonb_object_agg(k, v) FROM (
                        SELECT i ->> 'kind' AS k, jsonb_agg(DISTINCT i ->> 'value') AS v
                          FROM jsonb_array_elements(coalesce(p.snap -> 'identifiers', '[]'::jsonb)) i GROUP BY 1) g),
                   'derived_identifiers', (SELECT jsonb_object_agg(k, v) FROM (
                        SELECT i ->> 'kind' AS k, jsonb_agg(DISTINCT i ->> 'value') AS v
                          FROM jsonb_array_elements(coalesce(p.snap -> 'identifiers', '[]'::jsonb)) i
                         WHERE coalesce((i ->> 'derived')::boolean, false) GROUP BY 1) g)
               ))
           ) AS sample
      FROM pairs p
     WHERE p.match IS NOT NULL
)
SELECT coalesce(jsonb_pretty(jsonb_agg(sample ORDER BY id, candidate_id)), '[]')
  FROM samples;
-- EXPORT END

COMMIT;
