// Package services: asset facet aggregation queries.
package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// assetFacetExpr maps a facet level to the SQL that produces its bucket key.
//
// The vocabulary is ADR-0006 D2's: class, status, environment, site, segment,
// owner, business unit, tag, risk band, provenance, and has-open-findings. The
// older spellings (`asset_type`, `location.region`, …) are kept as aliases so a
// saved view built before the rename keeps working.
//
// Every expression here is CODE, never user text — the level is looked up in
// this map and an unknown one is refused. That is what keeps a facet level from
// reaching SQL as an identifier.
var assetFacetExpr = map[string]string{
	// Assets / context
	"business_unit": "COALESCE(a.business_unit, 'Unknown')",
	"environment":   "COALESCE(a.environment::text, 'Unknown')",
	"owner_email":   "COALESCE(a.owner_email, 'Unknown')",
	"owner":         "COALESCE(a.owner_email, 'Unknown')",
	"support_group": "COALESCE(a.support_group, 'Unknown')",
	"status":        "COALESCE(a.asset_status::text, 'Unknown')",
	"ownership":     "COALESCE(a.asset_ownership::text, 'Unknown')",
	"stale_status":  "COALESCE(a.stale_status, 'Unknown')",

	// Location
	"site":              "COALESCE(a.site, a.tags->'location'->>'site', a.tags->>'site', 'Unknown')",
	"region":            "COALESCE(a.region, a.tags->'location'->>'region', a.tags->>'region', 'Unknown')",
	"zone":              "COALESCE(a.zone, a.tags->'location'->>'zone', a.tags->>'zone', 'Unknown')",
	"location.site":     "COALESCE(a.site, a.tags->'location'->>'site', a.tags->>'site', 'Unknown')",
	"location.region":   "COALESCE(a.region, a.tags->'location'->>'region', a.tags->>'region', 'Unknown')",
	"location.zone":     "COALESCE(a.zone, a.tags->'location'->>'zone', a.tags->>'zone', 'Unknown')",
	"location.building": "COALESCE(a.tags->'location'->>'building', a.tags->>'building', 'Unknown')",

	"segment": "COALESCE(ns.name, 'Unsegmented')",

	// Class attributes
	"operating_system": "COALESCE(" + assetOperatingSystemSQL + ", 'Unknown')",

	// Provenance: HOW the class was decided (measured / declared / imported /
	// inferred), which is ADR-0006 D2's "discovered, imported, declared,
	// proposed" facet under the names the column actually holds.
	"source":            "COALESCE(a.class_source_kind, 'Unknown')",
	"class_source_kind": "COALESCE(a.class_source_kind, 'Unknown')",
	"proposed_by":       "COALESCE(a.class_source_ref, 'Unknown')",
}

// assetFacetLevelAliases resolves the levels that are not a plain column
// expression, because they aggregate something.
const (
	facetLevelClass        = "class"
	facetLevelRisk         = "risk"
	facetLevelTag          = "tag"
	facetLevelHasFindings  = "has_findings"
	facetLevelHasEndpoints = "has_endpoints"
)

// `has_findings` is back (workstream 3.1), because there is now ONE findings
// table and the count and the click can finally be the same question.
//
// It was withdrawn in Gate 1 for a reason worth keeping in view: it counted
// `compliance_findings` by `asset_id` while the rail's click wrote a
// `finding:(…)` term, which the query language resolves over `findings` and
// over the asset's DESCENDANTS as well. Two tables, two subject vocabularies,
// one question — so the rail's number described a different set from the list
// it led to.
//
// The repair is not "point the old EXISTS at the new table". It is to stop
// having a second expression at all: the facet COMPILES findings.OpenQuery —
// the exact text the rail writes — through the SAME translator the list
// compiles, so the count and the click are the same predicate by construction
// rather than by agreement. TestIntegration_HasFindingsFacet_AgreesWithQuery
// drives both against one fixture and fails if they diverge.
func (s *AssetService) hasFindingsFacet(tenantID uuid.UUID, where string, args []interface{}) ([]models.AssetFacetBucket, error) {
	compiled, err := CompileAssetQuery(findings.OpenQuery, QueryTargetAsset, len(args)+1, assetQueryAlias)
	if err != nil {
		// Unreachable unless the constant stops parsing, which is a build-time
		// mistake wearing a runtime disguise — so it is reported, not swallowed
		// into an empty count.
		return nil, fmt.Errorf("compiling the open-findings predicate failed: %w", err)
	}
	return s.booleanFacet(tenantID, where, append(args, compiled.Args...), compiled.Where)
}

// GetAssetFacets returns bucket counts for one facet level over the SAME
// population the asset list shows.
//
// It compiles the same predicate the list compiles — the caller's `?query=`
// AND the translated legacy filters — so a count beside a list can no longer
// describe a different set from the list itself. Before, two hand-written
// WHERE-builders ran side by side and drifted; there is now one.
//
// Nothing here aggregates crypto: the risk facet reads the persisted per-asset
// rollup, so a bucket counts ASSETS and the buckets are mutually exclusive.
// The old query grouped by the facet key over a join to crypto_implementations
// and took a MAX inside it, which made one 75-scoring configuration report
// every asset in a business unit as high risk.
func (s *AssetService) GetAssetFacets(tenantID uuid.UUID, filters models.AssetFilters, level string, limit int) ([]models.AssetFacetBucket, error) {
	if limit <= 0 {
		limit = 50
	}
	level = strings.ToLower(strings.TrimSpace(level))

	// The SAME validation the list runs. Skipping it meant a filter value the
	// list REJECTS — an environment that is not an environment, a risk band that
	// is not a band — was accepted here and counted nothing, so the rail showed
	// zeroes beside a list that showed a 400. Two answers to one question, and
	// the silent one was the wrong one.
	if err := validateAssetFilters(filters); err != nil {
		return nil, err
	}

	pred, err := buildAssetWhere(filters.Query, filters, 2, assetQueryAlias)
	if err != nil {
		return nil, err
	}
	args := append([]interface{}{tenantID}, pred.Args...)
	where := "a.tenant_id = $1 AND a.deleted_at IS NULL AND (" + pred.Where + ")"
	discoveryWhere, args := discoverySourcePredicate(filters, args)
	where += discoveryWhere

	switch level {
	case facetLevelClass:
		return s.classFacets(tenantID, where, args, limit)
	case facetLevelRisk:
		return s.riskFacets(tenantID, where, args)
	case facetLevelTag:
		return s.tagFacets(tenantID, where, args, limit)
	case facetLevelHasFindings:
		return s.hasFindingsFacet(tenantID, where, args)
	case facetLevelHasEndpoints:
		return s.booleanFacet(tenantID, where, args,
			`EXISTS (SELECT 1 FROM asset_endpoints fe WHERE fe.tenant_id = a.tenant_id AND fe.asset_id = a.id)`)
	}

	expr, ok := assetFacetExpr[level]
	if !ok {
		// `asset_type` was the old name for the class facet and its buckets were
		// class keys, so it redirects rather than erroring: a saved view that
		// still asks for it gets the facet it meant.
		if level == "asset_type" {
			return s.classFacets(tenantID, where, args, limit)
		}
		return nil, fmt.Errorf("unsupported facet level: %s", level)
	}

	args = append(args, limit)
	query := fmt.Sprintf(`
		SELECT %s AS "key", COUNT(*) AS "count"
		FROM assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		WHERE %s
		GROUP BY 1
		ORDER BY "count" DESC, "key" ASC
		LIMIT $%d`, expr, where, len(args))
	return s.facetRows(tenantID, query, args)
}

// classFacets counts each class and every ANCESTOR of it, so picking "Hardware"
// in the rail shows the count of the whole branch and drilling to "Server"
// narrows it.
//
// The hierarchy comes from `class_path`, the materialised ancestry the class
// registry writes: a row at `hardware.computer.server` contributes to
// `hardware`, `hardware.computer` and `hardware.computer.server`. Counting only
// leaves would make every parent read zero, which is how a hierarchical facet
// usually goes wrong; summing children in the UI instead would make the rail's
// arithmetic a second implementation of the taxonomy.
func (s *AssetService) classFacets(tenantID uuid.UUID, where string, args []interface{}, limit int) ([]models.AssetFacetBucket, error) {
	// GROUPED BEFORE EXPANDED, and that ordering is the whole performance story
	// of this query — it was the dashboard's costliest at 243 ms on a 50,000-asset
	// tenant and is 13 ms written this way (measured; see the PR that changed it).
	//
	// The old shape expanded every ASSET into its ancestor prefixes and then
	// grouped, so the LATERAL ran 50,000 times. The cost was not the work: the
	// expansion itself took 76 ms. It was that `generate_series(1, <expr>)` has
	// no row estimate, so the planner assumed 1,000 rows per asset, costed the
	// join at fifty million rows, and crossed the JIT threshold — 164 of the
	// 243 ms were spent COMPILING a plan for a query that touches 1,389 pages.
	//
	// A class path is an identity, not a per-asset value: a tenant has a dozen
	// distinct ones however many assets it has. Counting them first and summing
	// the counts across the expansion gives the same numbers (verified row for
	// row at 50k) off twelve LATERAL calls instead of fifty thousand, and the
	// estimate that comes out of it never reaches the JIT threshold.
	//
	// A covering `(tenant_id, class_path) WHERE deleted_at IS NULL` index was
	// measured too and is NOT here: the planner does not choose it — one
	// tenant's assets live in one of eight hash partitions and a sequential scan
	// of it beats an index scan plus visibility-map checks — so it would have
	// bought nothing and cost a write on every asset upsert.
	//
	// `sum(...)::bigint`, not bare `sum`: sum over bigint returns NUMERIC, which
	// the row scanner would refuse.
	query := fmt.Sprintf(`
		WITH matched AS (
			SELECT a.class_path, COUNT(*) AS n
			FROM assets a
			LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
			WHERE %s
			GROUP BY a.class_path
		),
		expanded AS (
			SELECT array_to_string(p.parts[1:i], '.') AS path, m.n
			FROM matched m
			CROSS JOIN LATERAL (SELECT string_to_array(m.class_path, '.') AS parts) p
			CROSS JOIN LATERAL generate_series(1, cardinality(p.parts)) AS i
		)
		SELECT path AS "key", sum(n)::bigint AS "count"
		FROM expanded
		GROUP BY path
		ORDER BY "count" DESC, "key" ASC
		LIMIT $%d`, where, len(args)+1)
	args = append(args, limit)

	rows, err := s.facetRows(tenantID, query, args)
	if err != nil {
		return nil, err
	}
	// The bucket key is the PATH, because that is what the query language's
	// `class:` term matches on (§5.3). The label is the leaf key, which is what
	// the rail shows. A tenant leaf subclass is not in the generated registry,
	// so its own key is the honest label.
	for i := range rows {
		rows[i].Label = classLabelForPath(rows[i].Key)
	}
	return rows, nil
}

func classLabelForPath(path string) string {
	key := path
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		key = path[idx+1:]
	}
	if c, ok := assetclass.Get(key); ok && c.Label != "" {
		return c.Label
	}
	return key
}

// riskFacets counts assets per risk BAND, banding the persisted per-asset
// rollup once.
//
// The bands come from models.RiskBands through RiskBandSQL, never from a
// threshold written here — that is the drift that once banded High at ≥60 in a
// badge and ≥70 in a facet. `not_assessed` is its own bucket and is not a band:
// a score of 0 with an empty `risk_assessed_by` means nobody looked, which is a
// different answer from "assessed, scored zero" (§5.2).
func (s *AssetService) riskFacets(tenantID uuid.UUID, where string, args []interface{}) ([]models.AssetFacetBucket, error) {
	var arms []string
	arms = append(arms, `COUNT(*) FILTER (WHERE COALESCE(array_length(a.risk_assessed_by, 1), 0) = 0) AS not_assessed`)
	labels := make([]string, 0, len(models.RiskBands))
	for _, band := range models.RiskBands {
		cond := models.MustRiskBandSQL("a.risk_score", band.Label)
		arms = append(arms, fmt.Sprintf(
			`COUNT(*) FILTER (WHERE COALESCE(array_length(a.risk_assessed_by, 1), 0) > 0 AND (%s)) AS %s`,
			cond, strings.ToLower(band.Label)))
		labels = append(labels, band.Label)
	}
	query := fmt.Sprintf(`
		SELECT %s
		FROM assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		WHERE %s`, strings.Join(arms, ",\n\t\t       "), where)

	counts := make([]int64, len(labels)+1)
	dest := make([]interface{}, len(counts))
	for i := range counts {
		dest[i] = &counts[i]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// `where` is the same compiled predicate the asset list runs
	// (assetQueryStatementTimeout).
	if err := database.WithTenantTxTimeout(ctx, s.db, tenantID, assetQueryStatementTimeout, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx, query, args...).Scan(dest...)
	}); err != nil {
		return nil, fmt.Errorf("failed to get risk facets: %w", err)
	}

	out := []models.AssetFacetBucket{{Key: "not_assessed", Label: "Not assessed", Count: int(counts[0])}}
	for i, label := range labels {
		out = append(out, models.AssetFacetBucket{
			Key: strings.ToLower(label), Label: label, Count: int(counts[i+1]),
		})
	}
	return out, nil
}

// tagFacets counts assets per tag KEY. The values live one level down and are
// reached with `tag.<key>` once a key is picked; a facet over every key/value
// pair in a tenant's inventory is not a rail, it is a haystack.
func (s *AssetService) tagFacets(tenantID uuid.UUID, where string, args []interface{}, limit int) ([]models.AssetFacetBucket, error) {
	args = append(args, limit)
	query := fmt.Sprintf(`
		SELECT t.key AS "key", COUNT(DISTINCT a.id) AS "count"
		FROM assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		CROSS JOIN LATERAL jsonb_each_text(COALESCE(a.tags, '{}'::jsonb)) AS t(key, value)
		WHERE %s
		GROUP BY t.key
		ORDER BY "count" DESC, "key" ASC
		LIMIT $%d`, where, len(args))
	return s.facetRows(tenantID, query, args)
}

// booleanFacet is a two-bucket facet over a predicate: yes and no, both always
// returned. Returning only the populated side would let a rail render "12 with
// findings" beside nothing at all, which reads as "everything has findings".
func (s *AssetService) booleanFacet(tenantID uuid.UUID, where string, args []interface{}, predicate string) ([]models.AssetFacetBucket, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*) FILTER (WHERE %s) AS yes,
		       COUNT(*) FILTER (WHERE NOT (%s)) AS no
		FROM assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		WHERE %s`, predicate, predicate, where)
	var yes, no int64
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// `where` is the same compiled predicate the asset list runs, so this read
	// takes the same statement ceiling (assetQueryStatementTimeout).
	if err := database.WithTenantTxTimeout(ctx, s.db, tenantID, assetQueryStatementTimeout, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx, query, args...).Scan(&yes, &no)
	}); err != nil {
		return nil, fmt.Errorf("failed to get facet: %w", err)
	}
	return []models.AssetFacetBucket{
		{Key: "true", Label: "Yes", Count: int(yes)},
		{Key: "false", Label: "No", Count: int(no)},
	}, nil
}

func (s *AssetService) facetRows(tenantID uuid.UUID, query string, args []interface{}) ([]models.AssetFacetBucket, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var buckets []models.AssetFacetBucket
	// RLS-scoped read over assets, with the statement ceiling: every caller
	// builds `query` around the compiled asset predicate
	// (assetQueryStatementTimeout).
	if err := database.WithTenantTxTimeout(ctx, s.db, tenantID, assetQueryStatementTimeout, func(tx *sqlx.Tx) error {
		rows, e := tx.QueryxContext(ctx, query, args...)
		if e != nil {
			return fmt.Errorf("failed to get asset facets: %w", e)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var bucket models.AssetFacetBucket
			if e := rows.Scan(&bucket.Key, &bucket.Count); e != nil {
				return fmt.Errorf("failed to scan asset facet bucket: %w", e)
			}
			buckets = append(buckets, bucket)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("error iterating asset facet rows: %w", e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return buckets, nil
}

// AssetFacetLevels lists every facet level the API accepts, for the UI's rail
// and for the OpenAPI enum. Sorted, de-duplicated and derived from the map
// above so the two cannot disagree about what is supported.
func AssetFacetLevels() []string {
	seen := map[string]bool{}
	out := []string{facetLevelClass, facetLevelRisk, facetLevelTag, facetLevelHasFindings, facetLevelHasEndpoints}
	for _, l := range out {
		seen[l] = true
	}
	for l := range assetFacetExpr {
		if !seen[l] {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}
