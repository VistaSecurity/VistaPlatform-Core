// Package riskrollup is the ONE definition of per-asset risk (ADR-0005 D4).
//
// An asset's `risk_score` is the MAX score over the OPEN findings that feed
// risk and whose subject belongs to the asset — the asset itself plus the four
// descendant subject paths `shared/findings.AssetSubjects` walks. Its
// `risk_assessed_by` is the set of producers that have completed a pass over
// it, read from `producer_assessments`.
//
// # Why one package, and why it writes both columns in one statement
//
// The score and the coverage answer two halves of a single question — "how bad
// is this, and does anybody know?" — and a reader that gets one without the
// other cannot tell "assessed clean" from "nobody looked". Writing them in
// separate statements leaves a window in which the pair is inconsistent, and
// `assets` is read by the inventory list, the facets, the dashboard
// distribution and the compliance `finding` shape, every one of which draws a
// conclusion from the pair.
//
// It also means exactly one statement in the platform writes `assets.risk_*`.
// Before this, ingest wrote the score from a `MAX(crypto_implementations
// .risk_score)` and appended `crypto` to the array in the same UPDATE, while
// the producers that would later have their own opinion had nowhere to put it.
// Six producers appending to a text[] on a hot partitioned table would be six
// racing read-modify-writes; deriving the array from `producer_assessments`
// removes the race by construction.
//
// # What it deliberately does NOT do
//
//   - It does not sweep, resolve or create findings. It reads them.
//   - It does not decide WHICH kinds feed risk. That is
//     `standards/findings-registry.yaml`, via findings.RiskFeedingKeys().
//
// # `risk_assessed_by` is the RISK-FEEDING subset of the coverage record
//
// `producer_assessments` carries a row for EVERY producer that has completed a
// pass over an asset, `hygiene` included. The array on `assets` carries only
// the producers with at least one risk-feeding kind
// (findings.RiskFeedingProducers), because the array means "the RISK score on
// this asset is a real answer" and the inventory UI reads a non-empty one as
// exactly that: an asset only the hygiene producer has visited must still read
// NOT ASSESSED for risk, since nothing that could move the score has been
// evaluated. (Orchestrator decision,.)
//
// Everything that needs the FULL record — compliance-engine's `finding`
// measurement shape, which gates `assessed_by: hygiene` and
// `assessed_by: configuration` rows — reads `producer_assessments` directly
// rather than the array.
//   - It does not band. `shared/riskbands` owns the 0-100 → label ladder and is
//     applied by the readers.
package riskrollup

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// Recompute rewrites risk_score and risk_assessed_by for one tenant's assets.
//
// assetID narrows it to a single asset; pass uuid.Nil for the whole tenant. Both
// spellings run the SAME statement, because "the score of one asset" and "the
// scores of every asset" are the same definition and two statements would be two
// chances to write it differently — which is exactly how the four live
// `MAX(ci.risk_score)` computations came to sit beside the persisted rollup they
// were supposed to have replaced.
//
// tx must already be inside the tenant's RLS session
// (shared/database.WithTenantTx or postgres.Repository.RunInTx). The explicit
// tenant_id predicates are belt and braces, not a substitute for it.
//
// Returns how many asset rows actually changed. A converged tenant returns 0 and
// touches nothing — the statement's own WHERE excludes rows whose pair is
// already correct, so a nightly recompute over a static inventory does not churn
// `updated_at` on every asset (which the compliance `finding` shape reads as its
// measured_at, and which would otherwise make every measurement look fresh).
func Recompute(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID) (int, error) {
	return recompute(ctx, tx, tenantID, assetID, findings.RiskFeedingKeys(), findings.RiskFeedingProducers())
}

// recompute is Recompute with the feeds-risk set handed in.
//
// The seam exists for ONE reason: to make the registry filter mutation-testable.
// A test passes a list with one kind's flag flipped and asserts the score moves;
// without the seam the filter could only be exercised through the real registry,
// where "the filter is applied" and "the filter is `true`" look identical.
func recompute(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, riskKeys, riskProducers []string) (int, error) {
	if tx == nil {
		return 0, fmt.Errorf("riskrollup: Recompute needs a transaction")
	}
	if tenantID == uuid.Nil {
		return 0, fmt.Errorf("riskrollup: refusing to recompute risk for the nil tenant")
	}

	var scopedAsset any
	if assetID != uuid.Nil {
		scopedAsset = assetID
	}

	res, err := tx.ExecContext(ctx, Statement(), tenantID, scopedAsset, pq.Array(riskKeys), pq.Array(riskProducers))
	if err != nil {
		return 0, fmt.Errorf("riskrollup: recompute tenant %s: %w", tenantID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return int(n), nil
}

// safeSubjectType guards the one value spliced into the statement as a literal.
//
// Subject types come from the generated registry, so this cannot fire on any
// input a caller controls — which is exactly why it is here. A literal spliced
// because "it comes from a constant" is one refactor away from being spliced
// because it came from a request, and the assertion costs nothing.
var safeSubjectType = regexp.MustCompile(`^[a-z_]+$`)

// statementText is built once; the registry it derives from is generated and
// cannot change at runtime.
var statementText = build()

// Statement returns the recompute, for a test that wants to read it or run it
// by hand. Parameters: $1 tenant_id, $2 asset_id or NULL, $3 text[] of
// `<producer>/<kind>` keys that feed risk, $4 text[] of the producers that have
// at least one such kind.
func Statement() string { return statementText }

func build() string {
	n := 0
	uniq := func(prefix string) string { n++; return prefix + fmt.Sprint(n) }

	// The descendant subject paths, as rows rather than as a correlated OR.
	//
	// findings.AssetSubjects gives each path as a SELECT of ids correlated to
	// the asset alias, which is the shape a per-asset EXISTS wants. A set-based
	// recompute wants the transpose — (asset_id, subject_type, subject_id) for
	// every asset in scope — and LATERAL is what turns one into the other
	// WITHOUT restating the join. Restating it is the failure this whole file
	// exists to avoid: `AssetSubjects` is already the single definition the
	// query language and the per-asset findings read share, and a fifth
	// hand-written copy here would be the one that silently disagrees.
	var parts []string
	for _, s := range findings.AssetSubjects("s", uniq) {
		if !safeSubjectType.MatchString(s.Type) {
			panic("riskrollup: subject type " + s.Type + " is not a bare identifier")
		}
		if s.Self {
			parts = append(parts, "    SELECT s.id AS asset_id, '"+s.Type+"'::text AS subject_type, s.id AS subject_id\n"+
				"    FROM scope s")
			continue
		}
		parts = append(parts, "    SELECT s.id AS asset_id, '"+s.Type+"'::text AS subject_type, x.id AS subject_id\n"+
			"    FROM scope s, LATERAL ("+s.IDs+") AS x(id)")
	}

	return `
WITH scope AS (
    SELECT a.tenant_id, a.id
    FROM assets a
    WHERE a.tenant_id = $1
      AND a.deleted_at IS NULL
      AND ($2::uuid IS NULL OR a.id = $2::uuid)
),
subject AS (
` + strings.Join(parts, "\n    UNION ALL\n") + `
),
risk AS (
    SELECT s.id AS asset_id, COALESCE(MAX(f.score), 0) AS max_score
    FROM scope s
    LEFT JOIN subject sub ON sub.asset_id = s.id
    LEFT JOIN findings f
           ON f.tenant_id = s.tenant_id
          AND f.subject_type = sub.subject_type
          AND f.subject_id = sub.subject_id
          AND (f.producer || '/' || f.kind) = ANY($3::text[])
          AND ` + findings.OpenSQL("f") + `
    GROUP BY s.id
),
cover AS (
    SELECT s.id AS asset_id,
           COALESCE(
               array_agg(pa.producer ORDER BY pa.producer) FILTER (WHERE pa.producer IS NOT NULL),
               ARRAY[]::text[]
           ) AS producers
    FROM scope s
    LEFT JOIN producer_assessments pa
           ON pa.tenant_id = s.tenant_id AND pa.asset_id = s.id
          AND pa.producer = ANY($4::text[])
    GROUP BY s.id
)
UPDATE assets a
SET risk_score       = risk.max_score,
    risk_assessed_by = cover.producers,
    updated_at       = NOW()
FROM risk JOIN cover ON cover.asset_id = risk.asset_id
WHERE a.tenant_id = $1
  AND a.id = risk.asset_id
  AND (a.risk_score IS DISTINCT FROM risk.max_score
       OR a.risk_assessed_by IS DISTINCT FROM cover.producers)`
}
