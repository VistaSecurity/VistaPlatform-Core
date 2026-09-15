package producer

// Coverage: the record of which producer has LOOKED at which asset.
//
// A finding says "this is wrong". Its ABSENCE says one of two completely
// different things — "I checked and it is fine" or "nobody has checked" — and
// the findings table cannot tell them apart, because both are spelled "no row".
// `producer_assessments` is the second half of the sentence: one row per
// (asset, producer) written by a pass that COMPLETED, whether or not it found
// anything.
//
// There are TWO readers and they are not the same set. `assets.risk_assessed_by`
// is the RISK-FEEDING subset of these rows, derived by the risk rollup —
// "is the risk score on this asset a real answer?" — and it is what the
// inventory UI reads. Everything that needs the FULL record, `hygiene`
// included, reads this table directly; compliance-engine's `finding`
// measurement shape is the one that does. The indirection through the rollup is
// deliberate: the array is one column on a hot, partitioned table that six
// producers would otherwise read-modify-write concurrently, and the rollup is
// already the one statement allowed to write it.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// markAssessedSQL records this producer's coverage of a set of assets.
//
// `ON CONFLICT DO UPDATE` rather than DO NOTHING: the row's meaning is "the
// last completed pass that examined this asset", so a second pass has to move
// assessed_at. DO NOTHING would freeze the timestamp at the first pass and make
// a producer that has been broken for a month indistinguishable from one that
// ran an hour ago.
//
// The INSERT is one statement over an unnest rather than a loop, because a
// tenant pass covers every asset it examined and a per-asset round trip over
// ten thousand of them is the shape that turns a nightly job into an overnight
// one.
const markAssessedSQL = `
INSERT INTO producer_assessments (tenant_id, asset_id, producer, assessed_at)
SELECT $1, s.asset_id, $2, $4
FROM unnest($3::uuid[]) AS s(asset_id)
ON CONFLICT (tenant_id, asset_id, producer)
DO UPDATE SET assessed_at = EXCLUDED.assessed_at`

// MarkAssessed records that this producer has evaluated each of assetIDs.
//
// Call it from INSIDE the pass's own write transaction — the same one carrying
// the upserts and the sweep, and it takes that transaction as an argument so
// there is nowhere else to put it. That is what makes "a failed pass marks
// nothing" true by construction rather than by a convention somebody has to
// remember: a run that dies half way rolls its coverage claim back along with
// its findings, and the asset keeps whatever coverage the last COMPLETED pass
// gave it. A claim committed in a transaction of its own OUTLIVES the rollback
// of the findings that justify it, and the asset then reads "assessed, nothing
// found" forever. Each producer owes a test that fails the write phase after
// this call and asserts no row survives — see
// TestIntegration_CryptoProducer_AFailedWritePhaseClaimsNoCoverage. A cancelled
// context does not prove it: it kills the read phase too, so the write never
// runs and the assertion holds however the claim is arranged.
//
// # What belongs in assetIDs
//
// The assets the pass actually EXAMINED — the ones it formed an opinion about,
// or could have. That is narrower than "every asset in the tenant" and narrower
// than "every asset the pass READ". The vulnerability producer examines assets
// that have identifiable software installs; an asset whose every install carries
// neither a CPE nor a PURL was not assessed by it, and claiming otherwise would
// report "no known vulnerabilities" for a host nothing could be matched against.
// Marking generously is the failure mode here, not marking sparsely: an
// unclaimed asset reads "not assessed", which is true and visible, while an
// over-claimed one reads "assessed clean", which is false and silent.
//
// The parameter is ASSET ids even for a producer whose findings are about
// something else, because coverage is a statement about an asset — it is what
// the asset page and the compliance `finding` shape ask about. A producer whose
// subjects are endpoints, configurations, certificates or relationships resolves
// them to their assets itself and marks those, and it marks EVERY asset a
// subject belongs to, not one of them: a certificate served by four hosts is
// examined on behalf of all four, and a finding on it raises all four
// (`findings.AssetSubjects`). Worked examples of the judgement:
//
//   - `hygiene` marks every live asset — its subject IS the asset, and an asset
//     it read is an asset it judged.
//   - `configuration` marks the assets whose endpoints or facts it actually
//     read, not those it had nothing to look at.
//   - `drift` marks only the assets with a baseline to compare against; without
//     one there is no question it could have answered.
//
// # Coverage is not `feeds_risk`
//
// Every producer marks, `hygiene` included. Whether a producer's coverage
// reaches `assets.risk_assessed_by` is the ROLLUP's decision, taken from the
// registry (findings.RiskFeedingProducers) — not this call's, and not the
// producer's.
//
// Duplicates in assetIDs are harmless (the conflict target absorbs them) and the
// nil uuid is dropped rather than written, since no asset has it.
//
// Returns how many rows the statement wrote, for the caller's run log.
func (w *Writer) MarkAssessed(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, assetIDs []uuid.UUID) (int, error) {
	if tx == nil {
		return 0, fmt.Errorf("producer %s: MarkAssessed needs a transaction", w.producer)
	}
	if tenantID == uuid.Nil {
		return 0, fmt.Errorf("producer %s: refusing to record coverage for the nil tenant", w.producer)
	}

	ids := make([]string, 0, len(assetIDs))
	seen := make(map[uuid.UUID]bool, len(assetIDs))
	for _, id := range assetIDs {
		if id == uuid.Nil || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id.String())
	}
	if len(ids) == 0 {
		return 0, nil
	}

	res, err := tx.ExecContext(ctx, markAssessedSQL, tenantID, w.producer, pq.Array(ids), w.now().UTC())
	if err != nil {
		return 0, fmt.Errorf("producer %s: recording coverage of %d assets: %w", w.producer, len(ids), err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// The write happened; only the count is unavailable. Reporting 0 would
		// read as "covered nothing", which is the opposite of what is true.
		return len(ids), nil
	}
	return int(n), nil
}
