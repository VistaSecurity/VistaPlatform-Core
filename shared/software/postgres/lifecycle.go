package postgres

// The per-install lifecycle record: what the `eol` producer concluded for each
// software install, written beside its findings.
//
// Two statements, and the producer calls both from INSIDE its write
// transaction. [UpsertLifecycle] restates every install the pass assessed;
// [SweepLifecycle] then deletes the rows of every install it did not. A pass is
// a FULL STATEMENT — the same rule the findings sweep follows — so an install
// that was removed, went stale, or vanished loses its row in the same
// transaction that would have refreshed it, and "no row" keeps meaning exactly
// "no completed pass has assessed this install since it was last active".
//
// The shape rules are checked here as well as by the schema's CHECK, because
// a constraint violation inside a producer's transaction surfaces as a
// rolled-back pass with a Postgres message naming a constraint, while an error
// from here names the install and the word that was wrong.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/software"
)

// LifecycleRow is one install's recorded end-of-life answer.
//
// CatalogueID and EOLDate follow the assessment: both set for `supported` and
// `end_of_life`, only the id for `no_date`, neither for `not_in_catalogue`.
// [UpsertLifecycle] refuses any other combination.
type LifecycleRow struct {
	InstallID   uuid.UUID
	Assessment  string
	CatalogueID *uuid.UUID
	EOLDate     *time.Time
}

// validate mirrors the schema's two CHECK constraints.
func (r LifecycleRow) validate() error {
	if r.InstallID == uuid.Nil {
		return fmt.Errorf("lifecycle row has no install id")
	}
	if !software.LifecycleAssessmentKnown(r.Assessment) {
		return fmt.Errorf("lifecycle row for install %s: %q is not an assessment", r.InstallID, r.Assessment)
	}
	hasID, hasDate := r.CatalogueID != nil && *r.CatalogueID != uuid.Nil, r.EOLDate != nil
	switch r.Assessment {
	case software.LifecycleSupported, software.LifecycleEndOfLife:
		if !hasID || !hasDate {
			return fmt.Errorf("lifecycle row for install %s: %s needs a catalogue id and a date", r.InstallID, r.Assessment)
		}
	case software.LifecycleNoDate:
		if !hasID || hasDate {
			return fmt.Errorf("lifecycle row for install %s: no_date needs a catalogue id and no date", r.InstallID)
		}
	case software.LifecycleNotInCatalogue:
		if hasID || hasDate {
			return fmt.Errorf("lifecycle row for install %s: not_in_catalogue cites nothing", r.InstallID)
		}
	}
	return nil
}

// upsertLifecycleSQL restates a set of installs' answers in one statement.
//
// `ON CONFLICT DO UPDATE` over every column: the row's meaning is "the last
// completed pass's conclusion", so a re-run has to move assessed_at even when
// the word did not change — a producer broken for a month must not look like
// one that ran an hour ago — and a catalogue whose date moved has to move the
// date. One statement over unnest rather than a loop, for the same reason the
// coverage record is: a tenant pass covers every install it examined.
const upsertLifecycleSQL = `
INSERT INTO software_install_lifecycle (tenant_id, install_id, assessment, catalogue_id, eol_date, assessed_at)
SELECT $1, r.install_id, r.assessment, r.catalogue_id, r.eol_date, $6
FROM unnest($2::uuid[], $3::text[], $4::uuid[], $5::date[]) AS r(install_id, assessment, catalogue_id, eol_date)
ON CONFLICT (tenant_id, install_id)
DO UPDATE SET assessment   = EXCLUDED.assessment,
              catalogue_id = EXCLUDED.catalogue_id,
              eol_date     = EXCLUDED.eol_date,
              assessed_at  = EXCLUDED.assessed_at`

// UpsertLifecycle records what this pass concluded for each install in rows.
//
// Call it from inside the producer's write transaction. Duplicate install ids
// are refused rather than resolved: a pass that planned two answers for one
// install has a bug, and picking one silently would hide it. Returns how many
// rows the statement wrote.
func UpsertLifecycle(ctx context.Context, tx Execer, tenantID uuid.UUID, rows []LifecycleRow, assessedAt time.Time) (int, error) {
	if tenantID == uuid.Nil {
		return 0, fmt.Errorf("software lifecycle: refusing to write for the nil tenant")
	}
	if len(rows) == 0 {
		return 0, nil
	}
	installs := make([]string, 0, len(rows))
	assessments := make([]string, 0, len(rows))
	catalogueIDs := make([]sql.NullString, 0, len(rows))
	dates := make([]sql.NullString, 0, len(rows))
	seen := make(map[uuid.UUID]bool, len(rows))
	for _, r := range rows {
		if err := r.validate(); err != nil {
			return 0, fmt.Errorf("software lifecycle: %w", err)
		}
		if seen[r.InstallID] {
			return 0, fmt.Errorf("software lifecycle: install %s planned twice in one pass", r.InstallID)
		}
		seen[r.InstallID] = true
		installs = append(installs, r.InstallID.String())
		assessments = append(assessments, r.Assessment)
		var cid, date sql.NullString
		if r.CatalogueID != nil {
			cid = sql.NullString{String: r.CatalogueID.String(), Valid: true}
		}
		if r.EOLDate != nil {
			date = sql.NullString{String: r.EOLDate.UTC().Format("2006-01-02"), Valid: true}
		}
		catalogueIDs = append(catalogueIDs, cid)
		dates = append(dates, date)
	}

	res, err := tx.ExecContext(ctx, upsertLifecycleSQL,
		tenantID, pq.Array(installs), pq.Array(assessments), pq.Array(catalogueIDs), pq.Array(dates), assessedAt.UTC())
	if err != nil {
		return 0, fmt.Errorf("software lifecycle: recording %d installs: %w", len(rows), err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// The write happened; only the count is unavailable.
		return len(rows), nil
	}
	return int(n), nil
}

// sweepLifecycleSQL deletes every row of the tenant whose install is not in
// the keep set. Written as NOT EXISTS over unnest rather than `<> ALL($2)`:
// the planner hashes the unnested set, which is what a sixty-thousand-install
// tenant needs.
const sweepLifecycleSQL = `
DELETE FROM software_install_lifecycle l
 WHERE l.tenant_id = $1
   AND NOT EXISTS (SELECT 1 FROM unnest($2::uuid[]) AS k(install_id) WHERE k.install_id = l.install_id)`

// SweepLifecycle deletes the records of every install this pass did NOT
// assess — the ones in keep are the pass's full statement.
//
// An empty keep deletes every row of the tenant, which is right for a pass
// that completed and found no active install to assess, and catastrophic for
// one that failed half way. Call it only from the write phase of a pass whose
// read and resolve phases completed, in the same transaction as the upsert.
// Returns how many rows went.
func SweepLifecycle(ctx context.Context, tx Execer, tenantID uuid.UUID, keep []uuid.UUID) (int, error) {
	if tenantID == uuid.Nil {
		return 0, fmt.Errorf("software lifecycle: refusing to sweep the nil tenant")
	}
	ids := make([]string, 0, len(keep))
	for _, id := range keep {
		if id != uuid.Nil {
			ids = append(ids, id.String())
		}
	}
	res, err := tx.ExecContext(ctx, sweepLifecycleSQL, tenantID, pq.Array(ids))
	if err != nil {
		return 0, fmt.Errorf("software lifecycle: sweeping: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return int(n), nil
}
