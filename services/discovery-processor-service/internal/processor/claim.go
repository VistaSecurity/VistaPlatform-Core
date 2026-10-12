package processor

// Batch claim: renewal and fencing (the "stale claim" fix).
//
// processNextBatch stamps claimed_at on the rows it takes, and any worker may
// take them over once the stamp is older than batchClaimTimeout. That bounds a
// worker that DIES mid-batch. It said nothing about a worker that is merely
// SLOW: importing costs 100-280 ms per finding on the inventory side, so a batch
// of about two thousand findings outlives ten minutes, a second replica
// re-claims the same rows and imports them again (observation counts
// double-increment — the reason rows are stamped processed only at the end), and
// the first worker's late stamps then overwrite the second's.
//
// Two mechanisms close it:
//
//   - renewal: the worker refreshes claimed_at on its rows before every import
//     chunk (renewClaim), so a live worker never looks stale;
//   - fencing: every UPDATE that stamps the rows' fate (markProcessed,
//     recordRowFailures, RecordBatchFailure) carries `claimed_at = <the claim>`,
//     so a worker that DID lose its claim writes nothing. markProcessed also
//     checks that it stamped every row it expected to, and rolls back and
//     reports errClaimLost when it did not.
//
// A claim is identified by its stamp, and renewal changes the stamp, so the
// worker tracks the current value in batchClaim.at.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// errClaimLost reports that another worker took the batch's rows over, so
// nothing this worker still holds may be written back.
var errClaimLost = errors.New("batch claim lost to another worker")

// batchClaim is the claim one worker holds on a batch's rows.
type batchClaim struct {
	tenantID uuid.UUID
	batchID  string
	// at is the claimed_at stamp every row of the claim currently carries.
	at time.Time
	// rows is how many rows carry it, as read when the claim was opened.
	rows int
}

// arg is the claim as a SQL parameter: NULL (no fence) for an unclaimed run.
func (c *batchClaim) arg() interface{} {
	if c == nil {
		return nil
	}
	return c.at
}

// claimMovedError carries the claim's CURRENT stamp out of a failed
// processBatch: renewal moved it, and RecordBatchFailure (fenced on the stamp)
// would otherwise match nothing and leave the rows with no attempt counted.
type claimMovedError struct {
	current time.Time
	err     error
}

func (e *claimMovedError) Error() string { return e.err.Error() }
func (e *claimMovedError) Unwrap() error { return e.err }

// renewClaim moves the claim's rows to a fresh claimed_at, provided they still
// carry the claim's stamp. It returns errClaimLost when fewer rows than the
// claim holds were renewed: the rest were taken over.
func (p *BatchProcessor) renewClaim(ctx context.Context, c *batchClaim) error {
	if c == nil {
		return nil
	}
	var renewed int
	var stamp time.Time
	err := shareddatabase.WithTenantTx(ctx, p.db.DB, c.tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			UPDATE sensor_discoveries SET claimed_at = now()
			WHERE tenant_id = $1 AND batch_id = $2 AND claimed_at = $3 AND processed_at IS NULL
			RETURNING claimed_at`, c.tenantID, c.batchID, c.at)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			if err := rows.Scan(&stamp); err != nil {
				return err
			}
			renewed++
		}
		return rows.Err()
	})
	if err != nil {
		return fmt.Errorf("renew claim on batch %s: %w", c.batchID, err)
	}
	if renewed < c.rows {
		return fmt.Errorf("%w: batch %s, %d of %d row(s) still ours", errClaimLost, c.batchID, renewed, c.rows)
	}
	c.at = stamp
	return nil
}
