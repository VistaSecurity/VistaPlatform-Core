package processor

// Per-row failure for sensor_discoveries ( F14).
//
// A batch is a unit of WORK, not a unit of fate. It used to be both: one
// failed import chunk or one failed external-connection upsert failed the
// batch, the poller retried the whole batch, and after three failures
// markBatchAsFailed stamped every row still unprocessed `rejected` — rows
// whose chunk had never even been sent included.
//
// Now each row that did not land is recorded on its own:
//
//   - process_attempts counts the times it has been tried and failed;
//   - process_error says why, the last time;
//   - while attempts remain, the row stays unprocessed and its claim is
//     released with a backoff, so the next wake or poll retries it once the
//     backoff has passed (and not before — the drain loop cannot spin on it);
//   - when the failure is permanent (a 4xx from inventory-service, a row whose
//     own content cannot be converted or routed) or the attempts are spent, the
//     row is terminal: processed_at is set and approval_status is `rejected`,
//     one of the approval_status values already in use for "not accepted"
//     (the column has no CHECK constraint; the vocabulary is by convention),
//     with process_error saying why.
//
// Rows that succeeded are marked processed exactly as before (markProcessed).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// errThirdPartyNoSourceIP is a third-party discovery with no source address:
// a connection record needs both ends, and no retry supplies the missing one.
var errThirdPartyNoSourceIP = errors.New("third-party discovery has no source_ip; a connection needs both ends")

// rowFailure is one sensor_discoveries row that did not land this attempt.
type rowFailure struct {
	id        uuid.UUID
	err       error
	permanent bool
	// drop marks a row skipped for its own content — a third-party row with
	// no source address, a row that does not convert. It is settled terminal
	// like any permanent failure, but it is a decision about that row, not a
	// fault in processing, so on its own it does not report the batch failed.
	drop bool
}

// importFailures is importInChunks' report of the rows whose chunk (or whose
// own outcome) failed. Every other chunk was still imported.
type importFailures struct {
	rows  []rowFailure
	first error
}

func (f *importFailures) add(err error) {
	if f.first == nil {
		f.first = err
	}
}

func (f *importFailures) Error() string {
	return fmt.Sprintf("%d finding(s) failed to import: %v", len(f.rows), f.first)
}

func (f *importFailures) Unwrap() error { return f.first }

// RowFailuresError is ProcessBatch's report of a batch some of whose rows did
// not land. Those rows are ALREADY recorded (retry scheduled, or terminal), so
// the caller must not treat the batch as failed: everything else in it was
// processed.
type RowFailuresError struct {
	// Failed is how many rows failed this attempt; Terminal how many of them
	// are now settled as rejected; Total how many rows the batch read.
	Failed, Terminal, Total int
	// Err is a representative cause (the first), kept for errors.Is/As — so
	// an all-skipped batch still classifies as ErrNoValidFindings and an
	// inventory 5xx as inventory_http_5xx in the audit record.
	Err error
}

func (e *RowFailuresError) Error() string {
	return fmt.Sprintf("%d of %d row(s) failed (%d now terminal, the rest retried with backoff): %v",
		e.Failed, e.Total, e.Terminal, e.Err)
}

func (e *RowFailuresError) Unwrap() error { return e.Err }

// RetryPolicy is how a failed row is retried.
type RetryPolicy struct {
	// MaxAttempts is how many failed attempts make a row terminal.
	MaxAttempts int
	// BackoffBase is the wait after the first failure; it doubles per
	// attempt up to BackoffCap. The knob is honoured exactly: there is no
	// floor beneath it.
	BackoffBase time.Duration
	BackoffCap  time.Duration
}

// DefaultRetryPolicy sizes the budget for a rolling restart of
// inventory-service, not a blip: seven attempts, backing off 30s, 1m, 2m, 4m,
// 8m, 10m (about 25 minutes before the last attempt settles the row). Under
// steady ingest every wake re-claims a row the moment its backoff passes, so
// a short ladder is spent in seconds against an outage that lasts minutes.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 7, BackoffBase: 30 * time.Second, BackoffCap: 10 * time.Minute}
}

// Backoff is the wait after the (failedBefore+1)th failure of a row:
// BackoffBase doubled failedBefore times, capped at BackoffCap. It is the one
// source of the ladder; recordRowFailures hands the whole ladder to SQL.
func (p RetryPolicy) Backoff(failedBefore int) time.Duration {
	d := p.BackoffBase
	for i := 0; i < failedBefore; i++ {
		if d >= p.BackoffCap {
			break
		}
		d *= 2
	}
	if d > p.BackoffCap {
		d = p.BackoffCap
	}
	return d
}

// ladderMillis is Backoff for failedBefore = 0..MaxAttempts-1, in
// milliseconds, for the SQL that indexes it by the row's attempts so far.
func (p RetryPolicy) ladderMillis() []int64 {
	out := make([]int64, p.MaxAttempts)
	for i := range out {
		out[i] = p.Backoff(i).Milliseconds()
	}
	return out
}

// SetRetryPolicy replaces the default; non-positive fields keep it.
func (p *BatchProcessor) SetRetryPolicy(rp RetryPolicy) {
	d := DefaultRetryPolicy()
	if rp.MaxAttempts <= 0 {
		rp.MaxAttempts = d.MaxAttempts
	}
	if rp.BackoffBase <= 0 {
		rp.BackoffBase = d.BackoffBase
	}
	if rp.BackoffCap <= 0 {
		rp.BackoffCap = d.BackoffCap
	}
	if rp.BackoffCap < rp.BackoffBase {
		rp.BackoffCap = rp.BackoffBase
	}
	p.retry = rp
}

func (p *BatchProcessor) retryPolicy() RetryPolicy {
	if p.retry.MaxAttempts <= 0 {
		return DefaultRetryPolicy()
	}
	return p.retry
}

// maxProcessErrorLen bounds process_error. err.Error() can quote an inventory
// response body; the column records why, not a copy of the payload.
const maxProcessErrorLen = 1000

func truncateError(err error) string {
	if err == nil {
		return ""
	}
	// Postgres text cannot hold NUL. Strip it first: one in the message would
	// make the UPDATE that records the failure fail, and the row would then
	// retry for ever with no attempt counted.
	msg := strings.ReplaceAll(err.Error(), "\x00", "")
	if len(msg) > maxProcessErrorLen {
		msg = msg[:maxProcessErrorLen]
	}
	// Cutting at a byte offset can split a rune; drop the fragment.
	return strings.ToValidUTF8(msg, "")
}

// failureSet is the SET clause shared by both failure writers. In an UPDATE,
// d.process_attempts on the right-hand side is the value BEFORE this update.
//
// The released claim: a batch is claimable once claimed_at is older than
// batchClaimTimeout (processNextBatch), so setting it to
// now - batchClaimTimeout + backoff makes the row claimable again exactly
// `backoff` from now.
//
// Parameters: $1 now, $2 max attempts, $3 claim timeout, $4 the backoff
// ladder (bigint[] of milliseconds, RetryPolicy.Backoff for attempts so far
// 0..n-1). The row-specific error and permanence come from `v`.
const failureSet = `
	process_attempts = d.process_attempts + 1,
	process_error    = v.error,
	processed_at     = CASE WHEN v.permanent OR d.process_attempts + 1 >= $2 THEN $1::timestamptz END,
	approval_status  = CASE WHEN v.permanent OR d.process_attempts + 1 >= $2 THEN 'rejected' ELSE d.approval_status END,
	claimed_at       = CASE WHEN v.permanent OR d.process_attempts + 1 >= $2 THEN d.claimed_at
	                        ELSE $1::timestamptz - $3::interval
	                             + ($4::bigint[])[LEAST(d.process_attempts + 1, cardinality($4::bigint[]))] * interval '1 millisecond' END`

func intervalArg(d time.Duration) string {
	return fmt.Sprintf("%d milliseconds", d.Milliseconds())
}

// recordRowFailures writes failures onto their rows (see the file comment)
// and returns how many are now terminal.
func (p *BatchProcessor) recordRowFailures(ctx context.Context, tenantID uuid.UUID, failures []rowFailure) (int, error) {
	if len(failures) == 0 {
		return 0, nil
	}
	ids := make([]string, len(failures))
	msgs := make([]string, len(failures))
	permanent := make([]bool, len(failures))
	for i, f := range failures {
		ids[i], msgs[i], permanent[i] = f.id.String(), truncateError(f.err), f.permanent
	}
	rp := p.retryPolicy()
	terminal := 0
	err := shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			UPDATE sensor_discoveries d SET `+failureSet+`
			FROM (SELECT unnest($5::uuid[]) AS id, unnest($6::text[]) AS error, unnest($7::bool[]) AS permanent) v
			WHERE d.tenant_id = $8 AND d.id = v.id AND d.processed_at IS NULL
			RETURNING d.processed_at IS NOT NULL`,
			time.Now().UTC(), rp.MaxAttempts, intervalArg(batchClaimTimeout), pq.Array(rp.ladderMillis()),
			pq.Array(ids), pq.Array(msgs), pq.Array(permanent), tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var done bool
			if err := rows.Scan(&done); err != nil {
				return err
			}
			if done {
				terminal++
			}
		}
		return rows.Err()
	})
	return terminal, err
}

// RecordBatchFailure records a failure that happened before any row of the
// batch could be settled on its own — the batch could not be read, or
// ProcessBatch failed outright — against every unprocessed row of the claim
// (claimed_at = claimedAt). Rows in another claim's backoff, or that joined
// the batch after this claim, were not part of the attempt and are not
// charged for it.
// The same attempt counting and backoff as recordRowFailures; returns how many
// rows are now terminal.
func (p *BatchProcessor) RecordBatchFailure(ctx context.Context, tenantID uuid.UUID, batchID string, claimedAt time.Time, cause error) (int, error) {
	rp := p.retryPolicy()
	terminal := 0
	err := shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
		// tenant_id is in the predicate so the planner can prune to the one
		// hash partition that can hold this tenant's rows.
		rows, err := tx.QueryContext(ctx, `
			UPDATE sensor_discoveries d SET `+failureSet+`
			FROM (SELECT $5::text AS error, $6::bool AS permanent) v
			WHERE d.tenant_id = $7 AND d.batch_id = $8 AND d.processed_at IS NULL AND d.claimed_at = $9
			RETURNING d.processed_at IS NOT NULL`,
			time.Now().UTC(), rp.MaxAttempts, intervalArg(batchClaimTimeout), pq.Array(rp.ladderMillis()),
			truncateError(cause), isPermanentError(cause), tenantID, batchID, claimedAt)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var done bool
			if err := rows.Scan(&done); err != nil {
				return err
			}
			if done {
				terminal++
			}
		}
		return rows.Err()
	})
	return terminal, err
}

// expandToFollowers gives every row folded into a failed survivor the
// survivor's failure. A folded row's fate is its survivor's (processedMarks
// does the same for success): left out, it would keep its original claim, be
// re-claimed unfolded ten minutes later, and be orphaned if the survivor went
// terminal. Both then share process_attempts, process_error, the backoff and
// the terminal status, because recordRowFailures applies one rule to both.
func expandToFollowers(failures []rowFailure, followers tlsFoldFollowers) []rowFailure {
	if len(followers) == 0 {
		return failures
	}
	// Deduplicated by id: a markProcessed failure already lists followers.
	seen := make(map[uuid.UUID]bool, len(failures))
	out := make([]rowFailure, 0, len(failures))
	for _, f := range failures {
		if !seen[f.id] {
			seen[f.id] = true
			out = append(out, f)
		}
		for _, id := range followers[f.id] {
			if !seen[id] {
				seen[id] = true
				c := f
				c.id = id
				out = append(out, c)
			}
		}
	}
	return out
}

// settleFailures records the batch's row failures and reports the outcome.
// nil when every row landed or was only dropped (cause, when set, is returned
// regardless); a *RowFailuresError when some failed and were recorded; a
// plain error only when recording them failed (the caller then falls back to
// RecordBatchFailure, and failing that, the claim timeout).
func (p *BatchProcessor) settleFailures(ctx context.Context, tenantID uuid.UUID, batchID string, ba *batchAudit, failures []rowFailure, followers tlsFoldFollowers, total int, cause error) error {
	if len(failures) == 0 {
		return cause
	}
	failures = expandToFollowers(failures, followers)
	terminal, err := p.recordRowFailures(ctx, tenantID, failures)
	if err != nil {
		return fmt.Errorf("record %d row failure(s) for batch %s: %w", len(failures), batchID, err)
	}
	ba.counts["rows_failed"] = len(failures)
	ba.counts["rows_terminal"] = terminal
	first := cause
	failed := 0
	for _, f := range failures {
		if f.drop {
			continue
		}
		failed++
		if first == nil {
			first = f.err
		}
	}
	if first == nil {
		// Only drops: settled, counted in the audit record, not a failure.
		return nil
	}
	fmt.Printf("Batch %s: %d of %d row(s) did not land (%d now terminal as rejected, the rest retried with backoff): %v\n",
		batchID, len(failures), total, terminal, first)
	return &RowFailuresError{Failed: len(failures), Terminal: terminal, Total: total, Err: first}
}
