package processor

// Retry budget and the "no path retries for ever uncounted" guarantees,
// against a real sensor_discoveries table with a stand-in inventory-service.
// Skips without TEST_DATABASE_URL.
//
// Mutations that turn these red (see the PR comment):
//   - ladder: put a floor back under the base, or index the ladder off by one
//     in failureSet;
//   - transient budget: set DefaultRetryPolicy().MaxAttempts back to 3 / make
//     a 503 permanent;
//   - markProcessed: make ProcessBatch ignore markProcessed's error.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func seedOneManaged(t *testing.T, p *BatchProcessor, tenant uuid.UUID, batchID, ip string) uuid.UUID {
	t.Helper()
	host := "svc.corp.example"
	return seedTLSDiscovery(t, p.db, tenant, uuid.New(), batchID, ip, 443, &host,
		`{"discovery_method":"passive","cipher_suite":"TLS_AES_128_GCM_SHA256","version":"TLS 1.3"}`)
}

// Three 503s in a row (about the length of the old retry budget) leave the
// row retryable with the error recorded, and the backoff each time follows the
// configured ladder, base knob included.
func TestIntegration_TransientFailuresStayRetryableOnTheLadder(t *testing.T) {
	p, _, db, tenant := newFlakyBatchProcessor(t, 1) // every single-finding import 503s
	p.SetRetryPolicy(RetryPolicy{MaxAttempts: 7, BackoffBase: 2 * time.Second, BackoffCap: 10 * time.Second})
	batchID := uuid.New().String()
	id := seedOneManaged(t, p, tenant, batchID, "10.78.0.1")

	for attempt := 1; attempt <= 3; attempt++ {
		var rf *RowFailuresError
		if err := p.ProcessBatch(batchID, tenant); !errors.As(err, &rf) || rf.Terminal != 0 {
			t.Fatalf("attempt %d: %v, want a retryable failure, not terminal", attempt, err)
		}
		s := readRows(t, db, tenant, batchID)[id]
		if s.processed || s.status == "rejected" || s.attempts != attempt || !strings.Contains(s.errMsg, "503") {
			t.Fatalf("attempt %d: row = %+v, want unprocessed, not rejected, attempts=%d, the 503 recorded", attempt, s, attempt)
		}
		// Claimable again after Backoff(attempt-1): claimed_at = now - timeout + backoff.
		wait := p.retryPolicy().Backoff(attempt - 1)
		due := time.Now().Add(-batchClaimTimeout + wait)
		if s.claimedAt == nil || s.claimedAt.Sub(due).Abs() > 2*time.Second {
			t.Fatalf("attempt %d: claimed_at %v, want about %v (a %v backoff)", attempt, s.claimedAt, due, wait)
		}
	}
}

// A permanent 4xx settles the row on the first failure.
func TestIntegration_PermanentFailureIsTerminalOnTheFirstAttempt(t *testing.T) {
	p, inv, db, tenant := newFlakyBatchProcessor(t, 1)
	inv.failCode = http.StatusBadRequest
	batchID := uuid.New().String()
	id := seedOneManaged(t, p, tenant, batchID, "10.78.1.1")

	var rf *RowFailuresError
	if err := p.ProcessBatch(batchID, tenant); !errors.As(err, &rf) || rf.Terminal != 1 {
		t.Fatalf("ProcessBatch = %v, want one terminal row", err)
	}
	if s := readRows(t, db, tenant, batchID)[id]; !s.processed || s.status != "rejected" || s.attempts != 1 || !strings.Contains(s.errMsg, "400") {
		t.Fatalf("row = %+v, want processed, rejected, 1 attempt, the 400 recorded", s)
	}
}

// With the default policy a row survives well past the old three attempts.
func TestIntegration_DefaultPolicySurvivesSixTransientFailures(t *testing.T) {
	p, _, db, tenant := newFlakyBatchProcessor(t, 1)
	batchID := uuid.New().String()
	id := seedOneManaged(t, p, tenant, batchID, "10.78.2.1")
	for i := 1; i <= 6; i++ {
		_ = p.ProcessBatch(batchID, tenant)
		if s := readRows(t, db, tenant, batchID)[id]; s.processed || s.attempts != i {
			t.Fatalf("after failure %d: %+v, want still retryable", i, s)
		}
	}
	_ = p.ProcessBatch(batchID, tenant)
	if s := readRows(t, db, tenant, batchID)[id]; !s.processed || s.status != "rejected" || s.attempts != 7 {
		t.Fatalf("after the 7th failure: %+v, want terminal rejected", s)
	}
}

// Rows that LANDED but could not be stamped processed are charged an attempt
// each, not re-imported every claim timeout for ever. The stamp is made to fail
// with a trigger that rejects only the processed-and-error-cleared update for this
// tenant; the failure record (which sets process_error) goes through.
func TestIntegration_MarkProcessedFailureCountsAnAttempt(t *testing.T) {
	p, _, db, tenant := newFlakyBatchProcessor(t, 0) // imports succeed
	batchID := uuid.New().String()
	var ids []uuid.UUID
	for i := 0; i < 3; i++ {
		ids = append(ids, seedOneManaged(t, p, tenant, batchID, fmt.Sprintf("10.78.3.%d", i+1)))
	}
	name := "fail_mark_" + strings.ReplaceAll(tenant.String(), "-", "")
	if _, err := db.Exec(`CREATE OR REPLACE FUNCTION ` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected mark failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER ` + name + ` BEFORE UPDATE ON sensor_discoveries_partitioned
		FOR EACH ROW WHEN (NEW.tenant_id = '` + tenant.String() + `' AND NEW.processed_at IS NOT NULL AND NEW.process_error IS NULL)
		EXECUTE FUNCTION ` + name + `()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + name + ` ON sensor_discoveries_partitioned`)
		_, _ = db.Exec(`DROP FUNCTION IF EXISTS ` + name + `()`)
	})

	var rf *RowFailuresError
	if err := p.ProcessBatch(batchID, tenant); !errors.As(err, &rf) || rf.Failed != 3 || rf.Terminal != 0 {
		t.Fatalf("ProcessBatch = %v, want 3 retryable row failures", err)
	}
	for _, id := range ids {
		s := readRows(t, db, tenant, batchID)[id]
		if s.processed || s.attempts != 1 || !strings.Contains(s.errMsg, "mark processed") {
			t.Fatalf("row %s = %+v, want unprocessed, attempts=1, 'mark processed' recorded", id, s)
		}
	}
	// And it ends: with the policy's attempts spent the rows go terminal.
	p.SetRetryPolicy(RetryPolicy{MaxAttempts: 2})
	if err := p.ProcessBatch(batchID, tenant); !errors.As(err, &rf) || rf.Terminal != 3 {
		t.Fatalf("second attempt = %v, want all 3 terminal", err)
	}
}

// A folded pair shares its survivor's failure: same attempts, error, backoff
// claim and terminal status. Otherwise the follower keeps its original claim,
// is re-claimed unfolded ten minutes later, and is orphaned if the survivor
// goes terminal.
func TestIntegration_FoldedPairSharesTheSurvivorsFailure(t *testing.T) {
	h := newPairHarness(t)
	h.rec.failCode = http.StatusServiceUnavailable
	passive := h.seed(t, "10.0.0.5", "10.20.30.40", 443, "portal.example.test", passiveTLSEnvelope("10.0.0.5", "portal.example.test", nil))
	active := h.seed(t, "10.0.0.5", "10.20.30.40", 443, "", activeTLSEnvelope("10.0.0.5"))

	var rf *RowFailuresError
	if err := h.p.ProcessBatch(h.batchID, h.tenant); !errors.As(err, &rf) || rf.Failed != 2 || rf.Total != 2 || rf.Terminal != 0 {
		t.Fatalf("ProcessBatch = %v, want a RowFailuresError with Failed=2 Total=2 (followers counted), none terminal", err)
	}
	rows := readRows(t, h.raw, h.tenant, h.batchID)
	a, b := rows[passive], rows[active]
	if a.processed || b.processed || a.attempts != 1 || b.attempts != 1 || !strings.Contains(a.errMsg, "503") || a.errMsg != b.errMsg {
		t.Fatalf("after a 503 the pair = %+v / %+v, want both unprocessed, attempts=1, the same error", a, b)
	}
	if a.claimedAt == nil || b.claimedAt == nil || !a.claimedAt.Equal(*b.claimedAt) {
		t.Fatalf("claimed_at differ: %v vs %v; the follower must share the survivor's backoff", a.claimedAt, b.claimedAt)
	}

	// A permanent failure settles both.
	h.rec.failCode = http.StatusBadRequest
	if err := h.p.ProcessBatch(h.batchID, h.tenant); !errors.As(err, &rf) || rf.Terminal != 2 {
		t.Fatalf("ProcessBatch = %v, want both rows terminal", err)
	}
	for name, id := range map[string]uuid.UUID{"passive": passive, "active": active} {
		if s := readRows(t, h.raw, h.tenant, h.batchID)[id]; !s.processed || s.status != "rejected" || s.attempts != 2 || !strings.Contains(s.errMsg, "400") {
			t.Errorf("%s row = %+v, want processed, rejected, attempts=2, the 400", name, s)
		}
	}
}
