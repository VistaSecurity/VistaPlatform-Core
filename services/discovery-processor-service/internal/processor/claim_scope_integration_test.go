package processor

// ProcessClaimedBatch reads only the rows of ITS claim ( WP1).
//
// One batch, three unprocessed rows: one carrying this claim's stamp, one in
// another claim's retry backoff (claimed_at = now - batchClaimTimeout + 5m,
// which looks freshly claimed), and one that joined the batch after the
// claim (claimed_at NULL). Only the first may be processed: the backing-off
// row would otherwise be retried early by any re-claim of its batch, and the
// late row processed with no claim at all.
//
// Drop the `claimed_at = $3` predicate from processBatch's query and this
// goes red: all three rows are imported.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIntegration_ProcessClaimedBatch_ReadsOnlyTheRowsOfItsClaim(t *testing.T) {
	p, inv, db, tenant := newFlakyBatchProcessor(t, -1) // nothing fails
	batchID, sensorID := uuid.New().String(), uuid.New()
	seed := func(i int) uuid.UUID {
		host := fmt.Sprintf("claim-%d.corp.example", i)
		return seedTLSDiscovery(t, db, tenant, sensorID, batchID, fmt.Sprintf("10.79.0.%d", i), 443, &host,
			`{"discovery_method":"passive","cipher_suite":"TLS_AES_128_GCM_SHA256","version":"TLS 1.3"}`)
	}
	claimed, backingOff, late := seed(1), seed(2), seed(3)

	var stamp time.Time
	if err := db.QueryRow(`UPDATE sensor_discoveries SET claimed_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING claimed_at`, tenant, claimed).Scan(&stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sensor_discoveries SET claimed_at = now() - $3::interval + interval '5 minutes', process_attempts = 1
		WHERE tenant_id = $1 AND id = $2`, tenant, backingOff, intervalArg(batchClaimTimeout)); err != nil {
		t.Fatal(err)
	}

	if err := p.ProcessClaimedBatch(batchID, tenant, stamp); err != nil {
		t.Fatalf("ProcessClaimedBatch: %v", err)
	}

	inv.mu.Lock()
	sizes := append([]int(nil), inv.imports...)
	inv.mu.Unlock()
	if len(sizes) != 1 || sizes[0] != 1 {
		t.Fatalf("import calls carried %v findings, want exactly [1]: only the claimed row may be sent", sizes)
	}
	rows := readRows(t, db, tenant, batchID)
	if !rows[claimed].processed {
		t.Errorf("the row this claim took was not processed: %+v", rows[claimed])
	}
	if s := rows[backingOff]; s.processed || s.attempts != 1 {
		t.Errorf("the row in retry backoff was processed early by another claim: %+v", s)
	}
	if s := rows[late]; s.processed || s.claimedAt != nil {
		t.Errorf("the row that joined after the claim was processed without one: %+v", s)
	}
}
