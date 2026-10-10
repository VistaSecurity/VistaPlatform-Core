package processor

// Per-row failure ( F14), driven through the REAL ProcessBatch against a
// real sensor_discoveries table, with a stand-in inventory-service.
//
// Before: one failed import chunk (or one failed external-connection upsert)
// failed the batch; the poller retried the WHOLE batch and, three failures
// later, markBatchAsFailed stamped every row still unprocessed `rejected` —
// rows whose chunk had never been sent included.
//
// After: only the failed rows stay unprocessed, carrying the attempt and the
// error; every row that landed is marked processed; and only the failed rows
// become terminal, with the error, once their attempts are spent.
//
// Mutations that prove it (each goes red in
// TestIntegration_ProcessBatch_FailedChunkCostsOnlyItsRows): make ProcessBatch
// return on a failed import (the old whole-batch shape), or make
// importInChunks abandon the chunks after a failed one.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// flakyInventory stands in for inventory's import: it fails every import of
// exactly failSize findings with a 503 and answers every other.
type flakyInventory struct {
	mu       sync.Mutex
	srv      *httptest.Server
	imports  []int
	failSize int // an import of exactly this many findings fails
	failCode int // status of a failed import; 503 when zero
}

func newFlakyInventory(t *testing.T, failSize int) *flakyInventory {
	t.Helper()
	f := &flakyInventory{failSize: failSize}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			Findings []json.RawMessage `json:"findings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.imports = append(f.imports, len(body.Findings))
		f.mu.Unlock()
		if len(body.Findings) == f.failSize {
			code := f.failCode
			if code == 0 {
				code = http.StatusServiceUnavailable
			}
			http.Error(w, "inventory-service is restarting", code)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"imported": len(body.Findings)})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

type failRowState struct {
	processed bool
	status    string
	attempts  int
	errMsg    string
	claimedAt *time.Time
}

func readRows(t *testing.T, db *sqlx.DB, tenant uuid.UUID, batchID string) map[uuid.UUID]failRowState {
	t.Helper()
	rows, err := db.Query(`SELECT id, processed_at IS NOT NULL, COALESCE(approval_status,''), process_attempts, COALESCE(process_error,''), claimed_at
		FROM sensor_discoveries WHERE tenant_id = $1 AND batch_id = $2`, tenant, batchID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[uuid.UUID]failRowState{}
	for rows.Next() {
		var id uuid.UUID
		var s failRowState
		if err := rows.Scan(&id, &s.processed, &s.status, &s.attempts, &s.errMsg, &s.claimedAt); err != nil {
			t.Fatal(err)
		}
		out[id] = s
	}
	return out
}

func newFlakyBatchProcessor(t *testing.T, failSize int) (*BatchProcessor, *flakyInventory, *sqlx.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	inv := newFlakyInventory(t, failSize)
	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: inv.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	p := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), c, nil)
	return p, inv, db, tenant
}

func TestIntegration_ProcessBatch_FailedChunkCostsOnlyItsRows(t *testing.T) {
	// 60 managed findings → a chunk of 50 that FAILS, then a chunk of 10 that
	// lands. The failing chunk comes first on purpose: the old code abandoned
	// every chunk after a failure, so the 10 would never have been sent.
	p, inv, db, tenant := newFlakyBatchProcessor(t, importChunkSize)
	p.SetRetryPolicy(RetryPolicy{MaxAttempts: 3}) // the default budget is longer; this test walks a short one to its end
	batchID, sensorID := uuid.New().String(), uuid.New()
	for i := 0; i < 60; i++ {
		host := fmt.Sprintf("host-%02d.corp.example", i)
		seedTLSDiscovery(t, db, tenant, sensorID, batchID, fmt.Sprintf("10.77.0.%d", i+1), 443, &host,
			`{"discovery_method":"passive","cipher_suite":"TLS_AES_128_GCM_SHA256","version":"TLS 1.3"}`)
	}

	// Attempt 1.
	err := p.ProcessBatch(batchID, tenant)
	var rf *RowFailuresError
	if !errors.As(err, &rf) || rf.Failed != 50 || rf.Terminal != 0 {
		t.Fatalf("ProcessBatch = %v, want a RowFailuresError for exactly the 50 rows of the failed chunk, none terminal yet", err)
	}
	var landed, failed []uuid.UUID
	for id, s := range readRows(t, db, tenant, batchID) {
		if s.processed {
			landed = append(landed, id)
			if s.attempts != 0 || s.errMsg != "" {
				t.Errorf("landed row %s carries attempts=%d error=%q", id, s.attempts, s.errMsg)
			}
			continue
		}
		failed = append(failed, id)
		if s.attempts != 1 || !strings.Contains(s.errMsg, "503") {
			t.Errorf("failed row %s: attempts=%d error=%q, want 1 and the 503", id, s.attempts, s.errMsg)
		}
		// Released with a backoff: claimable again once claimed_at is
		// batchClaimTimeout old, i.e. after the backoff, not now.
		if s.claimedAt == nil || !s.claimedAt.Before(time.Now().Add(-batchClaimTimeout+time.Minute)) || !s.claimedAt.After(time.Now().Add(-batchClaimTimeout)) {
			t.Errorf("failed row %s: claimed_at %v is not a backoff release (between now-%v and now-%v+1m)", id, s.claimedAt, batchClaimTimeout, batchClaimTimeout)
		}
	}
	if len(landed) != 10 || len(failed) != 50 {
		t.Fatalf("after one attempt: %d rows processed, %d unprocessed — want the second chunk's 10 processed and only the failed chunk's 50 left for retry", len(landed), len(failed))
	}

	// Attempts 2 and 3: only the failed rows are read and re-sent.
	for attempt := 2; attempt <= 3; attempt++ {
		err := p.ProcessBatch(batchID, tenant)
		if !errors.As(err, &rf) || rf.Failed != 50 {
			t.Fatalf("attempt %d: %v, want the same 50 rows failing", attempt, err)
		}
		if attempt == 3 && rf.Terminal != 50 {
			t.Fatalf("attempt 3 left %d of 50 terminal, want all 50", rf.Terminal)
		}
	}
	inv.mu.Lock()
	sizes := append([]int(nil), inv.imports...)
	inv.mu.Unlock()
	if want := []int{50, 10, 50, 50}; len(sizes) != len(want) || sizes[0] != 50 || sizes[1] != 10 || sizes[2] != 50 || sizes[3] != 50 {
		t.Fatalf("import calls carried %v findings, want %v: the chunk after a failed one is still sent, and a retry re-sends only the failed rows", sizes, want)
	}

	after := readRows(t, db, tenant, batchID)
	for _, id := range landed {
		if s := after[id]; !s.processed || s.status == "rejected" {
			t.Errorf("landed row %s became %+v; a later failure of OTHER rows must not touch it", id, s)
		}
	}
	for _, id := range failed {
		s := after[id]
		if !s.processed || s.status != "rejected" || s.attempts != 3 || !strings.Contains(s.errMsg, "503") {
			t.Errorf("failed row %s after 3 attempts = %+v, want processed, rejected, 3 attempts, the 503 recorded", id, s)
		}
	}
}

// A third-party finding with no source address is dropped by inventory
// ( D2) and costs only its own row: it is settled terminal with the
// reason, counted, and the batch is not failed — the managed row beside it
// lands as usual.
func TestIntegration_ProcessBatch_DroppedThirdPartyCostsOnlyItsRow(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	inv := newRouteInventoryStandIn(t)
	audit := &recordingSink{}
	p := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), inv.client(t), audit)

	batchID, sensorID := uuid.New().String(), uuid.New()
	// seedTLSDiscovery writes a source_ip; clear it on the third-party row.
	dropped := seedTLSDiscovery(t, db, tenant, sensorID, batchID, "203.0.113.77", 443, nil, `{"discovery_method":"passive"}`)
	if _, err := db.Exec(`UPDATE sensor_discoveries SET source_ip = NULL WHERE tenant_id=$1 AND id=$2`, tenant, dropped); err != nil {
		t.Fatal(err)
	}
	host := "app.corp.example"
	managed := seedTLSDiscovery(t, db, tenant, sensorID, batchID, "10.77.1.1", 443, &host, `{"discovery_method":"passive"}`)

	if err := p.ProcessBatch(batchID, tenant); err != nil {
		t.Fatalf("ProcessBatch = %v; a dropped finding is a decision about its row, not a batch failure", err)
	}
	inv.assertOnlyImports(t)
	if n := len(inv.allImported()); n != 2 {
		t.Fatalf("imported %d findings, want both — the processor no longer decides what is third party", n)
	}
	rows := readRows(t, db, tenant, batchID)
	if !rows[managed].processed || rows[managed].status == "rejected" {
		t.Fatalf("the managed row = %+v, want processed as usual", rows[managed])
	}
	if s := rows[dropped]; !s.processed || s.status != "rejected" || !strings.Contains(s.errMsg, "source_ip") {
		t.Fatalf("the dropped row = %+v, want processed, rejected, with the reason", s)
	}
	if events := audit.all(); len(events) != 1 || events[0].Counts["third_party_dropped_no_source_ip"] != 1 {
		t.Fatalf("audit events = %+v, want the drop counted", events)
	}
}

// A 4xx is permanent: the row is terminal at once, with the error, and still
// only that row.
func TestIntegration_ProcessBatch_PermanentRowFailureIsTerminalAtOnce(t *testing.T) {
	p, _, db, tenant := newFlakyBatchProcessor(t, 0)
	batchID := uuid.New().String()
	id := seedTLSDiscovery(t, db, tenant, uuid.New(), batchID, "10.77.2.1", 443, nil, `{}`)
	terminal, err := p.recordRowFailures(t.Context(), tenant, []rowFailure{{
		id: id, permanent: true, err: &client.HTTPStatusError{StatusCode: http.StatusUnprocessableEntity, Op: "import", Body: "bad"},
	}})
	if err != nil || terminal != 1 {
		t.Fatalf("recordRowFailures = %d %v, want 1 terminal", terminal, err)
	}
	if s := readRows(t, db, tenant, batchID)[id]; !s.processed || s.status != "rejected" || s.attempts != 1 || !strings.Contains(s.errMsg, "422") {
		t.Fatalf("row = %+v, want processed, rejected, attempt 1, the 422 recorded", s)
	}
}
