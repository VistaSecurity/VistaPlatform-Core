package processor

// A third-party finding whose external_connections route failed in
// inventory-service comes back as outcome "error". The discovery row must be
// retried (unprocessed, attempt counted, backoff set), not settled the way
// "rejected" is; the permanent "dropped" verdict beside it stays terminal
// ( WP3 follow-up).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// routefailInventory answers each import with the outcome its destination
// names: 203.0.113.50 error, 203.0.113.51 dropped, anything else created.
func routefailInventory(t *testing.T, errorOutcome string) *client.InventoryClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Findings []converter.IngestFinding `json:"findings"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		results := make([]identity.IngestResult, len(body.Findings))
		statuses := make([]string, len(body.Findings))
		for i, f := range body.Findings {
			ip := ""
			if f.IPAddress != nil {
				ip = *f.IPAddress
			}
			switch ip {
			case "203.0.113.50":
				results[i] = identity.IngestResult{Outcome: errorOutcome, Reason: "external_connections route failed: connection reset"}
			case "203.0.113.51":
				results[i] = identity.IngestResult{Outcome: outcomeDropped, Reason: dropReasonThirdPartyNoSourceIP}
			default:
				results[i] = identity.IngestResult{Outcome: string(identity.OutcomeCreated), AssetID: uuid.NewString()}
				statuses[i] = "pending_approval"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"imported": len(results), "asset_statuses": statuses, "results": results})
	}))
	t.Cleanup(srv.Close)
	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIntegration_ProcessBatch_RoutefailErrorOutcomeIsRetriedDroppedIsTerminal(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	p := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), routefailInventory(t, outcomeError), nil)

	batchID, sensorID := uuid.New().String(), uuid.New()
	meta := `{"discovery_method":"passive"}`
	failed := seedTLSDiscovery(t, db, tenant, sensorID, batchID, "203.0.113.50", 443, nil, meta)
	dropped := seedTLSDiscovery(t, db, tenant, sensorID, batchID, "203.0.113.51", 443, nil, meta)
	host := "app.corp.example"
	managed := seedTLSDiscovery(t, db, tenant, sensorID, batchID, "10.77.3.1", 443, &host, meta)

	err := p.ProcessBatch(batchID, tenant)
	if err == nil {
		t.Fatal("ProcessBatch = nil, want a RowFailuresError for the row that must be retried")
	}
	rows := readRows(t, db, tenant, batchID)

	if s := rows[failed]; s.processed || s.status == "rejected" || s.status == "suppressed" || s.attempts != 1 ||
		!strings.Contains(s.errMsg, "connection reset") ||
		s.claimedAt == nil || !s.claimedAt.Before(time.Now().Add(-batchClaimTimeout+time.Minute)) {
		t.Errorf("error-outcome row = %+v, want unprocessed, not rejected/suppressed, 1 attempt, the cause recorded, released with backoff", s)
	}
	if s := rows[dropped]; !s.processed || s.status != "rejected" || !strings.Contains(s.errMsg, "source_ip") {
		t.Errorf("dropped row = %+v, want it still terminal (processed, rejected, with the reason)", s)
	}
	if s := rows[managed]; !s.processed || s.status == "rejected" || s.attempts != 0 {
		t.Errorf("managed row = %+v, want processed as usual", s)
	}
}

// An unrecognised outcome string must not get the retry treatment: pins that
// the test above is exercising the "error" arm and not a generic failure.
func TestIntegration_ProcessBatch_RoutefailUnknownOutcomeIsNotRetried(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	p := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), routefailInventory(t, "some_future_outcome"), nil)

	batchID := uuid.New().String()
	id := seedTLSDiscovery(t, db, tenant, uuid.New(), batchID, "203.0.113.50", 443, nil, `{"discovery_method":"passive"}`)
	if err := p.ProcessBatch(batchID, tenant); err != nil {
		t.Fatalf("ProcessBatch = %v", err)
	}
	if s := readRows(t, db, tenant, batchID)[id]; !s.processed || s.attempts != 0 {
		t.Errorf("row = %+v, want processed with no retry (unknown outcomes are left as the rules set them)", s)
	}
}
