package processor

// What a processed cloud discovery row is left saying ( slice F).
//
// Six cloud rows on the demo host sat `approval_status = 'pending'` with
// `asset_id` NULL and `processed_at` set. Nothing surfaced them and no user
// action could clear them: Discovery → Approvals lists pending ASSETS, and the
// only consumer of the value — cluster-sensor-service's per-job materialization
// summary — went on reporting them as "awaiting approval" forever.
//
// This drives the REAL ProcessBatch against a real Postgres and a recorded
// inventory-service, and asserts what each of the three outcomes leaves in the
// row:
//
//	landed on a monitoring asset  → auto_approved, asset_id set
//	landed on a pending asset     → pending (honest), asset_id set — which is
//	                                what lets the later approval settle it
//	landed on NOTHING (routed to
//	external_connections)         → observed, asset_id NULL
//
// Mutations that prove it:
//
//	delete `adoptAssetID(d, result.AssetID)` from importInChunks   → every
//	    asset_id assertion goes red
//	delete the asset-id UPDATE from markProcessed                  → the same
//	    (the id is adopted in memory and never written)
//	delete the `case "routed":` arm from importInChunks            → the CDN
//	    row is `pending` again, which is the exact bug
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// cloudImportOutcome is what the recorded inventory-service answers for one
// finding, keyed by the finding's hostname.
type cloudImportOutcome struct {
	status  string // asset_statuses[i]; "" means "landed on no asset"
	outcome string // results[i].outcome
	assetID string // results[i].asset_id; "" means none
}

// newCloudSettlementInventory answers classify-asset the way a cloud-hinted
// classification really does — `internal`, because the resource sits in a cloud
// segment the tenant owns, which is why these rows travel the managed path
// rather than the processor's own third-party door — and answers the import
// from the per-hostname table.
func newCloudSettlementInventory(t *testing.T, outcomes map[string]cloudImportOutcome) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/api/v2/inventory-service/network-segments/classify-asset" {
			_ = json.NewEncoder(w).Encode(map[string]any{"ownership": "internal", "network_type": "private"})
			return
		}
		var body struct {
			Findings []converter.IngestFinding `json:"findings"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		statuses := make([]string, len(body.Findings))
		results := make([]map[string]string, len(body.Findings))
		for i, f := range body.Findings {
			host := ""
			if f.Hostname != nil {
				host = *f.Hostname
			}
			out, ok := outcomes[host]
			if !ok {
				t.Errorf("the import carried an unexpected finding for %q", host)
				out = cloudImportOutcome{outcome: "rejected"}
			}
			statuses[i] = out.status
			results[i] = map[string]string{"outcome": out.outcome}
			if out.assetID != "" {
				results[i]["asset_id"] = out.assetID
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"imported":       len(body.Findings),
			"asset_statuses": statuses,
			"results":        results,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIntegration_CloudDiscoveryRowsAreSettledAndLinkedToTheirAsset(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	monitoringAsset := uuid.New()
	pendingAsset := uuid.New()

	const (
		bucketHost = "example-bucket-123456789012"
		cdnHost    = "d00000000000aa.example.net"
		freshHost  = "example-fresh-123456789012"
	)

	srv := newCloudSettlementInventory(t, map[string]cloudImportOutcome{
		// The bucket the tenant already approved: ingest matched it and says so.
		bucketHost: {status: "monitoring", outcome: "matched", assetID: monitoringAsset.String()},
		// The distribution: ingest classified it third-party and wrote it to
		// external_connections, so it landed on no asset and reports no status.
		cdnHost: {status: "", outcome: "routed"},
		// A resource seen for the first time: a new asset, awaiting a human.
		freshHost: {status: "pending_approval", outcome: "created", assetID: pendingAsset.String()},
	})

	inventory, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: srv.URL})
	if err != nil {
		t.Fatalf("NewInventoryClient: %v", err)
	}
	processor := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), approval.NewService(raw), inventory, nil)

	batchID, sensorID := uuid.New().String(), uuid.New()
	rows := []struct {
		host     string
		ip       string
		port     int
		protocol string
		atRest   bool
	}{
		{bucketHost, "0.0.0.0", 0, "", true},
		{cdnHost, "203.0.113.61", 443, "HTTPS", false},
		{freshHost, "0.0.0.0", 0, "", true},
	}
	for _, r := range rows {
		metadata := map[string]any{
			"discovery_method": "cloud_api",
			"cloud_provider":   "aws",
			"cloud_region":     "us-east-1",
			"integration_id":   uuid.NewString(),
		}
		if r.atRest {
			metadata["at_rest"] = true
		}
		encoded, _ := json.Marshal(metadata)
		if _, err := raw.Exec(`INSERT INTO sensor_discoveries
			(id,sensor_id,tenant_id,batch_id,protocol,dest_ip,port,confidence,metadata,hostname,timestamp,created_at)
			VALUES($1,$2,$3,$4,$5,$6::inet,$7,1,$8::jsonb,$9,now(),now())`,
			uuid.New(), sensorID, tenant, batchID, r.protocol, r.ip, r.port, encoded, r.host); err != nil {
			t.Fatalf("insert %s: %v", r.host, err)
		}
	}

	if err := processor.ProcessBatch(batchID, tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	type settled struct {
		status  string
		assetID *uuid.UUID
	}
	got := map[string]settled{}
	dbRows, err := raw.Query(`SELECT hostname, approval_status, asset_id FROM sensor_discoveries
		WHERE tenant_id=$1 AND batch_id=$2`, tenant, batchID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	defer func() { _ = dbRows.Close() }()
	for dbRows.Next() {
		var host, status string
		var assetID *uuid.UUID
		if err := dbRows.Scan(&host, &status, &assetID); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[host] = settled{status: status, assetID: assetID}
	}
	if err := dbRows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read back %d rows, want 3", len(got))
	}

	if s := got[bucketHost]; s.status != "auto_approved" {
		t.Errorf("the row on an already-monitoring asset is %q, want %q — its data was materialized and "+
			"nothing will ever clear a `pending` here", s.status, "auto_approved")
	} else if s.assetID == nil || *s.assetID != monitoringAsset {
		t.Errorf("asset_id = %v, want %s — without the link nothing can find the row from the asset", s.assetID, monitoringAsset)
	}

	if s := got[cdnHost]; s.status != "observed" {
		t.Errorf("the routed row is %q, want %q — it landed on no asset, so no approval decision will ever "+
			"be made about it, and claiming `auto_approved` would claim an approval nobody made", s.status, "observed")
	} else if s.assetID != nil {
		t.Errorf("the routed row names asset %s — it produced no asset", *s.assetID)
	}

	if s := got[freshHost]; s.status != "pending" {
		t.Errorf("the row on a newly created pending asset is %q, want %q — there IS a pending asset for a "+
			"human to approve, so this row is honestly waiting", s.status, "pending")
	} else if s.assetID == nil || *s.assetID != pendingAsset {
		t.Errorf("asset_id = %v, want %s — this is the link the later approval settles the row through",
			s.assetID, pendingAsset)
	}
}
