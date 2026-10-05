package services

// A "Scan all" whose batches do not all dispatch ( item 10).
//
// An Active Scan is split into one job per port list, and each is routed to an
// executor. When one batch's job is created and another's is refused for a
// reason that is not a target verdict (a rate limit, a budget, a downstream
// failure), the request still succeeds — and the refused batch's assets used to
// appear nowhere in the response: not in `jobs`, not in `skipped`. The person
// saw "Active scan started for N assets" and nine hosts were never scanned,
// with only a server log line to say so.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ActiveScan_RefusedBatchIsReportedWhenAnotherBatchStarts(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	user := uuid.New()

	insertAsset := func(hostname, address string) uuid.UUID {
		id := uuid.New()
		if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,$3,$4,'server','hardware.computer.server','monitoring')`, id, tenant, hostname, address); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// One asset with an endpoint on its own port: its own batch (ports [8080]).
	withPort := insertAsset("has-endpoint", "10.20.0.5")
	if _, err := raw.Exec(`INSERT INTO asset_endpoints(tenant_id,asset_id,address,port,transport) VALUES($1,$2,'10.20.0.5',8080,'tcp')`, tenant, withPort); err != nil {
		t.Fatal(err)
	}
	// Three with no endpoint: one batch on the fallback ports, several targets.
	var portless []uuid.UUID
	for _, h := range []string{"10.20.0.11", "10.20.0.12", "10.20.0.13"} {
		portless = append(portless, insertAsset("portless-"+h, h))
	}

	// The fallback-ports batch (several targets) is refused; the single-target
	// batch is accepted.
	cluster := &fakeClusterSensor{answer: func(body map[string]interface{}) (int, string) {
		if targets, _ := body["targets"].([]interface{}); len(targets) > 1 {
			return http.StatusTooManyRequests, `{"error":"rate limit exceeded: too many concurrent jobs (5/5)"}`
		}
		return http.StatusAccepted, `{"job":{"id":"` + uuid.NewString() + `","status":"queued"}}`
	}}
	srv := httptest.NewServer(cluster)
	t.Cleanup(srv.Close)
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", srv.URL)
	ds, err := NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	svc := &RevalidationService{db: db, discoveryService: ds}

	ids := append([]uuid.UUID{withPort}, portless...)
	result, err := svc.CreateActiveScanJob(tenant, user, ids, "", RunFrom{Mode: RunFromPlatform}, false)
	if err != nil {
		t.Fatalf("a partial dispatch is a success with a report, got error: %v", err)
	}
	if len(result.Jobs) != 1 || result.Scanned != 1 {
		t.Fatalf("jobs=%+v scanned=%d, want the one accepted batch", result.Jobs, result.Scanned)
	}

	// Every asset of the refused batch is named, with a reason that says why.
	skipped := map[uuid.UUID]string{}
	for _, s := range result.Skipped {
		skipped[s.AssetID] = s.Reason
	}
	for _, id := range portless {
		reason, ok := skipped[id]
		if !ok {
			t.Fatalf("asset %v was neither scanned nor reported as skipped: skipped=%+v", id, result.Skipped)
		}
		if !strings.Contains(reason, "rate limit exceeded") {
			t.Errorf("skip reason %q does not carry the downstream refusal", reason)
		}
	}
	if _, ok := skipped[withPort]; ok {
		t.Errorf("the dispatched asset was also reported as skipped")
	}
}
