package services

// Per-asset Active Scan of an asset outside the registered networks (
// W5.13b, owner decision Q10): ASKED about, not refused — and nothing about
// the asset changes until the person answers. Real Postgres for the scope and
// the asset rows; an httptest server stands in for cluster-sensor-service.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type fakeClusterSensor struct {
	mu     sync.Mutex
	bodies []map[string]interface{}
	answer func(body map[string]interface{}) (int, string)
}

func (f *fakeClusterSensor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.bodies = append(f.bodies, body)
	f.mu.Unlock()
	status, out := http.StatusAccepted, `{"job":{"id":"`+uuid.NewString()+`","status":"queued"}}`
	if f.answer != nil {
		status, out = f.answer(body)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(out))
}

func (f *fakeClusterSensor) calls() []map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]interface{}{}, f.bodies...)
}

func TestIntegration_ActiveScan_ExternalAssetsAskFirst(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	user := uuid.New()

	insertAsset := func(hostname, address string) uuid.UUID {
		id := uuid.New()
		var addr interface{}
		if address != "" {
			addr = address
		}
		if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,$3,$4,'server','hardware.computer.server','pending_approval')`, id, tenant, hostname, addr); err != nil {
			t.Fatal(err)
		}
		return id
	}
	external := insertAsset("partner-portal", "93.184.216.34")
	internal := insertAsset("intranet-web", "10.20.0.5")
	named := insertAsset("portal.example.com", "")

	cluster := &fakeClusterSensor{}
	srv := httptest.NewServer(cluster)
	t.Cleanup(srv.Close)
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", srv.URL)
	ds, err := NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	svc := &RevalidationService{db: db, discoveryService: ds}
	platform := RunFrom{Mode: RunFromPlatform}
	status := func(id uuid.UUID) string {
		var s string
		if err := raw.QueryRow(`SELECT asset_status FROM assets WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// 1. Unconfirmed: asked, naming the public asset only; NOTHING dispatched
	//    or stamped — not even the internal asset in the same request.
	_, err = svc.CreateActiveScanJob(tenant, user, []uuid.UUID{external, internal}, "", platform, false)
	var needs *ExternalConfirmationError
	if !errors.As(err, &needs) {
		t.Fatalf("unconfirmed scan of a public asset: err=%v, want ExternalConfirmationError", err)
	}
	if len(needs.Targets) != 1 || needs.Targets[0].AssetID != external || needs.Targets[0].AssetName != "partner-portal" || needs.Targets[0].Target != "93.184.216.34" {
		t.Fatalf("asked about %+v, want only partner-portal at 93.184.216.34", needs.Targets)
	}
	if n := len(cluster.calls()); n != 0 {
		t.Fatalf("%d dispatch(es) before the person answered", n)
	}
	if s := status(external); s != "pending_approval" {
		t.Fatalf("external asset was changed to %q before confirmation", s)
	}
	if s := status(internal); s != "pending_approval" {
		t.Fatalf("internal asset in the same request was changed to %q before the question was answered", s)
	}

	// 2. Confirmed: dispatched with the flag.
	result, err := svc.CreateActiveScanJob(tenant, user, []uuid.UUID{external, internal}, "", platform, true)
	if err != nil || len(result.Jobs) == 0 {
		t.Fatalf("confirmed scan: result=%+v err=%v", result, err)
	}
	for _, body := range cluster.calls() {
		if body["external_targets_confirmed"] != true {
			t.Fatalf("confirmed scan dispatched without the flag: %v", body)
		}
	}

	// 3. The stale-revalidation sweep never carries a confirmation.
	before := len(cluster.calls())
	if _, err := svc.CreateRevalidationJob(tenant, user, []uuid.UUID{external}, ""); err != nil {
		t.Fatal(err)
	}
	for _, body := range cluster.calls()[before:] {
		if _, has := body["external_targets_confirmed"]; has {
			t.Fatalf("the revalidation sweep sent a confirmation: %v", body)
		}
	}

	// 4. An asset known only by name is resolved and asked about too, before
	//    anything changes.
	svc.resolver = stubNames{"portal.example.com": "93.184.216.40"}
	before = len(cluster.calls())
	_, err = svc.CreateActiveScanJob(tenant, user, []uuid.UUID{named}, "", platform, false)
	if !errors.As(err, &needs) || len(needs.Targets) != 1 || needs.Targets[0].AssetID != named {
		t.Fatalf("name-only asset: err=%v, want ExternalConfirmationError naming it", err)
	}
	if got := needs.Targets[0].Addresses; len(got) != 1 || got[0] != "93.184.216.40" {
		t.Fatalf("resolved addresses not reported: %+v", needs.Targets[0])
	}
	if n := len(cluster.calls()) - before; n != 0 {
		t.Fatalf("%d dispatch(es) for a name-only asset before the person answered", n)
	}
	if s := status(named); s != "pending_approval" {
		t.Fatalf("name-only asset was changed to %q before confirmation", s)
	}

	// 5. cluster-sensor-service's verdict on a batch reaches the caller per
	//    asset, as a skip with the reason — not a folded "failed to dispatch".
	cluster.answer = func(map[string]interface{}) (int, string) {
		return http.StatusBadRequest, `{"error":"targets_refused","message":"refused","refused_targets":[{"target":"10.20.0.5","reason":"the range is excluded from scanning"}]}`
	}
	result, err = svc.CreateActiveScanJob(tenant, user, []uuid.UUID{internal}, "", platform, false)
	if err != nil {
		t.Fatalf("a refused batch became an error instead of a per-asset skip: %v", err)
	}
	if len(result.Skipped) != 1 || result.Skipped[0].AssetID != internal || result.Skipped[0].Reason != "the range is excluded from scanning" {
		t.Fatalf("skipped = %+v, want the internal asset with the refusal reason", result.Skipped)
	}
}

type stubNames map[string]string

func (r stubNames) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	return nil, errors.New("no such host")
}

// TestRecordTargetVerdict_MapsTheAnswerBackToAssets is the fallback: when
// cluster-sensor-service answers a batch with a target verdict, each asset
// gets its own outcome — never one folded "failed to start".
func TestRecordTargetVerdict_MapsTheAnswerBackToAssets(t *testing.T) {
	a1, a2 := uuid.New(), uuid.New()
	batch := activeScanBatch{assetIDs: []uuid.UUID{a1, a2}, targets: []string{"portal.example.com", "93.184.216.9"},
		assetsByHost: map[string][]uuid.UUID{"portal.example.com": {a1}, "93.184.216.9": {a2}}}
	var r ActiveScanResult
	svc := &RevalidationService{}
	ok := svc.recordTargetVerdict(&r, batch, &DownstreamError{Status: 422, Code: "external_targets_unconfirmed",
		ExternalTargets: []byte(`[{"target":"portal.example.com","addresses":["93.184.216.40"]}]`)})
	if !ok || len(r.NeedsConfirmation) != 1 || r.NeedsConfirmation[0].AssetID != a1 {
		t.Fatalf("unconfirmed verdict mapped to %+v", r.NeedsConfirmation)
	}
	r = ActiveScanResult{}
	svc.recordTargetVerdict(&r, batch, &DownstreamError{Status: 400, Code: "targets_refused",
		RefusedTargets: []byte(`[{"target":"93.184.216.9","reason":"it resolves to an address the platform never scans"}]`)})
	if len(r.Skipped) != 1 || r.Skipped[0].AssetID != a2 || r.Skipped[0].Reason == "" {
		t.Fatalf("refused verdict mapped to %+v", r.Skipped)
	}
	r = ActiveScanResult{}
	svc.recordTargetVerdict(&r, batch, &DownstreamError{Status: 403, Code: "external_targets_disabled"})
	if len(r.Skipped) != 2 {
		t.Fatalf("disabled verdict skipped %d asset(s), want both", len(r.Skipped))
	}
	if svc.recordTargetVerdict(&r, batch, &DownstreamError{Status: 409, Message: "sensor offline"}) {
		t.Fatal("a non-verdict error was treated as a verdict")
	}
}
