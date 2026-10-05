package services

// What reaches cluster-sensor-service from three of the four callers that
// moved onto the shared scan engine ( WP4), driven through the REAL
// entry points — CreateActiveScanJob, CreateRevalidationJob and the identity
// backend's Dispatch — against a real Postgres, with an httptest stand-in for
// cluster-sensor-service recording each request body: scan_depth "custom" on
// the caller's ports, no protocols, no ports, the caller's routing unchanged,
// and options.active_scan (the provenance stamp on the results). The
// automatic scan's request is pinned in internal/jobs.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// assertPlannedWire checks one recorded request body.
func assertPlannedWire(t *testing.T, who string, body map[string]interface{}, tcpPorts, mode string, sensors []string) {
	t.Helper()
	if body["scan_depth"] != "custom" || body["tcp_ports"] != tcpPorts {
		t.Errorf("%s: scan_depth %v tcp_ports %v, want custom on %q", who, body["scan_depth"], body["tcp_ports"], tcpPorts)
	}
	for _, legacy := range []string{"protocols", "ports"} {
		if list, _ := body[legacy].([]interface{}); len(list) != 0 {
			t.Errorf("%s: still sends %s %v", who, legacy, body[legacy])
		}
	}
	if body["execution_mode"] != mode {
		t.Errorf("%s: execution_mode %v, want %q", who, body["execution_mode"], mode)
	}
	got, _ := body["preferred_sensor_ids"].([]interface{})
	if len(got) != len(sensors) {
		t.Errorf("%s: preferred_sensor_ids %v, want %v", who, got, sensors)
	} else {
		for i := range sensors {
			if got[i] != sensors[i] {
				t.Errorf("%s: preferred_sensor_ids %v, want %v", who, got, sensors)
			}
		}
	}
	opts, _ := body["options"].(map[string]interface{})
	if opts["active_scan"] != true {
		t.Errorf("%s: options %v lack active_scan — the results would be ingested as passive observations", who, opts)
	}
}

type fixedRouter struct{ sensor sensorrouting.Sensor }

func (r fixedRouter) Resolve(context.Context, uuid.UUID, []string, time.Time) (sensorrouting.Plan, error) {
	return sensorrouting.Plan{}, nil
}
func (r fixedRouter) FindDispatchable(context.Context, uuid.UUID, uuid.UUID, time.Time) (sensorrouting.Sensor, error) {
	return r.sensor, nil
}

func TestIntegration_ActiveScanAndRevalidation_SendPlannedJobs(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	user := uuid.New()
	asset := func(address string, port int) uuid.UUID {
		id := uuid.New()
		if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,$3,$4,'server','hardware.computer.server','monitoring')`,
			id, tenant, "wire-"+id.String()[:8], address); err != nil {
			t.Fatal(err)
		}
		if port > 0 {
			if _, err := raw.Exec(`INSERT INTO asset_endpoints(tenant_id,asset_id,address,port,transport) VALUES($1,$2,$3,$4,'tcp')`, tenant, id, address, port); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	ssh := asset("10.20.0.5", 2222)
	portless := asset("10.20.0.6", 0)
	// An SSH configuration recorded on the 2222 asset: before WP4 it chose
	// the protocol list; now nothing reads it.
	if _, err := raw.Exec(`INSERT INTO crypto_implementations(tenant_id,asset_id,protocol,discovery_method) VALUES($1,$2,'SSH','active')`, tenant, ssh); err != nil {
		t.Fatal(err)
	}

	cluster := &fakeClusterSensor{}
	srv := httptest.NewServer(cluster)
	t.Cleanup(srv.Close)
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", srv.URL)
	ds, err := NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	beat := time.Now()
	sensor := sensorrouting.Sensor{ID: uuid.New(), Name: "edge", Status: "active", LastHeartbeat: &beat, ReportingInterval: 30}
	svc := &RevalidationService{db: db, discoveryService: ds, router: fixedRouter{sensor: sensor}}

	// Active Scan from the platform: one job per port list.
	if _, err := svc.CreateActiveScanJob(tenant, user, []uuid.UUID{ssh, portless}, "", RunFrom{Mode: RunFromPlatform}, false); err != nil {
		t.Fatal(err)
	}
	calls := cluster.calls()
	if len(calls) != 2 {
		t.Fatalf("%d jobs, want 2 (2222, and the 443/8443 fallback)", len(calls))
	}
	byPorts := map[string]map[string]interface{}{}
	for _, b := range calls {
		ports, _ := b["tcp_ports"].(string)
		byPorts[ports] = b
	}
	assertPlannedWire(t, "Active Scan, asset port", byPorts["2222"], "2222", "async", nil)
	assertPlannedWire(t, "Active Scan, fallback ports", byPorts["443,8443"], "443,8443", "async", nil)

	// Active Scan from a named sensor: routing unchanged.
	if _, err := svc.CreateActiveScanJob(tenant, user, []uuid.UUID{ssh}, "", RunFrom{Mode: RunFromSensor, SensorID: sensor.ID}, false); err != nil {
		t.Fatal(err)
	}
	calls = cluster.calls()
	assertPlannedWire(t, "Active Scan, run from a sensor", calls[len(calls)-1], "2222", "sensors", []string{sensor.ID.String()})

	// Revalidation: the platform, same port grouping.
	if _, err := svc.CreateRevalidationJob(tenant, user, []uuid.UUID{ssh}, ""); err != nil {
		t.Fatal(err)
	}
	calls = cluster.calls()
	assertPlannedWire(t, "Revalidation", calls[len(calls)-1], "2222", "async", nil)
}

func TestIntegration_IdentityProbeDispatch_SendsAPlannedJob(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	ctx := context.Background()
	sensor, segment := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat) VALUES($1,$2,'branch-sensor','linux','4.4.0','datacenter_host','active',$3)`, []any{sensor, tenant, now}},
		{`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, []any{tenant}},
	} {
		if _, err := raw.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	cluster := &fakeClusterSensor{}
	cs := httptest.NewServer(cluster)
	defer cs.Close()
	backend := NewIdentityEnrichmentBackend(NewAssetService(db), &DiscoveryService{httpClient: cs.Client(), clusterSensorURL: cs.URL})
	store := &identityenrichment.Store{DB: db}
	o := identityenrichment.Observation{ID: uuid.New(), State: "unresolved", Evidence: identity.Observation{
		TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + sensor.String()}, ObservedAt: now,
		Network:     identity.Network{SegmentID: segment.String()},
		Identifiers: []identity.Identifier{{Kind: identity.KindIPAddress, Value: "10.40.0.31", Scope: segment.String()}},
	}}
	evidence, _ := json.Marshal(o.Evidence)
	if _, err := raw.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1,$2,$3,'measured',$4,$5,$6,$6)`,
		tenant, o.ID, uuid.NewString(), o.Evidence.Source.Ref, string(evidence), now); err != nil {
		t.Fatal(err)
	}
	plan := identityenrichment.Plan{Action: "probe", Executor: "sensor:" + sensor.String(), SensorID: sensor, SegmentID: segment, SegmentCIDR: "10.40.0.0/24",
		Addresses: []string{"10.40.0.31"}, Protocols: []string{"SSH", "TLS"}, Ports: []int{22, 443}}
	job, err := store.EnsureProbe(ctx, tenant, o, plan, now, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.Dispatch(ctx, job, o)
	if err != nil || result.State != "queued" {
		t.Fatalf("dispatch = %+v %v", result, err)
	}
	calls := cluster.calls()
	if len(calls) != 1 {
		t.Fatalf("%d requests, want 1", len(calls))
	}
	body := calls[0]
	assertPlannedWire(t, "identity probe", body, "22,443", "sensors", []string{sensor.String()})
	opts, _ := body["options"].(map[string]interface{})
	if opts["identity_enrichment_request_id"] != job.RequestID.String() || opts["origin"] != "identity_enrichment" {
		t.Fatalf("identity options %v lost the request id or origin", opts)
	}
}
