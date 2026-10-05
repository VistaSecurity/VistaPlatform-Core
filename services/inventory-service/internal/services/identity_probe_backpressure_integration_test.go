package services

// The identity-enrichment probe flood seen on a lab deployment, the submit and
// correlation half: the real backend refuses to hand a full sensor another
// probe (no request leaves inventory-service), and maps the sensor's own
// "busy" refusal to a wait-and-resend with a NEW request — not to the
// `probe_failed_review_collector_before_retry` block that a real failure gets.
// cluster-sensor-service is an httptest stand-in that records every job
// request and writes the discovery_jobs row the real one would.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_IdentityProbeBackPressureAtSubmit(t *testing.T) {
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
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat) VALUES($1,$2,'branch-sensor','windows','4.3.1','datacenter_host','active',$3)`, []any{sensor, tenant, now}},
		{`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, []any{tenant}},
	} {
		if _, err := raw.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}

	// cluster-sensor-service: accept the job, write its row as awaiting the
	// sensor (as the real dispatcher would), remember the request ID.
	var (
		mu       sync.Mutex
		requests []string
	)
	cs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Options map[string]interface{} `json:"options"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requestID, _ := body.Options["identity_enrichment_request_id"].(string)
		id := uuid.New()
		meta, _ := json.Marshal(map[string]interface{}{"options": body.Options})
		if _, err := raw.Exec(`INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,assigned_sensor_id,requested_sensor_ids,metadata) VALUES($1,$2,'sensors','awaiting_sensor',$3,ARRAY[$5::text],$4)`, id, tenant, sensor, string(meta), sensor.String()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		requests = append(requests, requestID)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"job": map[string]interface{}{"id": id.String(), "status": "queued"}})
	}))
	defer cs.Close()
	sent := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), requests...)
	}

	backend := NewIdentityEnrichmentBackend(NewAssetService(db), &DiscoveryService{httpClient: cs.Client(), clusterSensorURL: cs.URL})
	store := &identityenrichment.Store{DB: db}
	o := identityenrichment.Observation{ID: uuid.New(), State: "unresolved", Evidence: identity.Observation{
		TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + sensor.String()}, ObservedAt: now,
		Network:     identity.Network{SegmentID: segment.String()},
		Identifiers: []identity.Identifier{{Kind: identity.KindIPAddress, Value: "198.51.100.131", Scope: segment.String()}},
	}}
	evidence, _ := json.Marshal(o.Evidence)
	if _, err := raw.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1,$2,$3,'measured',$4,$5,$6,$6)`,
		tenant, o.ID, uuid.NewString(), o.Evidence.Source.Ref, string(evidence), now); err != nil {
		t.Fatal(err)
	}
	plan := identityenrichment.Plan{Action: "probe", Executor: "sensor:" + sensor.String(), SensorID: sensor, SegmentID: segment, SegmentCIDR: "198.51.100.0/24",
		Addresses: []string{"198.51.100.131"}, Protocols: []string{"SSH", "TLS"}, Ports: []int{22, 443}}
	job, err := store.EnsureProbe(ctx, tenant, o, plan, now, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// The sensor already holds its share of work from other scans.
	var busy []uuid.UUID
	for range identityenrichment.MaxCollectorJobsInFlight {
		id := uuid.New()
		if _, err := raw.Exec(`INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,assigned_sensor_id,metadata) VALUES($1,$2,'sensors','awaiting_sensor',$3,'{"options":{"origin":"manual"}}')`, id, tenant, sensor); err != nil {
			t.Fatal(err)
		}
		busy = append(busy, id)
	}
	held, err := backend.Dispatch(ctx, job, o)
	if err != nil {
		t.Fatal(err)
	}
	if held.State != "waiting" || held.Reason != identityenrichment.ReasonCollectorBusy || held.RemoteID != "" {
		t.Fatalf("dispatch to a full sensor = %+v, want waiting/%s with nothing sent", held, identityenrichment.ReasonCollectorBusy)
	}
	if n := len(sent()); n != 0 {
		t.Fatalf("%d probe request(s) sent to a sensor already holding %d jobs, want 0", n, identityenrichment.MaxCollectorJobsInFlight)
	}

	// One of them finishes: there is room, and the probe goes out.
	if _, err := raw.Exec(`UPDATE discovery_jobs SET status='completed' WHERE id=$1`, busy[0]); err != nil {
		t.Fatal(err)
	}
	claimed, lease, ok, err := store.Claim(ctx, job, now)
	if err != nil || !ok {
		t.Fatalf("claim %v %v", ok, err)
	}
	queued, err := backend.Dispatch(ctx, claimed, o)
	if err != nil || queued.State != "queued" || queued.RemoteID == "" {
		t.Fatalf("dispatch with room = %+v %v, want queued", queued, err)
	}
	if err := store.Finish(ctx, claimed, lease, queued, now); err != nil {
		t.Fatal(err)
	}
	first := sent()
	if len(first) != 1 || first[0] != claimed.RequestID.String() {
		t.Fatalf("requests sent = %v, want exactly the job's request %s", first, claimed.RequestID)
	}

	// The sensor refuses it anyway (a race between workers, or room taken by a
	// person's scan): cluster-sensor fails it with the sensor-busy code.
	if _, err := raw.Exec(`UPDATE discovery_jobs SET status='failed',error_message='sensor branch-sensor refused the job: sensor busy: 8 discovery jobs already queued; nothing was scanned',
		metadata=jsonb_set(metadata,'{`+sensordispatch.FailureCodeKey+`}',to_jsonb($2::text)) WHERE id=$1`, queued.RemoteID, sensordispatch.FailureCodeSensorBusy); err != nil {
		t.Fatal(err)
	}
	later := now.Add(2 * time.Minute)
	claimed, lease, ok, err = store.Claim(ctx, job, later)
	if err != nil || !ok {
		t.Fatalf("claim for poll %v %v", ok, err)
	}
	polled, err := backend.Poll(ctx, claimed, o)
	if err != nil {
		t.Fatal(err)
	}
	if polled.State != "waiting" || polled.Reason != identityenrichment.ReasonCollectorBusy || !polled.Redispatch {
		t.Fatalf("poll of a busy refusal = %+v, want waiting/%s and a redispatch — not probe_failed_review_collector_before_retry", polled, identityenrichment.ReasonCollectorBusy)
	}
	if err := store.Finish(ctx, claimed, lease, polled, later); err != nil {
		t.Fatal(err)
	}
	var next time.Time
	if err := raw.QueryRow(`SELECT next_attempt_at FROM identity_enrichment_jobs WHERE tenant_id=$1 AND id=$2`, tenant, job.ID).Scan(&next); err != nil {
		t.Fatal(err)
	}
	claimed, lease, ok, err = store.Claim(ctx, job, next)
	if err != nil || !ok {
		t.Fatalf("claim after backoff %v %v", ok, err)
	}
	if claimed.RemoteID != "" {
		t.Fatalf("after a busy refusal the job still names the refused request %s", claimed.RemoteID)
	}
	again, err := backend.Dispatch(ctx, claimed, o)
	if err != nil || again.State != "queued" {
		t.Fatalf("redispatch = %+v %v", again, err)
	}
	if err := store.Finish(ctx, claimed, lease, again, next); err != nil {
		t.Fatal(err)
	}
	all := sent()
	if len(all) != 2 || all[1] == all[0] {
		t.Fatalf("requests sent = %v, want a second, NEW request — cluster-sensor replays a known request ID as the refused job", all)
	}

	// The other polarity: a failure that is not the sensor being full still
	// blocks for review, exactly as before.
	if _, err := raw.Exec(`UPDATE discovery_jobs SET status='failed',error_message='sensor branch-sensor refused the job: malformed discovery_job payload' WHERE id=$1`, again.RemoteID); err != nil {
		t.Fatal(err)
	}
	claimed, _, ok, err = store.Claim(ctx, job, next.Add(2*time.Minute))
	if err != nil || !ok {
		t.Fatalf("claim for second poll %v %v", ok, err)
	}
	blocked, err := backend.Poll(ctx, claimed, o)
	if err != nil {
		t.Fatal(err)
	}
	if blocked.State != "blocked" || blocked.Reason != "probe_failed_review_collector_before_retry" || blocked.Redispatch {
		t.Fatalf("poll of a real failure = %+v, want blocked/probe_failed_review_collector_before_retry", blocked)
	}
}
