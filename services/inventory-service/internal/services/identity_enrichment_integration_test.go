package services

import (
	"context"
	"encoding/json"
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

func TestIntegration_EnrichmentDNSRemainsWeakThenReconcilesThroughIdentity(t *testing.T) {
	for _, mode := range []string{"one_verified_address", "multiple_addresses", "competing_identifier", "new_dhcp_uncertainty", "enrichment_disabled"} {
		t.Run(mode, func(t *testing.T) { testEnrichmentCorroboration(t, mode) })
	}
}

func testEnrichmentCorroboration(t *testing.T, mode string) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewAssetService(db)
	_, err := svc.identityEngine()
	if err != nil {
		t.Fatal(err)
	}
	svc.identityEng, err = identity.New(identity.Config{Repo: svc.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	sensor, segment := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_capabilities,reported_dns_interfaces) VALUES($1,$2,'Enrichment collector','linux','test-v1','datacenter_host','active',$3,ARRAY['eth0'],ARRAY['identity_dns_v1'],ARRAY['eth0'])`, []any{sensor, tenant, now}},
		{`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0','192.168.80.4',24)`, []any{sensor}},
		{`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'Enrichment network','cidr','192.168.80.0/24','production')`, []any{segment, tenant}},
		{`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, []any{tenant}},
		{`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason) SELECT $1,id,'{"quantity":10}','enrichment regression' FROM billable_items WHERE key='max_assets'`, []any{tenant}},
	} {
		if _, err := raw.Exec(query.sql, query.args...); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	original := identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + sensor.String()}, ObservedAt: now.Add(-time.Minute), Network: identity.Network{SegmentID: segment.String()}, Admission: identity.AdmissionEvidence{ReceiptID: "original", CollectorVersion: "test-v1"}, Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "opaque-uuid.local", Scope: segment.String()}}}
	first, err := svc.resolveObservationWith(ctx, original, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Asset.Zero() {
		t.Fatal("weak name created an asset")
	}
	o := identityenrichment.Observation{ID: uuid.MustParse(first.ObservationID), Evidence: original, State: "unresolved"}
	store := &identityenrichment.Store{DB: db}
	scope, excluded, err := store.Scope(ctx, tenant, o, now)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := store.Policy(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	plan, reason := identityenrichment.NetworkPlan(o, policy, scope, nil, excluded)
	if reason != "" || plan.Action != "dns" {
		t.Fatalf("plan %+v %s", plan, reason)
	}
	job, err := store.Ensure(ctx, tenant, o, plan, now)
	if err != nil {
		t.Fatal(err)
	}
	backend := NewIdentityEnrichmentBackend(svc, &DiscoveryService{})
	queued, err := backend.Dispatch(ctx, job, o)
	if err != nil {
		t.Fatal(err)
	}
	job.RemoteID = queued.RemoteID
	result := sensordispatch.IdentityDNSResult{RequestID: job.RequestID.String(), ObservationID: o.ID.String(), Hostname: plan.Hostname, NetworkScope: segment.String(), Addresses: []string{"192.168.80.20"}, ObservedAt: now, CollectorVersion: "test-v1"}
	if mode == "multiple_addresses" {
		result.Addresses = append(result.Addresses, "192.168.80.21")
	}
	payload, _ := json.Marshal(result)
	if _, err := raw.Exec(`UPDATE sensor_commands SET status='completed',response_data=$2 WHERE id=$1`, job.RemoteID, string(payload)); err != nil {
		t.Fatal(err)
	}
	completed, err := backend.Poll(ctx, job, o)
	if err != nil || completed.State != "completed" {
		t.Fatalf("DNS poll %+v %v", completed, err)
	}
	var count int
	if err := raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("DNS established device %d %v", count, err)
	}
	if _, err := raw.Exec(`UPDATE identity_enrichment_jobs SET state='completed',remote_id=$3,result=$4 WHERE tenant_id=$1 AND id=$2`, tenant, job.ID, job.RemoteID, string(completed.Data)); err != nil {
		t.Fatal(err)
	}
	// An actual responsive endpoint is separate proof. DNS does not synthesize it.
	direct := identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:probe:" + sensor.String(), Mode: identity.ModeActive}, ObservedAt: now, Network: original.Network, Admission: identity.AdmissionEvidence{Direct: true, ReceiptID: "actual-probe"}, Identifiers: []identity.Identifier{{Kind: identity.KindIPAddress, Value: "192.168.80.20", Scope: segment.String()}}, Endpoints: []identity.EndpointObservation{{Address: "192.168.80.20", Port: 443, Transport: "tcp", Protocol: "TLS"}}}
	probeID, discoveryID := uuid.New(), uuid.New()
	direct.Admission.ReceiptID = discoveryID.String()
	probePlan := identityenrichment.Plan{Action: "probe", Executor: "sensor:" + sensor.String(), SensorID: sensor, SegmentID: segment, SegmentCIDR: "192.168.80.0/24", Addresses: []string{"192.168.80.20"}, Protocols: []string{"TLS"}, Ports: []int{443}}
	probe, err := store.Ensure(ctx, tenant, o, probePlan, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,metadata) VALUES($1,$2,'sensors','completed',jsonb_build_object('options',jsonb_build_object('identity_enrichment_request_id',$3::text),'sensor_result',jsonb_build_object('discoveries_submitted',1)))`, probeID, tenant, probe.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE identity_enrichment_jobs SET remote_id=$3,state='completed' WHERE tenant_id=$1 AND id=$2`, tenant, probe.ID, probeID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO sensor_discoveries(id,sensor_id,tenant_id,batch_id,protocol,dest_ip,port,confidence,metadata,processed_at,"timestamp") VALUES($1,$2,$3,'enrichment-proof','TLS','192.168.80.20',443,1,jsonb_build_object('raw_metadata',jsonb_build_object('job_id',$4::text)),now(),$5)`, discoveryID, sensor, tenant, probeID, now); err != nil {
		t.Fatal(err)
	}
	strong, err := svc.resolveObservationWith(ctx, direct, nil)
	if err != nil || strong.Asset.Zero() {
		t.Fatalf("direct %+v %v", strong, err)
	}
	if mode == "competing_identifier" {
		other := original
		other.Source.Ref = "sensor:other_verified_device"
		other.Admission = identity.AdmissionEvidence{Direct: true, ReceiptID: "competing-direct"}
		other.ObservedAt = now
		other.Identifiers = append(append([]identity.Identifier(nil), original.Identifiers...), identity.Identifier{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55"})
		competing, err := svc.resolveObservationWith(ctx, other, nil)
		if err != nil || competing.Asset.Zero() || competing.Asset.ID == strong.Asset.ID {
			t.Fatalf("competing asset %+v %v", competing, err)
		}
	}
	if mode == "new_dhcp_uncertainty" {
		if _, err := raw.Exec(`UPDATE network_segments SET metadata='{"dynamic":true}' WHERE tenant_id=$1 AND id=$2`, tenant, segment); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "enrichment_disabled" {
		if _, err := raw.Exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,enabled}','false') WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := backend.Reevaluate(ctx, tenant, o); err != nil {
			t.Fatal(err)
		}
	}
	if mode != "one_verified_address" {
		var linked *uuid.UUID
		var state string
		var seen time.Time
		var count int
		if err := raw.QueryRow(`SELECT asset_id,state,last_seen_at,occurrence_count FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, o.ID).Scan(&linked, &state, &seen, &count); err != nil {
			t.Fatal(err)
		}
		if linked != nil || state != "unresolved" || !seen.Equal(original.ObservedAt) || count != 1 {
			t.Fatalf("unsafe evidence linked or rewrote sighting: %v %s %v %d", linked, state, seen, count)
		}
		if mode == "competing_identifier" {
			var proposals int
			if err := raw.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND changes_json->>'kind'='merge_proposal'`, tenant).Scan(&proposals); err != nil || proposals == 0 {
				t.Fatalf("competing ownership lacked review evidence: %d %v", proposals, err)
			}
		}
		return
	}
	var linked string
	var sightings int
	var last time.Time
	if err := raw.QueryRow(`SELECT asset_id::text,occurrence_count,last_seen_at FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, o.ID).Scan(&linked, &sightings, &last); err != nil {
		t.Fatal(err)
	}
	if linked != strong.Asset.ID || sightings != 1 || !last.Equal(original.ObservedAt) {
		t.Fatalf("reconciliation changed identity/freshness: %s %d %s", linked, sightings, last)
	}
	if err := raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replay duplicated assets %d %v", count, err)
	}
	// A changed/dismissed original observation cannot be revived by this worker.
	if _, err := raw.Exec(`UPDATE identity_observations SET state='dismissed' WHERE tenant_id=$1 AND id=$2`, tenant, o.ID); err != nil {
		t.Fatal(err)
	}
	if err := backend.Reevaluate(ctx, tenant, o); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := raw.QueryRow(`SELECT state FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, o.ID).Scan(&state); err != nil || state != "dismissed" {
		t.Fatalf("dismissal lost %s %v", state, err)
	}
}

func TestIntegration_EnrichmentCollectorsKeepSeparateEvidence(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	foreign := testdb.NewTenant(t, raw)
	svc := NewAssetService(&database.DB{DB: sqlx.NewDb(raw, "postgres")})
	if _, err := svc.identityEngine(); err != nil {
		t.Fatal(err)
	}
	var err error
	svc.identityEng, err = identity.New(identity.Config{Repo: svc.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	sensors := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for i, sensor := range sensors {
		owner := tenant
		if i == 2 {
			owner = foreign
		}
		if _, err := raw.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status) VALUES($1,$2,'Collector','linux','test','datacenter_host','active')`, sensor, owner); err != nil {
			t.Fatal(err)
		}
	}
	name := "opaque-uuid.local"
	ids := map[string]bool{}
	for _, sensor := range sensors[:2] {
		source := sensor.String()
		f := IngestFinding{Hostname: &name, SourceSensorID: &source, RawData: map[string]interface{}{"source": "active_scan", "discovery_id": uuid.NewString(), "observed_at": time.Now().UTC()}}
		observation, err := svc.discoveryObservation(tenant, f, nil, "internal")
		if err != nil {
			t.Fatal(err)
		}
		if observation.Source.Ref != "scan:"+source {
			t.Fatalf("collector lost: %+v", observation.Source)
		}
		result, err := svc.resolveObservationWith(context.Background(), observation, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Asset.Zero() || result.ObservationID == "" {
			t.Fatalf("weak source admitted: %+v", result)
		}
		ids[result.ObservationID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("independent collector evidence collapsed: %v", ids)
	}
	for _, source := range []string{sensors[2].String(), "malformed", uuid.Nil.String()} {
		if _, err := svc.discoveryObservation(tenant, IngestFinding{Hostname: &name, SourceSensorID: &source}, nil, "internal"); err == nil {
			t.Fatalf("invalid collector accepted: %s", source)
		}
	}
	for _, source := range []string{"cloud_discovery", "device_interrogation"} {
		sensor := sensors[0].String()
		got := findingSource(IngestFinding{SourceSensorID: &sensor, RawData: map[string]interface{}{"source": source}})
		if got.Ref != "cloud" && got.Ref != "interrogation" {
			t.Fatalf("producer context overwritten: %+v", got)
		}
	}
}
