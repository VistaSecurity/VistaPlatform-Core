package services

// An identity-enrichment probe run as a PLANNED job ( WP3, spec V5),
// against a real Postgres, through the real Poll, Reevaluate and
// jobunits.RecordSensorBatch / jobunits.Commit:
//
//   - the poll waits until every result the job mirrored into
//     sensor_discoveries (batch_id = the job) is processed, and completes at
//     once for a probe that found nothing — whichever executor ran it;
//   - a mirrored result becomes identity evidence attributed exactly as the
//     legacy sensor's result for the same probe is, and corroborates the DNS
//     answer the same way.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const (
	plannedProbeAddr = "10.0.0.20"
	plannedProbeCIDR = "10.0.0.0/24"
)

type plannedProbeFixture struct {
	raw      *sql.DB
	svc      *AssetService
	store    *identityenrichment.Store
	backend  *IdentityEnrichmentBackend
	tenant   uuid.UUID
	sensor   uuid.UUID // the tenant collector (identity executor)
	platform uuid.UUID // the tenant's platform discovery sensor
	segment  uuid.UUID
	now      time.Time
}

func newPlannedProbeFixture(t *testing.T) *plannedProbeFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	f := &plannedProbeFixture{raw: raw, tenant: testdb.NewTenant(t, raw), sensor: uuid.New(), segment: uuid.New(),
		now: time.Now().UTC().Truncate(time.Microsecond)}
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	f.svc = NewAssetService(db)
	if _, err := f.svc.identityEngine(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.svc.identityEng, err = identity.New(identity.Config{Repo: f.svc.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	f.store = &identityenrichment.Store{DB: db}
	f.backend = NewIdentityEnrichmentBackend(f.svc, &DiscoveryService{})
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_capabilities,reported_dns_interfaces) VALUES($1,$2,'Planned collector','linux','test-v1','datacenter_host','active',$3,ARRAY['eth0'],ARRAY['identity_dns_v1','scan_plan_v1'],ARRAY['eth0'])`, []any{f.sensor, f.tenant, f.now}},
		{`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0','10.0.0.4',24)`, []any{f.sensor}},
		{`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'Planned probe network','cidr',$3,'production')`, []any{f.segment, f.tenant, plannedProbeCIDR}},
		{`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, []any{f.tenant}},
		{`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason) SELECT $1,id,'{"quantity":10}','planned probe regression' FROM billable_items WHERE key='max_assets'`, []any{f.tenant}},
	} {
		if _, err := raw.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	// Every tenant is created with its Platform Discovery Sensor (trigger
	// create_system_sensors_for_tenant): the sensor a platform run queues
	// its results under.
	if err := raw.QueryRow(`SELECT id FROM sensors WHERE tenant_id=$1 AND profile='discovery' AND 'system'=ANY(tags)`, f.tenant).Scan(&f.platform); err != nil {
		t.Fatalf("platform discovery sensor: %v", err)
	}
	return f
}

func (f *plannedProbeFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.raw.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

// weakSighting is an unresolved name in the segment: what enrichment is for.
func (f *plannedProbeFixture) weakSighting(t *testing.T) (identityenrichment.Observation, identity.Observation) {
	t.Helper()
	original := identity.Observation{TenantID: f.tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + f.sensor.String()}, ObservedAt: f.now.Add(-time.Minute),
		Network: identity.Network{SegmentID: f.segment.String()}, Admission: identity.AdmissionEvidence{ReceiptID: "original", CollectorVersion: "test-v1"},
		Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "planned-probe.local", Scope: f.segment.String()}}}
	first, err := f.svc.resolveObservationWith(context.Background(), original, nil)
	if err != nil || !first.Asset.Zero() {
		t.Fatalf("weak sighting %+v %v", first, err)
	}
	return identityenrichment.Observation{ID: uuid.MustParse(first.ObservationID), Evidence: original, State: "unresolved"}, original
}

// probeJob registers an identity probe for o and a PLANNED discovery job for
// it, in the state the dispatcher leaves one: a tenant-sensor job assigned
// and awaiting the sensor, or a platform job running. One target, one unit at
// attempt 1.
func (f *plannedProbeFixture) probeJob(t *testing.T, o identityenrichment.Observation, platform bool) (identityenrichment.Job, jobunits.Unit) {
	t.Helper()
	plan := identityenrichment.Plan{Action: "probe", Executor: "sensor:" + f.sensor.String(), SensorID: f.sensor, SegmentID: f.segment, SegmentCIDR: plannedProbeCIDR,
		Addresses: []string{plannedProbeAddr}, Protocols: []string{"TLS"}, Ports: []int{443}}
	job, err := f.store.Ensure(context.Background(), f.tenant, o, plan, f.now)
	if err != nil {
		t.Fatal(err)
	}
	jobID := uuid.New()
	options := map[string]any{"origin": "identity_enrichment", "active_scan": true, "identity_enrichment_request_id": job.RequestID.String(),
		"identity_observation_id": o.ID.String(), "identity_network_scope": f.segment.String()}
	meta, _ := json.Marshal(map[string]any{shareddisc.ScanPlanMetadataKey: map[string]any{"depth": "custom"}, "options": options})
	if platform {
		f.exec(t, `INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,started_at,metadata) VALUES($1,$2,'platform','running',now(),$3::jsonb)`, jobID, f.tenant, string(meta))
	} else {
		f.exec(t, `INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,requested_sensor_ids,assigned_sensor_id,dispatched_at,metadata) VALUES($1,$2,'sensors',$3,ARRAY[$4::text],$4::uuid,now(),$5::jsonb)`,
			jobID, f.tenant, sensordispatch.StatusAwaitingSensor, f.sensor.String(), string(meta))
	}
	u := jobunits.Unit{JobID: jobID.String(), TenantID: f.tenant.String(), TargetInput: plannedProbeAddr, Address: plannedProbeAddr}
	if err := f.raw.QueryRow(`INSERT INTO discovery_targets(job_id,tenant_id,input,protocols,ports) VALUES($1,$2,$3,'{}',ARRAY[443]) RETURNING id`, jobID, f.tenant, plannedProbeAddr).Scan(&u.TargetID); err != nil {
		t.Fatal(err)
	}
	unitStatus := "pending"
	if platform {
		unitStatus = "running"
	}
	if err := f.raw.QueryRow(`INSERT INTO discovery_job_units(tenant_id,job_id,target_id,address,attempts,status) VALUES($1,$2,$3,$4,1,$5) RETURNING id`,
		f.tenant, jobID, u.TargetID, plannedProbeAddr, unitStatus).Scan(&u.ID); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE identity_enrichment_jobs SET remote_id=$3,state='running' WHERE tenant_id=$1 AND id=$2`, f.tenant, job.ID, jobID.String())
	job.RemoteID = jobID.String()
	return job, u
}

// tlsHost is one host's engine output: TLS answered on 443 (found=true), or
// nothing answered (found=false).
func tlsHost(found bool) shareddisc.UnitOutput {
	a := netip.MustParseAddr(plannedProbeAddr)
	if !found {
		return shareddisc.UnitOutput{Host: shareddisc.HostScan{Addr: a, Liveness: shareddisc.LivenessUp, LivenessEvidence: "tcp-rst:443", PortsRequested: 1, Closed: 1}}
	}
	return shareddisc.UnitOutput{
		Host: shareddisc.HostScan{Addr: a, Liveness: shareddisc.LivenessUp, LivenessEvidence: "tcp-open:443", PortsRequested: 1, Open: []int{443}, OpenCount: 1},
		TCP: []shareddisc.Observation{{Addr: a, Port: 443, Transport: "tcp", State: "open", Protocol: "TLS", Identified: true,
			Result: &shareddisc.ProbeResult{Protocol: "TLS", Port: 443, TLSVersions: []string{"TLS 1.3"}, SelectedCipher: "TLS_AES_128_GCM_SHA256"}}},
	}
}

// reportFromSensor stores the host the way a tenant sensor's report is stored.
func (f *plannedProbeFixture) reportFromSensor(t *testing.T, u jobunits.Unit, found bool) {
	t.Helper()
	resp, err := jobunits.RecordSensorBatch(context.Background(), f.raw, f.tenant, f.sensor, uuid.MustParse(u.JobID),
		sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sensordispatch.NewUnitResult(u.TargetID, u.Address, 1, tlsHost(found))}})
	if err != nil || resp.Accepted != 1 {
		t.Fatalf("sensor report = %+v %v", resp, err)
	}
}

// commitOnPlatform stores the host the way the Platform Sensor's run does
// (cluster-sensor-service commitUnit): queued under the platform sensor.
func (f *plannedProbeFixture) commitOnPlatform(t *testing.T, u jobunits.Unit, found bool) {
	t.Helper()
	err := shareddatabase.WithTenantTx(context.Background(), f.raw, f.tenant, func(tx *sql.Tx) error {
		return jobunits.Commit(tx, u, tlsHost(found), jobunits.CommitOptions{From: "running", Attempt: 1, ActiveScan: true,
			MirrorSensorID: func(jobunits.Tx) (string, error) { return f.platform.String(), nil }})
	})
	if err != nil {
		t.Fatalf("platform commit: %v", err)
	}
}

// complete closes the job as its executor does. For a sensor job that is
// sensor-manager's CompleteSensorJob, which records the sensor's completion —
// and a planned sensor's completion carries no submitted count, so the field
// is the zero the sensor sends (sensor/cmd/plan_job.go).
func (f *plannedProbeFixture) complete(t *testing.T, jobID string) {
	t.Helper()
	f.exec(t, `UPDATE discovery_jobs SET status='completed',completed_at=now(),
	   metadata=metadata||jsonb_build_object('sensor_result',jsonb_build_object('status','completed','discoveries_submitted',0))
	 WHERE tenant_id=$1 AND id=$2`, f.tenant, jobID)
}

func (f *plannedProbeFixture) poll(t *testing.T, j identityenrichment.Job, o identityenrichment.Observation) identityenrichment.Result {
	t.Helper()
	r, err := f.backend.Poll(context.Background(), j, o)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	return r
}

func (f *plannedProbeFixture) mirrored(t *testing.T, jobID string, sensor uuid.UUID) []uuid.UUID {
	t.Helper()
	rows, err := f.raw.Query(`SELECT id FROM sensor_discoveries WHERE tenant_id=$1 AND batch_id=$2 AND sensor_id=$3`, f.tenant, jobID, sensor)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func TestIntegration_IdentityProbePoll_PlannedJobWaitsForItsMirroredResults(t *testing.T) {
	for _, executor := range []string{"sensor", "platform"} {
		t.Run(executor, func(t *testing.T) {
			f := newPlannedProbeFixture(t)
			o, _ := f.weakSighting(t)
			platform := executor == "platform"
			job, u := f.probeJob(t, o, platform)
			queuedUnder := f.sensor
			if platform {
				queuedUnder = f.platform
			}

			if r := f.poll(t, job, o); r.State != "running" {
				t.Fatalf("poll of a job still scanning = %+v", r)
			}
			if platform {
				f.commitOnPlatform(t, u, true)
			} else {
				f.reportFromSensor(t, u, true)
			}
			rows := f.mirrored(t, job.RemoteID, queuedUnder)
			if len(rows) != 1 {
				t.Fatalf("mirrored %d rows under the %s executor, want 1", len(rows), executor)
			}
			f.complete(t, job.RemoteID)

			// The job is complete but the discovery processor has not read its
			// result: the probe is NOT ingested yet. The legacy test read
			// discoveries_submitted (0) >= rows carrying a job_id and said yes.
			if r := f.poll(t, job, o); r.State != "running" {
				t.Fatalf("poll before the mirrored result was processed = %+v, want running", r)
			}
			// A row another sensor of the tenant queued under a batch id equal
			// to the job id is not this job's result and does not hold it.
			f.exec(t, `INSERT INTO sensor_discoveries(sensor_id,tenant_id,batch_id,protocol,dest_ip,port,confidence,metadata) VALUES($1,$2,$3,'TLS','10.0.0.99',443,1,'{}')`,
				map[bool]uuid.UUID{true: f.sensor, false: f.platform}[platform], f.tenant, job.RemoteID)

			f.exec(t, `UPDATE sensor_discoveries SET processed_at=now() WHERE id=$1`, rows[0])
			if r := f.poll(t, job, o); r.State != "completed" || r.Reason != "probe_results_ingested" {
				t.Fatalf("poll after the result was processed = %+v, want completed", r)
			}
		})
	}
}

func TestIntegration_IdentityProbePoll_PlannedJobThatFoundNothingCompletes(t *testing.T) {
	for _, executor := range []string{"sensor", "platform"} {
		t.Run(executor, func(t *testing.T) {
			f := newPlannedProbeFixture(t)
			o, _ := f.weakSighting(t)
			platform := executor == "platform"
			job, u := f.probeJob(t, o, platform)
			if platform {
				f.commitOnPlatform(t, u, false)
			} else {
				f.reportFromSensor(t, u, false)
			}
			f.complete(t, job.RemoteID)
			if r := f.poll(t, job, o); r.State != "completed" || r.Reason != "probe_results_ingested" {
				t.Fatalf("poll of a completed probe with no results = %+v, want completed", r)
			}
		})
	}
}

// The legacy branch is unchanged: the sensor's submitted count, and rows
// carrying the job id in their metadata.
func TestIntegration_IdentityProbePoll_LegacyJobStillCountsSubmitted(t *testing.T) {
	f := newPlannedProbeFixture(t)
	o, _ := f.weakSighting(t)
	plan := identityenrichment.Plan{Action: "probe", Executor: "sensor:" + f.sensor.String(), SensorID: f.sensor, SegmentID: f.segment, SegmentCIDR: plannedProbeCIDR,
		Addresses: []string{plannedProbeAddr}, Protocols: []string{"TLS"}, Ports: []int{443}}
	job, err := f.store.Ensure(context.Background(), f.tenant, o, plan, f.now)
	if err != nil {
		t.Fatal(err)
	}
	jobID := uuid.New()
	job.RemoteID = jobID.String()
	f.exec(t, `INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,assigned_sensor_id,metadata) VALUES($1,$2,'sensors','completed',$3,
	   jsonb_build_object('options',jsonb_build_object('identity_enrichment_request_id',$4::text),'sensor_result',jsonb_build_object('discoveries_submitted',2)))`,
		jobID, f.tenant, f.sensor, job.RequestID.String())
	insert := `INSERT INTO sensor_discoveries(sensor_id,tenant_id,batch_id,protocol,dest_ip,port,confidence,metadata,processed_at) VALUES($1,$2,'legacy-batch','TLS',$3,443,1,jsonb_build_object('raw_metadata',jsonb_build_object('job_id',$4::text)),now())`
	f.exec(t, insert, f.sensor, f.tenant, plannedProbeAddr, jobID.String())
	if r := f.poll(t, job, o); r.State != "running" {
		t.Fatalf("legacy poll with 1 of 2 submitted rows = %+v, want running", r)
	}
	f.exec(t, insert, f.sensor, f.tenant, "10.0.0.21", jobID.String())
	if r := f.poll(t, job, o); r.State != "completed" {
		t.Fatalf("legacy poll with every submitted row processed = %+v, want completed", r)
	}
}

// ingestFindingFrom is the finding the discovery processor hands inventory for
// a sensor_discoveries row (discovery-processor's ToIngestFinding): the
// envelope flattened (outer keys win), the row's id as discovery_id, and the
// scan provenance read from discovery_source.
func ingestFindingFrom(t *testing.T, raw *sql.DB, id uuid.UUID) IngestFinding {
	t.Helper()
	var sensor, ip string
	var port int
	var metaRaw []byte
	if err := raw.QueryRow(`SELECT sensor_id::text,host(dest_ip),port,metadata FROM sensor_discoveries WHERE id=$1`, id).Scan(&sensor, &ip, &port, &metaRaw); err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatal(err)
	}
	data := map[string]any{}
	if nested, ok := meta["raw_metadata"].(map[string]any); ok {
		for k, v := range nested {
			data[k] = v
		}
	}
	for k, v := range meta {
		if k != "raw_metadata" {
			data[k] = v
		}
	}
	data["discovery_id"] = id.String()
	data["observed_at"] = time.Now().UTC().Format(time.RFC3339)
	data["source"] = "sensor_discovery"
	if data["discovery_source"] == sensordispatch.DiscoverySourceActiveScan {
		data["source"] = "active_scan"
	}
	cipher, _ := data["cipher_suite"].(string)
	return IngestFinding{IPAddress: &ip, Port: &port, Protocol: "TLS", CipherSuite: &cipher, SourceSensorID: &sensor, RawData: data}
}

// A planned probe's mirrored result is attributed as the legacy sensor's
// result for the same probe is — same collector, same active mode, same
// channel, same network scope, same job — and, end to end, corroborates the
// DNS answer and links the weak sighting.
func TestIntegration_IdentityProbe_PlannedResultIsAttributedLikeLegacy(t *testing.T) {
	f := newPlannedProbeFixture(t)
	ctx := context.Background()
	o, _ := f.weakSighting(t)

	// The DNS step: one answer, in the segment.
	scope, excluded, err := f.store.Scope(ctx, f.tenant, o, f.now)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := f.store.Policy(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	dnsPlan, reason := identityenrichment.NetworkPlan(o, policy, scope, nil, excluded)
	if reason != "" || dnsPlan.Action != "dns" {
		t.Fatalf("plan %+v %s", dnsPlan, reason)
	}
	dnsJob, err := f.store.Ensure(ctx, f.tenant, o, dnsPlan, f.now)
	if err != nil {
		t.Fatal(err)
	}
	queued, err := f.backend.Dispatch(ctx, dnsJob, o)
	if err != nil {
		t.Fatal(err)
	}
	dnsJob.RemoteID = queued.RemoteID
	answer, _ := json.Marshal(sensordispatch.IdentityDNSResult{RequestID: dnsJob.RequestID.String(), ObservationID: o.ID.String(), Hostname: dnsPlan.Hostname,
		NetworkScope: f.segment.String(), Addresses: []string{plannedProbeAddr}, ObservedAt: f.now, CollectorVersion: "test-v1"})
	f.exec(t, `UPDATE sensor_commands SET status='completed',response_data=$2 WHERE id=$1`, dnsJob.RemoteID, string(answer))
	dnsDone, err := f.backend.Poll(ctx, dnsJob, o)
	if err != nil || dnsDone.State != "completed" {
		t.Fatalf("DNS poll %+v %v", dnsDone, err)
	}
	f.exec(t, `UPDATE identity_enrichment_jobs SET state='completed',remote_id=$3,result=$4 WHERE tenant_id=$1 AND id=$2`, f.tenant, dnsJob.ID, dnsJob.RemoteID, string(dnsDone.Data))

	// The probe, planned, reported by the sensor.
	probe, u := f.probeJob(t, o, false)
	f.reportFromSensor(t, u, true)
	f.complete(t, probe.RemoteID)
	rows := f.mirrored(t, probe.RemoteID, f.sensor)
	if len(rows) != 1 {
		t.Fatalf("mirrored %d rows, want 1", len(rows))
	}
	f.exec(t, `UPDATE identity_enrichment_jobs SET state='completed' WHERE tenant_id=$1 AND id=$2`, f.tenant, probe.ID)

	// The legacy sensor's row for the same probe (sensor/internal/discovery/
	// job_results.go discoveryForFinding, nested by sensor-manager).
	legacyID := uuid.New()
	f.exec(t, `INSERT INTO sensor_discoveries(id,sensor_id,tenant_id,batch_id,protocol,dest_ip,port,confidence,metadata) VALUES($1,$2,$3,'legacy-batch','TLS',$4,443,0.95,
	   jsonb_build_object('discovery_method','active','cipher_suite','TLS_AES_128_GCM_SHA256','version','TLS 1.3',
	     'raw_metadata',jsonb_build_object('job_id',$5::text,'discovery_source','active_scan','cipher_suite','TLS_AES_128_GCM_SHA256')))`,
		legacyID, f.sensor, f.tenant, plannedProbeAddr, probe.RemoteID)

	plannedFinding, legacyFinding := ingestFindingFrom(t, f.raw, rows[0]), ingestFindingFrom(t, f.raw, legacyID)
	if plannedFinding.RawData[sensordispatch.MetadataJobIDKey] != probe.RemoteID || legacyFinding.RawData[sensordispatch.MetadataJobIDKey] != probe.RemoteID {
		t.Fatalf("job not carried: planned %v, legacy %v", plannedFinding.RawData[sensordispatch.MetadataJobIDKey], legacyFinding.RawData[sensordispatch.MetadataJobIDKey])
	}
	ip := plannedProbeAddr
	planned, err := f.svc.discoveryObservation(f.tenant, plannedFinding, &ip, "internal")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := f.svc.discoveryObservation(f.tenant, legacyFinding, &ip, "internal")
	if err != nil {
		t.Fatal(err)
	}
	if planned.Source != legacy.Source || planned.Source.Ref != "scan:"+f.sensor.String() || planned.Source.Mode != identity.ModeActive {
		t.Fatalf("attribution differs: planned %+v, legacy %+v", planned.Source, legacy.Source)
	}
	if planned.Network.SegmentID != legacy.Network.SegmentID || planned.Network.SegmentID != f.segment.String() {
		t.Fatalf("network scope differs: planned %q, legacy %q, want %s", planned.Network.SegmentID, legacy.Network.SegmentID, f.segment)
	}
	if planned.Admission.Direct != legacy.Admission.Direct || !planned.Admission.Direct {
		t.Fatalf("admission differs: planned %+v, legacy %+v", planned.Admission, legacy.Admission)
	}

	// End to end: the planned result is ingested (only the planned row — the
	// legacy one was a comparison), processed, and corroborates the DNS answer.
	f.exec(t, `DELETE FROM sensor_discoveries WHERE id=$1`, legacyID)
	strong, err := f.svc.resolveObservationWith(ctx, planned, nil)
	if err != nil || strong.Asset.Zero() {
		t.Fatalf("planned probe result %+v %v", strong, err)
	}
	f.exec(t, `UPDATE sensor_discoveries SET processed_at=now() WHERE id=$1`, rows[0])
	if r := f.poll(t, probe, o); r.State != "completed" {
		t.Fatalf("probe poll after ingest = %+v", r)
	}
	if err := f.backend.Reevaluate(ctx, f.tenant, o); err != nil {
		t.Fatal(err)
	}
	var linked sql.NullString
	if err := f.raw.QueryRow(`SELECT asset_id::text FROM identity_observations WHERE tenant_id=$1 AND id=$2`, f.tenant, o.ID).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if !linked.Valid || linked.String != strong.Asset.ID {
		t.Fatalf("weak sighting linked to %v, want the probed asset %s — the planned result did not corroborate", linked, strong.Asset.ID)
	}
}
