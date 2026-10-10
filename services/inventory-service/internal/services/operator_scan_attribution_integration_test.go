package services

// item 1, through the REAL inventory intake: IngestFindingsReport →
// discoveryObservation → operatorScanAttribution (the job, target and asset
// rows the platform wrote) → the production engine (admission ENFORCED) →
// the Postgres identity repository → the retained-evidence worker.
//
// A host on a DHCP segment with no device binding. An active scan of its
// address is held by admission (`dynamic_address_without_device_binding`) —
// right for a scan nobody asked for, wrong for one a person ran on that asset.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).
//
// Mutation checks (each run, each red, each restored; see the PR):
//   - drop `j.created_by IS NOT NULL` → forged_origin_without_a_person attaches;
//   - drop the `origin = 'manual'` test → person_but_automatic_origin attaches;
//   - drop the executor test → submitted_by_another_sensor attaches;
//   - drop the Active Scan record test → job_not_recorded_on_the_asset attaches;
//   - drop the discovery_targets EXISTS → address_not_a_target attaches;
//   - drop the asset-address test → address_not_the_assets attaches;
//   - drop the archived/denied test → archived_asset attaches;
//   - drop the engine's owned-by-another-asset refusal →
//     address_held_by_another_asset attaches;
//   - drop operatorScanBindingConflict's refusal → conflicting_host_key attaches;
//   - drop the retention worker's payload-marker test → the automatic receipt
//     on the person-linked row is materialised.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

const operatorScanHostKey = "SHA256:operator-scan-held-host-key-aaaaaaaaaaaaaaaaaaaaaaa"

type operatorScanFixture struct {
	*provisionalFixture
	user uuid.UUID
}

func newOperatorScanFixture(t *testing.T) *operatorScanFixture {
	f := &operatorScanFixture{provisionalFixture: newProvisionalFixture(t)}
	// The DHCP segment: an address here never decides a match.
	f.exec(`UPDATE network_segments SET metadata = '{"dynamic":true,"dynamic_source":"measured"}'::jsonb
	         WHERE tenant_id=$1 AND id=$2`, f.tenant, f.segA)
	f.user = f.actor()
	return f
}

// host creates a monitored, established asset at addr with an endpoint on 443
// and no identifier the scan carries: what a laptop on DHCP looks like after
// it was approved.
func (f *operatorScanFixture) host(name, addr string, extra ...identity.Identifier) identity.AssetRef {
	f.t.Helper()
	ids := append([]identity.Identifier{{
		Kind: identity.KindHostname, Value: name, Scope: f.segA.String(), Confidence: 1,
		Source: identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}, SeenAt: f.now.Add(-72 * time.Hour),
	}}, extra...)
	ref, err := f.svc.identityRepo.CreateAsset(context.Background(), f.tenant.String(), identity.NewAsset{
		ClassKey: "server", ClassSourceKind: identity.ClassSourceDeclared, DisplayName: name, Hostname: name,
		PrimaryAddress: addr, NetworkSegment: f.segA.String(),
		Status: identity.StatusMonitoring, IdentityStatus: string(identity.IdentityEstablished),
		Source:      identity.Source{Kind: identity.SourceDeclared, Ref: "manual"},
		Identifiers: ids,
		Endpoints:   []identity.EndpointObservation{{Address: addr, Port: 443, Transport: "tcp"}},
		FirstSeenAt: f.now.Add(-72 * time.Hour), LastSeenAt: f.now.Add(-72 * time.Hour),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return ref
}

// scanJob writes the discovery job a scan request created and, when record is
// set, records it on the asset exactly as CreateActiveScanJob does. createdBy
// uuid.Nil writes a job with no person; origin is the server-stamped origin.
func (f *operatorScanFixture) scanJob(asset identity.AssetRef, createdBy uuid.UUID, origin string, targets []string, record bool) uuid.UUID {
	f.t.Helper()
	job := uuid.New()
	meta, _ := json.Marshal(map[string]any{"options": map[string]any{"active_scan": true, "origin": origin}, "scan_plan": map[string]any{}})
	var by any
	if createdBy != uuid.Nil {
		by = createdBy
	}
	f.exec(`INSERT INTO discovery_jobs(id,tenant_id,created_by,execution_mode,status,assigned_sensor_id,metadata,completed_at)
	        VALUES($1,$2,$3,'sensors','completed',$4,$5,now())`, job, f.tenant, by, f.sensorA, string(meta))
	for _, target := range targets {
		f.exec(`INSERT INTO discovery_targets(job_id,tenant_id,input,protocols,ports,status,completed_at)
		        VALUES($1,$2,$3,'{}',ARRAY[443],'completed',now())`, job, f.tenant, target)
	}
	if record {
		assetID := uuid.MustParse(asset.ID)
		if err := database.WithTenantTx(context.Background(), f.db, f.tenant, func(tx *sqlx.Tx) error {
			return autoscan.RecordActiveScanTx(context.Background(), tx, f.tenant, []uuid.UUID{assetID}, []int{443}, job.String(), time.Now())
		}); err != nil {
			f.t.Fatal(err)
		}
	}
	return job
}

// finding is the converter's shape for an active TLS probe result of a
// planned job: the platform's mirror stamps job_id, and the row's batch is the
// job.
func (f *operatorScanFixture) finding(addr string, job uuid.UUID, at time.Time, extra map[string]any) IngestFinding {
	port := 443
	sensor := f.sensorA.String()
	raw := map[string]interface{}{
		"source":       "active_scan",
		"job_id":       job.String(),
		"batch_id":     job.String(),
		"discovery_id": uuid.NewString(),
		"observed_at":  at.Format(time.RFC3339Nano),
	}
	for k, v := range extra {
		raw[k] = v
	}
	return IngestFinding{
		IPAddress: strPtr(addr), Port: &port, Protocol: "TLS",
		ProtocolVersion: strPtr("TLS 1.3"), CipherSuite: strPtr("TLS_AES_256_GCM_SHA384"), KeyExchangeAlgorithm: strPtr("X25519"),
		SourceSensorID: &sensor, RawData: raw,
	}
}

func (f *operatorScanFixture) ingest(fd IngestFinding) identity.IngestResult {
	f.t.Helper()
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{fd}, "monitoring")
	if err != nil {
		f.t.Fatal(err)
	}
	if len(report.Results) != 1 {
		f.t.Fatalf("results = %+v, want one", report.Results)
	}
	return report.Results[0]
}

type scanObservation struct {
	state, outcome, asset string
	reasons               []string
}

func (f *operatorScanFixture) observation(id string) scanObservation {
	f.t.Helper()
	var o scanObservation
	if err := f.raw.QueryRow(`SELECT state, COALESCE(resolution_outcome,''), COALESCE(asset_id::text,''), admission_reasons
	   FROM identity_observations WHERE tenant_id=$1 AND id=$2`, f.tenant, id).Scan(&o.state, &o.outcome, &o.asset, pq.Array(&o.reasons)); err != nil {
		f.t.Fatal(err)
	}
	return o
}

// verifiedAt is the TLS 1.3 crypto configuration's last-verified time on the
// asset, zero when it has none.
func (f *operatorScanFixture) verifiedAt(asset identity.AssetRef) time.Time {
	f.t.Helper()
	var at *time.Time
	if err := f.raw.QueryRow(`SELECT max(last_verified_at) FROM crypto_implementations
	   WHERE tenant_id=$1 AND asset_id=$2 AND protocol_version='TLS 1.3'`, f.tenant, asset.ID).Scan(&at); err != nil {
		f.t.Fatal(err)
	}
	if at == nil {
		return time.Time{}
	}
	return *at
}

func (f *operatorScanFixture) sweep() {
	f.t.Helper()
	if _, err := f.svc.SweepIdentityEvidence(context.Background(), f.tenant); err != nil {
		f.t.Fatal(err)
	}
}

// requireHeld is today's answer for a scan nobody asked for: no asset, the
// observation unresolved for the dynamic-address reason, nothing materialised.
func (f *operatorScanFixture) requireHeld(got identity.IngestResult, asset identity.AssetRef) {
	f.t.Helper()
	if got.Outcome != string(identity.OutcomeUnresolved) || got.AssetID != "" {
		f.t.Fatalf("outcome %s on %q, want unresolved on no asset", got.Outcome, got.AssetID)
	}
	o := f.observation(got.ObservationID)
	if o.state != "unresolved" || o.asset != "" || len(o.reasons) != 1 || o.reasons[0] != identity.ReasonDynamicAddressWithoutDeviceBinding {
		f.t.Fatalf("observation %+v, want unresolved on no asset for %s", o, identity.ReasonDynamicAddressWithoutDeviceBinding)
	}
	f.sweep()
	if v := f.verifiedAt(asset); !v.IsZero() {
		f.t.Fatalf("the held scan put a TLS 1.3 configuration on %s (verified %s)", asset.ID, v)
	}
}

func TestIntegration_OperatorScan_AttachesToTheScannedAsset(t *testing.T) {
	f := newOperatorScanFixture(t)
	const addr = "192.0.2.41"
	laptop := f.host("laptop-41", addr)

	// Baseline: the same scan from the automatic scanner is held, as before.
	auto := f.scanJob(laptop, uuid.Nil, autoscan.Origin, []string{addr}, false)
	f.requireHeld(f.ingest(f.finding(addr, auto, f.now.Add(-30*time.Minute), nil)), laptop)

	// A person scans it.
	first := f.now.Add(-20 * time.Minute)
	job := f.scanJob(laptop, f.user, "manual", []string{addr}, true)
	got := f.ingest(f.finding(addr, job, first, nil))
	if got.Outcome != string(identity.OutcomeMatched) || got.AssetID != laptop.ID {
		t.Fatalf("person's scan resolved %s on %q, want matched on the scanned asset %s", got.Outcome, got.AssetID, laptop.ID)
	}
	o := f.observation(got.ObservationID)
	if o.state != "linked" || o.asset != laptop.ID || o.outcome != pgidentity.ResolutionOperatorScanRequest {
		t.Fatalf("observation %+v, want linked to %s with outcome %s", o, laptop.ID, pgidentity.ResolutionOperatorScanRequest)
	}
	var decided, jobOnTimeline string
	if err := f.raw.QueryRow(`SELECT changes_json->>'decided_by', changes_json->>'operator_scan_job' FROM asset_history
	   WHERE tenant_id=$1 AND asset_id=$2 AND changes_json ? 'operator_scan_job' ORDER BY seq DESC LIMIT 1`, f.tenant, laptop.ID).Scan(&decided, &jobOnTimeline); err != nil {
		t.Fatalf("no timeline entry for the link: %v", err)
	}
	if decided != identity.DecidedByOperatorScanRequest || jobOnTimeline != job.String() {
		t.Fatalf("timeline decided_by=%q job=%q, want %q and %s", decided, jobOnTimeline, identity.DecidedByOperatorScanRequest, job)
	}

	// The crypto configuration materialises — the person's receipt only.
	f.sweep()
	v1 := f.verifiedAt(laptop)
	if !v1.Equal(first) {
		t.Fatalf("TLS 1.3 verified at %s, want the person's scan time %s", v1, first)
	}

	// The automatic scan's earlier receipt shares the observation row (same
	// source, same evidence) and stays held; so does a later automatic one.
	var pending int
	if err := f.raw.QueryRow(`SELECT count(*) FROM deferred_crypto_findings WHERE tenant_id=$1 AND observation_id=$2 AND replayed_at IS NULL`,
		f.tenant, got.ObservationID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("unmaterialised receipts on the row = %d, want 1 (the automatic scan's)", pending)
	}
	later := f.now.Add(-10 * time.Minute)
	auto2 := f.scanJob(laptop, uuid.Nil, autoscan.Origin, []string{addr}, false)
	if got := f.ingest(f.finding(addr, auto2, later, nil)); got.AssetID != "" {
		t.Fatalf("a later automatic scan resolved onto %s, want no asset", got.AssetID)
	}
	f.sweep()
	if v := f.verifiedAt(laptop); !v.Equal(v1) {
		t.Fatalf("an automatic scan moved the verified time to %s; only a person's scan may", v)
	}

	// A second person's scan advances it.
	second := f.now.Add(-time.Minute)
	job2 := f.scanJob(laptop, f.user, "manual", []string{addr}, true)
	if got := f.ingest(f.finding(addr, job2, second, nil)); got.AssetID != laptop.ID {
		t.Fatalf("second scan resolved onto %q, want %s", got.AssetID, laptop.ID)
	}
	f.sweep()
	if v := f.verifiedAt(laptop); !v.Equal(second) {
		t.Fatalf("TLS 1.3 verified at %s after the second scan, want %s", v, second)
	}

	// And the endpoint leaves `scanning`.
	if _, err := autoscan.NewStore(f.db).FinishActiveScans(context.Background(), f.tenant); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := f.raw.QueryRow(`SELECT COALESCE(last_scan_status,'') FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2 AND port=443`,
		f.tenant, laptop.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != autoscan.ActiveScanCompleted {
		t.Fatalf("endpoint last_scan_status = %q, want %q", status, autoscan.ActiveScanCompleted)
	}
	if n := f.assetCount(); n != 1 {
		t.Fatalf("assets = %d, want only the scanned host", n)
	}
}

// Each case is a finding that names a person's-scan-shaped job but must still
// be held exactly as today.
func TestIntegration_OperatorScan_HeldWhenTheRequestDoesNotProveIt(t *testing.T) {
	f := newOperatorScanFixture(t)
	at := f.now.Add(-5 * time.Minute)
	n := 50
	next := func() (string, string) {
		n++
		return fmt.Sprintf("192.0.2.%d", n), fmt.Sprintf("host-%d", n)
	}

	t.Run("automatic_job", func(t *testing.T) {
		addr, name := next()
		a := f.host(name, addr)
		// Recorded on the asset too: only the job row's origin and user stop it.
		job := f.scanJob(a, uuid.Nil, autoscan.Origin, []string{addr}, true)
		f.requireHeld(f.ingest(f.finding(addr, job, at, nil)), a)
	})
	t.Run("forged_origin_without_a_person", func(t *testing.T) {
		addr, name := next()
		a := f.host(name, addr)
		job := f.scanJob(a, uuid.Nil, "manual", []string{addr}, true)
		f.requireHeld(f.ingest(f.finding(addr, job, at, nil)), a)
	})
	t.Run("person_but_automatic_origin", func(t *testing.T) {
		addr, name := next()
		a := f.host(name, addr)
		job := f.scanJob(a, f.user, "identity_enrichment", []string{addr}, true)
		f.requireHeld(f.ingest(f.finding(addr, job, at, nil)), a)
	})
	t.Run("job_not_recorded_on_the_asset", func(t *testing.T) {
		// The asset's current Active Scan record names another request's
		// job; this one is a person's job for the address, but not one the
		// asset was scanned by.
		addr, name := next()
		a := f.host(name, addr)
		f.scanJob(a, f.user, "manual", []string{addr}, true)
		job := f.scanJob(a, f.user, "manual", []string{addr}, false)
		f.requireHeld(f.ingest(f.finding(addr, job, at, nil)), a)
	})
	t.Run("address_not_a_target", func(t *testing.T) {
		// The asset is at addr, but the job scanned another address.
		addr, name := next()
		other, _ := next()
		a := f.host(name, addr)
		job := f.scanJob(a, f.user, "manual", []string{other}, true)
		f.requireHeld(f.ingest(f.finding(addr, job, at, nil)), a)
	})
	t.Run("address_not_the_assets", func(t *testing.T) {
		// The job scanned addr and other, but the asset is at other: the
		// answer from addr is not this asset's.
		other, name := next()
		addr, _ := next()
		a := f.host(name, other)
		job := f.scanJob(a, f.user, "manual", []string{other, addr}, true)
		f.requireHeld(f.ingest(f.finding(addr, job, at, nil)), a)
	})
	t.Run("archived_asset", func(t *testing.T) {
		addr, name := next()
		a := f.host(name, addr)
		job := f.scanJob(a, f.user, "manual", []string{addr}, true)
		f.exec(`UPDATE assets SET asset_status='archived' WHERE tenant_id=$1 AND id=$2`, f.tenant, a.ID)
		f.requireHeld(f.ingest(f.finding(addr, job, at, nil)), a)
	})
	t.Run("submitted_by_another_sensor", func(t *testing.T) {
		// A sensor of the tenant that did not run the job reports a result
		// for it.
		addr, name := next()
		a := f.host(name, addr)
		job := f.scanJob(a, f.user, "manual", []string{addr}, true)
		fd := f.finding(addr, job, at, nil)
		other := f.sensorB.String()
		fd.SourceSensorID = &other
		f.requireHeld(f.ingest(fd), a)
	})
	t.Run("address_held_by_another_asset", func(t *testing.T) {
		// Another asset holds the scanned address as an identifier: the
		// lease may have moved to it, so the scanned asset does not get the
		// answer.
		addr, name := next()
		a := f.host(name, addr)
		holder := f.host(name+"-holder", "192.0.2.250", identity.Identifier{
			Kind: identity.KindIPAddress, Value: addr, Scope: f.segA.String(), Confidence: 1,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:lan"}, SeenAt: f.now.Add(-time.Hour),
		})
		job := f.scanJob(a, f.user, "manual", []string{addr}, true)
		got := f.ingest(f.finding(addr, job, at, nil))
		if got.AssetID == a.ID {
			t.Fatalf("the answer from an address %s holds was attached to the scanned asset", holder.ID)
		}
		if o := f.observation(got.ObservationID); o.asset == a.ID || o.outcome == pgidentity.ResolutionOperatorScanRequest {
			t.Fatalf("observation %+v names the scanned asset", o)
		}
		f.sweep()
		if v := f.verifiedAt(a); !v.IsZero() {
			t.Fatalf("the scan put a TLS 1.3 configuration on %s", a.ID)
		}
	})
	t.Run("conflicting_host_key", func(t *testing.T) {
		// The asset is bound to one SSH host key; the scan met another. The
		// address answers as a different device, so the person's request does
		// not attach it.
		addr, name := next()
		a := f.host(name, addr, identity.Identifier{
			Kind: identity.KindSSHHostKeyFingerprint, Value: operatorScanHostKey, Confidence: 1,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:lan", Mode: identity.ModeActive}, SeenAt: f.now.Add(-72 * time.Hour),
		})
		job := f.scanJob(a, f.user, "manual", []string{addr}, true)
		got := f.ingest(f.finding(addr, job, at, map[string]any{"ssh_host_key_fingerprint": "SHA256:operator-scan-other-host-key-bbbbbbbbbbbbbbbbbbbbbbbb"}))
		if got.AssetID == a.ID {
			t.Fatalf("a scan that met a different host key was attached to %s", a.ID)
		}
		if got.ObservationID != "" {
			if o := f.observation(got.ObservationID); o.asset == a.ID || o.outcome == pgidentity.ResolutionOperatorScanRequest {
				t.Fatalf("observation %+v names the scanned asset", o)
			}
		}
		f.sweep()
		if v := f.verifiedAt(a); !v.IsZero() {
			t.Fatalf("the conflicting scan put a TLS 1.3 configuration on %s", a.ID)
		}
	})
}
