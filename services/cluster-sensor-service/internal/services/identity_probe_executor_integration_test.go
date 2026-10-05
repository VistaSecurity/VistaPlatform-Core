package services

// An identity probe's EXECUTOR is chosen separately from its OBSERVER: the
// planner prefers the collector that heard the evidence, otherwise any live
// tenant collector with an interface on the target network. The dispatch
// guard therefore authorizes the two separately, and these tests drive it
// through the real CreateJob (and, where the job is accepted, the real
// dispatcher's re-check) against a real Postgres:
//
//   - observer == executor: authorized, as before;
//   - observer on another network, executor on the target network: authorized
//     (it used to be refused as "probe source or scope changed");
//   - an executor without a live interface on the target network, or the
//     platform's own collector: refused, whoever observed;
//   - an observer that is not a current collector of THIS tenant: refused;
//   - evidence that is not a collector's measurement in the planned scope:
//     refused, as before;
//   - a target outside the tenant's probe scope: refused whatever the executor
//     can reach.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const (
	targetNetwork   = "10.188.0.0/24" // where the probed host lives
	observerNetwork = "10.189.0.0/24" // where the observing collector lives
)

// collectorOn is a live, plan-capable tenant collector whose DNS interface
// eth0 holds address/prefix.
func (f *dispatchFixture) collectorOn(t *testing.T, name, address string, prefix int) uuid.UUID {
	t.Helper()
	id := f.capableSensor(t, name)
	if _, err := f.raw.Exec(`UPDATE sensors SET reported_dns_interfaces=ARRAY['eth0'] WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0',$2,$3)`, id, address, prefix); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *dispatchFixture) probeSegment(t *testing.T, cidr string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,$3,'cidr',$4,'production')`, id, f.tenant, "net "+cidr, cidr); err != nil {
		t.Fatal(err)
	}
	return id
}

// identityObservation stores evidence of the given source in segment.
func (f *dispatchFixture) identityObservation(t *testing.T, kind identity.SourceKind, ref string, segment uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	evidence, err := json.Marshal(identity.Observation{TenantID: f.tenant.String(), Source: identity.Source{Kind: kind, Ref: ref}, Network: identity.Network{SegmentID: segment.String()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO identity_observations(id,tenant_id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1::uuid,$2,$1::text,$3,$4,$5,now(),now())`,
		id, f.tenant, string(kind), ref, string(evidence)); err != nil {
		t.Fatal(err)
	}
	return id
}

// identityProbe is the request inventory's enrichment worker sends: one
// target, custom depth on the policy's port, run on the executor.
func identityProbe(executor, observation, segment uuid.UUID, target string) models.CreateDiscoveryJobRequest {
	return models.CreateDiscoveryJobRequest{Targets: []string{target}, ScanDepth: "custom", TCPPorts: "443", RunFrom: "sensor", SensorID: executor.String(),
		Options: map[string]interface{}{
			"origin":                         "identity_enrichment",
			"active_scan":                    true,
			"identity_enrichment_request_id": uuid.NewString(),
			"identity_observation_id":        observation.String(),
			"identity_network_scope":         segment.String(),
		}}
}

type executorWorld struct {
	f                 *dispatchFixture
	target, observed  uuid.UUID // the two segments
	observer          uuid.UUID // on observerNetwork only
	executor          uuid.UUID // on targetNetwork
	crossVLANEvidence uuid.UUID // measured by observer, about targetNetwork
}

func newExecutorWorld(t *testing.T) executorWorld {
	t.Helper()
	f := newDispatchFixture(t)
	f.setTenantConfig(t, unattendedPolicy)
	w := executorWorld{f: f, target: f.probeSegment(t, targetNetwork), observed: f.probeSegment(t, observerNetwork)}
	w.observer = f.collectorOn(t, "observer", "10.189.0.4", 24)
	// The observer also holds an address on the target network, on an
	// interface it does not report for network checks: it cannot execute
	// there, and the address is still never a target.
	if _, err := f.raw.Exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'wlan0','10.188.0.7',24)`, w.observer); err != nil {
		t.Fatal(err)
	}
	w.executor = f.collectorOn(t, "executor", "10.188.0.4", 24)
	w.crossVLANEvidence = f.identityObservation(t, identity.SourceMeasured, "sensor:"+w.observer.String(), w.target)
	return w
}

// refused asserts the request is refused BY THE DISPATCH GUARD with the given
// reason (any refusal when want is empty) and that nothing was written.
func (w executorWorld) refused(t *testing.T, req models.CreateDiscoveryJobRequest, want string) {
	t.Helper()
	before := w.f.countJobs(t)
	_, err := w.f.svc.CreateJob(w.f.tenant.String(), "system", req)
	if err == nil {
		t.Fatal("an unauthorized identity probe was created")
	}
	if want != "" && (!errors.Is(err, dispatchguard.ErrDenied) || !strings.Contains(err.Error(), want)) {
		t.Fatalf("err = %v, want the dispatch guard's refusal %q", err, want)
	}
	if after := w.f.countJobs(t); after != before {
		t.Fatalf("jobs %d → %d: the refused probe was written", before, after)
	}
}

// accepted asserts the request is created AND that the dispatcher's own
// re-check hands the executor the planned target.
func (w executorWorld) accepted(t *testing.T, req models.CreateDiscoveryJobRequest, executor uuid.UUID) {
	t.Helper()
	job, err := w.f.svc.CreateJob(w.f.tenant.String(), "system", req)
	if err != nil {
		t.Fatalf("an authorized identity probe was refused: %v", err)
	}
	if job.Plan == nil {
		t.Fatal("the identity probe was not planned")
	}
	payload, _ := w.f.dispatchPlan(t, job.ID)
	if len(payload.Plan.Targets) != 1 || payload.Plan.Targets[0].Target != req.Targets[0] {
		t.Fatalf("dispatched plan = %+v, want the one target %s", payload.Plan, req.Targets[0])
	}
	var assigned string
	if err := w.f.raw.QueryRow(`SELECT assigned_sensor_id::text FROM discovery_jobs WHERE id=$1`, job.ID).Scan(&assigned); err != nil || assigned != executor.String() {
		t.Fatalf("job assigned to %q (%v), want the executor %s", assigned, err, executor)
	}
}

func TestIntegration_IdentityProbe_ObserverIsExecutor(t *testing.T) {
	w := newExecutorWorld(t)
	own := w.f.identityObservation(t, identity.SourceMeasured, "sensor:"+w.executor.String(), w.target)
	w.accepted(t, identityProbe(w.executor, own, w.target, "10.188.0.20"), w.executor)
	scanned := w.f.identityObservation(t, identity.SourceMeasured, "scan:"+w.executor.String(), w.target)
	w.accepted(t, identityProbe(w.executor, scanned, w.target, "10.188.0.21"), w.executor)
}

// The case the executor split exists for: the observer heard about a host on
// a network it has no interface on, and another of the tenant's collectors,
// which does, runs the probe.
func TestIntegration_IdentityProbe_CrossNetworkExecutorIsAuthorized(t *testing.T) {
	w := newExecutorWorld(t)
	w.accepted(t, identityProbe(w.executor, w.crossVLANEvidence, w.target, "10.188.0.20"), w.executor)

	// The observer is provenance only: it need not be live to vouch for what
	// it measured, so long as it is still one of this tenant's collectors.
	if _, err := w.f.raw.Exec(`UPDATE sensors SET status='offline', last_heartbeat=now()-interval '1 day' WHERE id=$1`, w.observer); err != nil {
		t.Fatal(err)
	}
	w.accepted(t, identityProbe(w.executor, w.crossVLANEvidence, w.target, "10.188.0.21"), w.executor)
}

func TestIntegration_IdentityProbe_ExecutorMustReachTheTargetNetwork(t *testing.T) {
	w := newExecutorWorld(t)
	const unreachable = "executing collector network scope is no longer reachable"

	t.Run("the observer itself, which has no checked interface there", func(t *testing.T) {
		w.refused(t, identityProbe(w.observer, w.crossVLANEvidence, w.target, "10.188.0.20"), unreachable)
	})
	t.Run("a collector on yet another network", func(t *testing.T) {
		elsewhere := w.f.collectorOn(t, "elsewhere", "10.189.0.5", 24)
		w.refused(t, identityProbe(elsewhere, w.crossVLANEvidence, w.target, "10.188.0.20"), unreachable)
	})
	t.Run("a collector whose address on the network is stale", func(t *testing.T) {
		stale := w.f.collectorOn(t, "stale-address", "10.188.0.8", 24)
		if _, err := w.f.raw.Exec(`UPDATE agent_addresses SET last_seen_at=now()-interval '1 hour' WHERE sensor_id=$1`, stale); err != nil {
			t.Fatal(err)
		}
		w.refused(t, identityProbe(stale, w.crossVLANEvidence, w.target, "10.188.0.20"), unreachable)
	})
	t.Run("the platform's own collector", func(t *testing.T) {
		platform := w.f.collectorOn(t, "platform-managed", "10.188.0.9", 24)
		if _, err := w.f.raw.Exec(`UPDATE sensors SET platform_managed=true WHERE id=$1`, platform); err != nil {
			t.Fatal(err)
		}
		w.refused(t, identityProbe(platform, w.crossVLANEvidence, w.target, "10.188.0.20"), unreachable)
	})
	t.Run("a collector of another tenant", func(t *testing.T) {
		other := testdb.NewTenant(t, w.f.raw)
		foreign := uuid.New()
		beat := time.Now()
		if _, err := w.f.raw.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, reporting_interval, last_heartbeat, reported_dns_interfaces) VALUES ($1,$2,'foreign','linux','1.0.0','datacenter_host','active',30,$3,ARRAY['eth0'])`, foreign, other, beat); err != nil {
			t.Fatal(err)
		}
		if _, err := w.f.raw.Exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0','10.188.0.10',24)`, foreign); err != nil {
			t.Fatal(err)
		}
		// CreateJob may refuse a sensor of another tenant before the guard
		// does; either way nothing may be written.
		w.refused(t, identityProbe(foreign, w.crossVLANEvidence, w.target, "10.188.0.20"), "")
	})
}

func TestIntegration_IdentityProbe_ObserverMustBeACollectorOfThisTenant(t *testing.T) {
	w := newExecutorWorld(t)
	const notOurs = "probe source is not a collector of this tenant"
	refuseFrom := func(t *testing.T, observer uuid.UUID) {
		t.Helper()
		obs := w.f.identityObservation(t, identity.SourceMeasured, "sensor:"+observer.String(), w.target)
		w.refused(t, identityProbe(w.executor, obs, w.target, "10.188.0.20"), notOurs)
	}

	t.Run("a sensor of another tenant", func(t *testing.T) {
		other := testdb.NewTenant(t, w.f.raw)
		foreign := uuid.New()
		if _, err := w.f.raw.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, reporting_interval, last_heartbeat) VALUES ($1,$2,'foreign','linux','1.0.0','datacenter_host','active',30,now())`, foreign, other); err != nil {
			t.Fatal(err)
		}
		refuseFrom(t, foreign)
	})
	t.Run("an id no sensor has", func(t *testing.T) { refuseFrom(t, uuid.New()) })
	t.Run("a deleted sensor", func(t *testing.T) {
		gone := w.f.collectorOn(t, "deleted", "10.189.0.6", 24)
		if _, err := w.f.raw.Exec(`UPDATE sensors SET deleted_at=now() WHERE id=$1`, gone); err != nil {
			t.Fatal(err)
		}
		refuseFrom(t, gone)
	})
	t.Run("the platform's own collector", func(t *testing.T) {
		platform := w.f.liveSensor(t, "platform-discovery")
		if _, err := w.f.raw.Exec(`UPDATE sensors SET tags=ARRAY['system'] WHERE id=$1`, platform); err != nil {
			t.Fatal(err)
		}
		refuseFrom(t, platform)
	})
}

// Evidence that is not a collector's own measurement in the planned network
// scope never directs a probe, whichever collector would run it — exactly as
// before the executor was split from the observer.
func TestIntegration_IdentityProbe_NonCollectorEvidenceStaysRefused(t *testing.T) {
	w := newExecutorWorld(t)
	const changed = "probe source or scope changed"
	for name, tc := range map[string]struct {
		kind    identity.SourceKind
		ref     string
		segment func() uuid.UUID
	}{
		"interrogation":                  {kind: identity.SourceMeasured, ref: "interrogation"},
		"a sensor ref with no collector": {kind: identity.SourceMeasured, ref: "sensor"},
		"a scan ref with no collector":   {kind: identity.SourceMeasured, ref: "scan"},
		"a pcap upload":                  {kind: identity.SourceMeasured, ref: "sensor:pcap"},
		"an import naming a collector":   {kind: identity.SourceImported, ref: "sensor:" + w.executor.String()},
		"evidence from another network":  {kind: identity.SourceMeasured, ref: "sensor:" + w.observer.String(), segment: func() uuid.UUID { return w.observed }},
	} {
		t.Run(name, func(t *testing.T) {
			segment := w.target
			if tc.segment != nil {
				segment = tc.segment()
			}
			obs := w.f.identityObservation(t, tc.kind, tc.ref, segment)
			// The job's scope is the target network; the evidence's may not be.
			w.refused(t, identityProbe(w.executor, obs, w.target, "10.188.0.20"), changed)
		})
	}
}

// What the executor can reach never widens WHAT may be probed: the target must
// be in the observation's network scope, not excluded, and not a collector.
func TestIntegration_IdentityProbe_TargetScopeHoldsForAnyExecutor(t *testing.T) {
	w := newExecutorWorld(t)
	t.Run("the observer's network", func(t *testing.T) {
		w.refused(t, identityProbe(w.executor, w.crossVLANEvidence, w.target, "10.189.0.20"), "probe target outside authorized scope")
	})
	t.Run("an excluded address", func(t *testing.T) {
		w.f.mergeTenantConfig(t, `{"identity_enrichment":{"enabled":true,"excluded_cidrs":["10.188.0.20/32"]}}`)
		defer w.f.setTenantConfig(t, unattendedPolicy)
		// The every-origin target guard refuses an excluded address before
		// the identity guard is reached; either is a refusal of the job.
		w.refused(t, identityProbe(w.executor, w.crossVLANEvidence, w.target, "10.188.0.20"), "excluded")
	})
	t.Run("the executor's own address", func(t *testing.T) {
		w.refused(t, identityProbe(w.executor, w.crossVLANEvidence, w.target, "10.188.0.4"), "probe target belongs to a collector")
	})
	t.Run("the observer's own address", func(t *testing.T) {
		w.refused(t, identityProbe(w.executor, w.crossVLANEvidence, w.target, "10.188.0.7"), "probe target belongs to a collector")
	})
	t.Run("a public address", func(t *testing.T) {
		w.refused(t, identityProbe(w.executor, w.crossVLANEvidence, w.target, "93.184.216.34"), "")
	})
}
