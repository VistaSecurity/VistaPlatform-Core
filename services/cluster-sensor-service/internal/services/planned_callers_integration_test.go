package services

// The four platform callers as PLANNED jobs ( WP4), against a real
// Postgres through the real CreateJob, each in the exact request shape
// inventory-service now sends:
//
//   - automatic scan: execution_mode "sensors" + one preferred sensor (the
//     observing sensor) is run_from sensor; "async" is the platform; an old
//     sensor gets the legacy job with the policy's protocols (D3);
//   - identity probe: a probe a pre-upgrade build dispatched in the legacy
//     shape and an upgraded build retries in the planned shape is the SAME
//     job, not "request ID reused with different inputs";
//   - Active Scan: a plan on the named sensor, the legacy TLS+SSH job on an
//     old one (D3), and a person's confirmed external target at custom depth
//     with one or two ports is accepted from the platform.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func TestIntegration_PlannedAutomaticScan_ExecutionModeRoutingAsSent(t *testing.T) {
	f := newDispatchFixture(t)
	f.setTenantConfig(t, unattendedPolicy)
	f.eligibleAsset(t, "10.185.9.20")
	capable := f.capableSensor(t, "edge-new")
	old := f.liveSensor(t, "edge-old")

	// autoActiveScanJob's request for a batch routed to the observing sensor
	// (inventory-service automaticScanJobInput).
	sent := func(mode string, sensors ...string) models.CreateDiscoveryJobRequest {
		return models.CreateDiscoveryJobRequest{Targets: []string{"10.185.9.20"}, ExecutionMode: mode, PreferredSensorIDs: sensors,
			ScanDepth: "custom", TCPPorts: "443,8443", Options: map[string]interface{}{"origin": "auto_scan", "active_scan": true}}
	}

	onSensor, err := f.svc.CreateJob(f.tenant.String(), "system", sent("sensors", capable.String()))
	if err != nil {
		t.Fatalf("automatic scan for a capable sensor: %v", err)
	}
	if onSensor.Plan == nil || onSensor.Plan.ExecutorResolved != shareddisc.ExecutorSensor || onSensor.Plan.SensorID != capable.String() || onSensor.Plan.TCPPorts != "443,8443" {
		t.Fatalf("job.Plan = %+v, want a custom plan on 443,8443 run from %s", onSensor.Plan, capable)
	}

	onPlatform, err := f.svc.CreateJob(f.tenant.String(), "system", sent("async"))
	if err != nil {
		t.Fatalf("automatic scan for the platform: %v", err)
	}
	if onPlatform.Plan == nil || onPlatform.Plan.ExecutorResolved != shareddisc.ExecutorPlatform {
		t.Fatalf("job.Plan = %+v, want a plan run from the platform", onPlatform.Plan)
	}

	fallback, err := f.svc.CreateJob(f.tenant.String(), "system", sent("sensors", old.String()))
	if err != nil {
		t.Fatalf("automatic scan for an old sensor: %v", err)
	}
	if fallback.Plan != nil {
		t.Fatalf("the old sensor was handed a plan: %+v", fallback.Plan)
	}
	protocols, ports := f.targetRows(t, fallback.ID)
	if !reflect.DeepEqual(protocols, [][]string{{"TLS"}}) || !reflect.DeepEqual(ports, [][]int64{{443, 8443}}) {
		t.Fatalf("legacy target rows = %v × %v, want the policy's [TLS] × the plan's [443 8443]", protocols, ports)
	}
}

// The upgrade case: inventory-service persisted the request ID and dispatched
// the probe in the legacy shape; it then restarted (or lost the answer) and
// the upgraded build retries the same request ID in the planned shape.
func TestIntegration_IdentityProbe_RetryAcrossTheUpgradeReturnsTheStoredJob(t *testing.T) {
	f := newDispatchFixture(t)
	sensor := f.capableSensor(t, "edge-new")
	options := preparePlannedEnrichment(t, f, sensor)
	options["origin"], options["active_scan"] = "identity_enrichment", true

	// What the pre-upgrade inventory-service sent (Protocols/Ports from the
	// identity plan), stored as a legacy job. This release creates that shape
	// only for a sensor without plan support ( D3), so the sensor is
	// briefly one: the stored row is the same either way.
	if _, err := f.raw.Exec(`UPDATE sensors SET reported_capabilities = '{}' WHERE id = $1`, sensor); err != nil {
		t.Fatal(err)
	}
	legacy, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.186.0.20"}, ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor.String()},
		Protocols: []string{"TLS"}, Ports: []int{443}, Options: options,
	})
	if err != nil || legacy.Plan != nil {
		t.Fatalf("pre-upgrade probe: job = %+v err = %v, want a legacy job", legacy, err)
	}
	if _, err := f.raw.Exec(`UPDATE sensors SET reported_capabilities = $2 WHERE id = $1`, sensor, pq.Array([]string{sensordispatch.ScanPlanCapability})); err != nil {
		t.Fatal(err)
	}

	// What the upgraded inventory-service sends for the SAME request ID.
	planned := models.CreateDiscoveryJobRequest{
		Targets: []string{"10.186.0.20"}, ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor.String()},
		ScanDepth: "custom", TCPPorts: "443", Options: options,
	}
	before := f.countJobs(t)
	retry, err := f.svc.CreateJob(f.tenant.String(), "system", planned)
	if err != nil {
		t.Fatalf("retry after the upgrade: %v — the observation would be stranded on this refusal", err)
	}
	if retry.ID != legacy.ID {
		t.Fatalf("retry created job %s, want the stored job %s", retry.ID, legacy.ID)
	}
	if after := f.countJobs(t); after != before {
		t.Fatalf("jobs %d → %d: the retry probed again", before, after)
	}

	// The same request ID for a DIFFERENT sensor is still refused.
	other := f.capableSensor(t, "edge-other")
	elsewhere := planned
	elsewhere.PreferredSensorIDs = []string{other.String()}
	if _, err := f.svc.CreateJob(f.tenant.String(), "system", elsewhere); err == nil {
		t.Fatal("a request ID reused for another sensor was accepted as a replay")
	}
}

func TestIntegration_ActiveScan_PlannedOnSensorAndLegacyOnAnOldOne(t *testing.T) {
	f := newDispatchFixture(t)
	user := f.tenantUser(t)
	capable := f.capableSensor(t, "edge-new")
	old := f.liveSensor(t, "edge-old")

	// CreateActiveScanJob's request for an asset on 2222, run from a sensor.
	sent := func(sensor uuid.UUID) models.CreateDiscoveryJobRequest {
		return models.CreateDiscoveryJobRequest{Targets: []string{"10.185.10.20"}, ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor.String()},
			ScanDepth: "custom", TCPPorts: "2222", Options: map[string]interface{}{"active_scan": true}}
	}

	planned, err := f.svc.CreateJob(f.tenant.String(), user, sent(capable))
	if err != nil {
		t.Fatalf("Active Scan on a capable sensor: %v", err)
	}
	if planned.Plan == nil || planned.Plan.SensorID != capable.String() || planned.Plan.TCPPorts != "2222" {
		t.Fatalf("job.Plan = %+v, want a custom plan on 2222 run from %s", planned.Plan, capable)
	}

	fallback, err := f.svc.CreateJob(f.tenant.String(), user, sent(old))
	if err != nil {
		t.Fatalf("Active Scan on an old sensor was refused: %v — it ran there before the move", err)
	}
	if fallback.Plan != nil {
		t.Fatalf("the old sensor was handed a plan: %+v", fallback.Plan)
	}
	protocols, ports := f.targetRows(t, fallback.ID)
	if !reflect.DeepEqual(protocols, [][]string{{"SSH", "TLS"}}) || !reflect.DeepEqual(ports, [][]int64{{2222}}) {
		t.Fatalf("legacy target rows = %v × %v, want [SSH TLS] × [2222]", protocols, ports)
	}
	payload, _ := f.dispatchLegacy(t, fallback.ID)
	if payload.Plan != nil || !reflect.DeepEqual(payload.Ports, []int{2222}) {
		t.Fatalf("dispatched payload = %+v, want the legacy shape on 2222", payload)
	}
}

// A person's confirmed Active Scan of an asset outside the registered
// networks runs from the platform on the plan path, which caps an external
// target's custom scan (capExternal): one port or the two fallback ports are
// well inside the cap and arrive unchanged.
func TestIntegration_ActiveScan_ConfirmedExternalCustomDepthFromThePlatform(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newDispatchFixture(t)
	user := f.tenantUser(t)

	for _, ports := range []string{"443", "443,8443"} {
		t.Run(ports, func(t *testing.T) {
			req := models.CreateDiscoveryJobRequest{Targets: []string{"93.184.216.34"}, ExecutionMode: "async",
				ScanDepth: "custom", TCPPorts: ports, Options: map[string]interface{}{"active_scan": true}}
			if _, err := f.svc.CreateJob(f.tenant.String(), user, req); err == nil {
				t.Fatal("an unconfirmed external Active Scan was created")
			}
			req.ExternalTargetsConfirmed = true
			job, err := f.svc.CreateJob(f.tenant.String(), user, req)
			if err != nil {
				t.Fatalf("confirmed external Active Scan refused: %v", err)
			}
			if job.Plan == nil || job.Plan.ExecutorResolved != shareddisc.ExecutorPlatform || len(job.Plan.Targets) != 1 {
				t.Fatalf("job.Plan = %+v, want one target run from the platform", job.Plan)
			}
			target := job.Plan.Targets[0]
			if target.Depth != shareddisc.DepthCustom || target.TCPPorts != ports {
				t.Fatalf("plan target = %+v, want custom on %s", target, ports)
			}
			if len(job.Plan.DepthAdjustments) != 0 {
				t.Fatalf("external cap adjusted the scan: %+v", job.Plan.DepthAdjustments)
			}
			if len(job.ExternalTargets) != 1 {
				t.Fatalf("consent not recorded: %+v", job.ExternalTargets)
			}
		})
	}
}
