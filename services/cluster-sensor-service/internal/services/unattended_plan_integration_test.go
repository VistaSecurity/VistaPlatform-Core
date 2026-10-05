package services

// Automatic scans and identity probes as PLANNED jobs ( WP2), against a
// real Postgres, through the real CreateJob, dispatcher and work-unit
// executor:
//
//   - creation accepts a planned automatic or identity job and refuses one
//     the automatic-scan rules refuse (excluded, sensitive, paused, a port the
//     policy does not allow, UDP, a deep depth, OT, an external target);
//   - an identity probe's request-ID replay works for a planned request;
//   - the platform executor re-checks the automatic-scan policy per unit,
//     before any packet;
//   - the dispatcher judges a planned automatic job on the plan it hands over;
//   - D3: an automatic, identity or translated job for a sensor without plan
//     support is created as the legacy job that sensor can run;
//   - D2: the legacy request translation, off (unchanged) and on.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// unattendedPolicy is an automatic-scan policy allowing TLS on 443 and 8443
// only, with identity enrichment switched on. Port 22 is therefore NOT allowed.
const unattendedPolicy = `{"discovery_auto_scan":{"enabled":true,"protocols":["TLS"],"ports":[443,8443]},"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}`

func (f *dispatchFixture) setTenantConfig(t *testing.T, config string) {
	t.Helper()
	if _, err := f.raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,$2::jsonb) ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, f.tenant, config); err != nil {
		t.Fatal(err)
	}
}

// mergeTenantConfig merges a JSON object into the tenant's settings.
func (f *dispatchFixture) mergeTenantConfig(t *testing.T, patch string) {
	t.Helper()
	if _, err := f.raw.Exec(`UPDATE tenant_admin_settings SET config=config||$2::jsonb WHERE tenant_id=$1`, f.tenant, patch); err != nil {
		t.Fatal(err)
	}
}

func (f *dispatchFixture) eligibleAsset(t *testing.T, address string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,$3,$4,'server','hardware.computer.server','monitoring')`,
		id, f.tenant, "auto-"+id.String()[:8], address); err != nil {
		t.Fatal(err)
	}
	return id
}

func automaticOptions() map[string]interface{} { return map[string]interface{}{"origin": "auto_scan"} }

func plannedAutomatic(targets ...string) models.CreateDiscoveryJobRequest {
	return models.CreateDiscoveryJobRequest{Targets: targets, ScanDepth: "custom", TCPPorts: "443", RunFrom: "platform", Options: automaticOptions()}
}

func (f *dispatchFixture) targetRows(t *testing.T, jobID string) (protocols [][]string, ports [][]int64) {
	t.Helper()
	rows, err := f.raw.Query(`SELECT protocols, ports FROM discovery_targets WHERE job_id=$1 ORDER BY created_at, id`, jobID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var pr pq.StringArray
		var po pq.Int64Array
		if err := rows.Scan(&pr, &po); err != nil {
			t.Fatal(err)
		}
		protocols, ports = append(protocols, []string(pr)), append(ports, []int64(po))
	}
	return protocols, ports
}

func TestIntegration_PlannedAutomaticScan_CreateJobAuthorizesThePlan(t *testing.T) {
	f := newDispatchFixture(t)
	f.setTenantConfig(t, unattendedPolicy)
	asset := f.eligibleAsset(t, "10.185.0.20")

	job, err := f.svc.CreateJob(f.tenant.String(), "system", plannedAutomatic("10.185.0.20"))
	if err != nil {
		t.Fatalf("an allowed planned automatic scan was refused: %v", err)
	}
	if job.Plan == nil || job.Plan.Depth != shareddisc.DepthCustom || job.Plan.TCPPorts != "443" {
		t.Fatalf("job.Plan = %+v, want a custom plan on 443", job.Plan)
	}

	for name, tc := range map[string]struct {
		mutate func(req *models.CreateDiscoveryJobRequest)
		config string
		want   func(error) bool
	}{
		"address excluded": {config: `{"identity_enrichment":{"enabled":true,"excluded_cidrs":["10.185.0.0/24"]}}`},
		"sensitive asset":  {config: `{"identity_enrichment":{"enabled":true,"sensitive_asset_ids":["` + asset.String() + `"]}}`},
		"policy paused": {config: `{"discovery_auto_scan":{"enabled":false,"protocols":["TLS"],"ports":[443,8443]}}`,
			want: func(err error) bool { return errors.Is(err, dispatchguard.ErrPaused) }},
		"port the policy does not allow": {mutate: func(r *models.CreateDiscoveryJobRequest) { r.TCPPorts = "22" }},
		"UDP port":                       {mutate: func(r *models.CreateDiscoveryJobRequest) { r.UDPPorts = "161" }},
		"standard depth":                 {mutate: func(r *models.CreateDiscoveryJobRequest) { r.ScanDepth, r.TCPPorts = "standard", "" }},
		"OT opt-in": {mutate: func(r *models.CreateDiscoveryJobRequest) { r.OTProbeProtocols = []string{"Modbus"} },
			want: func(err error) bool { return err != nil && strings.Contains(err.Error(), "OT probes") }},
		"no eligible asset": {mutate: func(r *models.CreateDiscoveryJobRequest) { r.Targets = []string{"10.185.0.99"} }},
	} {
		t.Run(name, func(t *testing.T) {
			f.setTenantConfig(t, unattendedPolicy)
			if tc.config != "" {
				f.mergeTenantConfig(t, tc.config)
			}
			req := plannedAutomatic("10.185.0.20")
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			before := f.countJobs(t)
			_, err := f.svc.CreateJob(f.tenant.String(), "system", req)
			want := tc.want
			if want == nil {
				want = func(err error) bool { return errors.Is(err, dispatchguard.ErrDenied) }
			}
			if !want(err) {
				t.Fatalf("err = %v, want a refusal", err)
			}
			if after := f.countJobs(t); after != before {
				t.Fatalf("jobs %d → %d: the refused job was written", before, after)
			}
		})
	}
}

// An automatic scan has no person behind it: a target outside the tenant's
// networks is refused whatever the request says — confirmed, from a user id,
// at quick depth (the external depth cap is for a person's scan, never a way
// in for an unattended one).
func TestIntegration_PlannedAutomaticScan_ExternalTargetsStayRefused(t *testing.T) {
	f := newDispatchFixture(t)
	f.setTenantConfig(t, unattendedPolicy)
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	user := f.tenantUser(t)
	for _, depth := range []string{"custom", "quick"} {
		t.Run(depth, func(t *testing.T) {
			req := plannedAutomatic("93.184.216.34")
			req.ExternalTargetsConfirmed = true
			if depth == "quick" {
				req.ScanDepth, req.TCPPorts = "quick", ""
			}
			before := f.countJobs(t)
			_, err := f.svc.CreateJob(f.tenant.String(), user, req)
			// Refused by the target guard itself, as a legacy automatic
			// scan's external target is — not left to a later check.
			var refused *dispatchguard.RefusedTargetsError
			if !errors.As(err, &refused) {
				t.Fatalf("err = %v, want the external target refused by the target guard", err)
			}
			if f.countJobs(t) != before {
				t.Fatal("an automatic scan of an external target was written")
			}
		})
	}
}

// The platform executor re-checks the automatic-scan policy for each unit,
// before any packet: an asset marked sensitive after the job was created is
// never contacted, and its neighbour still is.
func TestIntegration_PlannedAutomaticScan_PlatformRechecksPolicyPerUnit(t *testing.T) {
	f, fake := newUnitFixture(t)
	f.setTenantConfig(t, unattendedPolicy)
	sensitive := f.eligibleAsset(t, "10.185.1.10")
	f.eligibleAsset(t, "10.185.1.21")
	fake.Host("10.185.1.10", nil, nil)
	fake.Host("10.185.1.21", nil, nil)
	job, err := f.svc.CreateJob(f.tenant.String(), "system", plannedAutomatic("10.185.1.10", "10.185.1.21"))
	if err != nil {
		t.Fatal(err)
	}
	f.mergeTenantConfig(t, `{"identity_enrichment":{"enabled":true,"sensitive_asset_ids":["`+sensitive.String()+`"]}}`)

	if claimed, err := f.svc.ClaimJob(job.ID); err != nil || !claimed {
		t.Fatal(claimed, err)
	}
	loaded, err := f.svc.GetJob(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.processDiscoveryJob(context.Background(), loaded); err != nil {
		t.Fatalf("processDiscoveryJob: %v", err)
	}
	dialed := fake.DialedAddrs()
	if dialed["10.185.1.10"] != 0 {
		t.Errorf("the sensitive asset was dialled %d time(s): the automatic-scan policy was not re-checked per unit", dialed["10.185.1.10"])
	}
	if dialed["10.185.1.21"] == 0 {
		t.Error("the still-eligible address was never scanned — the test proves nothing")
	}
	st := f.unitStatuses(t, job.ID)
	if st["10.185.1.10"] != unitFailed || st["10.185.1.21"] != unitDone {
		t.Errorf("units = %v, want the sensitive one failed and .21 done", st)
	}
}

// A planned automatic job for a tenant sensor is judged at dispatch on the
// plan it hands over: paused, it stays queued with no command; resumed, the
// command carries the plan.
func TestIntegration_PlannedAutomaticScan_DispatchJudgesThePlan(t *testing.T) {
	f := newDispatchFixture(t)
	f.setTenantConfig(t, unattendedPolicy)
	sensor := f.capableSensor(t, "edge-new")
	f.eligibleAsset(t, "10.185.2.20")
	req := plannedAutomatic("10.185.2.20")
	req.RunFrom, req.SensorID = "sensor", sensor.String()
	job, err := f.svc.CreateJob(f.tenant.String(), "system", req)
	if err != nil {
		t.Fatal(err)
	}
	if job.Plan == nil {
		t.Fatal("a planned automatic job for a capable sensor was not planned")
	}
	f.mergeTenantConfig(t, `{"discovery_auto_scan":{"enabled":false,"protocols":["TLS"],"ports":[443,8443]}}`)
	if err := f.jp.dispatchToSensor(job); err != nil {
		t.Fatal(err)
	}
	if status := f.jobStatus(t, job.ID); status != "queued" {
		t.Fatalf("paused automatic job is %s, want queued", status)
	}
	var count int
	if err := f.raw.QueryRow(`SELECT count(*) FROM sensor_commands WHERE sensor_id=$1`, sensor).Scan(&count); err != nil || count != 0 {
		t.Fatalf("paused dispatch wrote %d command(s) %v", count, err)
	}
	f.setTenantConfig(t, unattendedPolicy)
	payload, _ := f.dispatchPlan(t, job.ID)
	if len(payload.Plan.Targets) != 1 || payload.Plan.Targets[0].Target != "10.185.2.20" || payload.Plan.Targets[0].TCPPorts != "443" {
		t.Fatalf("dispatched plan = %+v", payload.Plan)
	}
}

// preparePlannedEnrichment is an identity probe's world on 10.186.0.0/24: an
// observation measured by sensor on that segment, the sensor reachable there.
func preparePlannedEnrichment(t *testing.T, f *dispatchFixture, sensor uuid.UUID) map[string]interface{} {
	t.Helper()
	observation, segment := uuid.New(), uuid.New()
	if _, err := f.raw.Exec(`UPDATE sensors SET reported_dns_interfaces=ARRAY['eth0'] WHERE id=$1`, sensor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0','10.186.0.4',24)`, sensor); err != nil {
		t.Fatal(err)
	}
	f.setTenantConfig(t, unattendedPolicy)
	if _, err := f.raw.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'probe network','cidr','10.186.0.0/24','production')`, segment, f.tenant); err != nil {
		t.Fatal(err)
	}
	evidence := `{"tenant_id":"` + f.tenant.String() + `","source":{"kind":"` + string(identity.SourceMeasured) + `","ref":"sensor:` + sensor.String() + `"},"network":{"segment_id":"` + segment.String() + `"}}`
	if _, err := f.raw.Exec(`INSERT INTO identity_observations(id,tenant_id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1::uuid,$2,$1::text,'measured',$3,$4,now(),now())`,
		observation, f.tenant, "sensor:"+sensor.String(), evidence); err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{
		"identity_enrichment_request_id": uuid.NewString(),
		"identity_observation_id":        observation.String(),
		"identity_network_scope":         segment.String(),
	}
}

func plannedIdentity(sensor uuid.UUID, options map[string]interface{}) models.CreateDiscoveryJobRequest {
	return models.CreateDiscoveryJobRequest{Targets: []string{"10.186.0.20"}, ScanDepth: "custom", TCPPorts: "443", RunFrom: "sensor", SensorID: sensor.String(), Options: options}
}

func TestIntegration_PlannedIdentityProbe_CreateJobAuthorizesAndReplays(t *testing.T) {
	f := newDispatchFixture(t)
	sensor := f.capableSensor(t, "edge-new")
	options := preparePlannedEnrichment(t, f, sensor)
	req := plannedIdentity(sensor, options)

	job, err := f.svc.CreateJob(f.tenant.String(), "system", req)
	if err != nil {
		t.Fatalf("an allowed planned identity probe was refused: %v", err)
	}
	if job.Plan == nil {
		t.Fatal("the identity probe was not planned")
	}
	replay, err := f.svc.CreateJob(f.tenant.String(), "system", req)
	if err != nil || replay.ID != job.ID {
		t.Fatalf("replay = %+v %v, want job %s again", replay, err, job.ID)
	}
	changed := req
	changed.TCPPorts = "8443"
	if _, err := f.svc.CreateJob(f.tenant.String(), "system", changed); err == nil || !strings.Contains(err.Error(), "different inputs") {
		t.Fatalf("same request id with different ports: err = %v", err)
	}

	for name, tc := range map[string]struct {
		mutate func(*models.CreateDiscoveryJobRequest)
		config string
	}{
		"target excluded":                {config: `{"identity_enrichment":{"enabled":true,"excluded_cidrs":["10.186.0.20/32"]}}`},
		"port the policy does not allow": {mutate: func(r *models.CreateDiscoveryJobRequest) { r.TCPPorts = "22" }},
		"UDP port":                       {mutate: func(r *models.CreateDiscoveryJobRequest) { r.UDPPorts = "161" }},
		"target outside the segment":     {mutate: func(r *models.CreateDiscoveryJobRequest) { r.Targets = []string{"10.187.0.20"} }},
		"the collector's own address":    {mutate: func(r *models.CreateDiscoveryJobRequest) { r.Targets = []string{"10.186.0.4"} }},
	} {
		t.Run(name, func(t *testing.T) {
			f.setTenantConfig(t, unattendedPolicy)
			if tc.config != "" {
				f.mergeTenantConfig(t, tc.config)
			}
			opts := map[string]interface{}{}
			for k, v := range options {
				opts[k] = v
			}
			opts["identity_enrichment_request_id"] = uuid.NewString()
			r := plannedIdentity(sensor, opts)
			if tc.mutate != nil {
				tc.mutate(&r)
			}
			before := f.countJobs(t)
			if _, err := f.svc.CreateJob(f.tenant.String(), "system", r); err == nil {
				t.Fatal("an unauthorized planned identity probe was created")
			}
			if f.countJobs(t) != before {
				t.Fatal("the refused identity probe was written")
			}
		})
	}
}

// The identity fingerprint is taken from the request as sent, so a replay
// matches whether or not the legacy request was translated to a plan: a probe
// stored as a legacy job (the sensor could not run a plan then, D3) is the
// answer to the same request after the sensor is upgraded.
func TestIntegration_IdentityProbe_ReplayAcrossTheTranslationSwitch(t *testing.T) {
	f := newDispatchFixture(t)
	sensor := f.capableSensor(t, "edge-new")
	options := preparePlannedEnrichment(t, f, sensor)
	req := models.CreateDiscoveryJobRequest{Targets: []string{"10.186.0.20"}, Protocols: []string{"TLS"}, Ports: []int{443},
		ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor.String()}, Options: options}

	setCaps := func(caps []string) {
		t.Helper()
		if _, err := f.raw.Exec(`UPDATE sensors SET reported_capabilities = $2 WHERE id = $1`, sensor, pq.Array(caps)); err != nil {
			t.Fatal(err)
		}
	}
	setCaps([]string{})
	legacy, err := f.svc.CreateJob(f.tenant.String(), "system", req)
	if err != nil || legacy.Plan != nil {
		t.Fatalf("old sensor: job = %+v err = %v, want a legacy job", legacy, err)
	}
	setCaps([]string{sensordispatch.ScanPlanCapability})
	replay, err := f.svc.CreateJob(f.tenant.String(), "system", req)
	if err != nil || replay.ID != legacy.ID {
		t.Fatalf("upgraded sensor: replay = %+v err = %v, want job %s", replay, err, legacy.ID)
	}

	fresh := req
	fresh.Options = map[string]interface{}{}
	for k, v := range options {
		fresh.Options[k] = v
	}
	fresh.Options["identity_enrichment_request_id"] = uuid.NewString()
	planned, err := f.svc.CreateJob(f.tenant.String(), "system", fresh)
	if err != nil || planned.Plan == nil || planned.Plan.TCPPorts != "443" {
		t.Fatalf("switch on: job = %+v err = %v, want a custom plan on 443", planned, err)
	}
	again, err := f.svc.CreateJob(f.tenant.String(), "system", fresh)
	if err != nil || again.ID != planned.ID {
		t.Fatalf("switch on: replay of a translated probe = %+v %v, want %s", again, err, planned.ID)
	}
}

// D3: a sensor without scan_plan_v1 gets the legacy job it can run when the
// job is automatic, an identity probe, or a translated legacy request; a
// person's own planned job is still refused.
func TestIntegration_SensorWithoutPlanSupport_UnattendedJobsFallBackToLegacy(t *testing.T) {

	t.Run("automatic", func(t *testing.T) {
		f := newDispatchFixture(t)
		f.setTenantConfig(t, unattendedPolicy)
		old := f.liveSensor(t, "edge-old")
		f.eligibleAsset(t, "10.185.3.20")
		req := plannedAutomatic("10.185.3.20")
		req.RunFrom, req.SensorID = "sensor", old.String()
		job, err := f.svc.CreateJob(f.tenant.String(), "system", req)
		if err != nil {
			t.Fatalf("automatic job for an old sensor: %v", err)
		}
		if job.Plan != nil {
			t.Fatalf("the old sensor was handed a plan: %+v", job.Plan)
		}
		protocols, ports := f.targetRows(t, job.ID)
		if !reflect.DeepEqual(protocols, [][]string{{"TLS"}}) || !reflect.DeepEqual(ports, [][]int64{{443}}) {
			t.Fatalf("legacy target rows = %v × %v, want [TLS] × [443] (policy protocols, plan ports)", protocols, ports)
		}
		payload, _ := f.dispatchLegacy(t, job.ID)
		if payload.Plan != nil || !reflect.DeepEqual(payload.Protocols, []string{"TLS"}) || !reflect.DeepEqual(payload.Ports, []int{443}) {
			t.Fatalf("dispatched payload = %+v, want the legacy shape", payload)
		}
		// The fallback is still an automatic scan: its rules still apply.
		req.TCPPorts = "22"
		if _, err := f.svc.CreateJob(f.tenant.String(), "system", req); !errors.Is(err, dispatchguard.ErrDenied) {
			t.Fatalf("fallback with a port the policy does not allow: err = %v", err)
		}
		req.TCPPorts, req.UDPPorts = "443", "161"
		var bad *shareddisc.ScanRequestError
		if _, err := f.svc.CreateJob(f.tenant.String(), "system", req); !errors.As(err, &bad) {
			t.Fatalf("fallback of a plan with UDP: err = %v", err)
		}
	})

	t.Run("identity", func(t *testing.T) {
		f := newDispatchFixture(t)
		old := f.liveSensor(t, "edge-old")
		options := preparePlannedEnrichment(t, f, old)
		job, err := f.svc.CreateJob(f.tenant.String(), "system", plannedIdentity(old, options))
		if err != nil {
			t.Fatalf("identity probe for an old sensor: %v", err)
		}
		if job.Plan != nil {
			t.Fatalf("the old sensor was handed a plan: %+v", job.Plan)
		}
		replay, err := f.svc.CreateJob(f.tenant.String(), "system", plannedIdentity(old, options))
		if err != nil || replay.ID != job.ID {
			t.Fatalf("replay of a fallen-back probe = %+v %v", replay, err)
		}
	})

	t.Run("translated", func(t *testing.T) {
		f := newDispatchFixture(t)
		old := f.liveSensor(t, "edge-old")
		job, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
			Targets: []string{"10.185.4.20"}, Protocols: []string{"TLS", "SSH"}, Ports: []int{443, 22},
			ExecutionMode: "sensors", PreferredSensorIDs: []string{old.String()}, Options: map[string]interface{}{"active_scan": true},
		})
		if err != nil || job.Plan != nil {
			t.Fatalf("translated request for an old sensor: job = %+v err = %v, want the legacy job", job, err)
		}
		protocols, ports := f.targetRows(t, job.ID)
		if !reflect.DeepEqual(protocols, [][]string{{"TLS", "SSH"}}) || !reflect.DeepEqual(ports, [][]int64{{443, 22}}) {
			t.Fatalf("legacy target rows = %v × %v, want the request as sent", protocols, ports)
		}
	})

	t.Run("a person's planned job is still refused", func(t *testing.T) {
		f := newDispatchFixture(t)
		old := f.liveSensor(t, "edge-old")
		_, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
			Targets: []string{"10.185.5.20"}, ScanDepth: "custom", TCPPorts: "443", RunFrom: "sensor", SensorID: old.String(),
		})
		if !errors.Is(err, ErrSensorScanPlanUnsupported) {
			t.Fatalf("err = %v, want ErrSensorScanPlanUnsupported", err)
		}
	})
}

// dispatchLegacy runs the dispatcher for a legacy job and returns its command
// as the sensor parses it.
func (f *dispatchFixture) dispatchLegacy(t *testing.T, jobID string) (sensordispatch.Payload, string) {
	t.Helper()
	job, err := f.svc.GetJob(jobID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.dispatchToSensor(job); err != nil {
		t.Fatalf("dispatchToSensor: %v", err)
	}
	var (
		cmdID string
		m     map[string]interface{}
		raw   []byte
	)
	if err := f.raw.QueryRow(`SELECT id, payload FROM sensor_commands WHERE command_type = $1 AND payload ->> 'job_id' = $2`,
		sensordispatch.CommandType, jobID).Scan(&cmdID, &raw); err != nil {
		t.Fatalf("no command for %s: %v (job %s)", jobID, err, f.jobStatus(t, jobID))
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	payload, err := sensordispatch.ParsePayload(m)
	if err != nil {
		t.Fatalf("the sensor would refuse the stored payload: %v", err)
	}
	return payload, cmdID
}

// D2 (unconditional since WP5): ports become a custom plan, protocols
// are accepted and ignored (but an unknown one is still refused), and an
// OT-only request becomes a custom plan on its OT ports with its opt-in.
func TestIntegration_LegacyRequestTranslation_PlansThePorts(t *testing.T) {
	f := newDispatchFixture(t)

	job, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.185.7.20"}, Protocols: []string{"TLS", "SSH"}, Ports: []int{443, 22}, ExecutionMode: "async",
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Plan == nil || job.Plan.Depth != shareddisc.DepthCustom || job.Plan.TCPPorts != "22,443" || job.Plan.ExecutorResolved != shareddisc.ExecutorPlatform {
		t.Fatalf("job.Plan = %+v, want a custom plan on 22,443 run from the platform", job.Plan)
	}
	protocols, ports := f.targetRows(t, job.ID)
	if !reflect.DeepEqual(protocols, [][]string{{}}) || !reflect.DeepEqual(ports, [][]int64{{22, 443}}) {
		t.Fatalf("target rows = %v × %v, want no protocols and the plan's ports", protocols, ports)
	}

	capable := f.capableSensor(t, "edge-new")
	onSensor, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.185.7.21"}, Protocols: []string{"TLS"}, Ports: []int{443},
		ExecutionMode: "sensors", PreferredSensorIDs: []string{capable.String()},
	})
	if err != nil || onSensor.Plan == nil || onSensor.Plan.SensorID != capable.String() {
		t.Fatalf("translated sensor request: job = %+v err = %v, want a plan on the named sensor", onSensor, err)
	}

	if _, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.185.7.22"}, Protocols: []string{"Modbus"}, Ports: []int{502}, ExecutionMode: "async",
	}); err == nil {
		t.Fatal("an unknown/OT protocol name was accepted because it is ignored")
	}

	if _, err := f.raw.Exec(`UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'community') WHERE id = $1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	otOnly, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.185.7.23"}, OTProbeProtocols: []string{"Modbus"}, ExecutionMode: "async",
	})
	if err != nil || otOnly.Plan == nil || otOnly.Plan.TCPPorts != "502" || otOnly.Plan.UDPPorts != "" {
		t.Fatalf("OT-only request: job = %+v err = %v, want a custom plan on TCP 502", otOnly, err)
	}
}
