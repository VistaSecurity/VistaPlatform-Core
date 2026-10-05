package services_test

// Scan-plan jobs ( WP3) through the REAL CreateJob and GetJob handlers
// against a real Postgres: the per-target external depth cap (D3), the segment
// that granted ownership, the probe budget (H19) and Auto routing (D7, H11).
//
// It lives beside the services package (as services_test) rather than in
// handlers so it can use the test-only helpers in export_test.go.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type planFixture struct {
	db     *sqlx.DB
	tenant uuid.UUID
	r      *gin.Engine
}

// newPlanFixture is a tenant and the real handlers over a real database.
func newPlanFixture(t *testing.T) *planFixture {
	t.Helper()
	return newPlanFixtureAsIs(t)
}

func newPlanFixtureAsIs(t *testing.T) *planFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	sqlDB := testdb.Connect(t)
	db := sqlx.NewDb(sqlDB, "postgres")
	tenant := testdb.NewTenant(t, db.DB)
	user := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, user, tenant, user.String()+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := handlers.NewDiscoveryHandler(services.NewDiscoveryService(db, db), services.NewRateLimiter(db), nil, nil)
	r := gin.New()
	as := func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set(sharedmw.CtxKeyTenantID, tenant)
			c.Set("userID", user.String())
			next(c)
		}
	}
	r.POST("/jobs", as(h.CreateJob))
	r.GET("/jobs/:id", as(h.GetJob))
	return &planFixture{db: db, tenant: tenant, r: r}
}

func (f *planFixture) post(t *testing.T, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewReader(raw)))
	return w
}

// created posts and decodes a 202's job.
func (f *planFixture) created(t *testing.T, body map[string]interface{}) jobWithPlan {
	t.Helper()
	w := f.post(t, body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST %v = %d (%s), want 202", body, w.Code, w.Body)
	}
	var resp struct {
		Job jobWithPlan `json:"job"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Job.Plan == nil {
		t.Fatalf("create response carries no plan: %s", w.Body)
	}
	return resp.Job
}

type jobWithPlan struct {
	ID                 string               `json:"id"`
	ExecutionMode      string               `json:"execution_mode"`
	RequestedSensorIDs []string             `json:"requested_sensor_ids"`
	Plan               *shareddisc.ScanPlan `json:"plan"`
}

func (f *planFixture) storedMode(t *testing.T, jobID string) (string, []string) {
	t.Helper()
	var mode string
	var ids pq.StringArray
	if err := f.db.QueryRow(`SELECT execution_mode, requested_sensor_ids FROM discovery_jobs WHERE id = $1`, jobID).Scan(&mode, &ids); err != nil {
		t.Fatal(err)
	}
	return mode, []string(ids)
}

// D3 per target, through the real handler: a private /24 and a registered
// public block run at the requested Thorough depth while an external host in
// the SAME job runs at Standard, the downgrade is reported, the registered
// target names its segment, and the target rows carry the planned ports.
func TestIntegration_ScanPlan_ExternalCapIsPerTarget(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	t.Setenv(shareddisc.EnvMaxJobProbes, "")
	f := newPlanFixture(t)
	var segmentID string
	if err := f.db.QueryRow(`INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, is_active)
		VALUES ($1, 'dmz', 'cidr', '93.184.217.0/28', 'public', 'production', true) RETURNING id`, f.tenant).Scan(&segmentID); err != nil {
		t.Fatal(err)
	}

	job := f.created(t, map[string]interface{}{
		"targets":                    []string{"10.20.30.0/24", "93.184.216.34", "93.184.217.0/29"},
		"scan_depth":                 "thorough",
		"run_from":                   "platform",
		"external_targets_confirmed": true,
	})
	plan := job.Plan
	if len(plan.Targets) != 3 {
		t.Fatalf("plan targets = %+v", plan.Targets)
	}
	private, external, registered := plan.Targets[0], plan.Targets[1], plan.Targets[2]
	if private.Class != shareddisc.ClassPrivate || private.Depth != shareddisc.DepthThorough || private.TCPPortCount != 65535 {
		t.Errorf("private /24 = %+v, want thorough", private)
	}
	if external.Class != shareddisc.ClassExternal || external.Depth != shareddisc.DepthStandard || external.TCPPortCount != shareddisc.StandardPorts().Len() {
		t.Errorf("external host = %+v, want capped to standard", external)
	}
	if registered.Class != shareddisc.ClassRegisteredSegment || registered.SegmentID != segmentID || registered.Depth != shareddisc.DepthThorough {
		t.Errorf("registered block = %+v, want thorough and segment %s", registered, segmentID)
	}
	if len(plan.DepthAdjustments) != 1 || plan.DepthAdjustments[0].Target != "93.184.216.34" ||
		plan.DepthAdjustments[0].Applied != shareddisc.DepthStandard || !strings.Contains(plan.DepthAdjustments[0].Reason, "register the range if it is yours") {
		t.Errorf("adjustments = %+v", plan.DepthAdjustments)
	}
	if plan.ExecutorResolved != shareddisc.ExecutorPlatform || plan.RunFromRequested != shareddisc.RunFromPlatform || plan.ProbeLimit != shareddisc.DefaultMaxJobProbes {
		t.Errorf("plan executor/limit = %+v", plan)
	}

	// The target rows the executor reads carry each target's PLANNED ports.
	rows, err := f.db.Query(`SELECT input, cardinality(ports), cardinality(protocols) FROM discovery_targets WHERE job_id = $1`, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][2]int{}
	for rows.Next() {
		var input string
		var ports, protocols int
		if err := rows.Scan(&input, &ports, &protocols); err != nil {
			t.Fatal(err)
		}
		got[input] = [2]int{ports, protocols}
	}
	_ = rows.Close()
	want := map[string][2]int{"10.20.30.0/24": {65535, 0}, "93.184.216.34": {shareddisc.StandardPorts().Len(), 0}, "93.184.217.0/29": {65535, 0}}
	for input, w := range want {
		if got[input] != w {
			t.Errorf("target row %s = %v (ports, protocols), want %v", input, got[input], w)
		}
	}

	// GET returns the stored plan.
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/jobs/"+job.ID, nil))
	var read jobWithPlan
	_ = json.Unmarshal(w.Body.Bytes(), &read)
	if w.Code != http.StatusOK || read.Plan == nil || len(read.Plan.Targets) != 3 || read.Plan.Targets[1].Depth != shareddisc.DepthStandard || read.Plan.Targets[2].SegmentID != segmentID {
		t.Fatalf("GET = %d plan %+v", w.Code, read.Plan)
	}
	if mode, _ := f.storedMode(t, job.ID); mode != "async" {
		t.Errorf("run_from platform stored as %q, want async", mode)
	}
}

// H19: one probe over the budget is refused with the numbers; at the budget
// is accepted; the variable is read on the request and fails closed.
func TestIntegration_ScanPlan_Budget(t *testing.T) {
	f := newPlanFixture(t)
	body := map[string]interface{}{"targets": []string{"10.21.0.0/28"}, "scan_depth": "custom", "tcp_ports": "1-100", "run_from": "platform"}
	jobs := func() int {
		var n int
		_ = f.db.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id = $1`, f.tenant).Scan(&n)
		return n
	}

	t.Setenv(shareddisc.EnvMaxJobProbes, "1599")
	before := jobs()
	w := f.post(t, body)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("one over the budget = %d (%s), want 422", w.Code, w.Body)
	}
	var refused struct {
		Error           string `json:"error"`
		Message         string `json:"message"`
		EstimatedProbes uint64 `json:"estimated_probes"`
		ProbeLimit      uint64 `json:"probe_limit"`
		LargestTarget   struct {
			Target          string `json:"target"`
			Addresses       uint64 `json:"addresses"`
			TCPPortCount    int    `json:"tcp_port_count"`
			EstimatedProbes uint64 `json:"estimated_probes"`
		} `json:"largest_target"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &refused)
	if refused.Error != shareddisc.CodeScanBudgetExceeded || refused.EstimatedProbes != 1600 || refused.ProbeLimit != 1599 ||
		refused.LargestTarget.Target != "10.21.0.0/28" || refused.LargestTarget.Addresses != 16 || refused.LargestTarget.TCPPortCount != 100 ||
		!strings.Contains(refused.Message, "1,600") || !strings.Contains(refused.Message, "split the targets") {
		t.Fatalf("refusal = %+v", refused)
	}
	if jobs() != before {
		t.Fatal("a refused job was written")
	}

	t.Setenv(shareddisc.EnvMaxJobProbes, "1600")
	if w := f.post(t, body); w.Code != http.StatusAccepted {
		t.Fatalf("exactly at the budget = %d (%s), want 202", w.Code, w.Body)
	}

	// Unparsable: the default, not "unlimited" and not "nothing".
	t.Setenv(shareddisc.EnvMaxJobProbes, "lots")
	if job := f.created(t, body); job.Plan.ProbeLimit != shareddisc.DefaultMaxJobProbes {
		t.Fatalf("probe_limit = %d, want the default", job.Plan.ProbeLimit)
	}
	// And the default refuses the next step up from what it is sized for.
	t.Setenv(shareddisc.EnvMaxJobProbes, "")
	if w := f.post(t, map[string]interface{}{"targets": []string{"10.22.0.0/23"}, "scan_depth": "thorough", "run_from": "platform"}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("thorough /23 under the default budget = %d (%s), want 422", w.Code, w.Body)
	}
}

// D7/H11: Auto picks the one online tenant sensor whose networks contain every
// target, and the platform otherwise — always saying why.
func TestIntegration_ScanPlan_AutoRouting(t *testing.T) {
	t.Setenv(shareddisc.EnvMaxJobProbes, "")
	f := newPlanFixture(t)
	sensor := func(name string, online bool, network string, caps ...string) string {
		beat := time.Now().Add(-20 * time.Second)
		if !online {
			beat = time.Now().Add(-3 * time.Hour)
		}
		if caps == nil {
			// Software that runs planned scans ( WP2b).
			caps = []string{sensordispatch.ScanPlanCapability}
		}
		id := uuid.New()
		if _, err := f.db.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, tags, ip_address, reporting_interval, last_heartbeat, reported_capabilities)
			VALUES ($1, $2, $3, 'linux', '1.0.0', 'datacenter_host', 'active', '{}', $4, 30, $5, $6)`, id, f.tenant, name, strings.TrimSuffix(network, ".0/24")+".2", beat, pq.Array(caps)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.Exec(`INSERT INTO agent_addresses (sensor_id, interface_name, address, prefix_length, is_primary) VALUES ($1, 'eth0', $2, 24, true)`,
			id, strings.TrimSuffix(network, ".0/24")+".2"); err != nil {
			t.Fatal(err)
		}
		return id.String()
	}
	edgeA := sensor("edge-a", true, "10.50.0.0/24")
	sensor("edge-b", true, "10.60.0.0/24")
	sensor("edge-c", false, "10.70.0.0/24")

	for _, tc := range []struct {
		name    string
		targets []string
		sensor  string
		reason  string
	}{
		{"one sensor serves every target", []string{"10.50.0.0/25", "10.50.0.200"}, edgeA, "sensor edge-a is online"},
		{"targets on two sensors' networks", []string{"10.50.0.10", "10.60.0.10"}, "", "different sensors"},
		{"the serving sensor is offline", []string{"10.70.0.10"}, "", "edge-c serves every target but is offline"},
		{"no sensor serves the target", []string{"10.99.0.10"}, "", `"10.99.0.10"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := f.created(t, map[string]interface{}{"targets": tc.targets, "scan_depth": "quick"})
			p := job.Plan
			if p.RunFromRequested != shareddisc.RunFromAuto || !strings.Contains(p.ExecutorReason, tc.reason) {
				t.Fatalf("plan run_from=%s reason=%q, want auto and %q", p.RunFromRequested, p.ExecutorReason, tc.reason)
			}
			mode, ids := f.storedMode(t, job.ID)
			if tc.sensor != "" {
				if p.ExecutorResolved != shareddisc.ExecutorSensor || p.SensorID != tc.sensor || mode != "sensors" || len(ids) != 1 || ids[0] != tc.sensor {
					t.Fatalf("plan %+v stored %s %v, want sensor %s", p, mode, ids, tc.sensor)
				}
				return
			}
			if p.ExecutorResolved != shareddisc.ExecutorPlatform || p.SensorID != "" || mode != "async" || len(ids) != 0 {
				t.Fatalf("plan %+v stored %s %v, want the platform", p, mode, ids)
			}
		})
	}

	// run_from sensor keeps the existing refusal vocabulary.
	if w := f.post(t, map[string]interface{}{"targets": []string{"10.50.0.10"}, "scan_depth": "quick", "run_from": "sensor", "sensor_id": uuid.NewString()}); w.Code != http.StatusNotFound {
		t.Errorf("unknown sensor = %d (%s), want 404", w.Code, w.Body)
	}
	job := f.created(t, map[string]interface{}{"targets": []string{"10.99.0.10"}, "scan_depth": "quick", "run_from": "sensor", "sensor_id": edgeA})
	if job.Plan.ExecutorResolved != shareddisc.ExecutorSensor || job.Plan.SensorName != "edge-a" || !strings.Contains(job.Plan.ExecutorReason, "requested") {
		t.Errorf("run_from sensor plan = %+v", job.Plan)
	}
}

// WP2b: a sensor whose software does not report scan_plan_v1 is never
// handed a scan-plan job. Auto passes it over (and says why); naming it is a
// coded 409 that says what to do — through the real router, the dry run
// included — and writes nothing; and the same sensor still runs a protocols ×
// ports job, as every deployed sensor does.
func TestIntegration_ScanPlan_SensorWithoutTheScanPlanCapability(t *testing.T) {
	t.Setenv(shareddisc.EnvMaxJobProbes, "")
	f := newPlanFixture(t)
	edgeOld := uuid.NewString()
	if _, err := f.db.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, tags, ip_address, reporting_interval, last_heartbeat, reported_capabilities)
		VALUES ($1, $2, 'edge-old', 'linux', '1.0.0', 'datacenter_host', 'active', '{}', '10.80.0.2', 30, $3, $4)`,
		edgeOld, f.tenant, time.Now().Add(-20*time.Second), pq.Array([]string{sensordispatch.IdentityDNSCapability})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO agent_addresses (sensor_id, interface_name, address, prefix_length, is_primary) VALUES ($1, 'eth0', '10.80.0.2', 24, true)`, edgeOld); err != nil {
		t.Fatal(err)
	}

	job := f.created(t, map[string]interface{}{"targets": []string{"10.80.0.10"}, "scan_depth": "quick"})
	if p := job.Plan; p.ExecutorResolved != shareddisc.ExecutorPlatform || p.SensorID != "" ||
		!strings.Contains(p.ExecutorReason, "edge-old serves every target but its software does not support scan depth") {
		t.Fatalf("Auto plan = %+v, want the platform with the reason", p)
	}
	if mode, ids := f.storedMode(t, job.ID); mode != "async" || len(ids) != 0 {
		t.Fatalf("Auto stored %s %v, want the platform", mode, ids)
	}

	var jobsBefore int
	if err := f.db.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id = $1`, f.tenant).Scan(&jobsBefore); err != nil {
		t.Fatal(err)
	}
	for _, body := range []map[string]interface{}{
		{"targets": []string{"10.80.0.10"}, "scan_depth": "quick", "run_from": "sensor", "sensor_id": edgeOld},
		{"targets": []string{"10.80.0.10"}, "scan_depth": "quick", "run_from": "sensor", "sensor_id": edgeOld, "dry_run": true},
		{"targets": []string{"10.80.0.10"}, "scan_depth": "quick", "execution_mode": "sensors", "preferred_sensor_ids": []string{edgeOld}},
	} {
		w := f.post(t, body)
		var got struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		if w.Code != http.StatusConflict || got.Error != sensordispatch.CodeScanPlanUnsupported ||
			!strings.Contains(got.Message, "edge-old") || !strings.Contains(got.Message, "upgrade it, or run the scan from the platform") {
			t.Errorf("%v = %d %s, want 409 %s naming the sensor and what to do", body, w.Code, w.Body, sensordispatch.CodeScanPlanUnsupported)
		}
	}
	var jobsAfter int
	if err := f.db.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id = $1`, f.tenant).Scan(&jobsAfter); err != nil {
		t.Fatal(err)
	}
	if jobsAfter != jobsBefore {
		t.Fatalf("a refused request wrote %d job row(s)", jobsAfter-jobsBefore)
	}
	// The same sensor still runs a protocols × ports job, as every deployed
	// sensor does.
	if w := f.post(t, map[string]interface{}{"targets": []string{"10.80.0.10"}, "protocols": []string{"TLS"}, "ports": []int{443}, "execution_mode": "sensors", "preferred_sensor_ids": []string{edgeOld}}); w.Code != http.StatusAccepted {
		t.Errorf("legacy job on the same sensor = %d (%s), want 202", w.Code, w.Body)
	}
}

// Request-shape refusals are named, not "failed to create job".
func TestIntegration_ScanPlan_RequestRefusalsAreNamed(t *testing.T) {
	f := newPlanFixture(t)
	for body, want := range map[string]string{
		`{"targets":["10.1.1.1"],"scan_depth":"thorough","protocols":["TLS"],"ports":[443]}`: "cannot be combined with protocols/ports",
		`{"targets":["10.1.1.1"],"scan_depth":"custom","tcp_ports":"22,ssh"}`:                `port spec entry \"ssh\"`,
		`{"targets":["10.1.1.1"],"scan_depth":"custom"}`:                                     "needs tcp_ports, udp_ports or both",
	} {
		w := httptest.NewRecorder()
		f.r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/jobs", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "validation_error") || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s = %d %s, want 400 naming %q", body, w.Code, w.Body, want)
		}
	}
}
