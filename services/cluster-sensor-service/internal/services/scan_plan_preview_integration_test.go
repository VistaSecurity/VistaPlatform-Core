package services_test

// POST /discovery/jobs with dry_run ( WP3b) through the REAL handler and
// service against a real Postgres.
//
// What must hold, and what each test is the guard for:
//
//   - PARITY: the plan a dry run returns is the plan a real create returns,
//     and every refusal a real create gives a dry run gives with the same
//     status and body. They are one code path (DiscoveryService.createJob), so
//     these tests go red the moment a dry run builds its own plan or maps its
//     own errors.
//   - NOTHING WRITTEN: a dry run changes no row in any table that has a
//     tenant_id, announces nothing, and writes no audit event for a job.
//   - EXTERNAL CONFIRMATION is reported, not refused.
//   - The legacy request shape previews the plan it is translated into.
//
// Skips unless TEST_DATABASE_URL is set (make test-integration-db).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// previewAudit is audit-service as far as the middleware can tell.
type previewAudit struct {
	mu      sync.Mutex
	entries []map[string]interface{}
}

func (a *previewAudit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var entry map[string]interface{}
	if json.Unmarshal(body, &entry) == nil {
		a.mu.Lock()
		a.entries = append(a.entries, entry)
		a.mu.Unlock()
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"id":"` + uuid.NewString() + `"}`))
}

func (a *previewAudit) count(eventType string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if e["event_type"] == eventType {
			n++
		}
	}
	return n
}

// waitForCount waits out the middleware's asynchronous flush until at least
// want events of eventType have arrived.
func (a *previewAudit) waitForCount(eventType string, want int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if a.count(eventType) >= want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

type previewFixture struct {
	db     *sqlx.DB
	tenant uuid.UUID
	r      *gin.Engine
	audit  *previewAudit

	mu        sync.Mutex
	announced []string // job ids the handler announced to the executor
}

func (f *previewFixture) announcedJobs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.announced...)
}

// newPreviewFixture builds the real handler and service for a fresh tenant
// with room for many jobs (the default allowance is 5 concurrent jobs, which
// the parity tables would exhaust), the audit middleware wired as main.go
// wires it, and a recording stand-in for the NATS publish.
func newPreviewFixture(t *testing.T) *previewFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("AUDIT_USE_NATS", "")
	t.Setenv(shareddisc.EnvMaxJobProbes, "")
	sqlDB := testdb.Connect(t)
	db := sqlx.NewDb(sqlDB, "postgres")
	tenant := testdb.NewTenant(t, db.DB)
	user := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, user, tenant, user.String()+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	f := &previewFixture{db: db, tenant: tenant, audit: &previewAudit{}}
	auditSrv := httptest.NewServer(f.audit)
	t.Cleanup(auditSrv.Close)
	cfg := auditmiddleware.DefaultConfig()
	cfg.ServiceName = "cluster-sensor-service"
	cfg.AuditServiceURL = auditSrv.URL
	cfg.BatchSize = 1
	cfg.FlushInterval = 50 * time.Millisecond
	audit := auditmiddleware.NewMiddleware(cfg)

	h := handlers.NewDiscoveryHandler(services.NewDiscoveryService(db, db), services.NewRateLimiter(db), nil, nil).
		WithSubmitPublisher(func(_ string, job *models.DiscoveryJob) {
			f.mu.Lock()
			f.announced = append(f.announced, job.ID)
			f.mu.Unlock()
		})
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("audit_middleware", audit)
		c.Set(sharedmw.CtxKeyTenantID, tenant)
		c.Set("userID", user.String())
		c.Next()
	})
	r.POST("/jobs", h.CreateJob)
	f.r = r
	f.setAllowance(t, 1000)
	return f
}

func (f *previewFixture) setAllowance(t *testing.T, concurrent int) {
	t.Helper()
	if _, err := f.db.Exec(`INSERT INTO discovery_rate_limits (tenant_id, scans_per_hour, concurrent_jobs, max_targets_per_job, is_active)
		VALUES ($1, 1000, $2, 1000, true)
		ON CONFLICT (tenant_id) DO UPDATE SET concurrent_jobs = EXCLUDED.concurrent_jobs`, f.tenant, concurrent); err != nil {
		t.Fatal(err)
	}
}

func (f *previewFixture) post(t *testing.T, body map[string]interface{}) (int, map[string]interface{}, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewReader(raw)))
	var parsed map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &parsed)
	return w.Code, parsed, w.Body.Bytes()
}

// dryRun posts body with dry_run and decodes a 200's preview.
func (f *previewFixture) dryRun(t *testing.T, body map[string]interface{}) (int, shareddisc.ScanPreview, []byte) {
	t.Helper()
	withFlag := map[string]interface{}{"dry_run": true}
	for k, v := range body {
		withFlag[k] = v
	}
	code, _, raw := f.post(t, withFlag)
	var preview shareddisc.ScanPreview
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &preview); err != nil {
			t.Fatalf("dry run body is not a preview: %v: %s", err, raw)
		}
	}
	return code, preview, raw
}

func (f *previewFixture) sensor(t *testing.T, name string, online bool, network string) string {
	t.Helper()
	beat := time.Now().Add(-20 * time.Second)
	if !online {
		beat = time.Now().Add(-3 * time.Hour)
	}
	id := uuid.New()
	ip := strings.TrimSuffix(network, ".0/24") + ".2"
	// Software that runs planned scans ( WP2b): only such a sensor is
	// ever handed a scan-plan job.
	if _, err := f.db.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, tags, ip_address, reporting_interval, last_heartbeat, reported_capabilities)
		VALUES ($1, $2, $3, 'linux', '1.0.0', 'datacenter_host', 'active', '{}', $4, 30, $5, $6)`, id, f.tenant, name, ip, beat, pq.Array([]string{sensordispatch.ScanPlanCapability})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO agent_addresses (sensor_id, interface_name, address, prefix_length, is_primary) VALUES ($1, 'eth0', $2, 24, true)`, id, ip); err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func (f *previewFixture) registerPublicSegment(t *testing.T, cidr string) string {
	t.Helper()
	var id string
	if err := f.db.QueryRow(`INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, is_active)
		VALUES ($1, 'dmz', 'cidr', $2, 'public', 'production', true) RETURNING id`, f.tenant, cidr).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// footprint is every row this tenant owns, in every table that has a
// tenant_id column, plus the sensor commands (keyed by sensor). It is the
// definition of "a dry run wrote nothing" — derived from the schema, not from
// the tables CreateJob happens to insert into today, so a write added to the
// path later is caught too.
func (f *previewFixture) footprint(t *testing.T) map[string]int {
	t.Helper()
	rows, err := f.db.Query(`SELECT c.table_name FROM information_schema.columns c
		JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
		WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id' ORDER BY c.table_name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	_ = rows.Close()
	out := map[string]int{}
	for _, name := range tables {
		var n int
		if err := f.db.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %q WHERE tenant_id::text = $1`, name), f.tenant.String()).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", name, err)
		}
		out[name] = n
	}
	var commands int
	if err := f.db.QueryRow(`SELECT count(*) FROM sensor_commands c JOIN sensors s ON s.id = c.sensor_id WHERE s.tenant_id = $1`, f.tenant).Scan(&commands); err != nil {
		t.Fatal(err)
	}
	out["sensor_commands"] = commands
	if _, ok := out["discovery_jobs"]; !ok {
		t.Fatalf("footprint does not cover discovery_jobs: %v", out)
	}
	return out
}

func diffFootprint(before, after map[string]int) []string {
	var changed []string
	for table, n := range after {
		if before[table] != n {
			changed = append(changed, fmt.Sprintf("%s %d→%d", table, before[table], n))
		}
	}
	sort.Strings(changed)
	return changed
}

// previewCase is one request, with the state it needs.
type previewCase struct {
	name  string
	setup func(t *testing.T, f *previewFixture) map[string]interface{}
}

func targetsBody(depth string, extra map[string]interface{}, targets ...string) map[string]interface{} {
	body := map[string]interface{}{"targets": targets}
	if depth != "" {
		body["scan_depth"] = depth
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// PARITY, success: the plan of the dry run is the plan the real create
// stores, for every depth, pace, mix of targets and run_from.
func TestIntegration_DryRun_PlanEqualsTheRealCreatesPlan(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newPreviewFixture(t)
	edgeA := f.sensor(t, "edge-a", true, "10.50.0.0/24")
	f.sensor(t, "edge-c", false, "10.70.0.0/24")
	f.registerPublicSegment(t, "93.184.217.0/28")

	for _, tc := range []previewCase{
		{"quick, one host, auto", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("quick", nil, "10.20.30.40")
		}},
		{"default depth (standard), platform", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("", map[string]interface{}{"run_from": "platform"}, "10.20.31.0/28")
		}},
		{"thorough /24, polite", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("thorough", map[string]interface{}{"pace": "polite", "run_from": "platform"}, "10.20.32.0/24")
		}},
		{"custom ports, fast", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("custom", map[string]interface{}{"tcp_ports": "22,8000-8100", "udp_ports": "53,500", "pace": "fast"}, "10.20.33.0/29")
		}},
		{"custom UDP only", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("custom", map[string]interface{}{"udp_ports": "500"}, "10.20.34.0/29")
		}},
		{"URL target adds its explicit port", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("quick", nil, "https://10.20.35.5:8443/x")
		}},
		{"mixed internal, registered and external, confirmed, thorough", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("thorough", map[string]interface{}{"run_from": "platform", "external_targets_confirmed": true},
				"10.20.36.0/28", "93.184.216.34", "93.184.217.0/29")
		}},
		{"custom with too many TCP ports on an external target", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("custom", map[string]interface{}{"tcp_ports": "1-3000", "udp_ports": "53,500", "external_targets_confirmed": true, "run_from": "platform"},
				"93.184.216.35")
		}},
		{"auto picks the covering sensor", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("standard", nil, "10.50.0.0/25")
		}},
		{"auto with an offline serving sensor falls back to the platform", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("quick", nil, "10.70.0.10")
		}},
		{"auto with an external target stays on the platform", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("quick", map[string]interface{}{"external_targets_confirmed": true}, "10.50.0.10", "93.184.216.36")
		}},
		{"run_from sensor", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("quick", map[string]interface{}{"run_from": "sensor", "sensor_id": edgeA}, "10.99.0.10")
		}},
		{"legacy execution_mode alias", func(*testing.T, *previewFixture) map[string]interface{} {
			return targetsBody("quick", map[string]interface{}{"execution_mode": "cloud"}, "10.20.37.1")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.setup(t, f)
			code, preview, raw := f.dryRun(t, body)
			if code != http.StatusOK {
				t.Fatalf("dry run = %d %s, want 200", code, raw)
			}
			realCode, parsed, realRaw := f.post(t, body)
			if realCode != http.StatusAccepted {
				t.Fatalf("real create = %d %s, want 202", realCode, realRaw)
			}
			var created struct {
				Job struct {
					Plan *shareddisc.ScanPlan `json:"plan"`
				} `json:"job"`
			}
			if err := json.Unmarshal(realRaw, &created); err != nil || created.Job.Plan == nil {
				t.Fatalf("real create has no plan: %v %s", err, realRaw)
			}
			_ = parsed
			if !reflect.DeepEqual(&preview.Plan, created.Job.Plan) {
				dry, _ := json.MarshalIndent(preview.Plan, "", " ")
				real, _ := json.MarshalIndent(created.Job.Plan, "", " ")
				t.Fatalf("the dry run's plan differs from the real create's\n--- dry run\n%s\n--- real\n%s", dry, real)
			}
			// The estimate is the plan's, by the one function.
			want, err := shareddisc.EstimateScan(preview.Plan)
			if err != nil || !reflect.DeepEqual(want, preview.Estimate) {
				t.Fatalf("estimate = %+v, want %+v (%v)", preview.Estimate, want, err)
			}
			if preview.Estimate.Probes != preview.Plan.EstimatedProbes {
				t.Fatalf("estimate.probes %d != plan.estimated_probes %d", preview.Estimate.Probes, preview.Plan.EstimatedProbes)
			}
		})
	}
}

// PARITY, refusal: every refusal a real create gives, a dry run gives with the
// same status and the same body — validation, the operator switch, reserved
// targets, an oversize job, the budget, an unknown or offline sensor.
func TestIntegration_DryRun_RefusalsEqualTheRealCreates(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newPreviewFixture(t)
	f.sensor(t, "edge-c", false, "10.70.0.0/24")
	offline := f.sensor(t, "edge-d", false, "10.71.0.0/24")

	for _, tc := range []struct {
		name       string
		body       map[string]interface{}
		env        map[string]string
		wantStatus int
		wantCode   string // the body's "error"
	}{
		{"bad depth", targetsBody("deep", nil, "10.1.1.1"), nil, 400, "validation_error"},
		{"custom without ports", targetsBody("custom", nil, "10.1.1.1"), nil, 400, "validation_error"},
		{"bad port token", targetsBody("custom", map[string]interface{}{"tcp_ports": "22,https"}, "10.1.1.1"), nil, 400, "validation_error"},
		{"bad pace", targetsBody("quick", map[string]interface{}{"pace": "warp"}, "10.1.1.1"), nil, 400, "validation_error"},
		{"depth with protocols", targetsBody("quick", map[string]interface{}{"protocols": []string{"TLS"}, "ports": []int{443}}, "10.1.1.1"), nil, 400, "validation_error"},
		{"loopback is refused", targetsBody("quick", nil, "127.0.0.1"), nil, 400, dispatchguard.CodeTargetsRefused},
		{"cloud metadata is refused even confirmed", targetsBody("quick", map[string]interface{}{"external_targets_confirmed": true}, "169.254.169.254"), nil, 400, dispatchguard.CodeTargetsRefused},
		{"external switched off by the operator", targetsBody("quick", map[string]interface{}{"external_targets_confirmed": true}, "93.184.216.34"),
			map[string]string{dispatchguard.EnvExternalTargetsEnabled: "false"}, 403, dispatchguard.CodeExternalTargetsDisabled},
		{"oversize target", targetsBody("quick", nil, "10.0.0.0/19"), nil, 422, shareddisc.CodeScanTargetTooLarge},
		{"oversize job", targetsBody("quick", nil, "10.0.0.0/20", "10.1.0.0/20", "10.2.0.0/20", "10.3.0.0/20", "10.4.0.0/20"), nil, 422, shareddisc.CodeScanTargetTooLarge},
		{"over the probe budget", targetsBody("thorough", map[string]interface{}{"run_from": "platform"}, "10.22.0.0/23"), nil, 422, shareddisc.CodeScanBudgetExceeded},
		{"unknown sensor", targetsBody("quick", map[string]interface{}{"run_from": "sensor", "sensor_id": uuid.NewString()}, "10.1.1.1"), nil, 404, ""},
		{"offline sensor", targetsBody("quick", map[string]interface{}{"run_from": "sensor", "sensor_id": offline}, "10.71.0.5"), nil, 409, ""},
		{"offline sensor, external target", targetsBody("quick", map[string]interface{}{"run_from": "sensor", "sensor_id": offline, "external_targets_confirmed": true}, "93.184.216.34"), nil, 409, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			dryCode, _, dryRaw := f.post(t, withDryRun(tc.body))
			realCode, _, realRaw := f.post(t, tc.body)
			if realCode != tc.wantStatus {
				t.Fatalf("real create = %d %s, want %d (the case no longer tests what it names)", realCode, realRaw, tc.wantStatus)
			}
			if tc.wantCode != "" && !strings.Contains(string(realRaw), tc.wantCode) {
				t.Fatalf("real create body %s lacks code %q", realRaw, tc.wantCode)
			}
			if dryCode != realCode {
				t.Fatalf("dry run = %d %s, real create = %d %s: a dry run must refuse with the real create's status", dryCode, dryRaw, realCode, realRaw)
			}
			var a, b map[string]interface{}
			_ = json.Unmarshal(dryRaw, &a)
			_ = json.Unmarshal(realRaw, &b)
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("dry run body %s differs from the real create's %s", dryRaw, realRaw)
			}
		})
	}
}

func withDryRun(body map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{"dry_run": true}
	for k, v := range body {
		out[k] = v
	}
	return out
}

// NOTHING WRITTEN: after dry runs of every kind — accepted, refused, external
// unconfirmed — no tenant table has gained or lost a row, nothing was
// announced to the executor, and no audit event for a job was written. The
// same requests, really created, change the footprint and announce the job
// (the other polarity: the counters do move).
func TestIntegration_DryRun_WritesNothing(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newPreviewFixture(t)
	f.sensor(t, "edge-a", true, "10.50.0.0/24")
	// A tenant with no stored allowance: even the lazily created default row
	// must not appear.
	if _, err := f.db.Exec(`DELETE FROM discovery_rate_limits WHERE tenant_id = $1`, f.tenant); err != nil {
		t.Fatal(err)
	}

	requests := []map[string]interface{}{
		targetsBody("thorough", map[string]interface{}{"run_from": "platform"}, "10.20.30.0/24"),
		targetsBody("quick", nil, "10.50.0.10"),                                                                                  // Auto → sensor
		targetsBody("standard", map[string]interface{}{"external_targets_confirmed": true}, "93.184.216.34"),                     // confirmed external
		targetsBody("standard", nil, "93.184.216.34"),                                                                            // unconfirmed external
		targetsBody("thorough", map[string]interface{}{"run_from": "platform"}, "10.22.0.0/23"),                                  // over budget
		targetsBody("quick", nil, "127.0.0.1"),                                                                                   // refused
		targetsBody("custom", map[string]interface{}{"tcp_ports": "22", "ot_probe_protocols": []string{"Modbus"}}, "10.20.31.1"), // OT opt-in rides along
	}

	before := f.footprint(t)
	for _, body := range requests {
		f.post(t, withDryRun(body))
	}
	if changed := diffFootprint(before, f.footprint(t)); len(changed) > 0 {
		t.Fatalf("dry runs changed the tenant's rows: %v", changed)
	}
	if n := len(f.announcedJobs()); n != 0 {
		t.Fatalf("dry runs announced %d job(s) to the executor", n)
	}
	// Let any (wrongly) written audit event flush: the real create below waits
	// for ITS event, and flushes are ordered, so an earlier stray one would be
	// counted by then.
	var realJob string
	{
		code, _, raw := f.post(t, targetsBody("standard", map[string]interface{}{"external_targets_confirmed": true, "run_from": "platform"}, "93.184.216.34"))
		if code != http.StatusAccepted {
			t.Fatalf("real create = %d %s", code, raw)
		}
		var resp struct {
			Job struct {
				ID string `json:"id"`
			} `json:"job"`
		}
		_ = json.Unmarshal(raw, &resp)
		realJob = resp.Job.ID
	}
	if !f.audit.waitForCount(handlers.AuditEventExternalTargets, 1, 5*time.Second) {
		t.Fatal("a real confirmed external create wrote no audit event: the audit wiring this test relies on is not live")
	}
	time.Sleep(300 * time.Millisecond)
	if n := f.audit.count(handlers.AuditEventExternalTargets); n != 1 {
		t.Fatalf("%d external-target audit events, want exactly the real create's: a dry run wrote one", n)
	}

	// The other polarity: the real create moved the counters and announced.
	changed := diffFootprint(before, f.footprint(t))
	if len(changed) == 0 || !strings.Contains(strings.Join(changed, ","), "discovery_jobs 0→1") || !strings.Contains(strings.Join(changed, ","), "discovery_targets") {
		t.Fatalf("a real create left the footprint as %v: the footprint cannot see a write", changed)
	}
	if got := f.announcedJobs(); len(got) != 1 || got[0] != realJob {
		t.Fatalf("announced = %v, want the real job %s only", got, realJob)
	}
}

// EXTERNAL CONFIRMATION: a real create answers 422 and lists them; a dry run
// answers 200, says confirmation is required, lists them, and shows the
// downgrade that applies once confirmed. Confirmed, it still lists them and
// no longer requires anything. Reserved or switched-off remains a refusal.
func TestIntegration_DryRun_ExternalTargetsAreReportedNotRefused(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newPreviewFixture(t)
	edge := f.sensor(t, "edge-a", true, "10.50.0.0/24")
	mixed := targetsBody("thorough", map[string]interface{}{"run_from": "platform"}, "10.20.30.0/28", "93.184.216.34")

	// The real create refuses until confirmed.
	code, body, raw := f.post(t, mixed)
	if code != http.StatusUnprocessableEntity || body["error"] != dispatchguard.CodeExternalTargetsUnconfirmed {
		t.Fatalf("real create unconfirmed = %d %s, want 422 external_targets_unconfirmed", code, raw)
	}

	// The dry run does not.
	dryCode, preview, dryRaw := f.dryRun(t, mixed)
	if dryCode != http.StatusOK {
		t.Fatalf("dry run unconfirmed = %d %s, want 200", dryCode, dryRaw)
	}
	if !preview.ConfirmationRequired || len(preview.ExternalTargets) != 1 || preview.ExternalTargets[0].Target != "93.184.216.34" ||
		!reflect.DeepEqual(preview.ExternalTargets[0].Addresses, []string{"93.184.216.34"}) {
		t.Fatalf("preview = %+v, want confirmation required for 93.184.216.34", preview)
	}
	if len(preview.Plan.DepthAdjustments) != 1 || preview.Plan.DepthAdjustments[0].Target != "93.184.216.34" ||
		preview.Plan.DepthAdjustments[0].Applied != shareddisc.DepthStandard {
		t.Fatalf("the downgrade that applies once confirmed is not shown: %+v", preview.Plan.DepthAdjustments)
	}

	// Confirmed: same plan, nothing left to confirm, the list still there.
	confirmed := withKey(mixed, "external_targets_confirmed", true)
	cCode, cPreview, cRaw := f.dryRun(t, confirmed)
	if cCode != http.StatusOK || cPreview.ConfirmationRequired || len(cPreview.ExternalTargets) != 1 {
		t.Fatalf("confirmed dry run = %d %s, want 200, no confirmation required, the target still listed", cCode, cRaw)
	}
	if !reflect.DeepEqual(cPreview.Plan, preview.Plan) {
		t.Fatal("confirming changed the plan: the unconfirmed preview did not show what confirming does")
	}

	// Nothing external: no confirmation, an empty list (an array, not null).
	_, none, noneRaw := f.dryRun(t, targetsBody("quick", nil, "10.20.30.0/28"))
	if none.ConfirmationRequired || none.ExternalTargets == nil || len(none.ExternalTargets) != 0 || !strings.Contains(string(noneRaw), `"external_targets":[]`) {
		t.Fatalf("a private-only preview = %s", noneRaw)
	}

	// Judged as confirmed does not mean admitted: a tenant sensor cannot scan
	// outside the registered networks, so the preview says so now rather than
	// after the person confirms.
	sCode, _, sRaw := f.post(t, withDryRun(targetsBody("quick", map[string]interface{}{"run_from": "sensor", "sensor_id": edge}, "93.184.216.34")))
	if sCode != http.StatusBadRequest || !strings.Contains(string(sRaw), dispatchguard.CodeTargetsRefused) {
		t.Fatalf("external via a tenant sensor = %d %s, want 400 targets_refused", sCode, sRaw)
	}
	// The operator switch is a refusal, with its own status and code.
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "false")
	oCode, oBody, oRaw := f.post(t, withDryRun(mixed))
	if oCode != http.StatusForbidden || oBody["error"] != dispatchguard.CodeExternalTargetsDisabled {
		t.Fatalf("switched off = %d %s, want 403 external_targets_disabled", oCode, oRaw)
	}
}

func withKey(body map[string]interface{}, key string, value interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range body {
		out[k] = v
	}
	out[key] = value
	return out
}

// The legacy shape is translated into a plan ( D2) with no switch left to
// stop it (WP5), so its dry run previews that plan — the plan a real create
// of the same request stores — and writes nothing.
func TestIntegration_DryRun_LegacyShapePreviewsItsTranslatedPlan(t *testing.T) {
	f := newPreviewFixture(t)
	before := f.footprint(t)
	body := map[string]interface{}{"targets": []string{"10.51.0.10"}, "protocols": []string{"TLS"}, "ports": []int{443, 22}}
	code, preview, raw := f.dryRun(t, body)
	if code != http.StatusOK {
		t.Fatalf("legacy dry run = %d %s, want 200 with the translated plan", code, raw)
	}
	if preview.Plan.Depth != shareddisc.DepthCustom || preview.Plan.TCPPorts != "22,443" || preview.Plan.ExecutorResolved != shareddisc.ExecutorPlatform {
		t.Fatalf("legacy dry run plan = %+v, want custom on 22,443 from the platform", preview.Plan)
	}
	if changed := diffFootprint(before, f.footprint(t)); len(changed) > 0 {
		t.Fatalf("a dry run changed the tenant's rows: %v", changed)
	}
}

// ALLOWANCE: a dry run is refused where a real create would be (a preview that
// says yes to a request Start answers 429 is no preview) but consumes none of
// it — any number of dry runs leave the tenant able to create its full quota.
func TestIntegration_DryRun_ConsumesNoAllowance(t *testing.T) {
	f := newPreviewFixture(t)
	f.setAllowance(t, 2)
	body := targetsBody("quick", map[string]interface{}{"run_from": "platform"}, "10.52.0.10")
	for range 6 {
		if code, _, raw := f.post(t, withDryRun(body)); code != http.StatusOK {
			t.Fatalf("dry run = %d %s, want 200", code, raw)
		}
	}
	for i := range 2 {
		if code, _, raw := f.post(t, body); code != http.StatusAccepted {
			t.Fatalf("create %d after six dry runs = %d %s, want 202: dry runs consumed allowance", i+1, code, raw)
		}
	}
	if code, _, raw := f.post(t, withDryRun(body)); code != http.StatusTooManyRequests {
		t.Fatalf("dry run at the allowance = %d %s, want 429 like a real create", code, raw)
	}
	if code, _, raw := f.post(t, body); code != http.StatusTooManyRequests {
		t.Fatalf("create at the allowance = %d %s, want 429", code, raw)
	}
}

// The service refuses what must never be a dry run's side effect: a real
// create asked to dry-run (it would create the job the caller asked not to), and
// an identity-enrichment/automatic request, whose replay token a dry run would
// otherwise reserve.
func TestIntegration_DryRun_ServiceBoundaries(t *testing.T) {
	f := newPreviewFixture(t)
	svc := services.NewDiscoveryService(f.db, f.db)
	before := f.footprint(t)

	_, err := svc.CreateJob(f.tenant.String(), uuid.NewString(), models.CreateDiscoveryJobRequest{Targets: []string{"10.1.1.1"}, ScanDepth: "quick", DryRun: true})
	var refused *shareddisc.ScanRequestError
	if !errors.As(err, &refused) {
		t.Fatalf("CreateJob with dry_run = %v, want a refusal rather than a created job", err)
	}
	for _, opts := range []map[string]interface{}{
		{"identity_enrichment_request_id": uuid.NewString()},
		{"origin": "auto_scan"},
	} {
		_, err := svc.PreviewJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{Targets: []string{"10.1.1.1"}, ScanDepth: "quick", Options: opts})
		if !errors.As(err, &refused) {
			t.Fatalf("PreviewJob with options %v = %v, want a scan-plan refusal", opts, err)
		}
	}
	if changed := diffFootprint(before, f.footprint(t)); len(changed) > 0 {
		t.Fatalf("refused previews changed the tenant's rows: %v", changed)
	}
}
