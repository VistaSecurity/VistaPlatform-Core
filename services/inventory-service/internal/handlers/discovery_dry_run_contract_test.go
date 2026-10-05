package handlers

// POST /discovery/jobs with dry_run ( WP3b), through the proxy the browser
// calls. What must survive it: the flag on the way in, the preview (plan,
// estimate, confirmation) on the way out, every refusal with its status and
// code, no job-created audit entry for a request that created nothing — and a
// cluster-sensor-service that would have created a job anyway is not mistaken
// for a preview.

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// auditedProxy is newProxyEngine with the audit middleware on the context and
// a recording audit-service behind it, so a test can see whether a request
// wrote the job-created entry.
type auditedProxy struct {
	engine  *gin.Engine
	cluster *httptest.Server
	mu      sync.Mutex
	events  []string
}

func newAuditedProxy(t *testing.T, cluster http.HandlerFunc) *auditedProxy {
	t.Helper()
	t.Setenv("AUDIT_USE_NATS", "")
	a := &auditedProxy{}
	auditSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var entry map[string]interface{}
		if json.Unmarshal(body, &entry) == nil {
			a.mu.Lock()
			a.events = append(a.events, entry["event_type"].(string))
			a.mu.Unlock()
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + uuid.NewString() + `"}`))
	}))
	t.Cleanup(auditSrv.Close)
	cfg := auditmiddleware.DefaultConfig()
	cfg.ServiceName = "inventory-service"
	cfg.AuditServiceURL = auditSrv.URL
	cfg.BatchSize = 1
	cfg.FlushInterval = 50 * time.Millisecond
	mw := auditmiddleware.NewMiddleware(cfg)

	a.cluster = httptest.NewServer(cluster)
	t.Cleanup(a.cluster.Close)
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", a.cluster.URL)
	svc, err := services.NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatalf("NewDiscoveryService: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := NewDiscoveryHandler(nil, svc)
	a.engine = gin.New()
	a.engine.POST("/discovery/jobs", func(c *gin.Context) {
		c.Set("audit_middleware", mw)
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		h.CreateJob(c)
	})
	return a
}

func (a *auditedProxy) count(eventType string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.events {
		if e == eventType {
			n++
		}
	}
	return n
}

func (a *auditedProxy) waitFor(eventType string, want int) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if a.count(eventType) >= want {
			return true
		}
	}
	return false
}

// previewFromPlanner is a preview built by the same functions
// cluster-sensor-service uses.
func previewFromPlanner(t *testing.T) shareddisc.ScanPreview {
	t.Helper()
	shape, err := shareddisc.ResolveJobRequest(shareddisc.JobRequestFields{ScanDepth: "thorough", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := shareddisc.BuildScanPlan(shape.Spec, nil, []shareddisc.PlanTargetInput{
		{Target: "10.20.30.0/28", Class: shareddisc.ClassPrivate},
		{Target: "93.184.216.34", Class: shareddisc.ClassExternal},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.RunFromRequested, plan.ExecutorResolved, plan.ExecutorReason = "auto", "platform", "an external target keeps the job on the platform"
	if err := plan.CheckBudget(shareddisc.DefaultMaxJobProbes); err != nil {
		t.Fatal(err)
	}
	preview, err := shareddisc.NewScanPreview(plan, true, []shareddisc.PreviewExternalTarget{{Target: "93.184.216.34", Addresses: []string{"93.184.216.34"}}})
	if err != nil {
		t.Fatal(err)
	}
	return preview
}

const dryRunBody = `{"targets":["10.20.30.0/28","93.184.216.34"],"scan_depth":"thorough","pace":"polite","dry_run":true}`

func TestContract_DryRun_ForwardsTheFlagAndRelaysThePreview(t *testing.T) {
	sv := loadSpec(t)
	sv.assertConforms(t, "CreateDiscoveryJobRequest", []byte(dryRunBody))
	want := previewFromPlanner(t)
	wantJSON, _ := json.Marshal(want)

	var forwarded map[string]interface{}
	calls := 0
	var mu sync.Mutex
	realCreate := false
	a := newAuditedProxy(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if realCreate {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"job":{"id":"6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d","tenant_id":"t","status":"queued","execution_mode":"async","created_at":"2026-10-02T12:00:00Z","updated_at":"2026-10-02T12:00:00Z"}}`))
			return
		}
		calls++
		_ = json.NewDecoder(r.Body).Decode(&forwarded)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wantJSON)
	})
	w := postThrough(a.engine, dryRunBody)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body)
	}
	mu.Lock()
	if calls != 1 || forwarded["dry_run"] != true || forwarded["scan_depth"] != "thorough" || forwarded["pace"] != "polite" {
		t.Fatalf("forwarded %d time(s): %v — the flag and the plan fields must reach cluster-sensor-service", calls, forwarded)
	}
	mu.Unlock()
	sv.assertConforms(t, "DiscoveryJobPreview", w.Body.Bytes())
	var got shareddisc.ScanPreview
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the preview did not survive the proxy\n got  %s\n want %s", w.Body, wantJSON)
	}
	if !got.ConfirmationRequired || len(got.ExternalTargets) != 1 || got.Estimate.SecondsWorst < got.Estimate.SecondsBest || got.Estimate.Basis == "" {
		t.Fatalf("preview lost its confirmation or estimate: %+v", got)
	}

	// No job was created, so no "job created" audit entry: send a REAL create
	// through the same engine and wait for ITS entry; an earlier stray one
	// from the dry run would be counted by then (flushes are ordered).
	mu.Lock()
	realCreate = true
	mu.Unlock()
	if w := postThrough(a.engine, `{"targets":["10.20.30.1"],"scan_depth":"quick"}`); w.Code != http.StatusAccepted {
		t.Fatalf("real create = %d %s", w.Code, w.Body)
	}
	if !a.waitFor("discovery.job.created", 1) {
		t.Fatal("a real create wrote no job-created audit entry: the audit wiring this test relies on is not live")
	}
	time.Sleep(200 * time.Millisecond)
	if n := a.count("discovery.job.created"); n != 1 {
		t.Fatalf("%d job-created audit entries, want only the real create's: a dry run audited a job that does not exist", n)
	}
}

// A dry run's refusals are the real create's: same status, same code, same
// lists. The downstream verdicts below are cluster-sensor-service's own.
func TestContract_DryRun_RefusalsKeepTheirStatusAndCode(t *testing.T) {
	sv := loadSpec(t)
	for _, tc := range []struct {
		name   string
		status int
		body   string
		code   string
	}{
		{"budget", 422, `{"error":"scan_budget_exceeded","message":"this scan would send about 33,579,520 probes","estimated_probes":33579520,"probe_limit":25000000,"largest_target":{"target":"10.0.0.0/23","addresses":512,"tcp_port_count":65535,"udp_port_count":11,"estimated_probes":33559552}}`, "scan_budget_exceeded"},
		{"oversize", 422, `{"error":"scan_target_too_large","message":"too big","oversize_targets":[{"target":"10.0.0.0/19","addresses":"8192"}],"target_limit":4096}`, "scan_target_too_large"},
		{"switched off", 403, `{"error":"external_targets_disabled","message":"off","external_targets":[{"target":"93.184.216.34","addresses":["93.184.216.34"]}]}`, "external_targets_disabled"},
		{"refused", 400, `{"error":"targets_refused","message":"no","refused_targets":[{"target":"127.0.0.1","reason":"loopback addresses are the scanner itself"}]}`, "targets_refused"},
		{"plan unavailable", 422, `{"error":"scan_plan_unavailable","message":"use protocols and ports"}`, "scan_plan_unavailable"},
		{"unknown sensor", 404, `{"error":"sensor not found"}`, ""},
		{"offline sensor", 409, `{"error":"sensor offline"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}
			dry := postThrough(newAuditedProxy(t, cluster).engine, dryRunBody)
			real := postThrough(newAuditedProxy(t, cluster).engine, strings.Replace(dryRunBody, `,"dry_run":true`, "", 1))
			if dry.Code != tc.status || real.Code != tc.status {
				t.Fatalf("dry run %d / real %d, want %d for both; dry=%s", dry.Code, real.Code, tc.status, dry.Body)
			}
			if tc.code != "" {
				sv.assertConforms(t, "DiscoveryTargetVerdictError", dry.Body.Bytes())
				if !strings.Contains(dry.Body.String(), `"error":"`+tc.code+`"`) {
					t.Fatalf("dry run lost the code %s: %s", tc.code, dry.Body)
				}
			}
			if dry.Body.String() != real.Body.String() {
				t.Fatalf("dry run body %s differs from the real create's %s", dry.Body, real.Body)
			}
		})
	}
}

// What can be decided here is decided here, before anything is forwarded: the
// legacy shape has no plan to preview, and a malformed plan is named.
func TestContract_DryRun_ValidatedBeforeForwarding(t *testing.T) {
	for body, want := range map[string]string{
		`{"targets":["10.1.1.1"],"protocols":["TLS"],"ports":[443],"dry_run":true}`:    "dry_run previews a scan-depth request",
		`{"targets":["10.1.1.1"],"ot_probe_protocols":["Modbus"],"dry_run":true}`:      "dry_run previews a scan-depth request",
		`{"targets":["10.1.1.1"],"scan_depth":"deep","dry_run":true}`:                  `scan_depth \"deep\"`,
		`{"targets":["10.1.1.1"],"scan_depth":"custom","dry_run":true}`:                "needs tcp_ports, udp_ports or both",
		`{"targets":["10.1.1.1"],"scan_depth":"thorough","ports":[22],"dry_run":true}`: "cannot be combined with protocols/ports",
	} {
		calls := 0
		a := newAuditedProxy(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
		w := postThrough(a.engine, body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "validation_error") || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s = %d %s, want 400 naming %q", body, w.Code, w.Body, want)
		}
		if calls != 0 {
			t.Errorf("%s reached cluster-sensor-service", body)
		}
	}
}

// Without the flag nothing about the forwarded request changes: no dry_run key
// on a real create, scan-plan or legacy.
func TestContract_DryRun_AbsentFromARealCreate(t *testing.T) {
	for _, body := range []string{
		`{"targets":["10.1.1.1"],"scan_depth":"quick"}`,
		`{"targets":["10.1.1.1"],"scan_depth":"quick","dry_run":false}`,
		`{"targets":["10.1.1.1"],"protocols":["TLS"],"ports":[443]}`,
	} {
		forwarded, calls := forwardedBody(t, body)
		if calls != 1 {
			t.Fatalf("%s: forwarded %d times", body, calls)
		}
		if _, present := forwarded["dry_run"]; present {
			t.Errorf("%s forwarded dry_run: %v", body, forwarded)
		}
	}
}

// A cluster-sensor-service that predates dry_run ignores the flag and creates
// the job, answering 202. That must never be presented to the person as a
// preview.
func TestContract_DryRun_ACreatedJobIsNotAPreview(t *testing.T) {
	a := newAuditedProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job":{"id":"6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d","status":"queued"}}`))
	})
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	w := postThrough(a.engine, dryRunBody)
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), `"plan"`) {
		t.Fatalf("a 202 from downstream was relayed as a preview: %d %s", w.Code, w.Body)
	}
	if w.Code < 400 {
		t.Fatalf("status = %d, want an error", w.Code)
	}
	// An operator must be able to see that a job was created by a "preview".
	if !strings.Contains(logged.String(), "does not support dry_run and CREATED a job") {
		t.Fatalf("the version skew was not logged: %s", logged.String())
	}
}
