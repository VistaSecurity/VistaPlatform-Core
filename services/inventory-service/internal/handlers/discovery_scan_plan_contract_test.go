package handlers

// POST /discovery/jobs, scan-plan shape ( WP3), through the proxy the
// browser calls. What must survive it: the new fields and the OT opt-in on
// the way in (inventory never forwarded ot_probe_protocols, which made OT
// unreachable from the UI); a malformed plan refused HERE with its reason; and
// cluster-sensor-service's plan and budget verdict on the way out, unflattened.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func forwardedBody(t *testing.T, body string) (map[string]interface{}, int) {
	t.Helper()
	var forwarded map[string]interface{}
	calls := 0
	engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewDecoder(r.Body).Decode(&forwarded)
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()
	postThrough(engine, body)
	return forwarded, calls
}

func TestContract_CreateDiscoveryJob_ForwardsScanPlanFieldsAndOTOptIn(t *testing.T) {
	sv := loadSpec(t)
	sensorID := uuid.NewString()
	body := `{"targets":["10.20.30.0/24"],"scan_depth":"custom","tcp_ports":"22,8000-8100","udp_ports":"53","pace":"polite","run_from":"sensor","sensor_id":"` + sensorID + `","ot_probe_protocols":["Modbus"]}`
	sv.assertConforms(t, "CreateDiscoveryJobRequest", []byte(body))

	got, calls := forwardedBody(t, body)
	if calls != 1 {
		t.Fatalf("cluster-sensor called %d times", calls)
	}
	for key, want := range map[string]string{"scan_depth": "custom", "tcp_ports": "22,8000-8100", "udp_ports": "53", "pace": "polite", "run_from": "sensor", "sensor_id": sensorID} {
		if got[key] != want {
			t.Errorf("forwarded %s = %v, want %q", key, got[key], want)
		}
	}
	if ot, _ := got["ot_probe_protocols"].([]interface{}); len(ot) != 1 || ot[0] != "Modbus" {
		t.Errorf("ot_probe_protocols not forwarded: %v", got["ot_probe_protocols"])
	}
}

// The legacy request is forwarded exactly as before: no scan-plan key appears.
func TestCreateDiscoveryJob_LegacyPayloadUnchanged(t *testing.T) {
	got, _ := forwardedBody(t, `{"targets":["10.1.1.1"],"protocols":["TLS"],"ports":[443],"execution_mode":"auto"}`)
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "execution_mode,ports,preferred_sensor_ids,protocols,retention_cap_mb,retention_ttl_hours,targets"
	if strings.Join(keys, ",") != want {
		t.Fatalf("legacy payload keys = %v, want %s", keys, want)
	}
}

// A malformed plan is refused before anything is forwarded, naming what to fix.
func TestCreateDiscoveryJob_ScanPlanRefusedWithItsReason(t *testing.T) {
	for body, want := range map[string]string{
		`{"targets":["10.1.1.1"],"scan_depth":"thorough","protocols":["TLS"],"ports":[443]}`: "scan_depth cannot be combined with protocols/ports",
		`{"targets":["10.1.1.1"],"scan_depth":"custom","tcp_ports":"22,https"}`:              `tcp_ports: port spec entry \"https\"`,
		`{"targets":["10.1.1.1"],"scan_depth":"custom"}`:                                     "needs tcp_ports, udp_ports or both",
		`{"targets":["10.1.1.1"],"scan_depth":"deep"}`:                                       `scan_depth \"deep\"`,
		`{"targets":["10.1.1.1"],"pace":"warp"}`:                                             "unknown scan pace",
		`{"targets":["10.1.1.1"],"run_from":"sensor"}`:                                       "needs a sensor_id",
		`{"targets":["10.1.1.1"],"run_from":"platform","execution_mode":"cloud"}`:            "cannot both be set",
	} {
		calls := 0
		engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
		w := postThrough(engine, body)
		srv.Close()
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "validation_error") || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s = %d %s, want 400 naming %q", body, w.Code, w.Body, want)
		}
		if calls != 0 {
			t.Errorf("%s reached cluster-sensor-service", body)
		}
	}
}

func TestContract_CreateDiscoveryJob_BudgetVerdictKeepsItsNumbers(t *testing.T) {
	sv := loadSpec(t)
	engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"scan_budget_exceeded","message":"this scan would send about 33,579,520 probes (addresses × ports), and one scan may send at most 25,000,000","estimated_probes":33579520,"probe_limit":25000000,"largest_target":{"target":"10.0.0.0/23","addresses":512,"tcp_port_count":65535,"udp_port_count":11,"estimated_probes":33559552}}`))
	})
	defer srv.Close()
	w := postThrough(engine, `{"targets":["10.0.0.0/23"],"scan_depth":"thorough"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	sv.assertConforms(t, "DiscoveryTargetVerdictError", w.Body.Bytes())
	var got struct {
		Error           string `json:"error"`
		Details         string `json:"details"`
		EstimatedProbes uint64 `json:"estimated_probes"`
		ProbeLimit      uint64 `json:"probe_limit"`
		LargestTarget   struct {
			Target string `json:"target"`
		} `json:"largest_target"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Error != shareddisc.CodeScanBudgetExceeded || got.EstimatedProbes != 33579520 || got.ProbeLimit != 25000000 ||
		got.LargestTarget.Target != "10.0.0.0/23" || !strings.Contains(got.Details, "25,000,000") {
		t.Fatalf("budget verdict lost its code or numbers through the proxy: %s", w.Body)
	}
}

// The created job carries cluster-sensor-service's plan through this proxy's
// re-marshal, and the Go plan type both services share conforms to the spec.
func TestContract_CreateDiscoveryJob_CreatedJobCarriesItsPlan(t *testing.T) {
	sv := loadSpec(t)
	spec, err := shareddisc.ResolveJobRequest(shareddisc.JobRequestFields{ScanDepth: "thorough"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := shareddisc.BuildScanPlan(spec.Spec, nil, []shareddisc.PlanTargetInput{
		{Target: "10.20.30.0/24", Class: shareddisc.ClassPrivate},
		{Target: "93.184.216.34", Class: shareddisc.ClassExternal},
		{Target: "93.184.217.0/29", Class: shareddisc.ClassRegisteredSegment, SegmentID: uuid.NewString()},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.RunFromRequested, plan.ExecutorResolved, plan.ExecutorReason = "auto", "platform", "no tenant sensor reports a network containing \"93.184.216.34\""
	if err := plan.CheckBudget(shareddisc.DefaultMaxJobProbes); err != nil {
		t.Fatal(err)
	}
	planJSON, _ := json.Marshal(plan)
	sv.assertConforms(t, "DiscoveryScanPlan", planJSON)

	engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job":{"id":"6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d","tenant_id":"t","status":"queued","execution_mode":"async","created_at":"2026-10-02T12:00:00Z","updated_at":"2026-10-02T12:00:00Z","plan":` + string(planJSON) + `}}`))
	})
	defer srv.Close()
	w := postThrough(engine, `{"targets":["10.20.30.0/24","93.184.216.34","93.184.217.0/29"],"scan_depth":"thorough","external_targets_confirmed":true}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	sv.assertConforms(t, "DiscoveryJobResponse", w.Body.Bytes())
	var got struct {
		Job struct {
			Plan *shareddisc.ScanPlan `json:"plan"`
		} `json:"job"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Job.Plan == nil || len(got.Job.Plan.Targets) != 3 || len(got.Job.Plan.DepthAdjustments) != 1 || got.Job.Plan.Targets[1].Depth != shareddisc.DepthStandard {
		t.Fatalf("the plan did not survive the proxy: %s", w.Body)
	}
}

// With plan execution switched off, cluster-sensor refuses the shape with
// scan_plan_unavailable, and the person must read that, not "failed to create
// discovery job" or a bare validation_error.
func TestContract_CreateDiscoveryJob_ScanPlanUnavailablePassesThrough(t *testing.T) {
	sv := loadSpec(t)
	engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"scan_plan_unavailable","message":"scan depth is switched off on this deployment; use protocols and ports"}`))
	})
	defer srv.Close()
	w := postThrough(engine, `{"targets":["10.1.1.0/24"],"scan_depth":"thorough"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	sv.assertConforms(t, "DiscoveryTargetVerdictError", w.Body.Bytes())
	var got struct {
		Error   string `json:"error"`
		Details string `json:"details"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Error != shareddisc.CodeScanPlanUnavailable || !strings.Contains(got.Details, "use protocols and ports") {
		t.Fatalf("the transitional refusal did not reach the caller intact: %s", w.Body)
	}
}

// WP2b: a scan-plan job naming a sensor whose software cannot run one is
// cluster-sensor-service's coded 409, and the person must read the code and
// what to do — not a bare validation_error.
func TestContract_CreateDiscoveryJob_SensorWithoutScanPlanSupportPassesThrough(t *testing.T) {
	sv := loadSpec(t)
	engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"sensor_scan_plan_unsupported","message":"sensor cannot run scan-plan jobs: sensor branch-01's software does not support scan depth — upgrade it, or run the scan from the platform; nothing was scanned"}`))
	})
	defer srv.Close()
	w := postThrough(engine, `{"targets":["10.1.1.10"],"scan_depth":"quick","run_from":"sensor","sensor_id":"`+uuid.NewString()+`"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	sv.assertConforms(t, "DiscoveryTargetVerdictError", w.Body.Bytes())
	var got struct {
		Error   string `json:"error"`
		Details string `json:"details"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Error != sensordispatch.CodeScanPlanUnsupported || !strings.Contains(got.Details, "upgrade it, or run the scan from the platform") {
		t.Fatalf("the refusal did not reach the caller intact: %s", w.Body)
	}
}

// A scan-plan job's per-host progress and coverage ( WP2) reach the
// caller through the GET proxy verbatim, in the documented shape.
// cluster-sensor-service pins its Go type's keys to the same schema
// (TestJobCoverage_KeysMatchTheSpec), so the two cannot drift apart.
func TestContract_GetDiscoveryJob_CarriesCoverage(t *testing.T) {
	sv := loadSpec(t)
	coverage := `{"hosts_total":254,"hosts_responded":31,"hosts_no_answer":222,"hosts_undetermined":0,"hosts_failed":1,"hosts_pending":0,"hosts_cancelled":0,` +
		`"ports_requested":346456,"ports_open":57,"ports_closed":41234,"ports_filtered":1325,"ports_local_errors":0,"ports_not_probed":303840,` +
		`"tarpit_hosts":0,"ot_suspect_hosts":0,"udp_answered":4,"warnings":["1 address(es) could not be scanned (e.g. not scanned: excluded)"]}`
	sv.assertConforms(t, "DiscoveryJobCoverage", []byte(coverage))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d","tenant_id":"t","status":"completed","execution_mode":"async","progress":100,` +
			`"target_counts":{"total":1,"pending":0,"running":0,"completed":1,"failed":0,"cancelled":0},"coverage":` + coverage + `}`))
	}))
	defer srv.Close()
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", srv.URL)
	svc, err := services.NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/discovery/jobs/:id", NewDiscoveryHandler(nil, svc).GetJob)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/discovery/jobs/6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	sv.assertConforms(t, "DiscoveryJob", w.Body.Bytes())
	var got struct {
		Coverage map[string]interface{} `json:"coverage"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Coverage["hosts_no_answer"] != float64(222) {
		t.Fatalf("coverage did not survive the proxy: %s", w.Body)
	}
}

// GET /discovery/jobs/{id}/results?group=host ( H21): the query reaches
// cluster-sensor-service and the grouped page comes back in the documented
// shape. cluster-sensor-service pins its Go types' keys to the same schemas
// (TestResultsByHost_KeysMatchTheSpec).
func TestContract_GetDiscoveryJobResults_GroupedByHost(t *testing.T) {
	sv := loadSpec(t)
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id":"6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d","group":"host","total_hosts":31,"page":1,"page_size":20,"hosts":[` +
			`{"address":"10.20.30.5","hostname":"db-01.example.test","ports":[` +
			`{"finding_id":"a","port":443,"protocol":"TLS","transport":"tcp","identified":true,"confidence_score":0.9,"data":{"cipher_suite":"TLS_AES_128_GCM_SHA256"}},` +
			`{"finding_id":"b","port":9000,"protocol":"tcp","transport":"tcp","identified":false,"confidence_score":0.5,"data":{"unidentified":true,"banner_len":0}}],` +
			`"unit":{"status":"done","liveness_state":"up","ports_requested":1364,"open_count":2,"closed_count":1362,"filtered_count":0,"not_probed_count":0,"responds_on_all_ports":false,"ot_suspect":false}}]}`))
	}))
	defer srv.Close()
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", srv.URL)
	svc, err := services.NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/discovery/jobs/:id/results", NewDiscoveryHandler(nil, svc).GetJobResults)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/discovery/jobs/6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d/results?group=host&page_size=20", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	if !strings.Contains(gotQuery, "group=host") {
		t.Fatalf("cluster-sensor was asked %q, without group=host", gotQuery)
	}
	sv.assertConforms(t, "DiscoveryJobResultsByHost", w.Body.Bytes())
	sv.assertConforms(t, "DiscoveryJobResults", w.Body.Bytes()) // the endpoint's declared schema
}
