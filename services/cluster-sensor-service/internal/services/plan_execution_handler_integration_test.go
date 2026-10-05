package services_test

// A scan-plan job end to end ( WP2): POSTed through the REAL CreateJob
// handler, delivered to the REAL processor entry point (handleDiscoveryJob),
// run in work units on the shared engine, and read back through the REAL
// GetJob / GetJobStatus / GetJobResults handlers.
//
// The engine's only way onto the network is a FakeNet (fakenet_test.go): it
// maps the scanned addresses onto loopback listeners on ephemeral ports and
// records every address it was asked for. Nothing leaves the loopback
// interface. What it proves:
//
//   - units are created per address and every one is authorized first — an
//     address excluded after the job was created becomes a failed unit and is
//     NEVER dialled, not even by the liveness sweep (H16);
//   - findings appear as hosts finish: one host's findings are stored and
//     queued for inventory while another host of the same job is still being
//     scanned (H10);
//   - an open TLS port is the canonical TLS finding, an open port nothing can
//     name is a "tcp" finding with no banner bytes, a UDP service that replied
//     is a finding, and closed / filtered / silent ports are counts only (H13);
//   - coverage is conserved: hosts and ports add up (H21);
//   - an external target's capped port set (D3) is what its unit scans;
//   - the OCSP fetch a scanned certificate asks for goes through the platform's
//     outbound guard (no request reaches loopback);
//   - the job ends completed, with progress 100.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type execFixture struct {
	db     *sqlx.DB
	tenant uuid.UUID
	r      *gin.Engine
	net    *services.FakeNet
	jp     *services.JobProcessor
}

func newExecFixture(t *testing.T) *execFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	user := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, user, tenant, user.String()+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// The tenant's Platform Discovery Sensor: what a platform job's findings
	// are queued for inventory under.
	if _, err := db.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, tags, ip_address, reporting_interval, last_heartbeat)
		VALUES ($1, $2, 'Platform Discovery Sensor', 'platform', '1.0.0', 'discovery', 'active', '{system}', '10.0.0.1', 30, NOW())`, uuid.New(), tenant); err != nil {
		t.Fatalf("seed platform sensor: %v", err)
	}
	svc := services.NewDiscoveryService(db, db)
	fake := services.NewFakeNet()
	jp := services.NewPlanJobProcessorForTest(t, db, svc, fake)
	h := handlers.NewDiscoveryHandler(svc, services.NewRateLimiter(db), nil, nil)
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
	r.GET("/jobs/:id/status", as(h.GetJobStatus))
	r.GET("/jobs/:id/results", as(h.GetJobResults))
	return &execFixture{db: db, tenant: tenant, r: r, net: fake, jp: jp}
}

func (f *execFixture) do(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, httptest.NewRequest(method, path, rd))
	return w
}

type jobRead struct {
	ID           string                  `json:"id"`
	Status       string                  `json:"status"`
	Progress     int                     `json:"progress"`
	TargetCounts *models.JobTargetCounts `json:"target_counts"`
	Coverage     *models.JobCoverage     `json:"coverage"`
	Plan         *shareddisc.ScanPlan    `json:"plan"`
}

func (f *execFixture) job(t *testing.T, id string) jobRead {
	t.Helper()
	w := f.do(t, http.MethodGet, "/jobs/"+id, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /jobs/%s = %d %s", id, w.Code, w.Body)
	}
	var j jobRead
	if err := json.Unmarshal(w.Body.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	return j
}

func (f *execFixture) count(t *testing.T, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func TestIntegration_PlanJob_RunsInUnitsEndToEnd(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	t.Setenv(shareddisc.EnvMaxJobProbes, "")
	f := newExecFixture(t)

	const (
		hostA    = "10.183.7.10" // named alone: assumed up
		hostB    = "10.183.7.21" // inside the range, answers (refuses everything)
		excluded = "10.183.7.23" // inside the range, excluded after the job is created
		external = "93.184.216.34"
	)
	trap := services.NewHTTPTrap(t)
	f.net.Host(hostA, map[uint16]string{
		443:  services.ServeTLSWithOCSP(t, trap.URL),
		25:   services.ServeBanner(t, "220 mail.example.test ESMTP ready\r\n"),
		1999: services.ServeSilent(t),
	}, map[uint16]string{53: services.ServeDNSUDP(t)})
	f.net.Host(hostB, nil, nil)
	f.net.Host(excluded, nil, nil) // would answer — if it were ever asked

	// Slow host B's port scan down until host A's findings are visible:
	// findings must appear as hosts finish, not when the job ends. Each of B's
	// port-scan connects (not its liveness probes) waits up to 700ms — under
	// the 1.5s connect timeout, so the port still gets its real verdict — so
	// B's 2,000 ports take far longer than A's whole unit, until released.
	releaseB := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseB) }) })
	liveness := shareddisc.DefaultLivenessPorts()
	f.net.OnDial = func(ctx context.Context, network string, ap netip.AddrPort) {
		if network == "tcp" && ap.Addr().String() == hostB && !liveness.Contains(int(ap.Port())) {
			select {
			case <-releaseB:
			case <-ctx.Done():
			case <-time.After(700 * time.Millisecond):
			}
		}
	}

	w := f.do(t, http.MethodPost, "/jobs", map[string]interface{}{
		"targets":                    []string{hostA, "10.183.7.20-10.183.7.23", external},
		"scan_depth":                 "custom",
		"tcp_ports":                  "1-2000",
		"udp_ports":                  "53",
		"run_from":                   "platform",
		"external_targets_confirmed": true,
	})
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST /jobs = %d %s", w.Code, w.Body)
	}
	var created struct {
		Job jobRead `json:"job"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	jobID := created.Job.ID
	if ext := created.Job.Plan.Targets[2]; ext.Class != shareddisc.ClassExternal || ext.TCPPortCount != shareddisc.MaxExternalCustomTCPPorts {
		t.Fatalf("external plan target = %+v, want capped to %d TCP ports", ext, shareddisc.MaxExternalCustomTCPPorts)
	}

	// The tenant marks one address sensitive after creating the job: it must
	// be refused at dispatch, per address, before any packet.
	if _, err := f.db.Exec(`INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
		VALUES ($1, 'fragile', 'cidr', $2, 'private', 'production', true, '{"sensitive": "true"}')`, f.tenant, excluded+"/32"); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- f.jp.DeliverJobForTest(t, jobID) }()

	// Host A finishes while B is held: its findings are stored and queued.
	deadline := time.Now().Add(60 * time.Second)
	for f.count(t, `SELECT count(*) FROM discovery_findings WHERE job_id = $1 AND host(resolved_ip) = $2`, jobID, hostA) < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("host A's findings did not appear while the job ran; dials so far: %d", len(f.net.Dials()))
		}
		time.Sleep(100 * time.Millisecond)
	}
	mid := f.job(t, jobID)
	if mid.Status != "running" || mid.Progress >= 100 || mid.Coverage == nil || mid.Coverage.HostsPending == 0 {
		t.Fatalf("mid-scan read = status %s progress %d coverage %+v, want running with hosts pending", mid.Status, mid.Progress, mid.Coverage)
	}
	if n := f.count(t, `SELECT count(*) FROM sensor_discoveries WHERE batch_id = $1 AND tenant_id = $2`, jobID, f.tenant); n != 4 {
		t.Fatalf("ingestion-queue rows mid-scan = %d, want host A's 4 already queued", n)
	}
	releaseOnce.Do(func() { close(releaseB) })

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("processing: %v", err)
		}
	case <-time.After(120 * time.Second):
		t.Fatal("job did not finish")
	}

	// H16: the excluded address was never contacted.
	dialed := f.net.DialedAddrs()
	if n := dialed[excluded]; n != 0 {
		t.Fatalf("the excluded address was dialled %d time(s)", n)
	}
	allowed := map[string]bool{hostA: true, hostB: true, "10.183.7.20": true, "10.183.7.22": true, external: true}
	for addr := range dialed {
		if !allowed[addr] {
			t.Fatalf("the engine dialled %s, which no unit names", addr)
		}
	}
	if trap.Hits() != 0 {
		t.Fatalf("the OCSP URL in the scanned certificate (loopback) was fetched %d time(s): the outbound guard is not wired", trap.Hits())
	}

	final := f.job(t, jobID)
	if final.Status != "completed" || final.Progress != 100 {
		t.Fatalf("final = %s %d%%, want completed 100%%", final.Status, final.Progress)
	}
	c := final.Coverage
	if c == nil {
		t.Fatal("completed scan-plan job carries no coverage")
	}
	// 6 addresses: A, B, .20 .22 (no answer), .23 (refused), external (no answer).
	want := models.JobCoverage{
		HostsTotal: 6, HostsResponded: 2, HostsNoAnswer: 3, HostsFailed: 1,
		PortsRequested: 2000 + 2000 + 2*2000 + 1024,
		PortsOpen:      3, PortsClosed: 1997 + 2000, PortsFiltered: 1024, PortsNotProbed: 2 * 2000,
		UDPAnswered: 1,
	}
	if c.HostsTotal != want.HostsTotal || c.HostsResponded != want.HostsResponded || c.HostsNoAnswer != want.HostsNoAnswer ||
		c.HostsFailed != want.HostsFailed || c.HostsPending != 0 || c.HostsCancelled != 0 || c.HostsUndetermined != 0 {
		t.Errorf("hosts = %+v, want %+v", c, want)
	}
	if c.PortsRequested != want.PortsRequested || c.PortsOpen != want.PortsOpen || c.PortsClosed != want.PortsClosed ||
		c.PortsFiltered != want.PortsFiltered || c.PortsNotProbed != want.PortsNotProbed || c.PortsLocalErrors != 0 || c.UDPAnswered != want.UDPAnswered {
		t.Errorf("ports = %+v, want %+v", c, want)
	}
	if c.HostsTotal != c.HostsResponded+c.HostsNoAnswer+c.HostsUndetermined+c.HostsFailed+c.HostsPending+c.HostsCancelled {
		t.Errorf("hosts not conserved: %+v", c)
	}
	if c.PortsRequested != c.PortsOpen+c.PortsClosed+c.PortsFiltered+c.PortsLocalErrors+c.PortsNotProbed {
		t.Errorf("ports not conserved: %+v", c)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "1 address(es) could not be scanned") {
		t.Errorf("warnings = %q, want only the refused address", c.Warnings)
	}
	if final.TargetCounts == nil || final.TargetCounts.Completed != 3 {
		t.Errorf("target_counts = %+v, want the 3 targets completed", final.TargetCounts)
	}

	// The refusal is on the unit, with the guard's reason.
	var status, reason string
	if err := f.db.QueryRow(`SELECT status, COALESCE(error_message, '') FROM discovery_job_units WHERE job_id = $1 AND address = $2`, jobID, excluded).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.HasPrefix(reason, "not scanned:") {
		t.Errorf("excluded unit = %s %q, want failed with the reason", status, reason)
	}
	// The external unit scanned exactly its capped port set.
	var extRequested int
	if err := f.db.QueryRow(`SELECT ports_requested FROM discovery_job_units WHERE job_id = $1 AND address = $2`, jobID, external).Scan(&extRequested); err != nil {
		t.Fatal(err)
	}
	if extRequested != shareddisc.MaxExternalCustomTCPPorts {
		t.Errorf("external unit ports_requested = %d, want the cap %d", extRequested, shareddisc.MaxExternalCustomTCPPorts)
	}

	// The findings: what the legacy ingestion reads.
	type row struct {
		Protocol string
		Port     int
		Details  map[string]interface{}
	}
	rows, err := f.db.Query(`SELECT protocol, port, details FROM discovery_findings WHERE job_id = $1 ORDER BY port`, jobID)
	if err != nil {
		t.Fatal(err)
	}
	var got []row
	for rows.Next() {
		var r row
		var raw []byte
		if err := rows.Scan(&r.Protocol, &r.Port, &raw); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &r.Details)
		got = append(got, r)
	}
	_ = rows.Close()
	if len(got) != 4 {
		t.Fatalf("findings = %+v, want 4 (smtp/tcp 25, DNS 53, TLS 443, tcp 1999)", got)
	}
	byPort := map[int]row{}
	for _, r := range got {
		byPort[r.Port] = r
	}
	if r := byPort[443]; r.Protocol != "TLS" || r.Details["certificates"] == nil || r.Details["cipher_suite"] == nil {
		t.Errorf("443 = %+v, want the canonical TLS finding", r)
	}
	if r := byPort[25]; r.Protocol != "tcp" || r.Details["service_hint"] != "smtp" || r.Details["unidentified"] != false {
		t.Errorf("25 = %+v, want a tcp endpoint named smtp by its banner", r)
	}
	if r := byPort[1999]; r.Protocol != "tcp" || r.Details["unidentified"] != true {
		t.Errorf("1999 = %+v, want an unidentified tcp endpoint", r)
	}
	if r := byPort[53]; r.Protocol != "DNS" || r.Details["transport"] != "udp" {
		t.Errorf("53 = %+v, want the DNS reply", r)
	}
	for _, r := range got {
		for k := range r.Details {
			if strings.Contains(strings.ToLower(k), "banner") && k != "banner_len" {
				t.Errorf("finding on %d carries %q — banner bytes must never be stored", r.Port, k)
			}
		}
	}
	if n := f.count(t, `SELECT count(*) FROM sensor_discoveries WHERE batch_id = $1 AND tenant_id = $2`, jobID, f.tenant); n != 4 {
		t.Errorf("ingestion-queue rows = %d, want 4", n)
	}

	// /status carries the same coverage; /results the findings.
	w = f.do(t, http.MethodGet, "/jobs/"+jobID+"/status", nil)
	var st struct {
		Progress int                 `json:"progress"`
		Coverage *models.JobCoverage `json:"coverage"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.Progress != 100 || st.Coverage == nil || st.Coverage.HostsResponded != 2 {
		t.Errorf("GET /status = %s", w.Body)
	}

	// Results grouped by host (H21): one host per entry, its ports together,
	// paged by host — every host that responded, so host B, which
	// refused everything, is listed too, with no ports, on the next page.
	w = f.do(t, http.MethodGet, "/jobs/"+jobID+"/results?group=host&page_size=1", nil)
	var byHost models.DiscoveryResultsByHostResponse
	if err := json.Unmarshal(w.Body.Bytes(), &byHost); err != nil || w.Code != http.StatusOK {
		t.Fatalf("GET results?group=host = %d %s", w.Code, w.Body)
	}
	if byHost.TotalHosts != 2 || len(byHost.Hosts) != 1 || st.Coverage == nil || byHost.TotalHosts != st.Coverage.HostsResponded {
		t.Fatalf("hosts = %d (total %d), want host A on page 1 of 2 — the coverage's responded count", len(byHost.Hosts), byHost.TotalHosts)
	}
	w = f.do(t, http.MethodGet, "/jobs/"+jobID+"/results?group=host&page_size=1&page=2", nil)
	var page2 models.DiscoveryResultsByHostResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page2); err != nil || len(page2.Hosts) != 1 {
		t.Fatalf("GET results?group=host page 2 = %d %s", w.Code, w.Body)
	}
	if b := page2.Hosts[0]; b.Address != hostB || !b.NothingOpen || len(b.Ports) != 0 || b.Unit == nil || b.Unit.ClosedCount == 0 {
		t.Fatalf("host B = %+v, want it listed as answered with nothing open", b)
	}
	a := byHost.Hosts[0]
	if a.Address != hostA || len(a.Ports) != 4 || a.Unit == nil || a.Unit.Status != "done" || a.Unit.OpenCount != 3 {
		t.Fatalf("host A = %+v", a)
	}
	gotPorts := []int{a.Ports[0].Port, a.Ports[1].Port, a.Ports[2].Port, a.Ports[3].Port}
	if gotPorts[0] != 25 || gotPorts[1] != 53 || gotPorts[2] != 443 || gotPorts[3] != 1999 {
		t.Errorf("ports %v, want in port order", gotPorts)
	}
	if !a.Ports[2].Identified || a.Ports[2].Protocol != "TLS" || a.Ports[3].Identified || a.Ports[3].Protocol != "tcp" || a.Ports[1].Transport != "udp" {
		t.Errorf("port entries = %+v", a.Ports)
	}
	if w = f.do(t, http.MethodGet, "/jobs/"+jobID+"/results?group=port", nil); w.Code != http.StatusBadRequest {
		t.Errorf("GET results?group=port = %d, want 400", w.Code)
	}
}
