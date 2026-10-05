package services

// A person-initiated scan is recorded as FINISHED, against a real Postgres,
// through the real entry points:
//
//   - CreateActiveScanJob / CreateRevalidationJob dispatch to an httptest
//     stand-in for cluster-sensor-service that writes the job the way
//     cluster-sensor-service does (discovery_jobs, one discovery_targets row
//     per target carrying its ports, and for a planned job metadata.scan_plan
//     plus one discovery_job_units row per host);
//   - the job is then finished the way the executors finish it: jobunits.Commit
//     for a host the Platform Sensor scanned, the reaper's failed/cancelled
//     shapes, or a legacy job whose old sensor never moved its target rows;
//   - autoscan.FinishActiveScans — what the worker runs — settles it, and the
//     real AssetService.GetAssets with unscanned_only=true reads the result.
//
// The store and the service run as the RLS app role, so the tenant-scoped
// statements are checked against the policies production enforces.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// simJob is one job the simulated cluster-sensor-service created.
type simJob struct {
	id      uuid.UUID
	planned bool
	ports   []int
	targets map[string]uuid.UUID     // input → discovery_targets.id
	units   map[string]jobunits.Unit // address → unit (planned only)
}

// simCluster stands in for cluster-sensor-service's POST /discovery/jobs.
type simCluster struct {
	t       *testing.T
	owner   *sql.DB
	tenant  uuid.UUID
	planned bool // false = write a legacy job (an old sensor's shape)
	refuse  bool // answer 500 without creating anything

	mu   sync.Mutex
	jobs []*simJob
}

func (c *simCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body struct {
		Targets       []string `json:"targets"`
		TCPPorts      string   `json:"tcp_ports"`
		ExecutionMode string   `json:"execution_mode"`
	}
	_ = json.Unmarshal(raw, &body)
	if c.refuse {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"cluster-sensor-service is down"}`))
		return
	}
	job := &simJob{id: uuid.New(), planned: c.planned, targets: map[string]uuid.UUID{}, units: map[string]jobunits.Unit{}}
	for _, p := range strings.Split(body.TCPPorts, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			c.t.Errorf("tcp_ports %q is not a port list", body.TCPPorts)
			continue
		}
		job.ports = append(job.ports, n)
	}
	// Exactly what cluster-sensor-service stores for a job created with a
	// person's credentials: it stamps origin "manual" itself, whatever the
	// caller sent (discovery_handler.go, #H5).
	meta := map[string]any{"options": map[string]any{"active_scan": true, "origin": "manual"}}
	if c.planned {
		meta[shareddisc.ScanPlanMetadataKey] = map[string]any{"depth": "custom", "tcp_ports": body.TCPPorts}
	}
	metaJSON, _ := json.Marshal(meta)
	if body.ExecutionMode == "" {
		body.ExecutionMode = "async"
	}
	if !c.planned && body.ExecutionMode != "sensors" {
		// Since WP5 the platform always plans its jobs; only a tenant sensor
		// without scan_plan_v1 can still be sent the legacy shape.
		c.t.Errorf("a legacy job for execution mode %q: the platform no longer creates one", body.ExecutionMode)
	}
	c.exec(`INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, metadata) VALUES ($1, $2, $3, 'queued', $4::jsonb)`,
		job.id, c.tenant, body.ExecutionMode, string(metaJSON))
	for _, input := range body.Targets {
		var targetID uuid.UUID
		ports := make([]string, len(job.ports))
		for i, p := range job.ports {
			ports[i] = strconv.Itoa(p)
		}
		if err := c.owner.QueryRow(`INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports) VALUES ($1, $2, $3, '{}', $4::int[]) RETURNING id`,
			job.id, c.tenant, input, "{"+strings.Join(ports, ",")+"}").Scan(&targetID); err != nil {
			c.t.Errorf("insert target: %v", err)
			continue
		}
		job.targets[input] = targetID
		if c.planned {
			u := jobunits.Unit{JobID: job.id.String(), TenantID: c.tenant.String(), TargetID: targetID.String(), TargetInput: input, Address: input}
			if err := c.owner.QueryRow(`INSERT INTO discovery_job_units (tenant_id, job_id, target_id, address, attempts, status) VALUES ($1, $2, $3, $4, 1, 'pending') RETURNING id`,
				c.tenant, job.id, targetID, input).Scan(&u.ID); err != nil {
				c.t.Errorf("insert unit: %v", err)
				continue
			}
			job.units[input] = u
		}
	}
	c.mu.Lock()
	c.jobs = append(c.jobs, job)
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"job":{"id":"` + job.id.String() + `","status":"queued"}}`))
}

func (c *simCluster) exec(q string, args ...any) {
	c.t.Helper()
	if _, err := c.owner.Exec(q, args...); err != nil {
		c.t.Fatalf("%v\n%s", err, q)
	}
}

// jobFor returns the job that scans the given target input.
func (c *simCluster) jobFor(input string) *simJob {
	c.t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.jobs) - 1; i >= 0; i-- {
		if _, ok := c.jobs[i].targets[input]; ok {
			return c.jobs[i]
		}
	}
	c.t.Fatalf("no job scans %s", input)
	return nil
}

// closedEverywhere is the engine's output for a host that answered nothing:
// up, every requested port refused. No finding comes back from it.
func closedEverywhere(addr string, ports []int) shareddisc.UnitOutput {
	a := netip.MustParseAddr(addr)
	out := shareddisc.UnitOutput{Host: shareddisc.HostScan{Addr: a, Liveness: shareddisc.LivenessUp, LivenessEvidence: "tcp-rst", PortsRequested: len(ports), Closed: len(ports)}}
	for _, p := range ports {
		out.TCP = append(out.TCP, shareddisc.Observation{Addr: a, Port: p, Transport: "tcp", State: "closed"})
	}
	return out
}

// complete runs every host of a planned job through jobunits.Commit, as the
// Platform Sensor does, then completes the job.
func (c *simCluster) complete(job *simJob) {
	c.t.Helper()
	c.exec(`UPDATE discovery_jobs SET status = 'running', started_at = NOW() WHERE id = $1`, job.id)
	for addr, u := range job.units {
		c.exec(`UPDATE discovery_job_units SET status = 'running', started_at = NOW() WHERE id = $1`, u.ID)
		err := shareddatabase.WithTenantTx(context.Background(), c.owner, c.tenant, func(tx *sql.Tx) error {
			return jobunits.Commit(tx, u, closedEverywhere(addr, job.ports), jobunits.CommitOptions{From: "running", Attempt: 1, ActiveScan: true})
		})
		if err != nil {
			c.t.Fatalf("commit unit %s: %v", addr, err)
		}
	}
	c.exec(`UPDATE discovery_jobs SET status = 'completed', completed_at = NOW() WHERE id = $1`, job.id)
}

// scanThenFail is a job whose host WAS scanned (its unit committed `done`)
// before the job itself was swept as failed.
func (c *simCluster) scanThenFail(job *simJob) {
	c.t.Helper()
	c.complete(job)
	c.exec(`UPDATE discovery_jobs SET status = 'failed', error_message = 'stalled after its last host' WHERE id = $1`, job.id)
}

// failUnitThenComplete is a job that completed with one host's unit failed
// (the host could not be scanned): the unit and its target fail, the job ends
// `completed`.
func (c *simCluster) failUnitThenComplete(job *simJob) {
	c.t.Helper()
	for _, u := range job.units {
		c.exec(`UPDATE discovery_job_units SET status = 'failed', error_message = 'address unreachable', finished_at = NOW() WHERE id = $1`, u.ID)
		err := shareddatabase.WithTenantTx(context.Background(), c.owner, c.tenant, func(tx *sql.Tx) error {
			return jobunits.SettleTarget(tx, u.JobID, u.TargetID, u.TargetInput)
		})
		if err != nil {
			c.t.Fatalf("settle target: %v", err)
		}
	}
	c.exec(`UPDATE discovery_jobs SET status = 'completed', started_at = NOW(), completed_at = NOW() WHERE id = $1`, job.id)
}

// failStale is the stale-dispatch sweep's shape: the job never started, it and
// its hosts end `failed`.
func (c *simCluster) failStale(job *simJob) {
	c.t.Helper()
	c.exec(`UPDATE discovery_jobs SET status = 'failed', completed_at = NOW(), error_message = 'the sensor never collected the job; nothing was scanned' WHERE id = $1`, job.id)
	c.exec(`UPDATE discovery_job_units SET status = 'failed', finished_at = NOW() WHERE job_id = $1`, job.id)
	c.exec(`UPDATE discovery_targets SET status = 'failed', completed_at = NOW() WHERE job_id = $1`, job.id)
}

// cancel is a person cancelling the job before it ran.
func (c *simCluster) cancel(job *simJob) {
	c.t.Helper()
	c.exec(`UPDATE discovery_jobs SET status = 'cancelled', completed_at = NOW() WHERE id = $1`, job.id)
	c.exec(`UPDATE discovery_job_units SET status = 'cancelled', finished_at = NOW() WHERE job_id = $1`, job.id)
	c.exec(`UPDATE discovery_targets SET status = 'cancelled', completed_at = NOW() WHERE job_id = $1`, job.id)
}

// finishFixture is one tenant with the service and the store wired against a
// simulated cluster-sensor-service.
type finishFixture struct {
	t       *testing.T
	owner   *sql.DB
	tenant  uuid.UUID
	cluster *simCluster
	svc     *RevalidationService
	assets  *AssetService
	store   *autoscan.Store
}

func newFinishFixture(t *testing.T) *finishFixture {
	t.Helper()
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	app := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, owner), "postgres")}
	cluster := &simCluster{t: t, owner: owner, tenant: tenant, planned: true}
	srv := httptest.NewServer(cluster)
	t.Cleanup(srv.Close)
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", srv.URL)
	ds, err := NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return &finishFixture{
		t: t, owner: owner, tenant: tenant, cluster: cluster,
		svc:    &RevalidationService{db: app, discoveryService: ds},
		assets: NewAssetService(app),
		store:  autoscan.NewStore(app),
	}
}

// asset writes a monitoring asset; port 0 means no endpoint at all, an empty
// address means nothing to connect to.
func (f *finishFixture) asset(address string, port int) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	var addr any
	hostname := any(nil)
	if address != "" {
		addr = address
		hostname = "host-" + id.String()[:8] + ".example.test"
	}
	f.cluster.exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,$3,$4,'server','hardware.computer.server','monitoring')`,
		id, f.tenant, hostname, addr)
	if port > 0 {
		f.cluster.exec(`INSERT INTO asset_endpoints(tenant_id,asset_id,address,port,transport) VALUES($1,$2,$3,$4,'tcp')`, f.tenant, id, address, port)
	}
	return id
}

func (f *finishFixture) endpoint(assetID uuid.UUID) (sql.NullTime, sql.NullString) {
	f.t.Helper()
	var at sql.NullTime
	var status sql.NullString
	if err := f.owner.QueryRow(`SELECT last_scanned_at, last_scan_status FROM asset_endpoints WHERE tenant_id = $1 AND asset_id = $2`,
		f.tenant, assetID).Scan(&at, &status); err != nil {
		f.t.Fatalf("read endpoint: %v", err)
	}
	return at, status
}

// unscanned returns the Active Scan list (unscanned_only=true), keyed by id.
func (f *finishFixture) unscanned() map[uuid.UUID]models.Asset {
	f.t.Helper()
	yes := true
	list, _, err := f.assets.GetAssets(f.tenant, models.AssetFilters{UnscannedOnly: &yes, Page: 1, PageSize: 100})
	if err != nil {
		f.t.Fatalf("GetAssets(unscanned_only): %v", err)
	}
	out := map[uuid.UUID]models.Asset{}
	for _, a := range list {
		out[a.ID] = a
	}
	return out
}

func (f *finishFixture) finish() autoscan.FinishedScans {
	f.t.Helper()
	done, err := f.store.FinishActiveScans(context.Background(), f.tenant)
	if err != nil {
		f.t.Fatalf("FinishActiveScans: %v", err)
	}
	return done
}

func scanStatus(a models.Asset) string {
	if a.ActiveScan == nil {
		return ""
	}
	return a.ActiveScan.Status
}

func TestIntegration_ActiveScan_IsRecordedAsFinished(t *testing.T) {
	f := newFinishFixture(t)
	ctx := context.Background()
	user := uuid.New()

	withEndpoint := f.asset("10.0.0.11", 443) // one endpoint on 443
	noEndpoint := f.asset("10.0.0.12", 0)     // nothing ever answered: no endpoint
	atRest := f.asset("", 0)                  // nothing to connect to

	// An asset the AUTOMATIC scan already covered: its endpoint carries the
	// automatic stamp and its metadata the automatic record. It must be left
	// exactly as it is.
	autoScanned := f.asset("10.0.0.13", 22)
	autoJob := uuid.New()
	f.cluster.exec(`INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, completed_at, metadata) VALUES ($1, $2, 'async', 'completed', NOW() - interval '1 hour', $3::jsonb)`,
		autoJob, f.tenant, `{"options":{"active_scan":true,"origin":"auto_scan"}}`)
	f.cluster.exec(`UPDATE asset_endpoints SET last_scanned_at = NOW() - interval '1 hour', last_scan_status = 'completed' WHERE asset_id = $1`, autoScanned)
	f.cluster.exec(`UPDATE assets SET metadata = jsonb_build_object('last_auto_scan_job_id', $2::text, 'last_auto_scan_at', '2026-01-01T00:00:00Z') WHERE id = $1`, autoScanned, autoJob.String())
	var autoMetaBefore string
	if err := f.owner.QueryRow(`SELECT metadata::text FROM assets WHERE id = $1`, autoScanned).Scan(&autoMetaBefore); err != nil {
		t.Fatal(err)
	}
	autoAtBefore, _ := f.endpoint(autoScanned)

	before := f.unscanned()
	for _, id := range []uuid.UUID{withEndpoint, noEndpoint, atRest} {
		if _, ok := before[id]; !ok {
			t.Fatalf("asset %s missing from the unscanned list before any scan", id)
		}
	}
	if _, ok := before[autoScanned]; ok {
		t.Fatal("the automatically scanned asset is on the unscanned list")
	}

	res, err := f.svc.CreateActiveScanJob(f.tenant, user, []uuid.UUID{withEndpoint, noEndpoint, atRest}, "", RunFrom{Mode: RunFromPlatform}, false)
	if err != nil {
		t.Fatalf("CreateActiveScanJob: %v", err)
	}
	if len(res.Jobs) != 2 {
		t.Fatalf("%d jobs, want 2 (the endpoint's 443, the 443/8443 fallback)", len(res.Jobs))
	}

	// In flight: the endpoint reads `scanning` with NO scan time, and both
	// scanned assets stay on the list, shown as scanning.
	if at, status := f.endpoint(withEndpoint); at.Valid || status.String != "scanning" {
		t.Fatalf("in flight: endpoint = %v %q, want no scan time and `scanning`", at, status.String)
	}
	mid := f.unscanned()
	for _, id := range []uuid.UUID{withEndpoint, noEndpoint} {
		a, ok := mid[id]
		if !ok || scanStatus(a) != "scanning" {
			t.Fatalf("in flight: asset %s on list=%v active_scan=%+v, want listed and scanning", id, ok, a.ActiveScan)
		}
		if len(a.ActiveScan.JobIDs) != 1 {
			t.Fatalf("in flight: asset %s records jobs %v, want its one job", id, a.ActiveScan.JobIDs)
		}
	}
	if _, ok := mid[atRest]; !ok || scanStatus(mid[atRest]) != "" {
		t.Fatalf("the at-rest asset was recorded as scanned (%+v) though nothing could be scanned", mid[atRest].ActiveScan)
	}

	// Nothing has ended: nothing is settled.
	if done := f.finish(); done.Assets != 0 || done.Endpoints != 0 {
		t.Fatalf("settled %+v while the jobs were queued", done)
	}

	// The jobs complete. Neither host answered on any port: no finding.
	f.cluster.complete(f.cluster.jobFor("10.0.0.11"))
	f.cluster.complete(f.cluster.jobFor("10.0.0.12"))
	done := f.finish()
	if done.Assets != 2 || done.Endpoints != 1 {
		t.Fatalf("settled %+v, want 2 assets and 1 endpoint", done)
	}
	if at, status := f.endpoint(withEndpoint); !at.Valid || status.String != "completed" {
		t.Fatalf("after completion: endpoint = %v %q, want a scan time and `completed`", at, status.String)
	}
	after := f.unscanned()
	for _, id := range []uuid.UUID{withEndpoint, noEndpoint} {
		if a, ok := after[id]; ok {
			t.Fatalf("asset %s still on the unscanned list after its scan completed (active_scan %+v)", id, a.ActiveScan)
		}
	}
	if _, ok := after[atRest]; !ok {
		t.Fatal("the at-rest asset left the unscanned list though nothing scanned it")
	}

	// The field a person can write in the Inventory query bar reaches the same
	// fact: the no-endpoint asset was scanned in the last day, the at-rest one
	// never was.
	recent, _, err := f.assets.GetAssets(f.tenant, models.AssetFilters{Query: "last_scanned > now-1d", Page: 1, PageSize: 100})
	if err != nil {
		t.Fatalf("GetAssets(last_scanned > now-1d): %v", err)
	}
	gotRecent := map[uuid.UUID]bool{}
	for _, a := range recent {
		gotRecent[a.ID] = true
	}
	if !gotRecent[noEndpoint] || gotRecent[atRest] || gotRecent[autoScanned] {
		t.Fatalf("last_scanned > now-1d matched %v; want the scanned no-endpoint asset and not the at-rest or automatic one", gotRecent)
	}

	// The asset read carries the finished record.
	got, err := f.assets.GetAssetByID(f.tenant, noEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got.ActiveScan == nil || got.ActiveScan.Status != "completed" || got.ActiveScan.FinishedAt == nil {
		t.Fatalf("asset read active_scan = %+v, want completed with a finish time", got.ActiveScan)
	}

	// The automatically scanned asset is untouched.
	var autoMetaAfter string
	if err := f.owner.QueryRow(`SELECT metadata::text FROM assets WHERE id = $1`, autoScanned).Scan(&autoMetaAfter); err != nil {
		t.Fatal(err)
	}
	autoAtAfter, autoStatus := f.endpoint(autoScanned)
	if autoMetaAfter != autoMetaBefore || !autoAtAfter.Time.Equal(autoAtBefore.Time) || autoStatus.String != "completed" {
		t.Fatalf("the automatically scanned asset changed: metadata %s → %s, endpoint %v → %v %q",
			autoMetaBefore, autoMetaAfter, autoAtBefore, autoAtAfter, autoStatus.String)
	}

	// Idempotent.
	if done := f.finish(); done.Assets != 0 || done.Endpoints != 0 {
		t.Fatalf("a second pass settled %+v", done)
	}
	_ = ctx
}

func TestIntegration_ActiveScan_FailedOrCancelledIsRecordedAsFailed(t *testing.T) {
	for _, c := range []struct {
		name string
		end  func(*simCluster, *simJob)
	}{
		{"swept as a stale dispatch", (*simCluster).failStale},
		{"cancelled", (*simCluster).cancel},
		{"completed, but the host could not be scanned", (*simCluster).failUnitThenComplete},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFinishFixture(t)
			withEndpoint := f.asset("10.0.0.21", 8443)
			noEndpoint := f.asset("10.0.0.22", 0)
			if _, err := f.svc.CreateActiveScanJob(f.tenant, uuid.New(), []uuid.UUID{withEndpoint, noEndpoint}, "", RunFrom{Mode: RunFromPlatform}, false); err != nil {
				t.Fatalf("CreateActiveScanJob: %v", err)
			}
			c.end(f.cluster, f.cluster.jobFor("10.0.0.21"))
			c.end(f.cluster, f.cluster.jobFor("10.0.0.22"))

			if done := f.finish(); done.Assets != 2 || done.Endpoints != 1 {
				t.Fatalf("settled %+v, want 2 assets and 1 endpoint", done)
			}
			if at, status := f.endpoint(withEndpoint); at.Valid || status.String != "failed" {
				t.Fatalf("endpoint = %v %q, want no scan time and `failed`", at, status.String)
			}
			list := f.unscanned()
			for _, id := range []uuid.UUID{withEndpoint, noEndpoint} {
				a, ok := list[id]
				if !ok {
					t.Fatalf("asset %s left the unscanned list though its scan failed", id)
				}
				if scanStatus(a) != "failed" {
					t.Fatalf("asset %s active_scan = %+v, want failed", id, a.ActiveScan)
				}
			}
		})
	}
}

// An asset with endpoints on two ports is two jobs (Active Scan groups by
// port). Both are recorded on the asset, the asset waits for BOTH, and each
// endpoint is settled by the job that probed ITS port: 443's job completed,
// 22's was swept as failed.
func TestIntegration_ActiveScan_EachEndpointIsSettledByTheJobForItsPort(t *testing.T) {
	f := newFinishFixture(t)
	asset := f.asset("10.0.0.27", 443)
	f.cluster.exec(`INSERT INTO asset_endpoints(tenant_id,asset_id,address,port,transport) VALUES($1,$2,'10.0.0.27',22,'tcp')`, f.tenant, asset)
	res, err := f.svc.CreateActiveScanJob(f.tenant, uuid.New(), []uuid.UUID{asset}, "", RunFrom{Mode: RunFromPlatform}, false)
	if err != nil || len(res.Jobs) != 2 {
		t.Fatalf("CreateActiveScanJob = %d jobs, %v; want 2 (one per port)", len(res.Jobs), err)
	}
	got, err := f.assets.GetAssetByID(f.tenant, asset)
	if err != nil || got.ActiveScan == nil || len(got.ActiveScan.JobIDs) != 2 {
		t.Fatalf("active_scan = %+v (%v), want both jobs recorded", got.ActiveScan, err)
	}
	var jobs [2]*simJob
	f.cluster.mu.Lock()
	for _, j := range f.cluster.jobs {
		if j.ports[0] == 443 {
			jobs[0] = j
		} else {
			jobs[1] = j
		}
	}
	f.cluster.mu.Unlock()

	f.cluster.complete(jobs[0])
	if done := f.finish(); done.Assets != 0 || done.Endpoints != 0 {
		t.Fatalf("settled %+v while the port-22 job was still queued", done)
	}
	f.cluster.failStale(jobs[1])
	f.finish()
	port := func(p int) string {
		var status string
		if err := f.owner.QueryRow(`SELECT last_scan_status FROM asset_endpoints WHERE asset_id = $1 AND port = $2`, asset, p).Scan(&status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	if port(443) != "completed" || port(22) != "failed" {
		t.Fatalf("443 = %q, 22 = %q; want completed and failed", port(443), port(22))
	}
}

// A job that scanned the host and THEN failed did scan it: "failed" is for a
// host the job never reached.
func TestIntegration_ActiveScan_AJobThatFailedAfterScanningTheHostCountsAsScanned(t *testing.T) {
	f := newFinishFixture(t)
	withEndpoint := f.asset("10.0.0.25", 443)
	noEndpoint := f.asset("10.0.0.26", 0)
	if _, err := f.svc.CreateActiveScanJob(f.tenant, uuid.New(), []uuid.UUID{withEndpoint, noEndpoint}, "", RunFrom{Mode: RunFromPlatform}, false); err != nil {
		t.Fatal(err)
	}
	f.cluster.scanThenFail(f.cluster.jobFor("10.0.0.25"))
	f.cluster.scanThenFail(f.cluster.jobFor("10.0.0.26"))
	f.finish()
	if at, status := f.endpoint(withEndpoint); !at.Valid || status.String != "completed" {
		t.Fatalf("endpoint = %v %q, want completed — its host was scanned", at, status.String)
	}
	list := f.unscanned()
	for _, id := range []uuid.UUID{withEndpoint, noEndpoint} {
		if _, ok := list[id]; ok {
			t.Fatalf("asset %s still unscanned though its host was scanned", id)
		}
	}
}

// An asset whose earlier scan completed keeps its scan time through a later
// scan that fails: a failure is not evidence the asset was never scanned.
func TestIntegration_ActiveScan_ALaterFailureKeepsTheEarlierScan(t *testing.T) {
	f := newFinishFixture(t)
	noEndpoint := f.asset("10.0.0.31", 0)
	if _, err := f.svc.CreateActiveScanJob(f.tenant, uuid.New(), []uuid.UUID{noEndpoint}, "", RunFrom{Mode: RunFromPlatform}, false); err != nil {
		t.Fatal(err)
	}
	f.cluster.complete(f.cluster.jobFor("10.0.0.31"))
	f.finish()
	if _, ok := f.unscanned()[noEndpoint]; ok {
		t.Fatal("still unscanned after a completed scan")
	}
	if _, err := f.svc.CreateActiveScanJob(f.tenant, uuid.New(), []uuid.UUID{noEndpoint}, "", RunFrom{Mode: RunFromPlatform}, false); err != nil {
		t.Fatal(err)
	}
	f.cluster.failStale(f.cluster.jobFor("10.0.0.31"))
	f.finish()
	if _, ok := f.unscanned()[noEndpoint]; ok {
		t.Fatal("a failed rescan put a scanned asset back on the unscanned list")
	}
	got, err := f.assets.GetAssetByID(f.tenant, noEndpoint)
	if err != nil || got.ActiveScan == nil || got.ActiveScan.Status != "failed" {
		t.Fatalf("active_scan = %+v (%v), want the rescan recorded as failed", got.ActiveScan, err)
	}
}

// A dispatch that fails leaves no `scanning` behind and no record: the asset
// stays on the list.
func TestIntegration_ActiveScan_DispatchFailureLeavesNothingScanning(t *testing.T) {
	f := newFinishFixture(t)
	f.cluster.refuse = true
	withEndpoint := f.asset("10.0.0.41", 443)
	if _, err := f.svc.CreateActiveScanJob(f.tenant, uuid.New(), []uuid.UUID{withEndpoint}, "", RunFrom{Mode: RunFromPlatform}, false); err == nil {
		t.Fatal("CreateActiveScanJob succeeded against a cluster-sensor-service that refused")
	}
	if at, status := f.endpoint(withEndpoint); at.Valid || status.String != "failed" {
		t.Fatalf("endpoint = %v %q, want no scan time and `failed`", at, status.String)
	}
	a, ok := f.unscanned()[withEndpoint]
	if !ok || a.ActiveScan != nil {
		t.Fatalf("on list=%v active_scan=%+v, want listed with no scan record", ok, a.ActiveScan)
	}
}

// A revalidation (the stale-asset sweep's job, always run from the platform
// and so always planned) is recorded and settled the same way.
func TestIntegration_Revalidation_IsRecordedAsFinished(t *testing.T) {
	f := newFinishFixture(t)
	withEndpoint := f.asset("10.0.0.51", 443)
	if _, err := f.svc.CreateRevalidationJob(f.tenant, uuid.New(), []uuid.UUID{withEndpoint}, ""); err != nil {
		t.Fatal(err)
	}
	if _, status := f.endpoint(withEndpoint); status.String != "scanning" {
		t.Fatalf("revalidation did not mark the endpoint scanning: %q", status.String)
	}
	f.cluster.complete(f.cluster.jobFor("10.0.0.51"))
	if done := f.finish(); done.Assets != 1 || done.Endpoints != 1 {
		t.Fatalf("settled %+v, want 1 asset and 1 endpoint", done)
	}
	if at, status := f.endpoint(withEndpoint); !at.Valid || status.String != "completed" {
		t.Fatalf("endpoint = %v %q, want completed", at, status.String)
	}
	if _, ok := f.unscanned()[withEndpoint]; ok {
		t.Fatal("still unscanned after the revalidation completed")
	}
}

// An Active Scan run from a tenant sensor that lacks scan_plan_v1 is the one
// place a LEGACY job can still be created (since WP5 the platform always
// plans): no scan plan, no units, and target rows the old sensor never moves
// off `pending`. Once the job completes, its targets count as scanned.
func TestIntegration_ActiveScan_LegacySensorJobIsRecordedAsFinished(t *testing.T) {
	f := newFinishFixture(t)
	f.cluster.planned = false
	beat := time.Now()
	sensor := sensorrouting.Sensor{ID: uuid.New(), Name: "old-sensor", Status: "active", LastHeartbeat: &beat, ReportingInterval: 30}
	f.svc.router = fixedRouter{sensor: sensor}
	withEndpoint := f.asset("10.0.0.52", 443)
	noEndpoint := f.asset("10.0.0.53", 0)
	if _, err := f.svc.CreateActiveScanJob(f.tenant, uuid.New(), []uuid.UUID{withEndpoint, noEndpoint}, "", RunFrom{Mode: RunFromSensor, SensorID: sensor.ID}, false); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"10.0.0.52", "10.0.0.53"} {
		f.cluster.exec(`UPDATE discovery_jobs SET status = 'completed', started_at = NOW(), completed_at = NOW() WHERE id = $1`, f.cluster.jobFor(addr).id)
	}
	if done := f.finish(); done.Assets != 2 || done.Endpoints != 1 {
		t.Fatalf("settled %+v, want 2 assets and 1 endpoint", done)
	}
	if at, status := f.endpoint(withEndpoint); !at.Valid || status.String != "completed" {
		t.Fatalf("endpoint = %v %q, want completed", at, status.String)
	}
	list := f.unscanned()
	for _, id := range []uuid.UUID{withEndpoint, noEndpoint} {
		if _, ok := list[id]; ok {
			t.Fatalf("asset %s still unscanned after its legacy sensor job completed", id)
		}
	}
}

// An endpoint an older build marked `scanning` — scan time written at
// dispatch, no job list on the asset — is settled from the job that build
// dispatched, and a stamp with no job to be found is failed after a day.
//
// The job is matched by origin as cluster-sensor-service actually records it:
// "manual" for every job a person's credentials created, and no origin at all
// on rows from builds before that. An automatic or identity-probe job for the
// same address and port is never taken for the person's scan.
func TestIntegration_ActiveScan_SettlesEndpointsStampedByAnOlderBuild(t *testing.T) {
	f := newFinishFixture(t)
	stampedAt := time.Now().Add(-10 * time.Minute)
	stamp := func(asset uuid.UUID, at time.Time) {
		f.cluster.exec(`UPDATE asset_endpoints SET last_scanned_at = $2, last_scan_status = 'scanning' WHERE asset_id = $1`, asset, at)
	}
	job := func(addr, status, options string) {
		id := uuid.New()
		var completed any
		if status == "completed" {
			completed = time.Now()
		}
		f.cluster.exec(`INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, created_at, completed_at, metadata) VALUES ($1, $2, 'async', $3, $4, $5, jsonb_build_object('options', $6::jsonb))`,
			id, f.tenant, status, stampedAt.Add(time.Second), completed, options)
		f.cluster.exec(`INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports, status) VALUES ($1, $2, $3, '{}', '{443}', $4)`,
			id, f.tenant, addr, map[bool]string{true: "completed", false: "running"}[status == "completed"])
	}
	manual := f.asset("10.0.0.61", 443)    // the real shape: origin "manual"
	noOrigin := f.asset("10.0.0.63", 443)  // a row from before origin was stamped
	running := f.asset("10.0.0.64", 443)   // its person's job is still running
	automatic := f.asset("10.0.0.65", 443) // only an automatic job and an identity probe match
	orphan := f.asset("10.0.0.62", 443)    // no job at all, stamped two days ago
	for _, a := range []uuid.UUID{manual, noOrigin, running, automatic} {
		stamp(a, stampedAt)
	}
	stamp(orphan, time.Now().Add(-48*time.Hour))
	job("10.0.0.61", "completed", `{"active_scan":true,"origin":"manual"}`)
	job("10.0.0.63", "completed", `{"active_scan":true}`)
	job("10.0.0.64", "running", `{"active_scan":true,"origin":"manual"}`)
	job("10.0.0.65", "completed", `{"active_scan":true,"origin":"auto_scan"}`)
	job("10.0.0.65", "completed", `{"active_scan":true,"origin":"identity_enrichment"}`)

	if done := f.finish(); done.Endpoints != 3 {
		t.Fatalf("settled %+v, want 3 endpoints (manual, no origin, orphan)", done)
	}
	for _, c := range []struct {
		name  string
		asset uuid.UUID
		want  string
	}{
		{"origin manual, job completed", manual, "completed"},
		{"no origin (older rows), job completed", noOrigin, "completed"},
		{"job still running", running, "scanning"},
		{"only automatic / identity jobs match", automatic, "scanning"},
		{"no job, stamped two days ago", orphan, "failed"},
	} {
		if _, status := f.endpoint(c.asset); status.String != c.want {
			t.Errorf("%s: endpoint = %q, want %q", c.name, status.String, c.want)
		}
	}

	// Idempotent: a second pass settles nothing more and changes nothing.
	if done := f.finish(); done.Endpoints != 0 || done.Assets != 0 {
		t.Fatalf("a second pass settled %+v", done)
	}
}
