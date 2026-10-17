package services

// Rate-limit configuration cannot break job creation; the per-tenant target cap
// and the concurrency limits are enforced, atomically; a failure to find the
// sensor findings are queued under fails the unit instead of dropping them from
// the inventory feed; per-unit authorization reads its tenant-level state once
// per unitScopeTTL. Skip without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

func (f *dispatchFixture) platformJobRequest(targets ...string) models.CreateDiscoveryJobRequest {
	return models.CreateDiscoveryJobRequest{Targets: targets, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "auto"}
}

// A stored limits row that is switched off, or that holds values no request
// could meet, must not stop jobs being created: the defaults apply. An inactive
// row used to be invisible to the reader, so the default insert hit ON CONFLICT,
// the re-read found nothing and CreateJob / the processor failed on sql.ErrNoRows.
func TestIntegration_RateLimit_InactiveOrZeroedRowFallsBackToDefaults(t *testing.T) {
	for name, row := range map[string]string{
		"inactive":            `100, 5, 1000, false`,
		"inactive and zeroed": `0, 0, 0, false`,
		"zero concurrency":    `100, 0, 1000, true`,
		"zero scans":          `0, 5, 1000, true`,
		"zero targets":        `100, 5, 0, true`,
		"inactive and tight":  `1, 1, 1, false`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newDispatchFixture(t)
			if _, err := f.raw.Exec(`INSERT INTO discovery_rate_limits (tenant_id, scans_per_hour, concurrent_jobs, max_targets_per_job, is_active)
				VALUES ($1, `+row+`)`, f.tenant); err != nil {
				t.Fatal(err)
			}
			tenant := f.tenant.String()
			// Two jobs of two targets each: a tight inactive row, if honoured,
			// would refuse the second job and the second target.
			for i := 0; i < 2; i++ {
				if _, err := f.svc.CreateJob(tenant, f.tenantUser(t), f.platformJobRequest("10.188.0.10", "10.188.0.11")); err != nil {
					t.Fatalf("CreateJob %d with a %s limits row: %v", i+1, name, err)
				}
			}
			if err := f.jp.rateLimiter.CheckRateLimit(tenant); err != nil {
				t.Fatalf("CheckRateLimit: %v", err)
			}
			if _, err := f.jp.rateLimiter.GetRateLimit(tenant); err != nil {
				t.Fatalf("GetRateLimit: %v", err)
			}
		})
	}
}

// max_targets_per_job is enforced: the lower of the tenant's value and 1000.
func TestIntegration_RateLimit_MaxTargetsPerJobIsEnforced(t *testing.T) {
	f := newDispatchFixture(t)
	f.setLimits(t, 1000, 1000, 2)
	tenant, user := f.tenant.String(), f.tenantUser(t)

	var tooMany *TooManyTargetsError
	_, err := f.svc.CreateJob(tenant, user, f.platformJobRequest("10.188.1.1", "10.188.1.2", "10.188.1.3"))
	if !errors.As(err, &tooMany) || tooMany.Max != 2 {
		t.Fatalf("3 targets against max_targets_per_job=2: err = %v, want *TooManyTargetsError{Max: 2}", err)
	}
	if _, err := f.svc.CreateJob(tenant, user, f.platformJobRequest("10.188.1.1", "10.188.1.2")); err != nil {
		t.Fatalf("2 targets against max_targets_per_job=2: %v", err)
	}

	// A tenant value above the platform ceiling does not raise it.
	f.setLimits(t, 1000, 1000, 5000)
	if got := f.jp.rateLimiter.MaxTargetsFor(tenant); got != 1000 {
		t.Fatalf("MaxTargetsFor with a stored 5000 = %d, want the 1000 ceiling", got)
	}
	targets := make([]string, 1001)
	for i := range targets {
		targets[i] = "10.188.2.1"
	}
	if _, err := f.svc.CreateJob(tenant, user, f.platformJobRequest(targets...)); !errors.As(err, &tooMany) || tooMany.Max != 1000 {
		t.Fatalf("1001 targets: err = %v, want *TooManyTargetsError{Max: 1000}", err)
	}
}

// The limit check and the insert are one atomic step per tenant: twenty
// simultaneous creates against concurrent_jobs = 3 admit exactly three.
func TestIntegration_RateLimit_ConcurrentCreatesRespectConcurrentJobs(t *testing.T) {
	f := newDispatchFixture(t)
	f.setLimits(t, 1000, 3, 1000)
	tenant, user := f.tenant.String(), f.tenantUser(t)

	const attempts = 20
	var wg sync.WaitGroup
	gate := make(chan struct{})
	errs := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			_, err := f.svc.CreateJob(tenant, user, f.platformJobRequest("10.188.3.10"))
			errs <- err
		}()
	}
	close(gate)
	wg.Wait()
	close(errs)
	ok, refused := 0, 0
	for err := range errs {
		var limit *RateLimitExceededError
		switch {
		case err == nil:
			ok++
		case errors.As(err, &limit):
			refused++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 3 || refused != attempts-3 {
		t.Fatalf("%d created, %d refused; want 3 and %d", ok, refused, attempts-3)
	}
	var queued int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM discovery_jobs WHERE tenant_id = $1`, f.tenant).Scan(&queued); err != nil || queued != 3 {
		t.Fatalf("jobs stored = %d (%v), want 3", queued, err)
	}
}

// scans_per_hour is counted in the same transaction.
func TestIntegration_RateLimit_ScansPerHourEnforcedAtCreate(t *testing.T) {
	f := newDispatchFixture(t)
	f.setLimits(t, 2, 1000, 1000)
	tenant, user := f.tenant.String(), f.tenantUser(t)
	for i := 0; i < 2; i++ {
		if _, err := f.svc.CreateJob(tenant, user, f.platformJobRequest("10.188.4.10")); err != nil {
			t.Fatal(err)
		}
	}
	var limit *RateLimitExceededError
	if _, err := f.svc.CreateJob(tenant, user, f.platformJobRequest("10.188.4.10")); !errors.As(err, &limit) || limit.Limit != "scans this hour" {
		t.Fatalf("third create: err = %v, want a scans-this-hour refusal", err)
	}
}

// A partial PUT keeps what it does not name; a tenant with no row yet gets one.
func TestIntegration_RateLimit_UpdateIsPartialAndUpserts(t *testing.T) {
	f := newDispatchFixture(t)
	tenant := f.tenant.String()
	n := func(v int) *int { return &v }
	if err := f.jp.rateLimiter.UpdateRateLimit(tenant, models.RateLimitConfigRequest{ConcurrentJobs: n(7)}); err != nil {
		t.Fatal(err)
	}
	got, err := f.jp.rateLimiter.GetRateLimit(tenant)
	if err != nil || got.ConcurrentJobs != 7 || got.ScansPerHour != 100 || got.MaxTargetsPerJob != 1000 || !got.IsActive {
		t.Fatalf("after a first partial PUT: %+v, %v; want concurrent 7, the rest default", got, err)
	}
	if err := f.jp.rateLimiter.UpdateRateLimit(tenant, models.RateLimitConfigRequest{ScansPerHour: n(9)}); err != nil {
		t.Fatal(err)
	}
	got, _ = f.jp.rateLimiter.GetRateLimit(tenant)
	if got.ConcurrentJobs != 7 || got.ScansPerHour != 9 {
		t.Fatalf("a PUT naming only scans_per_hour changed the rest: %+v", got)
	}
}

// A unit whose findings cannot be queued for inventory fails, retryably, with a
// note a person can act on. It used to commit `done` with the findings only in
// the job record, the job completed, and Retry skipped the done unit.
func TestIntegration_PlanUnits_MirrorSensorMissingFailsTheUnitRetryably(t *testing.T) {
	f, fake := newUnitFixture(t)
	const addr = "10.188.5.10"
	fake.Host(addr, map[uint16]string{443: f.banner}, nil)
	jobID := f.createPlatformJob(t, addr)
	if _, err := f.raw.Exec(`DELETE FROM sensors WHERE tenant_id = $1 AND profile = 'discovery'`, f.tenant); err != nil {
		t.Fatal(err)
	}
	_ = f.jp.processDiscoveryJobByID(jobID)
	st := f.unitStatuses(t, jobID)
	if st[addr] != unitFailed {
		t.Fatalf("units = %v: the unit whose findings could not be queued must be failed, not done", st)
	}
	var note string
	if err := f.raw.QueryRow(`SELECT error_message FROM discovery_job_units WHERE job_id = $1`, jobID).Scan(&note); err != nil || !strings.Contains(note, "Platform Sensor") {
		t.Fatalf("unit note = %q (%v), want one naming the Platform Sensor", note, err)
	}
	if n := f.findingCount(t, jobID); n != 0 {
		t.Fatalf("findings = %d: a failed commit must store nothing", n)
	}
	// The job fails with a note naming the cause, rather than completing.
	if status, msg := f.jobStatusAndError(t, jobID); status != "failed" || !strings.Contains(msg, "Platform Sensor") {
		t.Fatalf("job = %q / %q, want failed with a note naming the Platform Sensor", status, msg)
	}

	// Once the sensor exists, Retry runs the unit again and the feed gets it.
	if _, err := f.raw.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, tags, ip_address, reporting_interval, last_heartbeat)
		VALUES ($1, $2, 'Platform Discovery Sensor', 'platform', '1.0.0', 'discovery', 'active', '{system}', '10.0.0.1', 30, NOW())`, uuid.New(), f.tenant); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RequeueJobForRetry(jobID); err != nil {
		t.Fatalf("RequeueJobForRetry: %v", err)
	}
	if err := f.jp.processDiscoveryJobByID(jobID); err != nil {
		t.Fatal(err)
	}
	if status := f.jobStatus(t, jobID); status != "completed" {
		t.Fatalf("retried job = %q, want completed", status)
	}
	if st := f.unitStatuses(t, jobID); st[addr] != unitDone {
		t.Fatalf("after Retry units = %v, want done", st)
	}
	var mirrored int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM sensor_discoveries WHERE tenant_id = $1`, f.tenant).Scan(&mirrored); err != nil || mirrored == 0 {
		t.Fatalf("sensor_discoveries rows = %d (%v): the retried unit's findings never reached the inventory feed", mirrored, err)
	}
}

// countingDB is a second handle on the test database that records every
// statement and transaction start, so a test can assert how many round trips
// an operation costs.
type queryLog struct {
	mu    sync.Mutex
	stmts []string
}

func (l *queryLog) add(s string) {
	l.mu.Lock()
	l.stmts = append(l.stmts, s)
	l.mu.Unlock()
}

func (l *queryLog) total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.stmts)
}

func (l *queryLog) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.stmts {
		if strings.Contains(s, substr) {
			n++
		}
	}
	return n
}

type countingDriver struct{ log *queryLog }

func (d countingDriver) Open(name string) (driver.Conn, error) {
	c, err := (&pq.Driver{}).Open(name)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: c, log: d.log}, nil
}

type countingConn struct {
	driver.Conn
	log *queryLog
}

func (c *countingConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.log.add("BEGIN")
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}

func (c *countingConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.log.add(q)
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func (c *countingConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.log.add(q)
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}

var countingDrivers atomic.Int64

// countedProcessor is a JobProcessor over the fixture's database whose every
// statement is logged.
func (f *dispatchFixture) countedProcessor(t *testing.T) (*JobProcessor, *queryLog) {
	t.Helper()
	log := &queryLog{}
	name := fmt.Sprintf("pgcount-%d", countingDrivers.Add(1))
	sql.Register(name, countingDriver{log: log})
	raw, err := sql.Open(name, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	db := sqlx.NewDb(raw, "postgres")
	jp := &JobProcessor{db: db, bypassDB: db, discoveryService: f.svc, rateLimiter: f.jp.rateLimiter, planEngineOptions: f.jp.planEngineOptions}
	jp.ctx, jp.cancel = context.WithCancelCause(context.Background())
	return jp, log
}

// Unit authorization reads the automatic-scan policy and segments once per
// unitScopeTTL, not once per unit — and re-reads them when the TTL passes, so a
// pause still stops the scan.
func TestIntegration_UnitAuthorizer_AutomaticScopeIsCachedPerTTL(t *testing.T) {
	f, _ := newUnitFixture(t)
	jp, log := f.countedProcessor(t)
	tenant := f.tenant.String()
	if _, err := f.raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{}') ON CONFLICT(tenant_id) DO UPDATE SET config='{}'`, f.tenant); err != nil {
		t.Fatal(err)
	}
	addrs := []string{"10.188.6.10", "10.188.6.11", "10.188.6.12", "10.188.6.13"}
	for _, a := range addrs {
		if _, err := f.raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,$3,$4,'server','hardware.computer.server','monitoring')`, uuid.New(), f.tenant, "h-"+a, a); err != nil {
			t.Fatal(err)
		}
	}
	tcp, err := shareddisc.NewPortSet(443)
	if err != nil {
		t.Fatal(err)
	}
	tg := &planTarget{tcp: tcp, depth: shareddisc.DepthCustom}
	auth := &unitAuthorizer{jp: jp, tenantID: tenant, options: map[string]interface{}{"origin": "auto_scan"}, platformExecutor: true}

	for _, a := range addrs {
		if err := auth.authorizeUnit(tg, a); err != nil {
			t.Fatalf("authorizeUnit(%s): %v", a, err)
		}
	}
	// Two scopes read the policy row FOR SHARE: the target scope and the
	// automatic-scan scope. Each once, however many units.
	if n := log.count("FOR SHARE"); n != 2 {
		t.Fatalf("policy row read %d times for %d units, want 2 (one per scope)", n, len(addrs))
	}
	if n := log.count("FROM prefixes"); n > 2 { // 1 automatic scope + 1 target scope
		t.Fatalf("prefixes read %d times for %d units, want once per scope", n, len(addrs))
	}

	// Within the TTL a pause is not yet seen (the trade the manual path makes);
	// past it, it is, and the next unit is refused.
	if _, err := f.raw.Exec(`UPDATE tenant_admin_settings SET config='{"identity_admission":{"mode":"paused"}}' WHERE tenant_id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if err := auth.authorizeUnit(tg, addrs[0]); err != nil {
		t.Fatalf("within the TTL the cached scope should still serve: %v", err)
	}
	old := unitScopeTTL
	unitScopeTTL = time.Millisecond
	t.Cleanup(func() { unitScopeTTL = old })
	time.Sleep(5 * time.Millisecond)
	if err := auth.authorizeUnit(tg, addrs[0]); err == nil {
		t.Fatal("after the TTL the pause was not seen")
	}
	if n := log.count("FOR SHARE"); n != 4 {
		t.Fatalf("policy reads = %d, want 4 (both scopes loaded once, both re-read once after expiry)", n)
	}
}

// ensureUnits reads the job's grants and which targets have units once for the
// whole job: the read cost no longer grows with the target count.
func TestIntegration_EnsureUnits_GrantsAreReadOncePerJob(t *testing.T) {
	f, _ := newUnitFixture(t)
	f.setLimits(t, 1000, 1000, 1000)
	cost := func(n int, base int) int {
		targets := make([]string, n)
		for i := range targets {
			targets[i] = fmt.Sprintf("10.188.%d.%d", 10+base, 10+i)
		}
		jobID := f.createPlatformJob(t, targets...)
		job, _ := f.svc.GetJob(jobID)
		jp, log := f.countedProcessor(t)
		run, planTargets, err := jp.newPlanRun(job, nil)
		if err != nil {
			t.Fatal(err)
		}
		before := log.total()
		if err := jp.ensureUnits(job, planTargets, run.auth); err != nil {
			t.Fatal(err)
		}
		if st := f.unitStatuses(t, jobID); len(st) != n {
			t.Fatalf("units = %v, want %d", st, n)
		}
		return log.total() - before
	}
	small, large := cost(5, 0), cost(25, 1)
	// Per target: the unit insert's transaction (3) and the settle's (3). The
	// grant and has-units reads used to add a transaction of 4 more per target.
	if perTarget := float64(large-small) / 20; perTarget > 6.5 {
		t.Fatalf("ensureUnits costs %.1f statements per extra target (5 targets: %d, 25 targets: %d), want 6 (insert + settle)", perTarget, small, large)
	}
}
