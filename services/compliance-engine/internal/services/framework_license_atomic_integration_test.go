package services

// Integration tests for the tenant framework-licence write paths: the cap is
// enforced atomically, cancelling keeps a valid default and fails closed, the
// default lookup is read-only, and one default exists per tenant.
//
// Skip unless TEST_DATABASE_URL is set (see shared/testdb).

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type licenceFixture struct {
	db     *sqlx.DB
	svc    *FrameworkLicenseService
	tenant uuid.UUID
	bp     uuid.UUID
	jobsMu sync.Mutex
	jobs   []ReconcileJob
}

// newLicenceFixture makes a tenant (which the DB trigger gives Best Practices
// as default) with compliance_frameworks_max overridden to cap.
func newLicenceFixture(t *testing.T, cap int) *licenceFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	f := &licenceFixture{db: sqlx.NewDb(raw, "postgres"), tenant: testdb.NewTenant(t, raw)}
	f.svc = NewFrameworkLicenseService(f.db)
	f.svc.SetReconcileEnqueuer(&ReconcileEnqueuer{sink: func(j ReconcileJob) {
		f.jobsMu.Lock()
		defer f.jobsMu.Unlock()
		f.jobs = append(f.jobs, j)
	}})
	if err := raw.QueryRow(`SELECT id FROM platform_frameworks WHERE is_platform_default AND status = 'published'`).Scan(&f.bp); err != nil {
		t.Fatalf("Best Practices framework: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		SELECT $1,id,jsonb_build_object('quantity',$2::int),'licence atomicity test'
		  FROM billable_items WHERE key='compliance_frameworks_max'`, f.tenant, cap); err != nil {
		t.Fatalf("set cap: %v", err)
	}
	return f
}

// paidFramework inserts a published, non-free platform framework.
func (f *licenceFixture) paidFramework(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO platform_frameworks (id, code, name, version, organization, status, is_platform_default, created_by)
		VALUES ($1, $2, $3, '1.0', 'IT Org', 'published', false, '00000000-0000-0000-0000-000000000001')`,
		id, "it-paid-"+id.String()[:8], "IT Paid "+id.String()[:8]); err != nil {
		t.Fatalf("insert paid framework: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.db.Exec(`DELETE FROM tenant_framework_licenses WHERE platform_framework_id = $1`, id)
		_, _ = f.db.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, id)
	})
	return id
}

func (f *licenceFixture) subscribe(id uuid.UUID, asDefault bool) error {
	return f.svc.SubscribeFramework(f.tenant, models.ProvisionFrameworkInput{
		FrameworkID: id.String(), ProvisionedBy: "self_service", SetAsDefault: asDefault,
	}, uuid.New())
}

func (f *licenceFixture) defaults(t *testing.T) []uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	rows, err := f.db.Query(`SELECT platform_framework_id FROM tenant_framework_licenses WHERE tenant_id = $1 AND is_default`, f.tenant)
	if err != nil {
		t.Fatalf("read defaults: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func (f *licenceFixture) licenceCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM tenant_framework_licenses WHERE tenant_id = $1`, f.tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *licenceFixture) status(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := f.db.QueryRow(`SELECT subscription_status FROM tenant_framework_licenses WHERE tenant_id = $1 AND platform_framework_id = $2`, f.tenant, id).Scan(&s); err != nil {
		t.Fatalf("status of %s: %v", id, err)
	}
	return s
}

func (f *licenceFixture) jobReasons() []string {
	f.jobsMu.Lock()
	defer f.jobsMu.Unlock()
	var r []string
	for _, j := range f.jobs {
		r = append(r, j.Reason)
	}
	return r
}

func TestIntegration_SetAsDefaultClearsPreviousDefault(t *testing.T) {
	f := newLicenceFixture(t, 5)
	a, b := f.paidFramework(t), f.paidFramework(t)

	if got := f.defaults(t); len(got) != 1 || got[0] != f.bp {
		t.Fatalf("premise: new tenant default = %v, want Best Practices", got)
	}
	if err := f.subscribe(a, true); err != nil {
		t.Fatalf("subscribe A as default: %v", err)
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != a {
		t.Fatalf("defaults after A = %v, want exactly [A]", got)
	}
	if err := f.subscribe(b, true); err != nil {
		t.Fatalf("subscribe B as default: %v", err)
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != b {
		t.Fatalf("defaults after B = %v, want exactly [B] (the old default must be cleared)", got)
	}

	// Re-subscribe is idempotent: cancel A, subscribe again without asking for
	// the default — A comes back active, B keeps the default.
	if err := f.svc.CancelSubscription(f.tenant, a); err != nil {
		t.Fatalf("cancel A: %v", err)
	}
	if err := f.subscribe(a, false); err != nil {
		t.Fatalf("re-subscribe A: %v", err)
	}
	if f.status(t, a) != "active" {
		t.Error("re-subscribed licence is not active")
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != b {
		t.Fatalf("defaults after re-subscribe = %v, want [B]", got)
	}
	// And re-subscribing AS default moves it, again leaving exactly one.
	if err := f.svc.CancelSubscription(f.tenant, a); err != nil {
		t.Fatal(err)
	}
	if err := f.subscribe(a, true); err != nil {
		t.Fatalf("re-subscribe A as default: %v", err)
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != a {
		t.Fatalf("defaults after re-subscribe as default = %v, want [A]", got)
	}
}

func TestIntegration_ConcurrentSubscribesRespectCap(t *testing.T) {
	const capN, attempts = 3, 20
	f := newLicenceFixture(t, capN)
	ids := make([]uuid.UUID, attempts)
	for i := range ids {
		ids[i] = f.paidFramework(t)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for _, id := range ids {
		wg.Add(1)
		go func(id uuid.UUID) {
			defer wg.Done()
			<-start
			if err := f.subscribe(id, false); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(id)
	}
	close(start)
	wg.Wait()

	var active int
	if err := f.db.QueryRow(`
		SELECT COUNT(*) FROM tenant_framework_licenses tfl
		JOIN platform_frameworks pf ON pf.id = tfl.platform_framework_id
		WHERE tfl.tenant_id = $1 AND tfl.subscription_status = 'active' AND NOT pf.is_platform_default`, f.tenant).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != capN || ok != capN {
		t.Fatalf("%d concurrent subscribes against cap %d: %d succeeded, %d paid licences active; want exactly %d of each", attempts, capN, ok, active, capN)
	}
}

func TestIntegration_SelectFrameworksIsCappedSingleDefaultAndReconciles(t *testing.T) {
	f := newLicenceFixture(t, 3)
	a, b, c, d := f.paidFramework(t), f.paidFramework(t), f.paidFramework(t), f.paidFramework(t)

	if err := f.svc.SelectFrameworks(f.tenant, []uuid.UUID{a, b, c, d}, a, uuid.New()); !errors.Is(err, ErrFrameworkLimitExceeded) {
		t.Fatalf("4 paid frameworks against cap 3: err = %v, want ErrFrameworkLimitExceeded", err)
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != f.bp {
		t.Fatalf("a refused selection changed the default: %v", got)
	}

	if err := f.svc.SelectFrameworks(f.tenant, []uuid.UUID{a, b}, b, uuid.New()); err != nil {
		t.Fatalf("SelectFrameworks: %v", err)
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != b {
		t.Fatalf("defaults = %v, want [B]", got)
	}
	// Selecting a different set with a different default must not trip the
	// one-default constraint on the cancelled rows' stale flag.
	if err := f.svc.SelectFrameworks(f.tenant, []uuid.UUID{c}, c, uuid.New()); err != nil {
		t.Fatalf("second SelectFrameworks: %v", err)
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != c {
		t.Fatalf("defaults = %v, want [C]", got)
	}
	if len(f.jobReasons()) == 0 {
		t.Fatal("SelectFrameworks enqueued no reconcile (SubscribeFramework does)")
	}
}

func TestIntegration_CancelDefaultMovesDefaultToBestPractices(t *testing.T) {
	f := newLicenceFixture(t, 5)
	a := f.paidFramework(t)
	if err := f.subscribe(a, true); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CancelSubscription(f.tenant, a); err != nil {
		t.Fatalf("cancel default: %v", err)
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != f.bp {
		t.Fatalf("defaults after cancelling the default = %v, want [Best Practices]", got)
	}
	var cancelledStillDefault bool
	if err := f.db.QueryRow(`SELECT is_default FROM tenant_framework_licenses WHERE tenant_id=$1 AND platform_framework_id=$2`, f.tenant, a).Scan(&cancelledStillDefault); err != nil || cancelledStillDefault {
		t.Fatalf("cancelled licence still flagged default (err=%v)", err)
	}
	d, err := f.svc.GetDefaultFramework(f.tenant)
	if err != nil || d.FrameworkID != f.bp.String() {
		t.Fatalf("GetDefaultFramework = %+v, %v; want Best Practices", d, err)
	}
	reasons := f.jobReasons()
	if len(reasons) == 0 || reasons[len(reasons)-1] != "framework_deactivated" {
		t.Fatalf("reconcile reasons = %v; cancel must enqueue framework_deactivated", reasons)
	}
}

func TestIntegration_CancelBestPracticesIsRefused(t *testing.T) {
	f := newLicenceFixture(t, 5)
	if err := f.svc.CancelSubscription(f.tenant, f.bp); err == nil {
		t.Fatal("cancelling Best Practices was allowed")
	}
	if f.status(t, f.bp) != "active" {
		t.Fatal("Best Practices licence is no longer active")
	}
}

// A failed Best Practices lookup must refuse the cancel, not wave it through.
// The service is pointed at a connection whose search_path resolves
// platform_frameworks to a shadow table without is_platform_default, so only
// that lookup errors; every other statement still works.
func TestIntegration_CancelFailsClosedOnLookupError(t *testing.T) {
	f := newLicenceFixture(t, 5)
	url0 := os.Getenv(testdb.URLEnv)
	schema := "shadow_" + f.tenant.String()[:8]
	if _, err := f.db.Exec(fmt.Sprintf(`CREATE SCHEMA %s`, schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.db.Exec(fmt.Sprintf(`DROP SCHEMA %s CASCADE`, schema)) })
	if _, err := f.db.Exec(fmt.Sprintf(`CREATE TABLE %s.platform_frameworks (id uuid)`, schema)); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(url0)
	if err != nil {
		t.Skipf("TEST_DATABASE_URL is not a URL: %v", err)
	}
	q := u.Query()
	q.Set("options", "-c search_path="+schema+",public")
	u.RawQuery = q.Encode()
	raw, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	broken := NewFrameworkLicenseService(sqlx.NewDb(raw, "postgres"))

	a := f.paidFramework(t)
	if err := f.subscribe(a, false); err != nil {
		t.Fatal(err)
	}
	// The error must come from the guard's own lookup, not from a later
	// statement that happens to fail on the same broken connection.
	if err := broken.CancelSubscription(f.tenant, a); err == nil || !strings.Contains(err.Error(), "check platform default framework") {
		t.Fatalf("cancel err = %v; want the Best Practices lookup failure to refuse it (fail-closed)", err)
	}
	if f.status(t, a) != "active" {
		t.Fatal("licence was cancelled despite the failed lookup")
	}
}

func TestIntegration_GetDefaultFrameworkIsReadOnly(t *testing.T) {
	f := newLicenceFixture(t, 5)
	a := f.paidFramework(t)
	if err := f.subscribe(a, false); err != nil {
		t.Fatal(err)
	}

	// Best Practices lapsed (cancelled directly, as an operator or an older
	// build could leave it) and no row is flagged default: the GET must fall
	// back to the remaining active licence and write nothing.
	if _, err := f.db.Exec(`UPDATE tenant_framework_licenses SET subscription_status='cancelled', is_default=false WHERE tenant_id=$1 AND platform_framework_id=$2`, f.tenant, f.bp); err != nil {
		t.Fatal(err)
	}
	before := f.licenceCount(t)
	d, err := f.svc.GetDefaultFramework(f.tenant)
	if err != nil || d.FrameworkID != a.String() {
		t.Fatalf("fallback default = %+v, %v; want the only active licence", d, err)
	}
	if after := f.licenceCount(t); after != before {
		t.Fatalf("GET inserted licences: %d -> %d", before, after)
	}
	if got := f.defaults(t); len(got) != 0 {
		t.Fatalf("GET wrote a default flag: %v", got)
	}

	// Nothing active at all: a typed error, still no write.
	if _, err := f.db.Exec(`UPDATE tenant_framework_licenses SET subscription_status='cancelled' WHERE tenant_id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetDefaultFramework(f.tenant); !errors.Is(err, ErrNoActiveFramework) {
		t.Fatalf("err = %v, want ErrNoActiveFramework", err)
	}
	if after := f.licenceCount(t); after != before {
		t.Fatalf("GET inserted licences: %d -> %d", before, after)
	}

	// The write path repairs it: subscribing re-activates Best Practices and,
	// with no active default, makes it the default.
	if err := f.subscribe(a, false); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if f.status(t, f.bp) != "active" {
		t.Error("subscribe did not repair the lapsed Best Practices licence")
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != f.bp {
		t.Fatalf("defaults after repair = %v, want [Best Practices]", got)
	}
}

// A freshly created tenant holds an active, default Best Practices licence
// from the tenants AFTER INSERT trigger alone: GetDefaultFramework is a pure
// read, so this trigger is what guarantees the licence exists.
func TestIntegration_NewTenantGetsBestPracticesViaTrigger(t *testing.T) {
	f := newLicenceFixture(t, 5)
	if f.status(t, f.bp) != "active" {
		t.Fatalf("Best Practices licence status = %q, want active", f.status(t, f.bp))
	}
	if got := f.defaults(t); len(got) != 1 || got[0] != f.bp {
		t.Fatalf("defaults = %v, want [Best Practices]", got)
	}
	before := f.licenceCount(t)
	d, err := f.svc.GetDefaultFramework(f.tenant)
	if err != nil || d.FrameworkID != f.bp.String() {
		t.Fatalf("GetDefaultFramework = %+v, %v; want Best Practices", d, err)
	}
	if after := f.licenceCount(t); after != before {
		t.Fatalf("GET changed licence count: %d -> %d", before, after)
	}
}

// With the Best Practices licence row absent entirely (a provisioning path
// that bypassed the trigger), a GET reports a typed not-found and does NOT
// repair it by inserting the row.
func TestIntegration_GetDefaultFrameworkDoesNotRepairMissingLicence(t *testing.T) {
	f := newLicenceFixture(t, 5)
	if _, err := f.db.Exec(`DELETE FROM tenant_framework_licenses WHERE tenant_id = $1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetDefaultFramework(f.tenant); !errors.Is(err, ErrNoActiveFramework) {
		t.Fatalf("err = %v, want ErrNoActiveFramework", err)
	}
	if n := f.licenceCount(t); n != 0 {
		t.Fatalf("GET inserted %d licence row(s); a read must not repair state", n)
	}
}
