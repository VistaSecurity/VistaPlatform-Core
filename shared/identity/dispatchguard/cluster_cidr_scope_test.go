package dispatchguard

// A tenant user's scan of the platform's own pod and Service ranges.
//
// RFC 1918 space is the tenant's by address class, and a cluster's pod and
// Service CIDRs are RFC 1918, so LoadTargetScope's private allowance admitted a
// scan of 10.43.0.0/16 — the Platform Sensor would then port-scan Postgres,
// Redis, NATS and every other Service and the job results returned what it
// found. The chart hands the cluster's own ranges to the service as
// VISTA_PLATFORM_INTERNAL_CIDRS; this drives LoadTargetScope ITSELF (not a
// hand-built TargetScope) against a stand-in database and asserts they are
// excluded, with a control that they are not when the variable is absent.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"testing"

	"github.com/google/uuid"
)

// emptyTenantDriver answers LoadTargetScope's two reads for a tenant with no
// saved restrictions and no registered segments.
type emptyTenantDriver struct{}

func (emptyTenantDriver) Open(string) (driver.Conn, error) { return emptyTenantConn{}, nil }

type emptyTenantConn struct{}

func (emptyTenantConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (emptyTenantConn) Close() error                        { return nil }
func (emptyTenantConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (emptyTenantConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if contains(query, "tenant_admin_settings") {
		return &rowsOf{cols: []string{"config"}}, nil // no row: sql.ErrNoRows
	}
	return &rowsOf{cols: []string{"segments"}, data: [][]driver.Value{{[]byte("[]")}}}, nil
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

type rowsOf struct {
	cols []string
	data [][]driver.Value
	i    int
}

func (r *rowsOf) Columns() []string { return r.cols }
func (r *rowsOf) Close() error      { return nil }
func (r *rowsOf) Next(dest []driver.Value) error {
	if r.i >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.i])
	r.i++
	return nil
}

func init() { sql.Register("dispatchguard-empty-tenant", emptyTenantDriver{}) }

func loadEmptyTenantScope(t *testing.T) TargetScope {
	t.Helper()
	db, err := sql.Open("dispatchguard-empty-tenant", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scope, err := LoadTargetScope(db, uuid.NewString())
	if err != nil {
		t.Fatalf("LoadTargetScope: %v", err)
	}
	return scope
}

func TestForPlatformSensor_ExcludesTheClustersOwnRanges(t *testing.T) {
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", "10.42.0.0/16,10.43.0.0/16")
	t.Setenv("DISCOVERY_AUTO_SCAN_EXCLUDE_CIDRS", "")
	scope := loadEmptyTenantScope(t).ForPlatformSensor()

	for _, target := range []string{"10.43.0.1", "10.43.0.0/16", "10.42.7.9", "10.42.0.0/24"} {
		if err := scope.Authorize(target); err == nil {
			t.Errorf("a Platform Sensor scan of the cluster's own range %s was authorized", target)
		}
	}
	// The rest of RFC 1918 is still the tenant's own: refusing it would be the
	// over-strict failure, since scanning the customer's network is the job.
	for _, target := range []string{"10.44.0.1", "10.0.0.0/24", "192.168.1.10"} {
		if err := scope.Authorize(target); err != nil {
			t.Errorf("customer private address %s was refused: %v", target, err)
		}
	}
}

// The other polarity, with the variable SET: the scope a tenant's own sensor's
// scan is judged against (LoadTargetScope, no ForPlatformSensor) must still
// authorize those numbers — to that sensor they are the customer's LAN.
func TestLoadTargetScope_DoesNotRefuseTheClusterRangesForATenantSensor(t *testing.T) {
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", "10.42.0.0/16,10.43.0.0/16")
	t.Setenv("DISCOVERY_AUTO_SCAN_EXCLUDE_CIDRS", "")
	scope := loadEmptyTenantScope(t)

	for _, target := range []string{"10.43.0.10", "10.42.7.9", "10.43.0.0/24"} {
		if err := scope.Authorize(target); err != nil {
			t.Errorf("%s was refused for a tenant sensor: %v", target, err)
		}
	}
}

// AuthorizeAndClassifyManualTargets is the creation door; PlatformExecutor is
// what selects the platform scope. Both values, variable set.
func TestAuthorizeAndClassifyManualTargets_PlatformExecutorSelectsTheClusterExclusion(t *testing.T) {
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", "10.43.0.0/16")
	t.Setenv("DISCOVERY_AUTO_SCAN_EXCLUDE_CIDRS", "")
	db, err := sql.Open("dispatchguard-empty-tenant", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	targets, err := ParseManualTargets([]string{"10.43.0.10"})
	if err != nil {
		t.Fatal(err)
	}
	resolved := make([]ResolvedTarget, len(targets))
	for i, mt := range targets {
		resolved[i] = ResolvedTarget{ManualTarget: mt}
	}

	_, _, err = AuthorizeAndClassifyManualTargets(db, uuid.NewString(), resolved, ManualOptions{PlatformExecutor: true})
	if err == nil {
		t.Error("a platform-executed scan of the cluster's own range was authorized")
	}
	if _, _, err = AuthorizeAndClassifyManualTargets(db, uuid.NewString(), resolved, ManualOptions{PlatformExecutor: false}); err != nil {
		t.Errorf("the same scan on a tenant sensor was refused: %v", err)
	}
}
