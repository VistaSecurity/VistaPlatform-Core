package api

// The MSP soft cap on the self-signup path, driven through the REAL
// SetupRouter over a real database (edition-licensing spec §3, PR 3).
//
// shared/entitlements' own tests prove the cap's decision table. What only this
// can show is the wiring: that POST /auth/register and /auth/register/complete
// reach AdmitTenantCreation inside createTenant's transaction, on the
// production pools (crypto_app for the transaction, crypto_bypass for the grace
// clock), and that the refusal comes back as a 409 carrying the public refusal
// text rather than the generic 500. Delete the AdmitTenantCreation call from
// createTenant, or the IsTenantCapExceeded case from either handler, and a test
// here goes red.
//
// Each test uses its own scratch database: the cap counts every live tenant on
// the install and reads the one platform_license row, neither of which can be
// shared with concurrently running packages.
//
// Skips without TEST_DATABASE_URL (make test-integration-db / nightly).

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type signupCapEnv struct {
	owner  *sql.DB
	router *gin.Engine
	base   int
}

func newSignupCapEnv(t *testing.T) *signupCapEnv {
	t.Helper()
	owner := testdb.ScratchDatabase(t)
	app := testdb.ConnectScratchAsAppRole(t, owner)
	bypass := testdb.ConnectScratchAsBypassRole(t, owner)
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: "test-secret-tenant-cap-signup", JWTExpiry: time.Hour}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on the register path
	t.Cleanup(func() { _ = rdb.Close() })
	env := &signupCapEnv{owner: owner, router: SetupRouter(cfg, app, bypass, rdb, nil, EditionHooks{})}
	if err := owner.QueryRow(`SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL AND NOT is_operator`).Scan(&env.base); err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *signupCapEnv) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := e.owner.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// currentClockSQL reads the grace clock recorded under the licence in force.
const currentClockSQL = `SELECT g.grace_started_at FROM license_cap_grace g
	JOIN platform_license l ON l.license_id = g.license_id`

// licence installs a NEW licence (its own license_id, as a re-mint has) with
// max_tenants = base + slots (slots < 0: no cap).
func (e *signupCapEnv) licence(t *testing.T, edition string, slots, graceDays int) {
	t.Helper()
	var maxTenants any
	if slots >= 0 {
		maxTenants = e.base + slots
	}
	e.exec(t, `DELETE FROM platform_license`)
	e.exec(t, `INSERT INTO platform_license (subject, edition, expires_at, token_sha256, license_id, max_tenants, grace_days)
		VALUES ('it', $1, now() + interval '1 day', $4, $4, $2, $3)`, edition, maxTenants, graceDays, "lic-"+uuid.NewString())
}

// signup posts one registration to path and returns the status and error text.
func (e *signupCapEnv) signup(t *testing.T, path string) (int, string) {
	t.Helper()
	id := uuid.NewString()[:8]
	body := `{"email":"cap-` + id + `@example.test","password":"Cap!Signup-2026-x","first_name":"Cap","last_name":"Test","tenant_name":"Cap Co ` + id + `","accepted_legal":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	var out struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out.Error
}

func (e *signupCapEnv) mustSignUp(t *testing.T, path string) {
	t.Helper()
	if code, msg := e.signup(t, path); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("POST %s: %d %q, want success", path, code, msg)
	}
}

func (e *signupCapEnv) mustBeRefused(t *testing.T, path string) {
	t.Helper()
	code, msg := e.signup(t, path)
	if code != http.StatusConflict {
		t.Fatalf("POST %s past grace: %d %q, want 409", path, code, msg)
	}
	// The visitor gets the generic text — never the install's counts or the
	// licence vendor (those go to the operator's audit trail).
	if msg != entitlements.TenantCapPublicMessage {
		t.Errorf("POST %s: refusal text %q, want %q", path, msg, entitlements.TenantCapPublicMessage)
	}
}

func (e *signupCapEnv) liveTenants(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(`SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Under the cap → at it → over it in grace → past grace refused (both signup
// routes) → back AT the licence still refused (the grace period is once per
// licence: review, reproduction b) → below it, room for exactly one →
// a re-minted licence gets a fresh grace period.
func TestIntegration_SignupTenantCap_UnderGraceBlockedBackUnder(t *testing.T) {
	e := newSignupCapEnv(t)
	e.licence(t, "msp", 1, 10)

	e.mustSignUp(t, "/auth/register")          // base+1: at the licence
	e.mustSignUp(t, "/auth/register/complete") // base+2: over, grace starts
	var started sql.NullTime
	if err := e.owner.QueryRow(currentClockSQL).Scan(&started); err != nil || !started.Valid {
		t.Fatalf("grace clock not started by the signup that went over (err=%v)", err)
	}
	e.mustSignUp(t, "/auth/register") // still within grace

	// Eleven days later — past the 10-day grace.
	e.exec(t, `UPDATE license_cap_grace SET grace_started_at = now() - interval '11 days'
		WHERE license_id = (SELECT license_id FROM platform_license)`)
	before := e.liveTenants(t)
	e.mustBeRefused(t, "/auth/register")
	e.mustBeRefused(t, "/auth/register/complete")
	if after := e.liveTenants(t); after != before {
		t.Errorf("refused signups changed the tenant count: %d → %d", before, after)
	}

	var spent sql.NullTime
	if err := e.owner.QueryRow(currentClockSQL).Scan(&spent); err != nil {
		t.Fatal(err)
	}

	// Back to exactly the licence: delete two of the three created tenants.
	// The next signup would take it to base+2 — over again — and the grace
	// period under this licence is spent, so it is refused. ( cleared the
	// clock here and handed out a fresh one, without limit.)
	deleteNewest := func(n int) {
		t.Helper()
		e.exec(t, `UPDATE tenants SET deleted_at = now() WHERE id IN (
			SELECT id FROM tenants WHERE name LIKE 'Cap Co %' AND deleted_at IS NULL ORDER BY created_at DESC LIMIT $1)`, n)
	}
	deleteNewest(2)
	e.mustBeRefused(t, "/auth/register")
	e.mustBeRefused(t, "/auth/register/complete")

	// Below the licence: room for exactly one, then refused again. The clock
	// never moves.
	deleteNewest(1)
	e.mustSignUp(t, "/auth/register")
	e.mustBeRefused(t, "/auth/register")
	if err := e.owner.QueryRow(currentClockSQL).Scan(&started); err != nil {
		t.Fatal(err)
	}
	if !started.Valid || !started.Time.Equal(spent.Time) {
		t.Errorf("the spent clock moved: %v → %v", spent, started)
	}

	// A re-minted licence (new token) with the same terms: the next crossing
	// starts a fresh grace period.
	e.licence(t, "msp", 1, 10)
	e.mustSignUp(t, "/auth/register")
	if err := e.owner.QueryRow(currentClockSQL).Scan(&started); err != nil {
		t.Fatal(err)
	}
	if !started.Valid || time.Since(started.Time) > time.Hour {
		t.Errorf("new licence: the crossing should start a fresh clock; got %v", started)
	}
}

// The operator's own tenants are not counted.
func TestIntegration_SignupTenantCap_OperatorTenantsExcluded(t *testing.T) {
	e := newSignupCapEnv(t)
	e.licence(t, "msp", 0, 0) // no room, no grace
	e.mustBeRefused(t, "/auth/register")

	// Mark every live tenant as the MSP's own: the customer count drops to 0.
	e.exec(t, `UPDATE tenants SET is_operator = true WHERE deleted_at IS NULL`)
	e.base = 0
	e.licence(t, "msp", 1, 0)
	e.mustSignUp(t, "/auth/register")
	e.mustBeRefused(t, "/auth/register")
}

// Enterprise (and Core) installs are never capped, whatever the licence row
// carries.
func TestIntegration_SignupTenantCap_NonMSPNeverCapped(t *testing.T) {
	e := newSignupCapEnv(t)
	e.licence(t, "enterprise", 0, 0)
	e.mustSignUp(t, "/auth/register")
	e.mustSignUp(t, "/auth/register/complete")

	e.exec(t, `DELETE FROM platform_license`) // Core
	e.mustSignUp(t, "/auth/register")
}
