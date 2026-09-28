package api

// The sign-up gate on the real signup routes and the real service.
//
// shared/entitlements' own tests prove the decision table and the lock. What
// only these show is the wiring:
//   - both password routes refuse a Core install's second sign-up with 403 and
//     the public text, through the REAL SetupRouter;
//   - createTenant itself refuses, with the handlers bypassed. This is the check
//     that holds under a race (two sign-ups can both pass the handlers' early,
//     unlocked check). Delete the AdmitSignupTenant call from createTenant and
//     TestIntegration_SignupGate_CreateTenantRefusesWithoutTheHandler goes red.
//
// Scratch databases, as in tenant_cap_signup_integration_test.go: the gate
// counts every live tenant on the install.
//
// Skips without TEST_DATABASE_URL (make test-integration-db / nightly).

import (
	"net/http"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newFreshCoreSignupEnv is a Core install before its first sign-up: no licence,
// no recorded sign-up choice, no live tenant.
func newFreshCoreSignupEnv(t *testing.T) *signupCapEnv {
	t.Helper()
	e := newSignupCapEnv(t)
	e.exec(t, `UPDATE tenants SET deleted_at = NOW() WHERE deleted_at IS NULL`)
	e.exec(t, `DELETE FROM platform_license`)
	e.exec(t, `DELETE FROM platform_settings WHERE setting_key = 'registration_enabled'`)
	e.base = 0
	return e
}

func (e *signupCapEnv) mustBeRefusedByTheGate(t *testing.T, path string) {
	t.Helper()
	code, msg := e.signup(t, path)
	if code != http.StatusForbidden {
		t.Fatalf("POST %s after the bootstrap window: %d %q, want 403", path, code, msg)
	}
	if msg != entitlements.SignupClosedPublicMessage {
		t.Errorf("POST %s: refusal text %q, want %q", path, msg, entitlements.SignupClosedPublicMessage)
	}
}

func TestIntegration_SignupGate_CoreAdmitsOnlyTheFirstSignup(t *testing.T) {
	e := newFreshCoreSignupEnv(t)

	e.mustSignUp(t, "/auth/register")
	e.mustBeRefusedByTheGate(t, "/auth/register")
	e.mustBeRefusedByTheGate(t, "/auth/register/complete")
	if n := e.liveTenants(t); n != 1 {
		t.Fatalf("live tenants = %d, want 1", n)
	}

	// The operator opens sign-up deliberately: the next one is admitted.
	e.exec(t, `INSERT INTO platform_settings (setting_key, setting_value) VALUES ('registration_enabled', 'true'::jsonb)`)
	e.mustSignUp(t, "/auth/register/complete")
	if n := e.liveTenants(t); n != 2 {
		t.Fatalf("live tenants after the operator opened sign-up = %d, want 2", n)
	}
}

func TestIntegration_SignupGate_PublicConfigMirrorsTheGate(t *testing.T) {
	e := newFreshCoreSignupEnv(t)
	signupEnabled := func() bool {
		t.Helper()
		store := &platformSettingsRepository{db: testdb.ConnectScratchAsAppRole(t, e.owner)}
		return store.SignupOpen()
	}
	if !signupEnabled() {
		t.Fatal("fresh Core install: /platform/config signup_enabled = false, want true (bootstrap window)")
	}
	e.mustSignUp(t, "/auth/register")
	if signupEnabled() {
		t.Fatal("after the first tenant: /platform/config signup_enabled = true, want false")
	}
}

func TestIntegration_SignupGate_CreateTenantRefusesWithoutTheHandler(t *testing.T) {
	e := newFreshCoreSignupEnv(t)
	app := testdb.ConnectScratchAsAppRole(t, e.owner)
	bypass := testdb.ConnectScratchAsBypassRole(t, e.owner)
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on this path
	t.Cleanup(func() { _ = rdb.Close() })
	svc := auth.NewAuthService(app, bypass, rdb, auth.NewJWTService("test-secret-signup-gate", time.Hour, time.Hour))

	if _, err := svc.CreateTenantPublic("First Org"); err != nil {
		t.Fatalf("first tenant in the bootstrap window refused: %v", err)
	}
	_, err := svc.CreateTenantPublic("Second Org")
	if !entitlements.IsSignupClosed(err) {
		t.Fatalf("second tenant with the handlers bypassed: err = %v, want a SignupClosedError", err)
	}
	if n := e.liveTenants(t); n != 1 {
		t.Fatalf("live tenants = %d, want 1", n)
	}
}
