package entitlements_test

// Real-Postgres tests for the self-service sign-up gate (signup_gate.go).
//
// Each test runs on its own testdb.ScratchDatabase (via newCapHarness): the
// bootstrap window counts EVERY live tenant and reads the one platform_license
// row, so on the shared database other packages' tenants would close it and a
// licence written here would change their answers. Admission runs as
// crypto_app, the pool auth-service's createTenant uses.
//
// Mutations run against these (each turns at least one test red):
//   - drop the advisory lock before the bootstrap count      → ConcurrentFirstSignups
//   - `s.LiveTenants <= 1` for the bootstrap window           → CoreBootstrapWindowClosesAfterTheFirstTenant
//   - an absent row means open on every edition (the old rule) → CoreBootstrapWindowClosesAfterTheFirstTenant, EnterpriseHasNoOpenDefault
//   - ignore the explicit setting when it is false            → ExplicitChoiceWinsOnEveryEdition
//   - MSP default closed                                      → MSPDefaultStaysOpen
//   - count soft-deleted tenants                              → SoftDeletedTenantsDoNotCount
//   - a non-boolean value read as true                        → NonBooleanSettingIsNoChoice
//
// Skip without TEST_DATABASE_URL (make test-integration-db / nightly).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// signupHarness starts from a Core install with no tenant and no recorded
// operator choice: the state of a fresh install before its first sign-up.
func newSignupHarness(t *testing.T) *capHarness {
	t.Helper()
	h := newCapHarness(t)
	mustExec(t, h.owner, `UPDATE tenants SET deleted_at = NOW() WHERE deleted_at IS NULL`)
	mustExec(t, h.owner, `DELETE FROM platform_license`)
	mustExec(t, h.owner, `DELETE FROM platform_settings WHERE setting_key = 'registration_enabled'`)
	return h
}

func (h *capHarness) setRegistration(t *testing.T, rawJSON string) {
	t.Helper()
	mustExec(t, h.owner, `DELETE FROM platform_settings WHERE setting_key = 'registration_enabled'`)
	mustExec(t, h.owner, `INSERT INTO platform_settings (setting_key, setting_value) VALUES ('registration_enabled', $1::jsonb)`, rawJSON)
}

func (h *capHarness) signupState(t *testing.T) entitlements.SignupState {
	t.Helper()
	s, err := entitlements.ReadSignupState(context.Background(), h.app, time.Now())
	if err != nil {
		t.Fatalf("ReadSignupState: %v", err)
	}
	return s
}

// signup runs one sign-up's tenant creation the way createTenant does: the
// gate inside the app-pool transaction, then INSERT, then commit. Safe to call
// from a goroutine: it reports with t.Errorf, never t.Fatalf.
func (h *capHarness) signup(t *testing.T, holdBeforeInsert time.Duration) error {
	t.Helper()
	ctx := context.Background()
	tx, err := h.app.BeginTx(ctx, nil)
	if err != nil {
		t.Errorf("begin: %v", err)
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := entitlements.AdmitSignupTenant(ctx, tx, time.Now()); err != nil {
		return err
	}
	time.Sleep(holdBeforeInsert)
	id := uuid.New()
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, id, "signup "+id.String()[:8], "signup-"+id.String()); err != nil {
		t.Errorf("insert tenant: %v", err)
		return err
	}
	if err := tx.Commit(); err != nil {
		t.Errorf("commit: %v", err)
		return err
	}
	return nil
}

func mustBeRefused(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: admitted, want refused", what)
	}
	if !entitlements.IsSignupClosed(err) {
		t.Fatalf("%s: unexpected error %v, want a SignupClosedError", what, err)
	}
}

func TestIntegration_SignupGate_CoreBootstrapWindowClosesAfterTheFirstTenant(t *testing.T) {
	h := newSignupHarness(t)

	s := h.signupState(t)
	if !s.Open || !s.Bootstrap || s.Setting != nil || s.Edition != entitlements.EditionCore {
		t.Fatalf("fresh Core install: %+v, want open in the bootstrap window with no choice recorded", s)
	}
	if s.Effective() {
		t.Fatalf("fresh Core install: Effective() = true, want false (the bootstrap window is not the setting)")
	}
	if err := h.signup(t, 0); err != nil {
		t.Fatalf("first sign-up refused: %v", err)
	}

	s = h.signupState(t)
	if s.Open || s.Bootstrap || s.LiveTenants != 1 {
		t.Fatalf("after the first tenant: %+v, want closed", s)
	}
	mustBeRefused(t, h.signup(t, 0), "second sign-up on Core")
	if n := h.count(t); n != 1 {
		t.Fatalf("live tenants = %d, want 1", n)
	}
}

func TestIntegration_SignupGate_EnterpriseHasNoOpenDefault(t *testing.T) {
	h := newSignupHarness(t)
	h.licence(t, "enterprise", nil, nil, time.Now().Add(24*time.Hour))
	if err := h.signup(t, 0); err != nil {
		t.Fatalf("first sign-up on Enterprise refused: %v", err)
	}
	s := h.signupState(t)
	if s.Open || s.Edition != entitlements.EditionEnterprise || s.DefaultEnabled() {
		t.Fatalf("Enterprise after its first tenant: %+v, want closed with a closed default", s)
	}
	mustBeRefused(t, h.signup(t, 0), "second sign-up on Enterprise")
}

func TestIntegration_SignupGate_MSPDefaultStaysOpen(t *testing.T) {
	h := newSignupHarness(t)
	h.licence(t, "msp", nil, nil, time.Now().Add(24*time.Hour))
	for i := 0; i < 3; i++ {
		if err := h.signup(t, 0); err != nil {
			t.Fatalf("MSP sign-up %d refused: %v", i+1, err)
		}
	}
	if s := h.signupState(t); !s.Open || s.Bootstrap || !s.Effective() {
		t.Fatalf("MSP with tenants and no recorded choice: %+v, want open by default", s)
	}

	// An expired MSP licence resolves as Core: the default closes.
	h.licence(t, "msp", nil, nil, time.Now().Add(-time.Hour))
	mustBeRefused(t, h.signup(t, 0), "sign-up under an expired MSP licence")
}

func TestIntegration_SignupGate_ExplicitChoiceWinsOnEveryEdition(t *testing.T) {
	h := newSignupHarness(t)

	// Explicitly closed on a fresh Core install: the bootstrap window does not
	// override the operator.
	h.setRegistration(t, `false`)
	mustBeRefused(t, h.signup(t, 0), "Core, zero tenants, explicitly closed")

	// Explicitly open on Core: any number of tenants.
	h.setRegistration(t, `true`)
	for i := 0; i < 2; i++ {
		if err := h.signup(t, 0); err != nil {
			t.Fatalf("explicitly open Core sign-up %d refused: %v", i+1, err)
		}
	}
	if s := h.signupState(t); !s.Open || s.Setting == nil || !*s.Setting {
		t.Fatalf("explicitly open Core: %+v", s)
	}

	// Explicitly closed on MSP beats MSP's open default.
	h.licence(t, "msp", nil, nil, time.Now().Add(24*time.Hour))
	h.setRegistration(t, `false`)
	mustBeRefused(t, h.signup(t, 0), "MSP, explicitly closed")
}

func TestIntegration_SignupGate_NonBooleanSettingIsNoChoice(t *testing.T) {
	h := newSignupHarness(t)
	h.setRegistration(t, `"yes"`)
	if s := h.signupState(t); !s.Open || !s.Bootstrap || s.Setting != nil {
		t.Fatalf("non-boolean value, zero tenants: %+v, want the bootstrap window", s)
	}
	if err := h.signup(t, 0); err != nil {
		t.Fatalf("first sign-up refused: %v", err)
	}
	mustBeRefused(t, h.signup(t, 0), "second sign-up with a non-boolean setting")
}

func TestIntegration_SignupGate_SoftDeletedTenantsDoNotCount(t *testing.T) {
	h := newSignupHarness(t)
	if err := h.signup(t, 0); err != nil {
		t.Fatalf("first sign-up refused: %v", err)
	}
	mustExec(t, h.owner, `UPDATE tenants SET deleted_at = NOW() WHERE deleted_at IS NULL`)
	if s := h.signupState(t); !s.Open || !s.Bootstrap {
		t.Fatalf("only a soft-deleted tenant left: %+v, want the bootstrap window again", s)
	}
}

func TestIntegration_SignupGate_ConcurrentFirstSignups(t *testing.T) {
	h := newSignupHarness(t)

	var (
		wg   sync.WaitGroup
		errs [2]error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Holds its admission open long enough for the second to arrive.
		errs[0] = h.signup(t, 400*time.Millisecond)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond)
		errs[1] = h.signup(t, 0)
	}()
	wg.Wait()

	admitted := 0
	for _, err := range errs {
		switch {
		case err == nil:
			admitted++
		case !entitlements.IsSignupClosed(err):
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if admitted != 1 {
		t.Fatalf("%d of 2 simultaneous first sign-ups admitted on Core; want exactly 1", admitted)
	}
	if n := h.count(t); n != 1 {
		t.Fatalf("live tenants = %d, want 1", n)
	}
}
