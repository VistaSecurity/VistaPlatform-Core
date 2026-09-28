package entitlements

// The self-service sign-up gate (owner decision.
//
// Public sign-up is the only way a Core or Enterprise install gains a tenant:
// creating tenants is the MSP management plane. It used to be open by default
// on every edition and to fail OPEN, so an internet-facing Core deployment
// minted a new tenant for every stranger who found /signup until the operator
// thought to close it.
//
// The rule, decided in this order:
//
//  1. An explicit operator choice (platform_settings.registration_enabled set
//     to true or false in admin-ui → Settings → Access) wins, on every
//     edition.
//  2. With no choice recorded, an MSP install is open: onboarding customers
//     through sign-up is what MSP sells, and the licensed-tenant soft cap
//     (AdmitTenantCreation) still applies.
//  3. With no choice recorded, Core and Enterprise are open ONLY while the
//     install has no live tenant — the bootstrap window in which the operator
//     signs up to create their organisation. After that, sign-up is off and
//     people join by invitation.
//
// A value that is present but not a JSON boolean counts as no choice. A
// database error closes the gate: this path creates tenants, and "could not
// tell" must not mean "let anyone in".
//
// The same decision serves three callers: the register handlers' early 403,
// the public /platform/config mirror the /signup page renders from, and
// AdmitSignupTenant inside the transaction that inserts the tenant, which is
// the one that actually holds.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RegistrationSettingKey is the platform_settings key the operator's sign-up
// choice is stored under.
const RegistrationSettingKey = "registration_enabled"

// SignupClosedPublicMessage is the refusal a sign-up attempt receives.
const SignupClosedPublicMessage = "Self-service sign-up is disabled on this platform. Contact your platform operator for access."

// SignupClosedError is returned by AdmitSignupTenant when the gate refuses.
type SignupClosedError struct{}

func (*SignupClosedError) Error() string { return SignupClosedPublicMessage }

// IsSignupClosed reports whether err (or anything it wraps) is a sign-up gate
// refusal.
func IsSignupClosed(err error) bool {
	var closed *SignupClosedError
	return errors.As(err, &closed)
}

// SignupState is the gate's inputs and its answer.
type SignupState struct {
	// Edition is the install's effective edition. Only read when no explicit
	// choice is recorded; Core otherwise.
	Edition Edition
	// Setting is the operator's explicit choice, or nil when none is recorded.
	Setting *bool
	// LiveTenants is the number of tenants with deleted_at IS NULL. Only
	// counted on a non-MSP install with no explicit choice; 0 otherwise.
	LiveTenants int
	// Open is whether a sign-up may create a tenant now.
	Open bool
	// Bootstrap is true when the gate is open only because the install has no
	// tenant yet: the first sign-up will close it.
	Bootstrap bool
}

// DefaultEnabled is what sign-up is when no operator choice is recorded,
// ignoring the bootstrap window: on for MSP, off for Core and Enterprise.
func (s SignupState) DefaultEnabled() bool { return s.Edition == EditionMSP }

// Effective reports the registration setting as an operator should see it:
// their explicit choice, or the edition default.
func (s SignupState) Effective() bool {
	if s.Setting != nil {
		return *s.Setting
	}
	return s.DefaultEnabled()
}

const selectRegistrationSettingSQL = `SELECT setting_value FROM platform_settings WHERE setting_key = 'registration_enabled'`

// countLiveTenantsSQL counts every live tenant. tenants carries no RLS policy
// (it is the tenant registry), so the answer is the same on any pool.
const countLiveTenantsSQL = `SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL`

// ReadSignupState evaluates the gate on q (a pool or connection). It takes no
// lock, so it is for display and for the handlers' early refusal; the
// transaction that creates a tenant must use AdmitSignupTenant.
func ReadSignupState(ctx context.Context, q rowQueryer, now time.Time) (SignupState, error) {
	return readSignupState(ctx, q, now, func() (*License, error) { return readLicense(ctx, q) }, nil)
}

// SignupOpen is ReadSignupState's answer, closed on any error.
func SignupOpen(ctx context.Context, q rowQueryer, now time.Time) (bool, error) {
	s, err := ReadSignupState(ctx, q, now)
	if err != nil {
		return false, err
	}
	return s.Open, nil
}

// AdmitSignupTenant decides the gate inside the transaction that inserts a
// sign-up's tenant, and returns *SignupClosedError when it is shut. In the
// bootstrap window it takes the same transaction-scoped advisory lock as the
// MSP tenant cap before counting, so two simultaneous "first" sign-ups are
// serialised: the second counts the first one's tenant and is refused.
func AdmitSignupTenant(ctx context.Context, tx *sql.Tx, now time.Time) error {
	lock := func() error {
		if _, err := tx.ExecContext(ctx, tenantCapLockSQL); err != nil {
			return fmt.Errorf("entitlements: sign-up gate lock: %w", err)
		}
		return nil
	}
	s, err := readSignupState(ctx, tx, now, func() (*License, error) { return readLicenseInTx(ctx, tx) }, lock)
	if err != nil {
		return err
	}
	if !s.Open {
		return &SignupClosedError{}
	}
	return nil
}

func readSignupState(ctx context.Context, q rowQueryer, now time.Time, license func() (*License, error), lockBeforeCount func() error) (SignupState, error) {
	s := SignupState{Edition: EditionCore}

	var raw []byte
	switch err := q.QueryRowContext(ctx, selectRegistrationSettingSQL).Scan(&raw); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return s, fmt.Errorf("entitlements: read %s: %w", RegistrationSettingKey, err)
	default:
		var v bool
		if json.Unmarshal(raw, &v) == nil {
			s.Setting = &v
		}
	}
	if s.Setting != nil {
		s.Open = *s.Setting
		return s, nil
	}

	lic, err := license()
	if err != nil {
		return s, err
	}
	if lic.Active(now) {
		s.Edition = lic.Edition
	}
	if s.Edition == EditionMSP {
		s.Open = true
		return s, nil
	}

	if lockBeforeCount != nil {
		if err := lockBeforeCount(); err != nil {
			return s, err
		}
	}
	if err := q.QueryRowContext(ctx, countLiveTenantsSQL).Scan(&s.LiveTenants); err != nil {
		return s, fmt.Errorf("entitlements: count tenants for the sign-up gate: %w", err)
	}
	s.Open = s.LiveTenants == 0
	s.Bootstrap = s.Open
	return s, nil
}
