package entitlements

// The MSP soft cap on tenants (edition-licensing spec §3, "MSP soft cap").
//
// An MSP licence may carry max_tenants (and grace_days). When it does, the
// platform counts the install's LIVE tenants (deleted_at IS NULL), leaving out
// the MSP's own tenant(s) (tenants.is_operator), and compares that count to the
// licence:
//
//   - under the licensed number: nothing happens;
//   - a creation that would take the count OVER it starts the grace period
//     (a license_cap_grace row for the licence) and is allowed;
//   - while the grace period lasts, further creations are allowed and the
//     admin console shows a banner;
//   - once it has run out, every creation that would take the count over the
//     licence is refused (TenantCapExceededError, which every caller maps to
//     HTTP 409 with its PublicMessage). Being back AT the licensed number does
//     not help: the next creation would take it over again, so it is refused.
//     Only below the licensed number is there room again.
//
// The grace period is granted ONCE PER LICENCE. Each licence's clock is its
// own license_cap_grace row, keyed on the licence's canonical identity
// (platform_license.license_id: the hash of the token's signed header and
// payload), and a row is never updated or deleted:
//   - dropping back to or under the licensed number (tenants deleted, tenants
//     marked as the operator's own) leaves the clock running, or expired. The
//     first version cleared it there, which let an install reset its grace
//     period indefinitely: delete one tenant, or toggle is_operator on and
//     off, then create again with a fresh clock;
//   - installing licence B and then licence A again finds A's clock where it
//     was. A single-row clock would have been overwritten by B's;
//   - the key is not the raw token's hash (token_sha256): one issued token
//     verifies in several byte forms, each with its own hash, and swapping
//     between them would have been a fresh licence every time.
// Only a NEW licence, one Vista Security minted, starts from a fresh clock. The
// cap is a guardrail (billing comes from usage reports), so what matters is
// that it cannot be side-stepped.
//
// Existing tenants are never affected: only NEW tenants are refused.
//
// Every tenant-creation path calls AdmitTenantCreation inside the transaction
// that inserts the tenant. It takes a transaction-scoped advisory lock first,
// so two creations at the cap are serialised: the second one counts the first
// one's row (committed by then) instead of both counting the same number and
// both slipping past. EvaluateTenantCap (after the licence is recorded, and
// after is_operator changes) takes the same lock. ReadTenantCapStatus, which
// GET /admin/license/cap serves, takes no lock and writes nothing.
//
// The grace clocks live in license_cap_grace, NOT on platform_license: the
// licence reconciler rewrites that row on every pass and deletes it on Core.
// Like platform_license, it is read-only for crypto_app; the writer passed in
// must be a bypass-pool handle (crypto_bypass).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DefaultTenantCapGraceDays is the grace period when the licence sets
// max_tenants but not grace_days.
const DefaultTenantCapGraceDays = 30

// TenantCapState is the cap's state as the admin console shows it: what the
// NEXT tenant creation would meet.
type TenantCapState string

const (
	// TenantCapUncapped: no active MSP licence, or one without max_tenants.
	TenantCapUncapped TenantCapState = "uncapped"
	// TenantCapUnder: the next creation stays within the licence, or (at the
	// licensed number, grace not yet used under this licence) would start the
	// grace period.
	TenantCapUnder TenantCapState = "under"
	// TenantCapGrace: the next creation would take the count over the
	// licence, and the grace period still allows it.
	TenantCapGrace TenantCapState = "grace"
	// TenantCapBlocked: the next creation would take the count over the
	// licence and the grace period under this licence has ended. New tenants
	// are refused.
	TenantCapBlocked TenantCapState = "blocked"
)

// TenantCapStatus is the cap's current state. Licensed is nil when uncapped.
type TenantCapStatus struct {
	// Edition is the active licence's edition, or EditionCore when there is
	// no active licence.
	Edition Edition
	// Licensed is the licence's max_tenants; nil when the install is uncapped.
	Licensed *int
	// Current counts live tenants that are not the operator's own.
	Current int
	// Operator counts live tenants marked is_operator (never counted).
	Operator int
	// GraceStartedAt is when the install first went over under the current
	// licence; nil when it has not (yet).
	GraceStartedAt *time.Time
	// GraceDays is the licence's grace period (DefaultTenantCapGraceDays when
	// the licence does not set one). Zero when uncapped.
	GraceDays int
	// GraceEndsAt is GraceStartedAt + GraceDays. Over the licence with no clock
	// recorded yet it is now + GraceDays (the latest the grace can end).
	GraceEndsAt *time.Time
	State       TenantCapState
}

// TenantCapExceededError refuses a tenant creation after the grace period.
// Callers map it to HTTP 409.
//
// Two audiences, two texts. Error() carries the counts and names the licence
// vendor: it is for the MSP operator — logs, the audit trail, the admin
// console. The only creation paths today are self-signup routes, answered to
// an ANONYMOUS visitor on the MSP's (possibly white-labelled) signup page, so
// what goes back over HTTP is PublicMessage(): no counts (the MSP's customer
// count is business-sensitive), no vendor name, no licensing instruction the
// visitor cannot act on.
type TenantCapExceededError struct {
	Licensed int
	Current  int
}

// TenantCapPublicMessage is the refusal as an unauthenticated signup sees it.
const TenantCapPublicMessage = "This platform is not accepting new organisations right now. Please contact the platform operator."

// Error is the operator-facing refusal (logs, audit). Never send it to a
// signup response — use PublicMessage.
func (e *TenantCapExceededError) Error() string {
	return fmt.Sprintf("Licensed tenant limit reached: %d of %d. Contact Vista Security to extend your licence.", e.Current, e.Licensed)
}

// PublicMessage is what a tenant-creation response returns to its caller.
func (e *TenantCapExceededError) PublicMessage() string {
	return TenantCapPublicMessage
}

// IsTenantCapExceeded reports whether err (or anything it wraps) is a cap
// refusal, and returns it.
func IsTenantCapExceeded(err error) (*TenantCapExceededError, bool) {
	var capErr *TenantCapExceededError
	if errors.As(err, &capErr) {
		return capErr, true
	}
	return nil, false
}

// Execer is satisfied by *sql.DB, *sql.Conn and *sql.Tx.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// tenantCapLockSQL serialises every cap decision on the database. Advisory
// locks are per database, and the key is fixed, so every creation path — on
// any service, through any pool — queues on the same lock. Transaction-scoped:
// it is released when the creating transaction commits or rolls back, i.e.
// exactly when the new tenant row becomes visible (or never will).
const tenantCapLockSQL = `SELECT pg_advisory_xact_lock(hashtextextended('vista.license.tenant_cap', 0))`

// countTenantsSQL counts live tenants, split into customers and the operator's
// own. tenants carries no RLS policy (it is the tenant registry), so the count
// is the same on the app pool and the bypass pool.
const countTenantsSQL = `
	SELECT COUNT(*) FILTER (WHERE NOT is_operator),
	       COUNT(*) FILTER (WHERE is_operator)
	  FROM tenants
	 WHERE deleted_at IS NULL`

// capTermsSQL reads the soft-cap terms. The licence itself — edition and
// expiry, and so whether it is active at all — comes from readLicenseInTx, the
// same read the resolver uses; this adds the two numbers the resolver has no
// use for, and the licence identity the grace clock is keyed on.
const capTermsSQL = `SELECT max_tenants, grace_days, license_id FROM platform_license LIMIT 1`

// unidentifiedLicenceKey keys the clock of a licence row with no license_id:
// one written by an admin-service older than the column, which the new
// reconciler rewrites on its first pass. Every such licence shares this one
// clock. At most once per install it can grant one extra grace period: a
// signup over the cap during the upgrade window starts this clock before the
// reconciler writes license_id, and the real licence then gets its own.
const unidentifiedLicenceKey = "unidentified"

const graceStartedSQL = `SELECT grace_started_at FROM license_cap_grace WHERE license_id = $1`

// startGraceSQL starts a licence's clock. It is the only write this file makes
// to license_cap_grace, and it never changes an existing row: a licence's
// clock, once started, stands for as long as the table does.
const startGraceSQL = `
	INSERT INTO license_cap_grace (license_id, grace_started_at)
	VALUES ($1, $2)
	ON CONFLICT (license_id) DO NOTHING`

type capInputs struct {
	edition   Edition
	licensed  *int
	graceDays int
	// licenceKey identifies the licence in force (its license_id).
	licenceKey string
	current    int
	operator   int
	// graceStartedAt is the clock started under THIS licence. A clock stored
	// under any other licence reads as nil.
	graceStartedAt *time.Time
}

// loadCapInputs reads everything else a cap decision needs, on tx, given the
// licence already read from it.
func loadCapInputs(ctx context.Context, tx *sql.Tx, lic *License, now time.Time) (capInputs, error) {
	var in capInputs
	in.edition = EditionCore
	if lic.Active(now) {
		in.edition = lic.Edition
	}
	if in.edition == EditionMSP {
		var (
			maxTenants, graceDays sql.NullInt64
			key                   sql.NullString
		)
		err := tx.QueryRowContext(ctx, capTermsSQL).Scan(&maxTenants, &graceDays, &key)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return in, fmt.Errorf("entitlements: read tenant cap terms: %w", err)
		}
		if maxTenants.Valid {
			n := int(maxTenants.Int64)
			in.licensed = &n
			in.graceDays = DefaultTenantCapGraceDays
			if graceDays.Valid {
				in.graceDays = int(graceDays.Int64)
			}
			in.licenceKey = key.String
			if in.licenceKey == "" {
				in.licenceKey = unidentifiedLicenceKey
			}
		}
	}
	if err := tx.QueryRowContext(ctx, countTenantsSQL).Scan(&in.current, &in.operator); err != nil {
		return in, fmt.Errorf("entitlements: count tenants: %w", err)
	}
	if in.licensed == nil {
		return in, nil
	}
	var started time.Time
	err := tx.QueryRowContext(ctx, graceStartedSQL, in.licenceKey).Scan(&started)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No clock under this licence: its grace period is still unused.
	case err != nil:
		return in, fmt.Errorf("entitlements: read license_cap_grace: %w", err)
	default:
		in.graceStartedAt = &started
	}
	return in, nil
}

// statusFor derives the status from the inputs. State describes what the NEXT
// creation would meet (see TenantCapState).
//
// When a clock has been recorded under this licence, GraceStartedAt/EndsAt
// report it in every state: the grace period is spent once, so "under" with a
// clock means it has been used. Over the licence with no clock recorded yet (a
// read-only view of a re-minted, lower licence nothing has evaluated), the
// grace period is shown as ending GraceDays from now, the latest it can end.
func statusFor(in capInputs, now time.Time) TenantCapStatus {
	st := TenantCapStatus{
		Edition:  in.edition,
		Licensed: in.licensed,
		Current:  in.current,
		Operator: in.operator,
		State:    TenantCapUncapped,
	}
	if in.licensed == nil {
		return st
	}
	st.GraceDays = in.graceDays
	window := time.Duration(in.graceDays) * 24 * time.Hour
	if in.graceStartedAt != nil {
		start := *in.graceStartedAt
		ends := start.Add(window)
		st.GraceStartedAt = &start
		st.GraceEndsAt = &ends
	}
	switch {
	case in.current < *in.licensed:
		// The next creation fits within the licence.
		st.State = TenantCapUnder
		return st
	case in.graceStartedAt == nil && in.current == *in.licensed:
		// The next creation would start the grace period.
		st.State = TenantCapUnder
		return st
	case in.graceStartedAt == nil:
		ends := now.Add(window)
		st.GraceEndsAt = &ends
	}
	if now.Before(*st.GraceEndsAt) {
		st.State = TenantCapGrace
	} else {
		st.State = TenantCapBlocked
	}
	return st
}

// AdmitTenantCreation decides whether one more tenant may be created. Call it
// inside the transaction that INSERTs the tenant, BEFORE the INSERT: the
// advisory lock it takes is what stops two concurrent creations at the cap
// from both being admitted, and it holds only until that transaction ends.
//
// writer records the grace clock. It must be able to write license_cap_grace,
// which crypto_app cannot: pass the service's bypass pool. It runs on its own
// connection, so a grace period started by an admitted creation stays started
// even if the creation later rolls back: the attempt spends it, which is the
// conservative side for a once-per-licence allowance. A nil writer writes
// through tx (callers whose transaction is already on the bypass pool).
//
// On refusal it returns the status and a *TenantCapExceededError. When the
// install is uncapped it returns without taking the lock or writing anything,
// so Core and Enterprise signups pay one licence read and nothing else.
func AdmitTenantCreation(ctx context.Context, tx *sql.Tx, writer Execer, now time.Time) (TenantCapStatus, error) {
	lic, err := readLicenseInTx(ctx, tx)
	if err != nil {
		return TenantCapStatus{}, err
	}
	if !lic.Active(now) || lic.Edition != EditionMSP {
		edition := EditionCore
		if lic.Active(now) {
			edition = lic.Edition
		}
		return TenantCapStatus{Edition: edition, State: TenantCapUncapped}, nil
	}

	if _, err := tx.ExecContext(ctx, tenantCapLockSQL); err != nil {
		return TenantCapStatus{}, fmt.Errorf("entitlements: tenant cap lock: %w", err)
	}
	in, err := loadCapInputs(ctx, tx, lic, now)
	if err != nil {
		return TenantCapStatus{}, err
	}
	if in.licensed == nil {
		return statusFor(in, now), nil
	}
	if writer == nil {
		writer = tx
	}

	// The decision is about the count AFTER this creation: admitting it takes
	// the install over the licence when the current count is already at (or
	// above) the licensed number.
	after := in
	after.current++
	if in.current < *in.licensed {
		return statusFor(after, now), nil
	}

	// Over the licence. The first time under this licence, the grace period
	// starts now; after that the recorded clock stands, whatever the count did
	// in between.
	if in.graceStartedAt == nil {
		start := now
		after.graceStartedAt = &start
		if err := startGrace(ctx, writer, in.licenceKey, start); err != nil {
			return TenantCapStatus{}, err
		}
	}
	st := statusFor(after, now)
	if st.State == TenantCapBlocked {
		// Report the count as it stands — the tenant was not created.
		st.Current = in.current
		return st, &TenantCapExceededError{Licensed: *in.licensed, Current: in.current}
	}
	return st, nil
}

// EvaluateTenantCap starts the grace clock when the install is over its
// licence without one, and returns the status. Called on the writes that can
// take the count over without a creation: the licence being recorded (a
// re-mint with a lower number) and a tenant being unmarked as the operator's
// own. It never clears or restarts a clock (see the file comment), so calling
// it cannot hand out a second grace period. AdmitTenantCreation starts the
// clock on its own, so correctness never depends on an evaluation having run.
//
// db must be able to write license_cap_grace (the bypass pool). It takes the
// same advisory lock as AdmitTenantCreation, so it never races a creation, and
// writes only when it starts a clock.
func EvaluateTenantCap(ctx context.Context, db *sql.DB, now time.Time) (TenantCapStatus, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return TenantCapStatus{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, tenantCapLockSQL); err != nil {
		return TenantCapStatus{}, fmt.Errorf("entitlements: tenant cap lock: %w", err)
	}
	lic, err := readLicenseInTx(ctx, tx)
	if err != nil {
		return TenantCapStatus{}, err
	}
	in, err := loadCapInputs(ctx, tx, lic, now)
	if err != nil {
		return TenantCapStatus{}, err
	}
	if in.licensed != nil && in.current > *in.licensed && in.graceStartedAt == nil {
		start := now
		in.graceStartedAt = &start
		if err := startGrace(ctx, tx, in.licenceKey, start); err != nil {
			return TenantCapStatus{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return TenantCapStatus{}, err
	}
	return statusFor(in, now), nil
}

// ReadTenantCapStatus computes the cap's status without writing anything: no
// advisory lock, no clock started, in a READ ONLY transaction (so a write added
// here later fails loudly rather than slipping in). GET /admin/license/cap
// serves it: a poll must not change the state it reports. Any pool that can
// read tenants, platform_license and license_cap_grace will do.
func ReadTenantCapStatus(ctx context.Context, db *sql.DB, now time.Time) (TenantCapStatus, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TenantCapStatus{}, err
	}
	defer func() { _ = tx.Rollback() }()
	lic, err := readLicenseInTx(ctx, tx)
	if err != nil {
		return TenantCapStatus{}, err
	}
	in, err := loadCapInputs(ctx, tx, lic, now)
	if err != nil {
		return TenantCapStatus{}, err
	}
	return statusFor(in, now), nil
}

// startGrace records a licence's clock. Every caller holds the advisory lock
// and has just read that the licence has none, so the insert lands; if a row
// were there after all, DO NOTHING keeps it (the earlier clock wins), and only
// the status returned for this one call shows the later start.
func startGrace(ctx context.Context, w Execer, licenceKey string, started time.Time) error {
	if _, err := w.ExecContext(ctx, startGraceSQL, licenceKey, started); err != nil {
		return fmt.Errorf("entitlements: write license_cap_grace: %w", err)
	}
	return nil
}

// OperatorUnmarkRefusedError refuses taking a tenant out of the operator's own
// set (is_operator true -> false) when that would put the install over its
// licence after the grace period under the licence has ended ( item 1).
// Callers map it to HTTP 409. The only caller is a platform administrator, so
// the text carries the counts and names the licence vendor.
type OperatorUnmarkRefusedError struct {
	Licensed int
	// After is the customer-tenant count the unmark would produce.
	After int
}

func (e *OperatorUnmarkRefusedError) Error() string {
	return fmt.Sprintf("Unmarking this tenant would make it %d customer tenants against %d licensed, and the grace period under this licence has ended. "+
		"Remove a customer tenant first, or contact Vista Security to extend the licence.", e.After, e.Licensed)
}

// IsOperatorUnmarkRefused reports whether err (or anything it wraps) is an
// unmark refusal, and returns it.
func IsOperatorUnmarkRefused(err error) (*OperatorUnmarkRefusedError, bool) {
	var e *OperatorUnmarkRefusedError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// SetTenantOperator writes tenants.is_operator for a live tenant under the
// cap's advisory lock, refusing an UNMARK the licence no longer has room for.
//
// Without the check an install past its grace period could cycle the flag to
// grow: mark customer tenants as its own to drop under the licence, create a
// tenant (admitted: under), unmark them — one more tenant per round.
// The unmark is refused exactly when a creation would be: the licence is an
// active MSP licence with max_tenants, the grace period under THIS licence has
// started and ended, and the unmark would take the customer count OVER
// max_tenants. Being back AT the licensed number is within the licence, as it
// is for creations. Before the grace period has started (the unmark then
// starts it — call EvaluateTenantCap afterwards) or while it lasts, the unmark
// is allowed. Marking is always allowed, and unmarking a tenant that is not
// marked writes nothing new.
//
// It holds the same lock AdmitTenantCreation takes, so a concurrent creation
// and unmark cannot both take the last slot. db must be able to write
// tenants.is_operator: the bypass pool (the schema's guard_tenant_is_operator).
// found is false when no live tenant has that id.
func SetTenantOperator(ctx context.Context, db *sql.DB, tenantID uuid.UUID, isOperator bool, now time.Time) (found bool, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, tenantCapLockSQL); err != nil {
		return false, fmt.Errorf("entitlements: tenant cap lock: %w", err)
	}
	var marked bool
	err = tx.QueryRowContext(ctx,
		`SELECT is_operator FROM tenants WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, tenantID).Scan(&marked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("entitlements: read tenant: %w", err)
	}

	if marked && !isOperator {
		lic, err := readLicenseInTx(ctx, tx)
		if err != nil {
			return true, err
		}
		in, err := loadCapInputs(ctx, tx, lic, now)
		if err != nil {
			return true, err
		}
		if in.licensed != nil && in.graceStartedAt != nil && in.current+1 > *in.licensed {
			ends := in.graceStartedAt.Add(time.Duration(in.graceDays) * 24 * time.Hour)
			if !now.Before(ends) {
				return true, &OperatorUnmarkRefusedError{Licensed: *in.licensed, After: in.current + 1}
			}
		}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE tenants SET is_operator = $1, updated_at = NOW() WHERE id = $2`, isOperator, tenantID); err != nil {
		return true, fmt.Errorf("entitlements: update tenant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return true, err
	}
	return true, nil
}
