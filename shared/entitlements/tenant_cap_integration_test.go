package entitlements_test

// Real-Postgres tests for the MSP soft cap (tenant_cap.go).
//
// Every test runs on its own testdb.ScratchDatabase: the cap counts EVERY live
// tenant and reads the one platform_license row, so on the shared database
// another package creating tenants concurrently would move the count under the
// test, and a licence written here would change that package's answers.
//
// The creation transaction runs as crypto_app and the grace clock is written
// through crypto_bypass — the pools production uses — so these also prove the
// grants: crypto_app can read license_cap_grace inside its transaction, and a
// bypass writer can write it.
//
// Mutations run against these (each turns at least one test red):
//   - drop the advisory lock in AdmitTenantCreation    → ConcurrentCreationsAtTheCap
//   - `in.current <= *in.licensed` in the admit branch → Lifecycle (the N+1th slips in with no clock) and 5 more
//   - `now.Before(ends)` → `true` in statusFor          → Lifecycle (past grace admitted) and 3 more
//   - drop `WHERE NOT is_operator` from the count       → OperatorTenantsAreNotCounted
//   - read cap terms for any paid edition               → NonMSPEditionsAreNeverCapped (enterprise)
//   - treat an expired licence as active                → NonMSPEditionsAreNeverCapped (expired msp)
//
// The grace period is once per licence (the follow-up):
//   - clear the clock in Admit/Evaluate when back at or under the licence
// (the behaviour) → BackAtTheLicenceStaysBlocked, OperatorToggleDoesNotResetGrace
//   - read the newest clock whatever its licence (drop `WHERE license_id = $1`)
//                                                        → NewLicenceGetsAFreshGracePeriod, ALicenceReinstalledKeepsItsClock
//   - one clock per install: startGrace deletes the other licences' rows
// first (the single-row shape) → ALicenceReinstalledKeepsItsClock, NewLicenceGetsAFreshGracePeriod
//   - key an unidentified licence on its token_sha256
//     (`COALESCE(license_id, token_sha256)`)            → UnidentifiedLicencesShareOneClock
//   - Read path calls EvaluateTenantCap / takes the lock and writes → ReadWritesNothing
//   - statusFor treats "at the licence, grace spent" as under → BackAtTheLicenceStaysBlocked (status half)
//   - trigger allows everyone / refuses BYPASSRLS / refuses the owner /
//     ignores INSERT                                    → IsOperatorGuard
//     (refusing BYPASSRLS also fails OperatorToggleDoesNotResetGrace)
//
// One equivalent mutant, by design: AdmitTenantCreation's early return for a
// non-MSP licence is a fast path (no lock, no count); loadCapInputs applies the
// same rule again, so flipping only the fast path changes no answer.
//
// Skip without TEST_DATABASE_URL (make test-integration-db / nightly).

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type capHarness struct {
	owner, app, bypass *sql.DB
	base               int    // live non-operator tenants the scratch database starts with
	token              string // license_id (and token_sha256) licence() records; "" = "x"
}

func newCapHarness(t *testing.T) *capHarness {
	t.Helper()
	owner := testdb.ScratchDatabase(t)
	h := &capHarness{
		owner:  owner,
		app:    testdb.ConnectScratchAsAppRole(t, owner),
		bypass: testdb.ConnectScratchAsBypassRole(t, owner),
	}
	if err := owner.QueryRow(`SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL AND NOT is_operator`).Scan(&h.base); err != nil {
		t.Fatalf("count seed tenants: %v", err)
	}
	return h
}

// licence installs a licence. maxOverBase is max_tenants relative to the seed
// count (nil = no cap); graceDays nil = the licence does not set one.
func (h *capHarness) licence(t *testing.T, edition string, maxOverBase, graceDays *int, expires time.Time) {
	t.Helper()
	var maxTenants any
	if maxOverBase != nil {
		maxTenants = h.base + *maxOverBase
	}
	var grace any
	if graceDays != nil {
		grace = *graceDays
	}
	token := h.token
	if token == "" {
		token = "x"
	}
	mustExec(t, h.owner, `DELETE FROM platform_license`)
	mustExec(t, h.owner, `INSERT INTO platform_license (subject, edition, expires_at, token_sha256, license_id, max_tenants, grace_days)
		VALUES ('it', $1, $2, $5, $5, $3, $4)`, edition, expires, maxTenants, grace, token)
}

// key is the license_id licence() records.
func (h *capHarness) key() string {
	if h.token == "" {
		return "x"
	}
	return h.token
}

// create runs one tenant creation the way auth-service's createTenant does:
// admit inside the app-pool transaction, then INSERT, then commit.
func (h *capHarness) create(t *testing.T, now time.Time) (entitlements.TenantCapStatus, error) {
	t.Helper()
	return h.createWith(t, now, 0)
}

func (h *capHarness) createWith(t *testing.T, now time.Time, holdBeforeInsert time.Duration) (entitlements.TenantCapStatus, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := h.app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	st, err := entitlements.AdmitTenantCreation(ctx, tx, h.bypass, now)
	if err != nil {
		return st, err
	}
	time.Sleep(holdBeforeInsert)
	id := uuid.New()
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, id, "cap "+id.String()[:8], "cap-"+id.String()); err != nil {
		t.Errorf("insert tenant: %v", err)
		return st, err
	}
	if err := tx.Commit(); err != nil {
		t.Errorf("commit: %v", err)
		return st, err
	}
	return st, nil
}

func (h *capHarness) mustCreate(t *testing.T, now time.Time, want entitlements.TenantCapState) entitlements.TenantCapStatus {
	t.Helper()
	st, err := h.create(t, now)
	if err != nil {
		t.Fatalf("create: unexpected refusal: %v", err)
	}
	if st.State != want {
		t.Fatalf("create: state %q, want %q (status %+v)", st.State, want, st)
	}
	return st
}

// graceStarted is the clock recorded under the current licence, nil if none.
func (h *capHarness) graceStarted(t *testing.T) *time.Time {
	t.Helper()
	return h.graceStartedFor(t, h.key())
}

func (h *capHarness) graceStartedFor(t *testing.T, key string) *time.Time {
	t.Helper()
	var started time.Time
	err := h.owner.QueryRow(`SELECT grace_started_at FROM license_cap_grace WHERE license_id = $1`, key).Scan(&started)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatalf("read license_cap_grace: %v", err)
	}
	return &started
}

// graceRows is license_cap_grace as text, for "nothing changed" checks.
func (h *capHarness) graceRows(t *testing.T) string {
	t.Helper()
	var s sql.NullString
	if err := h.owner.QueryRow(`SELECT json_agg(g ORDER BY license_id)::text FROM license_cap_grace g`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s.String
}

func ptr(n int) *int { return &n }

// Under the cap, up to it, over it within grace, past grace refused.
func TestIntegration_TenantCap_Lifecycle(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now()
	h.licence(t, "msp", ptr(2), ptr(10), now.Add(365*24*time.Hour))

	h.mustCreate(t, now, entitlements.TenantCapUnder) // base+1
	st := h.mustCreate(t, now, entitlements.TenantCapUnder)
	if st.Current != h.base+2 || st.Licensed == nil || *st.Licensed != h.base+2 {
		t.Fatalf("at the cap: current %d licensed %v, want %d of %d", st.Current, st.Licensed, h.base+2, h.base+2)
	}
	if h.graceStarted(t) != nil {
		t.Fatal("grace started while at (not over) the licence")
	}

	// The creation that takes it over: allowed, clock starts.
	st = h.mustCreate(t, now, entitlements.TenantCapGrace)
	if st.GraceStartedAt == nil || st.GraceEndsAt == nil || st.GraceDays != 10 {
		t.Fatalf("over the cap: want a running 10-day clock, got %+v", st)
	}
	started := h.graceStarted(t)
	if started == nil {
		t.Fatal("grace_started_at not recorded on first crossing")
	}

	// Within grace: still allowed, and the clock does NOT restart.
	h.mustCreate(t, now.Add(9*24*time.Hour), entitlements.TenantCapGrace)
	if again := h.graceStarted(t); again == nil || !again.Equal(*started) {
		t.Fatalf("clock restarted within grace: %v → %v", started, again)
	}

	// Past grace: refused with the 409 message, nothing inserted.
	before := h.count(t)
	_, err := h.create(t, now.Add(10*24*time.Hour+time.Minute))
	capErr, ok := entitlements.IsTenantCapExceeded(err)
	if !ok {
		t.Fatalf("past grace: want TenantCapExceededError, got %v", err)
	}
	want := "Licensed tenant limit reached: " // N of N, then the contact line
	if got := capErr.Error(); len(got) < len(want) || got[:len(want)] != want {
		t.Errorf("refusal message %q", got)
	}
	if capErr.Licensed != h.base+2 || capErr.Current != h.base+4 {
		t.Errorf("refusal counts %d of %d, want %d of %d", capErr.Current, capErr.Licensed, h.base+4, h.base+2)
	}
	if after := h.count(t); after != before {
		t.Errorf("a refused creation changed the tenant count: %d → %d", before, after)
	}

	// Existing tenants are untouched: the status says blocked, nothing else.
	eval, err := entitlements.EvaluateTenantCap(context.Background(), h.bypass, now.Add(11*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if eval.State != entitlements.TenantCapBlocked {
		t.Errorf("evaluate past grace: state %q, want blocked", eval.State)
	}
}

func (h *capHarness) count(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.owner.QueryRow(`SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// grace_days = 0 means the first creation over the licence is already refused;
// a licence without grace_days gets the 30-day default.
func TestIntegration_TenantCap_GraceDaysDefaultAndZero(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now()
	h.licence(t, "msp", ptr(0), nil, now.Add(24*time.Hour))
	st := h.mustCreate(t, now, entitlements.TenantCapGrace)
	if st.GraceDays != entitlements.DefaultTenantCapGraceDays {
		t.Errorf("no grace_days on the licence: GraceDays %d, want %d", st.GraceDays, entitlements.DefaultTenantCapGraceDays)
	}

	h2 := newCapHarness(t)
	h2.licence(t, "msp", ptr(0), ptr(0), now.Add(24*time.Hour))
	if _, err := h2.create(t, now); err == nil {
		t.Error("grace_days 0: the first creation over the licence was allowed")
	}
}

// review, reproduction (b): deleting a tenant to get back to exactly the
// licensed number used to clear the clock, so the next creation got a whole
// new grace period, with no ceiling on how often. The grace period is once per
// licence: back at the licence, the clock stands, and once it has run out the
// next creation is refused. Only BELOW the licence is there room again.
func TestIntegration_TenantCap_BackAtTheLicenceStaysBlocked(t *testing.T) {
	h := newCapHarness(t)
	ctx := context.Background()
	now := time.Now()
	h.licence(t, "msp", ptr(1), ptr(5), now.Add(365*24*time.Hour))
	h.mustCreate(t, now, entitlements.TenantCapUnder)
	h.mustCreate(t, now, entitlements.TenantCapGrace) // over: the clock starts
	started := h.graceStarted(t)
	if started == nil {
		t.Fatal("premise: no clock after going over")
	}

	// Delete one tenant: back to the licensed number. Evaluating (what a
	// write path runs) does not clear the clock.
	h.deleteNewest(t)
	st, err := entitlements.EvaluateTenantCap(ctx, h.bypass, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if again := h.graceStarted(t); again == nil || !again.Equal(*started) {
		t.Fatalf("back at the licence: clock %v → %v, want it unchanged", started, again)
	}
	if st.State != entitlements.TenantCapGrace {
		t.Errorf("back at the licence within grace: state %q, want grace (the next creation spends it)", st.State)
	}

	// Past the grace period, still at the licence: the next creation is
	// refused, not handed a fresh clock.
	later := now.Add(30 * 24 * time.Hour)
	if st, err := entitlements.ReadTenantCapStatus(ctx, h.bypass, later); err != nil || st.State != entitlements.TenantCapBlocked {
		t.Fatalf("at the licence, grace spent: state %q (err %v), want blocked", st.State, err)
	}
	if _, err := h.create(t, later); err == nil {
		t.Fatal("at the licence after grace: creation admitted with a fresh grace period")
	} else if _, ok := entitlements.IsTenantCapExceeded(err); !ok {
		t.Fatalf("at the licence after grace: %v, want TenantCapExceededError", err)
	}
	if again := h.graceStarted(t); again == nil || !again.Equal(*started) {
		t.Fatalf("refused creation moved the clock: %v → %v", started, again)
	}

	// Below the licence there is room for exactly one, and then it is blocked
	// again — round and round never buys more grace.
	h.deleteNewest(t)
	h.mustCreate(t, later, entitlements.TenantCapBlocked) // admitted; the status after it is "next one blocked"
	if _, err := h.create(t, later); err == nil {
		t.Fatal("back at the licence a second time: creation admitted")
	}
	if again := h.graceStarted(t); again == nil || !again.Equal(*started) {
		t.Fatalf("clock moved: %v → %v", started, again)
	}
}

func (h *capHarness) deleteNewest(t *testing.T) {
	t.Helper()
	mustExec(t, h.owner, `UPDATE tenants SET deleted_at = now() WHERE id = (SELECT id FROM tenants WHERE slug LIKE 'cap-%' AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1)`)
}

// review, reproduction (a): marking a tenant as the operator's own drops
// the count under the licence; unmarking it takes it back over. That used to
// clear the clock and then start a fresh one. The toggle must leave the clock
// exactly where it was.
func TestIntegration_TenantCap_OperatorToggleDoesNotResetGrace(t *testing.T) {
	h := newCapHarness(t)
	ctx := context.Background()
	now := time.Now()
	h.licence(t, "msp", ptr(1), ptr(5), now.Add(365*24*time.Hour))
	h.mustCreate(t, now, entitlements.TenantCapUnder)
	h.mustCreate(t, now, entitlements.TenantCapGrace)
	started := h.graceStarted(t)

	var victim uuid.UUID
	if err := h.owner.QueryRow(`SELECT id FROM tenants WHERE slug LIKE 'cap-%' ORDER BY created_at DESC LIMIT 1`).Scan(&victim); err != nil {
		t.Fatal(err)
	}
	// The same sequence SetTenantOperator runs: write the flag on the bypass
	// pool, then evaluate.
	for i, flag := range []bool{true, false, true, false} {
		mustExec(t, h.bypass, `UPDATE tenants SET is_operator = $1 WHERE id = $2`, flag, victim)
		at := now.Add(time.Duration(i+1) * 24 * time.Hour)
		if _, err := entitlements.EvaluateTenantCap(ctx, h.bypass, at); err != nil {
			t.Fatal(err)
		}
		if again := h.graceStarted(t); again == nil || !again.Equal(*started) {
			t.Fatalf("toggle %d (is_operator=%v): clock %v → %v, want unchanged", i, flag, started, again)
		}
	}

	// Past the one grace period: refused.
	if _, err := h.create(t, now.Add(6*24*time.Hour)); err == nil {
		t.Fatal("after toggling is_operator, a creation past the original grace period was admitted")
	}
}

// Only a new licence (a re-minted token) gets a fresh grace period. A clock
// recorded under another licence is ignored; the one recorded under this
// licence survives the licence dropping its cap or turning Enterprise and back.
func TestIntegration_TenantCap_NewLicenceGetsAFreshGracePeriod(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now().Truncate(time.Microsecond) // Postgres keeps microseconds
	h.token = "licence-A"
	h.licence(t, "msp", ptr(1), ptr(5), now.Add(365*24*time.Hour))
	h.mustCreate(t, now, entitlements.TenantCapUnder)
	h.mustCreate(t, now, entitlements.TenantCapGrace)
	later := now.Add(30 * 24 * time.Hour)
	if _, err := h.create(t, later); err == nil {
		t.Fatal("premise: past grace under licence A, creation admitted")
	}

	// The same licence without a cap, then capped again: still spent.
	mustExec(t, h.owner, `UPDATE platform_license SET max_tenants = NULL`)
	h.mustCreate(t, later, entitlements.TenantCapUncapped)
	mustExec(t, h.owner, `UPDATE platform_license SET max_tenants = $1`, h.base+1)
	if _, err := h.create(t, later); err == nil {
		t.Fatal("the same licence re-capped: creation admitted with a fresh grace period")
	}

	// A re-minted licence, same terms: a fresh grace period starts at the next
	// creation over it, recorded under the new licence.
	h.token = "licence-B"
	h.licence(t, "msp", ptr(1), ptr(5), now.Add(365*24*time.Hour))
	st := h.mustCreate(t, later, entitlements.TenantCapGrace)
	if st.GraceStartedAt == nil || !st.GraceStartedAt.Equal(later) {
		t.Errorf("new licence: clock %v, want a fresh one at %v", st.GraceStartedAt, later)
	}
	if b := h.graceStartedFor(t, "licence-B"); b == nil || !b.Equal(later) {
		t.Errorf("licence-B clock %v, want %v", b, later)
	}
	if a := h.graceStartedFor(t, "licence-A"); a == nil || !a.Equal(now) {
		t.Errorf("licence-A clock %v, want it kept at %v", a, now)
	}
}

// review: the clock used to be one row, overwritten when another
// licence's clock started. Installing licence B (which went over and started
// its own clock) and then licence A again handed A a fresh grace period. Two
// valid licences at once is ordinary during a renewal overlap. Each licence's
// clock is its own row now, and A's is still spent when A comes back.
func TestIntegration_TenantCap_ALicenceReinstalledKeepsItsClock(t *testing.T) {
	h := newCapHarness(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Microsecond) // Postgres keeps microseconds
	h.token = "licence-A"
	h.licence(t, "msp", ptr(1), ptr(5), now.Add(365*24*time.Hour))
	h.mustCreate(t, now, entitlements.TenantCapUnder)
	h.mustCreate(t, now, entitlements.TenantCapGrace)
	aStarted := h.graceStarted(t)
	if _, err := h.create(t, now.Add(30*24*time.Hour)); err == nil {
		t.Fatal("premise: past grace under licence A, creation admitted")
	}

	// Licence B, with a long grace period: over it, so evaluating (what the
	// reconciler runs on every tick) starts B's own clock — still running when
	// A comes back, so reading B's clock for A would admit.
	h.token = "licence-B"
	h.licence(t, "msp", ptr(1), ptr(90), now.Add(365*24*time.Hour))
	if st, err := entitlements.EvaluateTenantCap(ctx, h.bypass, now.Add(31*24*time.Hour)); err != nil || st.State != entitlements.TenantCapGrace {
		t.Fatalf("licence B: state %q (err %v), want grace", st.State, err)
	}

	// Licence A again, well after B's clock started.
	h.token = "licence-A"
	h.licence(t, "msp", ptr(1), ptr(5), now.Add(365*24*time.Hour))
	back := now.Add(60 * 24 * time.Hour)
	if st, err := entitlements.ReadTenantCapStatus(ctx, h.bypass, back); err != nil || st.State != entitlements.TenantCapBlocked {
		t.Fatalf("licence A re-installed: state %q (err %v), want blocked", st.State, err)
	}
	st, err := h.create(t, back)
	if err == nil {
		t.Fatalf("licence A re-installed after A -> B -> A: creation admitted with a fresh grace period (%+v)", st)
	}
	if _, ok := entitlements.IsTenantCapExceeded(err); !ok {
		t.Fatalf("licence A re-installed: %v, want TenantCapExceededError", err)
	}
	if again := h.graceStarted(t); again == nil || !again.Equal(*aStarted) {
		t.Errorf("licence A's clock %v → %v, want unchanged", aStarted, again)
	}
	if b := h.graceStartedFor(t, "licence-B"); b == nil || !b.Equal(now.Add(31*24*time.Hour)) {
		t.Errorf("licence B's clock %v, want kept", b)
	}
}

// A licence row with no license_id (written by an admin-service older than
// the column) keys its clock as "unidentified". Every such row shares that
// one clock, so the upgrade window can cost grace but never grant more.
func TestIntegration_TenantCap_UnidentifiedLicencesShareOneClock(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now()
	h.licence(t, "msp", ptr(1), ptr(5), now.Add(365*24*time.Hour))
	mustExec(t, h.owner, `UPDATE platform_license SET license_id = NULL, token_sha256 = 'old-1'`)
	h.mustCreate(t, now, entitlements.TenantCapUnder)
	h.mustCreate(t, now, entitlements.TenantCapGrace)
	if h.graceStartedFor(t, "unidentified") == nil {
		t.Fatal("no clock recorded under the unidentified key")
	}
	mustExec(t, h.owner, `UPDATE platform_license SET token_sha256 = 'old-2'`)
	if _, err := h.create(t, now.Add(30*24*time.Hour)); err == nil {
		t.Fatal("a second unidentified licence got a fresh grace period")
	}
}

// The operator's own tenants are never counted.
func TestIntegration_TenantCap_OperatorTenantsAreNotCounted(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now()
	h.licence(t, "msp", ptr(1), ptr(0), now.Add(365*24*time.Hour))
	for i := 0; i < 3; i++ {
		id := uuid.New()
		mustExec(t, h.owner, `INSERT INTO tenants (id, name, slug, is_operator) VALUES ($1, 'op', $2, true)`, id, "op-"+id.String())
	}
	st := h.mustCreate(t, now, entitlements.TenantCapUnder)
	if st.Operator != 3 || st.Current != h.base+1 {
		t.Errorf("counts: current %d operator %d, want %d and 3", st.Current, st.Operator, h.base+1)
	}
	if _, err := h.create(t, now); err == nil {
		t.Error("grace 0, at the cap: creation allowed")
	}
}

// Core, Enterprise, an expired MSP licence and an MSP licence without
// max_tenants are never capped — and never touch license_cap_grace.
func TestIntegration_TenantCap_NonMSPEditionsAreNeverCapped(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name    string
		install func(h *capHarness, t *testing.T)
	}{
		{"core", func(*capHarness, *testing.T) {}},
		{"enterprise with max_tenants", func(h *capHarness, t *testing.T) {
			h.licence(t, "enterprise", ptr(0), ptr(0), now.Add(24*time.Hour))
		}},
		{"expired msp", func(h *capHarness, t *testing.T) {
			h.licence(t, "msp", ptr(0), ptr(0), now.Add(-time.Hour))
		}},
		{"msp without max_tenants", func(h *capHarness, t *testing.T) {
			h.licence(t, "msp", nil, ptr(0), now.Add(24*time.Hour))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCapHarness(t)
			tc.install(h, t)
			for i := 0; i < 3; i++ {
				h.mustCreate(t, now, entitlements.TenantCapUncapped)
			}
			// The status route's path (EvaluateTenantCap) agrees.
			st, err := entitlements.EvaluateTenantCap(context.Background(), h.bypass, now)
			if err != nil {
				t.Fatal(err)
			}
			if st.State != entitlements.TenantCapUncapped || st.Licensed != nil {
				t.Errorf("evaluate: state %q licensed %v, want uncapped", st.State, st.Licensed)
			}
			var rows int
			if err := h.owner.QueryRow(`SELECT COUNT(*) FROM license_cap_grace`).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != 0 {
				t.Errorf("an uncapped install wrote license_cap_grace (%d rows)", rows)
			}
		})
	}
}

// Two creations racing at the cap after grace: exactly one gets in. Without
// the advisory lock both count the same number and both are admitted.
func TestIntegration_TenantCap_ConcurrentCreationsAtTheCap(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now()
	h.licence(t, "msp", ptr(1), ptr(0), now.Add(24*time.Hour))

	var (
		wg   sync.WaitGroup
		errs [2]error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Holds its admission open long enough for the second to arrive.
		_, errs[0] = h.createWith(t, now, 400*time.Millisecond)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond)
		_, errs[1] = h.createWith(t, now, 0)
	}()
	wg.Wait()

	admitted := 0
	for _, err := range errs {
		if err == nil {
			admitted++
		} else if _, ok := entitlements.IsTenantCapExceeded(err); !ok {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if admitted != 1 {
		t.Fatalf("%d of 2 concurrent creations admitted at a cap with one slot and no grace; want exactly 1", admitted)
	}
	if n := h.count(t); n-h.base != 1 {
		// Seed operator tenants are zero on a scratch database, so live = base + created.
		t.Errorf("live tenants over the seed: %d, want 1", n-h.base)
	}
}

// Evaluating an over-cap install with no clock (the licence was re-minted with
// a lower number) starts the clock under that licence. Evaluating again, or
// with the licence uncapped, leaves it alone.
func TestIntegration_TenantCap_EvaluateStartsNeverClears(t *testing.T) {
	h := newCapHarness(t)
	ctx := context.Background()
	now := time.Now()
	h.licence(t, "msp", nil, nil, now.Add(24*time.Hour))
	for i := 0; i < 2; i++ {
		h.mustCreate(t, now, entitlements.TenantCapUncapped)
	}
	h.token = "lowered"
	h.licence(t, "msp", ptr(1), ptr(7), now.Add(24*time.Hour))
	st, err := entitlements.EvaluateTenantCap(ctx, h.bypass, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != entitlements.TenantCapGrace || st.GraceEndsAt == nil || !st.GraceEndsAt.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("lowered cap: %+v, want grace ending in 7 days", st)
	}
	started := h.graceStarted(t)

	if _, err := entitlements.EvaluateTenantCap(ctx, h.bypass, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	mustExec(t, h.owner, `UPDATE platform_license SET max_tenants = NULL`)
	st, err = entitlements.EvaluateTenantCap(ctx, h.bypass, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if st.State != entitlements.TenantCapUncapped {
		t.Errorf("uncapped: state %q", st.State)
	}
	if again := h.graceStarted(t); again == nil || !again.Equal(*started) {
		t.Errorf("clock %v → %v, want unchanged by re-evaluation and by the cap being lifted", started, again)
	}
}

// GET /admin/license/cap's read path writes nothing: over the licence with no
// clock it reports the grace period without starting it, and with a clock it
// leaves the row exactly as it was.
func TestIntegration_TenantCap_ReadWritesNothing(t *testing.T) {
	h := newCapHarness(t)
	ctx := context.Background()
	now := time.Now()
	h.licence(t, "msp", nil, nil, now.Add(24*time.Hour))
	for i := 0; i < 2; i++ {
		h.mustCreate(t, now, entitlements.TenantCapUncapped)
	}
	h.licence(t, "msp", ptr(1), ptr(7), now.Add(24*time.Hour))

	st, err := entitlements.ReadTenantCapStatus(ctx, h.bypass, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != entitlements.TenantCapGrace || st.GraceStartedAt != nil || st.GraceEndsAt == nil || !st.GraceEndsAt.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("over with no clock: %+v, want grace, no start recorded, ending 7 days from now", st)
	}
	if rows := h.graceRows(t); rows != "" {
		t.Fatalf("the read wrote license_cap_grace: %s", rows)
	}

	// With a clock: the rows are byte-for-byte unchanged by any number of
	// reads.
	if _, err := entitlements.EvaluateTenantCap(ctx, h.bypass, now); err != nil {
		t.Fatal(err)
	}
	before := h.graceRows(t)
	if before == "" {
		t.Fatal("premise: evaluating over the licence recorded no clock")
	}
	for i := 0; i < 3; i++ {
		if _, err := entitlements.ReadTenantCapStatus(ctx, h.bypass, now.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if after := h.graceRows(t); after != before {
		t.Errorf("reads changed license_cap_grace: %s → %s", before, after)
	}
}

// Only the bypass role (BYPASSRLS) or the table owner may change
// tenants.is_operator; crypto_app may not, on UPDATE or on INSERT.
func TestIntegration_TenantCap_IsOperatorGuard(t *testing.T) {
	h := newCapHarness(t)
	id := uuid.New()
	mustExec(t, h.owner, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'guard', $2)`, id, "guard-"+id.String())

	assertDenied := func(what string, err error) {
		t.Helper()
		var coded interface{ SQLState() string }
		if err == nil {
			t.Errorf("%s: allowed, want refused", what)
		} else if !errors.As(err, &coded) || coded.SQLState() != "42501" {
			t.Errorf("%s: %v, want insufficient_privilege (42501)", what, err)
		}
	}
	_, err := h.app.Exec(`UPDATE tenants SET is_operator = true WHERE id = $1`, id)
	assertDenied("crypto_app UPDATE is_operator", err)
	other := uuid.New()
	_, err = h.app.Exec(`INSERT INTO tenants (id, name, slug, is_operator) VALUES ($1, 'guard', $2, true)`, other, "guard-"+other.String())
	assertDenied("crypto_app INSERT is_operator=true", err)

	// Everything else crypto_app does to tenants is untouched.
	if _, err := h.app.Exec(`UPDATE tenants SET name = 'renamed', is_operator = false WHERE id = $1`, id); err != nil {
		t.Errorf("crypto_app UPDATE of other columns (is_operator unchanged): %v", err)
	}
	if _, err := h.app.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'guard', $2)`, other, "guard-"+other.String()); err != nil {
		t.Errorf("crypto_app INSERT of an ordinary tenant: %v", err)
	}

	// The bypass role (admin-service's PUT /admin/tenants/:id/operator) and
	// the owner may.
	if _, err := h.bypass.Exec(`UPDATE tenants SET is_operator = true WHERE id = $1`, id); err != nil {
		t.Errorf("crypto_bypass UPDATE is_operator: %v", err)
	}
	if _, err := h.owner.Exec(`UPDATE tenants SET is_operator = false WHERE id = $1`, id); err != nil {
		t.Errorf("owner UPDATE is_operator: %v", err)
	}
	var flag bool
	if err := h.owner.QueryRow(`SELECT is_operator FROM tenants WHERE id = $1`, id).Scan(&flag); err != nil || flag {
		t.Errorf("is_operator %v (err %v), want false after the owner's write", flag, err)
	}

	// The test's owner connection is a superuser. An install without the RLS
	// roles runs its services as a plain (non-superuser, non-BYPASSRLS) table
	// owner, as crypto_user is in production: that must keep working.
	ownerRole := "guard_owner_" + uuid.NewString()[:8]
	var prevOwner string
	if err := h.owner.QueryRow(`SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.tenants'::regclass`).Scan(&prevOwner); err != nil {
		t.Fatal(err)
	}
	mustExec(t, h.owner, `CREATE ROLE `+ownerRole+` NOLOGIN NOSUPERUSER NOBYPASSRLS`)
	mustExec(t, h.owner, `ALTER TABLE public.tenants OWNER TO `+ownerRole)
	defer func() {
		mustExec(t, h.owner, `ALTER TABLE public.tenants OWNER TO "`+prevOwner+`"`)
		mustExec(t, h.owner, `DROP ROLE `+ownerRole)
	}()
	asRole := func(role, q string, args ...any) error {
		tx, err := h.owner.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SET LOCAL ROLE ` + role); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(q, args...)
		return err
	}
	if err := asRole(ownerRole, `UPDATE tenants SET is_operator = true WHERE id = $1`, id); err != nil {
		t.Errorf("non-superuser table owner UPDATE is_operator: %v", err)
	}
	assertDenied("crypto_app via SET ROLE", asRole(testdb.RLSAppRole, `UPDATE tenants SET is_operator = true WHERE id = $1`, id))
}

// crypto_app can read the clocks but not write or delete them; the bypass
// role can write them.
func TestIntegration_TenantCap_StateIsReadOnlyForTheAppPool(t *testing.T) {
	h := newCapHarness(t)
	if _, err := h.app.Exec(`INSERT INTO license_cap_grace (license_id, grace_started_at) VALUES ('app', now())`); err == nil {
		t.Error("crypto_app wrote license_cap_grace")
	}
	var n int
	if err := h.app.QueryRow(`SELECT COUNT(*) FROM license_cap_grace`).Scan(&n); err != nil {
		t.Errorf("crypto_app cannot read license_cap_grace: %v", err)
	}
	if _, err := h.bypass.Exec(`INSERT INTO license_cap_grace (license_id, grace_started_at) VALUES ('bypass', now())`); err != nil {
		t.Errorf("crypto_bypass cannot write license_cap_grace: %v", err)
	}
	if _, err := h.app.Exec(`DELETE FROM license_cap_grace`); err == nil {
		t.Error("crypto_app deleted from license_cap_grace")
	}
}
