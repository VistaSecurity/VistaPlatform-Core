package services

// Database-integration tests for the PERSISTED per-tenant re-evaluation cooldown.
// Skips unless TEST_DATABASE_URL is set (see shared/testdb); run locally via
// `make test-integration-db`.
//
// These run against real Postgres deliberately: the cooldown's whole correctness
// argument is that the DATABASE arbitrates (one conditional upsert), not a process.
// A unit test over a fake would prove nothing about the ON CONFLICT ... WHERE, which
// is the only thing standing between us and a multi-replica bypass. They connect as
// crypto_app — the non-owner, NOBYPASSRLS role services actually use — so an RLS or
// grant mistake fails here rather than in production.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newReevaluationFixture returns a service on an app-role (RLS-subject) connection
// plus the owner handle for fixtures.
func newReevaluationFixture(t *testing.T, cooldown time.Duration) (*ReevaluationService, *sql.DB) {
	t.Helper()
	owner := testdb.Connect(t) // skips if TEST_DATABASE_URL unset
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	return NewReevaluationService(sqlx.NewDb(app, "postgres")).WithCooldown(cooldown), owner
}

// The core rule: a second request inside the window is refused, and one after the
// window is allowed.
func TestIntegration_ReevaluationCooldown_RefusesInsideWindowAllowsAfter(t *testing.T) {
	svc, owner := newReevaluationFixture(t, time.Hour)
	tenant := testdb.NewTenant(t, owner)
	user := uuid.New()
	ctx := context.Background()

	// 1. First request on a tenant that has never run one.
	st, claimed, err := svc.Claim(ctx, tenant, user)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if !claimed {
		t.Fatalf("first ever request was refused; state=%+v", st)
	}
	if st.LastRequestedAt == nil {
		t.Fatal("an accepted claim must report when it happened")
	}

	// 2. Second request immediately after — refused, and NOTHING written.
	before := *st.LastRequestedAt
	st2, claimed2, err := svc.Claim(ctx, tenant, user)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if claimed2 {
		t.Fatal("second request inside the 1h window was accepted — the cooldown does not hold")
	}
	if st2.Allowed {
		t.Fatal("a refused claim must report allowed=false")
	}
	if st2.NextAllowedAt == nil {
		t.Fatal("a refused claim must say when the next one is allowed")
	}
	// A blocked request must not extend the cooldown — otherwise a client that
	// retries in a loop can never get back in.
	if st2.LastRequestedAt == nil || !st2.LastRequestedAt.Equal(before) {
		t.Fatalf("blocked request moved last_requested_at: %v -> %v", before, st2.LastRequestedAt)
	}
	var count int
	if err := owner.QueryRow(`SELECT request_count FROM tenant_reevaluation_requests WHERE tenant_id = $1`, tenant).Scan(&count); err != nil {
		t.Fatalf("read request_count: %v", err)
	}
	if count != 1 {
		t.Fatalf("request_count = %d after one accepted + one blocked request, want 1", count)
	}

	// 3. Age the row past the window: the next request is allowed. (Backdating the
	// stored timestamp is the honest equivalent of waiting an hour — the predicate
	// under test compares the stored value against now().)
	if _, err := owner.Exec(
		`UPDATE tenant_reevaluation_requests SET last_requested_at = now() - interval '61 minutes' WHERE tenant_id = $1`,
		tenant); err != nil {
		t.Fatalf("age the cooldown row: %v", err)
	}
	st3, claimed3, err := svc.Claim(ctx, tenant, user)
	if err != nil {
		t.Fatalf("third claim: %v", err)
	}
	if !claimed3 {
		t.Fatalf("request after the window elapsed was refused; state=%+v", st3)
	}
}

// State must read what Claim wrote, and must report "never" as nil rather than a
// zero time — the UI renders "Not re-evaluated yet" off exactly that.
func TestIntegration_ReevaluationState_ReflectsClaims(t *testing.T) {
	svc, owner := newReevaluationFixture(t, time.Hour)
	tenant := testdb.NewTenant(t, owner)
	ctx := context.Background()

	st, err := svc.State(ctx, tenant)
	if err != nil {
		t.Fatalf("state before any claim: %v", err)
	}
	if st.LastRequestedAt != nil || !st.Allowed {
		t.Fatalf("a tenant that never ran one should be allowed with no last-run; got %+v", st)
	}

	if _, claimed, err := svc.Claim(ctx, tenant, uuid.New()); err != nil || !claimed {
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}
	st, err = svc.State(ctx, tenant)
	if err != nil {
		t.Fatalf("state after claim: %v", err)
	}
	if st.Allowed || st.LastRequestedAt == nil || st.NextAllowedAt == nil {
		t.Fatalf("after a claim the tenant should be in cooldown with both timestamps; got %+v", st)
	}
	if got := st.RetryAfter(time.Now()); got <= 0 || got > 3600 {
		t.Fatalf("RetryAfter = %d, want 1..3600", got)
	}
}

// One tenant's cooldown must not consume another's, and a tenant must not be able
// to see or affect another tenant's row (RLS, under the app role).
func TestIntegration_ReevaluationCooldown_IsPerTenant(t *testing.T) {
	svc, owner := newReevaluationFixture(t, time.Hour)
	a := testdb.NewTenant(t, owner)
	b := testdb.NewTenant(t, owner)
	ctx := context.Background()

	if _, claimed, err := svc.Claim(ctx, a, uuid.New()); err != nil || !claimed {
		t.Fatalf("tenant A claim: claimed=%v err=%v", claimed, err)
	}
	// B is untouched by A's claim.
	stB, err := svc.State(ctx, b)
	if err != nil {
		t.Fatalf("tenant B state: %v", err)
	}
	if !stB.Allowed || stB.LastRequestedAt != nil {
		t.Fatalf("tenant A's claim leaked into tenant B: %+v", stB)
	}
	if _, claimed, err := svc.Claim(ctx, b, uuid.New()); err != nil || !claimed {
		t.Fatalf("tenant B claim was blocked by tenant A's: claimed=%v err=%v", claimed, err)
	}
	// And A is still in cooldown — B's claim did not reset it.
	stA, err := svc.State(ctx, a)
	if err != nil {
		t.Fatalf("tenant A state: %v", err)
	}
	if stA.Allowed {
		t.Fatal("tenant B's claim released tenant A's cooldown")
	}

	// RLS: scoped to A, B's row is invisible. This is the cross-tenant read the
	// handler's context-only tenant derivation is the first line of defence for;
	// RLS is the second.
	var visible int
	err = shareddatabase.WithTenantTx(ctx, svc.db.DB, a, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT count(*) FROM tenant_reevaluation_requests WHERE tenant_id = $1`, b).Scan(&visible)
	})
	if err != nil {
		t.Fatalf("scoped read: %v", err)
	}
	if visible != 0 {
		t.Fatalf("tenant A can see %d of tenant B's cooldown rows under RLS, want 0", visible)
	}
}

// The platform-admin escape hatch is NOT rate-limited (owner decision). The admin
// path calls ReconcileEnqueuer directly and never touches this table; pinning it
// here means closing the exemption cannot happen silently.
func TestIntegration_PlatformAdminReevaluation_IsNotRateLimited(t *testing.T) {
	svc, owner := newReevaluationFixture(t, time.Hour)
	tenant := testdb.NewTenant(t, owner)
	ctx := context.Background()

	// A tenant-triggered run puts the tenant firmly in cooldown.
	if _, claimed, err := svc.Claim(ctx, tenant, uuid.New()); err != nil || !claimed {
		t.Fatalf("tenant claim: claimed=%v err=%v", claimed, err)
	}

	// The admin path: enqueue directly, repeatedly. A nil NATS client makes publish
	// a no-op, which is fine — what is under test is that nothing CONSULTS or
	// MUTATES the cooldown, not that a message reaches a broker.
	adminEnq := NewReconcileEnqueuer(nil, nil)
	for i := 0; i < 3; i++ {
		adminEnq.EnqueueTenant(tenant, "manual platform-admin re-evaluation")
	}

	var last time.Time
	var count int
	if err := owner.QueryRow(
		`SELECT last_requested_at, request_count FROM tenant_reevaluation_requests WHERE tenant_id = $1`,
		tenant).Scan(&last, &count); err != nil {
		t.Fatalf("read cooldown row: %v", err)
	}
	if count != 1 {
		t.Fatalf("platform-admin re-evaluations consumed the tenant cooldown (request_count=%d, want 1)", count)
	}
	// And the tenant's own cooldown is unchanged by them — neither extended nor
	// released.
	st, err := svc.State(ctx, tenant)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if st.Allowed {
		t.Fatal("admin re-evaluation released the tenant cooldown")
	}
}
