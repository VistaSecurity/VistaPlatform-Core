package auth

import (
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Integration tests for BootstrapTrialIfApplicable. Skipped without
// TEST_DATABASE_URL — same convention as the resolver tests in
// shared/entitlements and internal/api/trial_status_test.go.

const bootstrapSkip = "TEST_DATABASE_URL not set; skipping DB-backed BootstrapTrialIfApplicable tests"

func openBootstrapDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip(bootstrapSkip)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping test db: %v", err)
	}
	return db
}

// applyBootstrapSchemaAndSeed delegates to the shared harness (advisory-lock
// serialized — concurrent appliers hit "tuple concurrently updated").
func applyBootstrapSchemaAndSeed(t *testing.T, db *sql.DB) {
	t.Helper()
	testdb.ApplySchemaAndSeed(t, db)
}

func bootstrapMkTenant(t *testing.T, db *sql.DB, tier string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	slug := "boot-" + id.String()[:8]
	_, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name=$4), NOW(), NOW())
	`, id, slug, slug, tier)
	if err != nil {
		t.Fatalf("create tenant on %s: %v", tier, err)
	}
	return id
}

// Direct construction of AuthService for the BootstrapTrialIfApplicable
// test — the method only uses a.db so the Redis/JWT/email fields stay nil
// here. NewAuthService can't be used because it dials Redis at construction.
func makeAuthForTest(db *sql.DB) *AuthService {
	return &AuthService{db: db, bypassDB: db}
}

func TestBootstrapTrialIfApplicable_FreeTier_InsertsRow(t *testing.T) {
	db := openBootstrapDB(t)
	applyBootstrapSchemaAndSeed(t, db)
	auth := makeAuthForTest(db)

	tenant := bootstrapMkTenant(t, db, "free")
	if err := auth.BootstrapTrialIfApplicable(tenant); err != nil {
		t.Fatalf("BootstrapTrialIfApplicable: %v", err)
	}

	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM billing_trial_tracking WHERE tenant_id = $1
	`, tenant).Scan(&n); err != nil {
		t.Fatalf("count trial rows: %v", err)
	}
	if n != 1 {
		t.Errorf("trial row count = %d, want 1", n)
	}
}

func TestBootstrapTrialIfApplicable_PaidTier_NoRow(t *testing.T) {
	db := openBootstrapDB(t)
	applyBootstrapSchemaAndSeed(t, db)
	auth := makeAuthForTest(db)

	// Starter is not a trial tier (is_trial=false). No row should be inserted.
	tenant := bootstrapMkTenant(t, db, "starter")
	if err := auth.BootstrapTrialIfApplicable(tenant); err != nil {
		t.Fatalf("BootstrapTrialIfApplicable: %v", err)
	}

	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM billing_trial_tracking WHERE tenant_id = $1
	`, tenant).Scan(&n); err != nil {
		t.Fatalf("count trial rows: %v", err)
	}
	if n != 0 {
		t.Errorf("paid tenant trial row count = %d, want 0", n)
	}
}

func TestBootstrapTrialIfApplicable_Idempotent(t *testing.T) {
	db := openBootstrapDB(t)
	applyBootstrapSchemaAndSeed(t, db)
	auth := makeAuthForTest(db)

	tenant := bootstrapMkTenant(t, db, "free")
	for i := 0; i < 3; i++ {
		if err := auth.BootstrapTrialIfApplicable(tenant); err != nil {
			t.Fatalf("call %d: BootstrapTrialIfApplicable: %v", i, err)
		}
	}

	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM billing_trial_tracking WHERE tenant_id = $1
	`, tenant).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("after 3 calls trial row count = %d, want 1 (idempotent)", n)
	}
}

func TestBootstrapTrialIfApplicable_NoTier_NoRow(t *testing.T) {
	db := openBootstrapDB(t)
	applyBootstrapSchemaAndSeed(t, db)
	auth := makeAuthForTest(db)

	id := uuid.New()
	slug := "ntr-" + id.String()[:8]
	if _, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, id, slug, slug); err != nil {
		t.Fatalf("create no-tier tenant: %v", err)
	}

	if err := auth.BootstrapTrialIfApplicable(id); err != nil {
		t.Fatalf("BootstrapTrialIfApplicable: %v", err)
	}

	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM billing_trial_tracking WHERE tenant_id = $1
	`, id).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("tenant with no tier should get no trial row; got %d", n)
	}
}
