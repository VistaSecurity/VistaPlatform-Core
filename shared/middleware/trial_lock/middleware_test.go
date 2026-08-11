package trial_lock_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	trial_lock "github.com/vistasecurity/vistaplatform/shared/middleware/trial_lock"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const skip = "TEST_DATABASE_URL not set; skipping DB-backed trial_lock middleware tests"

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip(skip)
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

// applySchemaAndSeed delegates to the shared harness (advisory-lock
// serialized — concurrent appliers hit "tuple concurrently updated").
func applySchemaAndSeed(t *testing.T, db *sql.DB) {
	t.Helper()
	testdb.ApplySchemaAndSeed(t, db)
}

func mkTenant(t *testing.T, db *sql.DB, tier string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	slug := "tl-" + id.String()[:8]
	_, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name=$4), NOW(), NOW())
	`, id, slug, slug, tier)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return id
}

// mkTrial inserts a billing_trial_tracking row aged trialAgeDays ago.
// 30+ days = locked, 20 = soft_prompt, 5 = full.
func mkTrial(t *testing.T, db *sql.DB, tenantID uuid.UUID, trialAgeDays int) {
	t.Helper()
	trialStart := time.Now().Add(time.Duration(-trialAgeDays) * 24 * time.Hour)
	trialEnd := trialStart.Add(28 * 24 * time.Hour)
	_, err := db.Exec(`
		INSERT INTO billing_trial_tracking (tenant_id, trial_start, trial_end, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, tenantID, trialStart, trialEnd)
	if err != nil {
		t.Fatalf("insert trial: %v", err)
	}
}

// newRouter wires a tiny Gin engine with the middleware + a no-op
// handler at every method, so tests can hit any verb and any path.
func newRouter(db *sql.DB, tenantID uuid.UUID, cfg *trial_lock.Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Stub the auth layer: every request gets the test tenant in
	// context, mirroring what RequireAuth would do upstream.
	r.Use(func(c *gin.Context) {
		if tenantID != uuid.Nil {
			c.Set("tenantID", tenantID.String())
		}
		c.Next()
	})
	r.Use(trial_lock.Middleware(db, cfg))
	noop := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	r.Any("/*any", noop)
	return r
}

// newRouterUUIDContext mirrors newRouter but stores the tenant ID as a
// uuid.UUID under "tenantID" — exactly how the real JWT auth middleware
// (shared/middleware.RequireJWTAuth) populates the context. The original
// string-based newRouter masked a production no-op: the middleware only
// read the string form, so a real uuid.UUID-typed value fell through and
// the lock never fired. This helper exercises the production path.
func newRouterUUIDContext(db *sql.DB, tenantID uuid.UUID, cfg *trial_lock.Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if tenantID != uuid.Nil {
			c.Set("tenantID", tenantID) // uuid.UUID, not string
		}
		c.Next()
	})
	r.Use(trial_lock.Middleware(db, cfg))
	noop := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	r.Any("/*any", noop)
	return r
}

func do(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestPassthrough_GETAlwaysAllowed(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	locked := mkTenant(t, db, "free")
	mkTrial(t, db, locked, 30) // hard-locked

	r := newRouter(db, locked, nil)
	for _, p := range []string{"/api/v2/inventory-service/assets", "/dashboard", "/anything"} {
		w := do(r, http.MethodGet, p)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s should pass; got %d body=%s", p, w.Code, w.Body.String())
		}
	}
}

func TestBlock_WritesByLockedTenant(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	locked := mkTenant(t, db, "free")
	mkTrial(t, db, locked, 30) // hard-locked

	r := newRouter(db, locked, nil)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		w := do(r, method, "/api/v2/inventory-service/assets")
		if w.Code != http.StatusLocked {
			t.Errorf("%s should return 423 for locked tenant; got %d", method, w.Code)
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["error"] != "trial_locked" {
			t.Errorf("error body = %v; want trial_locked", body["error"])
		}
	}
}

// TestBlock_WritesByLockedTenant_UUIDContext is the regression guard for
// the bug Cursor Bugbot caught: the middleware must resolve a tenant ID
// stored as a uuid.UUID (the real JWT path), not only a string. Without
// the fix this test fails open (200) because the tenant never resolves.
func TestBlock_WritesByLockedTenant_UUIDContext(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	locked := mkTenant(t, db, "free")
	mkTrial(t, db, locked, 30) // hard-locked

	r := newRouterUUIDContext(db, locked, nil)
	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusLocked {
		t.Errorf("uuid.UUID-context locked tenant POST should 423; got %d (bug: tenant ID not resolved from uuid.UUID)", w.Code)
	}
}

func TestPassthrough_FullPhaseTenantCanWrite(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	active := mkTenant(t, db, "free")
	mkTrial(t, db, active, 5) // day 5 of 14 — PhaseFull

	r := newRouter(db, active, nil)
	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusOK {
		t.Errorf("active-trial tenant POST should pass; got %d body=%s", w.Code, w.Body.String())
	}
}

func TestPassthrough_SoftPromptTenantCanWrite(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	tenant := mkTenant(t, db, "free")
	mkTrial(t, db, tenant, 20) // day 20 of 28 — PhaseSoftPrompt

	r := newRouter(db, tenant, nil)
	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusOK {
		t.Errorf("soft-prompt tenant POST should pass; got %d", w.Code)
	}
}

func TestPassthrough_PaidTenantCanWrite(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	tenant := mkTenant(t, db, "pro")
	// No trial row — PhaseNone.

	r := newRouter(db, tenant, nil)
	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusOK {
		t.Errorf("paid tenant POST should pass; got %d", w.Code)
	}
}

func TestPassthrough_ConvertedTenantCanWrite(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	tenant := mkTenant(t, db, "free")
	mkTrial(t, db, tenant, 30) // age would be locked, but...
	_, _ = db.Exec(`UPDATE billing_trial_tracking SET converted_to_paid = true WHERE tenant_id = $1`, tenant)

	r := newRouter(db, tenant, nil)
	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusOK {
		t.Errorf("converted tenant POST should pass; got %d", w.Code)
	}
}

func TestPassthrough_AllowedPathPrefix(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	locked := mkTenant(t, db, "free")
	mkTrial(t, db, locked, 30)

	r := newRouter(db, locked, nil)
	// Default config allow-listed paths — locked tenant should be
	// able to POST to billing flows.
	for _, p := range []string{
		"/api/v1/auth-service/auth/refresh",
		"/api/v1/auth-service/tenant/billing/upgrade",
		"/api/v2/admin-service/my-billing/subscriptions",
	} {
		w := do(r, http.MethodPost, p)
		if w.Code != http.StatusOK {
			t.Errorf("locked tenant POST to allow-listed %s should pass; got %d", p, w.Code)
		}
	}
}

func TestPassthrough_NoTenantInContext(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	// Pass nil tenant — internal traffic with no auth context.
	r := newRouter(db, uuid.Nil, nil)

	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusOK {
		t.Errorf("unauthenticated POST should pass; got %d", w.Code)
	}
}

func TestDisabled_PassthroughOnEverything(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	locked := mkTenant(t, db, "free")
	mkTrial(t, db, locked, 30)

	cfg := trial_lock.DefaultConfig()
	cfg.Enabled = false
	r := newRouter(db, locked, cfg)
	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusOK {
		t.Errorf("disabled middleware should pass everything; got %d", w.Code)
	}
}

func TestBlock_ResponseBodyShape(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	locked := mkTenant(t, db, "free")
	mkTrial(t, db, locked, 40)

	r := newRouter(db, locked, nil)
	w := do(r, http.MethodPost, "/api/v2/inventory-service/assets")
	if w.Code != http.StatusLocked {
		t.Fatalf("want 423; got %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	for _, k := range []string{"error", "message", "upgrade_path"} {
		if _, ok := body[k]; !ok {
			t.Errorf("response body missing field %q: %v", k, body)
		}
	}
}

// Defensive — make sure the SQL doesn't choke when the join is empty
// (paid tenant + no trial row). This is the common case in production.
func TestResolverNoTrialRow(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	pro := mkTenant(t, db, "pro")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Run the resolver via the middleware indirectly — issue a POST
	// and confirm it isn't gated.
	r := newRouter(db, pro, nil)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/anywhere", strings.NewReader(""))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("pro tenant should pass; got %d", w.Code)
	}
}
