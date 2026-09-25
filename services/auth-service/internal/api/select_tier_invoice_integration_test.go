package api

// POST /auth/select-tier through the REAL SetupRouter over a real database:
// a tenant billed by invoice that picks another plan for itself ends its
// invoice subscription in the same write (third review of, owner
// decision 5). The handler updates tenants.subscription_tier_id on the
// application role with no tenant context, where billing_subscriptions (RLS)
// is invisible; the tenants_plan_change_retires_manual_subscription trigger
// runs as the owner, so the row is retired anyway — status 'canceled',
// canceled_at set, end_reason 'plan_change'. (Whether that is churn is
// admin-service revenue's per-tenant rule: here the tenant picks the free
// plan and stops paying, so it is — revenue_churn_integration_test.go.)
// Before it, the row stayed 'active' and admin-service kept counting the
// invoice price as revenue for a plan the tenant had left.
//
// Mutation-checked: dropping the trigger, or its SECURITY DEFINER, turns
// this red. Scratch database: it writes the global manual billing provider.
// Skips without TEST_DATABASE_URL.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SelectTier_EndsTheInvoiceSubscription(t *testing.T) {
	owner := testdb.ScratchDatabase(t)
	app := testdb.ConnectScratchAsAppRole(t, owner)
	bypass := testdb.ConnectScratchAsBypassRole(t, owner)

	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: "test-secret-select-tier-invoice", JWTExpiry: time.Hour}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on this path
	t.Cleanup(func() { _ = rdb.Close() })
	router := SetupRouter(cfg, app, bypass, rdb, nil, EditionHooks{})

	// An invoice-billed tenant, as admin-service's Assign to tenant leaves it.
	var invoicePlan uuid.UUID
	if err := owner.QueryRow(`
		INSERT INTO subscription_tiers (name, display_name, price_cents, billing_interval, is_active, billing_method, retention_days)
		VALUES ($1, 'IT invoice', 90000, 'monthly', true, 'invoice', 90) RETURNING id`,
		"it-invoice-"+uuid.NewString()[:6]).Scan(&invoicePlan); err != nil {
		t.Fatal(err)
	}
	tenantID := uuid.New()
	if _, err := owner.Exec(`INSERT INTO tenants (id, name, slug, billing_email, subscription_tier_id, payment_status)
		VALUES ($1, 'Invoice customer', $2, '', $3, 'active')`, tenantID, "inv-"+tenantID.String()[:8], invoicePlan); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`
		WITH p AS (
			INSERT INTO billing_providers (key, display_name, is_active) VALUES ('manual', 'Manual / Invoice', true)
			ON CONFLICT (key) DO UPDATE SET is_active = true RETURNING id)
		INSERT INTO billing_subscriptions (tenant_id, provider_id, external_subscription_id, plan_key, status)
		SELECT $1, p.id, $2, 'it-invoice', 'active' FROM p`, tenantID, "invoice:"+invoicePlan.String()); err != nil {
		t.Fatal(err)
	}
	manual := func() (status string, dated bool, reason string) {
		t.Helper()
		var r sql.NullString
		if err := owner.QueryRow(`SELECT bs.status, bs.canceled_at IS NOT NULL, bs.end_reason FROM billing_subscriptions bs
			JOIN billing_providers bp ON bp.id = bs.provider_id AND bp.key = 'manual' WHERE bs.tenant_id = $1`, tenantID).
			Scan(&status, &dated, &r); err != nil {
			t.Fatal(err)
		}
		return status, dated, r.String
	}

	seedSystemRoles(t, owner, tenantID)
	user := newUserInRole(t, owner, tenantID, "billing_admin")
	var email string
	if err := owner.QueryRow(`SELECT email FROM users WHERE id = $1`, user).Scan(&email); err != nil {
		t.Fatal(err)
	}
	access, _, err := auth.NewJWTService(cfg.JWTSecret, time.Hour, time.Hour).GenerateTokens(user, tenantID, email, "billing_admin")
	if err != nil {
		t.Fatal(err)
	}

	free := tierIDByName(t, owner, "free")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/select-tier",
		strings.NewReader(`{"subscription_tier_id":"`+free.String()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("select-tier = %d %s", w.Code, w.Body.String())
	}
	if got := tenantTier(t, owner, tenantID); got != free {
		t.Fatalf("tenant tier = %s, want the selected free tier %s", got, free)
	}
	if s, d, r := manual(); s != "canceled" || !d || r != "plan_change" {
		t.Errorf("invoice subscription after selecting another plan = %s (dated %v, end_reason %q), want canceled, dated, plan_change", s, d, r)
	}
}
