package api

// GET /tenant/features on an Enterprise install, against a real database:
// the handler exactly as router.go mounts it (getTenantFeaturesHandler(db)),
// the real resolver, the real platform_license row, and a tenant that a
// platform admin switched SSO off for the way admin-service's switch writes it
// (a tenant_entitlements override {"enabled": false}, reason "operator: …").
//
//   - the switched-off feature reads false and every other Enterprise feature
//     true, so the tenant UI hides exactly what the admin switched off;
//   - billing_portal is false (MSP-only), so no billing controls render;
//   - the plan block says "Vista Platform Enterprise" with the licensee;
//   - the copy guard: the body never says "community" or "trial", although
//     the tenant row sits on the seeded community tier with a trial status.
//
// Scratch database because it writes the global licence row. Skips without
// TEST_DATABASE_URL.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_TenantFeatures_EnterpriseSwitchedOff(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	t.Cleanup(entitlements.FlushLicenseCache)

	if _, err := db.Exec(`INSERT INTO platform_license (subject, edition, licensee, expires_at, token_sha256)
		VALUES ('it', 'enterprise', 'Acme Corp', now() + interval '90 days', 'x')`); err != nil {
		t.Fatalf("write licence: %v", err)
	}
	entitlements.FlushLicenseCache()

	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'community'),
		payment_status = 'trial', trial_ends_at = now() + interval '30 days' WHERE id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, reason, effective_from)
		SELECT $1, id, '{"enabled": false}'::jsonb, 'operator: contractor tenant', now() - interval '1 minute'
		FROM billable_items WHERE key = 'sso_saml'`, tenant); err != nil {
		t.Fatalf("switch sso off: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("tenantID", tenant.String()); c.Next() })
	r.GET("/tenant/features", getTenantFeaturesHandler(db))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tenant/features", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Features map[string]bool   `json:"features"`
		Plan     entitlements.Plan `json:"plan"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for key, on := range resp.Features {
		want := entitlements.EditionCovers(entitlements.EditionEnterprise, key) && key != "sso_saml"
		if on != want {
			t.Errorf("%s = %v, want %v", key, on, want)
		}
	}
	if resp.Features["billing_portal"] {
		t.Error("billing_portal on for an Enterprise tenant")
	}
	if resp.Plan.DisplayName != entitlements.PlanDisplayNameEnterprise || resp.Plan.Licensee == nil || *resp.Plan.Licensee != "Acme Corp" {
		t.Errorf("plan = %+v", resp.Plan)
	}
	lower := strings.ToLower(w.Body.String())
	for _, word := range []string{"community", "trial"} {
		if strings.Contains(lower, word) {
			t.Errorf("Enterprise /tenant/features contains %q: %s", word, w.Body.String())
		}
	}

	// The tenant-facing plan catalogue (Settings → Billing's plan picker) is
	// empty on Enterprise: there are no plans, and each tier's retention_days
	// would describe a cap nobody is on.
	r.GET("/billing/tiers", getSubscriptionTiersHandler(db))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/billing/tiers", nil))
	if w.Code != http.StatusOK || w.Body.String() != `{"tiers":[]}` {
		t.Errorf("Enterprise /billing/tiers = %d %s, want an empty catalogue", w.Code, w.Body.String())
	}

	// GET /tenant/billing (the handler router.go mounts) names the plan, not
	// the placeholder tier, and never a trial.
	r.GET("/tenant/billing", GetTenantBilling(db, nil))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tenant/billing", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/tenant/billing status %d: %s", w.Code, w.Body.String())
	}
	lower = strings.ToLower(w.Body.String())
	for _, word := range []string{"community", "trial"} {
		if strings.Contains(lower, word) {
			t.Errorf("Enterprise /tenant/billing contains %q: %s", word, w.Body.String())
		}
	}
	if !strings.Contains(w.Body.String(), entitlements.PlanDisplayNameEnterprise) {
		t.Errorf("Enterprise /tenant/billing lacks the plan name: %s", w.Body.String())
	}
}
