package handlers

// Real-router test for GET /admin/tiers/:id/impact-analysis (skips without
// TEST_DATABASE_URL).
//
// The analysis compared the legacy subscription_tiers.max_* columns, which the
// plan editor never writes on edit — so for an admin-authored plan it reported
// "no change / 0 tenants over limit" whatever the composition did. It also
// counted platform collectors as the tenant's sensors and ignored pending
// invitations, so its usage disagreed with the gates it claims to predict.
// The scratch tiers here carry legacy columns that CONTRADICT their
// composition; the assertions can only pass if the composition is what is
// compared.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_TierImpactAnalysis_ComparesResolvedEntitlements(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	InitializeTierService(db, db)

	n999 := 999
	mkTier := func(suffix string, sensors, users int) uuid.UUID {
		t.Helper()
		name := "impact-" + suffix + "-" + uuid.New().String()[:8]
		tier, err := tierService.CreateTier(models.TierCreateRequest{
			Name: name, DisplayName: name, BillingInterval: "month", BillingMethod: "invoice",
			// Legacy columns say 999 for everything; the composition says otherwise.
			MaxSensors: &n999, MaxAssets: &n999, MaxUsers: &n999,
			Entitlements: []models.TierEntitlementInput{
				{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": ` + strconv.Itoa(sensors) + `}`)},
				{ItemKey: "max_users", IncludedValue: json.RawMessage(`{"quantity": ` + strconv.Itoa(users) + `}`)},
				{ItemKey: "max_assets", IncludedValue: json.RawMessage(`{"quantity": null}`)},
			},
		}, uuid.Nil)
		if err != nil {
			t.Fatalf("CreateTier %s: %v", suffix, err)
		}
		return tier.ID
	}
	source := mkTier("src", 5, 10)
	target := mkTier("dst", 2, 1)

	tenant := testdb.NewTenant(t, db)
	// Detach the tenant before the tiers are deleted (Cleanups run LIFO, and
	// NewTenant's runs last).
	t.Cleanup(func() {
		_, _ = db.Exec(`UPDATE tenants SET subscription_tier_id = NULL WHERE id = $1`, tenant)
		_, _ = db.Exec(`DELETE FROM subscription_tiers WHERE id IN ($1, $2)`, source, target)
	})
	if _, err := db.Exec(`UPDATE tenants SET subscription_tier_id = $1 WHERE id = $2`, source, tenant); err != nil {
		t.Fatalf("assign tier: %v", err)
	}

	// Usage: 3 registered sensors (plus the trigger-seeded platform collectors
	// and one row carrying ONLY the system tag, which must NOT count), 1 user +
	// 1 pending invitation (= 2 seats). The tag-only row pins the second arm of
	// the shared platform predicate; trigger rows carry both markers and cannot.
	for i := 0; i < 3; i++ {
		if _, err := db.Exec(`
			INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, created_at, updated_at)
			VALUES ($1, $2, 'impact-sensor', 'linux', '1.0.0', 'standard', 'active', NOW(), NOW())
		`, uuid.New(), tenant); err != nil {
			t.Fatalf("seed sensor: %v", err)
		}
	}
	if _, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, tags, created_at, updated_at)
		VALUES ($1, $2, 'impact-system-tag-only', 'linux', '1.0.0', 'standard', 'active', ARRAY['system'], NOW(), NOW())
	`, uuid.New(), tenant); err != nil {
		t.Fatalf("seed tag-only platform sensor: %v", err)
	}
	var platformSeeded int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE tenant_id = $1 AND platform = 'platform'`, tenant).Scan(&platformSeeded)
	if platformSeeded == 0 {
		t.Fatal("expected trigger-seeded platform sensors; without them the exclusion is untested")
	}
	if _, err := db.Exec(`
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name)
		VALUES ($1, $2, $3, 'x', 'Impact', 'User')
	`, uuid.New(), tenant, "impact-"+tenant.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO invitations (tenant_id, email, role, token_hash, status, expires_at)
		VALUES ($1, $2, 'viewer', $3, 'pending', NOW() + INTERVAL '1 day')
	`, tenant, "invite-"+tenant.String()[:8]+"@example.test", uuid.New().String()); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET(apiBase+"/admin/tiers/:id/impact-analysis", TierImpactAnalysis)
	w := doRequest(r, http.MethodGet, apiBase+"/admin/tiers/"+source.String()+"/impact-analysis?target_tier_id="+target.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var got struct {
		AffectedTenants int `json:"affected_tenants"`
		TenantDetails   []struct {
			TenantID uuid.UUID `json:"tenant_id"`
			Usage    struct {
				Assets  int `json:"assets"`
				Users   int `json:"users"`
				Sensors int `json:"sensors"`
			} `json:"current_usage"`
		} `json:"tenant_details"`
		LimitChanges []struct {
			Field            string `json:"field"`
			CurrentLimit     *int   `json:"current_limit"`
			NewLimit         *int   `json:"new_limit"`
			Impact           string `json:"impact"`
			TenantsOverLimit int    `json:"tenants_over_limit"`
		} `json:"limit_changes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, w.Body.String())
	}
	if got.AffectedTenants != 1 || len(got.TenantDetails) != 1 {
		t.Fatalf("affected_tenants = %d (%d details), want 1", got.AffectedTenants, len(got.TenantDetails))
	}
	u := got.TenantDetails[0].Usage
	if u.Sensors != 3 {
		t.Errorf("usage.sensors = %d, want 3 — %d platform collectors must not count against the tenant", u.Sensors, platformSeeded)
	}
	if u.Users != 2 {
		t.Errorf("usage.users = %d, want 2 (1 user + 1 pending invitation, as CheckUserLimit counts)", u.Users)
	}

	changes := map[string]struct {
		cur, next *int
		over      int
		impact    string
	}{}
	for _, c := range got.LimitChanges {
		changes[c.Field] = struct {
			cur, next *int
			over      int
			impact    string
		}{c.CurrentLimit, c.NewLimit, c.TenantsOverLimit, c.Impact}
	}
	s, ok := changes["max_sensors"]
	if !ok {
		t.Fatalf("no max_sensors change reported; with the legacy 999 columns it would read 'no change' — got %+v", got.LimitChanges)
	}
	if s.cur == nil || *s.cur != 5 || s.next == nil || *s.next != 2 {
		t.Errorf("max_sensors change = %v -> %v, want 5 -> 2 (the compositions, not the 999 columns)", s.cur, s.next)
	}
	if s.over != 1 {
		t.Errorf("max_sensors tenants_over_limit = %d, want 1 (3 registered sensors > 2)", s.over)
	}
	us, ok := changes["max_users"]
	if !ok {
		t.Fatalf("no max_users change reported — got %+v", got.LimitChanges)
	}
	if us.cur == nil || *us.cur != 10 || us.next == nil || *us.next != 1 {
		t.Errorf("max_users change = %v -> %v, want 10 -> 1", us.cur, us.next)
	}
	if us.over != 1 {
		t.Errorf("max_users tenants_over_limit = %d, want 1 (2 seats > 1)", us.over)
	}
	if _, reported := changes["max_assets"]; reported {
		t.Errorf("max_assets reported as a change though both tiers grant unlimited: %+v", changes["max_assets"])
	}
}
