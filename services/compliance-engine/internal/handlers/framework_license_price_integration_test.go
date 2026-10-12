package handlers

// A tenant POSTing price_cents to the self-service subscribe route must not
// get it recorded as purchase_price_cents. Real router, real service, real DB.
// Skips unless TEST_DATABASE_URL is set (see shared/testdb).

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SelfServiceSubscribeIgnoresTenantPrice(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	if _, err := raw.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		SELECT $1,id,'{"quantity":5}'::jsonb,'price test' FROM billable_items WHERE key='compliance_frameworks_max'`, tenant); err != nil {
		t.Fatalf("set cap: %v", err)
	}
	var fw uuid.UUID
	if err := raw.QueryRow(`SELECT id FROM platform_frameworks WHERE code = 'pqc-readiness' AND status = 'published' LIMIT 1`).Scan(&fw); err != nil {
		t.Fatalf("framework: %v", err)
	}

	svc := services.NewFrameworkLicenseService(sqlx.NewDb(raw, "postgres"))
	h := NewFrameworkLicenseHandlers(svc)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenantID", tenant)
		c.Set("userID", uuid.New())
		c.Next()
	})
	r.POST("/subscribe", h.SubscribeFramework)

	body := `{"framework_id":"` + fw.String() + `","price_cents":1,"set_as_default":true}`
	w := do(r, http.MethodPost, "/subscribe", strings.NewReader(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}

	var price *int
	var by string
	var isDefault bool
	if err := raw.QueryRow(`SELECT purchase_price_cents, provisioned_by, is_default FROM tenant_framework_licenses WHERE tenant_id=$1 AND platform_framework_id=$2`, tenant, fw).Scan(&price, &by, &isDefault); err != nil {
		t.Fatal(err)
	}
	if price != nil {
		t.Errorf("purchase_price_cents = %d, want NULL: a tenant named its own price", *price)
	}
	if by != "self_service" {
		t.Errorf("provisioned_by = %q", by)
	}
	if !isDefault {
		t.Error("set_as_default was not honoured")
	}
}
