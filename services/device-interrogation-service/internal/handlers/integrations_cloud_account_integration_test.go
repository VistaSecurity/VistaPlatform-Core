package handlers

// The cloud account as an asset, declared by the integration write path
// (asset-inventory ADR-0009 D1), and the account auto-approval rule derived
// from the integration's setting (D5) — through the REAL handlers, the real
// repository, the real identity engine (the reference sighting route) and the
// real schema.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/cloudaccount"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type cloudAccountFixture struct {
	owner  *sql.DB
	engine *gin.Engine
	tenant uuid.UUID
}

func newCloudAccountFixture(t *testing.T) *cloudAccountFixture {
	t.Helper()
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/device-interrogation-service")
	grp.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Next() })
	h := NewIntegrationHandlers(app, owner, testEncryptionKey)
	grp.GET("/integrations", h.ListIntegrations)
	grp.POST("/integrations", h.CreateIntegration)
	grp.GET("/integrations/:id", h.GetIntegration)
	grp.PUT("/integrations/:id", h.UpdateIntegration)
	grp.DELETE("/integrations/:id", h.DeleteIntegration)
	return &cloudAccountFixture{owner: owner, engine: r, tenant: tenant}
}

func (f *cloudAccountFixture) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, "/api/v1/device-interrogation-service"+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.engine.ServeHTTP(w, req)
	return w
}

// createAWS adds an AWS integration for the account through POST /integrations.
func (f *cloudAccountFixture) createAWS(t *testing.T, account string, autoApprove *bool) CloudIntegration {
	t.Helper()
	body := map[string]any{
		"integration_type": "aws",
		"integration_name": "aws-" + uuid.NewString()[:8],
		"provider":         "cloud",
		"account_id":       account,
		"config":           map[string]any{"access_key_id": "AKIAEXAMPLEEXAMPLE", "secret_access_key": "secret-secret-secret"},
	}
	if autoApprove != nil {
		body["auto_approve_resources"] = *autoApprove
	}
	w := f.do(t, http.MethodPost, "/integrations", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create integration: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Integration CloudIntegration `json:"integration"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Integration
}

func (f *cloudAccountFixture) get(t *testing.T, id uuid.UUID) CloudIntegration {
	t.Helper()
	w := f.do(t, http.MethodGet, "/integrations/"+id.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get integration: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Integration CloudIntegration `json:"integration"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Integration
}

type accountAssetRow struct {
	id, class, status string
	integrationIDs    []string
}

func (f *cloudAccountFixture) accountAssets(t *testing.T, account string) []accountAssetRow {
	t.Helper()
	rows, err := f.owner.Query(`
		SELECT a.id::text, a.class_key, a.asset_status, coalesce(a.attributes->'integration_ids', '[]'::jsonb)
		  FROM assets a JOIN asset_identifiers i ON i.asset_id = a.id AND i.tenant_id = a.tenant_id
		 WHERE a.tenant_id = $1 AND i.kind = 'cloud_resource_id' AND i.value = $2 AND a.deleted_at IS NULL`,
		f.tenant, cloudaccount.ResourceID("aws", account))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []accountAssetRow
	for rows.Next() {
		var r accountAssetRow
		var ids []byte
		if err := rows.Scan(&r.id, &r.class, &r.status, &ids); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(ids, &r.integrationIDs)
		out = append(out, r)
	}
	return out
}

// accountRule returns whether the account's rule exists and is active.
func (f *cloudAccountFixture) accountRule(t *testing.T, account string) (exists, active bool) {
	t.Helper()
	rows, err := f.owner.Query(`SELECT query, is_active FROM discovery_auto_approval_rules WHERE tenant_id = $1`, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var q string
		var a bool
		if err := rows.Scan(&q, &a); err != nil {
			t.Fatal(err)
		}
		if acct, ok := approval.CloudAccountIDFromQuery(q); ok && acct == account {
			if exists {
				t.Fatalf("two rules for account %s", account)
			}
			exists, active = true, a
		}
	}
	return exists, active
}

// TestIntegration_CreateIntegration_UpsertsAccountAsset_Idempotent: adding an
// integration declares its account as ONE approved `cloud_account` asset; a
// second integration for the same account matches it rather than minting a
// second; both integrations report it; deleting one leaves it in place.
//
// Mutation: give the account's identifier a per-call value (drop the identity
// lookup) and the second create mints a second asset.
func TestIntegration_CreateIntegration_UpsertsAccountAsset_Idempotent(t *testing.T) {
	f := newCloudAccountFixture(t)
	account := "2" + uuid.NewString()[:11]

	first := f.createAWS(t, account, nil)
	if !first.AutoApproveResources {
		t.Fatal("auto_approve_resources must default to true (ADR-0009 D5)")
	}
	assets := f.accountAssets(t, account)
	if len(assets) != 1 {
		t.Fatalf("%d account assets after the first integration, want 1", len(assets))
	}
	acct := assets[0]
	if acct.class != cloudaccount.ClassKey || acct.status != "monitoring" {
		t.Fatalf("account asset = %+v, want class %s, monitoring (approved by the act of adding it)", acct, cloudaccount.ClassKey)
	}

	second := f.createAWS(t, account, nil)
	assets = f.accountAssets(t, account)
	if len(assets) != 1 || assets[0].id != acct.id {
		t.Fatalf("a second integration for the same account produced %v, want the one asset %s", assets, acct.id)
	}
	if len(assets[0].integrationIDs) != 2 {
		t.Fatalf("integration_ids = %v, want both integrations", assets[0].integrationIDs)
	}
	for _, in := range []CloudIntegration{first, second} {
		got := f.get(t, in.ID)
		if got.AccountAssetID == nil || *got.AccountAssetID != acct.id {
			t.Fatalf("integration %s reports account asset %v, want %s", in.ID, got.AccountAssetID, acct.id)
		}
	}
	if exists, active := f.accountRule(t, account); !exists || !active {
		t.Fatalf("account rule exists=%v active=%v, want an active rule", exists, active)
	}

	if w := f.do(t, http.MethodDelete, "/integrations/"+first.ID.String(), nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if assets := f.accountAssets(t, account); len(assets) != 1 || assets[0].id != acct.id {
		t.Fatalf("deleting an integration must not delete the account asset; now %v", assets)
	}
}

// A connected cloud account is authoritative provider-API evidence. Under
// identity admission enforcement it must therefore materialize immediately,
// rather than being retained as an unresolved observation with no account
// asset or site.
func TestIntegration_CreateIntegration_AccountMaterializesWithAdmissionEnforced(t *testing.T) {
	f := newCloudAccountFixture(t)
	if _, err := f.owner.Exec(`UPDATE tenants SET subscription_tier_id=(SELECT id FROM subscription_tiers WHERE name='free') WHERE id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config)
		VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
		ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, f.tenant); err != nil {
		t.Fatal(err)
	}

	account := "123456789012"
	in := f.createAWS(t, account, nil)
	assets := f.accountAssets(t, account)
	if len(assets) != 1 || assets[0].status != "monitoring" {
		t.Fatalf("account assets = %+v, want one monitoring asset", assets)
	}
	if got := f.get(t, in.ID); got.AccountAssetID == nil || *got.AccountAssetID != assets[0].id {
		t.Fatalf("integration account asset = %v, want %s", got.AccountAssetID, assets[0].id)
	}
}

// The switch, both polarities: off on every integration for the account
// deactivates its rule; on again reactivates the same rule. Mutation: invert
// the auto_approve_resources read in the account sync and this goes red.
func TestIntegration_UpdateIntegration_AutoApproveSwitchDrivesTheAccountRule(t *testing.T) {
	f := newCloudAccountFixture(t)
	account := "3" + uuid.NewString()[:11]
	off := false
	in := f.createAWS(t, account, &off)
	if exists, active := f.accountRule(t, account); exists && active {
		t.Fatal("an integration created with auto-approve off has an active account rule")
	}

	if w := f.do(t, http.MethodPut, "/integrations/"+in.ID.String(), map[string]any{"auto_approve_resources": true}); w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	if exists, active := f.accountRule(t, account); !exists || !active {
		t.Fatalf("after switching auto-approve on: rule exists=%v active=%v", exists, active)
	}
	if got := f.get(t, in.ID); !got.AutoApproveResources {
		t.Fatal("GET does not report the switch the PUT set")
	}

	if w := f.do(t, http.MethodPut, "/integrations/"+in.ID.String(), map[string]any{"auto_approve_resources": false}); w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	if exists, active := f.accountRule(t, account); !exists || active {
		t.Fatalf("after switching auto-approve off: rule exists=%v active=%v, want present and inactive", exists, active)
	}
}
