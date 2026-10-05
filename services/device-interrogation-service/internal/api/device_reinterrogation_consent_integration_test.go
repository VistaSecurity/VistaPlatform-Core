package api

// The platform re-interrogation consent, through the REAL router: real
// RequireAuth, real RequireTenantPermission against user_has_permission(), real
// handlers and DeviceService on a schema-and-seed-loaded database. The consent
// is the operator's decision that lets identity enrichment re-run a device's
// interrogation unattended, so who can flip it is the point of this test, not
// the storage.
//
//   - a member with discovery.read only is refused (403) and nothing changes;
//   - a member of ANOTHER tenant holding discovery.update cannot reach the
//     device (404) and nothing changes;
//   - a member with discovery.update grants it, reads it back, and withdraws it;
//   - free-form `metadata` carrying the consent key is accepted as metadata but
//     never grants the consent;
//   - Add device by hand (POST /devices, discovery.create) can grant it.
//
// Mutation performed, observed red, then restored: drop
// RequireTenantPermission(db, rbac.PermissionDiscoveryUpdate) from
// devices.PUT("/:id", ...) in router.go → the read-only member's PUT is
// answered 200 and the consent lands.
//
// Skipped unless TEST_DATABASE_URL is set (make test-integration-db).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const consentGateSecret = "device-reinterrogation-consent-gate-test"

// The router's device service reads ENCRYPTION_MASTER_KEY; the fixture's must
// match so credentials written here decrypt there.
const consentMasterKey = "test-key-for-consent-gate-tests-only"

// tenantMember creates a user in tenant holding exactly perms.
func tenantMember(t *testing.T, db *sql.DB, tenant uuid.UUID, label string, perms ...string) uuid.UUID {
	t.Helper()
	user := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, user, tenant, label+"-"+user.String()[:8]+"@example.test"); err != nil {
		t.Fatal(err)
	}
	var role uuid.UUID
	if err := db.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, $2) RETURNING id`, tenant, label+"-"+user.String()[:8]).Scan(&role); err != nil {
		t.Fatal(err)
	}
	for _, p := range perms {
		res, err := db.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) SELECT $1, id FROM tenant_permissions WHERE name = $2`, role, p)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("permission %q is not in the seeded catalogue", p)
		}
	}
	if _, err := db.Exec(`INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active) VALUES ($1, $2, $3, true)`, user, tenant, role); err != nil {
		t.Fatal(err)
	}
	return user
}

func TestIntegration_DeviceReinterrogationConsent_RealRouter(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", consentMasterKey)
	t.Setenv("NATS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	router := SetupRouter(&config.Config{JWTSecret: consentGateSecret}, db, db, nil)

	tenant := testdb.NewTenant(t, db)
	foreign := testdb.NewTenant(t, db)
	reader := tenantMember(t, db, tenant, "reader", string(rbac.PermissionDiscoveryRead))
	editor := tenantMember(t, db, tenant, "editor", string(rbac.PermissionDiscoveryRead), string(rbac.PermissionDiscoveryCreate), string(rbac.PermissionDiscoveryUpdate))
	outsider := tenantMember(t, db, foreign, "outsider", string(rbac.PermissionDiscoveryRead), string(rbac.PermissionDiscoveryUpdate))

	devices := services.NewDeviceServiceWithKey(db, consentMasterKey)
	device, err := devices.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: strptrAPI("controller.example.test"), ManagementURL: strptrAPI("https://192.0.2.2")})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/device-interrogation-service/devices/" + device.ID.String()

	do := func(user, userTenant uuid.UUID, method, p string, body interface{}) *httptest.ResponseRecorder {
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, p, rd)
		req.Header.Set("Authorization", "Bearer "+testdb.SignTenantToken(t, consentGateSecret, user, userTenant, "admin"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	stored := func() bool {
		t.Helper()
		var v sql.NullString
		if err := db.QueryRow(`SELECT metadata->'device_metadata'->>$3 FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, device.ID, services.PlatformReinterrogationKey).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v.String == "platform"
	}
	read := func(w *httptest.ResponseRecorder) models.Device {
		t.Helper()
		var d models.Device
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
			t.Fatalf("decode %s: %v", w.Body.String(), err)
		}
		return d
	}
	grant := map[string]interface{}{"platform_reinterrogation_allowed": true}

	if w := do(reader, tenant, http.MethodPut, path, grant); w.Code != http.StatusForbidden {
		t.Fatalf("discovery.read alone: PUT = %d %s, want 403", w.Code, w.Body.String())
	}
	if stored() {
		t.Fatal("a refused PUT stored the consent")
	}
	if w := do(outsider, foreign, http.MethodPut, path, grant); w.Code != http.StatusNotFound {
		t.Fatalf("another tenant: PUT = %d %s, want 404", w.Code, w.Body.String())
	}
	if stored() {
		t.Fatal("another tenant stored the consent")
	}

	// Smuggled through free-form metadata: kept as metadata, never consent.
	w := do(editor, tenant, http.MethodPut, path, map[string]interface{}{"metadata": map[string]interface{}{services.PlatformReinterrogationKey: "platform", "site": "lab"}})
	if w.Code != http.StatusOK {
		t.Fatalf("metadata PUT = %d %s", w.Code, w.Body.String())
	}
	if d := read(w); d.PlatformReinterrogationAllowed || stored() || d.Metadata["site"] != "lab" {
		t.Fatalf("smuggled consent: allowed=%v stored=%v metadata=%v", d.PlatformReinterrogationAllowed, stored(), d.Metadata)
	}

	w = do(editor, tenant, http.MethodPut, path, grant)
	if w.Code != http.StatusOK || !read(w).PlatformReinterrogationAllowed || !stored() {
		t.Fatalf("grant: %d %s stored=%v", w.Code, w.Body.String(), stored())
	}
	w = do(reader, tenant, http.MethodGet, path, nil)
	if w.Code != http.StatusOK || !read(w).PlatformReinterrogationAllowed || read(w).InterrogatedByAgent {
		t.Fatalf("read back: %d %s", w.Code, w.Body.String())
	}
	w = do(editor, tenant, http.MethodPut, path, map[string]interface{}{"platform_reinterrogation_allowed": false})
	if w.Code != http.StatusOK || read(w).PlatformReinterrogationAllowed || stored() {
		t.Fatalf("withdraw: %d %s stored=%v", w.Code, w.Body.String(), stored())
	}

	// Add device by hand carries it too.
	w = do(editor, tenant, http.MethodPost, "/api/v1/device-interrogation-service/devices", map[string]interface{}{
		"device_type": "unifi", "hostname": "added.example.test", "management_url": "https://192.0.2.3", "platform_reinterrogation_allowed": true,
	})
	if w.Code != http.StatusCreated || !read(w).PlatformReinterrogationAllowed {
		t.Fatalf("create with consent: %d %s", w.Code, w.Body.String())
	}
}

func strptrAPI(s string) *string { return &s }
