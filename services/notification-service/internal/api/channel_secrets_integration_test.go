package api

// The tenant channel credential contract, end to end: the REAL router, the REAL
// ChannelManager and a real Postgres (real user_has_permission, real RLS-scoped
// storage, real encryption at rest).
//
//   - a member without settings.read gets 403 on both channel reads;
//   - a member with settings.read gets 200 and no credential anywhere in the body;
//   - an update that echoes the masked config back, or omits the secret, leaves
//     the stored — i.e. delivered-with — credential intact;
//   - an update carrying a genuinely new secret replaces it.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const itMasterKey = "integration-test-master-key-32byt"

// memberWith creates a tenant member holding exactly the named permissions
// (none at all when perms is empty).
func memberWith(t *testing.T, db *sql.DB, tenant uuid.UUID, label string, perms ...string) uuid.UUID {
	t.Helper()
	user := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		user, tenant, label+"-"+user.String()[:8]+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if len(perms) == 0 {
		return user
	}
	var role uuid.UUID
	if err := db.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, $2) RETURNING id`,
		tenant, label+"-"+user.String()[:8]).Scan(&role); err != nil {
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

func TestIntegration_TenantChannels_CredentialContractThroughTheRealRouter(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")

	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	sdb := sqlx.NewDb(raw, "postgres")

	cfg := &config.Config{JWTSecret: gateTestSecret, EncryptionMasterKey: itMasterKey}
	cm := services.NewChannelManager(sdb, cfg, nil)
	srv := &Server{config: cfg, db: sdb, channelManager: cm}
	router := srv.SetupRouter()

	nobody := memberWith(t, raw, tenant, "nobody")
	reader := memberWith(t, raw, tenant, "reader", "settings.read")
	admin := memberWith(t, raw, tenant, "admin", "settings.read", "settings.update")

	do := func(user uuid.UUID, method, path string, body interface{}) *httptest.ResponseRecorder {
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, "/api/v1/notification-service/tenant"+path, rd)
		req.Header.Set("Authorization", "Bearer "+testdb.SignTenantToken(t, gateTestSecret, user, tenant, "viewer"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	const (
		url0   = "https://hooks.example.test/hook/URLSECRETFAKE0"
		token0 = "BEARERTOKENFAKE9876543210"
		hdr0   = "HEADERSECRETFAKE-abcdef"
	)
	secrets := []string{"URLSECRETFAKE0", token0, hdr0}

	// --- admin creates a webhook channel with three credentials -----------
	w := do(admin, http.MethodPost, "/channels", map[string]interface{}{
		"channel_name": "ops-webhook", "channel_type": "webhook", "enabled": true,
		"config": map[string]interface{}{
			"url":     url0,
			"headers": map[string]interface{}{"X-Api-Key": hdr0},
			"auth":    map[string]interface{}{"type": "bearer", "token": token0},
		},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	for _, s := range secrets {
		if strings.Contains(w.Body.String(), s) {
			t.Fatalf("create response leaked %q: %s", s, w.Body.String())
		}
	}
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	chPath := "/channels/" + created.ID.String()

	// --- the gate -----------------------------------------------------------
	for _, p := range []string{"/channels", chPath} {
		if w := do(nobody, http.MethodGet, p, nil); w.Code != http.StatusForbidden {
			t.Errorf("member without settings.read: GET %s = %d, want 403 (%s)", p, w.Code, w.Body.String())
		}
	}
	if w := do(reader, http.MethodPut, chPath, map[string]interface{}{"description": "nope"}); w.Code != http.StatusForbidden {
		t.Errorf("settings.read alone must not edit a channel: PUT = %d", w.Code)
	}

	// --- masked reads -------------------------------------------------------
	var listBody, getBody string
	for _, p := range []string{"/channels", chPath} {
		w := do(reader, http.MethodGet, p, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("reader GET %s = %d %s", p, w.Code, w.Body.String())
		}
		for _, s := range secrets {
			if strings.Contains(w.Body.String(), s) {
				t.Errorf("GET %s leaked %q: %s", p, s, w.Body.String())
			}
		}
		if !strings.Contains(w.Body.String(), "https://hooks.example.test/") {
			t.Errorf("GET %s: masked URL should still identify the host: %s", p, w.Body.String())
		}
		if p == chPath {
			getBody = w.Body.String()
		} else {
			listBody = w.Body.String()
		}
	}
	_ = listBody

	delivered := func() map[string]interface{} {
		ch, err := cm.GetTenantChannelByID(context.Background(), tenant, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		return ch.Config
	}
	assertIntact := func(label string) {
		t.Helper()
		got, _ := json.Marshal(delivered())
		for _, s := range secrets {
			if !strings.Contains(string(got), s) {
				t.Fatalf("%s: delivery config lost %q — the stored credential was destroyed: %s", label, s, got)
			}
		}
	}
	assertIntact("after create")

	// --- edit round trip: echo the masked GET body back ----------------------
	var got struct {
		Config map[string]interface{} `json:"config"`
	}
	_ = json.Unmarshal([]byte(getBody), &got)
	if w := do(admin, http.MethodPut, chPath, map[string]interface{}{
		"channel_name": "ops-webhook-renamed", "config": got.Config,
	}); w.Code != http.StatusOK {
		t.Fatalf("masked round-trip PUT = %d %s", w.Code, w.Body.String())
	}
	assertIntact("after echoing the masked config back")

	// --- edit that omits every secret ---------------------------------------
	if w := do(admin, http.MethodPut, chPath, map[string]interface{}{
		"config": map[string]interface{}{
			"channel": "#renamed", // url omitted entirely
			"headers": map[string]interface{}{"X-Api-Key": ""},
			"auth":    map[string]interface{}{"type": "bearer"}, // token omitted
		},
	}); w.Code != http.StatusOK {
		t.Fatalf("secret-omitting PUT = %d %s", w.Code, w.Body.String())
	}
	assertIntact("after a PUT that omitted the secrets")

	// --- a genuinely new value replaces ---------------------------------------
	const rotated = "https://hooks.example.test/hook/ROTATEDFAKE1"
	if w := do(admin, http.MethodPut, chPath, map[string]interface{}{
		"config": map[string]interface{}{"url": rotated},
	}); w.Code != http.StatusOK {
		t.Fatalf("rotating PUT = %d %s", w.Code, w.Body.String())
	}
	if cur, _ := json.Marshal(delivered()); !strings.Contains(string(cur), "ROTATEDFAKE1") || strings.Contains(string(cur), "URLSECRETFAKE0") {
		t.Fatalf("a new url must replace the stored one, got %s", cur)
	}
}
