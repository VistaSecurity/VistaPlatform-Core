package handlers

// GET /admin/integrations/:id used to return the stored cloud credentials
// DECRYPTED, to any holder of platform.settings, with no audit row. Create and
// update echoed them too. Every response now carries the config with each
// secret masked plus has_credentials; an edit that leaves a secret blank (or
// echoes the mask) keeps the stored one.
//
// Driven through the real handlers against a real Postgres (skips without
// TEST_DATABASE_URL).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Integrations_ResponsesMaskSecretsAndBlankKeepsThem(t *testing.T) {
	db := testdb.Connect(t)
	InitializeIntegrationService(db, db, retiredTypesITMasterKey, logrus.New())
	gin.SetMode(gin.TestMode)
	userID := itPlatformUser(t, db)
	r := gin.New()
	as := func(h gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) { c.Set("userID", userID.String()); h(c) }
	}
	r.POST("/integrations", as(CreateIntegration()))
	r.PUT("/integrations/:id", as(UpdateIntegration()))
	r.GET("/integrations/:id", as(GetIntegration()))

	const secret = "s3cr3t-api-key-VALUE"
	body := func(apiKey interface{}) map[string]interface{} {
		cfg := map[string]interface{}{"base_url": "https://api.example.test"}
		if apiKey != nil {
			cfg["api_key"] = apiKey
		}
		return map[string]interface{}{
			"integration_type": "custom", "integration_name": "masking-" + uuid.NewString(),
			"provider": "saas", "config": cfg, "is_enabled": true,
		}
	}
	storedKey := func(id string) string {
		t.Helper()
		var cfg string
		if err := db.QueryRowContext(context.Background(), `SELECT config::text FROM platform_integrations WHERE id = $1`, id).Scan(&cfg); err != nil {
			t.Fatal(err)
		}
		var m map[string]interface{}
		_ = json.Unmarshal([]byte(cfg), &m)
		s, _ := m["api_key"].(string)
		return s
	}
	assertMasked := func(what string, w interface {
		Bytes() []byte
		String() string
	}) map[string]interface{} {
		t.Helper()
		if strings.Contains(w.String(), secret) {
			t.Fatalf("%s returned the secret in the clear: %s", what, w.String())
		}
		var out struct {
			Integration struct {
				ID             string                 `json:"id"`
				Config         map[string]interface{} `json:"config"`
				HasCredentials bool                   `json:"has_credentials"`
			} `json:"integration"`
		}
		if err := json.Unmarshal(w.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v (%s)", what, err, w.String())
		}
		if !out.Integration.HasCredentials || out.Integration.Config["api_key"] != "********" {
			t.Fatalf("%s: want has_credentials and a masked api_key, got %s", what, w.String())
		}
		if out.Integration.Config["base_url"] != "https://api.example.test" {
			t.Fatalf("%s: a non-secret field was masked: %s", what, w.String())
		}
		return map[string]interface{}{"id": out.Integration.ID}
	}

	// Create: the response is masked, the stored value is encrypted.
	w := retiredTypesDo(r, http.MethodPost, "/integrations", body(secret))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := assertMasked("create", w.Body)["id"].(string)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_integrations WHERE id = $1`, id) })
	original := storedKey(id)
	if original == "" || original == secret {
		t.Fatalf("stored api_key = %q, want an encrypted value", original)
	}

	// Get: masked, and no decrypted value anywhere.
	w = retiredTypesDo(r, http.MethodGet, "/integrations/"+id, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	assertMasked("get", w.Body)

	// Edit with the secret left out, blank, or echoed as the mask: kept.
	for name, v := range map[string]interface{}{"absent": nil, "blank": "", "mask": "********"} {
		w = retiredTypesDo(r, http.MethodPut, "/integrations/"+id, body(v))
		if w.Code != http.StatusOK {
			t.Fatalf("update (%s): %d %s", name, w.Code, w.Body.String())
		}
		assertMasked("update ("+name+")", w.Body)
		if got := storedKey(id); got != original {
			t.Fatalf("update (%s) changed the stored secret", name)
		}
	}

	// A new value replaces it.
	w = retiredTypesDo(r, http.MethodPut, "/integrations/"+id, body("a-different-secret"))
	if w.Code != http.StatusOK {
		t.Fatalf("update (new): %d %s", w.Code, w.Body.String())
	}
	if got := storedKey(id); got == original || got == "" || got == "a-different-secret" {
		t.Fatalf("a new secret was not stored encrypted: %q", got)
	}
}

// itPlatformUser inserts a platform user (the created_by / updated_by columns
// reference platform_users) and removes it at cleanup.
func itPlatformUser(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO platform_users (email, password_hash, first_name, last_name, role_id, is_active)
		SELECT $1, 'not-a-real-hash', 'It', 'User', id, true FROM platform_roles WHERE name = 'super_admin'
		RETURNING id`, "it-"+uuid.NewString()[:8]+"@example.test").Scan(&id); err != nil {
		t.Fatalf("platform user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`UPDATE platform_integrations SET created_by = NULL, updated_by = NULL WHERE created_by = $1 OR updated_by = $1`, id)
		_, _ = db.Exec(`UPDATE platform_settings SET updated_by = NULL WHERE updated_by = $1`, id)
		_, _ = db.Exec(`DELETE FROM platform_users WHERE id = $1`, id)
	})
	return id
}
