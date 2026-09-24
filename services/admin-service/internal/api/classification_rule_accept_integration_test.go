package api

// Catalog ▸ Classification rules "Update available" → Accept, through the REAL
// admin-service router (decision 4, RC-12): the route mounted by
// NewServerWithConnections, its catalogs.manage gate resolved from the
// database, the SQL store, and the platform audit emitter.
//
// Runs on a scratch database: accepting rewrites a shipped rule every tenant is
// classified against, and the shared database's rules are other suites' too.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const seededRuleSigningKey = "seeded-rule-accept-integration-not-a-real-key"

func TestIntegration_ClassificationRuleAccept_RealRouter(t *testing.T) {
	db := testdb.ScratchDatabase(t)

	// The admin tunes Cisco's shipped OUI rule; a later release ships a new
	// confidence for it (the seed's upsert, in a seed pass).
	var ruleID string
	if err := db.QueryRow(`UPDATE classification_rules SET confidence = 0.55
		WHERE rule_kind = 'oui' AND pattern = '00000C' RETURNING id`).Scan(&ruleID); err != nil {
		t.Fatalf("admin edit: %v", err)
	}
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SET vista.seed_apply = on`,
		`UPDATE classification_rules SET confidence = 0.75 WHERE id = '` + ruleID + `'`,
		`RESET vista.seed_apply`,
	} {
		if _, err := conn.ExecContext(t.Context(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = conn.Close()

	audits := make(chan map[string]interface{}, 32)
	auditSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		select {
		case audits <- body:
		default:
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + uuid.NewString() + `"}`))
	}))
	t.Cleanup(auditSrv.Close)
	t.Setenv("AUDIT_SERVICE_URL", auditSrv.URL)
	t.Setenv("AUDIT_LOGGING_ENABLED", "true")
	srv := NewServerWithConnections(&config.Config{Environment: "test", JWTSecret: seededRuleSigningKey}, db, db, EditionHooks{})

	curator := testdb.NewPlatformUser(t, db, testdb.NewPlatformRole(t, db, rbac.PermissionCatalogsManage))
	outsider := testdb.NewPlatformUser(t, db, testdb.NewPlatformRole(t, db, rbac.PermissionPlatformHealth))
	token := func(user uuid.UUID) string {
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, models.JWTClaims{
			UserID: user, Email: "curator@example.test", Role: "super_admin", Type: "access",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}).SignedString([]byte(seededRuleSigningKey))
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	do := func(user uuid.UUID, method, path string) (int, string) {
		req := httptest.NewRequest(method, "/api/v1/admin-service/admin/catalogs/classification-rules"+path, nil)
		req.Header.Set("Authorization", "Bearer "+token(user))
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	code, body := do(curator, http.MethodGet, "/"+ruleID)
	if code != http.StatusOK || !strings.Contains(body, `"update_available":true`) ||
		!strings.Contains(body, `"offered_update":{"confidence":0.75}`) || !strings.Contains(body, `"content_origin":"vista"`) {
		t.Fatalf("GET rule: %d %s", code, body)
	}

	// Gated like every other curation write.
	if code, body := do(outsider, http.MethodPost, "/"+ruleID+"/accept-update"); code != http.StatusForbidden {
		t.Errorf("accept without catalogs.manage: %d %s, want 403", code, body)
	}

	code, body = do(curator, http.MethodPost, "/"+ruleID+"/accept-update")
	if code != http.StatusOK {
		t.Fatalf("accept: %d %s", code, body)
	}
	var rule struct {
		Confidence      float64 `json:"confidence"`
		UpdateAvailable bool    `json:"update_available"`
		AdminModified   bool    `json:"admin_modified"`
	}
	if err := json.Unmarshal([]byte(body), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.Confidence != 0.75 || rule.UpdateAvailable || !rule.AdminModified {
		t.Errorf("after accept: %+v, want confidence 0.75, no offer, still the admin's", rule)
	}
	if code, body := do(curator, http.MethodPost, "/"+ruleID+"/accept-update"); code != http.StatusConflict {
		t.Errorf("second accept: %d %s, want 409", code, body)
	}
	if code, body := do(curator, http.MethodPost, "/"+uuid.NewString()+"/accept-update"); code != http.StatusNotFound {
		t.Errorf("accept on a missing rule: %d %s, want 404", code, body)
	}
	// Not a UUID: the caller's error, not a 500 from Postgres (22P02).
	if code, body := do(curator, http.MethodPost, "/not-a-uuid/accept-update"); code != http.StatusBadRequest {
		t.Errorf("accept on a malformed id: %d %s, want 400", code, body)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-audits:
			if e["event_type"] == "classification_rule.update_accepted" {
				return
			}
		case <-deadline:
			t.Fatal("no classification_rule.update_accepted audit entry reached audit-service")
		}
	}
}
