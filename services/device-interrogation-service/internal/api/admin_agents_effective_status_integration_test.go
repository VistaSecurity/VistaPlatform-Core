package api

// Admin-ui review RC-16 (tenants-overview-fleet-7): the platform-admin Fleet
// view showed device_agents.status as-is. That column is written 'active' at
// enrollment and nothing ever rewrites it — heartbeats update last_heartbeat
// only, and there is no reaper — so a dead discovery agent read "Active" with a
// green dot forever. GET /admin/agents now carries effective_status, derived
// from last_heartbeat with the same 15-minute window as the web-ui and the
// discovery_agent_offline alert.
//
// Driven through the REAL SetupRouter (platform-admin JWT, the /admin group's
// gates) against a real Postgres.
//
// Mutations run (each red, then restored green):
//   - ListAllAgents no longer sets EffectiveStatus → every assertion red.
//   - EffectiveAgentStatus ignores the heartbeat (returns status) → the stale
//     and never-heartbeated agents read "active"; red.
//   - `lastHeartbeat == nil ||` dropped → nil deref / never-heartbeated wrong.
//   - EffectiveAgentStatus forces "offline" for 'inactive' too → red.
//
// Needs TEST_DATABASE_URL (skips otherwise).

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// fleetSigningPhrase signs the test's platform-admin JWT (HS256 legacy path).
const fleetSigningPhrase = "fleet-effective-status-integration"

func TestIntegration_AdminAgents_EffectiveStatusFromHeartbeat(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	now := time.Now()
	fresh := now.Add(-2 * time.Minute)
	stale := now.Add(-20 * time.Minute)
	agents := []struct {
		name, status string
		heartbeat    *time.Time
		deleted      bool
		want         string
	}{
		{"fresh-active", "active", &fresh, false, "active"},
		{"stale-active", "active", &stale, false, "offline"},
		{"never-heartbeated", "active", nil, false, "offline"},
		{"operator-disabled", "inactive", &fresh, false, "inactive"},
		{"errored", "error", &stale, false, "error"},
		{"soft-deleted", "active", &fresh, true, ""}, // must not be listed at all
	}
	for _, a := range agents {
		var hb sql.NullTime
		if a.heartbeat != nil {
			hb = sql.NullTime{Time: *a.heartbeat, Valid: true}
		}
		if _, err := db.Exec(`INSERT INTO device_agents (tenant_id, registration_key, name, platform, version, status, last_heartbeat, deleted_at)
			VALUES ($1, $2, $3, 'linux', '1.0.0', $4, $5, CASE WHEN $6 THEN NOW() END)`,
			tenant, uuid.NewString(), a.name, a.status, hb, a.deleted); err != nil {
			t.Fatalf("seed %s: %v", a.name, err)
		}
	}

	gin.SetMode(gin.TestMode)
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-key-for-route-registration-only")
	t.Setenv("NATS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")
	router := SetupRouter(&config.Config{JWTSecret: fleetSigningPhrase}, db, db, nil)

	// The /admin reads are gated on the platform.health PERMISSION, resolved
	// from platform_users by platform_user_has_permission() — the role
	// claim on the token is not consulted. The operator therefore has to exist:
	// a real platform user holding the seeded super_admin role.
	operator := testdb.NewPlatformUser(t, db, testdb.SeededPlatformRole(t, db, "super_admin"))

	claims := models.JWTClaims{
		UserID: operator, Email: "operator@example.test", Role: "super_admin", Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(fleetSigningPhrase))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/device-interrogation-service/admin/agents?tenant_id="+tenant.String(), nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/agents = %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		Agents []struct {
			Name            string `json:"name"`
			Status          string `json:"status"`
			EffectiveStatus string `json:"effective_status"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	got := map[string]string{}
	raw := map[string]string{}
	for _, a := range body.Agents {
		got[a.Name] = a.EffectiveStatus
		raw[a.Name] = a.Status
	}
	for _, a := range agents {
		if a.deleted {
			if _, listed := got[a.name]; listed {
				t.Errorf("soft-deleted agent %q is listed", a.name)
			}
			continue
		}
		if got[a.name] != a.want {
			t.Errorf("%s: effective_status = %q, want %q", a.name, got[a.name], a.want)
		}
		// The stored column is still reported verbatim beside it.
		if raw[a.name] != a.status {
			t.Errorf("%s: status = %q, want the stored %q", a.name, raw[a.name], a.status)
		}
	}
}
