package api

// Self-signup records the tenant's licence usage 'created' event (shared/
// licenseusage), driven through the REAL SetupRouter against a real Postgres
// with production's two pools — the RLS app role and the bypass role — so a
// call site that wrote the ledger on the app pool (which may only read it)
// would fail here exactly as it would in production.
//
// Needs TEST_DATABASE_URL (skips otherwise).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Signup_RecordsTheCreatedUsageEvent(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	bypass := testdb.ConnectAsBypassRole(t, owner)

	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on this path
	t.Cleanup(func() { _ = rdb.Close() })
	router := SetupRouter(&config.Config{JWTSecret: "signup-usage-event-secret", JWTExpiry: time.Hour},
		app, bypass, rdb, nil, EditionHooks{})

	suffix := uuid.NewString()[:8]
	body, _ := json.Marshal(map[string]any{
		"email":          "founder-" + suffix + "@usage-event.example.test",
		"password":       "Str0ng!Passw0rd#2026",
		"first_name":     "Usage",
		"last_name":      "Event",
		"tenant_name":    "Usage Event Co " + suffix,
		"accepted_legal": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register: status %d, body %s", w.Code, w.Body.String())
	}
	var resp struct {
		User struct {
			TenantID uuid.UUID `json:"tenant_id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.User.TenantID == uuid.Nil {
		t.Fatalf("register response has no tenant id (%v): %s", err, w.Body.String())
	}
	tenant := resp.User.TenantID
	t.Cleanup(func() {
		_, _ = owner.Exec(`DELETE FROM license_usage_events WHERE tenant_id = $1`, tenant)
		_, _ = owner.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	rows, err := owner.Query(`SELECT type, actor FROM license_usage_events WHERE tenant_id = $1 ORDER BY id`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var typ, actor string
		if err := rows.Scan(&typ, &actor); err != nil {
			t.Fatal(err)
		}
		got = append(got, typ+"/"+actor)
	}
	if len(got) != 1 || got[0] != "created/signup" {
		t.Fatalf("usage events for the new tenant = %v, want exactly [created/signup]", got)
	}
}
