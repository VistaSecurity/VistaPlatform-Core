package api

// Tenant channel READS carry credentials: a Slack incoming-webhook URL IS the
// secret, PagerDuty's integration_key is a routing key, a webhook channel holds
// auth tokens / passwords / header values. GET /tenant/channels and
// GET /tenant/channels/:id had no permission gate at all and decrypted those
// straight into the response, so any signed-in tenant user (a viewer included)
// could read every channel's credentials.
//
// Two independent guards close it, and both are tested here through the REAL
// router (Server.SetupRouter — the one main() mounts), so deleting either
// line in server.go / handlers.go turns a test red:
//
//  1. WIRING — both GET routes carry settings.read.
//  2. MASKING — even a permitted caller never receives a credential value.
//
// The RBAC check is a database function call (user_has_permission), stood in
// for by a tiny in-memory driver so this runs in the plain PR gate with no
// Postgres. The DB-backed twin is channel_read_gate_integration_test.go.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Obviously fake secrets. Each is a distinctive substring so a leak in ANY
// position (whole value, URL path, token tail, header value) is caught.
const (
	fakeSlackURL     = "https://hooks.example.test/services/T0FAKE/B0FAKE/SLACKSECRETPATH"
	fakeRoutingKey   = "PDROUTINGKEYFAKE0123456789"
	fakeBearerToken  = "BEARERTOKENFAKE9876543210"
	fakeBasicPass    = "BASICPASSWORDFAKE"
	fakeHeaderSecret = "HEADERSECRETFAKE-abcdef"
)

var fakeSecrets = []string{
	"SLACKSECRETPATH", "T0FAKE", "B0FAKE", fakeRoutingKey, fakeBearerToken, fakeBasicPass, fakeHeaderSecret,
}

// permDB is a database/sql stand-in that answers `SELECT user_has_permission
// ($1,$2,$3)` from a fixed grant set and refuses everything else.
type permDB struct {
	mu      sync.Mutex
	granted map[string]bool
	asked   []string
}

func (p *permDB) Connect(context.Context) (driver.Conn, error) { return &permConn{p}, nil }
func (p *permDB) Driver() driver.Driver                        { return p }
func (p *permDB) Open(string) (driver.Conn, error)             { return &permConn{p}, nil }

type permConn struct{ p *permDB }

func (c *permConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("permDB: prepare unsupported")
}
func (c *permConn) Close() error              { return nil }
func (c *permConn) Begin() (driver.Tx, error) { return nil, errors.New("permDB: tx unsupported") }
func (c *permConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(q, "user_has_permission") || len(args) != 3 {
		return nil, errors.New("permDB: unexpected query: " + q)
	}
	perm, _ := args[2].Value.(string)
	c.p.mu.Lock()
	c.p.asked = append(c.p.asked, perm)
	granted := c.p.granted[perm]
	c.p.mu.Unlock()
	return &permRows{granted: granted}, nil
}

type permRows struct {
	granted bool
	done    bool
}

func (r *permRows) Columns() []string { return []string{"user_has_permission"} }
func (r *permRows) Close() error      { return nil }
func (r *permRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.granted
	return nil
}

const gateTestSecret = "channel-read-gate-test-jwt-secret"

func gateRouter(t *testing.T, granted map[string]bool, mgr channelManagerIface) (*gin.Engine, *permDB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("DATABASE_URL", "") // tenant-state lookup is not under test
	t.Setenv("REDIS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")

	pdb := &permDB{granted: granted}
	raw := sql.OpenDB(pdb)
	t.Cleanup(func() { _ = raw.Close() })
	srv := &Server{
		config:         &config.Config{JWTSecret: gateTestSecret},
		db:             sqlx.NewDb(raw, "postgres"),
		channelManager: mgr,
	}
	return srv.SetupRouter(), pdb
}

func secretBearingChannel(tenant uuid.UUID) models.TenantNotificationChannel {
	ch := sampleChannel()
	ch.TenantID = tenant
	ch.ChannelType = "webhook"
	ch.Config = map[string]interface{}{
		"webhook_url":     fakeSlackURL,
		"integration_key": fakeRoutingKey,
		"channel":         "#alerts",
		"recipients":      []interface{}{"ops@example.test"},
		"headers":         map[string]interface{}{"X-Api-Key": fakeHeaderSecret},
		"auth": map[string]interface{}{
			"type": "bearer", "token": fakeBearerToken, "password": fakeBasicPass,
		},
	}
	return ch
}

func gateGET(t *testing.T, router *gin.Engine, tenant, user uuid.UUID, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+testdb.SignTenantToken(t, gateTestSecret, user, tenant, "viewer"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func assertNoSecrets(t *testing.T, label, body string) {
	t.Helper()
	for _, s := range fakeSecrets {
		if strings.Contains(body, s) {
			t.Errorf("%s leaked credential material %q: %s", label, s, body)
		}
	}
}

func TestTenantChannelReads_403WithoutSettingsRead(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	ch := secretBearingChannel(tenant)
	router, pdb := gateRouter(t, map[string]bool{}, &stubChannelManager{
		list: []models.TenantNotificationChannel{ch}, get: &ch,
	})

	for _, path := range []string{
		"/api/v1/notification-service/tenant/channels",
		"/api/v1/notification-service/tenant/channels/" + ch.ID.String(),
	} {
		w := gateGET(t, router, tenant, user, path)
		if w.Code != http.StatusForbidden {
			t.Fatalf("GET %s without settings.read: status %d, want 403; body=%s", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "settings.read") {
			t.Errorf("GET %s: 403 does not name the required permission: %s", path, w.Body.String())
		}
		assertNoSecrets(t, "403 for "+path, w.Body.String())
	}
	if len(pdb.asked) != 2 {
		t.Fatalf("permission checks ran %d times (%v), want once per route — is the gate wired?", len(pdb.asked), pdb.asked)
	}
}

func TestTenantChannelReads_PermittedCallerSeesNoCredentials(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	ch := secretBearingChannel(tenant)
	router, _ := gateRouter(t, map[string]bool{"settings.read": true}, &stubChannelManager{
		list: []models.TenantNotificationChannel{ch}, get: &ch,
	})

	for _, path := range []string{
		"/api/v1/notification-service/tenant/channels",
		"/api/v1/notification-service/tenant/channels/" + ch.ID.String(),
	} {
		w := gateGET(t, router, tenant, user, path)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s with settings.read: status %d, want 200 (a gate that refuses everyone must not pass); body=%s",
				path, w.Code, w.Body.String())
		}
		assertNoSecrets(t, "response for "+path, w.Body.String())

		// The masked form must still say WHICH connection this is, and must
		// leave non-credentials readable.
		body := w.Body.String()
		for _, want := range []string{"https://hooks.example.test/", "ops@example.test", "#alerts", `"type":"bearer"`, "X-Api-Key"} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s: masked response lost %q: %s", path, want, body)
			}
		}
	}
}

// The stub hands back the SAME struct the manager would (decrypted config).
// Masking must not mutate it: delivery reads that struct's map.
func TestTenantChannelReads_MaskingDoesNotMutateTheSource(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	ch := secretBearingChannel(tenant)
	router, _ := gateRouter(t, map[string]bool{"settings.read": true}, &stubChannelManager{
		list: []models.TenantNotificationChannel{ch}, get: &ch,
	})
	_ = gateGET(t, router, tenant, user, "/api/v1/notification-service/tenant/channels/"+ch.ID.String())

	raw, _ := json.Marshal(ch.Config)
	if !strings.Contains(string(raw), fakeSlackURL) {
		t.Fatalf("masking mutated the stored config in place: %s", raw)
	}
}

// Create/update echo the channel back; they must not become a side door.
func TestTenantChannelWrites_ResponsesAreMaskedToo(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	ch := secretBearingChannel(tenant)
	router, _ := gateRouter(t, map[string]bool{"settings.update": true}, &stubChannelManager{
		created: &ch, updated: &ch,
	})
	tok := testdb.SignTenantToken(t, gateTestSecret, user, tenant, "viewer")

	do := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(`{"channel_name":"x","channel_type":"webhook","config":{},"enabled":true}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/api/v1/notification-service/tenant/channels", http.StatusCreated},
		{http.MethodPut, "/api/v1/notification-service/tenant/channels/" + ch.ID.String(), http.StatusOK},
	} {
		w := do(c.method, c.path)
		if w.Code != c.want {
			t.Fatalf("%s %s: status %d, want %d; body=%s", c.method, c.path, w.Code, c.want, w.Body.String())
		}
		assertNoSecrets(t, c.method+" response", w.Body.String())
	}
}
