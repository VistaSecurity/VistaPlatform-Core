package api

// The Core edition's login dispatcher must offer password and nothing else.
//
// This is the single most load-bearing assertion of the SSO carve. /auth/methods
// is what the login page asks before it renders: if a Core build ever leaked an
// "sso" or "platform_sso" entry, the page would render a button that goes
// nowhere (the routes do not exist in Core), and every user of every
// open-source install would hit it.
//
// The stub is exercised through sqlmock so the *only* query the handler is
// allowed to make — the email→tenant lookup on the bypass handle — is the only
// one the mock is prepared for. sqlmock is strict: any additional query (a
// sneaked-back sso_providers read, say) fails the test rather than passing
// silently.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func newAuthMethodsEngine(t *testing.T, knownUser bool) (*gin.Engine, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}

	q := mock.ExpectQuery("SELECT id, tenant_id FROM users")
	if knownUser {
		q.WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id"}).
			AddRow(uuid.New(), uuid.New()))
	} else {
		q.WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id"}))
	}

	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	// noSSOMethods{} is exactly what SetupRouter resolves to in a Core build.
	grp.POST("/auth/methods", AuthMethods(db, noSSOMethods{}))

	return r, func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet or unexpected queries — Core must issue exactly one lookup: %v", err)
		}
		_ = db.Close()
	}
}

func methodTypes(t *testing.T, body []byte) []string {
	t.Helper()
	var resp struct {
		Methods []map[string]any `json:"methods"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, string(body))
	}
	var out []string
	for _, m := range resp.Methods {
		s, _ := m["type"].(string)
		out = append(out, s)
	}
	return out
}

// A known user in Core gets password only — no "sso", no "platform_sso".
func TestCoreAuthMethods_knownUser_passwordOnly(t *testing.T) {
	eng, done := newAuthMethodsEngine(t, true)
	defer done()

	w := do(eng, http.MethodPost, "/api/v1/auth-service/auth/methods",
		strings.NewReader(`{"email":"someone@acme.com"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	got := methodTypes(t, w.Body.Bytes())
	if len(got) != 1 || got[0] != "password" {
		t.Fatalf("Core offered %v, want exactly [password]; body=%s", got, w.Body.String())
	}
}

// An unknown email is unchanged by the carve: password only, and the tenant_id
// echo stays empty.
func TestCoreAuthMethods_unknownUser_passwordOnly(t *testing.T) {
	eng, done := newAuthMethodsEngine(t, false)
	defer done()

	w := do(eng, http.MethodPost, "/api/v1/auth-service/auth/methods",
		strings.NewReader(`{"email":"nobody@acme.com"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	got := methodTypes(t, w.Body.Bytes())
	if len(got) != 1 || got[0] != "password" {
		t.Fatalf("Core offered %v, want exactly [password]; body=%s", got, w.Body.String())
	}

	var resp struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TenantID != "" {
		t.Errorf("tenant_id = %q for an unknown email, want empty", resp.TenantID)
	}
}

// The no-op enumerator is a value, not a nil pointer wrapped in an interface —
// calling through it must not panic. This is the typed-nil trap the carve
// pattern warns about, pinned.
func TestNoSSOMethods_isSafeToCall(t *testing.T) {
	var e SSOMethodEnumerator = noSSOMethods{}
	if got := e.TenantMethods(t.Context(), uuid.New()); got != nil {
		t.Errorf("TenantMethods = %v, want nil", got)
	}
	if got := e.PlatformMethods(t.Context(), uuid.New(), uuid.New()); got != nil {
		t.Errorf("PlatformMethods = %v, want nil", got)
	}
	if url, ok := e.AuthorizeRedirect(t.Context(), uuid.New(), uuid.NewString()); ok || url != "" {
		t.Errorf("AuthorizeRedirect = (%q, %v), want (\"\", false)", url, ok)
	}
}
