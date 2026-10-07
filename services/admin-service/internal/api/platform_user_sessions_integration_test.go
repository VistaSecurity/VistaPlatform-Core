package api

// D8 (pentest-readiness review), through the REAL router and a real Postgres:
// the platform-admin actions that end an account's standing must also end the
// refresh sessions it holds.
//
//   - PUT    /admin/users/:id/set-password  -> every refresh token revoked
//   - PUT    /admin/users/:id {is_active:false} -> every refresh token revoked
//   - DELETE /admin/users/:id               -> every refresh token revoked
//   - POST   /admin/auth/logout             -> refresh tokens revoked AND the
//     presented access token's jti written to the revocation denylist
//
// Each is the other polarity too where it matters: an edit that leaves the user
// active must not sign them out. A handler-level test would stay green if
// server.go stopped handing the handlers their refresh-token service; the real
// router would not.
//
// Needs TEST_DATABASE_URL (skips otherwise).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/models"
)

// seedRefreshTokens stores n live refresh tokens for user through the service
// the router uses, and returns how many remain unrevoked after fn runs.
func (f *roleAssignFixture) liveRefreshTokens(user uuid.UUID) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM platform_refresh_tokens WHERE platform_user_id = $1 AND is_revoked = false`, user).Scan(&n); err != nil {
		f.t.Fatalf("count refresh tokens: %v", err)
	}
	return n
}

func (f *roleAssignFixture) giveSessions(user uuid.UUID, n int) {
	f.t.Helper()
	f.t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM platform_refresh_tokens WHERE platform_user_id = $1`, user) })
	for i := 0; i < n; i++ {
		if _, err := f.srv.refreshTokenService.StoreRefreshToken(user, "refresh-"+uuid.NewString(), nil,
			time.Now().Add(time.Hour), "198.51.100.1", "integration-test"); err != nil {
			f.t.Fatalf("store refresh token: %v", err)
		}
	}
	if got := f.liveRefreshTokens(user); got != n {
		f.t.Fatalf("premise: %d live sessions, want %d", got, n)
	}
}

func TestIntegration_PlatformUserLifecycle_EndsSessions_RealRouter(t *testing.T) {
	f := newRoleAssignFixture(t)

	t.Run("set-password ends every session", func(t *testing.T) {
		f.giveSessions(f.target, 3)
		code, body := f.do(f.platformAdmin, http.MethodPut, "/"+f.target.String()+"/set-password",
			`{"new_password":"Str0ng!Passw0rd#2026"}`)
		expectStatus(t, "set-password", code, body, http.StatusOK)
		if n := f.liveRefreshTokens(f.target); n != 0 {
			t.Fatalf("%d refresh tokens survived an admin set-password", n)
		}
	})

	t.Run("an edit that leaves the user active keeps their sessions", func(t *testing.T) {
		f.giveSessions(f.target, 2)
		code, body := f.do(f.platformAdmin, http.MethodPut, "/"+f.target.String(), `{"first_name":"Renamed"}`)
		expectStatus(t, "rename", code, body, http.StatusOK)
		if n := f.liveRefreshTokens(f.target); n != 2 {
			t.Fatalf("a rename left %d live sessions, want 2 untouched", n)
		}
	})

	t.Run("deactivation ends every session", func(t *testing.T) {
		code, body := f.do(f.platformAdmin, http.MethodPut, "/"+f.target.String(), `{"is_active":false}`)
		expectStatus(t, "deactivate", code, body, http.StatusOK)
		if n := f.liveRefreshTokens(f.target); n != 0 {
			t.Fatalf("%d refresh tokens survived deactivation", n)
		}
	})

	t.Run("deletion ends every session", func(t *testing.T) {
		f.giveSessions(f.victim, 2)
		code, body := f.do(f.assigner, http.MethodDelete, "/"+f.victim.String(), ``)
		expectStatus(t, "delete", code, body, http.StatusOK)
		if n := f.liveRefreshTokens(f.victim); n != 0 {
			t.Fatalf("%d refresh tokens survived deletion", n)
		}
	})
}

// capturingRevoker records what Logout writes to the denylist.
type capturingRevoker struct {
	mu   sync.Mutex
	jtis map[string]time.Duration
}

func (c *capturingRevoker) RevokeJTI(_ context.Context, jti string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.jtis[jti] = ttl
	return nil
}

func TestIntegration_PlatformLogout_DenylistsTheAccessToken_RealRouter(t *testing.T) {
	f := newRoleAssignFixture(t)
	rev := &capturingRevoker{jtis: map[string]time.Duration{}}
	handlers.InitializeAccessTokenRevoker(rev) // after the server is built: Logout reads it per request
	t.Cleanup(func() { handlers.InitializeAccessTokenRevoker(nil) })

	f.giveSessions(f.support, 2)

	jti := uuid.NewString()
	claims := models.JWTClaims{
		UserID: f.support,
		Email:  "operator@example.test",
		Role:   "support_agent",
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(roleAssignJWTSecret))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin-service/admin/auth/logout", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("logout => %d %s", w.Code, w.Body.String())
	}

	if n := f.liveRefreshTokens(f.support); n != 0 {
		t.Fatalf("%d refresh tokens survived logout", n)
	}
	ttl, ok := rev.jtis[jti]
	if !ok {
		t.Fatalf("logout did not denylist the presented access token (jti %s); wrote %v", jti, rev.jtis)
	}
	if ttl < 50*time.Minute || ttl > time.Hour {
		t.Fatalf("denylist TTL %v; want the token's remaining life (just under an hour)", ttl)
	}
}
