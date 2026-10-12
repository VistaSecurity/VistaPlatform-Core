package api

// DB + Redis integration coverage for the per-user "tokens issued before T are
// invalid" cutoff: deactivating, deleting, resetting or changing the password
// of, or revoking a session of, a user ends that user's other LIVE access
// tokens on every service, not only the one presented. They drive the REAL
// auth-service router (SetupRouter) and the SHARED RequireJWTAuth every other
// service mounts, over a real Redis, so deleting the check in RequireAuth, or a
// call site, turns them red. Skip without TEST_DATABASE_URL / TEST_REDIS_ADDR.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/middleware"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

type liveTenants struct{}

func (liveTenants) Check(context.Context, uuid.UUID) (string, bool, error) { return "", false, nil }

type cutoffFixture struct {
	*identityFixture
	tenant     uuid.UUID
	adminToken string
	otherSvc   *gin.Engine
}

func newCutoffFixture(t *testing.T) *cutoffFixture {
	t.Helper()
	// RequireAuth captures its denylist reader when the router is built, and
	// resolves it from REDIS_URL once per process; point it at the test Redis,
	// BEFORE SetupRouter, for this test only.
	middleware.SetDefaultRevocationChecker(sharedmw.NewRedisRevocationChecker(identityRedis(t)))
	t.Cleanup(func() { middleware.SetDefaultRevocationChecker(nil) })
	f := newIdentityFixture(t, true)

	tenant := f.newTenant(t)
	adminEmail := uniqEmail("cutoff-admin")
	f.seedUser(t, tenant, adminEmail, "tenant_admin")

	other := gin.New()
	other.Use(sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret: identityTestSigningSecret, TenantState: liveTenants{},
		RevocationChecker: sharedmw.NewRedisRevocationChecker(f.rdb),
	}))
	other.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	return &cutoffFixture{identityFixture: f, tenant: tenant, adminToken: f.mustLogin(t, adminEmail).AccessToken, otherSvc: other}
}

func (f *cutoffFixture) cleanupCutoff(t *testing.T, id uuid.UUID) {
	t.Cleanup(func() { _ = f.rdb.Del(context.Background(), sharedmw.RevokedUserCutoffKey(id)).Err() })
}

func (f *cutoffFixture) me(token string) int {
	return f.do(http.MethodGet, "/auth/me", token, "").Code
}

// dataPlane is another service's middleware (the shared one) seeing the token.
func (f *cutoffFixture) dataPlane(token string) int {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.otherSvc.ServeHTTP(w, req)
	return w.Code
}

// afterCutoffSecond waits out the one-second iat resolution: a token minted in
// the same second as the event is refused as well.
func afterCutoffSecond() { time.Sleep(1100 * time.Millisecond) }

func (f *cutoffFixture) wantBoth(t *testing.T, what, token string, want int) {
	t.Helper()
	if got := f.me(token); got != want {
		t.Errorf("%s: auth-service /auth/me = %d, want %d", what, got, want)
	}
	if got := f.dataPlane(token); got != map[int]int{http.StatusOK: http.StatusNoContent, http.StatusUnauthorized: http.StatusUnauthorized}[want] {
		t.Errorf("%s: another service's middleware = %d (want the same verdict as auth-service)", what, got)
	}
}

func TestIntegration_Deactivate_InvalidatesLiveTokens_ReactivateAllowsNew(t *testing.T) {
	f := newCutoffFixture(t)
	email := uniqEmail("cutoff-victim")
	victim := f.seedUser(t, f.tenant, email, "viewer")
	f.cleanupCutoff(t, victim)

	old := f.mustLogin(t, email).AccessToken
	f.wantBoth(t, "before deactivation", old, http.StatusOK)

	w := f.do(http.MethodPut, "/users/"+victim.String(), f.adminToken, `{"is_active":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("deactivate = %d; %s", w.Code, w.Body.String())
	}
	f.wantBoth(t, "after deactivation", old, http.StatusUnauthorized)

	if w := f.do(http.MethodPut, "/users/"+victim.String(), f.adminToken, `{"is_active":true}`); w.Code != http.StatusOK {
		t.Fatalf("reactivate = %d; %s", w.Code, w.Body.String())
	}
	afterCutoffSecond()
	fresh := f.mustLogin(t, email).AccessToken
	f.wantBoth(t, "new token after reactivation", fresh, http.StatusOK)
	f.wantBoth(t, "pre-deactivation token after reactivation", old, http.StatusUnauthorized)
}

func TestIntegration_TenantMemberStatusAndDelete_InvalidateLiveTokens(t *testing.T) {
	f := newCutoffFixture(t)
	for _, tc := range []struct{ name, method, path, body string }{
		{"suspend", http.MethodPut, "/status", `{"status":"suspended"}`},
		{"delete", http.MethodDelete, "", ""},
	} {
		email := uniqEmail("cutoff-" + tc.name)
		victim := f.seedUser(t, f.tenant, email, "viewer")
		f.cleanupCutoff(t, victim)
		tok := f.mustLogin(t, email).AccessToken
		w := f.do(tc.method, "/tenant/"+f.tenant.String()+"/users/"+victim.String()+tc.path, f.adminToken, tc.body)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d; %s", tc.name, w.Code, w.Body.String())
		}
		f.wantBoth(t, tc.name, tok, http.StatusUnauthorized)
	}
}

func TestIntegration_DeleteUser_InvalidatesLiveTokens(t *testing.T) {
	f := newCutoffFixture(t)
	email := uniqEmail("cutoff-del")
	victim := f.seedUser(t, f.tenant, email, "viewer")
	f.cleanupCutoff(t, victim)
	tok := f.mustLogin(t, email).AccessToken
	if w := f.do(http.MethodDelete, "/users/"+victim.String(), f.adminToken, ""); w.Code != http.StatusOK {
		t.Fatalf("delete = %d; %s", w.Code, w.Body.String())
	}
	f.wantBoth(t, "after delete", tok, http.StatusUnauthorized)
}

func TestIntegration_PasswordReset_InvalidatesLiveTokens(t *testing.T) {
	f := newCutoffFixture(t)
	email := uniqEmail("cutoff-reset")
	victim := f.seedUser(t, f.tenant, email, "viewer")
	f.cleanupCutoff(t, victim)
	old := f.mustLogin(t, email).AccessToken
	f.wantBoth(t, "before reset", old, http.StatusOK)

	if w := f.reset(f.seedResetToken(t, victim), "New-Passw0rd!Strong"); w.Code != http.StatusOK {
		t.Fatalf("reset = %d; %s", w.Code, w.Body.String())
	}
	f.wantBoth(t, "after reset", old, http.StatusUnauthorized)

	afterCutoffSecond()
	w := f.login(email, "New-Passw0rd!Strong")
	if w.Code != http.StatusOK {
		t.Fatalf("login with the new password = %d; %s", w.Code, w.Body.String())
	}
	var tok idTokens
	_ = json.Unmarshal(w.Body.Bytes(), &tok)
	f.wantBoth(t, "token minted after the reset", tok.AccessToken, http.StatusOK)
}

func TestIntegration_PasswordChange_InvalidatesOtherSessions(t *testing.T) {
	f := newCutoffFixture(t)
	email := uniqEmail("cutoff-change")
	victim := f.seedUser(t, f.tenant, email, "viewer")
	f.cleanupCutoff(t, victim)
	a := f.mustLogin(t, email).AccessToken
	b := f.mustLogin(t, email).AccessToken // a second device
	body := `{"current_password":"` + identityLoginCredential + `","new_password":"Changed-Passw0rd!9"}`
	if w := f.do(http.MethodPost, "/auth/change-password", a, body); w.Code != http.StatusOK {
		t.Fatalf("change password = %d; %s", w.Code, w.Body.String())
	}
	f.wantBoth(t, "the other session after a password change", b, http.StatusUnauthorized)
}

func TestIntegration_RevokeSession_InvalidatesLiveAccessTokens(t *testing.T) {
	f := newCutoffFixture(t)
	email := uniqEmail("cutoff-session")
	victim := f.seedUser(t, f.tenant, email, "viewer")
	f.cleanupCutoff(t, victim)
	first := f.mustLogin(t, email)
	second := f.mustLogin(t, email)

	w := f.do(http.MethodGet, "/auth/sessions", first.AccessToken, "")
	var list struct {
		Sessions []struct {
			ID uuid.UUID `json:"id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Sessions) == 0 {
		t.Fatalf("list sessions = %d: %v; %s", w.Code, err, w.Body.String())
	}
	if w := f.do(http.MethodDelete, "/auth/sessions/"+list.Sessions[0].ID.String(), first.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatalf("revoke session = %d; %s", w.Code, w.Body.String())
	}
	f.wantBoth(t, "access token after a session revoke", second.AccessToken, http.StatusUnauthorized)
}

// A lockout that has run its course must not leave the cumulative counter at
// the threshold: the next typo would re-lock the account at once.
func TestIntegration_LockoutExpiry_ResetsFailedLoginCounter(t *testing.T) {
	f := newIdentityFixture(t, true)
	tenant := f.newTenant(t)
	email := uniqEmail("lockout")
	id := f.seedUser(t, tenant, email, "viewer")
	if _, err := f.owner.Exec(`UPDATE users SET failed_login_attempts = 5, locked_until = NOW() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	if w := f.login(email, "Wr0ng-Password!x"); w.Code != http.StatusUnauthorized {
		t.Fatalf("one typo after the lockout expired = %d, want 401", w.Code)
	}
	var attempts int
	var lockedUntil *time.Time
	if err := f.owner.QueryRow(`SELECT failed_login_attempts, locked_until FROM users WHERE id = $1`, id).Scan(&attempts, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || lockedUntil != nil {
		t.Fatalf("after one typo post-expiry: attempts=%d locked_until=%v, want 1 / nil (the counter must restart)", attempts, lockedUntil)
	}
	// ...and a correct password still signs in.
	f.mustLogin(t, email)
}
