package api

// Real-router, DB + Redis integration coverage for the public OAuth / auth-flow
// surface: atomic authorization-code redemption, the consent page's parameter
// round-trip, cookie-session checks on /oauth/authorize, the hardening of
// /auth/complete and /auth/initiate, and the signup response. Skips unless
// TEST_DATABASE_URL and REDIS_URL are set.

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type publicFlowFixture struct {
	suspensionFixture
	rdb *redis.Client
	jwt *auth.JWTService
}

func newPublicFlowFixture(t *testing.T) publicFlowFixture {
	t.Helper()
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		t.Skip("REDIS_URL not set")
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatalf("REDIS_URL: %v", err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis unreachable: %v", err)
	}

	base := newSuspensionFixture(t) // seeds a tenant + user; its own router uses a dead Redis
	app := testdb.ConnectAsAppRole(t, base.owner)
	bypass := testdb.ConnectAsBypassRole(t, base.owner)
	cfg := &config.Config{JWTSecret: suspensionTestSigningSecret, JWTExpiry: time.Hour}
	gin.SetMode(gin.TestMode)
	base.router = SetupRouter(cfg, app, bypass, rdb, nil, EditionHooks{})
	return publicFlowFixture{
		suspensionFixture: base,
		rdb:               rdb,
		jwt:               auth.NewJWTService(suspensionTestSigningSecret, time.Hour, 24*time.Hour),
	}
}

func (f publicFlowFixture) post(path, body, contentType string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f publicFlowFixture) revoke(t *testing.T, accessToken string) {
	t.Helper()
	claims, err := f.jwt.ValidateToken(accessToken)
	if err != nil || claims.ID == "" {
		t.Fatalf("validate token for revocation: %v (jti=%q)", err, claims.ID)
	}
	if err := f.rdb.Set(context.Background(), sharedmw.RevokedTokenKey(claims.ID), "1", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.rdb.Del(context.Background(), sharedmw.RevokedTokenKey(claims.ID)) })
}

func (f publicFlowFixture) newSessionID(t *testing.T) string {
	t.Helper()
	w := f.post("/auth/initiate", `{"email":"`+f.email+`"}`, "application/json")
	if w.Code != http.StatusOK {
		t.Fatalf("initiate = %d; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.SessionID == "" {
		t.Fatalf("initiate body: %v %s", err, w.Body.String())
	}
	return body.SessionID
}

func (f publicFlowFixture) complete(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"session_id": f.newSessionID(t), "token": token})
	return f.post("/auth/complete", string(b), "application/json")
}

// Two simultaneous redemptions of one authorization code must mint ONE token.
//
// Mutation: drop `AND used_at IS NULL` (and the RowsAffected check) from the
// token endpoint's UPDATE and more than one request gets a 200.
func TestIntegration_OAuthToken_ConcurrentRedemptionMintsOnePAT(t *testing.T) {
	f := newPublicFlowFixture(t)
	tok := f.mustLogin(t)
	w := f.authorizePOST(t, tok.AccessToken)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || loc == nil || loc.Query().Get("code") == "" {
		t.Fatalf("Allow = %d location=%q", w.Code, w.Header().Get("Location"))
	}
	code := loc.Query().Get("code")
	patsBefore := f.count(t, `SELECT count(*) FROM api_tokens WHERE tenant_id = $1`)

	const n = 48
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = f.token(t, code).Code
		}(i)
	}
	close(start)
	wg.Wait()

	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded (%v), want exactly 1", ok, n, codes)
	}
	if got := f.count(t, `SELECT count(*) FROM api_tokens WHERE tenant_id = $1`) - patsBefore; got != 1 {
		t.Fatalf("%d personal access tokens minted, want 1", got)
	}
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)

// The consent page must carry state and redirect_uri through the POST intact.
// Mutation: restore the JSON-encoding step in escapeHTML.
func TestIntegration_OAuthConsent_RoundTripsSpecialCharacters(t *testing.T) {
	f := newPublicFlowFixture(t)
	tok := f.mustLogin(t)
	state := `a&b<c>"d'e`
	redirect := "http://127.0.0.1:33418/callback?x=1&y=2"
	q := mcpAuthorizeQuery()
	q.Set("state", state)
	q.Set("redirect_uri", redirect)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth-service/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tok.AccessToken})
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("consent page = %d; body=%.300s", w.Code, w.Body.String())
	}
	got := map[string]string{}
	for _, m := range hiddenInput.FindAllStringSubmatch(w.Body.String(), -1) {
		got[m[1]] = html.UnescapeString(m[2])
	}
	if got["state"] != state {
		t.Errorf("state after browser decoding = %q, want %q", got["state"], state)
	}
	if got["redirect_uri"] != redirect {
		t.Errorf("redirect_uri after browser decoding = %q, want %q", got["redirect_uri"], redirect)
	}
}

// A refresh token or a denylisted access token in the cookie is not a session.
// Mutation: drop the type / revocation checks from sessionFromCookie.
func TestIntegration_OAuthAuthorize_CookieSessionChecks(t *testing.T) {
	f := newPublicFlowFixture(t)
	tok := f.mustLogin(t)
	if w := f.authorizeGET(t, tok.AccessToken); w.Code != http.StatusOK {
		t.Fatalf("baseline consent page = %d", w.Code)
	}
	if w := f.authorizeGET(t, tok.RefreshToken); w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "/login") {
		t.Errorf("refresh token as cookie: %d location=%q, want redirect to login", w.Code, w.Header().Get("Location"))
	}
	if w := f.authorizePOST(t, tok.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Errorf("Allow with refresh token cookie = %d, want 401", w.Code)
	}
	f.revoke(t, tok.AccessToken)
	if w := f.authorizeGET(t, tok.AccessToken); w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "/login") {
		t.Errorf("revoked token: %d location=%q, want redirect to login", w.Code, w.Header().Get("Location"))
	}
	if w := f.authorizePOST(t, tok.AccessToken); w.Code != http.StatusUnauthorized {
		t.Errorf("Allow with revoked token = %d, want 401", w.Code)
	}
}

// /auth/complete is public and echoes user data: only live access tokens count.
// Mutation: drop the type check / the denylist check / the is_active filter.
func TestIntegration_AuthComplete_RefusesNonSessionTokens(t *testing.T) {
	f := newPublicFlowFixture(t)
	tok := f.mustLogin(t)

	if w := f.complete(t, tok.AccessToken); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), f.email) {
		t.Fatalf("live access token = %d; body=%s", w.Code, w.Body.String())
	}
	if w := f.complete(t, tok.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Errorf("refresh token = %d, want 401; body=%s", w.Code, w.Body.String())
	}

	if _, err := f.owner.Exec(`UPDATE users SET is_active = false WHERE email = $1`, f.email); err != nil {
		t.Fatal(err)
	}
	if w := f.complete(t, tok.AccessToken); w.Code == http.StatusOK || strings.Contains(w.Body.String(), f.email) {
		t.Errorf("deactivated user = %d; body=%s, want a refusal that does not echo the user", w.Code, w.Body.String())
	}
	if _, err := f.owner.Exec(`UPDATE users SET is_active = true, deleted_at = now() WHERE email = $1`, f.email); err != nil {
		t.Fatal(err)
	}
	if w := f.complete(t, tok.AccessToken); w.Code == http.StatusOK || strings.Contains(w.Body.String(), f.email) {
		t.Errorf("deleted user = %d; body=%s, want a refusal that does not echo the user", w.Code, w.Body.String())
	}
	if _, err := f.owner.Exec(`UPDATE users SET deleted_at = NULL WHERE email = $1`, f.email); err != nil {
		t.Fatal(err)
	}

	f.revoke(t, tok.AccessToken)
	if w := f.complete(t, tok.AccessToken); w.Code != http.StatusUnauthorized {
		t.Errorf("denylisted token = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

// /auth/initiate stores a Redis session per call: it is capped per client IP.
// Mutation: remove the INCR/limit block from AuthInitiate.
func TestIntegration_AuthInitiate_CappedPerIP(t *testing.T) {
	f := newPublicFlowFixture(t)
	ip := "198.51.100." + "7"
	key := authInitiateIPKeyPrefix + ip
	f.rdb.Del(context.Background(), key)
	t.Cleanup(func() { f.rdb.Del(context.Background(), key) })

	var last int
	for i := 0; i < authInitiatePerIPLimit+5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/initiate", strings.NewReader(`{"email":"`+f.email+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":4000"
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, req)
		last = w.Code
		if i < authInitiatePerIPLimit && w.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200 within the cap", i+1, w.Code)
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("request over the cap = %d, want 429", last)
	}
}

// Public signup must answer an already-registered address like a new one.
func TestIntegration_Register_ExistingEmailIndistinguishable(t *testing.T) {
	f := newPublicFlowFixture(t)
	// Open sign-up explicitly (other suites in this database own this key too).
	if _, err := f.owner.Exec(`INSERT INTO platform_settings (setting_key, setting_value) VALUES ('registration_enabled', 'true'::jsonb)
		ON CONFLICT (setting_key) DO UPDATE SET setting_value = 'true'::jsonb`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.owner.Exec(`DELETE FROM platform_settings WHERE setting_key = 'registration_enabled'`)
	})
	body := func(email string) string {
		b, _ := json.Marshal(map[string]any{
			"email": email, "password": "Sup3r-Secret-Pass!", "first_name": "A", "last_name": "B",
			"tenant_name": "Org " + uuid.NewString()[:8], "accepted_legal": true,
		})
		return string(b)
	}
	fresh := f.post("/auth/register", body("fresh-"+uuid.NewString()[:8]+"@corp-example.test"), "application/json")
	dup := f.post("/auth/register", body(f.email), "application/json")
	if fresh.Code != http.StatusCreated {
		t.Fatalf("new signup = %d, want 201; body=%s", fresh.Code, fresh.Body.String())
	}
	if dup.Code != fresh.Code {
		t.Fatalf("existing email = %d, new = %d; body=%s", dup.Code, fresh.Code, dup.Body.String())
	}
	var fb, db map[string]any
	_ = json.Unmarshal(fresh.Body.Bytes(), &fb)
	_ = json.Unmarshal(dup.Body.Bytes(), &db)
	if fb["message"] != db["message"] {
		t.Errorf("message differs: %v vs %v", fb["message"], db["message"])
	}
	if len(fb["user"].(map[string]any)) != len(db["user"].(map[string]any)) {
		t.Errorf("user shape differs: %v vs %v", fb["user"], db["user"])
	}
}
