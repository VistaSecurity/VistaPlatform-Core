package api

// Follow-ups to the tenant suspension enforcement ( items 1 and 2), on
// the same REAL-router fixture as tenant_suspension_integration_test.go.
// Skips unless TEST_DATABASE_URL is set.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	mcpClientID    = "claude-code"
	mcpRedirectURI = "http://127.0.0.1:33418/callback"
	// PKCE verifier for the test flow. Not a credential.
	mcpPKCEVerifier = "suspension-followups-pkce-verifier-0123456789abcdefghijklmnop"
)

func mcpPKCEChallenge() string {
	sum := sha256.Sum256([]byte(mcpPKCEVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func mcpAuthorizeQuery() url.Values {
	return url.Values{
		"client_id":             {mcpClientID},
		"redirect_uri":          {mcpRedirectURI},
		"response_type":         {"code"},
		"state":                 {"st"},
		"code_challenge":        {mcpPKCEChallenge()},
		"code_challenge_method": {"S256"},
	}
}

// authorizeGET opens the MCP OAuth consent page with the session cookie.
func (f suspensionFixture) authorizeGET(t *testing.T, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth-service/oauth/authorize?"+mcpAuthorizeQuery().Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// authorizePOST submits "Allow" on the consent page with the session cookie.
func (f suspensionFixture) authorizePOST(t *testing.T, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	form := mcpAuthorizeQuery()
	form.Set("decision", "allow")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// token exchanges an authorization code for the MCP personal access token.
func (f suspensionFixture) token(t *testing.T, code string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {mcpClientID},
		"redirect_uri":  {mcpRedirectURI},
		"code":          {code},
		"code_verifier": {mcpPKCEVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f suspensionFixture) count(t *testing.T, query string) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(query, f.tenantID).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// TestIntegration_TenantSuspension_MCPOAuthAuthorizeRefused ( item 1) —
// /oauth/authorize reads the session cookie itself, not through the JWT
// middleware, so it skipped the tenant-state check: a blocked tenant's
// still-valid access token could approve an MCP client and mint a 90-day
// personal access token. Now the consent page, the Allow decision and the
// code exchange all refuse.
//
// Mutation: drop the checkTenantSession call in sessionFromCookie and the
// consent/decision assertions fail; drop the tenantstate.Gate in Token and the
// exchange assertion fails.
func TestIntegration_TenantSuspension_MCPOAuthAuthorizeRefused(t *testing.T) {
	cases := []struct {
		name     string
		mutate   string
		wantCode string
	}{
		{"suspended", `UPDATE tenants SET payment_status = 'suspended' WHERE id = $1`, "tenant_suspended"},
		{"canceled", `UPDATE tenants SET payment_status = 'canceled' WHERE id = $1`, "tenant_suspended"},
		{"soft-deleted", `UPDATE tenants SET deleted_at = NOW() WHERE id = $1`, "tenant_deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSuspensionFixture(t)
			tok := f.mustLogin(t)

			// Baseline: a live tenant sees the consent page and gets a code.
			if w := f.authorizeGET(t, tok.AccessToken); w.Code != http.StatusOK {
				t.Fatalf("live tenant consent page = %d; body=%.300s", w.Code, w.Body.String())
			}
			w := f.authorizePOST(t, tok.AccessToken)
			loc, _ := url.Parse(w.Header().Get("Location"))
			if w.Code != http.StatusFound || loc == nil || loc.Query().Get("code") == "" {
				t.Fatalf("live tenant Allow = %d location=%q", w.Code, w.Header().Get("Location"))
			}
			issuedCode := loc.Query().Get("code")
			codesBefore := f.count(t, `SELECT count(*) FROM oauth_authorization_codes WHERE tenant_id = $1`)
			patsBefore := f.count(t, `SELECT count(*) FROM api_tokens WHERE tenant_id = $1`)

			if _, err := f.owner.Exec(tc.mutate, f.tenantID); err != nil {
				t.Fatalf("mutate tenant: %v", err)
			}

			// The consent page sends the browser to sign-in with the reason.
			w = f.authorizeGET(t, tok.AccessToken)
			if w.Code != http.StatusFound || w.Header().Get("Location") != "/login?reason="+tc.wantCode {
				t.Errorf("consent page = %d location=%q, want 302 to /login?reason=%s", w.Code, w.Header().Get("Location"), tc.wantCode)
			}
			// The decision is refused with the tenant code and stores no code.
			assertRefused(t, "Allow decision", f.authorizePOST(t, tok.AccessToken), tc.wantCode)
			if n := f.count(t, `SELECT count(*) FROM oauth_authorization_codes WHERE tenant_id = $1`); n != codesBefore {
				t.Errorf("an authorization code was stored for a blocked tenant (%d → %d)", codesBefore, n)
			}
			// A code issued while the tenant was live exchanges for nothing.
			w = f.token(t, issuedCode)
			var body struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.Description != tc.wantCode {
				t.Errorf("code exchange = %d %s, want 400 invalid_grant/%s", w.Code, w.Body.String(), tc.wantCode)
			}
			if n := f.count(t, `SELECT count(*) FROM api_tokens WHERE tenant_id = $1`); n != patsBefore {
				t.Errorf("a personal access token was minted for a blocked tenant (%d → %d)", patsBefore, n)
			}
		})
	}
}

// TestIntegration_TenantSuspension_MCPOAuthLiveTenantStillExchanges — the
// other polarity: nothing above refuses a live tenant's code exchange.
func TestIntegration_TenantSuspension_MCPOAuthLiveTenantStillExchanges(t *testing.T) {
	f := newSuspensionFixture(t)
	tok := f.mustLogin(t)
	w := f.authorizePOST(t, tok.AccessToken)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || loc == nil || loc.Query().Get("code") == "" {
		t.Fatalf("Allow = %d location=%q", w.Code, w.Header().Get("Location"))
	}
	if w := f.token(t, loc.Query().Get("code")); w.Code != http.StatusOK {
		t.Fatalf("live tenant code exchange = %d; body=%.300s", w.Code, w.Body.String())
	}
}

// TestIntegration_TenantSuspension_PurgedTenantTokensStayDead ( item 2) —
// soft delete, then purge, within one access token's lifetime. The soft delete
// refused the token; the purge removed the row that carried the refusal, and
// the per-request check treated a missing row as "not blocked" — so the token
// worked again on every service until it expired. A missing row now fails
// closed everywhere the token is presented.
//
// Mutation: make tenantstate.Checker.Check / CheckSession return "not
// blocked" for a missing row and the post-purge assertions go red.
func TestIntegration_TenantSuspension_PurgedTenantTokensStayDead(t *testing.T) {
	f := newSuspensionFixture(t)
	tok := f.mustLogin(t)

	if _, err := f.owner.Exec(`UPDATE tenants SET deleted_at = NOW() WHERE id = $1`, f.tenantID); err != nil {
		t.Fatal(err)
	}
	assertRefused(t, "auth-service after the soft delete", f.me(t, tok.AccessToken), "tenant_deleted")

	// The purge: what PurgeTenant does once a tenant is soft-deleted.
	if _, err := f.owner.Exec(`DELETE FROM tenants WHERE id = $1`, f.tenantID); err != nil {
		t.Fatalf("purge tenant: %v", err)
	}
	var rows int
	if err := f.owner.QueryRow(`SELECT count(*) FROM tenants WHERE id = $1`, f.tenantID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("tenant row still present after purge (rows=%d err=%v)", rows, err)
	}

	assertRefused(t, "auth-service after the purge", f.me(t, tok.AccessToken), "tenant_deleted")
	assertRefused(t, "shared data-plane middleware after the purge", dataPlane(t, tok.AccessToken), "tenant_deleted")
	assertRefused(t, "MCP OAuth Allow after the purge", f.authorizePOST(t, tok.AccessToken), "tenant_deleted")
	// The purge cascades the refresh-token row away, so refresh is refused as
	// an unknown session (401) before the tenant gate is reached; either way
	// no new session exists.
	if w := f.refresh(t, tok.RefreshToken); w.Code == http.StatusOK {
		t.Errorf("refresh after the purge = 200; body=%.300s", w.Body.String())
	}
}
