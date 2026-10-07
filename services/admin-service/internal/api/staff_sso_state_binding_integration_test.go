package api

// Staff SSO sign-in is bound to the browser that started it, and its
// authorization code to the attempt that requested it (edge-session report D3),
// driven through the REAL admin-service router as a browser would: authorize,
// the fake IdP's authorize endpoint (which refuses a request without an S256
// PKCE challenge), back to the callback, and the IdP's token endpoint (which
// refuses a code_verifier that does not hash to the code's challenge).
//
// Before: the state was a double-submit cookie (Path=/) with nothing kept
// server-side — not single use, no PKCE.
//
// Needs TEST_DATABASE_URL (skips otherwise).
//
// Mutation-checked (each breaks a subtest; restored, green again):
//   - StaffSsoAuthorize without code_challenge → the IdP refuses; red.
//   - StaffSsoCallback without code_verifier in the token form → happy path red.
//   - ssostate.Finish without BindingMatches → "login CSRF" signs in.
//   - ssostate.MemoryStore.Take not deleting → "replayed callback" signs in.
//   - server.go handing the callback a different store than authorize →
//     happy path red (the wiring is shared).
//   - StaffSsoCallback ignoring Finish's error is still refused, by the
//     provider check on the (then empty) record — same redirect.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const staffCallbackPath = "/api/v1/admin-service/admin/sso/google/callback"

// staffSSOAuthorize runs GET authorize for provider on router and returns the
// IdP authorize URL it redirected to and the browser-binding cookie it set.
func staffSSOAuthorize(t *testing.T, router http.Handler, provider string) (*url.URL, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/admin-service/admin/sso/"+provider+"/authorize", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize status = %d; body=%s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") == "" {
		t.Fatalf("authorize did not redirect to an IdP: %s", loc)
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "admin_sso_binding" {
			return loc, ck
		}
	}
	t.Fatal("authorize set no browser-binding cookie")
	return nil, nil
}

// followStaffIdP plays the browser at the fake IdP and returns the callback URL
// it redirects back to.
func followStaffIdP(t *testing.T, idpURL *url.URL) *url.URL {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(idpURL.String())
	if err != nil {
		t.Fatalf("IdP authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("IdP authorize status = %d (a PKCE-enforcing IdP refused the request?)", resp.StatusCode)
	}
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return back
}

// staffSSOCallback requests the callback at requestURI, presenting binding
// (nil = none).
func staffSSOCallback(router http.Handler, requestURI string, binding *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, requestURI, nil)
	if binding != nil {
		req.AddCookie(&http.Cookie{Name: binding.Name, Value: binding.Value})
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func hasPlatformSession(w *httptest.ResponseRecorder) bool {
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "platform_access_token" && ck.Value != "" {
			return true
		}
	}
	return false
}

func TestIntegration_StaffSSO_StateBoundToBrowserAndPKCE(t *testing.T) {
	f := newSSOTakeoverFixture(t)
	router := f.srv.Router()
	code, body := f.admin(f.superA, http.MethodPost, "/identity-providers", f.providerBody())
	ssoTakeoverExpect(t, "super_admin create", code, body, http.StatusCreated)
	f.idpMu.Lock()
	f.userinfo = verifiedUserinfo(f.email("victim"))
	f.idpMu.Unlock()
	counts := func() (int, int) { f.idpMu.Lock(); defer f.idpMu.Unlock(); return f.tokenHits, f.pkceVerified }

	var used *url.URL
	var usedCookie *http.Cookie
	t.Run("happy path: S256 at authorize, the matching verifier at token exchange", func(t *testing.T) {
		idpURL, ck := staffSSOAuthorize(t, router, "google")
		if q := idpURL.Query(); q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 {
			t.Fatalf("authorize redirect lacks PKCE: %s", idpURL)
		}
		if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != staffCallbackPath || ck.MaxAge <= 0 || ck.MaxAge > 600 {
			t.Fatalf("binding cookie attributes wrong: HttpOnly=%v SameSite=%v Path=%q MaxAge=%d", ck.HttpOnly, ck.SameSite, ck.Path, ck.MaxAge)
		}
		back := followStaffIdP(t, idpURL)
		_, before := counts()
		w := staffSSOCallback(router, back.RequestURI(), ck)
		if w.Header().Get("Location") != "/" || !hasPlatformSession(w) {
			t.Fatalf("Location = %q, session = %v; want a session", w.Header().Get("Location"), hasPlatformSession(w))
		}
		if _, after := counts(); after-before != 1 {
			t.Fatal("the IdP did not receive the matching code_verifier")
		}
		cleared := false
		for _, c := range w.Result().Cookies() {
			if c.Name == "admin_sso_binding" && c.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Fatal("the callback did not expire the binding cookie")
		}
		used, usedCookie = back, ck
	})

	t.Run("replayed callback is refused", func(t *testing.T) {
		if used == nil {
			t.Skip("happy path failed")
		}
		hits, _ := counts()
		w := staffSSOCallback(router, used.RequestURI(), usedCookie)
		if w.Header().Get("Location") != "/login?error=sso_state" || hasPlatformSession(w) {
			t.Fatalf("Location = %q, session = %v; want the state refusal", w.Header().Get("Location"), hasPlatformSession(w))
		}
		if h, _ := counts(); h != hits {
			t.Fatal("a replayed callback reached the token endpoint")
		}
	})

	t.Run("callback without the binding cookie is refused before the code is exchanged", func(t *testing.T) {
		idpURL, _ := staffSSOAuthorize(t, router, "google")
		back := followStaffIdP(t, idpURL)
		hits, _ := counts()
		w := staffSSOCallback(router, back.RequestURI(), nil)
		if w.Header().Get("Location") != "/login?error=sso_state" || hasPlatformSession(w) {
			t.Fatalf("Location = %q; want the state refusal", w.Header().Get("Location"))
		}
		if h, _ := counts(); h != hits {
			t.Fatal("the code was exchanged")
		}
	})

	t.Run("login CSRF: the attacker's callback in the victim's browser is refused", func(t *testing.T) {
		attackerIdP, _ := staffSSOAuthorize(t, router, "google")
		attackerBack := followStaffIdP(t, attackerIdP)
		_, victimCookie := staffSSOAuthorize(t, router, "google")
		hits, _ := counts()
		w := staffSSOCallback(router, attackerBack.RequestURI(), victimCookie)
		if w.Header().Get("Location") != "/login?error=sso_state" || hasPlatformSession(w) {
			t.Fatalf("Location = %q; want the state refusal", w.Header().Get("Location"))
		}
		if h, _ := counts(); h != hits {
			t.Fatal("the attacker's code was exchanged")
		}
	})
}
