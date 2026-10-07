package api

// D10 (pentest-readiness review): POST /oauth/authorize records the user's
// consent from the session cookie alone. These tests drive the REAL router, so
// deleting the originguard line in router.go turns them red (a test of the
// middleware in isolation would stay green).
//
// The probe body carries no client_id, so a request that gets PAST the guard is
// answered 400 by the handler's parameter validation, with no database or
// session involved. The guard's refusal is 403. The two are told apart by status.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postConsent(t *testing.T, headers map[string]string) int {
	t.Helper()
	router, _ := newEnumerationRouter(t, 0)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/oauth/authorize", strings.NewReader("decision=allow"))
	req.Host = "vista.example.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code
}

func TestOAuthConsentPOST_RefusesCrossSiteBrowserRequests(t *testing.T) {
	for name, hdr := range map[string]map[string]string{
		"Sec-Fetch-Site cross-site":    {"Sec-Fetch-Site": "cross-site"},
		"foreign Origin":               {"Origin": "https://evil.example"},
		"null Origin":                  {"Origin": "null"},
		"same-site sibling Origin":     {"Origin": "https://admin.vista.example.test", "Sec-Fetch-Site": "same-site"},
		"same-origin metadata, forged": {"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.example"},
	} {
		if got := postConsent(t, hdr); got != http.StatusForbidden {
			t.Errorf("%s => %d; want 403 before the handler runs", name, got)
		}
	}
}

func TestOAuthConsentPOST_AllowsSameOriginAndNonBrowserClients(t *testing.T) {
	for name, hdr := range map[string]map[string]string{
		"no fetch metadata (non-browser client)": nil,
		"same-origin":                            {"Sec-Fetch-Site": "same-origin"},
		"matching Origin":                        {"Origin": "https://vista.example.test", "Sec-Fetch-Site": "same-origin"},
	} {
		if got := postConsent(t, hdr); got != http.StatusBadRequest {
			t.Errorf("%s => %d; want 400 (reached the handler, which rejects the empty parameters)", name, got)
		}
	}
}
