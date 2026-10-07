package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	adminauth "github.com/vistasecurity/vistaplatform/admin-service/internal/auth"
)

// useLoopbackStaffIdP swaps the guarded client for a plain one for the
// duration of a test whose fake IdP listens on 127.0.0.1, which the real client
// refuses. Tests of the guard itself do not call it.
func useLoopbackStaffIdP(t *testing.T) {
	t.Helper()
	previous := staffSSOHTTPClient
	staffSSOHTTPClient = &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(func() { staffSSOHTTPClient = previous })
}

// runStaffCallback drives the real StaffSsoCallback with a provider row naming
// the given token and userinfo URLs, and returns the redirect Location.
func runStaffCallback(t *testing.T, tokenURL, userinfoURL string, afterProvider func(mock sqlmock.Sqlmock)) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectQuery(regexp.QuoteMeta(staffProviderQuery)).
		WithArgs("google").
		WillReturnRows(sqlmock.NewRows(staffProviderColumns).
			AddRow(uuid.NewString(), "client-id", "client-secret", "https://idp.example.com/authorize", tokenURL, userinfoURL, nil, "{}"))
	if afterProvider != nil {
		afterProvider(mock)
	}

	r := gin.New()
	r.GET("/admin/sso/:provider/callback", StaffSsoCallback(db, "staff-sso-egress-test-secret", adminauth.NewPlatformRefreshTokenService(db)))
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/google/callback?state=s&code=c", nil)
	req.AddCookie(&http.Cookie{Name: "admin_sso_state", Value: "s"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", w.Code)
	}
	return w.Header().Get("Location")
}

func countingServer(t *testing.T, handle http.HandlerFunc) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		handle(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// The token URL is typed by a platform administrator. With the real client the
// code exchange must never reach a loopback or metadata address.
func TestStaffSsoCallback_TokenURLNeverReachesLoopback(t *testing.T) {
	idp, hits := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"t"}`))
	})

	// Control: reachable by an unguarded client.
	resp, err := http.PostForm(idp.URL+"/token", url.Values{})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	_ = resp.Body.Close()
	atomic.StoreInt32(hits, 0)

	for _, token := range []string{
		idp.URL + "/token",
		"http://169.254.169.254/latest/api/token",
		"http://[fd00:ec2::254]/latest/api/token",
		"http://10.43.0.1:443/token", // a cluster Service address
	} {
		loc := runStaffCallback(t, token, "https://idp.example.com/userinfo", nil)
		if loc != "/login?error=sso_exchange" {
			t.Errorf("token_url %s: Location = %q, want the exchange failure", token, loc)
		}
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("the loopback IdP saw %d request(s); the client secret went to an internal address", got)
	}
}

// The userinfo call is a separate call site. A routing transport lets the token
// request reach a loopback fake IdP (as a public IdP would be reachable) while
// everything else goes through the real guarded transport, so a userinfo URL
// aimed at loopback must still be refused, with the access token unspent.
func TestStaffSsoCallback_UserinfoURLNeverReachesLoopback(t *testing.T) {
	tokenIdP, _ := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"idp-access-token"}`))
	})
	internal, internalHits := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"email":"admin@example.com","email_verified":true}`))
	})

	guarded := newStaffSSOClient()
	tokenHost := strings.TrimPrefix(tokenIdP.URL, "http://")
	previous := staffSSOHTTPClient
	staffSSOHTTPClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == tokenHost {
				return http.DefaultTransport.RoundTrip(r)
			}
			return guarded.Transport.RoundTrip(r)
		}),
	}
	t.Cleanup(func() { staffSSOHTTPClient = previous })

	loc := runStaffCallback(t, tokenIdP.URL+"/token", internal.URL+"/userinfo", nil)
	if loc != "/login?error=sso_userinfo" {
		t.Errorf("Location = %q, want the userinfo failure", loc)
	}
	if got := atomic.LoadInt32(internalHits); got != 0 {
		t.Fatalf("the internal userinfo server saw %d request(s)", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// An IdP answer is read through a 1 MiB ceiling. Oversize token and userinfo
// documents are refused (truncated JSON does not parse), and a body that never
// ends is cut off instead of buffered.
func TestStaffSsoCallback_IdPResponsesAreCapped(t *testing.T) {
	useLoopbackStaffIdP(t)
	pad := strings.Repeat("A", 2<<20)

	t.Run("oversize token answer", func(t *testing.T) {
		idp, _ := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"t","pad":"`+pad+`"}`)
		})
		loc := runStaffCallback(t, idp.URL+"/token", idp.URL+"/userinfo", nil)
		if loc != "/login?error=sso_exchange" {
			t.Fatalf("Location = %q, want the exchange failure for an oversize token answer", loc)
		}
	})

	t.Run("oversize userinfo answer", func(t *testing.T) {
		idp, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/token" {
				_, _ = io.WriteString(w, `{"access_token":"t"}`)
				return
			}
			_, _ = io.WriteString(w, `{"email":"admin@example.com","email_verified":true,"pad":"`+pad+`"}`)
		})
		loc := runStaffCallback(t, idp.URL+"/token", idp.URL+"/userinfo", nil)
		if loc != "/login?error=sso_no_email" {
			t.Fatalf("Location = %q, want a refusal for an oversize userinfo answer", loc)
		}
	})

	t.Run("endless userinfo answer is not buffered", func(t *testing.T) {
		idp, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/token" {
				_, _ = io.WriteString(w, `{"access_token":"t"}`)
				return
			}
			_, _ = io.WriteString(w, `{"email":"`)
			chunk := []byte(strings.Repeat("a", 64<<10))
			for {
				if _, err := w.Write(chunk); err != nil {
					return // the reader gave up: exactly what the cap does
				}
			}
		})
		done := make(chan string, 1)
		go func() { done <- runStaffCallback(t, idp.URL+"/token", idp.URL+"/userinfo", nil) }()
		select {
		case loc := <-done:
			if loc != "/login?error=sso_no_email" {
				t.Fatalf("Location = %q, want a refusal", loc)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("the callback is still reading an endless userinfo body")
		}
	})
}

// Off-origin redirects are refused: a 307 from the token endpoint would
// otherwise replay the code exchange, client secret included, elsewhere.
func TestStaffSSORefusesOffOriginRedirect(t *testing.T) {
	if err := staffSSORefuseOffOriginRedirect(
		mustReq(t, "http://other.example.net/token"),
		[]*http.Request{mustReq(t, "http://idp.example.com/token")}); err == nil {
		t.Fatal("an off-origin redirect was followed")
	}
	if err := staffSSORefuseOffOriginRedirect(
		mustReq(t, "http://idp.example.com/token2"),
		[]*http.Request{mustReq(t, "http://idp.example.com/token")}); err != nil {
		t.Fatalf("a same-origin redirect was refused: %v", err)
	}
}

func mustReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
