package versions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const secret = "versions-client-test-internal-secret"

// The call reaches monitoring-service's route with a signature its shared
// verifier accepts — the same verifier RequireJWTAuth runs for HMAC calls.
func TestVersions_SignedAndProxiedVerbatim(t *testing.T) {
	gin.SetMode(gin.TestMode)
	verifier := serviceauth.NewVerifier(secret)
	var sawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = r
		if !verifier.Verify(c) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"status":"aligned"}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, srv.Client(), secret)
	if err != nil {
		t.Fatal(err)
	}
	body, err := c.Versions(context.Background())
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if sawPath != Path {
		t.Fatalf("called %q, want %q", sawPath, Path)
	}
	if string(body) != `{"status":"aligned"}` {
		t.Fatalf("body not proxied verbatim: %s", body)
	}
}

func TestVersions_Errors(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"non-200":  func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
		"not json": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			c, _ := New(srv.URL, srv.Client(), secret)
			if _, err := c.Versions(context.Background()); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestNew_RequiresSecret(t *testing.T) {
	if _, err := New("http://x", nil, " "); err == nil {
		t.Fatal("an unsigned version read must not be constructible")
	}
}
