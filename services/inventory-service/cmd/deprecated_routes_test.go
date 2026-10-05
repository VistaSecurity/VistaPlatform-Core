package main

// The Stale lens's old actions are deprecated: every v1 and v2
// registration must go through deprecatedRoute naming the right successor,
// and the middleware must send both headers without changing the response.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestDeprecatedLifecycleRoutesAreMarked(t *testing.T) {
	for path, successor := range map[string]string{
		"/inventory-service/assets/stale/rescan":                 "successorScan",
		"/inventory-service/assets/stale/archive":                "successorArchive",
		"/inventory-service/assets/revalidate":                   "successorScan",
		"/inventory-service/infrastructure-assets/stale/rescan":  "successorScan",
		"/inventory-service/infrastructure-assets/stale/archive": "successorArchive",
		"/inventory-service/infrastructure-assets/revalidate":    "successorScan",
	} {
		for _, args := range registrationsOf(t, http.MethodPost, path) {
			want := "deprecatedRoute(lifecycleRoutesDeprecatedAt, " + successor + ")"
			if !strings.Contains(args, want) {
				t.Errorf("POST %s is not mounted through %s:\n%s", path, want, args)
			}
		}
	}
}

func TestDeprecatedRouteSendsDeprecationAndSuccessor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	since := time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)
	r.POST("/old", deprecatedRoute(since, "/new"), func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/old", nil))
	if w.Code != http.StatusOK || w.Body.String() != `{"ok":true}` {
		t.Fatalf("the route's own response changed: %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Deprecation"); got != "@1791158400" {
		t.Errorf("Deprecation = %q, want @1791158400 (RFC 9745 date of 2026-10-05)", got)
	}
	if got := w.Header().Get("Link"); got != `</new>; rel="successor-version"` {
		t.Errorf("Link = %q", got)
	}
}
