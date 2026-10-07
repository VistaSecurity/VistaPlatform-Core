package api

// The request log must not carry the query string: on the staff SSO callback
// that is the OAuth code and state. Driven through the REAL router the service
// builds, so swapping the logger line in setupRouter back to gin.Logger() fails
// it.

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
)

func TestAccessLog_NeverWritesTheQueryString(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var logs bytes.Buffer
	prev := gin.DefaultWriter
	gin.DefaultWriter = &logs
	t.Cleanup(func() { gin.DefaultWriter = prev })

	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	router := NewServerWithConnections(&config.Config{Environment: "test"}, db, db, EditionHooks{}).Router()

	const path = "/api/v1/admin-service/admin/sso/google/callback"
	req := httptest.NewRequest(http.MethodGet, path+"?code=SECRETAUTHCODE&state=STATEVALUE123&id_token=SECRETIDTOKEN", nil)
	router.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.Contains(logs.String(), path) {
		t.Fatalf("the callback request was not logged at all:\n%s", logs.String())
	}
	for _, secret := range []string{"SECRETAUTHCODE", "STATEVALUE123", "SECRETIDTOKEN"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the request log contains %q:\n%s", secret, logs.String())
		}
	}
}
