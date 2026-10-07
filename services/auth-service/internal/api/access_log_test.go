package api

// The request logs must not carry the query string: on an SSO callback that is
// the OAuth code and state. The service has TWO request loggers, gin's
// (router.Use(sharedmw.AccessLog()), to gin.DefaultWriter) and the structured
// logrus one (middleware.Logging, to stderr), and both are checked here.
// Driven through the REAL SetupRouter, so swapping either back fails it.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

func TestAccessLog_NeverWritesTheQueryString(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var ginLogs bytes.Buffer
	prev := gin.DefaultWriter
	gin.DefaultWriter = &ginLogs
	t.Cleanup(func() { gin.DefaultWriter = prev })

	// middleware.Logging builds its logrus logger on os.Stderr when the router
	// is set up, so point stderr at a pipe for that window.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	realStderr := os.Stderr
	os.Stderr = pw
	t.Cleanup(func() { os.Stderr = realStderr })
	var structured bytes.Buffer
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(&structured, pr); close(copied) }()

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = rdb.Close() })
	router := SetupRouter(&config.Config{JWTSecret: "test-secret-for-access-log", JWTExpiry: time.Hour}, db, db, rdb, nil, EditionHooks{})

	secrets := []string{"SECRETAUTHCODE", "STATEVALUE123", "SECRETIDTOKEN", "SECRETACCESSTOKEN"}
	paths := []string{
		"/api/v1/auth-service/auth/sso/google/callback",
		"/api/v1/auth-service/auth/sso/platform/google/callback",
		"/api/v1/auth-service/oauth/authorize",
	}
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet,
			path+"?code=SECRETAUTHCODE&state=STATEVALUE123&id_token=SECRETIDTOKEN&access_token=SECRETACCESSTOKEN", nil)
		router.ServeHTTP(httptest.NewRecorder(), req)
	}

	os.Stderr = realStderr
	_ = pw.Close()
	<-copied

	for name, logs := range map[string]string{"gin request log": ginLogs.String(), "structured request log": structured.String()} {
		for _, path := range paths {
			if !strings.Contains(logs, path) {
				t.Fatalf("%s: the request to %s was not logged at all:\n%s", name, path, logs)
			}
		}
		for _, secret := range secrets {
			if strings.Contains(logs, secret) {
				t.Errorf("%s contains %q:\n%s", name, secret, logs)
			}
		}
		if strings.Contains(logs, "code=") || strings.Contains(logs, "state=") {
			t.Errorf("%s still carries a query string:\n%s", name, logs)
		}
	}
}
