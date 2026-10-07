package api

// The anonymous /admin-service/auth routes (login, refresh, reset-password,
// forgot-password) read a request body before any caller is authenticated.
// Driven through the REAL router the service builds, so deleting the group's
// MaxBody wiring in setupRouter fails these tests.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
)

func TestAnonymousAuthRoutes_RefuseAnOversizeBody(t *testing.T) {
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	router := NewServerWithConnections(&config.Config{Environment: "test"}, db, db, EditionHooks{}).Router()

	for _, path := range []string{
		"/api/v1/admin-service/auth/login",
		"/api/v1/admin-service/auth/refresh",
		"/api/v1/admin-service/auth/reset-password",
		"/api/v1/admin-service/auth/forgot-password",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"email":"`+strings.Repeat("a", maxAnonymousBodyBytes+1)+`"}`))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
			}
		})
	}

	// A small body still reaches the handler (a 400 from its own validation).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin-service/auth/login", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("a 2-byte body was refused as too large")
	}
}
