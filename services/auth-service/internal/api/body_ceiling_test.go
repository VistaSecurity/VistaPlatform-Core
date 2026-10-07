package api

// Request-body ceiling, driven through the REAL SetupRouter (the same recipe as
// select_tier_gate_test.go): deleting the router.Use(bodyCeiling()) line in
// router.go fails these tests, which a test of the middleware in isolation
// would not.
//
// Before the ceiling, every anonymous route here (login, register, password
// reset, OAuth token, invitation accept, ...) read whatever body the edge let
// through — up to 100 MiB — into a pod limited to a few hundred.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

const loginPath = "/api/v1/auth-service/auth/login"

func newBodyCeilingRouter(t *testing.T) (*gin.Engine, sqlmock.Sqlmock, *sql.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{JWTSecret: "test-secret-for-body-ceiling", JWTExpiry: time.Hour}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on these paths
	t.Cleanup(func() { _ = rdb.Close() })
	return SetupRouter(cfg, db, db, rdb, nil, EditionHooks{}), mock, db
}

// endlessBody is the start of a JSON string value that never ends, so a JSON
// decoder keeps reading (and buffering) it; it counts what was taken from it.
type endlessBody struct {
	n      atomic.Int64
	opened bool
}

func (b *endlessBody) Read(p []byte) (int, error) {
	i := 0
	if !b.opened {
		i = copy(p, `{"email":"`)
		b.opened = true
	}
	for ; i < len(p); i++ {
		p[i] = 'a'
	}
	b.n.Add(int64(len(p)))
	return len(p), nil
}

func TestBodyCeiling_AnonymousRoutesRefuseADeclaredOversizeBody(t *testing.T) {
	router, mock, _ := newBodyCeilingRouter(t)

	body := strings.NewReader(`{"email":"` + strings.Repeat("a", maxRequestBodyBytes+1) + `"}`)
	req := httptest.NewRequest(http.MethodPost, loginPath, body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("login with a >1 MiB body: status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the handler reached the database for a refused body: %v", err)
	}
}

func TestBodyCeiling_StopsAnUndeclaredStream(t *testing.T) {
	router, _, _ := newBodyCeilingRouter(t)

	body := &endlessBody{}
	req := httptest.NewRequest(http.MethodPost, loginPath, body)
	req.ContentLength = -1 // chunked: only MaxBytesReader can stop it
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("an endless login body was accepted")
	}
	// Whatever status the handler picks for the truncated body, the stream was
	// cut at the ceiling rather than consumed.
	if got := body.n.Load(); got > 4*maxRequestBodyBytes {
		t.Fatalf("pulled %d bytes from an endless body; the ceiling is %d", got, maxRequestBodyBytes)
	}
}

func TestBodyCeiling_OtherAnonymousRoutesAreCoveredToo(t *testing.T) {
	for _, path := range []string{
		"/api/v1/auth-service/auth/register",
		"/api/v1/auth-service/auth/forgot-password",
		"/api/v1/auth-service/auth/reset-password",
		"/api/v1/auth-service/auth/refresh",
		"/api/v1/auth-service/auth/authenticate",
		"/api/v1/auth-service/auth/invitations/accept",
		"/api/v1/auth-service/oauth/token",
	} {
		t.Run(path, func(t *testing.T) {
			router, _, _ := newBodyCeilingRouter(t)
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(strings.Repeat("a", maxRequestBodyBytes+1)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// A body inside the ceiling still reaches the handler: an empty JSON object is
// a 400 from the handler's own validation, not a 413 from the ceiling.
func TestBodyCeiling_NormalBodyStillReachesTheHandler(t *testing.T) {
	router, _, _ := newBodyCeilingRouter(t)

	req := httptest.NewRequest(http.MethodPost, loginPath, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("a 2-byte body was refused as too large")
	}
}

// The image-upload routes keep their own, larger ceiling: a 2 MiB request is
// past the standard ceiling but inside an image upload's, so it must get as far
// as authentication (401) — and an upload past MaxImageUploadRequestBytes is
// refused at the ceiling.
func TestBodyCeiling_ImageUploadRoutesKeepTheirOwnCeiling(t *testing.T) {
	for _, path := range []string{
		"/api/v1/auth-service/auth/upload-avatar",
		"/api/v1/auth-service/tenant/branding/upload",
	} {
		t.Run(path, func(t *testing.T) {
			router, _, _ := newBodyCeilingRouter(t)

			within := httptest.NewRequest(http.MethodPost, path, strings.NewReader(strings.Repeat("a", 2<<20)))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, within)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("2 MiB upload without credentials: status = %d, want 401 (past the ceiling, stopped by auth); body=%s", w.Code, w.Body.String())
			}

			over := httptest.NewRequest(http.MethodPost, path, strings.NewReader(strings.Repeat("a", MaxImageUploadRequestBytes+1)))
			w = httptest.NewRecorder()
			router.ServeHTTP(w, over)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("upload over the image ceiling: status = %d, want 413; body=%s", w.Code, w.Body.String())
			}
		})
	}
}
