package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Unit tests for the permission-based RequirePlatformAdmin. The database
// answer is mocked here; the per-service TestIntegration_* suites drive each
// service's real router against real platform_role_permissions rows.

const gatedPermission = "platform.health"

func platformGateRouter(t *testing.T, gate gin.HandlerFunc, setup func(c *gin.Context)) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/gated", func(c *gin.Context) {
		setup(c)
		c.Next()
	}, gate, func(c *gin.Context) {
		c.String(http.StatusOK, "reached")
	})
	return r
}

func serve(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/gated", nil))
	return w
}

func asPlatform(userID uuid.UUID, role string) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Set(CtxKeyUserID, userID)
		c.Set(CtxKeyUserType, UserTypePlatform)
		c.Set(CtxKeyRole, role)
	}
}

// The decision is the grant, not the role name: the same user passes or fails
// on what platform_user_has_permission() answers, whatever role string the
// token carries — including the two names the old gate admitted on sight.
func TestRequirePlatformAdmin_GrantDecidesNotRoleName(t *testing.T) {
	cases := []struct {
		name    string
		role    string
		granted bool
		want    int
	}{
		{"custom role with the grant passes", "noc_operator", true, http.StatusOK},
		{"custom role without the grant is refused", "noc_operator", false, http.StatusForbidden},
		{"role named platform_admin without the grant is refused", "platform_admin", false, http.StatusForbidden},
		{"role named super_admin without the grant is refused", "super_admin", false, http.StatusForbidden},
		{"role named support_admin without the grant is refused", "support_admin", false, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			userID := uuid.New()
			mock.ExpectQuery(`SELECT platform_user_has_permission\(\$1, \$2\)`).
				WithArgs(userID, gatedPermission).
				WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(tc.granted))

			w := serve(platformGateRouter(t, RequirePlatformAdmin(db, gatedPermission), asPlatform(userID, tc.role)))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusForbidden && !strings.Contains(w.Body.String(), `"required_permission":"`+gatedPermission+`"`) {
				t.Errorf("403 does not name the permission: %s", w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the gate did not ask the database for %s: %v", gatedPermission, err)
			}
		})
	}
}

// A tenant token is refused before the database is asked, whatever role claim
// it carries. An expectation-free mock fails the test if a query runs.
func TestRequirePlatformAdmin_TenantTokenRefusedWithoutQuery(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	w := serve(platformGateRouter(t, RequirePlatformAdmin(db, gatedPermission), func(c *gin.Context) {
		c.Set(CtxKeyUserID, uuid.New())
		c.Set(CtxKeyUserType, UserTypeTenant)
		c.Set(CtxKeyTenantID, uuid.New())
		c.Set(CtxKeyRole, "platform_admin")
	}))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Platform user required") {
		t.Fatalf("tenant token: status %d body %s, want 403 Platform user required", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("tenant token reached the database: %v", err)
	}
}

// Through the real JWT middleware: a tenant token claiming a platform role is
// refused; a platform token is resolved against the grant.
func TestRequirePlatformAdmin_AfterRequireJWTAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name     string
		tenantID uuid.UUID
		granted  bool
		queried  bool
		want     int
	}{
		{"platform identity with the grant", uuid.Nil, true, true, http.StatusOK},
		{"platform identity without the grant", uuid.Nil, false, true, http.StatusForbidden},
		{"tenant identity despite platform role string", uuid.New(), true, false, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			if tc.queried {
				mock.ExpectQuery(`platform_user_has_permission`).
					WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(tc.granted))
			}
			r := gin.New()
			r.Use(RequireJWTAuth(AuthConfig{TenantState: liveTenantState(), JWTSecret: testJWTSecret}))
			r.Use(RequirePlatformAdmin(db, gatedPermission))
			r.GET("/protected", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+signAccessToken(t, tc.tenantID))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d (body %s)", w.Code, tc.want, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}
		})
	}
}

// HMAC internal calls get NO bypass here: the operator routes this guards
// refused them under the old gate too. (sharedrbac.RequirePlatformPermission
// is the variant with the bypass.)
func TestRequirePlatformAdmin_NoInternalCallBypass(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	w := serve(platformGateRouter(t, RequirePlatformAdmin(db, gatedPermission), func(c *gin.Context) {
		c.Set(CtxKeyIsInternalCall, true)
		c.Set(CtxKeyUserID, InternalUserIDSentinel)
	}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("internal call: status %d, want 403", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestRequirePlatformAdmin_FailsClosed(t *testing.T) {
	t.Run("database error is a 500, not a pass", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		mock.ExpectQuery(`platform_user_has_permission`).WillReturnError(errors.New("connection reset"))
		w := serve(platformGateRouter(t, RequirePlatformAdmin(db, gatedPermission), asPlatform(uuid.New(), "super_admin")))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status %d, want 500", w.Code)
		}
	})
	t.Run("nil db is a 503", func(t *testing.T) {
		w := serve(platformGateRouter(t, RequirePlatformAdmin(nil, gatedPermission), asPlatform(uuid.New(), "super_admin")))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", w.Code)
		}
	})
	t.Run("nil db still refuses a tenant token as a tenant token", func(t *testing.T) {
		w := serve(platformGateRouter(t, RequirePlatformAdmin(nil, gatedPermission), func(c *gin.Context) {
			c.Set(CtxKeyUserID, uuid.New())
			c.Set(CtxKeyUserType, UserTypeTenant)
		}))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Platform user required") {
			t.Fatalf("status %d body %s, want 403 Platform user required", w.Code, w.Body.String())
		}
	})
	t.Run("missing user id is a 401", func(t *testing.T) {
		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		w := serve(platformGateRouter(t, RequirePlatformAdmin(db, gatedPermission), func(c *gin.Context) {
			c.Set(CtxKeyUserType, UserTypePlatform)
		}))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", w.Code)
		}
	})
	t.Run("an unnamed permission panics at wiring time", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("RequirePlatformAdmin(db, \"\") did not panic — a gate that checks nothing would have been mounted")
			}
		}()
		_ = RequirePlatformAdmin(nil, "")
	})
}

// A scope-narrowed token (read-only PAT) must carry the permission in its
// scopes even when the user's role holds it.
func TestRequirePlatformAdmin_TokenScopeNarrows(t *testing.T) {
	for _, tc := range []struct {
		scopes []string
		want   int
	}{
		{[]string{"platform.audit"}, http.StatusForbidden},
		{[]string{gatedPermission}, http.StatusOK},
	} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectQuery(`platform_user_has_permission`).
			WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(true))
		userID := uuid.New()
		w := serve(platformGateRouter(t, RequirePlatformAdmin(db, gatedPermission), func(c *gin.Context) {
			asPlatform(userID, "noc_operator")(c)
			c.Set(CtxKeyTokenScopes, tc.scopes)
		}))
		if w.Code != tc.want {
			t.Errorf("scopes %v: status %d, want %d", tc.scopes, w.Code, tc.want)
		}
		_ = db.Close()
	}
}
