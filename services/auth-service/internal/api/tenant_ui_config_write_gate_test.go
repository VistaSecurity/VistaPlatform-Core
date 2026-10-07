package api

// PUT /tenant/ui-config authorized on the JWT `role` string
// (`userRole != "platform_admin"`), a value that is not platform-controlled:
// tenant custom roles carry whatever name the tenant gives them, and the login
// path copies it into the token. A tenant user holding a role of that name could
// rewrite its tenant's UI config as if it were the platform. The route now needs
// a PLATFORM identity plus platform.settings (the pair its /admin/tenants/:id
// sibling already used), and the handler re-checks the identity itself.
//
// These drive the REAL SetupRouter, so deleting the gate from router.go (or the
// identity check from the handler AND the router) fails them.
//
// There are two independent identity layers by design: the router's
// RequirePlatformIdentity and the handler's own check. Mutations, and what each
// turns red:
//   - handler check removed alone: the handler-level contract tests in
//     tenant_ui_config_contract_test.go (this file's tests stay green; the
//     router still refuses);
//   - router RequirePlatformIdentity removed alone: nothing (the handler still
//     refuses) — redundancy, not a gap;
//   - both removed: TestTenantUIConfigPut_RejectsTenantTokenClaimingPlatformRole;
//   - router RequirePlatformPermission removed:
//     TestTenantUIConfigPut_RefusesPlatformIdentityWithoutPermission;
//   - the original role-string check restored: all of the above.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

const tenantUIConfigPutPath = "/api/v1/auth-service/tenant/ui-config"

// putTenantUIConfig sends PUT /tenant/ui-config through the real router with a
// token minted for (tenantID, roleClaim). script wires the sqlmock the handler
// chain will hit; it runs after the router is built.
func putTenantUIConfig(t *testing.T, tenantID uuid.UUID, roleClaim string, script func(mock sqlmock.Sqlmock)) (*httptest.ResponseRecorder, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := &config.Config{JWTSecret: "test-secret-for-tenant-ui-config-put"}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on this path
	t.Cleanup(func() { _ = rdb.Close() })

	router := SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})
	if script != nil {
		script(mock)
	}

	jwtService := auth.NewJWTService(cfg.JWTSecret, time.Hour, time.Hour)
	access, _, err := jwtService.GenerateTokens(uuid.New(), tenantID, "user@example.test", roleClaim)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, tenantUIConfigPutPath, strings.NewReader(`{"primary_color":"#000000"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w, mock
}

func TestTenantUIConfigPut_RejectsTenantTokenClaimingPlatformRole(t *testing.T) {
	for _, role := range []string{"platform_admin", "super_admin"} {
		t.Run(role, func(t *testing.T) {
			tenant := uuid.New()
			w, mock := putTenantUIConfig(t, tenant, role, func(m sqlmock.Sqlmock) {
				expectLiveTenantState(m, tenant) // the tenant is live; the refusal must come from the identity gate
			})
			if w.Code != http.StatusForbidden {
				t.Fatalf("tenant token with role=%q reached PUT /tenant/ui-config with status %d, want 403.\n"+
					"A tenant identity must never satisfy a platform gate, however its role string reads.\nbody: %s",
					role, w.Code, w.Body.String())
			}
			// Nothing past the gate may have run: only the tenant-state lookup.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unexpected or missing queries: %v", err)
			}
		})
	}
}

// The other polarity: a genuine platform identity (nil tenant id) holding
// platform.settings clears BOTH gates and reaches the handler. Scripting the
// store to report "tenant not found" gives a 404 that only the handler can
// produce, so "not 403/401" is not the whole assertion here.
func TestTenantUIConfigPut_AdmitsPlatformIdentityWithPermission(t *testing.T) {
	w, mock := putTenantUIConfig(t, uuid.Nil, "platform_admin", func(m sqlmock.Sqlmock) {
		m.ExpectQuery(`platform_user_has_permission`).
			WillReturnRows(sqlmock.NewRows([]string{"platform_user_has_permission"}).AddRow(true))
		m.ExpectQuery(`FROM tenants`).WillReturnRows(sqlmock.NewRows([]string{"ui_config"})) // no row -> sql.ErrNoRows
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("platform identity with platform.settings: status = %d, want 404 from the handler (it cleared both gates); body: %s",
			w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the request did not reach the handler: %v", err)
	}
}

// A platform identity WITHOUT platform.settings (a support_agent, say) is a
// platform identity and still must not rewrite UI config: the permission is the
// router's second gate.
func TestTenantUIConfigPut_RefusesPlatformIdentityWithoutPermission(t *testing.T) {
	w, mock := putTenantUIConfig(t, uuid.Nil, "support_agent", func(m sqlmock.Sqlmock) {
		m.ExpectQuery(`platform_user_has_permission`).
			WillReturnRows(sqlmock.NewRows([]string{"platform_user_has_permission"}).AddRow(false))
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("platform identity without platform.settings: status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected or missing queries: %v", err)
	}
}
