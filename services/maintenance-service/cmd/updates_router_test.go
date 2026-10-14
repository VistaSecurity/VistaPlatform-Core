package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/capabilities"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/updates"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// updatesRouterStub is the update-check service behind the router in tests:
// the gate tests need a route that answers; the service's own behaviour is
// tested in internal/updates and internal/handlers.
type updatesRouterStub struct{}

func (updatesRouterStub) Read(context.Context) (updates.View, error) {
	return updates.View{CheckEnabled: true}, nil
}

func (updatesRouterStub) Check(context.Context) (updates.View, error) {
	return updates.View{CheckEnabled: true}, nil
}

// The update-check routes are wired to REAL handlers, not the 501 stub WP1
// mounted: restoring handlers.NotImplemented on either fails here.
func TestUpdateRoutes_AreRealHandlers(t *testing.T) {
	for _, rt := range []struct {
		method, path, permission string
	}{
		{http.MethodGet, adminPrefix + "/updates", rbac.PermissionPlatformHealth},
		{http.MethodPost, adminPrefix + "/updates/check", rbac.PermissionPlatformMaintenance},
	} {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			r, mock := newProductionRouter(t)
			user := uuid.New()
			mock.ExpectQuery(permissionQuery).WithArgs(user, rt.permission).
				WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(true))
			w := do(r, authed(rt.method, rt.path, platformToken(t, user, uuid.Nil)))
			if w.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", w.Code, w.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if _, stub := body["work_package"]; stub {
				t.Fatalf("still the 501 stub: %s", w.Body.String())
			}
			if _, ok := body["update_available"]; !ok {
				t.Fatalf("body lacks update_available: %s", w.Body.String())
			}
		})
	}
}

// A viewer with platform.health but not platform.maintenance can read the
// status and cannot force a check (an outbound call the operator gates).
func TestUpdateRoutes_ReadAndCheckUseDifferentPermissions(t *testing.T) {
	r, mock := newProductionRouter(t)
	user := uuid.New()
	tok := platformToken(t, user, uuid.Nil)
	mock.ExpectQuery(permissionQuery).WithArgs(user, rbac.PermissionPlatformHealth).
		WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(true))
	if w := do(r, authed(http.MethodGet, adminPrefix+"/updates", tok)); w.Code != http.StatusOK {
		t.Fatalf("read = %d", w.Code)
	}
	mock.ExpectQuery(permissionQuery).WithArgs(user, rbac.PermissionPlatformMaintenance).
		WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(false))
	if w := do(r, authed(http.MethodPost, adminPrefix+"/updates/check", tok)); w.Code != http.StatusForbidden {
		t.Fatalf("check without platform.maintenance = %d, want 403", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A manual check lands in the activity trail with its own event, beyond the
// request-level entry. Dropping the audit call in the handler fails this.
func TestUpdateRoutes_ManualCheckIsAudited(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("DATABASE_URL", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("INTERNAL_AUTH_SECRET", testInternalSecret)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logger, _ := test.NewNullLogger()
	h := handlers.New(okPinger{}, nil, capabilities.NotKubernetes{}, staticVersions{}, handlers.Config{}, logger)
	h.SetUpdates(updatesRouterStub{})
	mw := newTestAuditMiddleware(t)
	r := newRouter(h, mw, newAuthMiddleware(testJWTSecret), db, backupsTestOps())

	user := uuid.New()
	mock.ExpectQuery(permissionQuery).WithArgs(user, rbac.PermissionPlatformMaintenance).
		WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(true))
	if w := do(r, authed(http.MethodPost, adminPrefix+"/updates/check", platformToken(t, user, uuid.Nil))); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	for _, e := range mw.PendingEntries() {
		if e.EventType == "maintenance.update.checked" {
			return
		}
	}
	t.Fatalf("no maintenance.update.checked entry among %d pending audit entries", len(mw.PendingEntries()))
}
