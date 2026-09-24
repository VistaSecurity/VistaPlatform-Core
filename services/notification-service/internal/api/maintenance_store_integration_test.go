package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Owner decision 9 (ADMIN_UI_DATA_REVIEW_2026-09, RC-20): the platform keeps
// ONE maintenance-window store — the one alert suppression reads. The admin
// console used to have two forms: Comms → Maintenance wrote a table nothing
// read (removed), and System → Alerts writes this service's
// /platform/maintenance-windows.
//
// This drives the REAL router (SetupRouter, with its real auth and
// platform.notifications.manage gate) against a real Postgres and proves that
// a window created through that route is the one suppression sees, and that
// deleting it lifts suppression. A second store, or suppression reading a
// different table, fails here.

const maintSigningValue = "notification-maintenance-integration-signing-value"

func TestIntegration_MaintenanceWindowRouteFeedsSuppression(t *testing.T) {
	db := testdb.Connect(t)
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")

	svc := services.NewNotificationService(sqlx.NewDb(db, "postgres"), db, &config.Config{})
	router := NewServer(&config.Config{JWTSecret: maintSigningValue}, sqlx.NewDb(db, "postgres"), db, svc).SetupRouter()

	role := testdb.NewPlatformRole(t, db, rbac.PermissionPlatformNotificationsManage)
	user := testdb.NewPlatformUser(t, db, role)
	bearer := testdb.SignPlatformToken(t, maintSigningValue, user, "platform_admin")

	do := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, "/api/v1/notification-service/platform/maintenance-windows"+path, &buf)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if testdb.RefusedByPlatformGate(w) {
			t.Fatalf("%s refused by the platform gate: %d %s", method, w.Code, w.Body.String())
		}
		return w
	}

	// Suppression is platform-wide, so an active window left behind by
	// something else would make both assertions below pass for the wrong
	// reason. Nothing else in the suites creates one; if one exists, say so
	// rather than skip — a skipped guard reads as a passing one.
	if svc.IsMaintenanceActive(context.Background()) {
		t.Fatal("a platform maintenance window is already active in this database; remove it (platform_maintenance_windows) — this test cannot tell its own window from it")
	}

	w := do(http.MethodPost, "", map[string]any{
		"starts_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		"ends_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"reason":    "decision-9 integration",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("POST maintenance window = %d %s", w.Code, w.Body.String())
	}
	var created services.MaintenanceWindow
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == uuid.Nil {
		t.Fatalf("decode created window: %v (%s)", err, w.Body.String())
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_maintenance_windows WHERE id = $1`, created.ID) })

	if !svc.IsMaintenanceActive(context.Background()) {
		t.Fatal("a window created through /platform/maintenance-windows does not suppress delivery — the form and suppression read different stores")
	}

	if w := do(http.MethodGet, "", nil); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(created.ID.String())) {
		t.Fatalf("GET maintenance windows = %d, want the created window listed: %s", w.Code, w.Body.String())
	}

	if w := do(http.MethodDelete, "/"+created.ID.String(), nil); w.Code != http.StatusOK {
		t.Fatalf("DELETE maintenance window = %d %s", w.Code, w.Body.String())
	}
	if svc.IsMaintenanceActive(context.Background()) {
		t.Fatal("deleting the window through the route did not lift suppression")
	}
}
