package api

// Contract test for the PLATFORM maintenance-windows HTTP surface (storm control
// §10.3) — the admin-ui-v2 System Health → Alerts panel manages these. Companion
// to the platform channels/rules slice; reuses its harness (ncLoadSpec / ncDo /
// ncBase / ncAID) and adds a stub for the narrow maintenanceIface introduced on
// *Server so the real gin handlers run over httptest with no database.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/services"
)

// stubMaintenance implements maintenanceIface.
type stubMaintenance struct {
	list      []services.MaintenanceWindow
	listErr   error
	created   *services.MaintenanceWindow
	createErr error
	deleteHit bool
	deleteErr error
}

func (s *stubMaintenance) ListMaintenanceWindows(context.Context) ([]services.MaintenanceWindow, error) {
	return s.list, s.listErr
}
func (s *stubMaintenance) CreateMaintenanceWindow(context.Context, time.Time, time.Time, string, *uuid.UUID) (*services.MaintenanceWindow, error) {
	return s.created, s.createErr
}
func (s *stubMaintenance) DeleteMaintenanceWindow(context.Context, uuid.UUID) (bool, error) {
	return s.deleteHit, s.deleteErr
}

func ncMaintenanceEngine(m maintenanceIface) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := newServerWithMaintenance(m)
	r := gin.New()
	grp := r.Group(ncBase)
	grp.Use(func(c *gin.Context) {
		c.Set("userID", ncUser.String())
		c.Next()
	})
	maint := grp.Group("/platform/maintenance-windows")
	maint.GET("", srv.listMaintenanceWindows)
	maint.POST("", srv.createMaintenanceWindow)
	maint.DELETE("/:id", srv.deleteMaintenanceWindow)
	return r
}

func sampleMaintenanceWindow() services.MaintenanceWindow {
	now := time.Now().UTC()
	by := uuid.New()
	return services.MaintenanceWindow{
		ID:        uuid.New(),
		StartsAt:  now,
		EndsAt:    now.Add(2 * time.Hour),
		Reason:    "planned database upgrade",
		CreatedBy: &by,
		CreatedAt: now,
	}
}

// created_by omitted when unset — guards the omitempty pointer path.
func minimalMaintenanceWindow() services.MaintenanceWindow {
	now := time.Now().UTC()
	return services.MaintenanceWindow{
		ID:        uuid.New(),
		StartsAt:  now,
		EndsAt:    now.Add(time.Hour),
		Reason:    "",
		CreatedAt: now,
	}
}

const mwBase = ncBase + "/platform/maintenance-windows"

func TestContract_ListMaintenanceWindows_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncMaintenanceEngine(&stubMaintenance{list: []services.MaintenanceWindow{sampleMaintenanceWindow(), minimalMaintenanceWindow()}})
	w := ncDo(eng, http.MethodGet, mwBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MaintenanceWindowListResponse", w.Body.Bytes())
}

// Empty list serializes as `"windows": []` (the service returns a non-nil empty
// slice) — guards against the null-collection regression.
func TestContract_ListMaintenanceWindows_200_empty(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncMaintenanceEngine(&stubMaintenance{list: []services.MaintenanceWindow{}})
	w := ncDo(eng, http.MethodGet, mwBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MaintenanceWindowListResponse", w.Body.Bytes())
}

func TestContract_ListMaintenanceWindows_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncMaintenanceEngine(&stubMaintenance{listErr: context.DeadlineExceeded})
	w := ncDo(eng, http.MethodGet, mwBase, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateMaintenanceWindow_201(t *testing.T) {
	sv := ncLoadSpec(t)
	m := sampleMaintenanceWindow()
	eng := ncMaintenanceEngine(&stubMaintenance{created: &m})
	body := strings.NewReader(`{"starts_at":"2030-01-01T00:00:00Z","ends_at":"2030-01-01T02:00:00Z","reason":"upgrade"}`)
	w := ncDo(eng, http.MethodPost, mwBase, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MaintenanceWindow", w.Body.Bytes())
}

// Missing required fields → 400 (ShouldBindJSON binding:"required").
func TestContract_CreateMaintenanceWindow_400_missingFields(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncMaintenanceEngine(&stubMaintenance{})
	w := ncDo(eng, http.MethodPost, mwBase, strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Spec-quirk regression: `ends_at` not after `starts_at` → 400 (explicit check).
func TestContract_CreateMaintenanceWindow_400_endBeforeStart(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncMaintenanceEngine(&stubMaintenance{})
	body := strings.NewReader(`{"starts_at":"2030-01-01T02:00:00Z","ends_at":"2030-01-01T00:00:00Z"}`)
	w := ncDo(eng, http.MethodPost, mwBase, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteMaintenanceWindow_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncMaintenanceEngine(&stubMaintenance{deleteHit: true})
	w := ncDo(eng, http.MethodDelete, mwBase+"/"+ncAID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StatusResponse", w.Body.Bytes())
}

func TestContract_DeleteMaintenanceWindow_400_badID(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncMaintenanceEngine(&stubMaintenance{})
	w := ncDo(eng, http.MethodDelete, mwBase+"/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Spec-quirk regression: a delete that matched no row returns 404, not a
// misleading 200.
func TestContract_DeleteMaintenanceWindow_404(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncMaintenanceEngine(&stubMaintenance{deleteHit: false})
	w := ncDo(eng, http.MethodDelete, mwBase+"/"+ncAID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
