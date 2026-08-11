package api

// Contract test for the tenant notification history + in-app reads.
//
// Extends the notification-service spec-first contract (ADR-0001) and reuses the
// shared harness (ncLoadSpec / assertConforms / ncDo / ncBase / ncTenant) from
// notifications_contract_test.go — only the read-store stub + engine + cases
// live here.
//
// These two handlers used to run a query then discard the rows (history never
// scanned; in-app returned a hardcoded empty array). This slice fixed that — the
// SQL moved into notificationReadStore with real scanning — so the contract test
// drives the real handlers over an in-memory stub returning actual rows.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

var errReadFail = errors.New("read failed")

// --- in-memory stub notificationReadStore ----------------------------------

type stubNotifReadStore struct {
	history       []models.NotificationHistory
	historyErr    error
	platformHist  []models.NotificationHistory
	platformErr   error
	inapp         []models.InAppNotification
	inappErr      error
	platformInapp []models.PlatformInAppNotification
	markedRead    []uuid.UUID
	markedAll     bool
	markErr       error
}

func (s *stubNotifReadStore) ListHistory(context.Context, uuid.UUID, int) ([]models.NotificationHistory, error) {
	return s.history, s.historyErr
}
func (s *stubNotifReadStore) ListPlatformHistory(context.Context, int) ([]models.NotificationHistory, error) {
	return s.platformHist, s.platformErr
}
func (s *stubNotifReadStore) ListInAppNotifications(context.Context, uuid.UUID) ([]models.InAppNotification, error) {
	return s.inapp, s.inappErr
}
func (s *stubNotifReadStore) MarkInAppRead(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	if s.markErr != nil {
		return s.markErr
	}
	s.markedRead = append(s.markedRead, id)
	return nil
}
func (s *stubNotifReadStore) MarkAllInAppRead(context.Context, uuid.UUID) error {
	if s.markErr != nil {
		return s.markErr
	}
	s.markedAll = true
	return nil
}
func (s *stubNotifReadStore) ListPlatformInAppNotifications(context.Context) ([]models.PlatformInAppNotification, error) {
	return s.platformInapp, s.inappErr
}
func (s *stubNotifReadStore) MarkPlatformInAppRead(_ context.Context, id uuid.UUID) error {
	if s.markErr != nil {
		return s.markErr
	}
	s.markedRead = append(s.markedRead, id)
	return nil
}
func (s *stubNotifReadStore) MarkAllPlatformInAppRead(context.Context) error {
	if s.markErr != nil {
		return s.markErr
	}
	s.markedAll = true
	return nil
}

func ncReadEngine(store notificationReadStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := newServerWithReadStore(store)
	r := gin.New()
	grp := r.Group(ncBase)
	grp.Use(func(c *gin.Context) {
		// String, matching production's StringifyUserID() rewrite.
		c.Set("tenantID", ncTenant.String())
		c.Next()
	})
	grp.GET("/tenant/history", srv.getTenantHistory)
	grp.GET("/tenant/notifications", srv.getTenantInAppNotifications)
	return r
}

// ncPlatformReadEngine registers the platform history route. It needs no tenant
// middleware — getPlatformHistory reads platform-wide rows (tenant_id IS NULL)
// and never touches the tenant context.
func ncPlatformReadEngine(store notificationReadStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := newServerWithReadStore(store)
	r := gin.New()
	grp := r.Group(ncBase)
	grp.GET("/platform/history", srv.getPlatformHistory)
	return r
}

func sampleHistory() models.NotificationHistory {
	tid := ncTenant
	return models.NotificationHistory{
		ID:               uuid.New(),
		TenantID:         &tid,
		NotificationType: "alert",
		AlertSource:      "certificates",
		AlertType:        "certificate.expiring",
		Severity:         "high",
		Message:          "Certificate expiring in 7 days",
		ChannelsUsed:     []string{"ops-email", "slack"},
		Status:           "sent",
		Metadata:         map[string]interface{}{"cert_id": "abc"},
		CreatedAt:        time.Now().UTC(),
	}
}

// minimalHistory leaves metadata nil (→ null) to exercise the nullable shape.
func minimalHistory() models.NotificationHistory {
	return models.NotificationHistory{
		ID:               uuid.New(),
		NotificationType: "system",
		AlertSource:      "platform",
		AlertType:        "maintenance",
		Severity:         "info",
		Message:          "Scheduled maintenance",
		ChannelsUsed:     []string{},
		Status:           "sent",
		CreatedAt:        time.Now().UTC(),
	}
}

func sampleInApp() models.InAppNotification {
	now := time.Now().UTC()
	jid := uuid.New()
	fid := uuid.New()
	return models.InAppNotification{
		ID:        uuid.New(),
		TenantID:  ncTenant,
		Type:      "discovery",
		Title:     "Discovery complete",
		Message:   "Found 12 new assets",
		JobID:     &jid,
		FindingID: &fid,
		ReadAt:    &now,
		CreatedAt: now,
	}
}

// minimalInApp leaves the omitempty pointers unset.
func minimalInApp() models.InAppNotification {
	return models.InAppNotification{
		ID:        uuid.New(),
		TenantID:  ncTenant,
		Type:      "system",
		Title:     "Welcome",
		Message:   "Thanks for joining",
		CreatedAt: time.Now().UTC(),
	}
}

// --- history ----------------------------------------------------------------

func TestContract_GetTenantHistory_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncReadEngine(&stubNotifReadStore{history: []models.NotificationHistory{sampleHistory(), minimalHistory()}})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantHistoryListResponse", w.Body.Bytes())
}

func TestContract_GetTenantHistory_200_empty(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncReadEngine(&stubNotifReadStore{history: []models.NotificationHistory{}})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantHistoryListResponse", w.Body.Bytes())
}

func TestContract_GetTenantHistory_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncReadEngine(&stubNotifReadStore{historyErr: errReadFail})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/history", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- platform history -------------------------------------------------------

// samplePlatformHistory is a platform-wide row (tenant_id IS NULL → TenantID nil).
func samplePlatformHistory() models.NotificationHistory {
	return models.NotificationHistory{
		ID:               uuid.New(),
		NotificationType: "system",
		AlertSource:      "platform",
		AlertType:        "broadcast",
		Severity:         "info",
		Message:          "Platform-wide maintenance scheduled",
		ChannelsUsed:     []string{"ops-email"},
		Status:           "sent",
		Metadata:         map[string]interface{}{"window": "2026-06-10"},
		CreatedAt:        time.Now().UTC(),
	}
}

func TestContract_GetPlatformHistory_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformReadEngine(&stubNotifReadStore{platformHist: []models.NotificationHistory{samplePlatformHistory(), minimalHistory()}})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformHistoryListResponse", w.Body.Bytes())
}

func TestContract_GetPlatformHistory_200_empty(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformReadEngine(&stubNotifReadStore{platformHist: []models.NotificationHistory{}})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformHistoryListResponse", w.Body.Bytes())
}

func TestContract_GetPlatformHistory_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformReadEngine(&stubNotifReadStore{platformErr: errReadFail})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/history", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- in-app -----------------------------------------------------------------

func TestContract_GetTenantInAppNotifications_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncReadEngine(&stubNotifReadStore{inapp: []models.InAppNotification{sampleInApp(), minimalInApp()}})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/notifications", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InAppNotificationListResponse", w.Body.Bytes())
}

func TestContract_GetTenantInAppNotifications_200_empty(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncReadEngine(&stubNotifReadStore{inapp: []models.InAppNotification{}})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/notifications", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InAppNotificationListResponse", w.Body.Bytes())
}

func TestContract_GetTenantInAppNotifications_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncReadEngine(&stubNotifReadStore{inappErr: errReadFail})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/notifications", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- drift guards -----------------------------------------------------------

func TestContract_NotificationHistory_DriftIsCaught(t *testing.T) {
	sv := ncLoadSpec(t)
	sch, err := sv.compiler.Compile(ncSpecBaseURI + "#/components/schemas/NotificationHistory")
	if err != nil {
		t.Fatalf("compile NotificationHistory: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"` + ncAID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted NotificationHistory, but it passed — the guardrail is not actually checking")
	}
}

func TestContract_InAppNotification_DriftIsCaught(t *testing.T) {
	sv := ncLoadSpec(t)
	sch, err := sv.compiler.Compile(ncSpecBaseURI + "#/components/schemas/InAppNotification")
	if err != nil {
		t.Fatalf("compile InAppNotification: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"` + ncAID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted InAppNotification, but it passed — the guardrail is not actually checking")
	}
}
