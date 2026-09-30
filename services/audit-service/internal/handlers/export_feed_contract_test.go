package handlers

// Contract tests for the internal export feed (ADR-0001): the live handlers'
// bodies conform to ExportFeedPage / ExportFeedHeadResponse, and what leaves
// is the export projection — never a change diff, metadata or user agent.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

type stubFeedService struct {
	page     services.ExportPage
	pageErr  error
	head     services.ExportCursor
	gotAfter services.ExportCursor
	gotLimit int
	gotBack  time.Duration
}

func (s *stubFeedService) ExportPage(_ context.Context, after services.ExportCursor, limit int, _ time.Duration) (services.ExportPage, error) {
	s.gotAfter, s.gotLimit = after, limit
	if s.pageErr != nil {
		return services.ExportPage{}, s.pageErr
	}
	return s.page, nil
}

func (s *stubFeedService) ExportHead(_ context.Context, backfill time.Duration) (services.ExportCursor, error) {
	s.gotBack = backfill
	return s.head, nil
}

func newFeedEngine(svc *stubFeedService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewExportFeedHandlerFor(svc, 0)
	r.GET(base+"/internal/export/events", h.GetEvents)
	r.GET(base+"/internal/export/head", h.GetHead)
	return r
}

func feedItem(e models.ActivityLog) services.ExportItem {
	return services.ExportItem{
		Cursor: services.ExportCursor{CreatedAt: e.CreatedAt, ID: e.ID},
		Event:  services.ExportEvent(&e),
	}
}

func TestContract_ExportFeedEvents_200(t *testing.T) {
	sv := loadSpec(t)
	full, minimal := sampleLog(), minimalLog()
	svc := &stubFeedService{page: services.ExportPage{
		Items:   []services.ExportItem{feedItem(full), feedItem(minimal)},
		Next:    services.ExportCursor{CreatedAt: minimal.CreatedAt, ID: minimal.ID},
		More:    true,
		Horizon: time.Now().UTC(),
	}}
	after := time.Date(2026, 9, 30, 1, 2, 3, 456789000, time.UTC)
	w := do(newFeedEngine(svc), http.MethodGet,
		base+"/internal/export/events?after_created_at="+after.Format(time.RFC3339Nano)+"&after_id="+aUUID+"&limit=2", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ExportFeedPage", w.Body.Bytes())
	if !svc.gotAfter.CreatedAt.Equal(after) || svc.gotAfter.ID.String() != aUUID || svc.gotLimit != 2 {
		t.Errorf("handler read cursor %+v limit %d; want %s/%s limit 2 (microseconds intact)", svc.gotAfter, svc.gotLimit, after, aUUID)
	}
	for _, leak := range []string{"old_values", "new_values", "metadata", "user_agent", "session_id", "changed_fields"} {
		if strings.Contains(w.Body.String(), `"`+leak+`"`) {
			t.Errorf("the feed exported %q: %s", leak, w.Body.String())
		}
	}
}

func TestContract_ExportFeedEvents_DefaultLimit(t *testing.T) {
	svc := &stubFeedService{page: services.ExportPage{Items: []services.ExportItem{}}}
	w := do(newFeedEngine(svc), http.MethodGet,
		base+"/internal/export/events?after_created_at=2026-09-30T00:00:00Z&after_id="+aUUID, nil)
	if w.Code != http.StatusOK || svc.gotLimit != services.ExportPageDefault {
		t.Fatalf("status %d, limit %d; want 200 and the default %d", w.Code, svc.gotLimit, services.ExportPageDefault)
	}
}

func TestContract_ExportFeedEvents_400(t *testing.T) {
	sv := loadSpec(t)
	for _, q := range []string{
		"", // no cursor at all
		"?after_created_at=yesterday&after_id=" + aUUID,
		"?after_created_at=2026-09-30T00:00:00Z&after_id=not-a-uuid",
		"?after_created_at=2026-09-30T00:00:00Z&after_id=" + aUUID + "&limit=ten",
	} {
		w := do(newFeedEngine(&stubFeedService{}), http.MethodGet, base+"/internal/export/events"+q, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET events%s = %d; want 400", q, w.Code)
			continue
		}
		sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	}
	// The service's own range check surfaces as 400, not 500.
	svc := &stubFeedService{pageErr: services.ErrInvalidExportRequest}
	w := do(newFeedEngine(svc), http.MethodGet,
		base+"/internal/export/events?after_created_at=2026-09-30T00:00:00Z&after_id="+aUUID+"&limit=5000", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("an out-of-range limit = %d; want 400", w.Code)
	}
}

func TestContract_ExportFeedEvents_500HidesTheCause(t *testing.T) {
	svc := &stubFeedService{pageErr: errors.New(`pq: relation "audit.activity_logs" secret detail`)}
	w := do(newFeedEngine(svc), http.MethodGet,
		base+"/internal/export/events?after_created_at=2026-09-30T00:00:00Z&after_id="+aUUID, nil)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "secret detail") {
		t.Fatalf("status %d body %s; want 500 without the database error", w.Code, w.Body.String())
	}
}

func TestContract_ExportFeedHead_200(t *testing.T) {
	sv := loadSpec(t)
	svc := &stubFeedService{head: services.ExportCursor{CreatedAt: time.Now().UTC(), ID: uuid.New()}}
	w := do(newFeedEngine(svc), http.MethodGet, base+"/internal/export/head?backfill_seconds=3600", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ExportFeedHeadResponse", w.Body.Bytes())
	if svc.gotBack != time.Hour {
		t.Errorf("backfill passed as %s; want 1h", svc.gotBack)
	}
	var body struct {
		Cursor services.ExportCursor `json:"cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Cursor.ID != svc.head.ID {
		t.Fatalf("head body %s (%v)", w.Body.String(), err)
	}
}

func TestContract_ExportFeedHead_400(t *testing.T) {
	for _, q := range []string{"?backfill_seconds=-1", "?backfill_seconds=604801", "?backfill_seconds=lots"} {
		w := do(newFeedEngine(&stubFeedService{}), http.MethodGet, base+"/internal/export/head"+q, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET head%s = %d; want 400", q, w.Code)
		}
	}
}
