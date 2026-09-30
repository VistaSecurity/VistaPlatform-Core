package handlers

// The HTTP ingestion path rings the stored-events doorbell once per STORED
// entry through services.RingStored, and never for an entry it failed to store.
// The NATS path's half of the same contract is in
// subscribers/doorbell_test.go.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
)

type countingDoorbell struct{ rings atomic.Int32 }

func (d *countingDoorbell) Ring() { d.rings.Add(1) }

// persistingStub assigns the id the way ActivityLogService.LogActivity does,
// or fails.
type persistingStub struct {
	stubActivityLogService
	err error
}

func (p *persistingStub) LogActivity(_ context.Context, e *models.ActivityLog) error {
	if p.err != nil {
		return p.err
	}
	e.ID = uuid.New()
	return nil
}

func ingest(t *testing.T, svc activityLogService, d StoredDoorbell, body string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &ActivityLogHandler{service: svc, doorbell: d}
	r.POST("/activity-logs", h.LogActivity)
	return do(r, http.MethodPost, "/activity-logs", strings.NewReader(body)).Code
}

const ingestBody = `{"event_type":"user.login_failed","event_category":"authentication","action":"login_failed",
	"user_type":"tenant","user_email":"someone@example.test","ip_address":"203.0.113.7","success":false}`

func TestHTTPIngestion_RingsTheDoorbellForAStoredEntry(t *testing.T) {
	d := &countingDoorbell{}
	if code := ingest(t, &persistingStub{}, d, ingestBody); code != http.StatusCreated {
		t.Fatalf("status %d", code)
	}
	if n := d.rings.Load(); n != 1 {
		t.Fatalf("rang %d times for one stored entry; want 1", n)
	}
}

func TestHTTPIngestion_DoesNotRingForWhatItFailedToStore(t *testing.T) {
	d := &countingDoorbell{}
	if code := ingest(t, &persistingStub{err: errors.New("db down")}, d, ingestBody); code != http.StatusInternalServerError {
		t.Fatalf("status %d", code)
	}
	if n := d.rings.Load(); n != 0 {
		t.Errorf("rang %d times for an entry that was not stored", n)
	}
}

func TestHTTPIngestion_NilDoorbellStillLogs(t *testing.T) {
	if code := ingest(t, &persistingStub{}, nil, ingestBody); code != http.StatusCreated {
		t.Fatalf("status %d", code)
	}
}
