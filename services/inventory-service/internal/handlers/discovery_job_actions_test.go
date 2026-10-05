package handlers

// Cancel and Rerun for a discovery job reach cluster-sensor-service.
//
// Until this change both handlers were stubs: Cancel answered 200 and wrote a
// "discovery.job.cancelled" audit event without calling anything, Rerun
// answered 202 and did nothing. The UI's Cancel button therefore never reached
// a running scan, and the audit log claimed cancellations that never happened.
//
// These tests drive the REAL handlers and a REAL audit middleware against an
// httptest cluster-sensor-service that models what the real one answers: 404
// for a job that is not the caller's (a job in another tenant looks exactly
// like a missing one), 409 for a job already ended, 400 for a retry of a job
// that is neither queued nor failed. The audit entry is asserted on the wire.
//
// To mutation-test (each turns a sub-test red):
//   - restore the stub (answer 200 without calling the service)
//   - stop forwarding Authorization (the fake answers 401)
//   - move the audit call above the downstream call
//   - map a downstream 409 to 200, or a retry 400 to 202

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

const actionsToken = "Bearer caller-token"

type sensorJobIDs struct {
	ok, otherTenant, ended, boom, notRerunnable, retryRaced, forbidden string
}

func newSensorJobIDs() sensorJobIDs {
	return sensorJobIDs{
		ok:            uuid.NewString(),
		otherTenant:   uuid.NewString(),
		ended:         uuid.NewString(),
		boom:          uuid.NewString(),
		notRerunnable: uuid.NewString(),
		retryRaced:    uuid.NewString(),
		forbidden:     uuid.NewString(),
	}
}

type recordedCall struct{ method, path, auth string }

type fakeSensor struct {
	mu    sync.Mutex
	calls []recordedCall
}

func (f *fakeSensor) recorded() []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCall(nil), f.calls...)
}

// handler models cluster-sensor-service's cancel and retry routes.
func (f *fakeSensor) handler(ids sensorJobIDs) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, recordedCall{r.Method, r.URL.Path, r.Header.Get("Authorization")})
		f.mu.Unlock()

		reply := func(code int, body string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}
		if r.Header.Get("Authorization") != actionsToken {
			reply(http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		const prefix = "/api/v1/discovery/jobs/"
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		id, action, _ := strings.Cut(rest, "/")
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, prefix) {
			reply(http.StatusNotFound, `{"error":"not found"}`)
			return
		}

		switch id {
		case ids.otherTenant:
			reply(http.StatusNotFound, `{"error":"job not found"}`)
		case ids.boom:
			reply(http.StatusInternalServerError, `{"error":"pq: connection to 10.0.0.5 refused"}`)
		case ids.forbidden:
			reply(http.StatusForbidden, `{"error":"permission denied"}`)
		case ids.ended:
			if action == "cancel" {
				reply(http.StatusConflict, `{"error":"job already completed"}`)
				return
			}
			reply(http.StatusBadRequest, `{"error":"job can only be retried if status is queued or failed"}`)
		case ids.notRerunnable:
			reply(http.StatusBadRequest, `{"error":"job can only be retried if status is queued or failed"}`)
		case ids.retryRaced:
			reply(http.StatusConflict, `{"error":"job can only be retried if status is queued or failed"}`)
		case ids.ok:
			if action == "cancel" {
				reply(http.StatusOK, `{"message":"job cancelled"}`)
				return
			}
			reply(http.StatusOK, `{"message":"job republished for processing","job_id":"`+id+`"}`)
		default:
			reply(http.StatusNotFound, `{"error":"job not found"}`)
		}
	}
}

type actionsHarness struct {
	engine  *gin.Engine
	sensor  *fakeSensor
	srv     *httptest.Server
	entries <-chan auditedEntry
	ids     sensorJobIDs
}

func newActionsHarness(t *testing.T) *actionsHarness {
	t.Helper()
	ids := newSensorJobIDs()
	sensor := &fakeSensor{}
	srv := httptest.NewServer(sensor.handler(ids))
	t.Cleanup(srv.Close)
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", srv.URL)
	svc, err := services.NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatalf("NewDiscoveryService: %v", err)
	}

	spy, entries := newAuditSpy(t)
	gin.SetMode(gin.TestMode)
	h := NewDiscoveryHandler(nil, svc)
	engine := gin.New()
	engine.Use(spy, func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	engine.POST("/discovery/jobs/:id/cancel", h.CancelJob)
	engine.POST("/discovery/jobs/:id/rerun", h.RerunJob)
	return &actionsHarness{engine: engine, sensor: sensor, srv: srv, entries: entries, ids: ids}
}

func (h *actionsHarness) do(action, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/discovery/jobs/"+id+"/"+action, nil)
	req.Header.Set("Authorization", actionsToken)
	w := httptest.NewRecorder()
	h.engine.ServeHTTP(w, req)
	return w
}

// assertNoAuditFor proves nothing was audited for `id`. A negative cannot be
// observed directly, so a request that DOES audit (a successful call on the
// known-good job) is sent after it: audit entries arrive in order, so once
// the marker's entry is seen, an entry for `id` would already have been.
// A guard that never saw the marker would pass for the wrong reason, so
// failing to see it fails the test.
func (h *actionsHarness) assertNoAuditFor(t *testing.T, action, id string) {
	t.Helper()
	if w := h.do(action, h.ids.ok); w.Code >= 300 {
		t.Fatalf("marker %s on the good job answered %d: %s", action, w.Code, w.Body.String())
	}
	deadline := time.After(10 * time.Second)
	sawMarker := false
	for !sawMarker {
		select {
		case e := <-h.entries:
			if e.ResourceID == id {
				t.Fatalf("an audit entry %q was written for job %s although the action did not succeed", e.EventType, id)
			}
			sawMarker = e.ResourceID == h.ids.ok
		case <-deadline:
			t.Fatal("the marker audit entry never arrived, so the absence check proved nothing")
		}
	}
	// Anything still in flight after the marker.
	for {
		select {
		case e := <-h.entries:
			if e.ResourceID == id {
				t.Fatalf("an audit entry %q was written for job %s although the action did not succeed", e.EventType, id)
			}
		case <-time.After(300 * time.Millisecond):
			return
		}
	}
}

func TestCancelJob_ReachesClusterSensorAndAuditsOnlyAfterItConfirms(t *testing.T) {
	h := newActionsHarness(t)

	w := h.do("cancel", h.ids.ok)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"Job cancelled"`) {
		t.Fatalf("status = %d body = %s, want 200 Job cancelled", w.Code, w.Body.String())
	}

	calls := h.sensor.recorded()
	if len(calls) != 1 {
		t.Fatalf("cluster-sensor saw %d calls, want exactly 1: %+v", len(calls), calls)
	}
	want := recordedCall{http.MethodPost, "/api/v1/discovery/jobs/" + h.ids.ok + "/cancel", actionsToken}
	if calls[0] != want {
		t.Errorf("downstream call = %+v, want %+v (the caller's Authorization must be forwarded)", calls[0], want)
	}

	e := awaitEntry(t, h.entries, "discovery.job.cancelled")
	if e.ResourceID != h.ids.ok || e.ResourceType != "discovery_job" || e.Action != "cancel" {
		t.Errorf("audit entry = %+v, want a cancel of discovery_job %s", e, h.ids.ok)
	}
}

func TestCancelJob_RefusalsAreNeverA200AndNeverAudited(t *testing.T) {
	cases := []struct {
		name       string
		pick       func(sensorJobIDs) string
		wantStatus int
		wantError  string
		wantDetail string
		forbidden  string // must not leak into the body
	}{
		{"another tenant's job looks missing", func(i sensorJobIDs) string { return i.otherTenant }, 404, "job not found", "", ""},
		{"an unknown job", func(sensorJobIDs) string { return uuid.NewString() }, 404, "job not found", "", ""},
		{"an already ended job", func(i sensorJobIDs) string { return i.ended }, 409, "job_not_cancellable", "job already completed", ""},
		{"the downstream permission gate", func(i sensorJobIDs) string { return i.forbidden }, 403, "forbidden", "permission denied", ""},
		{"a downstream failure", func(i sensorJobIDs) string { return i.boom }, 502, "failed to cancel discovery job", "", "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newActionsHarness(t)
			id := tc.pick(h.ids)

			w := h.do("cancel", id)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d. body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, tc.wantError) {
				t.Errorf("body = %s, want it to carry %q", body, tc.wantError)
			}
			if tc.wantDetail != "" && !strings.Contains(body, tc.wantDetail) {
				t.Errorf("body = %s, want the downstream reason %q", body, tc.wantDetail)
			}
			if tc.forbidden != "" && strings.Contains(body, tc.forbidden) {
				t.Errorf("body = %s leaks downstream detail %q", body, tc.forbidden)
			}
			if strings.Contains(body, "Job cancelled") {
				t.Errorf("a refused cancel reported success: %s", body)
			}
			h.assertNoAuditFor(t, "cancel", id)
		})
	}
}

func TestCancelJob_UnreachableClusterSensorIsNotASuccess(t *testing.T) {
	h := newActionsHarness(t)
	h.srv.Close()
	id := h.ids.ok

	w := h.do("cancel", id)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502. body=%s", w.Code, w.Body.String())
	}
	// h.srv is closed, so the marker cannot be sent through it; the entry
	// channel is simply watched for the grace period.
	select {
	case e := <-h.entries:
		t.Fatalf("an audit entry %q was written although cluster-sensor was unreachable", e.EventType)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestCancelJob_RejectsANonUUIDIdWithoutCallingDownstream(t *testing.T) {
	h := newActionsHarness(t)
	for _, id := range []string{"not-a-uuid", "1"} {
		if w := h.do("cancel", id); w.Code != http.StatusBadRequest {
			t.Errorf("id %q: status = %d, want 400", id, w.Code)
		}
	}
	if calls := h.sensor.recorded(); len(calls) != 0 {
		t.Errorf("a malformed id reached cluster-sensor: %+v", calls)
	}
}

func TestCancelJob_FallsBackToTheSessionCookie(t *testing.T) {
	h := newActionsHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/discovery/jobs/"+h.ids.ok+"/cancel", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "caller-token"})
	w := httptest.NewRecorder()
	h.engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("cookie-authenticated cancel answered %d: %s", w.Code, w.Body.String())
	}
}

func TestRerunJob_ReachesClusterSensorRetryAndAuditsOnlyAfterItConfirms(t *testing.T) {
	h := newActionsHarness(t)

	w := h.do("rerun", h.ids.ok)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"Job rerun initiated"`) {
		t.Fatalf("status = %d body = %s, want 202 Job rerun initiated", w.Code, w.Body.String())
	}

	calls := h.sensor.recorded()
	if len(calls) != 1 {
		t.Fatalf("cluster-sensor saw %d calls, want exactly 1: %+v", len(calls), calls)
	}
	want := recordedCall{http.MethodPost, "/api/v1/discovery/jobs/" + h.ids.ok + "/retry", actionsToken}
	if calls[0] != want {
		t.Errorf("downstream call = %+v, want %+v", calls[0], want)
	}

	e := awaitEntry(t, h.entries, "discovery.job.rerun")
	if e.ResourceID != h.ids.ok || e.Action != "rerun" {
		t.Errorf("audit entry = %+v, want a rerun of discovery_job %s", e, h.ids.ok)
	}
}

func TestRerunJob_RefusalsAreNeverA202AndNeverAudited(t *testing.T) {
	cases := []struct {
		name       string
		pick       func(sensorJobIDs) string
		wantStatus int
		wantError  string
		wantDetail string
		forbidden  string
	}{
		{"another tenant's job looks missing", func(i sensorJobIDs) string { return i.otherTenant }, 404, "job not found", "", ""},
		{"a job that is neither queued nor failed", func(i sensorJobIDs) string { return i.notRerunnable }, 409, "job_not_rerunnable", "queued or failed", ""},
		{"a finished job", func(i sensorJobIDs) string { return i.ended }, 409, "job_not_rerunnable", "queued or failed", ""},
		{"a retry that lost a race", func(i sensorJobIDs) string { return i.retryRaced }, 409, "job_not_rerunnable", "queued or failed", ""},
		{"the downstream permission gate", func(i sensorJobIDs) string { return i.forbidden }, 403, "forbidden", "permission denied", ""},
		{"a downstream failure", func(i sensorJobIDs) string { return i.boom }, 502, "failed to rerun discovery job", "", "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newActionsHarness(t)
			id := tc.pick(h.ids)

			w := h.do("rerun", id)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d. body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, tc.wantError) {
				t.Errorf("body = %s, want it to carry %q", body, tc.wantError)
			}
			if tc.wantDetail != "" && !strings.Contains(body, tc.wantDetail) {
				t.Errorf("body = %s, want the downstream reason %q", body, tc.wantDetail)
			}
			if tc.forbidden != "" && strings.Contains(body, tc.forbidden) {
				t.Errorf("body = %s leaks downstream detail %q", body, tc.forbidden)
			}
			if strings.Contains(body, "rerun initiated") {
				t.Errorf("a refused rerun reported success: %s", body)
			}
			h.assertNoAuditFor(t, "rerun", id)
		})
	}
}

func TestRerunJob_RejectsANonUUIDIdWithoutCallingDownstream(t *testing.T) {
	h := newActionsHarness(t)
	if w := h.do("rerun", "not-a-uuid"); w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if calls := h.sensor.recorded(); len(calls) != 0 {
		t.Errorf("a malformed id reached cluster-sensor: %+v", calls)
	}
}
