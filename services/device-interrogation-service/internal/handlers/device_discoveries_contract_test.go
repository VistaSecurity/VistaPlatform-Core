package handlers

// Contract + behaviour tests for agent-routed Add device ( slice B),
// driving the real handlers with an in-memory queue. The DB-backed claim path
// is covered by services' TestIntegration_DeviceDiscovery_* and the agent poll
// route by api's TestIntegration_AgentJobsRoute_DeviceDiscoveryCapability.

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

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

type stubDiscoveryQueue struct {
	enqueued   []services.EnqueueDeviceDiscoveryRequest
	enqueueErr error
	list       []services.DeviceDiscovery
	retryErr   error
	dismissErr error
}

func (s *stubDiscoveryQueue) Enqueue(_ context.Context, req services.EnqueueDeviceDiscoveryRequest) (*services.DeviceDiscovery, error) {
	s.enqueued = append(s.enqueued, req)
	if s.enqueueErr != nil {
		return nil, s.enqueueErr
	}
	exp := time.Now().Add(services.DeviceDiscoveryClaimWindow).UTC()
	return &services.DeviceDiscovery{ID: uuid.New(), Status: services.DiscoveryQueued, DeviceType: req.DeviceType,
		ManagementURL: req.ManagementURL, AgentID: req.AgentID, CreatedAt: time.Now().UTC(), ExpiresAt: &exp}, nil
}
func (s *stubDiscoveryQueue) List(context.Context, uuid.UUID) ([]services.DeviceDiscovery, error) {
	return s.list, nil
}
func (s *stubDiscoveryQueue) Retry(_ context.Context, _, id uuid.UUID) (*services.DeviceDiscovery, error) {
	if s.retryErr != nil {
		return nil, s.retryErr
	}
	return &services.DeviceDiscovery{ID: id, Status: services.DiscoveryQueued, DeviceType: "fortinet", ManagementURL: "https://192.0.2.10", AgentID: uuid.New(), CreatedAt: time.Now().UTC()}, nil
}
func (s *stubDiscoveryQueue) Dismiss(context.Context, uuid.UUID, uuid.UUID) error {
	return s.dismissErr
}

func newDiscoveryEngine(q *stubDiscoveryQueue, audits *[]probeAudit) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(base)
	grp.Use(func(c *gin.Context) { c.Set("tenantID", deviceTestTenant); c.Next() })
	h := &DeviceDiscoveryHandlers{queue: q, probes: newProbeLimiter(), audit: func(_ *gin.Context, p probeAudit) {
		if audits != nil {
			*audits = append(*audits, p)
		}
	}}
	grp.POST("/devices/discoveries", h.Create)
	grp.GET("/devices/discoveries", h.List)
	grp.POST("/devices/discoveries/:id/retry", h.Retry)
	grp.DELETE("/devices/discoveries/:id", h.Dismiss)
	return r
}

const discoveryBody = `{"device_type":"fortinet","management_url":"https://192.0.2.10","username":"readonly","password":"device-password-123","agent_id":"6f1c2a52-7d0e-4d0e-9a51-1d1f4f2b0c11"}`

func TestContract_CreateDeviceDiscovery_202(t *testing.T) {
	spec := loadSpec(t)
	q := &stubDiscoveryQueue{}
	var audits []probeAudit
	w := do(newDiscoveryEngine(q, &audits), http.MethodPost, base+"/devices/discoveries", strings.NewReader(discoveryBody))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	spec.assertConforms(t, "DeviceDiscovery", w.Body.Bytes())
	if len(q.enqueued) != 1 || q.enqueued[0].TenantID != deviceTestTenant || q.enqueued[0].AgentID.String() != "6f1c2a52-7d0e-4d0e-9a51-1d1f4f2b0c11" {
		t.Fatalf("enqueued = %+v", q.enqueued)
	}
	if strings.Contains(w.Body.String(), "device-password-123") {
		t.Fatal("the response echoed the password")
	}
	if len(audits) != 1 || audits[0].event != auditEventQueuedProbe || audits[0].outcome != outcomeOK {
		t.Fatalf("audits = %+v", audits)
	}
}

func TestContract_CreateDeviceDiscovery_Refusals(t *testing.T) {
	spec := loadSpec(t)
	for _, c := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"agent unavailable", &services.DeviceDiscoveryRequestError{Code: services.CodeAgentUnavailable, Message: "m"}, http.StatusConflict, services.CodeAgentUnavailable},
		{"agent not found", &services.DeviceDiscoveryRequestError{Code: services.CodeAgentNotFound, Message: "m"}, http.StatusUnprocessableEntity, services.CodeAgentNotFound},
		{"not supported", &services.DeviceDiscoveryRequestError{Code: "not_supported", Message: "m"}, http.StatusUnprocessableEntity, "not_supported"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := do(newDiscoveryEngine(&stubDiscoveryQueue{enqueueErr: c.err}, nil), http.MethodPost, base+"/devices/discoveries", strings.NewReader(discoveryBody))
			if w.Code != c.status {
				t.Fatalf("status = %d, want %d (%s)", w.Code, c.status, w.Body)
			}
			spec.assertConforms(t, "DeviceDiscoveryError", w.Body.Bytes())
			var body map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if body["error"] != c.code {
				t.Fatalf("error = %q, want %q", body["error"], c.code)
			}
		})
	}
	// No agent named: a 400, and nothing is queued.
	q := &stubDiscoveryQueue{}
	w := do(newDiscoveryEngine(q, nil), http.MethodPost, base+"/devices/discoveries",
		strings.NewReader(`{"device_type":"fortinet","management_url":"https://192.0.2.10","username":"u","password":"p"}`))
	if w.Code != http.StatusBadRequest || len(q.enqueued) != 0 {
		t.Fatalf("no agent: status %d, enqueued %d", w.Code, len(q.enqueued))
	}
}

// A queued discovery spends the same per-tenant probe budget as a synchronous
// Add device: it is a device login all the same, just made from an agent.
func TestCreateDeviceDiscovery_SharesTheProbeBudget(t *testing.T) {
	q := &stubDiscoveryQueue{}
	eng := newDiscoveryEngine(q, nil)
	for i := 0; i < probeTenantLimit; i++ {
		if w := do(eng, http.MethodPost, base+"/devices/discoveries", strings.NewReader(discoveryBody)); w.Code != http.StatusAccepted {
			t.Fatalf("probe %d: %d", i, w.Code)
		}
	}
	w := do(eng, http.MethodPost, base+"/devices/discoveries", strings.NewReader(discoveryBody))
	if w.Code != http.StatusTooManyRequests || len(q.enqueued) != probeTenantLimit {
		t.Fatalf("over budget: status %d, enqueued %d", w.Code, len(q.enqueued))
	}
}

func TestContract_ListDeviceDiscoveries_200(t *testing.T) {
	spec := loadSpec(t)
	code, msg := "connection_failed", "The agent couldn't connect."
	name := "branch-agent"
	asset := uuid.New()
	done := time.Now().UTC()
	q := &stubDiscoveryQueue{list: []services.DeviceDiscovery{
		{ID: uuid.New(), Status: services.DiscoveryQueued, DeviceType: "fortinet", ManagementURL: "https://192.0.2.10", AgentID: uuid.New(), CreatedAt: done},
		{ID: uuid.New(), Status: services.DiscoveryFailed, DeviceType: "f5", ManagementURL: "https://192.0.2.11", AgentID: uuid.New(), AgentName: &name, ErrorCode: &code, Message: &msg, CreatedAt: done, CompletedAt: &done},
		{ID: uuid.New(), Status: services.DiscoverySucceeded, DeviceType: "cisco", ManagementURL: "192.0.2.12", AgentID: uuid.New(), AssetID: &asset, CreatedAt: done, CompletedAt: &done},
	}}
	w := do(newDiscoveryEngine(q, nil), http.MethodGet, base+"/devices/discoveries", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	spec.assertConforms(t, "DeviceDiscoveryListResponse", w.Body.Bytes())
}

func TestContract_RetryAndDismissDeviceDiscovery(t *testing.T) {
	spec := loadSpec(t)
	id := uuid.NewString()
	w := do(newDiscoveryEngine(&stubDiscoveryQueue{}, nil), http.MethodPost, base+"/devices/discoveries/"+id+"/retry", nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("retry: %d", w.Code)
	}
	spec.assertConforms(t, "DeviceDiscovery", w.Body.Bytes())

	w = do(newDiscoveryEngine(&stubDiscoveryQueue{retryErr: services.ErrDeviceDiscoveryNotRetryable}, nil), http.MethodPost, base+"/devices/discoveries/"+id+"/retry", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("retry of a running discovery: %d", w.Code)
	}
	spec.assertConforms(t, "DeviceDiscoveryError", w.Body.Bytes())

	w = do(newDiscoveryEngine(&stubDiscoveryQueue{}, nil), http.MethodDelete, base+"/devices/discoveries/"+id, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("dismiss: %d", w.Code)
	}
	spec.assertConforms(t, "MessageResponse", w.Body.Bytes())

	w = do(newDiscoveryEngine(&stubDiscoveryQueue{dismissErr: services.ErrDeviceDiscoveryNotFound}, nil), http.MethodDelete, base+"/devices/discoveries/"+id, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("dismiss unknown: %d", w.Code)
	}
	spec.assertConforms(t, "DeviceDiscoveryError", w.Body.Bytes())

	w = do(newDiscoveryEngine(&stubDiscoveryQueue{dismissErr: errors.New("boom")}, nil), http.MethodDelete, base+"/devices/discoveries/"+id, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("dismiss error: %d", w.Code)
	}
}

// The production constructor shares the device handlers' limiter and audit, so
// Add device has one budget and one audit trail whichever way it goes.
func TestNewDeviceDiscoveryHandlers_SharesLimiterAndAudit(t *testing.T) {
	var sunk []*audithelpers.ActivityLogRequest
	dev := &DeviceHandlers{auditSink: func(_ context.Context, e *audithelpers.ActivityLogRequest) { sunk = append(sunk, e) }}
	h := NewDeviceDiscoveryHandlers(nil, dev)
	if h.probes == nil || h.probes != dev.probes {
		t.Fatal("discovery handlers do not share the device probe limiter")
	}
	h.queue = &stubDiscoveryQueue{}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/d", func(c *gin.Context) { c.Set("tenantID", deviceTestTenant); h.Create(c) })
	w := do(r, http.MethodPost, "/d", strings.NewReader(discoveryBody))
	if w.Code != http.StatusAccepted || len(sunk) != 1 || sunk[0].EventType != auditEventQueuedProbe {
		t.Fatalf("status %d, audits %d", w.Code, len(sunk))
	}
	if blob, _ := json.Marshal(sunk[0]); strings.Contains(string(blob), "device-password-123") {
		t.Fatal("the audit record carries the password")
	}
}

// device_discovery identifies a device that is not on record yet. Queued
// against an existing device it would be an unassigned discovery, which the
// CHECK refuses — a 500 at INSERT. It is refused here instead, and nothing is
// queued.
func TestInterrogateDevice_RefusesDeviceDiscovery(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "interrogate-refusal-test-key")
	store := &stubDeviceStore{device: sampleDevice(), stored: services.StoredDeviceCredentials{Username: "u", EncryptedPassword: "x"}}
	jobs := &recordingJobCreator{}
	eng := newDeviceEngineWithJobs(store, jobs)
	w := do(eng, http.MethodPost, base+"/devices/"+store.device.ID.String()+"/interrogate",
		strings.NewReader(`{"job_type":"device_discovery"}`))
	if w.Code != http.StatusBadRequest || len(jobs.reqs) != 0 {
		t.Fatalf("status %d, jobs %d: %s", w.Code, len(jobs.reqs), w.Body)
	}
}
