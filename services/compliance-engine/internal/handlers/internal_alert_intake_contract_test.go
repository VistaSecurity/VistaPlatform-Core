package handlers

// Contract test for the HTTP rail of alerts.raise (POST
// /api/v1/compliance-engine/internal/alerts/raise): the REAL route as
// RegisterInternalAlertIntake mounts it, a stub engine, requests signed the way
// shared/dcim/changenotify's HTTPAlertIntake signs them, and every body checked
// against api/openapi/compliance-engine.openapi.yaml.
//
// Mutations (each turns a test here red): drop RequireSignedServiceCall from
// the group → the unsigned and JWT-only cases answer 202; delete the
// tenant-mismatch check → the cross-tenant case reaches the engine; call
// anything but engine.Raise → the stub records nothing.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const intakeSecret = "contract-test-internal-secret"

type stubRaiser struct {
	got     []events.AlertRaiseEvent
	outcome services.RaiseOutcome
	err     error
}

func (s *stubRaiser) Raise(_ context.Context, ev events.AlertRaiseEvent) (services.RaiseOutcome, error) {
	s.got = append(s.got, ev)
	return s.outcome, s.err
}

func newIntakeEngine(s *stubRaiser) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterInternalAlertIntake(r.Group("/api/v1"), intakeSecret, s)
	return r
}

const intakePath = "/api/v1/compliance-engine/internal/alerts/raise"

func intakeRequest(t *testing.T, ev events.AlertRaiseEvent, tenantHeader string, sign bool) *http.Request {
	t.Helper()
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, intakePath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if tenantHeader != "" {
		req.Header.Set(serviceauth.HeaderTenantID, tenantHeader)
	}
	if sign {
		serviceauth.NewSigner(intakeSecret).SignRequest(req)
	}
	return req
}

func sampleChangeEvent(tenant uuid.UUID) events.AlertRaiseEvent {
	subject := uuid.New()
	return events.AlertRaiseEvent{
		EventID: uuid.New(), TenantID: tenant, AlertType: "object_changed", Source: "inventory-service",
		SubjectType: "cable", SubjectID: &subject, Severity: "info",
		Title: "Cable updated: C-1", Message: "a person updated cable C-1",
		Metadata: map[string]any{"object_kind": "cable", "action": "update"},
	}
}

func serve(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestContract_InternalAlertIntake_202(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubRaiser{outcome: services.RaiseNotified}
	r := newIntakeEngine(stub)
	tenant := uuid.New()
	ev := sampleChangeEvent(tenant)

	w := serve(r, intakeRequest(t, ev, tenant.String(), true))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	sv.assertConforms(t, "AlertIntakeResponse", w.Body.Bytes())
	if len(stub.got) != 1 {
		t.Fatalf("engine raised %d events, want 1", len(stub.got))
	}
	got := stub.got[0]
	if got.EventID != ev.EventID || got.TenantID != tenant || got.AlertType != "object_changed" ||
		got.SubjectID == nil || *got.SubjectID != *ev.SubjectID || got.Metadata["action"] != "update" {
		t.Fatalf("event reached the engine as %+v", got)
	}
}

// An event with no tenant_id is for the signed tenant.
func TestContract_InternalAlertIntake_TenantFromSignedHeader(t *testing.T) {
	stub := &stubRaiser{outcome: services.RaiseNotified}
	tenant := uuid.New()
	ev := sampleChangeEvent(uuid.Nil)
	if w := serve(newIntakeEngine(stub), intakeRequest(t, ev, tenant.String(), true)); w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	if len(stub.got) != 1 || stub.got[0].TenantID != tenant {
		t.Fatalf("engine got %+v", stub.got)
	}
}

func TestContract_InternalAlertIntake_Refusals(t *testing.T) {
	sv := loadSpec(t)
	tenant := uuid.New()
	cases := []struct {
		name string
		req  func() *http.Request
		want int
	}{
		{"unsigned", func() *http.Request { return intakeRequest(t, sampleChangeEvent(tenant), tenant.String(), false) }, http.StatusUnauthorized},
		{"a user token is not a service signature", func() *http.Request {
			req := intakeRequest(t, sampleChangeEvent(tenant), tenant.String(), false)
			req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x")
			return req
		}, http.StatusUnauthorized},
		{"signed for another tenant", func() *http.Request {
			return intakeRequest(t, sampleChangeEvent(uuid.New()), tenant.String(), true)
		}, http.StatusBadRequest},
		{"no tenant header", func() *http.Request { return intakeRequest(t, sampleChangeEvent(tenant), "", true) }, http.StatusBadRequest},
		{"no alert type", func() *http.Request {
			ev := sampleChangeEvent(tenant)
			ev.AlertType = ""
			return intakeRequest(t, ev, tenant.String(), true)
		}, http.StatusBadRequest},
		{"not a severity", func() *http.Request {
			ev := sampleChangeEvent(tenant)
			ev.Severity = "urgent"
			return intakeRequest(t, ev, tenant.String(), true)
		}, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubRaiser{outcome: services.RaiseNotified}
			w := serve(newIntakeEngine(stub), c.req())
			if w.Code != c.want {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, c.want, w.Body)
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
			if len(stub.got) != 0 {
				t.Fatalf("a refused call reached the engine: %+v", stub.got)
			}
		})
	}
}

// An empty secret refuses every call, signed or not — fail closed.
func TestContract_InternalAlertIntake_NoSecretRefusesEverything(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	stub := &stubRaiser{outcome: services.RaiseNotified}
	RegisterInternalAlertIntake(r.Group("/api/v1"), "", stub)
	tenant := uuid.New()
	if w := serve(r, intakeRequest(t, sampleChangeEvent(tenant), tenant.String(), true)); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if len(stub.got) != 0 {
		t.Fatal("reached the engine with no secret configured")
	}
}

// A failed raise is a 500, so the caller knows the event was lost.
func TestContract_InternalAlertIntake_500(t *testing.T) {
	sv := loadSpec(t)
	tenant := uuid.New()
	stub := &stubRaiser{err: errors.New("database down")}
	w := serve(newIntakeEngine(stub), intakeRequest(t, sampleChangeEvent(tenant), tenant.String(), true))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
