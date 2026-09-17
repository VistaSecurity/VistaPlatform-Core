package handlers

// Contract test for the dispatched-job completion callback:
// POST /sensors/{sensor_id}/discovery-jobs/{job_id}/complete, driven through
// the REAL gin route with an in-memory completer, every body checked against
// api/openapi/sensor-manager.openapi.yaml.
//
// Both polarities on the input: a well-formed completion reaches the service
// with exactly the fields the sensor sent, and a malformed one (unknown status,
// negative counts, bad ids) is refused BEFORE the service is consulted.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

type stubJobCompleter struct {
	calls  int
	tenant uuid.UUID
	sensor uuid.UUID
	job    uuid.UUID
	got    sensordispatch.Completion
	err    error
}

func (s *stubJobCompleter) CompleteSensorJob(_ context.Context, tenantID, sensorID, jobID uuid.UUID, c sensordispatch.Completion) error {
	s.calls++
	s.tenant, s.sensor, s.job, s.got = tenantID, sensorID, jobID, c
	return s.err
}

// newCompletionEngine mounts only the completion route, on the sensor group's
// path, with a tenant resolver standing in for TenantForSensor.
func newCompletionEngine(completer *stubJobCompleter, known map[uuid.UUID]uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{
		log:          logrus.New(),
		jobCompleter: completer,
		sensorTenant: func(_ *gin.Context, sensorID uuid.UUID) (uuid.UUID, bool) {
			t, ok := known[sensorID]
			return t, ok
		},
	}
	r.POST("/api/v1/sensor-manager/sensors/:sensor_id/discovery-jobs/:job_id/complete", h.CompleteDiscoveryJob)
	return r
}

func completionPath(sensor, job string) string {
	return "/api/v1/sensor-manager/sensors/" + sensor + "/discovery-jobs/" + job + "/complete"
}

func TestContract_CompleteDispatchedJob_RecordsTheSensorsReport(t *testing.T) {
	spec := loadSpec(t)
	sensorID, jobID := uuid.New(), uuid.New()
	completer := &stubJobCompleter{}
	eng := newCompletionEngine(completer, map[uuid.UUID]uuid.UUID{sensorID: testTenantID})

	body := `{"status":"completed","total_targets":3,"successful_targets":2,"failed_targets":1,"discoveries_submitted":5}`
	w := do(eng, http.MethodPost, completionPath(sensorID.String(), jobID.String()), strings.NewReader(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	spec.assertConforms(t, "DiscoveryJobCompletionResponse", w.Body.Bytes())

	if completer.calls != 1 {
		t.Fatalf("completer called %d times, want 1", completer.calls)
	}
	if completer.tenant != testTenantID || completer.sensor != sensorID || completer.job != jobID {
		t.Errorf("completer got tenant/sensor/job %s/%s/%s", completer.tenant, completer.sensor, completer.job)
	}
	want := sensordispatch.Completion{Status: "completed", TotalTargets: 3, SuccessfulTargets: 2, FailedTargets: 1, DiscoveriesSubmitted: 5}
	if completer.got != want {
		t.Errorf("completer got %+v, want %+v", completer.got, want)
	}
}

func TestContract_CompleteDispatchedJob_ZeroDiscoveriesIsALegitimateCompletion(t *testing.T) {
	sensorID := uuid.New()
	completer := &stubJobCompleter{}
	eng := newCompletionEngine(completer, map[uuid.UUID]uuid.UUID{sensorID: testTenantID})
	w := do(eng, http.MethodPost, completionPath(sensorID.String(), uuid.New().String()), strings.NewReader(`{"status":"completed"}`))
	if w.Code != http.StatusOK || completer.calls != 1 {
		t.Fatalf("status = %d calls = %d, body %s", w.Code, completer.calls, w.Body.String())
	}
}

func TestContract_CompleteDispatchedJob_RefusesMalformedReportsBeforeTheService(t *testing.T) {
	spec := loadSpec(t)
	sensorID, jobID := uuid.New(), uuid.New()

	cases := []struct {
		name   string
		sensor string
		job    string
		body   string
	}{
		{"unknown status", sensorID.String(), jobID.String(), `{"status":"partial"}`},
		{"missing status", sensorID.String(), jobID.String(), `{"total_targets":1}`},
		{"negative count", sensorID.String(), jobID.String(), `{"status":"completed","failed_targets":-1}`},
		{"not json", sensorID.String(), jobID.String(), `nope`},
		{"bad sensor id", "xps16", jobID.String(), `{"status":"completed"}`},
		{"bad job id", sensorID.String(), "job-1", `{"status":"completed"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			completer := &stubJobCompleter{}
			eng := newCompletionEngine(completer, map[uuid.UUID]uuid.UUID{sensorID: testTenantID})
			w := do(eng, http.MethodPost, completionPath(tc.sensor, tc.job), strings.NewReader(tc.body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", w.Code, w.Body.String())
			}
			spec.assertConforms(t, "LegacyError", w.Body.Bytes())
			if completer.calls != 0 {
				t.Errorf("a refused report reached the service (%d call(s))", completer.calls)
			}
		})
	}
}

func TestContract_CompleteDispatchedJob_UnknownSensorIs404(t *testing.T) {
	spec := loadSpec(t)
	completer := &stubJobCompleter{}
	eng := newCompletionEngine(completer, map[uuid.UUID]uuid.UUID{})
	w := do(eng, http.MethodPost, completionPath(uuid.New().String(), uuid.New().String()), strings.NewReader(`{"status":"completed"}`))
	if w.Code != http.StatusNotFound || completer.calls != 0 {
		t.Fatalf("status = %d calls = %d, want 404 and no service call; body %s", w.Code, completer.calls, w.Body.String())
	}
	spec.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CompleteDispatchedJob_ServiceVerdicts(t *testing.T) {
	spec := loadSpec(t)
	sensorID := uuid.New()
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"not this sensor's job", services.ErrJobNotAssignedToSensor, http.StatusNotFound},
		{"job already failed as sensor offline", services.ErrJobNotAwaitingSensor, http.StatusConflict},
		{"database down", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			completer := &stubJobCompleter{err: tc.err}
			eng := newCompletionEngine(completer, map[uuid.UUID]uuid.UUID{sensorID: testTenantID})
			w := do(eng, http.MethodPost, completionPath(sensorID.String(), uuid.New().String()), strings.NewReader(`{"status":"failed","error_message":"targets unreachable"}`))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.want, w.Body.String())
			}
			spec.assertConforms(t, "LegacyError", w.Body.Bytes())
		})
	}
}

func TestContract_CompleteDispatchedJob_NoServiceIs503(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{log: logrus.New()}
	r.POST("/api/v1/sensor-manager/sensors/:sensor_id/discovery-jobs/:job_id/complete", h.CompleteDiscoveryJob)
	w := do(r, http.MethodPost, completionPath(uuid.New().String(), uuid.New().String()), strings.NewReader(`{"status":"completed"}`))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}
