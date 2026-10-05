package handlers

// Contract test for a planned scan's per-host reports ( WP2b):
// POST /sensors/{sensor_id}/discovery-jobs/{job_id}/units, driven through the
// REAL gin handler with an in-memory recorder, every body checked against
// api/openapi/sensor-manager.openapi.yaml. A well-formed report reaches the
// service intact; a malformed one is refused before it; a stop answer is a 409
// carrying its code; an unknown job is a 404.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

type stubUnitRecorder struct {
	calls int
	got   sensordispatch.UnitBatch
	resp  sensordispatch.UnitBatchResponse
	err   error
}

func (s *stubUnitRecorder) RecordSensorUnits(_ context.Context, _, _, _ uuid.UUID, b sensordispatch.UnitBatch) (sensordispatch.UnitBatchResponse, error) {
	s.calls++
	s.got = b
	return s.resp, s.err
}

func newUnitsEngine(rec *stubUnitRecorder, known map[uuid.UUID]uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{log: logrus.New(), unitRecorder: rec, sensorTenant: func(_ *gin.Context, id uuid.UUID) (uuid.UUID, bool) {
		t, ok := known[id]
		return t, ok
	}}
	r.POST("/api/v1/sensor-manager/sensors/:sensor_id/discovery-jobs/:job_id/units", h.ReportDiscoveryJobUnits)
	return r
}

func unitsPath(sensor, job string) string {
	return "/api/v1/sensor-manager/sensors/" + sensor + "/discovery-jobs/" + job + "/units"
}

func oneHost() sensordispatch.UnitBatch {
	a := netip.MustParseAddr("10.183.9.1")
	return sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sensordispatch.NewUnitResult(uuid.NewString(), "10.183.9.1", 1, discovery.UnitOutput{
		Host: discovery.HostScan{Addr: a, Liveness: discovery.LivenessUp, LivenessEvidence: "tcp-open:22", PortsRequested: 2, Open: []int{22}, OpenCount: 1, Closed: 1},
		TCP:  []discovery.Observation{{Addr: a, Port: 22, Transport: "tcp", State: "open", Protocol: "SSH", Identified: true}},
	})}}
}

func TestContract_ReportDiscoveryJobUnits(t *testing.T) {
	spec := loadSpec(t)
	sensorID, jobID := uuid.New(), uuid.New()
	known := map[uuid.UUID]uuid.UUID{sensorID: testTenantID}
	body, _ := json.Marshal(oneHost())
	spec.assertConforms(t, "DiscoveryJobUnitBatch", body)

	rec := &stubUnitRecorder{resp: sensordispatch.UnitBatchResponse{JobStatus: sensordispatch.StatusAwaitingSensor, Accepted: 1}}
	w := do(newUnitsEngine(rec, known), http.MethodPost, unitsPath(sensorID.String(), jobID.String()), strings.NewReader(string(body)))
	if w.Code != http.StatusOK || rec.calls != 1 || len(rec.got.Units) != 1 || rec.got.Units[0].Host.OpenCount != 1 {
		t.Fatalf("status %d calls %d got %+v body %s", w.Code, rec.calls, rec.got, w.Body)
	}
	spec.assertConforms(t, "DiscoveryJobUnitBatchResponse", w.Body.Bytes())

	// A ping.
	rec = &stubUnitRecorder{resp: sensordispatch.UnitBatchResponse{JobStatus: sensordispatch.StatusAwaitingSensor}}
	if w := do(newUnitsEngine(rec, known), http.MethodPost, unitsPath(sensorID.String(), jobID.String()), strings.NewReader(`{"units":[]}`)); w.Code != http.StatusOK || rec.calls != 1 {
		t.Fatalf("ping = %d calls %d", w.Code, rec.calls)
	}

	// Stop: 409 with the code.
	rec = &stubUnitRecorder{resp: sensordispatch.UnitBatchResponse{JobStatus: "cancelled", Code: sensordispatch.UnitsCodeJobCancelled}}
	w = do(newUnitsEngine(rec, known), http.MethodPost, unitsPath(sensorID.String(), jobID.String()), strings.NewReader(string(body)))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), sensordispatch.UnitsCodeJobCancelled) {
		t.Fatalf("stop answer = %d %s", w.Code, w.Body)
	}
	spec.assertConforms(t, "DiscoveryJobUnitBatchResponse", w.Body.Bytes())

	// Not this sensor's job.
	rec = &stubUnitRecorder{err: services.ErrJobNotAssignedToSensor}
	if w := do(newUnitsEngine(rec, known), http.MethodPost, unitsPath(sensorID.String(), jobID.String()), strings.NewReader(string(body))); w.Code != http.StatusNotFound {
		t.Fatalf("unassigned = %d", w.Code)
	}
}

func TestContract_ReportDiscoveryJobUnits_RefusesMalformedReportsBeforeTheService(t *testing.T) {
	sensorID, jobID := uuid.New(), uuid.New()
	known := map[uuid.UUID]uuid.UUID{sensorID: testTenantID}
	bad := oneHost()
	bad.Units[0].Host.PortsRequested = 99
	badBody, _ := json.Marshal(bad)
	for name, tc := range map[string]struct{ sensor, job, body string }{
		"counts do not add up": {sensorID.String(), jobID.String(), string(badBody)},
		"not json":             {sensorID.String(), jobID.String(), `nope`},
		"bad target id":        {sensorID.String(), jobID.String(), `{"units":[{"target_id":"x","address":"10.0.0.1","attempt":1,"failed":true}]}`},
		"bad sensor id":        {"xps16", jobID.String(), `{"units":[]}`},
		"bad job id":           {sensorID.String(), "job-1", `{"units":[]}`},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &stubUnitRecorder{}
			w := do(newUnitsEngine(rec, known), http.MethodPost, unitsPath(tc.sensor, tc.job), strings.NewReader(tc.body))
			if w.Code != http.StatusBadRequest || rec.calls != 0 {
				t.Fatalf("status %d calls %d, want 400 before the service", w.Code, rec.calls)
			}
		})
	}
	rec := &stubUnitRecorder{}
	if w := do(newUnitsEngine(rec, map[uuid.UUID]uuid.UUID{}), http.MethodPost, unitsPath(sensorID.String(), jobID.String()), strings.NewReader(`{"units":[]}`)); w.Code != http.StatusNotFound || rec.calls != 0 {
		t.Fatalf("unregistered sensor = %d calls %d", w.Code, rec.calls)
	}
}
