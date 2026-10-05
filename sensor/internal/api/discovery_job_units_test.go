package api

// The sensor's side of a planned scan's report ( WP2b): the platform's
// answer is turned into "go on" or "stop", and anything else is an error the
// run retries — never mistaken for either.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch/planrun"
)

func TestReportDiscoveryJobUnits_MapsTheAnswer(t *testing.T) {
	var status int
	var body string
	var gotPath string
	var got sensordispatch.UnitBatch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := NewOutboundClient(&config.Config{SensorID: "22222222-2222-2222-2222-222222222222", ControlPlaneURL: srv.URL})
	const job = "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42"

	status, body = http.StatusOK, `{"job_status":"awaiting_sensor","accepted":0,"duplicate":0,"stale":0,"unknown":0}`
	if _, err := c.ReportDiscoveryJobUnits(job, sensordispatch.UnitBatch{}); err != nil {
		t.Fatalf("200 = %v", err)
	}
	if gotPath != "/api/v1/sensor-manager/sensors/22222222-2222-2222-2222-222222222222/discovery-jobs/"+job+"/units" || got.Units == nil {
		t.Fatalf("posted %s %+v — a ping must send an empty list, not null", gotPath, got)
	}
	for _, tc := range []struct {
		status int
		body   string
		stop   bool
	}{
		{http.StatusConflict, `{"code":"discovery_job_cancelled","job_status":"cancelled","accepted":0,"duplicate":0,"stale":0,"unknown":0}`, true},
		{http.StatusConflict, `{"code":"discovery_job_ended","job_status":"failed","accepted":0,"duplicate":0,"stale":0,"unknown":0}`, true},
		{http.StatusNotFound, `{"error":"Discovery job not found"}`, true},
		{http.StatusConflict, `{"error":"something else"}`, false},
		{http.StatusInternalServerError, `{"error":"boom"}`, false},
		{http.StatusBadRequest, `{"error":"bad"}`, false},
	} {
		status, body = tc.status, tc.body
		_, err := c.ReportDiscoveryJobUnits(job, sensordispatch.UnitBatch{})
		if err == nil {
			t.Errorf("%d %s = nil error", tc.status, tc.body)
			continue
		}
		if errors.Is(err, planrun.ErrJobStopped) != tc.stop {
			t.Errorf("%d %s = %v, want stop=%v", tc.status, tc.body, err, tc.stop)
		}
	}
}
