package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// POST /sensors/:sensor_id/exports used to INSERT into air_gapped_exports, a
// table no schema has ever defined, so it failed on every call. The
// feature was never built and was removed. This drives the real router and
// fails if any route ending in /exports is registered again, or if the path
// answers anything but 404.
//
// Mutation check: adding
//
//	agentRoutes.POST(sensors, "/exports", handler.Heartbeat)
//
// to router.go turns this red.
func TestNoAirGappedExportRoute(t *testing.T) {
	router, _, _ := newTestRouter(t)

	for _, r := range router.Routes() {
		if strings.HasSuffix(r.Path, "/exports") {
			t.Errorf("route %s %s is registered; the air-gapped export route was removed (#1508)", r.Method, r.Path)
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor-manager/sensors/"+pathSensorID.String()+"/exports", strings.NewReader("{}"))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST .../sensors/:sensor_id/exports = %d, want 404", rec.Code)
	}
}
