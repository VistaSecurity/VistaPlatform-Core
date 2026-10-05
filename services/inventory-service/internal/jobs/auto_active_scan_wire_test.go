package jobs

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// The automatic scan's request as it reaches cluster-sensor-service (
// WP4): the real sweep, the real router-to-executor split and the real
// DiscoveryService client, against an httptest stand-in recording the body.
// Each job is a custom-depth plan on the policy's ports with no protocol
// list, routed exactly as before, and carries options.active_scan — without
// it the results would be ingested as passive observations.
func TestSweepTenant_SendsPlannedJobsOverTheWire(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []map[string]interface{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job":{"id":"` + uuid.NewString() + `","status":"queued"}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", srv.URL)
	ds, err := services.NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}

	edge := liveSensorNamed("edge-sensor")
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1", "10.0.0.2")}
	router := &fakeRouter{plan: sensorrouting.Plan{
		Groups:   []sensorrouting.Group{{Sensor: edge, Targets: []string{"10.0.0.1"}}},
		Platform: []string{"10.0.0.2"},
	}}
	routedJob(store, ds, router).SweepTenant(context.Background(), uuid.New(), false)

	if len(bodies) != 2 {
		t.Fatalf("%d requests, want 2 (one sensor job, one platform job)", len(bodies))
	}
	wantPorts := shareddisc.CustomPortList(store.policy.Ports)
	for _, b := range bodies {
		if b["scan_depth"] != "custom" || b["tcp_ports"] != wantPorts {
			t.Errorf("request %v: want scan_depth custom on %q", b, wantPorts)
		}
		for _, legacy := range []string{"protocols", "ports"} {
			if list, _ := b[legacy].([]interface{}); len(list) != 0 {
				t.Errorf("request still sends %s %v", legacy, b[legacy])
			}
		}
		opts, _ := b["options"].(map[string]interface{})
		if opts["active_scan"] != true || opts["origin"] != "auto_scan" {
			t.Errorf("options %v: want active_scan true and origin auto_scan", opts)
		}
	}
	sensorJob, platformJob := bodies[0], bodies[1]
	if ids, _ := sensorJob["preferred_sensor_ids"].([]interface{}); sensorJob["execution_mode"] != "sensors" || len(ids) != 1 || ids[0] != edge.ID.String() {
		t.Errorf("sensor job routed %v %v, want sensors/[%s]", sensorJob["execution_mode"], sensorJob["preferred_sensor_ids"], edge.ID)
	}
	if platformJob["execution_mode"] != "async" {
		t.Errorf("platform job routed %v, want async", platformJob["execution_mode"])
	}
}
