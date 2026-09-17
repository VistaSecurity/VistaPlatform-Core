package services

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// Tenant-sensor dispatch. execution_mode "sensors" asks for a scan to
// run on a tenant-deployed sensor. Before the dispatcher existed such jobs fell
// through to the in-cluster nmap path — running from the platform cluster,
// reaching nothing on a target only the sensor can see, and finishing
// `completed` with zero findings. Two guards survive from that era and both
// are pinned here: creation refuses a job that cannot run (unknown, offline,
// system or air-gapped sensor), and the in-cluster path refuses to run a
// `sensors` row that somehow reaches it.

func fixedNow() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) }

func liveSensor(id uuid.UUID, name string) dispatchSensor {
	beat := fixedNow().Add(-30 * time.Second)
	return dispatchSensor{ID: id, Name: name, Status: "active", LastHeartbeat: &beat, ReportingInterval: 30}
}

func TestDecideSensorDispatch(t *testing.T) {
	tenantSensorID := uuid.MustParse("5f7d1b34-6c0a-4c1e-9c8f-2b1d3e4f5a6b")
	platformSensorID := uuid.MustParse("0a1b2c3d-4e5f-4a6b-8c7d-9e8f7a6b5c4d")
	offlineSensorID := uuid.MustParse("6b7c8d9e-0f1a-4b2c-9d3e-4f5a6b7c8d9e")
	airGappedID := uuid.MustParse("7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f")
	staleBeat := fixedNow().Add(-time.Hour)

	sensors := map[uuid.UUID]dispatchSensor{
		tenantSensorID: liveSensor(tenantSensorID, "xps16-sensor"),
		platformSensorID: func() dispatchSensor {
			s := liveSensor(platformSensorID, "Platform Discovery Sensor")
			s.Tags = []string{"system"}
			s.Platform = "platform"
			return s
		}(),
		offlineSensorID: {ID: offlineSensorID, Name: "branch-sensor", Status: "active", LastHeartbeat: &staleBeat, ReportingInterval: 30},
		airGappedID: func() dispatchSensor {
			s := liveSensor(airGappedID, "vault-sensor")
			s.AirGapped = true
			return s
		}(),
	}
	lookup := func(id uuid.UUID) (dispatchSensor, bool) {
		s, ok := sensors[id]
		return s, ok
	}

	cases := []struct {
		name      string
		mode      string
		sensorIDs []string
		wantErr   error // nil = accepted
		wantName  string
	}{
		{"sensors, live tenant sensor", "sensors", []string{tenantSensorID.String()}, nil, "xps16-sensor"},
		{"SENSORS uppercase, padded", "  SENSORS ", []string{tenantSensorID.String()}, nil, "xps16-sensor"},
		{"sensors, unknown sensor", "sensors", []string{uuid.New().String()}, ErrSensorNotFound, ""},
		{"sensors, offline sensor", "sensors", []string{offlineSensorID.String()}, ErrSensorOffline, ""},
		{"sensors, the platform's own sensor", "sensors", []string{platformSensorID.String()}, ErrSensorDispatchInvalid, ""},
		{"sensors, air-gapped sensor", "sensors", []string{airGappedID.String()}, ErrSensorDispatchInvalid, ""},
		{"sensors, no sensor named", "sensors", nil, ErrSensorDispatchInvalid, ""},
		{"sensors, two sensors named", "sensors", []string{tenantSensorID.String(), offlineSensorID.String()}, ErrSensorDispatchInvalid, ""},
		{"sensors, id not a uuid", "sensors", []string{"xps16"}, ErrSensorDispatchInvalid, ""},
		{"preferred sensor ids on a mode that does not dispatch", "auto", []string{tenantSensorID.String()}, ErrSensorDispatchInvalid, ""},
		{"preferred sensor ids with no mode", "", []string{tenantSensorID.String()}, ErrSensorDispatchInvalid, ""},
		{"auto", "auto", nil, nil, ""},
		{"cloud", "cloud", nil, nil, ""},
		{"async (internal re-validation)", "async", nil, nil, ""},
		{"empty", "", nil, nil, ""},
		{"empty sensor id slice is not a request", "auto", []string{}, nil, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decideSensorDispatch(tc.mode, tc.sensorIDs, lookup, fixedNow())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("decideSensorDispatch(%q, %v) = %v, want %v", tc.mode, tc.sensorIDs, err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("refused request still returned a sensor: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decideSensorDispatch(%q, %v) = %v, want nil — this is a supported request", tc.mode, tc.sensorIDs, err)
			}
			if tc.wantName == "" {
				if got != nil {
					t.Fatalf("a mode that does not dispatch returned a sensor: %+v", got)
				}
				return
			}
			if got == nil || got.Name != tc.wantName {
				t.Fatalf("got sensor %+v, want %q", got, tc.wantName)
			}
		})
	}
}

// The refusal for an offline sensor must carry the product promise verbatim:
// nothing was scanned, and when the sensor was last heard from.
func TestDecideSensorDispatch_OfflineMessageNamesTheSensorAndItsLastHeartbeat(t *testing.T) {
	id := uuid.New()
	beat := fixedNow().Add(-time.Hour)
	lookup := func(uuid.UUID) (dispatchSensor, bool) {
		return dispatchSensor{ID: id, Name: "branch-sensor", Status: "active", LastHeartbeat: &beat}, true
	}
	_, err := decideSensorDispatch("sensors", []string{id.String()}, lookup, fixedNow())
	if !errors.Is(err, ErrSensorOffline) {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"branch-sensor", "nothing was scanned", "2026-09-17T11:00:00Z"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

// The job processor is the last line: a `sensors` row that reaches the
// in-cluster scan path — however it got there — must FAIL, never run somewhere
// the caller did not ask for. The branch returns before any DB access, so a
// zero-value processor is enough to exercise it. Delete the branch and this
// goes red (the zero-value processor then panics on jp.db).
func TestProcessDiscoveryJob_FailsSensorExecutionMode(t *testing.T) {
	jp := &JobProcessor{}

	err := jp.processDiscoveryJob(&models.DiscoveryJob{
		ID:            "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42",
		TenantID:      "1c9e7a05-4d2b-4a63-9f18-7e5c2b0a3d64",
		ExecutionMode: "sensors",
	})
	if err == nil {
		t.Fatal("processDiscoveryJob accepted a sensors job — it would run in-cluster and report completed with zero findings")
	}
	if !strings.Contains(err.Error(), "sensors") || !strings.Contains(err.Error(), "not run from the platform") {
		t.Errorf("error = %v, want it to name the execution mode and say the platform did not run it", err)
	}
}

func TestBuildDispatchPayload_UnionsTheTargetRowsDeterministically(t *testing.T) {
	job := &models.DiscoveryJob{ID: "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42", TenantID: "1c9e7a05-4d2b-4a63-9f18-7e5c2b0a3d64"}
	rows := []dispatchTargetRow{
		{Input: "192.0.2.10", Protocols: []string{"TLS", "SSH"}, Ports: []int{443, 22}},
		{Input: "192.0.2.11", Protocols: []string{"TLS", "SSH"}, Ports: []int{443, 22}},
		{Input: "192.0.2.10", Protocols: []string{"Modbus"}, Ports: []int{502}}, // OT row for the same host
		{Input: "", Protocols: []string{"TLS"}, Ports: []int{0}},                // nothing usable
	}
	got := buildDispatchPayload(job, rows, map[string]interface{}{"active_scan": true})

	if got.JobID != job.ID || got.TenantID != job.TenantID {
		t.Errorf("ids: %+v", got)
	}
	if strings.Join(got.Targets, ",") != "192.0.2.10,192.0.2.11" {
		t.Errorf("targets = %v (want deduplicated, insertion-ordered)", got.Targets)
	}
	if strings.Join(got.Protocols, ",") != "Modbus,SSH,TLS" {
		t.Errorf("protocols = %v (want the sorted union)", got.Protocols)
	}
	if len(got.Ports) != 3 || got.Ports[0] != 22 || got.Ports[1] != 443 || got.Ports[2] != 502 {
		t.Errorf("ports = %v (want the sorted union, zero dropped)", got.Ports)
	}
	if v, _ := got.Options["active_scan"].(bool); !v {
		t.Errorf("options = %v", got.Options)
	}
	// And what the dispatcher writes, the sensor can read.
	if _, err := sensordispatch.ParsePayload(got.ToMap()); err != nil {
		t.Fatalf("the sensor would refuse this payload: %v", err)
	}
}

func TestDispatchFailureReason(t *testing.T) {
	beat := fixedNow().Add(-time.Hour)
	refused := "malformed discovery_job payload: targets is empty"

	cases := []struct {
		name string
		in   staleDispatch
		want []string
	}{
		{"never collected", staleDispatch{CommandStatus: "pending", SensorName: "xps16-sensor", LastHeartbeat: &beat},
			[]string{"xps16-sensor", "offline", "nothing was scanned", "2026-09-17T11:00:00Z"}},
		{"never collected, sensor row gone", staleDispatch{CommandStatus: "pending"},
			[]string{"sensor offline; nothing was scanned"}},
		{"refused by the sensor", staleDispatch{CommandStatus: "failed", SensorName: "xps16-sensor", CommandError: &refused},
			[]string{"xps16-sensor", "refused", refused, "nothing was scanned"}},
		{"collected, never finished", staleDispatch{CommandStatus: "delivered", SensorName: "xps16-sensor"},
			[]string{"xps16-sensor", "never reported completion", "2h0m0s"}},
		{"acknowledged, never finished", staleDispatch{CommandStatus: "acknowledged"},
			[]string{"never reported completion"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dispatchFailureReason(tc.in)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("reason %q lacks %q", got, want)
				}
			}
		})
	}
}

func TestExecutorFor(t *testing.T) {
	id := uuid.New().String()
	cases := []struct {
		mode     string
		assigned *string
		want     string
	}{
		{"async", nil, "platform"},
		{"auto", nil, "platform"},
		{"cloud", nil, "platform"},
		{"", nil, "platform"},
		{"sensors", &id, "sensor"},
		{"sensors", nil, "sensor"}, // queued or failed before assignment: still never the platform
		{"auto", &id, "sensor"},    // assigned wins regardless of how it was asked for
	}
	for _, tc := range cases {
		if got := executorFor(tc.mode, tc.assigned); got != tc.want {
			t.Errorf("executorFor(%q, %v) = %q, want %q", tc.mode, tc.assigned, got, tc.want)
		}
	}
}
