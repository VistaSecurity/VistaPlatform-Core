package services

// An OT-only request — ot_probe_protocols and nothing else, the shape the
// public API has always accepted — through the REAL CreateJob onto the shared
// engine ( WP5). Before WP5 it was the one request still created as a
// protocols × ports job for the legacy executors.
//
//   - it is planned: a custom scan on exactly the OT protocols' standard
//     ports, TCP for Modbus and OPC UA, UDP for BACnet and EtherNet/IP, with
//     the OT opt-in recorded in the audit column (and nothing else);
//   - run on the platform, the engine probes Modbus on 502 and records the
//     device; run on a tenant sensor, the plan the sensor is handed carries
//     the opt-in and the sensor's engine does the same.
//
// The BACnet half of the engine (an opted-in Who-Is over UDP) is pinned in
// shared/discovery (TestUnitEngine_OTOptInProbesBACnetOverUDP): the OT UDP
// probers dial the target address themselves, so no FakeNet can stand in for
// a routable address here.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// serveModbus answers every Modbus request with an exception (illegal
// function): enough for the Modbus prober to identify the device.
func serveModbus(t *testing.T) string {
	t.Helper()
	return serveTCP(t, func(c net.Conn) {
		req := make([]byte, 11)
		if _, err := c.Read(req); err != nil {
			return
		}
		_, _ = c.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0xAB, 0x01})
	})
}

// otSwitchOn puts the tenant on the community tier, whose ot_active_probing
// switch is on.
func (f *dispatchFixture) otSwitchOn(t *testing.T) {
	t.Helper()
	if _, err := f.raw.Exec(`UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'community') WHERE id = $1`, f.tenant); err != nil {
		t.Fatal(err)
	}
}

func (f *dispatchFixture) otAudit(t *testing.T, jobID string) []string {
	t.Helper()
	var col pq.StringArray
	if err := f.raw.QueryRow(`SELECT COALESCE(ot_probe_protocols, '{}') FROM discovery_jobs WHERE id = $1`, jobID).Scan(&col); err != nil {
		t.Fatal(err)
	}
	return []string(col)
}

// The plan an OT-only request becomes, per protocol.
func TestIntegration_OTOnlyRequest_IsPlannedOnItsStandardPorts(t *testing.T) {
	f := newDispatchFixture(t)
	f.otSwitchOn(t)
	for name, tc := range map[string]struct {
		protocols []string
		tcp, udp  string
		audit     []string
	}{
		"Modbus":             {[]string{"Modbus"}, "502", "", []string{"Modbus"}},
		"OPC UA":             {[]string{"opc-ua"}, "4840", "", []string{"OPC_UA"}},
		"BACnet":             {[]string{"BACnet"}, "", "47808", []string{"BACnet"}},
		"EtherNet/IP":        {[]string{"ethernet-ip"}, "", "44818", []string{"EtherNet_IP"}},
		"all four":           {[]string{"Modbus", "OPC_UA", "BACnet", "EtherNet_IP"}, "502,4840", "44818,47808", []string{"Modbus", "OPC_UA", "BACnet", "EtherNet_IP"}},
		"unknown names drop": {[]string{"Modbus", "DNP3", "garbage"}, "502", "", []string{"Modbus"}},
	} {
		t.Run(name, func(t *testing.T) {
			job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
				Targets: []string{"10.187.0.10"}, OTProbeProtocols: tc.protocols,
			})
			if err != nil {
				t.Fatalf("CreateJob: %v", err)
			}
			p := job.Plan
			if p == nil || p.Depth != shareddisc.DepthCustom || p.TCPPorts != tc.tcp || p.UDPPorts != tc.udp || p.ExecutorResolved != shareddisc.ExecutorPlatform {
				t.Fatalf("plan = %+v, want custom on TCP %q UDP %q from the platform", p, tc.tcp, tc.udp)
			}
			if got := f.otAudit(t, job.ID); !reflect.DeepEqual(got, tc.audit) {
				t.Fatalf("ot_probe_protocols = %v, want %v", got, tc.audit)
			}
		})
	}
}

// Platform: the planned OT-only job runs on the engine with the opt-in, and
// Modbus on 502 is probed and recorded. Mutation: pass nil instead of
// otProbePorts(otProtocols) in translateLegacyRequest and the request is not
// translated — it is created as a legacy OT job with no plan, which the
// platform no longer runs — turning this red.
func TestIntegration_OTOnlyRequest_RunsOnThePlatformEngine(t *testing.T) {
	f, fake := newUnitFixture(t)
	f.otSwitchOn(t)
	fake.Host("10.187.0.20", map[uint16]string{502: serveModbus(t)}, nil)
	job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
		Targets: []string{"10.187.0.20"}, OTProbeProtocols: []string{"Modbus"},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if job.Plan == nil {
		t.Fatal("the OT-only request was not planned")
	}
	if err := f.jp.handleDiscoveryJob(jobMessage(t, job.ID), &countingLease{}); err != nil {
		t.Fatal(err)
	}
	if s := f.jobStatus(t, job.ID); s != "completed" {
		t.Fatalf("job = %s, want completed", s)
	}
	keys := f.findingKeys(t, job.ID)
	if len(keys) != 1 || keys[0] != (findingKey{Protocol: "Modbus", Port: 502, IP: "10.187.0.20"}) {
		t.Fatalf("findings = %+v, want the Modbus device on 502", keys)
	}
	for addr := range fake.DialedAddrs() {
		if addr != "10.187.0.20" {
			t.Fatalf("the scan contacted %s", addr)
		}
	}
	for _, d := range fake.Dials() {
		if d != "tcp 10.187.0.20:502" {
			t.Fatalf("the scan made %q; an OT-only job touches only its OT ports", d)
		}
	}
}

// Tenant sensor: the plan the sensor is handed carries the OT opt-in and the
// OT ports, and the sensor's engine (planrun) probes Modbus with it.
func TestIntegration_OTOnlyRequest_RunsOnATenantSensor(t *testing.T) {
	f, fake := newUnitFixture(t)
	f.otSwitchOn(t)
	fake.Host("10.187.0.30", map[uint16]string{502: serveModbus(t)}, nil)
	sensor := f.capableSensor(t, "edge-ot")
	job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
		Targets: []string{"10.187.0.30"}, OTProbeProtocols: []string{"Modbus", "BACnet"},
		ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor.String()},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if job.Plan == nil || job.Plan.SensorID != sensor.String() {
		t.Fatalf("plan = %+v, want a plan on the named sensor", job.Plan)
	}
	payload, _ := f.dispatchPlan(t, job.ID)
	p := payload.Plan
	if !reflect.DeepEqual(p.OTProbeProtocols, []string{"Modbus", "BACnet"}) || len(p.Targets) != 1 || p.Targets[0].TCPPorts != "502" || p.Targets[0].UDPPorts != "47808" {
		t.Fatalf("plan payload = %+v targets %+v, want the OT opt-in on TCP 502 and UDP 47808", p, p.Targets)
	}
	// The sensor runs the TCP half here; the UDP probe dials the address
	// itself (see the file comment), so it is left out of this run.
	p.Targets[0].UDPPorts, p.Targets[0].UDPPortCount = "", 0
	rep := &dbReporter{db: f.raw, tenant: f.tenant, sensor: sensor, job: uuid.MustParse(job.ID)}
	sum, err := runOnSensor(context.Background(), *p, rep, fake)
	if err != nil || sum.Units != 1 || sum.Done != 1 {
		t.Fatalf("sensor run = %+v %v", sum, err)
	}
	keys := f.findingKeys(t, job.ID)
	if len(keys) != 1 || keys[0] != (findingKey{Protocol: "Modbus", Port: 502, IP: "10.187.0.30"}) {
		t.Fatalf("findings = %+v, want the Modbus device on 502", keys)
	}
}
