package services

import (
	"errors"
	"testing"

	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

func (f *dispatchFixture) countJobs(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id=$1`, f.tenant).Scan(&n); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	return n
}

// TestIntegration_CreateJob_ProtocolsAllowlist: the refusal leaves NO job row,
// the accepted shapes still create one, and the OT opt-in path — which writes
// discovery_targets with OT protocol names AFTER validation — is untouched.
func TestIntegration_CreateJob_ProtocolsAllowlist(t *testing.T) {
	f := newDispatchFixture(t)
	create := func(req models.CreateDiscoveryJobRequest) (*models.DiscoveryJob, error) {
		req.Targets = []string{"10.183.0.10"}
		req.ExecutionMode = "auto"
		return f.svc.CreateJob(f.tenant.String(), "system", req)
	}

	_, err := create(models.CreateDiscoveryJobRequest{Protocols: []string{"TLS", "Modbus"}, Ports: []int{443, 502}})
	var bad *shareddisc.ProtocolNotAllowedError
	if !errors.As(err, &bad) {
		t.Fatalf("[TLS Modbus] err = %v, want *ProtocolNotAllowedError", err)
	}
	if n := f.countJobs(t); n != 0 {
		t.Fatalf("a refused request left %d job row(s)", n)
	}

	job, err := create(models.CreateDiscoveryJobRequest{Protocols: []string{"TLS", "SSH"}, Ports: []int{443, 22}})
	if err != nil {
		t.Fatalf("[TLS SSH] refused: %v", err)
	}
	if n := f.countJobs(t); n != 1 {
		t.Fatalf("job rows = %d, want 1", n)
	}
	// Accepted and planned on its ports ( D2): the protocols are judged
	// by the allowlist, then ignored by the engine.
	if job.Plan == nil || job.Plan.TCPPorts != "22,443" {
		t.Errorf("[TLS SSH] job plan = %+v, want custom on 22,443", job.Plan)
	}

	// The explicit opt-in is a different field and is never judged by the
	// `protocols` allowlist: an OT name in ot_probe_protocols must not be refused
	// as a protocol. (Whether it is then dispatched or dropped is the
	// ot_active_probing entitlement's decision, which this test does not pin — a
	// tenant without it gets the TLS target only. When the OT rows ARE written,
	// they must be the standard-port ones.)
	otJob, err := create(models.CreateDiscoveryJobRequest{Protocols: []string{"TLS"}, Ports: []int{443}, OTProbeProtocols: []string{"Modbus", "OPC-UA"}})
	if err != nil {
		t.Fatalf("ot_probe_protocols job refused: %v", err)
	}
	rows, err := f.raw.Query(`SELECT protocols, ports FROM discovery_targets WHERE job_id=$1`, otJob.ID)
	if err != nil {
		t.Fatalf("read targets: %v", err)
	}
	defer func() { _ = rows.Close() }()
	want := map[string]int64{"Modbus": 502, "OPC_UA": 4840}
	for rows.Next() {
		var protos []string
		var ports []int64
		if err := rows.Scan(pq.Array(&protos), pq.Array(&ports)); err != nil {
			t.Fatal(err)
		}
		if len(protos) == 0 {
			continue // the plan's own row: its planned ports, no protocols
		}
		if len(protos) != 1 || len(ports) != 1 || want[protos[0]] != ports[0] {
			t.Errorf("target row %v/%v is not a one-protocol, standard-port row", protos, ports)
		}
	}
}
