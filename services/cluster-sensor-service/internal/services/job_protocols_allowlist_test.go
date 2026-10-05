package services

import (
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// H6 of: `protocols` reached the OT probers unfiltered, so ["Modbus"]
// skipped the explicit ot_probe_protocols opt-in. CreateJob now refuses it
// before it touches anything. The service is built with NO database: if the
// refusal ever moved behind the first query, this would panic on the nil
// handle instead of passing.
func TestCreateJob_RefusesProtocolsOutsideTheAllowlistBeforeAnyLookup(t *testing.T) {
	svc := NewDiscoveryService(nil, nil)
	for _, protocols := range [][]string{
		{"TLS", "Modbus"},
		{"OPC UA"},
		{"opc_ua"},
		{"EtherNet-IP"},
		{"BACnet"},
		{"DNP3"},
		{"HART-IP"},
		{"garbage"},
		{""},
	} {
		_, err := svc.CreateJob("00000000-0000-0000-0000-000000000001", "system", models.CreateDiscoveryJobRequest{
			Targets:       []string{"10.183.0.10"},
			ExecutionMode: "auto",
			Protocols:     protocols,
			Ports:         []int{443},
		})
		var bad *shareddisc.ProtocolNotAllowedError
		if !errors.As(err, &bad) {
			t.Errorf("CreateJob(protocols=%q) err = %v, want *ProtocolNotAllowedError", protocols, err)
		}
	}
}
