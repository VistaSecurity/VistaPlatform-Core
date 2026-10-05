package services

import (
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// CreateJob refuses a target the scanner cannot fully expand BEFORE it touches
// the database ( H4), so this needs none: a service with no database
// would panic on any later step, which is also what proves the refusal is not
// downstream of one. Delete the CheckTargetSizes call in CreateJob and this
// panics instead of returning the typed error.
func TestCreateJob_RefusesOversizeTargetBeforeAnyDatabaseWork(t *testing.T) {
	svc := NewDiscoveryService(nil, nil)
	for _, targets := range [][]string{
		{"10.20.0.0/19"},
		{"10.0.0.0-10.0.255.255"},
		{"2001:db8::/64"},
		{"0.0.0.0/0"},
		{"10.0.0.0/20", "10.1.0.0/20", "10.2.0.0/20", "10.3.0.0/20", "10.4.0.0/24"},
	} {
		_, err := svc.CreateJob("2a8f7c0e-0000-4000-8000-000000000001", "user", models.CreateDiscoveryJobRequest{
			Targets: targets, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "auto",
		})
		var tooLarge *shareddisc.TargetTooLargeError
		if !errors.As(err, &tooLarge) {
			t.Errorf("targets %v: err = %v, want *TargetTooLargeError", targets, err)
		}
	}
}

// A request that breaks BOTH rules gets one error, and the protocol allowlist
// wins: it is the first thing CreateJob checks, so an OT name is never let
// through to a size message that would suggest splitting the block and retrying
// with the same protocol. Reversing the order would make this fail.
func TestCreateJob_ProtocolAllowlistRunsBeforeTheTargetSizeCheck(t *testing.T) {
	svc := NewDiscoveryService(nil, nil)
	_, err := svc.CreateJob("2a8f7c0e-0000-4000-8000-000000000001", "user", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.20.0.0/19"}, Protocols: []string{"Modbus"}, Ports: []int{502}, ExecutionMode: "auto",
	})
	var badProtocol *shareddisc.ProtocolNotAllowedError
	var tooLarge *shareddisc.TargetTooLargeError
	if !errors.As(err, &badProtocol) || errors.As(err, &tooLarge) {
		t.Fatalf("err = %v, want only the protocol refusal", err)
	}
}
