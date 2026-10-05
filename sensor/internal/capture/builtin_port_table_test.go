package capture

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
)

// The console says "already monitored as <X>" from agentconfig's table of the
// sensor's built-in TCP ports ( WP5), not from this package, which the
// platform cannot import. So the table has to equal this classifier: every
// port getProtocolFromPort gives a meaning (STARTTLS on, its built-in set)
// must be in the table, and nothing else may be. Checked over the whole port
// space — a port added to the classifier and not the table fails here, which
// is the only way a person adding it as an extra would otherwise be told
// nothing.
//
// And each table port must be one the extras set never claims, so the
// console's "the sensor ignores it here" is true.
func TestBuiltInPortTableMatchesTheClassifier(t *testing.T) {
	for p := 1; p <= 65535; p++ {
		meaning := getProtocolFromPort(p, true, nil)
		_, listed := agentconfig.SensorBuiltInTCPPorts[p]
		switch {
		case meaning != "" && !listed:
			t.Errorf("port %d is classified %s but missing from agentconfig.SensorBuiltInTCPPorts", p, meaning)
		case meaning == "" && listed:
			t.Errorf("port %d is in agentconfig.SensorBuiltInTCPPorts but the sensor gives it no meaning", p)
		}
	}
	for p := range agentconfig.SensorBuiltInTCPPorts {
		if got := newExtraTLSPorts([]int{p}).protocol(p, nil); got != "" {
			t.Errorf("port %d listed as an extra is classified %q; extras must never override a built-in port", p, got)
		}
	}
}
