package dispatchguard

// Planned automatic scans and identity probes ( WP2).
//
// AuthorizeAutomaticScan and the identity-probe authorization were written
// for the legacy protocols × ports payload: the targets are Payload.Targets,
// the ports Payload.Ports. A planned payload carries none of those; its
// targets and ports are in Payload.Plan, one PlanTargetWork per target. Both
// authorizations read the payload through probeScopeOf, so they judge exactly
// the addresses and ports the scanner will contact whichever shape the job
// has.
//
// The rules an unattended plan must keep, beyond the ones the legacy payload
// already had (policy ports, tenant scope, exclusions, sensitive assets):
//
//   - every plan target is one address — no range, no hostname — just as the
//     legacy automatic payload names individual addresses;
//   - TCP only: no UDP port, ever;
//   - no OT opt-in: an unattended scan never probes a PLC;
//   - depth custom (the policy's ports) or quick. Standard and Thorough name
//     hundreds or all of the TCP ports and are a person's choice.
//
// The port list itself is checked against the policy by the callers, as the
// legacy one is, and can therefore never exceed autoscan.MaxPorts.

import (
	"net/netip"
	"sort"
	"strings"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// probeScope is what an automatic scan or identity probe will contact.
type probeScope struct {
	// Targets are the addresses (planned) or targets (legacy) to scan.
	Targets []string
	// Protocols is the legacy payload's protocol list; a plan has none —
	// services are identified from what answers.
	Protocols []string
	// Ports is the legacy payload's port list, or the union of the plan's
	// per-target TCP ports.
	Ports []int
	// Planned: the payload carried a plan.
	Planned bool
}

// probeScopeOf reads the scope of a payload. A legacy payload is returned as
// it is (no behaviour change); a planned one is refused unless it keeps the
// unattended-plan rules above.
func probeScopeOf(payload sensordispatch.Payload) (probeScope, error) {
	if payload.Plan == nil {
		return probeScope{Targets: payload.Targets, Protocols: payload.Protocols, Ports: payload.Ports}, nil
	}
	plan := payload.Plan
	if len(payload.Targets) > 0 || len(payload.Protocols) > 0 || len(payload.Ports) > 0 {
		return probeScope{}, denied("a planned scan carries its targets and ports in the plan, not beside it")
	}
	if len(plan.OTProbeProtocols) > 0 {
		return probeScope{}, denied("automatic scanning cannot request OT probes")
	}
	scope := probeScope{Planned: true}
	ports := map[int]bool{}
	for _, t := range plan.Targets {
		switch t.Depth {
		case shareddisc.DepthCustom, shareddisc.DepthQuick:
		default:
			return probeScope{}, denied("automatic scans and identity probes run at custom or quick depth only, not " + string(t.Depth))
		}
		udp, err := t.UDPPortSet()
		if err != nil {
			return probeScope{}, denied("planned scan has invalid UDP ports")
		}
		if udp.Len() > 0 {
			return probeScope{}, denied("automatic scans and identity probes cannot probe UDP ports")
		}
		tcp, err := t.TCPPortSet()
		if err != nil {
			return probeScope{}, denied("planned scan has invalid TCP ports")
		}
		if tcp.Len() == 0 {
			return probeScope{}, denied("planned scan target names no TCP port")
		}
		target := strings.TrimSpace(t.Target)
		if _, err := netip.ParseAddr(target); err != nil {
			return probeScope{}, denied("automatic scans and identity probes name individual addresses")
		}
		for _, p := range tcp.Ports() {
			ports[p] = true
		}
		// Addresses() is what the scanner runs: the target, unless this
		// attempt was told to skip it.
		scope.Targets = append(scope.Targets, t.Addresses()...)
	}
	for p := range ports {
		scope.Ports = append(scope.Ports, p)
	}
	sort.Ints(scope.Ports)
	return scope, nil
}
