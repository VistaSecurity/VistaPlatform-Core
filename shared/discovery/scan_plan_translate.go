package discovery

// The legacy request shape, translated (owner decision D2).
//
// POST /discovery/jobs has accepted `protocols` + `ports` since before scan
// plans existed, and the public API documents it. One scan path means every
// job runs on the shared engine, which needs no protocol list: it scans the
// ports and identifies services from what answers. So a legacy request is
// rewritten as the plan it means — scan_depth "custom" on exactly the ports it
// named — and its protocols are accepted and ignored.
//
// An OT opt-in (`ot_probe_protocols`) is translated too ( WP5): each OT
// probe the caller will actually dispatch adds its one standard port to the
// plan — TCP for Modbus and OPC UA, UDP for EtherNet/IP and BACnet, the
// transports the OT probers speak — and the opt-in itself stays on the
// caller's request, so the engine probes exactly those protocols on exactly
// those ports and every other OT port stays connect-only. An OT-only request
// becomes a custom plan on only its OT ports.
//
// This function only says what the translation is, and declines a request it
// cannot translate faithfully, which the caller then refuses or (for a tenant
// sensor without plan support) sends in the legacy shape.

import (
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// OTProbePort is one OT probe a request opts in to, at the standard port it is
// dispatched on: what the caller records in discovery_jobs.ot_probe_protocols
// after its own allowlist and the operator's ot_active_probing switch.
type OTProbePort struct {
	Protocol string
	Port     int
}

// TranslateLegacyJobRequest rewrites a legacy protocols × ports request (or an
// OT-only one) as a custom scan plan. ot is the request's OT opt-in AFTER the
// caller's allowlist and operator switch: the probes that will be dispatched,
// each at its standard port. ok=false leaves the request as it was:
//
//   - it names no ports and dispatches no OT probe (a scan-depth request, a
//     protocols-only request, or an OT-only request whose probes the operator
//     switched off — the caller refuses those with that reason);
//   - it also carries scan-plan fields (ResolveJobRequest refuses the mix,
//     naming it);
//   - ot names a probe while the request opted in to none, a protocol the
//     engine cannot probe, or a port out of range (a caller bug: nothing is
//     widened);
//   - its execution_mode and preferred_sensor_ids are a combination the legacy
//     path refuses (sensors with other than one sensor or one that is not a
//     UUID, sensors named for a mode that does not dispatch), so that
//     refusal is still the one given.
//
// The translated request runs where the legacy one would have: on the tenant
// sensor it named, or otherwise on the platform (the legacy path ran every
// non-"sensors" mode on the platform; "cloud" is normalised to the platform by
// the caller). The result carries no OTProbeProtocols: the caller keeps the
// opt-in on its own request.
func TranslateLegacyJobRequest(f JobRequestFields, ot []OTProbePort) (JobRequestFields, bool) {
	if len(f.planFieldsPresent()) > 0 {
		return f, false
	}
	if len(ot) > 0 && len(f.OTProbeProtocols) == 0 {
		return f, false
	}
	if len(f.Ports) == 0 && len(ot) == 0 {
		return f, false
	}
	var otTCP, otUDP []int
	for _, p := range ot {
		if p.Port < 1 || p.Port > 65535 {
			return f, false
		}
		if _, err := validateOTProbes([]string{p.Protocol}); err != nil {
			return f, false
		}
		if IsUDPProtocol(p.Protocol) {
			otUDP = appendNewPort(otUDP, p.Port)
		} else {
			otTCP = appendNewPort(otTCP, p.Port)
		}
	}
	out := JobRequestFields{DryRun: f.DryRun, ScanDepth: string(DepthCustom)}
	mode := strings.ToLower(strings.TrimSpace(f.ExecutionMode))
	switch {
	case mode == "sensors":
		if len(f.PreferredSensorIDs) != 1 {
			return f, false
		}
		if _, err := uuid.Parse(strings.TrimSpace(f.PreferredSensorIDs[0])); err != nil {
			return f, false
		}
		out.RunFrom, out.SensorID = RunFromSensor, strings.TrimSpace(f.PreferredSensorIDs[0])
	case len(f.PreferredSensorIDs) > 0:
		return f, false
	default:
		out.RunFrom = RunFromPlatform
	}
	tcp := append([]int(nil), f.Ports...)
	for _, p := range otTCP {
		tcp = appendNewPort(tcp, p)
	}
	out.TCPPorts = CustomPortList(tcp)
	out.UDPPorts = CustomPortList(otUDP)
	return out, true
}

func appendNewPort(ports []int, p int) []int {
	for _, q := range ports {
		if q == p {
			return ports
		}
	}
	return append(ports, p)
}

// CustomPortList renders a port list as the tcp_ports value of a scan-depth
// "custom" request ("443,22"), in the order given. It is what every caller
// that used to send `ports` sends instead ( WP4); ParsePortSpec reads it
// back. An empty list gives "", which a custom request refuses.
func CustomPortList(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
