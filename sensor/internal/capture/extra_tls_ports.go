package capture

import (
	"log"
	"strconv"
	"strings"
)

// extraTLSPorts is the immutable set of operator-declared TCP ports
// (capture.extraPortsToMonitor) that carry TLS on a non-standard port.
//
// The BPF filter has always admitted these ports, but admitting a packet is
// not decoding it: analyzePacket and the TLS stream factory both decide a
// flow's protocol from the port alone, and an unlisted port classified as ""
// is dropped before any assembler sees it. The setting looked configured and
// produced nothing. Classification therefore has to consult this set in every
// place port->protocol is decided for TCP.
//
// A nil set is valid and matches nothing.
type extraTLSPorts map[int]struct{}

// validCapturePort reports whether p is a usable TCP port number. The BPF
// filter shares this check: an out-of-range term fails the whole filter
// compile, which would take capture down for every other port.
func validCapturePort(p int) bool { return p > 0 && p <= 65535 }

// newExtraTLSPorts builds the set, ignoring out-of-range values with ONE log
// line however many are bad.
func newExtraTLSPorts(ports []int) extraTLSPorts {
	set := make(extraTLSPorts, len(ports))
	var bad []string
	for _, p := range ports {
		if !validCapturePort(p) {
			bad = append(bad, strconv.Itoa(p))
			continue
		}
		set[p] = struct{}{}
	}
	if len(bad) > 0 {
		log.Printf("capture: ignoring invalid extraPortsToMonitor value(s) %s (valid range 1-65535)", strings.Join(bad, ", "))
	}
	return set
}

// protocol returns "TLS" when port is an operator-declared TLS port that has
// no built-in meaning, otherwise "". Callers consult it only after
// getProtocolFromPort returned "", but it re-checks anyway: extras must never
// override a built-in port (22 stays SSH, 445 stays SMB) nor a STARTTLS port.
// STARTTLS ports are tested with the feature forced ON so that turning
// STARTTLS off does not silently reclassify port 25 as implicit TLS.
func (e extraTLSPorts) protocol(port int, starttlsPorts []int) string {
	if _, ok := e[port]; !ok {
		return ""
	}
	if getProtocolFromPort(port, true, starttlsPorts) != "" {
		return ""
	}
	return "TLS"
}
