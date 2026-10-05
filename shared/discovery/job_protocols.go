package discovery

import (
	"fmt"
	"slices"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// jobProtocolNames is what a discovery job's `protocols` field may ask for, in
// the order a refusal lists them. Every entry is a prober the scan runtimes
// reach for any requested port: TLS (and the TLS-wrapped names the scanner
// treats as TLS) and SSH have bespoke probers, SMB the shared one.
//
// OT/ICS protocols are deliberately NOT here. They reach their probers only
// through a job's separate `ot_probe_protocols` field, which is what carries the
// explicit opt-in, the audit column and the one-standard-port-per-device
// restriction. A name smuggled in through `protocols` would run the same probes
// without any of that, so the two fields must never overlap.
var jobProtocolNames = []string{
	"TLS", "SSH", "SMB",
	"HTTPS", "SSL", "LDAPS", "SMTPS", "IMAPS", "POP3S", "FTPS",
}

// tlsWrappedJobProtocols are the entries of jobProtocolNames that mean "this
// listener speaks TLS" — the scanner runs its TLS probe for them on whatever
// port the job named. Kept next to the allowlist so the two cannot drift: a
// name accepted here is one the scanner knows how to probe.
var tlsWrappedJobProtocols = []string{
	"TLS", "HTTPS", "SSL", "LDAPS", "SMTPS", "IMAPS", "POP3S", "FTPS",
}

// otProtocolsByCanonical are the canonical spellings (cryptoparse.NormalizeProtocol)
// of the OT/ICS protocols. Used only to make a refusal point at
// `ot_probe_protocols`; the allowlist itself is what refuses them.
var otProtocolsByCanonical = []string{
	"Modbus", "DNP3", "MMS", "ICCP", "IEC62351", "OPC_UA",
	"EtherNet_IP", "BACnet", "BACnet_SC", "HART_IP", "S7",
}

// JobProtocolNames returns the protocol names a job's `protocols` field accepts.
func JobProtocolNames() []string {
	return slices.Clone(jobProtocolNames)
}

// JobProtocolAllowed reports whether a job may request this protocol in
// `protocols`. Spelling variants fold the same way the scanner folds them
// (CanonicalProtocolName), so "tls", "Tls" and " TLS " are one name.
func JobProtocolAllowed(protocol string) bool {
	return slices.Contains(jobProtocolNames, CanonicalProtocolName(protocol))
}

// IsTLSWrappedProtocol reports whether a protocol name explicitly denotes a
// TLS-wrapped service.
func IsTLSWrappedProtocol(protocol string) bool {
	return slices.Contains(tlsWrappedJobProtocols, CanonicalProtocolName(protocol))
}

func isOTProtocol(protocol string) bool {
	return slices.Contains(otProtocolsByCanonical, cryptoparse.NormalizeProtocol(protocol))
}

// ProtocolNotAllowedError is a job's `protocols` naming something the field
// does not accept. It is a request-shape refusal: callers answer 400.
type ProtocolNotAllowedError struct {
	// Rejected is every offending entry as the caller spelled it, in order,
	// without repeats.
	Rejected []string
	// OT is the subset of Rejected that names an OT/ICS protocol.
	OT []string
}

func (e *ProtocolNotAllowedError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "protocols: %s not accepted; allowed values are %s",
		quoteAll(e.Rejected), strings.Join(jobProtocolNames, ", "))
	if len(e.OT) > 0 {
		fmt.Fprintf(&b, ". %s is an OT/ICS protocol: request it through ot_probe_protocols, the explicit opt-in for OT probes, not protocols", quoteAll(e.OT))
	}
	return b.String()
}

func quoteAll(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(quoted, ", ")
}

// ValidateJobProtocols returns a *ProtocolNotAllowedError when any entry is not
// in the allowlist, and nil otherwise. An empty list is valid HERE — whether a
// job may carry no protocols is the caller's own rule (cluster-sensor refuses a
// job with neither a protocol/port pair nor an OT opt-in).
//
// Both layers call this — inventory-service's POST /discovery/jobs, so the
// person gets the message, and cluster-sensor-service's CreateJob, which HMAC
// service callers reach directly — so a change to the allowlist cannot reach one
// layer and not the other.
func ValidateJobProtocols(protocols []string) error {
	var bad *ProtocolNotAllowedError
	for _, p := range protocols {
		if JobProtocolAllowed(p) {
			continue
		}
		if bad == nil {
			bad = &ProtocolNotAllowedError{}
		}
		if !slices.Contains(bad.Rejected, p) {
			bad.Rejected = append(bad.Rejected, p)
			if isOTProtocol(p) {
				bad.OT = append(bad.OT, p)
			}
		}
	}
	if bad == nil {
		return nil
	}
	return bad
}
