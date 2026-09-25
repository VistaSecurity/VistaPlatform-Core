package deviceinterrogation

import (
	"context"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// Secret material must never leave the interrogated device.
//
// The rule, the field-name lists and the crypto-posture allowlist now live in
// shared/redact, because four more boundaries need exactly the same decisions
// about exactly the same field names: the host agent, the SBOM parser, the
// CMDB connectors, and the AI provider boundary (ADR-0004 D4, ADR-0008 D4.5).
// One list, one set of mutation-tested guards. This file is what interrogation
// adds on top: the structural chokepoint.
//
// Two independent defences remain, deliberately:
//
//  1. Collectors project vendor responses onto an explicit allowlist of fields
//     we actually use, so secrets are never collected in the first place. That
//     is the real fix — see unifiDeviceMetadata in unifi.go.
//  2. Sanitize walks everything a collector emitted and redacts anything whose
//     field name still looks like a secret. This is the backstop for the next
//     collector someone writes, and for vendor fields we have not seen yet.
//
// Defence 2 exists BECAUSE defence 1 depends on a human remembering.

// RedactMap returns a copy of m with every secret-looking field replaced by
// redact.Marker, recursing through nested maps and slices. The input is not
// mutated. A nil map returns nil.
//
// Kept as this package's exported entry point because callers outside it
// (inventory-service's integration list, device-interrogation-service's job
// results) already read as "redact this the way interrogation does".
func RedactMap(m map[string]interface{}) map[string]interface{} {
	return redact.Map(m)
}

// Sanitize scrubs secret material from an interrogation result in place. It is
// applied by the Registry to every interrogator's output, so no collector can
// skip it and no new collector has to remember it.
//
// Every place a result can carry collector-controlled data must be walked here.
// That list grows: ops facts and observed relationships (ADR-0004 D1) added two
// more, and a fact value is `any`, which is the widest hole of the lot.
// TestSanitize_CoversEveryCollectedMapInTheResultType walks the result TYPE by
// reflection and fails if a new map[string]any, []map[string]any or `any` field
// appears anywhere in it without a line below — the gap the 0.5 review flagged,
// where a new field would have shipped unredacted and nothing would have said
// so.
//
// That walker covers the MAP-shaped sites. The string-shaped ones are covered
// by hand ([sanitizeIdentity], [sanitizePeer]) and are not structurally
// guarded, because a redactor that walked arbitrary strings by reflection is
// the heuristic shared/redact deliberately refuses. A new free-text string
// field on a collected type therefore still needs a line here.
func Sanitize(result *InterrogateResult) {
	if result == nil {
		return
	}
	result.DeviceInfo = redact.Map(result.DeviceInfo)
	for i := range result.Assets {
		result.Assets[i].Metadata = redact.Map(result.Assets[i].Metadata)
		sanitizeServiceHints(result.Assets[i].ServiceHints)
	}
	for i := range result.Facts {
		// redact.Any handles the shapes a fact value actually takes —
		// map[string]any, []map[string]any, []any, []string and string — and
		// returns anything else unchanged. That is why array-valued facts are
		// built as []map[string]any and never as typed structs: a struct would
		// pass through here untouched.
		result.Facts[i].Value = redact.Any(result.Facts[i].Value)
		sanitizePeer(&result.Facts[i].Subject)
	}
	for i := range result.Relationships {
		result.Relationships[i].Attributes = redact.Map(result.Relationships[i].Attributes)
		sanitizePeer(&result.Relationships[i].Subject)
		sanitizePeer(&result.Relationships[i].Peer)
	}
	sanitizeIdentity(result.DeviceIdentity)
	// Warnings are free text built from whatever a device answered — a vendor
	// error body, a Go *url.Error carrying the request URL. Their fields have
	// innocent names, so the value-shaped rules apply (see SanitizeWarnings).
	result.Warnings = SanitizeWarnings(result.Warnings)
}

// sanitizePeer masks PEM private-key blocks in a peer reference's free-text
// fields, by the same rule and for the same reason as [sanitizeIdentity].
//
// A peer's display name is the least trusted string in the whole result: it is
// whatever an LLDP neighbour advertised as its system name, or whatever an
// operator typed into a controller as a device label. The identical string
// reaches the result twice — once as `remote_name` inside the net.neighbors
// fact value, where [redact.Any] masks it, and once here, where nothing did.
// One string masked in one field and verbatim in the next is not a defensible
// boundary.
//
// Identifier values are covered too. Normalisation already rejects anything
// with a control character, so a multi-line PEM can never reach a MAC, an
// address or a DNS name — but `serial_number` is deliberately opaque
// (a serial's punctuation is the vendor's), so it is the one kind that would
// carry a single-line block through.
func sanitizePeer(peer *PeerRef) {
	if peer == nil {
		return
	}
	peer.DisplayName = redact.TextPEM(peer.DisplayName)
	// The advertised posture, by the same rule. Both are projections of an LLDP
	// system description or a CDP banner — free text from a device we do not
	// control — and a projection that keeps the product segment would keep a
	// single-line PEM block pasted where the product should be.
	peer.Platform = redact.TextPEM(peer.Platform)
	peer.SoftwareVersion = redact.TextPEM(peer.SoftwareVersion)
	// The capability lists are NOT walked: every element comes from a closed
	// vocabulary (lldpCapabilityNames drops anything else), so there is no
	// value in them that did not originate here.
	for i := range peer.Identifiers {
		peer.Identifiers[i].Value = redact.TextPEM(peer.Identifiers[i].Value)
	}
}

// sanitizeServiceHints masks PEM private-key blocks in an asset's identified
// service name and version.
//
// Same rule and same reason as [sanitizeIdentity]: name-based redaction cannot
// help on fields called `service_name` and `service_version`, and both hold
// free text whose ORIGIN is outside our control. The HTTP and TLS probers fill
// them from a server banner; host inventory (shared/hostinventory) fills the
// name from the process holding a listening socket, which is whatever the host
// called the binary. A host with a pasted key in a process name is absurd, and
// so was a device with one in its SNMP sysDescr until we found one.
func sanitizeServiceHints(hints *ServiceHints) {
	if hints == nil {
		return
	}
	hints.ServiceName = redact.TextPEM(hints.ServiceName)
	hints.ServiceVersion = redact.TextPEM(hints.ServiceVersion)
}

// sanitizeIdentity masks PEM private-key blocks in the device identity's string
// fields.
//
// Name-based redaction cannot help here — these fields are named `vendor` and
// `os_version` — and the values are vendor free text a collector copied
// verbatim. The concrete case is SNMP: sysDescr is a whole banner, it is the
// identity's OSVersion, and a device whose banner contains a pasted key would
// have carried it into the inventory with nothing to catch it. [redact.TextPEM]
// is the value-shaped rule that exists for exactly this, and applying it costs
// nothing on the version strings that are all these fields normally hold.
func sanitizeIdentity(identity *DeviceIdentity) {
	if identity == nil {
		return
	}
	identity.Vendor = redact.TextPEM(identity.Vendor)
	identity.Model = redact.TextPEM(identity.Model)
	identity.FirmwareVersion = redact.TextPEM(identity.FirmwareVersion)
	identity.SerialNumber = redact.TextPEM(identity.SerialNumber)
	identity.OSVersion = redact.TextPEM(identity.OSVersion)
}

// sanitizingInterrogator decorates a DeviceInterrogator so its result is
// scrubbed before any caller sees it. Registry.Get returns these, which is what
// makes redaction structural rather than a convention.
type sanitizingInterrogator struct {
	inner DeviceInterrogator
}

func (s sanitizingInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	result, err := s.inner.Interrogate(ctx, device, creds)
	if result != nil {
		// A warning always names its collector. Built-in collectors stamp
		// their own; this covers one that does not, by the device type it
		// was dispatched for.
		for i := range result.Warnings {
			if result.Warnings[i].Collector == "" {
				result.Warnings[i].Collector = device.DeviceType
			}
		}
	}
	Sanitize(result)
	return result, err
}

func (s sanitizingInterrogator) SupportedDeviceTypes() []string {
	return s.inner.SupportedDeviceTypes()
}
