package deviceinterrogation

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// Agent-routed device discovery ( slice B).
//
// Add device identifies a device by logging in to it. When only a deployed
// device agent can reach the device, the identification runs on that agent as
// a `device_discovery` job, and its outcome travels back to the platform as an
// IdentificationReport. Both runtimes call the SAME Registry.Identify — the
// agent does not carry a second copy of any vendor code — so a device the
// platform can reach and one only an agent can reach are identified the same
// way, with the same typed failures.

// JobTypeDeviceDiscovery is the device_jobs.job_type value of an agent-routed
// identification. The platform and the agent both spell it from here.
const JobTypeDeviceDiscovery = "device_discovery"

// AgentCapabilitiesHeader carries, on an agent's job poll, the job types the
// agent can execute beyond device_interrogation, comma-separated.
//
// An agent is shipped separately from the platform and is routinely a release
// behind it. An agent that predates a job type cannot execute it, and one it
// did claim would sit in_progress forever: the old executor answers "unknown
// job type" locally and submits nothing. So the platform hands a newer job type
// only to an agent that has SAID it can run it; an older agent sends no header
// and is never offered one.
const AgentCapabilitiesHeader = "X-Agent-Capabilities"

// CapabilityDeviceDiscovery is the capability that lets an agent claim
// device_discovery jobs.
const CapabilityDeviceDiscovery = JobTypeDeviceDiscovery

// AgentCapabilities is the capability list this build of the agent sends.
func AgentCapabilities() []string {
	return []string{CapabilityDeviceDiscovery}
}

// ParseAgentCapabilities reads an AgentCapabilitiesHeader value. Unknown
// entries are kept (a newer agent may know more than this platform does); empty
// entries and surrounding space are dropped.
func ParseAgentCapabilities(header string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(header, ",") {
		if p := strings.ToLower(strings.TrimSpace(part)); p != "" {
			out[p] = true
		}
	}
	return out
}

// IdentificationReport is the wire and storage form of a successful
// identification: what an agent sends home, and what the platform keeps in
// device_jobs.results.
//
// It is an ALLOWLIST. Every field is named, and nothing a vendor answered
// reaches it except through these fields — so an identification can never
// carry a credential, a key or a configuration blob home, whatever the vendor
// response held. (CLAUDE.md "Collect posture, never key material": layer 2,
// project the response.)
type IdentificationReport struct {
	Vendor          string `json:"vendor,omitempty"`
	Model           string `json:"model,omitempty"`
	SerialNumber    string `json:"serial_number,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	OSVersion       string `json:"os_version,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	IPAddress       string `json:"ip_address,omitempty"`
	MACAddress      string `json:"mac_address,omitempty"`
	// TargetHost / TargetPort are where the identification connected — the
	// operator's address resolved — not something the device said.
	TargetHost string `json:"target_host,omitempty"`
	TargetPort int    `json:"target_port,omitempty"`
	// SSHHostKeyFingerprint / SSHHostKeyType are the host key an SSH
	// identification authenticated through. Public by construction; the
	// platform pins it on the device it creates.
	SSHHostKeyFingerprint string `json:"ssh_host_key_fingerprint,omitempty"`
	SSHHostKeyType        string `json:"ssh_host_key_type,omitempty"`
}

// maxReportField bounds each free-text field. A model string is tens of
// characters; anything near this is not an identity.
const maxReportField = 256

// NewIdentificationReport projects an identification onto the report. Nil in,
// nil out.
func NewIdentificationReport(d *DeviceIdentification) *IdentificationReport {
	if d == nil {
		return nil
	}
	r := &IdentificationReport{
		Vendor:                d.Vendor,
		Model:                 d.Model,
		SerialNumber:          d.SerialNumber,
		FirmwareVersion:       d.FirmwareVersion,
		OSVersion:             d.OSVersion,
		Hostname:              d.Hostname,
		IPAddress:             d.IPAddress,
		MACAddress:            d.MACAddress,
		TargetHost:            d.TargetHost,
		TargetPort:            d.TargetPort,
		SSHHostKeyFingerprint: d.SSHHostKeyFingerprint,
		SSHHostKeyType:        d.SSHHostKeyType,
	}
	return r.Sanitized()
}

// Sanitized returns a copy with every string field run through the identity
// redaction rule and bounded in length, and a port outside 0–65535 dropped.
//
// The platform applies it to a report it RECEIVES, not only to one it built:
// an agent binary is not a boundary the platform owns, so what it relays is
// scrubbed again before it is stored — the same rule SubmitJobResult applies
// to collection warnings.
func (r *IdentificationReport) Sanitized() *IdentificationReport {
	if r == nil {
		return nil
	}
	clean := func(s string) string {
		s = strings.TrimSpace(redact.TextPEM(s))
		if len(s) > maxReportField {
			s = s[:maxReportField]
		}
		return s
	}
	out := &IdentificationReport{
		Vendor:                clean(r.Vendor),
		Model:                 clean(r.Model),
		SerialNumber:          clean(r.SerialNumber),
		FirmwareVersion:       clean(r.FirmwareVersion),
		OSVersion:             clean(r.OSVersion),
		Hostname:              clean(r.Hostname),
		IPAddress:             clean(r.IPAddress),
		MACAddress:            clean(r.MACAddress),
		TargetHost:            clean(DisplayAddress(r.TargetHost)),
		SSHHostKeyFingerprint: clean(r.SSHHostKeyFingerprint),
		SSHHostKeyType:        clean(r.SSHHostKeyType),
	}
	if r.TargetPort > 0 && r.TargetPort <= 65535 {
		out.TargetPort = r.TargetPort
	}
	return out
}

// IdentifiesSomething reports whether the report names the device beyond its
// vendor — the same bar Registry.Identify sets, so a relayed report that says
// nothing is refused on the platform as it would have been on the agent.
func (r *IdentificationReport) IdentifiesSomething() bool {
	if r == nil {
		return false
	}
	for _, v := range []string{r.Model, r.SerialNumber, r.FirmwareVersion, r.Hostname} {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// KnownIdentifyFailure reports whether code is one of the IdentifyFailure
// values. An agent relays a failure code; the platform stores only codes it
// knows and maps anything else to IdentifyFailed.
func KnownIdentifyFailure(code string) bool {
	switch IdentifyFailure(code) {
	case IdentifyNotSupported, IdentifyInvalidTarget, IdentifyTargetDisallowed,
		IdentifyConnectionFailed, IdentifyTLSUntrusted, IdentifyAuthenticationFailed,
		IdentifyHostKeyMismatch, IdentifyUnsupportedResponse, IdentifyFailed:
		return true
	}
	return false
}
