// Package hostinventory collects a general inventory of a host — its OS and
// kernel, hardware identity, installed packages, listening sockets and
// installed certificate stores — through a transport-agnostic [Runner]
// (asset-inventory ADR-0004 D3).
//
// One collector, two modes. LOCAL mode runs on the host itself, on a schedule,
// with no credentials and the strongest identity available (the agent's own
// id). REMOTE mode runs the SAME command set over SSH against a target with
// stored credentials, exactly the way the agent interrogates a firewall today.
//
// # The parity rule
//
// The parsers take command OUTPUT or FILE BYTES and nothing else. They never
// touch os/exec, never read a local path, and never consult runtime.GOOS. Local
// and remote therefore run identical commands and feed identical bytes to
// identical parsers, and parity is a property of the shape rather than a thing
// someone has to maintain. TestTransportParity drives the same fixture through
// a fake local runner and a fake SSH runner and requires byte-identical
// Reports.
//
// There is exactly one documented divergence: when `ip -j addr` is unavailable,
// LOCAL mode falls back to net.Interfaces(). It is opt-in on the Options, it
// only fires after the command has already failed, and the Report records it as
// a step error so the fallback is visible rather than silent.
//
// # What is never collected
//
// Posture, never key material (CLAUDE.md). Concretely, and enforced by tests:
//
//   - Certificate stores are read for CERTIFICATES only. A PEM block whose type
//     is not "CERTIFICATE" is skipped structurally, so a private key sitting in
//     a store directory cannot reach the Report even as an error message.
//   - Windows certificate stores are projected to subject, thumbprint and
//     expiry. `Get-ChildItem Cert:\...` can export a private key; the command
//     this package runs asks for three properties and nothing else.
//   - No command transcript is stored. A step that fails records the step name
//     and a bounded message, never the output it could not parse.
//
// # This package must stay pure Go and CGO-free
//
// It is compiled into the standalone agent, which cross-compiles to Linux,
// Windows and macOS. It must not import a database pool, NATS, tenant context
// or anything else platform-internal (CLAUDE.md, the sensor source-sharing
// rule).
package hostinventory

import "time"

// Mode is which way the collector reached the host it describes.
type Mode string

const (
	// ModeLocal — the collector ran ON the host, as the agent. It sees
	// loopback sockets, the package database and DMI that no remote view has,
	// and it carries the agent's own id as identity.
	ModeLocal Mode = "local"
	// ModeRemote — the collector reached the host over SSH with stored
	// credentials. Same commands, weaker identity, and whatever the account it
	// logged in as is allowed to read.
	ModeRemote Mode = "remote"
)

// Section outcomes. The three values are the point: a section that is empty
// because nothing was found and a section that is empty because the step failed
// are different claims, and collapsing them is how "not assessed" comes to read
// as "clean" (CLAUDE.md, the three-valued-honesty rule).
const (
	// SectionOK — the step ran and its result is in the Report, INCLUDING a
	// genuinely empty result.
	SectionOK = "ok"
	// SectionFailed — the step ran and failed, or could not run. The section is
	// empty and its emptiness means nothing.
	SectionFailed = "failed"
	// SectionUnsupported — this platform has no way to answer. Not a failure,
	// and not an absence of the thing either.
	SectionUnsupported = "unsupported"
)

// Section names, used as the keys of [Report.Sections] and as the Step of a
// [StepError]. Spelled as constants so a section can be renamed without a
// silent mismatch between the setter and the reader.
const (
	SectionHost        = "host"
	SectionHardware    = "hardware"
	SectionInterfaces  = "interfaces"
	SectionPackages    = "packages"
	SectionListeners   = "listeners"
	SectionCertStores  = "cert_stores"
	SectionPlatformDet = "platform"
)

// Report is one host inventory collection.
//
// Every section is independently fallible. A Report with an empty Packages
// slice and Sections["packages"] == SectionFailed is a report that learned
// nothing about packages; one with Sections["packages"] == SectionOK is a
// report that looked and found none. Consumers MUST read Sections before
// treating an empty slice as an answer.
type Report struct {
	// Collected is when the collection finished, in UTC.
	Collected time.Time `json:"collected"`
	// Mode is local or remote.
	Mode Mode `json:"mode"`
	// Platform is the target's OS family as the collector detected it:
	// "linux", "darwin" or "windows".
	Platform string `json:"platform"`
	// AgentID is the reporting agent's id. Populated in LOCAL mode only —
	// in remote mode the agent is not the thing being described, and stamping
	// its id on another host's report would give two assets one identity.
	AgentID string `json:"agent_id,omitempty"`

	Host       Host        `json:"host"`
	Hardware   Hardware    `json:"hardware"`
	Interfaces []Interface `json:"interfaces,omitempty"`
	Packages   []Package   `json:"packages,omitempty"`
	Listeners  []Listener  `json:"listeners,omitempty"`
	CertStores []CertStore `json:"cert_stores,omitempty"`

	// PackagesOmitted marks a Report whose Packages slice was emptied ON
	// PURPOSE before transmission, because the same list travels — sanitised —
	// in the observations beside it. Never set by the collector; set only by
	// the submission path (device-agent/internal/api), and read by anybody who
	// has to interpret an empty Packages slice.
	//
	// It means a list was ELIDED, so it is set only when there was one to
	// elide: a report whose package step failed, or which genuinely found no
	// packages, leaves it false. That is what makes it usable as a POSITIVE
	// assertion at the platform's intake, which refuses a marked submission
	// carrying no observations list — the only way that pair can arise is the
	// surviving copy having been lost in transit, and materialising it would
	// mark the host's whole software inventory uninstalled.
	//
	// It exists because without it the elision is a LIE in the three-valued
	// scheme this whole type is built around: Sections["packages"] would say
	// `ok` while Packages said nothing, which is precisely "we looked and found
	// none". A `--host-inventory-once` report, and the report the collector
	// hands its own caller, carry the full list and leave this false.
	PackagesOmitted bool `json:"packages_omitted,omitempty"`

	// Errors is one entry per step that did not complete. A step that fails
	// records an error and leaves its section empty; it never guesses.
	Errors []StepError `json:"errors,omitempty"`
	// Sections maps a section name to SectionOK / SectionFailed /
	// SectionUnsupported. Always populated for every section the platform
	// attempts, so a missing key means the collector never reached that step at
	// all (a context cancellation part-way through).
	Sections map[string]string `json:"sections"`
}

// Host is the operating-system and naming identity of the target.
type Host struct {
	// OS is the product name as the host spells it: "Ubuntu", "Alpine Linux",
	// "macOS", "Microsoft Windows Server 2022 Standard".
	OS string `json:"os,omitempty"`
	// OSVersion is the release string, verbatim: "22.04.3 LTS (Jammy
	// Jellyfish)", "14.5", "10.0.20348".
	OSVersion string `json:"os_version,omitempty"`
	// Kernel is the build identifier beneath the OS version — the kernel
	// release on Unix, the build number on Windows. A patched kernel on an
	// unchanged distribution release is exactly the difference a vulnerability
	// match cares about.
	Kernel   string `json:"kernel,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	// FQDN is the fully-qualified name, present only when the host actually
	// resolves one. A short hostname with a domain glued on is a guess.
	FQDN   string `json:"fqdn,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// Hardware is the manufacturer's identity of the machine. Every field is
// absent rather than guessed: DMI is unreadable without root on Linux, and an
// unreadable serial must not become an empty-string serial that two hosts then
// share.
type Hardware struct {
	Vendor string `json:"vendor,omitempty"`
	Model  string `json:"model,omitempty"`
	Serial string `json:"serial,omitempty"`
	UUID   string `json:"uuid,omitempty"`
	// Firmware is the BIOS/UEFI version where the platform reports one.
	Firmware string `json:"firmware,omitempty"`
}

// Interface is one network interface as the host describes it.
type Interface struct {
	Name string `json:"name"`
	MAC  string `json:"mac,omitempty"`
	// Addresses are assigned addresses in CIDR form where the source gives a
	// prefix length, bare otherwise.
	Addresses []string `json:"addresses,omitempty"`
	// State is "up", "down" or "unknown" — the vocabulary net.interfaces
	// declares in standards/fact-keys.yaml.
	State string `json:"state,omitempty"`
	// Virtual marks an interface whose MAC is not a stable asset key: loopback,
	// a bridge, a container veth, a tunnel. Identity must not be minted from
	// one.
	Virtual bool `json:"virtual,omitempty"`
}

// Package is one installed software package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Arch    string `json:"arch,omitempty"`
	// Manager is the package database this came from: dpkg, rpm, apk, pkgutil,
	// macos_app, windows_registry.
	Manager string `json:"manager,omitempty"`
	// PURL is the Package URL, where the ecosystem has one. Windows registry
	// entries and macOS applications have no purl type, so they carry name,
	// vendor and version and no purl rather than an invented one.
	PURL string `json:"purl,omitempty"`
}

// Listener is one socket the host is listening on. This is the host's OWN view,
// which sees the loopback-only and firewalled services no network scan reaches,
// and it is the ground truth for which asset a service actually runs on.
type Listener struct {
	// Proto is "tcp" or "udp".
	Proto string `json:"proto"`
	// Address is the bound address. 0.0.0.0 or :: means all interfaces.
	Address string `json:"address,omitempty"`
	Port    int    `json:"port"`
	// Process is the process or service name holding the socket, where the
	// collector could see it (it needs privilege on most platforms).
	Process string `json:"process,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

// CertStore is one certificate store found on the host, summarised.
type CertStore struct {
	// Path is the store's location: a filesystem path on Unix, a
	// `Cert:\LocalMachine\<name>` store name on Windows.
	Path string `json:"path"`
	// Count is how many certificates the store holds. It is the count of what
	// PARSED, so a store with unreadable entries reports fewer than it has and
	// says so through the section outcome.
	Count int    `json:"count"`
	Certs []Cert `json:"certs,omitempty"`
	// NonCertificateBlocks is how many PEM blocks in this store were refused on
	// type — a PRIVATE KEY, an RSA PRIVATE KEY, a CERTIFICATE REQUEST.
	//
	// A count, never the content. A private key loose in a trust directory is
	// worth an operator knowing about and is never worth carrying, and the
	// number is also what makes the type-based refusal in ParseCertificatePEM
	// observable enough to be mutation-tested.
	NonCertificateBlocks int `json:"non_certificate_blocks,omitempty"`
}

// Cert is the posture summary of one installed certificate. Deliberately four
// fields: enough to say what is trusted and when it expires, and nothing that
// could carry key material.
type Cert struct {
	SubjectDN         string `json:"subject_dn,omitempty"`
	IssuerDN          string `json:"issuer_dn,omitempty"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	NotAfter          string `json:"not_after,omitempty"`
}

// StepError records a step that did not complete.
//
// Message is a bounded description of the failure, never the output that
// produced it: a command transcript is exactly the thing this package refuses
// to store, and an error path is the easiest place to leak one by accident.
type StepError struct {
	Step    string `json:"step"`
	Message string `json:"message"`
}

// maxErrorMessage bounds a recorded failure. A remote command can fail with
// kilobytes of stderr, and stderr from a config-reading command is a
// config-shaped string.
const maxErrorMessage = 300

// fail records a step failure and marks the section failed.
func (r *Report) fail(step string, err error) {
	r.mark(step, SectionFailed)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if len(msg) > maxErrorMessage {
		msg = msg[:maxErrorMessage] + "…(truncated)"
	}
	r.Errors = append(r.Errors, StepError{Step: step, Message: msg})
}

// mark records a section outcome.
func (r *Report) mark(section, outcome string) {
	if r.Sections == nil {
		r.Sections = make(map[string]string)
	}
	r.Sections[section] = outcome
}

// SectionState returns the recorded outcome for a section, or "" when the
// collector never reached it.
func (r *Report) SectionState(section string) string {
	if r == nil {
		return ""
	}
	return r.Sections[section]
}

// Collected reports whether a section ran to completion, which is the only
// safe basis for reading an empty slice as "none found".
func (r *Report) SectionOK(section string) bool {
	return r.SectionState(section) == SectionOK
}
