package deviceinterrogation

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// Collector capability manifest ( W0.3, Principle 1: parity is enforced by
// a test, not by memory).
//
// Every interrogator the Registry dispatches to states, for EVERY capability in
// the closed set below, exactly one of:
//
//   - Supplies — its output carries the capability;
//   - NotApplicable — the capability cannot exist for what it interrogates, and
//     why (an F5 has no VPN the LTM collector could read);
//   - Gap — it could and does not, with the programme finding that records the
//     gap and the slice that closes it.
//
// It also lists every API path, CLI command, SNMP object and SQL statement it
// sends, with the privilege the account needs where that is known. The
// least-privilege setup guides (W6.1) are generated from that list, so it has
// to be exact rather than roughly right.
//
// Neither half is trusted. TestCollectorCapabilityConformance drives every
// registered interrogator against fake appliances serving fixture output and
// fails when a declaration disagrees with what the collector actually produced,
// or when the set of requests the fake appliance saw differs from the endpoint
// list. That is what makes adding a behaviour to one vendor force a decision
// for every other one: the new capability joins the closed set, and every
// manifest without a declaration for it is red.
//
// This file is the vocabulary and stays free of consumer dependencies like the
// rest of the package (the standalone agent vendors it). The declarations
// themselves are data, in capability_manifest.go. How to add a capability or a
// collector: docsv4/internal/developer/standards/COLLECTOR_CAPABILITIES.md.

// Capability is one behaviour a collector may supply.
type Capability string

// Behavioural capabilities: what a collector does beyond emitting a registered
// fact key. Mostly §A.3 of the discovery-beyond-the-lab programme spec
// (K-01…K-09), plus the pipeline behaviours a collector owns (P-13, P-16, P-17,
// C-09). Fact-key capabilities are derived from the fact registry instead; see
// [FactCapability].
const (
	// CapMgmtTLSChain: the device's management plane was TLS-probed and the
	// certificate chain it presented is in the result (K-01).
	CapMgmtTLSChain Capability = "mgmt.tls_chain"
	// CapMgmtSSHHostKey: the management SSH session's banner and host key are
	// recorded (K-01).
	CapMgmtSSHHostKey Capability = "mgmt.ssh_host_key"
	// CapMgmtSSHAlgorithms: the management SSH session's negotiated key
	// exchange, cipher and MAC are recorded (K-01).
	CapMgmtSSHAlgorithms Capability = "mgmt.ssh_algorithms"
	// CapVLANAddressing: net.vlans entries carry the segment's subnet and the
	// device's own gateway address on it (K-02).
	CapVLANAddressing Capability = "net.vlans.addressing"
	// CapVLANDHCP: net.vlans entries say whether the device serves DHCP on the
	// segment (K-02).
	CapVLANDHCP Capability = "net.vlans.dhcp"
	// CapIPv6: IPv6 addresses, neighbours or prefixes are collected, not only
	// IPv4 (C-09).
	CapIPv6 Capability = "net.ipv6"
	// CapNeighborEdges: LLDP/CDP neighbours become connects_to edges (K-03).
	CapNeighborEdges Capability = "topology.neighbor_edges"
	// CapNeighborPosture: those edges carry what the neighbour advertised about
	// itself — platform and capability bits — so it can be classified (K-03).
	CapNeighborPosture Capability = "topology.neighbor_posture"
	// CapEndpointPeers: clients and endpoints from an endpoint table (client
	// list, ARP, MAC table, leases) become peers with edges, not only a fact
	// (K-04).
	CapEndpointPeers Capability = "topology.endpoint_peers"
	// CapAdmissionEvidence: peers carry the identity-admission evidence the
	// collector verified (ControllerInventory / ConnectedInterface), so they
	// are admitted under identity_admission=enforce (P-16).
	CapAdmissionEvidence Capability = "topology.admission_evidence"
	// CapManagedSubjects: devices the interrogated device manages get their own
	// facts, as subjects that are members of it (K-05).
	CapManagedSubjects Capability = "topology.managed_subjects"
	// CapLBDependencies: a load balancer's stated virtual-server → pool-member
	// dependencies become depends_on edges (ADR-0004 D1 (5); the F5 cell of
	// K-04).
	CapLBDependencies Capability = "topology.lb_dependencies"
	// CapVPNCrypto: VPN configurations are inventoried with their measured
	// crypto — cipher, integrity, key exchange (K-06).
	CapVPNCrypto Capability = "vpn.crypto"
	// CapVPNTunnelEdges: a VPN peer or tunnel is an edge, not only metadata
	// (K-09; decision Q4: connects_to with protocol and tunnel attributes).
	CapVPNTunnelEdges Capability = "vpn.tunnel_edges"
	// CapDeviceServedTLS: TLS services the device serves beyond its management
	// plane (SSL-VPN, a VIP's client-ssl profile, a database's TLS) are
	// inventoried with something measured about them (K-07).
	CapDeviceServedTLS Capability = "tls.device_served"
	// CapCertificateInventory: certificates reach the canonical certificate
	// array on an asset, where inventory reads them (P-13).
	CapCertificateInventory Capability = "certs.inventory"
	// CapCollectionWarnings: sub-failures the collector survives are reported
	// as collection warnings rather than dropped (P-17, W0.1).
	CapCollectionWarnings Capability = "collection.warnings"
)

// factCapabilityPrefix marks a capability derived from the fact registry.
const factCapabilityPrefix = "fact:"

// FactCapability is the capability of emitting a registered fact key.
func FactCapability(key string) Capability {
	return Capability(factCapabilityPrefix + key)
}

// FactKey returns the fact key a fact capability stands for.
func (c Capability) FactKey() (string, bool) {
	key, ok := strings.CutPrefix(string(c), factCapabilityPrefix)
	return key, ok
}

// CapabilityInfo describes one capability for humans and for the generated
// documentation.
type CapabilityInfo struct {
	Capability Capability
	Title      string
	// Spec is the finding the capability comes from in
	// docsv4/internal/developer/standards/features/discovery-beyond-the-lab.md,
	// or "fact registry" for a fact key.
	Spec string
}

// behaviouralCapabilities is the hand-named half of the closed set, in display
// order. Adding one here makes every manifest without a declaration for it
// fail the conformance test — which is the point.
var behaviouralCapabilities = []CapabilityInfo{
	{CapMgmtTLSChain, "Management-plane TLS probed, with the certificate chain", "K-01"},
	{CapMgmtSSHHostKey, "Management SSH banner and host key", "K-01"},
	{CapMgmtSSHAlgorithms, "Management SSH key exchange, cipher and MAC", "K-01"},
	{CapVLANAddressing, "VLANs with subnet and gateway", "K-02"},
	{CapVLANDHCP, "VLANs with DHCP posture", "K-02"},
	{CapIPv6, "IPv6 collected", "C-09"},
	{CapNeighborEdges, "LLDP/CDP neighbours as edges", "K-03"},
	{CapNeighborPosture, "Neighbour platform and capabilities", "K-03"},
	{CapEndpointPeers, "Clients/endpoints as peers", "K-04"},
	{CapAdmissionEvidence, "Admission evidence on peers", "P-16"},
	{CapManagedSubjects, "Managed subordinate devices as subjects", "K-05"},
	{CapLBDependencies, "Load-balancer pool dependencies as edges", "K-04"},
	{CapVPNCrypto, "VPN crypto", "K-06"},
	{CapVPNTunnelEdges, "VPN peers or tunnels as edges", "K-09"},
	{CapDeviceServedTLS, "Device-served TLS inventoried", "K-07"},
	{CapCertificateInventory, "Certificates reach inventory", "P-13"},
	{CapCollectionWarnings, "Collection warnings", "P-17"},
}

// Capabilities returns the closed capability set: the behavioural
// capabilities, then one per fact key the registry
// (standards/fact-keys.yaml → shared/facts) lists device-interrogation as a
// producer of.
//
// The fact half is DERIVED, never written out: registering a new key for
// device-interrogation adds a capability every collector must then declare.
func Capabilities() []CapabilityInfo {
	out := make([]CapabilityInfo, 0, len(behaviouralCapabilities)+len(facts.All))
	out = append(out, behaviouralCapabilities...)
	for _, key := range facts.All {
		if !containsString(key.Producers, facts.ProducerDeviceInterrogation) {
			continue
		}
		out = append(out, CapabilityInfo{
			Capability: FactCapability(key.Key),
			Title:      "Fact " + key.Key,
			Spec:       "fact registry",
		})
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// DeclarationKind is which of the three answers a collector gave.
type DeclarationKind string

const (
	KindSupplies      DeclarationKind = "supplies"
	KindNotApplicable DeclarationKind = "not_applicable"
	KindGap           DeclarationKind = "gap"
)

// Unscheduled is the Slice of a gap no slice of the programme closes yet. It is
// allowed, and it is visible: the generated matrix and the PR that introduced
// it list every one.
const Unscheduled = "unscheduled"

// Declaration is one collector's answer for one capability.
type Declaration struct {
	Kind DeclarationKind
	// Reason says why the capability cannot exist for this collector.
	// NotApplicable only.
	Reason NAReason
	// Finding is the programme finding recording the gap (e.g. "K-03").
	// Gap only.
	Finding string
	// Slice is the slice that closes the gap (e.g. "W4.3"), or [Unscheduled].
	// Gap only.
	Slice string
	// Note is optional detail: what a Gap is missing, or where a Supplies is
	// only partial. It is documentation, not a checked claim.
	Note string
}

// Supplies declares that the collector's output carries the capability. note
// is optional and says where the supply is partial.
func Supplies(note ...string) Declaration {
	return Declaration{Kind: KindSupplies, Note: strings.Join(note, " ")}
}

// NAReason is why a capability cannot exist for a collector. Every reason is a
// named constant in capability_manifest.go (notApplicableReasons), never an
// inline string: rules (c) and (e) treat a Gap and a NotApplicable the same way
// — neither may appear in the output — so relabelling a gap as "not
// applicable" would otherwise cost nothing. Naming the reason makes the
// relabel a visible choice of constant in the diff, and a new reason a new
// constant a reviewer has to accept.
type NAReason string

// NotApplicable declares that the capability cannot exist for what this
// collector interrogates.
func NotApplicable(reason NAReason) Declaration {
	return Declaration{Kind: KindNotApplicable, Reason: reason}
}

// Gap declares that the collector could supply the capability and does not.
func Gap(finding, slice string, note ...string) Declaration {
	return Declaration{Kind: KindGap, Finding: finding, Slice: slice, Note: strings.Join(note, " ")}
}

// validate reports a declaration that is missing the field its kind requires.
func (d Declaration) validate() error {
	switch d.Kind {
	case KindSupplies:
		if d.Reason != "" || d.Finding != "" || d.Slice != "" {
			return fmt.Errorf("supplies carries a reason/finding/slice")
		}
	case KindNotApplicable:
		if strings.TrimSpace(string(d.Reason)) == "" {
			return fmt.Errorf("not_applicable needs a reason")
		}
	case KindGap:
		if strings.TrimSpace(d.Finding) == "" || strings.TrimSpace(d.Slice) == "" {
			return fmt.Errorf("gap needs a finding and a slice (or %q)", Unscheduled)
		}
	default:
		return fmt.Errorf("unknown declaration kind %q", d.Kind)
	}
	return nil
}

// EndpointTransport is how an endpoint is reached.
type EndpointTransport string

const (
	TransportHTTPS EndpointTransport = "https"
	TransportSSH   EndpointTransport = "ssh"
	TransportSNMP  EndpointTransport = "snmp"
	TransportSQL   EndpointTransport = "sql"
)

// Endpoint is one request a collector sends to the device.
type Endpoint struct {
	Transport EndpointTransport
	// Method is the HTTP method, "exec" for a CLI command, "get"/"walk" for
	// SNMP, or "query" for SQL.
	Method string
	// Target is exactly what is asked for: the request path with its whole
	// query, in the order sent (placeholders in braces, e.g. {site}; credential
	// values as {credential}), the CLI command, the OID, or the SQL statement.
	Target string
	// Body is the shape of the request body, when there is one: its encoding
	// and every top-level field in sorted order, credential values written
	// {credential} — e.g. `json{loginProviderName=tmos,password={credential},username={credential}}`.
	// A field the collector starts sending (a login provider, a Panorama
	// target) changes the request as much as a new path does.
	Body string
	// Name is the human name where it differs from Target — the op command a
	// PAN-OS XML request carries, the MIB object an OID is.
	Name string
	// Purpose says what the collector reads it for.
	Purpose string
	// Privilege is what the account needs for this request, where it is KNOWN.
	// Empty means not yet verified against the vendor's documentation or a
	// real device — the generated guide must say so rather than guess, for the
	// same reason a collector never fills a field it did not read.
	Privilege string
}

// Key is the endpoint's identity for comparison with what a fake appliance
// recorded: method, target and body shape.
func (e Endpoint) Key() string {
	if e.Body != "" {
		return e.Method + " " + e.Target + " " + e.Body
	}
	return e.Method + " " + e.Target
}

// CollectorManifest is one collector's declarations and endpoint list.
type CollectorManifest struct {
	// Collector is the collector's name, the one its collection warnings carry.
	Collector string
	// DeviceTypes are the device types the interrogator registers under,
	// filled from the interrogator itself by [Manifests].
	DeviceTypes  []string
	Declarations map[Capability]Declaration
	Endpoints    []Endpoint
}

// Declaration returns the collector's declaration for c.
func (m CollectorManifest) Declaration(c Capability) (Declaration, bool) {
	d, ok := m.Declarations[c]
	return d, ok
}

// manifestFor returns the manifest for a registered interrogator, matched on
// its concrete type so that no collector file has to know the manifest exists.
func manifestFor(interrogator DeviceInterrogator) (CollectorManifest, bool) {
	build, ok := collectorManifests[reflect.TypeOf(interrogator)]
	if !ok {
		return CollectorManifest{}, false
	}
	return build(), true
}

// Manifests returns the manifest of every interrogator NewRegistry registers,
// sorted by collector name, with each one's device types filled in. An
// interrogator with no manifest is an error: the conformance test fails on it,
// and a generator must not quietly skip a collector.
func Manifests() ([]CollectorManifest, error) {
	var out []CollectorManifest
	for _, interrogator := range NewRegistry().distinctInterrogators() {
		m, ok := manifestFor(interrogator)
		if !ok {
			return nil, fmt.Errorf("interrogator %T has no capability manifest", interrogator)
		}
		types := append([]string(nil), interrogator.SupportedDeviceTypes()...)
		sort.Strings(types)
		m.DeviceTypes = types
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Collector < out[j].Collector })
	return out, nil
}

// distinctInterrogators returns each registered interrogator once — the
// Registry maps every device-type alias to the same instance.
func (r *Registry) distinctInterrogators() []DeviceInterrogator {
	seen := map[DeviceInterrogator]bool{}
	var out []DeviceInterrogator
	types := r.SupportedDeviceTypes()
	sort.Strings(types)
	for _, deviceType := range types {
		interrogator := r.interrogators[deviceType]
		if seen[interrogator] {
			continue
		}
		seen[interrogator] = true
		out = append(out, interrogator)
	}
	return out
}
