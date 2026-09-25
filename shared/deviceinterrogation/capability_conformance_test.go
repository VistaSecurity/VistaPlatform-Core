package deviceinterrogation

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// TestCollectorCapabilityConformance holds every collector's capability
// manifest (capability_manifest.go) to what the collector actually does.
//
// For every interrogator NewRegistry registers, it runs the collector's
// harness (capability_fixtures_test.go) — the real interrogator, through the
// Registry, against fake appliances serving fixture output — and fails when:
//
//	(a) the manifest has no declaration, or an invalid one, for a capability
//	    in the closed set (or declares one outside it);
//	(b) a capability is declared Supplies and no run's output carries it;
//	(c) a capability is declared Gap and a run's output DOES carry it — which
//	    is what forces the manifest edit when someone closes the gap;
//	(e) a capability is declared NotApplicable and a run's output carries it;
//	(d) the requests the fake appliances recorded differ from the manifest's
//	    endpoint list, in either direction;
//	(w) a run's collection warnings differ from the ones that run declares
//	    (conformanceRun.warnings) — so a degraded scenario is tied to the
//	    warning for the endpoint IT refused, and a clean run may not warn;
//	(g) a Gap names a finding or a slice the programme spec does not have.
//
// "Carries it" is decided by capabilityEvidence below, one predicate per
// capability. A capability with no predicate fails too, so a new one cannot be
// added without saying how its presence is recognised.
func TestCollectorCapabilityConformance(t *testing.T) {
	registry := NewRegistry()
	interrogators := registry.distinctInterrogators()
	if len(interrogators) < 8 {
		t.Fatalf("the Registry yielded %d distinct interrogators; the walk has stopped seeing them", len(interrogators))
	}

	for _, interrogator := range interrogators {
		manifest, ok := manifestFor(interrogator)
		if !ok {
			t.Errorf("(a) interrogator %T is registered but has no capability manifest; add one to collectorManifests", interrogator)
			continue
		}
		t.Run(manifest.Collector, func(t *testing.T) {
			harness, ok := conformanceHarnesses[manifest.Collector]
			if !ok {
				t.Fatalf("collector %q has no conformance harness; its declarations would go untested", manifest.Collector)
			}
			runs := harness.runs(t)
			if len(runs) == 0 {
				t.Fatal("the harness ran no scenarios")
			}

			observed := observedCapabilities(runs, manifest.Collector)
			for _, run := range runs {
				for _, problem := range checkRunWarnings(manifest.Collector, run) {
					t.Error(problem)
				}
			}
			findings, slices := specIDs(t)
			if findings != nil {
				for _, problem := range checkGapIDs(manifest, findings, slices) {
					t.Error(problem)
				}
			}
			var requests []string
			if harness.staticRequests != nil {
				requests = harness.staticRequests(t)
			} else {
				for _, run := range runs {
					requests = append(requests, run.requests...)
				}
			}

			for _, problem := range checkConformance(manifest, observed, requests) {
				t.Error(problem)
			}
			if t.Failed() {
				t.Logf("observed capabilities: %v", observedList(observed))
				t.Logf("recorded requests: %v", uniqueSorted(requests))
			}
		})
	}
}

// TestCollectorCapabilityManifests_ExportedView pins the exported view W6.1
// will generate from: every registered interrogator appears once, with its
// device types filled in from the interrogator itself.
func TestCollectorCapabilityManifests_ExportedView(t *testing.T) {
	manifests, err := Manifests()
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, deviceType := range NewRegistry().SupportedDeviceTypes() {
		registered[deviceType] = true
	}
	covered := map[string]bool{}
	for _, m := range manifests {
		if len(m.DeviceTypes) == 0 {
			t.Errorf("manifest %q has no device types", m.Collector)
		}
		for _, deviceType := range m.DeviceTypes {
			if covered[deviceType] {
				t.Errorf("device type %q appears in two manifests", deviceType)
			}
			covered[deviceType] = true
		}
	}
	for deviceType := range registered {
		if !covered[deviceType] {
			t.Errorf("device type %q is registered but no manifest covers it", deviceType)
		}
	}
	if len(covered) != len(registered) {
		t.Errorf("manifests cover %d device types, the Registry registers %d", len(covered), len(registered))
	}
}

// TestCapabilities_FactHalfIsDerivedFromTheRegistry checks the derivation in
// both directions against the registry itself: every key device-interrogation
// may produce is a capability, and no key it may not produce is.
func TestCapabilities_FactHalfIsDerivedFromTheRegistry(t *testing.T) {
	got := map[string]bool{}
	for _, info := range Capabilities() {
		if key, ok := info.Capability.FactKey(); ok {
			got[key] = true
		}
	}
	for _, key := range facts.All {
		want := facts.MayWrite(facts.ProducerDeviceInterrogation, key.Key)
		if got[key.Key] != want {
			t.Errorf("fact %q: capability=%v, device-interrogation may write=%v", key.Key, got[key.Key], want)
		}
	}
	if len(got) == 0 {
		t.Fatal("no fact capabilities were derived; the registry walk has stopped working")
	}
}

// --- the rules ------------------------------------------------------------------

// checkConformance applies rules (a)–(e) to one manifest and returns every
// violation. It is pure so the rules themselves can be tested in both
// directions (TestCheckConformance_*) without a fake appliance.
func checkConformance(manifest CollectorManifest, observed map[Capability]bool, requests []string) []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(manifest.Collector+": "+format, args...))
	}

	closed := map[Capability]bool{}
	for _, info := range Capabilities() {
		closed[info.Capability] = true
		if !hasEvidencePredicate(info.Capability) {
			add("capability %q has no evidence predicate in capabilityEvidence; say how its presence is recognised", info.Capability)
		}

		decl, ok := manifest.Declarations[info.Capability]
		if !ok {
			add("(a) no declaration for %q — declare Supplies, NotApplicable(reason) or Gap(finding, slice)", info.Capability)
			continue
		}
		if err := decl.validate(); err != nil {
			add("(a) declaration for %q is invalid: %v", info.Capability, err)
			continue
		}
		switch decl.Kind {
		case KindSupplies:
			if !observed[info.Capability] {
				add("(b) declares Supplies for %q but no fixture run's output carries it", info.Capability)
			}
		case KindGap:
			if observed[info.Capability] {
				add("(c) declares Gap(%s, %s) for %q but the output carries it — the gap is closed; declare Supplies", decl.Finding, decl.Slice, info.Capability)
			}
		case KindNotApplicable:
			if observed[info.Capability] {
				add("(e) declares NotApplicable for %q but the output carries it — the reason %q is wrong", info.Capability, decl.Reason)
			}
		}
	}
	for c := range manifest.Declarations {
		if !closed[c] {
			add("(a) declares %q, which is not in the closed capability set", c)
		}
	}

	// (d) endpoints, both directions.
	listed := map[string]bool{}
	for _, e := range manifest.Endpoints {
		if e.Transport == "" || e.Method == "" || e.Target == "" || e.Purpose == "" {
			add("(d) endpoint %q is missing its transport, method, target or purpose", e.Key())
		}
		if listed[e.Key()] {
			add("(d) endpoint %q is listed twice", e.Key())
		}
		listed[e.Key()] = true
	}
	requested := map[string]bool{}
	for _, r := range requests {
		requested[r] = true
	}
	for _, r := range uniqueSorted(requests) {
		if !listed[r] {
			add("(d) the collector sent %q, which the manifest's endpoint list does not name", r)
		}
	}
	for _, e := range manifest.Endpoints {
		if !requested[e.Key()] {
			add("(d) the manifest lists %q but no fixture run sent it — remove it, or add the scenario that exercises it", e.Key())
		}
	}
	sort.Strings(problems)
	return problems
}

// --- evidence -------------------------------------------------------------------

// evidence is what one run's output says, with the context a predicate needs.
type evidence struct {
	result *InterrogateResult
	// mgmt is the host:port of the interrogated device's management plane.
	mgmt string
	// collector is the manifest's collector name, which its warnings carry.
	collector string
}

// mgmtHost is the interrogated device's own address.
func (e evidence) mgmtHost() string {
	host, _, err := net.SplitHostPort(e.mgmt)
	if err != nil {
		return ""
	}
	return host
}

// capabilityEvidence recognises each behavioural capability in a result. Fact
// capabilities are recognised generically (a fact with the key, about any
// subject), so they need no entry.
var capabilityEvidence = map[Capability]func(evidence) bool{
	CapMgmtTLSChain: func(e evidence) bool {
		if e.mgmt == "" {
			return false
		}
		for _, a := range e.result.Assets {
			if assetEndpoint(a) == e.mgmt && len(a.Certificates) > 0 {
				return true
			}
		}
		return false
	},
	CapMgmtSSHHostKey: func(e evidence) bool {
		for _, a := range e.result.Assets {
			if a.SSHInfo != nil && a.SSHInfo.Banner != "" && a.SSHInfo.HostKeyFingerprint != "" {
				return true
			}
		}
		return false
	},
	CapMgmtSSHAlgorithms: func(e evidence) bool {
		for _, a := range e.result.Assets {
			if s := a.SSHInfo; s != nil && s.KexAlgorithm != "" && s.EncryptionAlgC2S != "" && s.MACAlgC2S != "" {
				return true
			}
		}
		return false
	},
	CapVLANAddressing: func(e evidence) bool {
		// Both must PARSE, and the gateway must sit inside the subnet: a
		// non-empty string is not an address.
		for _, v := range factEntries(e.result, facts.KeyNetVlans) {
			subnet, _ := v["subnet"].(string)
			gateway, _ := v["gateway"].(string)
			prefix, err := netip.ParsePrefix(subnet)
			if err != nil {
				continue
			}
			addr, err := netip.ParseAddr(gateway)
			if err == nil && prefix.Contains(addr) {
				return true
			}
		}
		return false
	},
	CapVLANDHCP: func(e evidence) bool {
		for _, v := range factEntries(e.result, facts.KeyNetVlans) {
			if _, ok := v["dhcp_enabled"].(bool); ok {
				return true
			}
		}
		return false
	},
	CapIPv6: func(e evidence) bool {
		for _, addr := range resultAddresses(e.result) {
			if isIPv6(addr) {
				return true
			}
		}
		return false
	},
	CapNeighborEdges: func(e evidence) bool {
		return len(neighborEdges(e.result)) > 0
	},
	CapNeighborPosture: func(e evidence) bool {
		for _, r := range neighborEdges(e.result) {
			if r.Peer.Platform != "" || len(r.Peer.LLDPCapabilities) > 0 || len(r.Peer.CDPCapabilities) > 0 {
				return true
			}
		}
		return false
	},
	CapEndpointPeers: func(e evidence) bool {
		return len(endpointEdges(e.result)) > 0
	},
	// Admission evidence is recognised on the peers a collector VERIFIED —
	// managed subjects and endpoint-table peers — and, for a collector with
	// neither, on any other peer (its neighbours). Never on the interrogated
	// device itself: the controller's self-reference always carries
	// ConnectedInterface, and counting it made the capability impossible to
	// lose. Every managed subject and every endpoint peer must carry it; one
	// that does not is a peer the enforce mode would hold back.
	CapAdmissionEvidence: func(e evidence) bool {
		host := e.mgmtHost()
		verified := append(managedSubjects(e.result), endpointPeers(e.result)...)
		for _, p := range verified {
			if !hasAdmissionEvidence(p) && !isSelfRef(p, host) {
				return false
			}
		}
		for _, p := range resultPeerRefs(e.result) {
			if hasAdmissionEvidence(p) && !isSelfRef(p, host) {
				return true
			}
		}
		return false
	},
	CapManagedSubjects: func(e evidence) bool {
		return len(managedSubjects(e.result)) > 0
	},
	CapLBDependencies: func(e evidence) bool {
		for _, r := range e.result.Relationships {
			if r.Type == relTypeDependsOn {
				return true
			}
		}
		return false
	},
	CapVPNCrypto: func(e evidence) bool {
		for _, a := range e.result.Assets {
			if a.AssetType == "vpn_gateway" && (a.CipherSuite != nil || a.KeyExchangeAlg != nil || a.HashAlgorithm != nil) {
				return true
			}
		}
		return false
	},
	CapVPNTunnelEdges: func(e evidence) bool {
		for _, r := range e.result.Relationships {
			if isTunnelEdge(r) {
				return true
			}
		}
		return false
	},
	// A TLS SERVICE: an asset at an endpoint (address and port) other than the
	// management plane, with something about its TLS measured. A certificate
	// list with no endpoint is certs.inventory, not a service.
	CapDeviceServedTLS: func(e evidence) bool {
		for _, a := range e.result.Assets {
			endpoint := assetEndpoint(a)
			if endpoint == "" || endpoint == e.mgmt {
				continue
			}
			if isTLSProtocol(a.Protocol) && tlsMeasured(a) {
				return true
			}
		}
		return false
	},
	CapCertificateInventory: func(e evidence) bool {
		for _, a := range e.result.Assets {
			if len(a.Certificates) > 0 {
				return true
			}
		}
		return false
	},
	CapCollectionWarnings: func(e evidence) bool {
		for _, w := range e.result.Warnings {
			if w.Collector == e.collector {
				return true
			}
		}
		return false
	},
}

func hasEvidencePredicate(c Capability) bool {
	if _, ok := c.FactKey(); ok {
		return true
	}
	_, ok := capabilityEvidence[c]
	return ok
}

// observedCapabilities is every capability at least one run's output carries.
//
// Most capabilities are "some run shows it", so a scenario that suppresses
// one (a refused endpoint) does not hide it. The capabilities in
// universalCapabilities are claims about EVERY peer instead, and are judged
// against every run at once: otherwise a degraded run that happens to have no
// endpoint peers would vouch for a clean run whose endpoint peers lack the
// evidence.
func observedCapabilities(runs []conformanceRun, collector string) map[Capability]bool {
	out := map[Capability]bool{}
	combined := &InterrogateResult{}
	mgmt := ""
	for _, run := range runs {
		if run.result == nil {
			continue
		}
		combined.Facts = append(combined.Facts, run.result.Facts...)
		combined.Relationships = append(combined.Relationships, run.result.Relationships...)
		if mgmt == "" {
			mgmt = run.mgmt
		}
		e := evidence{result: run.result, mgmt: run.mgmt, collector: collector}
		for _, info := range Capabilities() {
			if key, ok := info.Capability.FactKey(); ok {
				if hasFact(run.result, key) {
					out[info.Capability] = true
				}
				continue
			}
			if universalCapabilities[info.Capability] {
				continue
			}
			if predicate, ok := capabilityEvidence[info.Capability]; ok && predicate(e) {
				out[info.Capability] = true
			}
		}
	}
	for c := range universalCapabilities {
		if predicate, ok := capabilityEvidence[c]; ok && predicate(evidence{result: combined, mgmt: mgmt, collector: collector}) {
			out[c] = true
		}
	}
	return out
}

// universalCapabilities are judged over all runs together (see
// observedCapabilities). Every run of a harness interrogates the same device
// address, so the self-reference is the same in all of them.
var universalCapabilities = map[Capability]bool{
	CapAdmissionEvidence: true,
}

func observedList(observed map[Capability]bool) []string {
	var out []string
	for c, ok := range observed {
		if ok {
			out = append(out, string(c))
		}
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// --- evidence helpers -----------------------------------------------------------

// assetEndpoint is the host:port an asset sits at.
func assetEndpoint(a CryptoAsset) string {
	host := a.IPAddress
	if host == "" {
		host = a.Hostname
	}
	if host == "" || a.Port == 0 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(a.Port))
}

// factEntries returns the array entries of every fact with key, whatever the
// container type Sanitize left them in.
func factEntries(result *InterrogateResult, key string) []map[string]any {
	var out []map[string]any
	for _, f := range result.Facts {
		if f.Key != key {
			continue
		}
		switch v := f.Value.(type) {
		case []map[string]interface{}:
			out = append(out, v...)
		case []interface{}:
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					out = append(out, m)
				}
			}
		}
	}
	return out
}

// resultAddresses is every address the result states anywhere: interface
// addresses, VLAN subnets and gateways, neighbour addresses, asset addresses
// and the ip_address identifiers of every peer.
func resultAddresses(result *InterrogateResult) []string {
	var out []string
	for _, iface := range factEntries(result, facts.KeyNetInterfaces) {
		switch addrs := iface["addresses"].(type) {
		case []string:
			out = append(out, addrs...)
		case []interface{}:
			for _, a := range addrs {
				if s, ok := a.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	for _, v := range factEntries(result, facts.KeyNetVlans) {
		for _, field := range []string{"subnet", "gateway"} {
			if s, ok := v[field].(string); ok {
				out = append(out, s)
			}
		}
	}
	for _, n := range factEntries(result, facts.KeyNetNeighbors) {
		if s, ok := n["remote_address"].(string); ok {
			out = append(out, s)
		}
	}
	for _, a := range result.Assets {
		out = append(out, a.IPAddress)
	}
	for _, p := range resultPeerRefs(result) {
		out = append(out, p.Identifier(IdentifierIPAddress))
	}
	return out
}

// isIPv6 reports whether s is an IPv6 address or prefix (not an IPv4-mapped
// one).
func isIPv6(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Addr().Is6() && !prefix.Addr().Is4In6()
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Is6() && !addr.Is4In6()
	}
	return false
}

// endpointTableSources are the discovery_protocol values an endpoint-table
// edge carries (W4.8 writes these), plus UniFi's client attachment, which
// names the port or AP it came through in `via`. An edge is an endpoint edge
// only when it SAYS it came from such a table: a neighbour edge that has lost
// its discovery_protocol is not thereby an endpoint.
var endpointTableSources = map[string]bool{
	"arp": true, "nd": true, "fdb": true, "mac_table": true, "dhcp_lease": true,
	"device_inventory": true, "client_table": true,
}

func isEndpointEdge(r RelationshipObservation) bool {
	if r.Type != relTypeConnectsTo || isTunnelEdge(r) {
		return false
	}
	if v, ok := r.Attributes["discovery_protocol"].(string); ok && endpointTableSources[strings.ToLower(v)] {
		return true
	}
	via, _ := r.Attributes["via"].(string)
	return via == "ap_mac" || via == "sw_mac"
}

func endpointEdges(result *InterrogateResult) []RelationshipObservation {
	var out []RelationshipObservation
	for _, r := range result.Relationships {
		if isEndpointEdge(r) {
			out = append(out, r)
		}
	}
	return out
}

// endpointPeers are the endpoints of endpoint edges: the edge's subject when
// it names one (a client attached to an AP), otherwise its peer (an ARP entry
// seen by the device).
func endpointPeers(result *InterrogateResult) []PeerRef {
	var out []PeerRef
	for _, r := range endpointEdges(result) {
		if !r.Subject.IsZero() {
			out = append(out, r.Subject)
		} else {
			out = append(out, r.Peer)
		}
	}
	return out
}

// managedSubjects are the subjects of member_of edges that also have facts of
// their own: devices the interrogated device manages.
func managedSubjects(result *InterrogateResult) []PeerRef {
	var out []PeerRef
	for _, r := range result.Relationships {
		if r.Type != relTypeMemberOf || r.Subject.IsZero() {
			continue
		}
		for _, f := range result.Facts {
			if sharesIdentifier(f.Subject, r.Subject) {
				out = append(out, r.Subject)
				break
			}
		}
	}
	return out
}

func hasAdmissionEvidence(p PeerRef) bool {
	return p.IdentityEvidence.ControllerInventory || p.IdentityEvidence.ConnectedInterface
}

// isSelfRef reports whether p names the interrogated device — the far end of
// a managed device's member_of edge is the controller itself.
func isSelfRef(p PeerRef, host string) bool {
	if host == "" {
		return false
	}
	for _, id := range p.Identifiers {
		if strings.EqualFold(id.Value, host) {
			return true
		}
	}
	return false
}

func isNeighborEdge(r RelationshipObservation) bool {
	if r.Type != relTypeConnectsTo {
		return false
	}
	switch strings.ToLower(fmt.Sprint(r.Attributes["discovery_protocol"])) {
	case "lldp", "cdp":
		return true
	}
	return false
}

func neighborEdges(result *InterrogateResult) []RelationshipObservation {
	var out []RelationshipObservation
	for _, r := range result.Relationships {
		if isNeighborEdge(r) {
			out = append(out, r)
		}
	}
	return out
}

// vpnEdgeProtocols is the protocol vocabulary a tunnel edge would carry
// (decision Q4: connects_to with protocol and tunnel attributes).
var vpnEdgeProtocols = map[string]bool{
	"ipsec": true, "ike": true, "ikev1": true, "ikev2": true, "wireguard": true,
	"openvpn": true, "l2tp": true, "pptp": true, "ssl_vpn": true, "sslvpn": true,
}

func isTunnelEdge(r RelationshipObservation) bool {
	if r.Type != relTypeConnectsTo {
		return false
	}
	if _, ok := r.Attributes["tunnel"]; ok {
		return true
	}
	for _, key := range []string{"protocol", "transport"} {
		if v, ok := r.Attributes[key].(string); ok && vpnEdgeProtocols[strings.ToLower(v)] {
			return true
		}
	}
	return false
}

// resultPeerRefs is every PeerRef in the result: fact subjects and both ends
// of every relationship.
func resultPeerRefs(result *InterrogateResult) []PeerRef {
	var out []PeerRef
	for _, f := range result.Facts {
		if !f.Subject.IsZero() {
			out = append(out, f.Subject)
		}
	}
	for _, r := range result.Relationships {
		if !r.Subject.IsZero() {
			out = append(out, r.Subject)
		}
		out = append(out, r.Peer)
	}
	return out
}

func sharesIdentifier(a, b PeerRef) bool {
	for _, x := range a.Identifiers {
		for _, y := range b.Identifiers {
			if x == y {
				return true
			}
		}
	}
	return false
}

func isTLSProtocol(protocol string) bool {
	p := strings.ToUpper(protocol)
	return strings.Contains(p, "TLS") || strings.Contains(p, "SSL") || p == "HTTPS"
}

// tlsMeasured reports whether anything about an asset's TLS was read, rather
// than the asset being a placeholder record for a service that exists.
//
// A protocol VERSION alone does not count. Two collectors still default one
// when they read none — Cisco's SSL converter and F5's VIP converter write
// "TLS 1.2" (P-04, W1.2) — and nothing in the asset says which versions were
// read and which were filled in. So only what no collector fabricates counts:
// a cipher, or a certificate. When W1.2 removes the defaults, versions can
// count again.
func tlsMeasured(a CryptoAsset) bool {
	return a.CipherSuite != nil || len(a.SupportedCiphers) > 0 || len(a.Certificates) > 0 || a.Certificate != nil
}

// --- per-run warnings (w) --------------------------------------------------------

// checkRunWarnings compares the endpoints of the collector's warnings in one
// run with the ones the run declares, exactly.
func checkRunWarnings(collector string, run conformanceRun) []string {
	if run.result == nil {
		return nil
	}
	var got []string
	for _, w := range run.result.Warnings {
		if w.Collector != collector {
			return []string{fmt.Sprintf("%s: (w) run %q carries a warning stamped %q, not this collector's name", collector, run.name, w.Collector)}
		}
		got = append(got, w.Endpoint)
	}
	got, want := uniqueSorted(got), uniqueSorted(run.warnings)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		return []string{fmt.Sprintf("%s: (w) run %q carries warnings for %q, but declares %q", collector, run.name, got, want)}
	}
	return nil
}

// --- gap IDs (g) -----------------------------------------------------------------

// programmeSpec is the spec every Gap's finding and slice must exist in.
const programmeSpec = "../../docsv4/internal/developer/standards/features/discovery-beyond-the-lab.md"

var (
	specFindingRowRE = regexp.MustCompile(`^\| ([A-Z][A-Z0-9]*-\d+)(?: ✔)? \|`)
	specSliceRowRE   = regexp.MustCompile(`^\| (W\d+\.\d+)\b`)
)

// specIDs parses the programme spec's finding rows (`| K-03 | …`) and slice
// rows (`| W4.3 | …`).
//
// The spec is internal documentation and does not ship in the public tree, so
// there — and only there — the check is skipped: a tree that still carries
// the Enterprise sources is the private one, and a missing spec in it fails.
func specIDs(t *testing.T) (findings, slices map[string]bool) {
	t.Helper()
	body, err := os.ReadFile(programmeSpec)
	if err != nil {
		if _, eeErr := os.Stat("../../services/compliance-engine/ee"); eeErr == nil {
			t.Fatalf("(g) the programme spec is missing from the private tree: %v", err)
		}
		return nil, nil
	}
	findings, slices = map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		if m := specFindingRowRE.FindStringSubmatch(line); m != nil {
			findings[m[1]] = true
		}
		if m := specSliceRowRE.FindStringSubmatch(line); m != nil {
			slices[m[1]] = true
		}
	}
	if len(findings) < 50 || len(slices) < 30 {
		t.Fatalf("(g) parsed %d findings and %d slices from the spec; the parser has stopped reading it", len(findings), len(slices))
	}
	return findings, slices
}

// checkGapIDs reports every Gap whose finding or slice the spec does not have.
func checkGapIDs(manifest CollectorManifest, findings, slices map[string]bool) []string {
	var problems []string
	for c, d := range manifest.Declarations {
		if d.Kind != KindGap {
			continue
		}
		if !findings[d.Finding] {
			problems = append(problems, fmt.Sprintf("%s: (g) Gap for %q names finding %q, which the spec has no row for", manifest.Collector, c, d.Finding))
		}
		if d.Slice != Unscheduled && !slices[d.Slice] {
			problems = append(problems, fmt.Sprintf("%s: (g) Gap for %q names slice %q, which the spec has no row for", manifest.Collector, c, d.Slice))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestCheckGapIDs_BothDirections(t *testing.T) {
	m := CollectorManifest{Collector: "synthetic", Declarations: map[Capability]Declaration{
		CapVPNCrypto: Gap("K-06", "W4.4"),
		CapIPv6:      Gap("C-09", Unscheduled),
	}}
	findings := map[string]bool{"K-06": true, "C-09": true}
	slices := map[string]bool{"W4.4": true}
	if problems := checkGapIDs(m, findings, slices); len(problems) != 0 {
		t.Fatalf("known IDs reported problems: %v", problems)
	}
	m.Declarations[CapVPNCrypto] = Gap("W0.3", "W4.4")
	requireProblem(t, checkGapIDs(m, findings, slices), `names finding "W0.3"`)
	m.Declarations[CapVPNCrypto] = Gap("K-06", "W9.9")
	requireProblem(t, checkGapIDs(m, findings, slices), `names slice "W9.9"`)
}

func TestProgrammeSpecIDs_AreParsed(t *testing.T) {
	findings, slices := specIDs(t)
	if findings == nil {
		t.Skip("public tree: the programme spec does not ship")
	}
	for _, id := range []string{"K-01", "K-09", "P-17", "C-09", "M-01", "M-13", "K8-01"} {
		if !findings[id] {
			t.Errorf("finding %s was not parsed from the spec", id)
		}
	}
	for _, id := range []string{"W0.3", "W4.7", "W5.15", "W1.9"} {
		if !slices[id] {
			t.Errorf("slice %s was not parsed from the spec", id)
		}
	}
}

// TestCollectorCapabilityManifests_NotApplicableReasonsAreNamed holds every
// NotApplicable to a named reason constant (see NAReason).
func TestCollectorCapabilityManifests_NotApplicableReasonsAreNamed(t *testing.T) {
	named := map[NAReason]bool{}
	for _, r := range notApplicableReasons {
		if named[r] {
			t.Errorf("reason %q is listed twice", r)
		}
		named[r] = true
	}
	used := map[NAReason]bool{}
	for _, build := range collectorManifests {
		m := build()
		for c, d := range m.Declarations {
			if d.Kind != KindNotApplicable {
				continue
			}
			used[d.Reason] = true
			if !named[d.Reason] {
				t.Errorf("%s: NotApplicable for %q uses an unnamed reason %q; add a constant to notApplicableReasons", m.Collector, c, d.Reason)
			}
		}
	}
	for r := range named {
		if !used[r] {
			t.Errorf("reason %q is named but no declaration uses it", r)
		}
	}
}

// --- the rules, tested in both directions ---------------------------------------
//
// checkConformance is what makes the manifest load-bearing, so each rule is
// pinned against a synthetic manifest: the clean input must pass, and each
// mutation must fail with the rule it breaks. A rule that could not fail here
// would be a guard that cannot fail anywhere.

func syntheticManifest() (CollectorManifest, map[Capability]bool, []string) {
	m := CollectorManifest{
		Collector:    "synthetic",
		Declarations: map[Capability]Declaration{},
		Endpoints: []Endpoint{
			{Transport: TransportHTTPS, Method: "GET", Target: "/status", Purpose: "identity"},
		},
	}
	observed := map[Capability]bool{}
	for _, info := range Capabilities() {
		m.Declarations[info.Capability] = Supplies()
		observed[info.Capability] = true
	}
	return m, observed, []string{"GET /status"}
}

func requireProblem(t *testing.T, problems []string, fragment string) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p, fragment) {
			return
		}
	}
	t.Errorf("want a problem containing %q, got %v", fragment, problems)
}

func TestCheckConformance_CleanManifestPasses(t *testing.T) {
	m, observed, requests := syntheticManifest()
	if problems := checkConformance(m, observed, requests); len(problems) != 0 {
		t.Fatalf("a manifest that matches its output reported problems: %v", problems)
	}
	// Each kind passes when the output agrees with it.
	m.Declarations[CapVPNCrypto] = Gap("K-06", "W4.4")
	m.Declarations[CapLBDependencies] = NotApplicable("not a load balancer")
	observed[CapVPNCrypto], observed[CapLBDependencies] = false, false
	if problems := checkConformance(m, observed, requests); len(problems) != 0 {
		t.Fatalf("honest Gap and NotApplicable declarations reported problems: %v", problems)
	}
}

func TestCheckConformance_A_MissingOrInvalidDeclaration(t *testing.T) {
	m, observed, requests := syntheticManifest()
	delete(m.Declarations, CapIPv6)
	requireProblem(t, checkConformance(m, observed, requests), `(a) no declaration for "net.ipv6"`)

	m, observed, requests = syntheticManifest()
	m.Declarations[FactCapability(facts.KeyNetVlans)] = Gap("K-02", "")
	requireProblem(t, checkConformance(m, observed, requests), `(a) declaration for "fact:net.vlans" is invalid`)

	m, observed, requests = syntheticManifest()
	m.Declarations[CapLBDependencies] = NotApplicable("  ")
	requireProblem(t, checkConformance(m, observed, requests), `(a) declaration for "topology.lb_dependencies" is invalid`)

	m, observed, requests = syntheticManifest()
	m.Declarations[Capability("made.up")] = Supplies()
	requireProblem(t, checkConformance(m, observed, requests), `(a) declares "made.up"`)
}

func TestCheckConformance_B_SuppliesWithoutEvidence(t *testing.T) {
	m, observed, requests := syntheticManifest()
	observed[CapNeighborEdges] = false
	requireProblem(t, checkConformance(m, observed, requests), `(b) declares Supplies for "topology.neighbor_edges"`)
}

func TestCheckConformance_C_GapWithEvidence(t *testing.T) {
	m, observed, requests := syntheticManifest()
	m.Declarations[FactCapability(facts.KeyNetUptimeSeconds)] = Gap("K-08", "W4.6")
	requireProblem(t, checkConformance(m, observed, requests), `(c) declares Gap(K-08, W4.6) for "fact:net.uptime_seconds"`)
}

func TestCheckConformance_E_NotApplicableWithEvidence(t *testing.T) {
	m, observed, requests := syntheticManifest()
	m.Declarations[CapLBDependencies] = NotApplicable("not a load balancer")
	requireProblem(t, checkConformance(m, observed, requests), `(e) declares NotApplicable for "topology.lb_dependencies"`)
}

func TestCheckConformance_D_EndpointsBothDirections(t *testing.T) {
	m, observed, _ := syntheticManifest()
	requireProblem(t, checkConformance(m, observed, []string{"GET /status", "GET /admin/users"}),
		`(d) the collector sent "GET /admin/users"`)
	requireProblem(t, checkConformance(m, observed, nil), `(d) the manifest lists "GET /status"`)

	m.Endpoints = append(m.Endpoints, m.Endpoints[0])
	requireProblem(t, checkConformance(m, observed, []string{"GET /status"}), `(d) endpoint "GET /status" is listed twice`)

	m, observed, requests := syntheticManifest()
	m.Endpoints[0].Purpose = ""
	requireProblem(t, checkConformance(m, observed, requests), "is missing its transport, method, target or purpose")
}

func TestCheckConformance_EveryCapabilityNeedsAPredicate(t *testing.T) {
	saved := capabilityEvidence[CapVPNCrypto]
	delete(capabilityEvidence, CapVPNCrypto)
	defer func() { capabilityEvidence[CapVPNCrypto] = saved }()

	m, observed, requests := syntheticManifest()
	requireProblem(t, checkConformance(m, observed, requests), `capability "vpn.crypto" has no evidence predicate`)
}
