package hostinventory

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// ToObservations turns a [Report] into the observation shape the rest of the
// platform already consumes — registered facts, peer identifiers, and endpoints
// — and sanitises the result.
//
// Three rules govern what crosses this boundary:
//
//  1. Every fact key is a compile-time reference to the generated registry
//     (shared/facts), written by the `device-agent` producer, which is what the
//     registry lists for os.kernel, hw.uuid, svc.listening_sockets,
//     sw.package_count, agent.id and agent.mode. An unregistered key or a wrong
//     producer is refused at emit time.
//  2. A section that FAILED emits no fact. An absent fact means "not measured";
//     a fact with an empty value would mean "measured, and the answer is
//     nothing". Collapsing the two is how a host that refused to answer comes
//     to read as a host with nothing to report.
//  3. The package list and the certificate summary ride in Metadata under an
//     explicit ALLOWLIST ([projectPackage], [projectCertStore]). They are the
//     two places a whole struct could otherwise be assigned wholesale, which is
//     the mistake that put a controller's mesh PSK in device_jobs.results.
//
// Everything then passes through [deviceinterrogation.Sanitize], the backstop
// that covers the field nobody has seen yet.
func ToObservations(rep *Report) (*di.InterrogateResult, error) {
	if rep == nil {
		return nil, fmt.Errorf("hostinventory: ToObservations on a nil report")
	}

	result := &di.InterrogateResult{
		Assets:     []di.CryptoAsset{},
		DeviceInfo: map[string]interface{}{},
	}

	subject := hostPeerRef(rep)
	add := func(key string, value any, confidence float64) {
		if err := result.AddFactFrom(facts.ProducerDeviceAgent, di.FactObservation{
			Key: key, Value: value, Confidence: confidence, Subject: subject,
		}); err != nil {
			// Every call below passes a constant key and a value built here, so
			// a failure is a programming error the projection tests catch before
			// it ships. At runtime, losing one fact must not lose the collection
			// that carried it — but it must not be silent either.
			//
			// STDERR, unlike the equivalent warning in deviceinterrogation.
			// This projection is what `device-agent --host-inventory-once`
			// prints, and that command's stdout IS the report: a diagnostic
			// line written there does not warn anybody, it makes the document
			// fail to parse.
			fmt.Fprintf(os.Stderr, "Warning: hostinventory dropping fact %s: %v\n", key, err)
		}
	}

	// --- agent provenance ---------------------------------------------------
	// agent.mode is emitted unconditionally: the mode bounds what the ABSENCE
	// of every other fact is allowed to mean (a remote collection cannot see
	// loopback sockets or a package database), so a report without it cannot be
	// read correctly.
	add(facts.KeyAgentMode, string(rep.Mode), di.ConfidenceReported)
	if rep.AgentID != "" {
		add(facts.KeyAgentID, rep.AgentID, di.ConfidenceReported)
	}

	// --- host ---------------------------------------------------------------
	if rep.SectionOK(SectionHost) {
		addIfSet(add, facts.KeyOSName, rep.Host.OS)
		addIfSet(add, facts.KeyOSVersion, rep.Host.OSVersion)
		addIfSet(add, facts.KeyOSKernel, rep.Host.Kernel)
	}

	// --- hardware -----------------------------------------------------------
	if rep.SectionOK(SectionHardware) {
		addIfSet(add, facts.KeyHWVendor, rep.Hardware.Vendor)
		addIfSet(add, facts.KeyHWModel, rep.Hardware.Model)
		addIfSet(add, facts.KeyHWSerial, rep.Hardware.Serial)
		addIfSet(add, facts.KeyHWUUID, rep.Hardware.UUID)
		addIfSet(add, facts.KeyHWFirmwareVersion, rep.Hardware.Firmware)
	}

	// --- interfaces ---------------------------------------------------------
	// Emitted as []map[string]any rather than as []Interface on purpose: the
	// redactor has no reflection fallback by design, so a typed struct would be
	// structurally invisible to Sanitize (see deviceinterrogation/redact.go).
	if rep.SectionOK(SectionInterfaces) && len(rep.Interfaces) > 0 {
		add(facts.KeyNetInterfaces, projectInterfaces(rep.Interfaces), di.ConfidenceReported)
	}

	// --- software -----------------------------------------------------------
	// sw.package_count is a COVERAGE fact, not an inventory: its job is to
	// distinguish "no software found" from "software was never enumerated". It
	// is therefore emitted only when the section succeeded, including when the
	// count is genuinely zero.
	if rep.SectionOK(SectionPackages) {
		add(facts.KeySWPackageCount, len(rep.Packages), di.ConfidenceReported)
	}

	// --- listening sockets --------------------------------------------------
	if rep.SectionOK(SectionListeners) && len(rep.Listeners) > 0 {
		add(facts.KeySvcListeningSockets, projectListeners(rep.Listeners), di.ConfidenceReported)
	}
	if rep.SectionOK(SectionBoundUDP) {
		add(facts.KeySvcBoundUdpSockets, projectBoundUDPSockets(rep.BoundUDPSockets), di.ConfidenceReported)
	}
	if rep.SectionOK(SectionConnections) {
		add(facts.KeyNetOutboundConnections, projectConnections(rep.Connections), di.ConfidenceReported)
	}

	// --- trust stores -------------------------------------------------------
	// SUMMARY ONLY, and counts for the same reason sw.package_count is a count:
	// what matters about a trust store is its SHAPE. Both numbers are emitted
	// whenever the section succeeded, INCLUDING when they are zero — a host
	// whose stores were read and held no stray key is a different statement
	// from a host whose stores were never read, and
	// certs.non_certificate_blocks is exactly the fact a hygiene finding
	// (BUILD_PLAN 3.5) will be computed from, so an absent zero would read as a
	// clean bill of health nobody issued.
	if rep.SectionOK(SectionCertStores) {
		certCount, nonCerts := 0, 0
		for _, store := range rep.CertStores {
			certCount += store.Count
			nonCerts += store.NonCertificateBlocks
		}
		add(facts.KeyCertsStoreCount, certCount, di.ConfidenceReported)
		add(facts.KeyCertsNonCertificateBlocks, nonCerts, di.ConfidenceReported)
	}

	// --- identity -----------------------------------------------------------
	result.DeviceIdentity = &di.DeviceIdentity{
		Vendor:          rep.Hardware.Vendor,
		Model:           rep.Hardware.Model,
		FirmwareVersion: rep.Hardware.Firmware,
		SerialNumber:    rep.Hardware.Serial,
		OSVersion:       strings.TrimSpace(rep.Host.OS + " " + rep.Host.OSVersion),
		// NO class hint. The collector measures an OS name, a vendor and a
		// model; what KIND of thing that makes the host is a RULE's decision
		// (ADR-0004 D6's curated table), and the consumer is the side that has
		// the table. "computer" looked harmless — this collector does run on
		// laptops as readily as on servers — but a hint reaches Approvals as a
		// proposal, and a plausible-looking proposal derived from no rule is
		// what gets bulk-approved. Absent shows as unclassified; wrong shows as
		// a fact. The consumer asks the Classifier seam with the vendor and
		// model this report carries, which is the one place the rules live.
		ClassHint: "",
	}

	// --- endpoints ----------------------------------------------------------
	// One endpoint per listening socket. These are ground truth for `runs_on`:
	// a socket the host itself reports is the only evidence that ties a service
	// to the machine rather than to an address that machine happens to answer
	// on today.
	for _, l := range rep.Listeners {
		result.Assets = append(result.Assets, listenerAsset(rep, l))
	}

	// --- metadata (allowlisted projections) ---------------------------------
	if rep.SectionOK(SectionPackages) && len(rep.Packages) > 0 {
		projected := make([]map[string]any, 0, len(rep.Packages))
		for _, p := range rep.Packages {
			projected = append(projected, projectPackage(p))
		}
		result.DeviceInfo["packages"] = projected
	}
	if rep.SectionOK(SectionCertStores) && len(rep.CertStores) > 0 {
		projected := make([]map[string]any, 0, len(rep.CertStores))
		for _, s := range rep.CertStores {
			projected = append(projected, projectCertStore(s))
		}
		result.DeviceInfo["cert_stores"] = projected
	}
	result.DeviceInfo["host_inventory"] = map[string]any{
		"collected":  rep.Collected.UTC().Format("2006-01-02T15:04:05Z07:00"),
		"mode":       string(rep.Mode),
		"platform":   rep.Platform,
		"sections":   projectSections(rep.Sections),
		"errors":     projectErrors(rep.Errors),
		"hostname":   rep.Host.Hostname,
		"fqdn":       rep.Host.FQDN,
		"identifier": projectIdentifiers(subject),
	}

	// The backstop, applied last, exactly as the Registry applies it to every
	// interrogator's output.
	di.Sanitize(result)
	return result, nil
}

// addIfSet emits a scalar fact only when there is a value.
//
// A registered string key with an empty value is not "the host answered with
// nothing" — it is "we did not learn this", and the registry has no way to say
// so in a value. Absence is the only honest encoding.
func addIfSet(add func(string, any, float64), key, value string) {
	if v := strings.TrimSpace(value); v != "" {
		add(key, v, di.ConfidenceReported)
	}
}

// hostPeerRef assembles the identifiers that name the host this report
// describes.
//
// The subject rides on every fact because a host-inventory report is not always
// about a device the platform already has a record of: in local mode there is
// no device row at all, and these identifiers are the only way the
// identification engine can bind the report to an asset.
//
// What is offered, and what deliberately is not:
//
//   - serial_number and the MAC of each NON-VIRTUAL interface. A veth, a
//     bridge or a tunnel MAC is generated, so minting identity from one
//     produces a new asset on every container restart. A locally-administered
//     MAC is excluded for the same reason, which is the rule the passive
//     host-observation contract already applies.
//   - hostname, and fqdn only when the host actually resolves one.
//   - the AGENT ID, in LOCAL mode only, and first. It is the strongest
//     identifier the product has — we issued it, and one installation names one
//     host — which is why ADR-0002 D3 puts it at the head of the precedence. It
//     is ALSO a registered fact (agent.id), and the two are not a duplication
//     but the two halves of one thing: the fact is provenance ("this agent
//     reported these values", the thing an operator needs when two collectors
//     disagree), the identifier is identity ("this is that host"). Only the
//     identifier can make a second collection land on the first one's asset.
//     Remote mode never offers it — the agent is not the thing being described,
//     and stamping its id on another host would give two assets one identity.
//   - NOT the hardware UUID. It identifies this host and it is a registered
//     fact (hw.uuid); a second identifier kind for it would be a second
//     spelling of a value that already has a home, and it buys nothing — the
//     agent id and the serial already outrank everything below them.
func hostPeerRef(rep *Report) di.PeerRef {
	// No ClassHint, for the reason ToObservations gives above it: a class is a
	// rule's decision, and this collector runs no rules.
	peer := di.PeerRef{DisplayName: displayName(rep)}

	if rep.Mode == ModeLocal && rep.AgentID != "" {
		peer.AddIdentifier(di.IdentifierAgentID, rep.AgentID)
	}
	if rep.SectionOK(SectionHardware) && rep.Hardware.Serial != "" {
		peer.AddIdentifier(di.IdentifierSerialNumber, rep.Hardware.Serial)
	}
	if rep.Host.Hostname != "" {
		peer.AddIdentifier(di.IdentifierHostname, rep.Host.Hostname)
	}
	if rep.Host.FQDN != "" {
		peer.AddIdentifier(di.IdentifierFQDN, rep.Host.FQDN)
	}
	if rep.SectionOK(SectionInterfaces) {
		for _, ifc := range rep.Interfaces {
			if ifc.Virtual || ifc.MAC == "" || locallyAdministered(ifc.MAC) {
				continue
			}
			peer.AddIdentifier(di.IdentifierMACAddress, ifc.MAC)
		}
	}
	return peer
}

// displayName is what an operator would recognise the host by.
func displayName(rep *Report) string {
	switch {
	case rep.Host.FQDN != "":
		return rep.Host.FQDN
	case rep.Host.Hostname != "":
		return rep.Host.Hostname
	default:
		return rep.Hardware.Serial
	}
}

// listenerAsset turns one listening socket into an endpoint.
//
// Protocol is the TRANSPORT, and the crypto fields are left nil throughout: a
// host inventory observes that something is listening, never what it
// negotiates. Leaving them nil is what keeps "not probed" distinguishable from
// "probed and found nothing" downstream — the same three-valued honesty that
// makes CryptoObserved a field on the results projection.
func listenerAsset(rep *Report, l Listener) di.CryptoAsset {
	asset := di.CryptoAsset{
		Hostname:  rep.Host.FQDN,
		IPAddress: l.Address,
		Port:      l.Port,
		Protocol:  l.Proto,
		// No AssetType. It was "server", which is the class guess ClassHint used
		// to make, one level down and in a field nothing validates: this
		// collector runs on laptops, and a socket says nothing about what the
		// machine holding it IS.
		Metadata: map[string]interface{}{
			"source":      "host_inventory",
			"agent_mode":  string(rep.Mode),
			"bound_local": isLoopback(l.Address),
		},
	}
	if asset.Hostname == "" {
		asset.Hostname = rep.Host.Hostname
	}
	if l.Process != "" {
		asset.ServiceHints = &di.ServiceHints{
			ServiceName: l.Process,
			// "reported" rather than "inferred": the host named the process
			// holding the socket, which is the strongest form of this claim
			// available anywhere in the product.
			Confidence:           "reported",
			IdentificationMethod: "host_socket_owner",
		}
	}
	return asset
}

// isLoopback reports whether a bound address is reachable only from the host.
// It is the fact a network scan can never establish, and the reason a local
// collection sees services no scan does.
//
// Parsed rather than prefix-matched. `bound_local` is a positive CLAIM about
// reachability, so getting it wrong on a spelling the string test did not
// anticipate — 0:0:0:0:0:0:0:1, ::ffff:127.0.0.1 — publishes "this service is
// reachable from the network" about one that is not. netip knows every
// spelling; a prefix test knows the two someone thought of.
func isLoopback(addr string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	return a.Unmap().IsLoopback()
}

// ---------------------------------------------------------------------------
// Allowlisted projections
// ---------------------------------------------------------------------------
//
// Each of these enumerates the fields that travel. Enumerating is the point:
// assigning a whole struct means a field added upstream ships without anyone
// deciding it should, which is how the UniFi collector came to persist a mesh
// PSK on every run. hostinventory_projection_test.go feeds each of these a
// value carrying poison and asserts it does not survive.

// projectInterfaces renders interfaces in the shape net.interfaces registers.
func projectInterfaces(ifaces []Interface) []map[string]any {
	out := make([]map[string]any, 0, len(ifaces))
	for _, i := range ifaces {
		entry := map[string]any{"name": i.Name}
		if i.MAC != "" {
			entry["mac"] = i.MAC
		}
		if len(i.Addresses) > 0 {
			entry["addresses"] = append([]string(nil), i.Addresses...)
		}
		if i.State != "" {
			entry["state"] = i.State
		}
		if i.Virtual {
			entry["virtual"] = true
		}
		out = append(out, entry)
	}
	return out
}

// projectListeners renders sockets in the shape svc.listening_sockets
// registers: address, port, transport, process.
func projectListeners(listeners []Listener) []map[string]any {
	out := make([]map[string]any, 0, len(listeners))
	for _, l := range listeners {
		entry := map[string]any{
			"port":      l.Port,
			"transport": l.Proto,
		}
		if l.Address != "" {
			entry["address"] = l.Address
		}
		if l.Process != "" {
			entry["process"] = l.Process
		}
		// Written UNCONDITIONALLY, including when false. "Reachable only from
		// this host" is a positive claim and so is its negation; omitting the
		// false would leave a reader unable to tell a socket measured as
		// network-facing from one whose binding nobody looked at. It is also
		// the one thing in this fact a network scan can never establish, which
		// is most of why a local collection is worth having.
		entry["bound_local"] = isLoopback(l.Address)
		// The PID is deliberately NOT carried into the fact. It identifies a
		// process on one boot of one machine, so it is meaningless the moment
		// the fact is read back, and a fact is a durable statement.
		out = append(out, entry)
	}
	return out
}

func projectBoundUDPSockets(sockets []BoundUDPSocket) []map[string]any {
	out := make([]map[string]any, 0, len(sockets))
	for _, s := range sockets {
		entry := map[string]any{"port": s.Port, "role": "unknown"}
		if s.Address != "" {
			entry["address"] = s.Address
		}
		if s.Process != "" {
			entry["process"] = s.Process
		}
		out = append(out, entry)
	}
	return out
}

func projectConnections(connections []Connection) []map[string]any {
	out := make([]map[string]any, 0, len(connections))
	for _, c := range connections {
		entry := map[string]any{
			"local_address":  c.LocalAddress,
			"remote_address": c.RemoteAddress,
			"remote_port":    c.RemotePort,
			"transport":      c.Proto,
		}
		if c.Process != "" {
			entry["process"] = c.Process
		}
		out = append(out, entry)
	}
	return out
}

// projectPackage enumerates the six fields a software install needs.
func projectPackage(p Package) map[string]any {
	entry := map[string]any{"name": p.Name}
	if p.Version != "" {
		entry["version"] = p.Version
	}
	if p.Vendor != "" {
		entry["vendor"] = p.Vendor
	}
	if p.Arch != "" {
		entry["arch"] = p.Arch
	}
	if p.Manager != "" {
		entry["manager"] = p.Manager
	}
	if p.PURL != "" {
		entry["purl"] = p.PURL
	}
	return entry
}

// projectCertStore enumerates a store's path, its count and the four posture
// fields of each certificate. There is no PEM and no key, here or in the type.
func projectCertStore(s CertStore) map[string]any {
	certs := make([]map[string]any, 0, len(s.Certs))
	for _, c := range s.Certs {
		entry := map[string]any{}
		if c.SubjectDN != "" {
			entry["subject_dn"] = c.SubjectDN
		}
		if c.IssuerDN != "" {
			entry["issuer_dn"] = c.IssuerDN
		}
		if c.FingerprintSHA256 != "" {
			entry["fingerprint_sha256"] = c.FingerprintSHA256
		}
		if c.NotAfter != "" {
			entry["not_after"] = c.NotAfter
		}
		certs = append(certs, entry)
	}
	out := map[string]any{"path": s.Path, "count": s.Count}
	if len(certs) > 0 {
		out["certs"] = certs
	}
	if s.NonCertificateBlocks > 0 {
		out["non_certificate_blocks"] = s.NonCertificateBlocks
	}
	return out
}

// projectSections copies the section outcomes. It is a string→string map, so
// the projection is a copy rather than an enumeration — but the copy is
// deliberate: handing the Report's own map over would let a later mutation of
// the Report change a result that has already been sanitised.
func projectSections(sections map[string]string) map[string]any {
	out := make(map[string]any, len(sections))
	for k, v := range sections {
		out[k] = v
	}
	return out
}

// projectErrors carries the step name and the bounded message.
func projectErrors(errs []StepError) []map[string]any {
	out := make([]map[string]any, 0, len(errs))
	for _, e := range errs {
		out = append(out, map[string]any{"step": e.Step, "message": e.Message})
	}
	return out
}

// projectIdentifiers renders the subject's identifiers for the metadata block,
// so a reader of a stored result can see what the report claimed to be without
// having to re-derive it from the facts.
func projectIdentifiers(peer di.PeerRef) []map[string]any {
	out := make([]map[string]any, 0, len(peer.Identifiers))
	for _, id := range peer.Identifiers {
		out = append(out, map[string]any{"kind": id.Kind, "value": id.Value})
	}
	return out
}
