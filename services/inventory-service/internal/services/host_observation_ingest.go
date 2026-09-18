package services

// The host-observation consumer (asset-inventory workstream 2.5, consumer half).
//
// A host observation is a passive statement that a device exists on a segment,
// with whatever identity the frame carried: a MAC, the addresses bound to it,
// the names it answers to, the manufacturer its OUI is registered to, and — for
// a switch or a phone that advertises itself — that device's own name and model.
// The producer half (sensor + pcap-processor, via shared/hostobs) has been
// emitting them since; discovery-processor held them at this boundary
// until this file existed.
//
// What makes it a separate builder rather than a branch inside
// discoveryObservation: almost nothing a crypto finding carries is present here.
// There is no port, no protocol version, no cipher suite, no endpoint, and
// often no address at all. What there IS instead — a MAC that identifies on its
// own, a set of names the host answered to, a vendor from the OUI table — has no
// equivalent on the crypto path. Threading both through one builder would mean a
// function whose every other line asks which kind it is holding.
//
// # The three things this must not do
//
// Each of these is why the rows were held back rather than let through, and each
// has a test that fails if it comes back.
//
//  1. **No resolver, ever.** The names in the payload ARE the measurement —
//     what the host called itself over DHCP, mDNS or NetBIOS. A reverse lookup
//     is a different claim from a different source, and the names are LAN-only:
//     resolving them sends the customer's internal host names to whatever
//     resolver the pod is configured with, from a feature whose whole premise
//     (and the reason it is on by default for air-gapped profiles) is that it
//     sends nothing onto the wire.
//     TestIntegration_HostObservation_IngestNeverResolves is the guard.
//  2. **Never external_connections.** That table records a CONNECTION between
//     two endpoints with a protocol and a cipher. A host observation has no
//     flow, no far end and no cryptography. An observation with no address
//     carries the documented dest_ip of 0.0.0.0, which is not RFC 1918, so the
//     ownership classifier called it `third_party` and the ingest wrote it
//     there — a row for a connection that never happened.
//  3. **Never a guessed class.** `_ipp._tcp` means printer and LLDP
//     `bridge+router` means a device that both bridges and routes, but those are
//     classification RULES and they live in a curated table (ADR-0004 D6), not
//     in a switch statement here. Workstream 2.10b wired that table in: the
//     evidence goes to shared/classify, a class it decides is recorded with
//     `class_source_kind: rule` and the id of the rule that argued it, and a
//     class it does NOT decide — including the case where two rules disagree —
//     leaves the asset `unknown_host`, coarse and true, which is the same choice
//     the PQC classifier's `unclassified` bucket makes.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// KindHostObservation is the IngestFinding.Kind marker for a passive
// host-presence row. It matches discovery-processor's converter constant and
// shared/approval's rule vocabulary; TestHostObservationKindSpellingIsShared
// pins the three together.
const KindHostObservation = "host_observation"

// hostObservationOwnership is the network ownership a passively observed host
// is recorded with.
//
// `unknown` — an address we have not placed in a registered segment — rather
// than `internal`, because that is exactly what we know. It is emphatically not
// `third_party`: that value means "a public endpoint something here connected
// OUT to", which is a statement about a flow, and it is the value the ordinary
// classifier returns for an observation whose dest_ip is 0.0.0.0 (not RFC 1918)
// or whose address is public but unregistered. Both are the classifier
// answering a question nobody asked it — a device on a segment we are watching
// is not a third party at any address.
//
// discovery-processor applies the same override before evaluating auto-approval
// (third_party can never auto-approve), so the two services agree.
const hostObservationOwnership = identity.OwnershipUnknown

// hostObservationPayload decodes the observation out of a finding's raw data.
//
// The payload is the `host_observation` key, put there by discovery-processor's
// converter exactly as shared/hostobs emitted it. It is round-tripped through
// JSON rather than type-asserted field by field because the typed struct is the
// contract: a field the producer renames stops arriving, loudly, instead of
// being read as an empty interface value.
func hostObservationPayload(f IngestFinding) (*hostobs.HostObservation, bool) {
	if f.RawData == nil {
		return nil, false
	}
	raw, ok := f.RawData["host_observation"]
	if !ok || raw == nil {
		return nil, false
	}
	blob, err := json.Marshal(raw)
	if err != nil {
		return nil, false
	}
	var obs hostobs.HostObservation
	if err := json.Unmarshal(blob, &obs); err != nil {
		return nil, false
	}
	return &obs, true
}

// isHostObservation reports whether a finding is a passive host-presence row.
//
// The KIND is the only thing consulted. The payload's presence is deliberately
// NOT part of the test: a finding marked `host_observation` whose payload is
// missing or unreadable must be REFUSED, not quietly re-routed onto the crypto
// path where every one of the three hazards above is waiting. "We could not read
// it" and "it is a crypto finding" are different answers.
func isHostObservation(f IngestFinding) bool {
	return f.Kind == KindHostObservation
}

// hostObservationObservation builds the identification-engine observation for a
// passively observed host.
//
// Identifier kinds are ADR-0002 D3's, mapped from the payload as the wire
// contract's consumer-obligations table says:
//
//	mac          → mac_address   (unscoped: a MAC is globally unique)
//	fqdns[]      → fqdn          (unscoped: a qualified name is globally unique)
//	hostnames[]  → hostname      (scoped by segment)
//	addresses[]  → ip_address    (scoped by ITS OWN segment)
//
// A MAC ALONE IS ENOUGH. That is the case this whole path exists for: an ARP
// frame from a device that answers no name and has not been given an address
// still says "this thing is here, and here is its hardware address", and
// `unknown_host` lists mac_address second in its identifier precedence so the
// engine can match on it. An observation carrying NOTHING attachable is still
// refused — errNoIdentifiers — because an asset nothing can ever match again
// becomes a new asset on every coalescing window.

// classHintForSelfReport turns a sensor's own registered platform/profile
// into a class HINT — the FLOOR an observation starts from, same status as
// assetclass.KeyUnknownHost, and still overridable by the curated rule table
// (applyClassProposal) below it. It is NOT an applied classification:
// class_source_kind stays whatever the rule table (or nothing) decides, the
// same "propose, do not apply" discipline host_inventory_ingest.go documents
// for the device-agent path ("Never guess a class... turning evidence into a
// class is a RULE's job").
//
// Deliberately a small, explicit heuristic rather than a lookup table: sensor
// profiles today are effectively a single value in practice
// (config.Profile defaults to "datacenter_host" for every sensor install —
// only the unrelated device-agent uses "device_interrogation"), so platform is
// doing almost all of the work. Flagged in the PR for the owner to review;
// widening sensor install profiles to a real workstation/laptop vocabulary
// would make this a straightforward lookup instead of a guess about Windows
// and macOS sensor hosts.
func classHintForSelfReport(ho *hostobs.HostObservation) assetclass.Key {
	if ho == nil || strings.TrimSpace(ho.AgentID) == "" {
		return assetclass.KeyUnknownHost
	}
	platform := strings.ToLower(strings.TrimSpace(ho.Platform))
	profile := strings.ToLower(strings.TrimSpace(ho.Profile))
	switch platform {
	case "linux":
		if profile == "" || strings.Contains(profile, "server") ||
			strings.Contains(profile, "datacenter") || strings.Contains(profile, "cloud") {
			return assetclass.KeyServer
		}
		return assetclass.KeyComputer
	case "windows", "darwin", "macos":
		return assetclass.KeyWorkstation
	default:
		return assetclass.KeyComputer
	}
}

func (s *AssetService) hostObservationObservation(tenantID uuid.UUID, f IngestFinding, ho *hostobs.HostObservation) (identity.Observation, error) {
	obs := identity.Observation{
		TenantID:   tenantID.String(),
		Source:     hostObservationSource(f),
		ObservedAt: hostObservationTime(f, ho),
		Confidence: hostObservationConfidence(f, ho),
		Network: identity.Network{
			Ownership: hostObservationOwnership,
			Type:      findingNetworkType(f),
		},
		// Coarse and true, and the FLOOR rather than the answer. Workstream
		// 2.10b hands this observation to the curated rule table before it is
		// resolved (see ingestHostObservation); when the rules decide a class
		// this is replaced, with `class_source_kind: rule` and a
		// `class_source_ref` naming the row. When they do not — or when they
		// contradict each other — it stands, which is the same honesty as the
		// PQC classifier's `unclassified` bucket.
		//
		// A SELF-report (ho.AgentID set) starts from a smarter floor: the
		// sensor's own registered platform/profile, which is real evidence
		// about the host it runs on, not a guess. See
		// classHintForSelfReport — it is still a HINT, exactly like
		// KeyUnknownHost is, and the rule table below can still override it.
		ClassHint: classHintForSelfReport(ho),
	}

	if agentID := strings.TrimSpace(ho.AgentID); agentID != "" {
		// The strongest identifier kind there is (shared/identity/identifier.go:
		// "a host agent's own installation id... because we issued it"). Set
		// ONLY on a sensor's self-report of the host it runs on — every
		// passively decoded observation leaves AgentID empty. Confidence 1: an
		// agent's own id is not graded on the arp/dhcp/mdns ladder that grades
		// how directly a THIRD PARTY's frame states an identity.
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindAgentID, Value: agentID, Confidence: 1,
		})
	}

	// The scope weak identifiers live in. Addresses are scoped individually
	// below — a host with an address in two segments is a real thing, and
	// scoping both to whichever one happened to be first would make one of them
	// identify in a segment it is not in.
	primaryAddr := hostObservationPrimaryAddress(ho)
	bestName := hostObservationBestName(ho)
	nameScope, nameScopeDynamic := s.observationScope(tenantID, primaryAddr, bestName)
	obs.Network.SegmentID = nameScope
	dynamic := map[string]bool{}
	if nameScopeDynamic {
		dynamic[nameScope] = true
	}

	if mac := strings.TrimSpace(ho.MAC); mac != "" {
		// Computed here as well as read from the payload: an older sensor
		// binary sends no `mac_virtual`, and the rule has to hold for it too.
		virtualProto, virtual := hostobs.VirtualMACProtocol(mac)
		if virtual || ho.MACVirtual {
			// A first-hop-redundancy virtual router MAC (VRRP, CARP, HSRP,
			// GLBP — shared/hostobs/virtualmac.go). It belongs to the floating
			// address's GROUP, not to a chassis, and moves to the standby
			// router at failover: keying a node on it makes the standby
			// "become" the active router every time. Same treatment as a
			// locally-administered MAC, for the same reason — identifier
			// confidence does not affect voting, so "attach weakly" is
			// indistinguishable from attaching. Recorded as an attribute
			// (hostObservationMetadata) so the row stays explicable.
			log.Printf("[AssetService] host observation %s: MAC %s is a %s virtual router address; not used as an identifier (it moves with the floating address)",
				hostObservationLabel(ho), mac, orDefault(virtualProto, "first-hop-redundancy"))
		} else if ho.MACLocallyAdministered {
			// The U/L bit is set: a randomised iOS/Android Wi-Fi address, a
			// virtual NIC, or a spoofed one. It is not a stable key — the device
			// rotates it — and attaching it would create a fresh asset on every
			// rotation, each holding a MAC that will never be seen again.
			//
			// It is dropped as an IDENTIFIER rather than attached weakly,
			// because identifier confidence does not affect whether a kind votes
			// (Engine.kindVotes reads scope, not confidence), so "attach it with
			// low confidence" would be indistinguishable from attaching it. The
			// observation is then identified by its names and addresses if it
			// carries any, and refused if it does not — which is the honest
			// outcome for a frame whose only identity is a number that changes.
			//
			// The value is still RECORDED, as an attribute, so the row is
			// explicable to a human looking at why no asset appeared.
			log.Printf("[AssetService] host observation %s: MAC %s is locally administered; not used as an identifier (it rotates)",
				hostObservationLabel(ho), mac)
		} else {
			obs.Identifiers = append(obs.Identifiers, identity.Identifier{
				Kind: identity.KindMACAddress, Value: mac, Confidence: 1,
			})
		}
	}

	// An FQDN is globally unique and needs no scope; a short name identifies
	// only within one. The producer has already filed each name under the right
	// heading (shared/hostobs addName), so this does not re-derive it — and it
	// must not: "an IP is never a hostname" is enforced at the source, where a
	// name that parses as an address never becomes a name at all.
	//
	// EXCEPT `.local`. An mDNS name is link-scoped by definition (RFC 6762 §3):
	// "printer.local" on one VLAN and "printer.local" on another are two hosts,
	// and nothing about the name says which. Filing it as an unscoped, globally
	// unique fqdn let one name DECIDE a match across segments — which is how a
	// gateway that reflected a laptop's announcement onto the sensor's VLAN
	// then absorbed the laptop's own observation from its home VLAN, decided
	// by fqdn, and with it the laptop's SSH endpoint. The whole name is kept
	// (a CMDB can still join on it) but as a hostname, scoped to the segment
	// the observation was made in, so it identifies where mDNS says it does.
	for _, fqdn := range ho.FQDNs {
		v := strings.TrimSpace(fqdn)
		if v == "" || isIPLiteral(v) {
			continue
		}
		if isMDNSLocalName(v) {
			obs.Identifiers = append(obs.Identifiers, identity.Identifier{
				Kind: identity.KindHostname, Value: v, Scope: nameScope, Confidence: 1,
			})
			continue
		}
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindFQDN, Value: v, Confidence: 1,
		})
	}
	for _, name := range ho.Hostnames {
		if v := strings.TrimSpace(name); v != "" && !isIPLiteral(v) {
			obs.Identifiers = append(obs.Identifiers, identity.Identifier{
				Kind: identity.KindHostname, Value: v, Scope: nameScope, Confidence: 1,
			})
		}
	}

	for _, addr := range ho.Addresses {
		if !addr.IsValid() || addr.IsUnspecified() {
			// 0.0.0.0 is the `dest_ip NOT NULL` column compromise, not an
			// address. shared/hostobs already refuses to record it, so this is
			// belt and braces against a hand-built payload.
			continue
		}
		v := addr.String()
		scope, scopeDynamic := s.observationScope(tenantID, &v, nil)
		if scopeDynamic {
			// An address handed out by DHCP is today's lease and tomorrow's
			// other host. The identifier is still RECORDED — it is true, and it
			// is what the asset's primary_address is taken from — but naming the
			// scope here is what stops it DECIDING a match (Engine.kindVotes).
			dynamic[scope] = true
		}
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindIPAddress, Value: v, Scope: scope, Confidence: 1,
		})
	}
	if len(dynamic) > 0 {
		obs.DynamicScopes = dynamic
	}

	// The ARP decoder's evidence, for the engine's floating-address rule. A
	// gratuitous ARP is the announcer CLAIMING the address, which corroborates
	// "node X announces VIP Y" when the MAC and the address resolve to two
	// assets. Only these two keys travel: Observation.Attributes is read by
	// the engine on an allowlist (SummaryAttributeKeys for the matcher; these
	// for the rule), and the rest of the decoder's attributes stay in the
	// asset's metadata where they always were.
	for _, key := range []string{"arp_gratuitous", "arp_operation"} {
		if v, ok := ho.Attributes[key]; ok {
			if obs.Attributes == nil {
				obs.Attributes = map[string]any{}
			}
			obs.Attributes[key] = v
		}
	}

	// Display name and hostname are context, not identity: the authoritative
	// list is Identifiers. A host with no name at all displays as its address,
	// and one with neither displays as its MAC — which is the only thing we were
	// told about it, and better than a blank row in Approvals.
	if bestName != nil {
		obs.Hostname = strings.ToLower(*bestName)
		obs.DisplayName = obs.Hostname
	} else if primaryAddr != nil {
		obs.DisplayName = *primaryAddr
	} else if ho.MAC != "" {
		obs.DisplayName = ho.MAC
	}

	// NO ENDPOINTS. A passive frame proves an address is bound to this host,
	// which the ip_address identifier already records and which the engine turns
	// into the asset's primary_address. An asset_endpoints row is a claim about a
	// reachable FACE — an address/port/transport something could connect to —
	// and nothing connected to anything here. `port = 0` in the stored row means
	// "not an endpoint", and this is what honouring that looks like.

	clean, rejected := obs.Sanitize()
	for _, r := range rejected {
		// One malformed identifier must not lose the whole observation, but the
		// reject is logged rather than dropped.
		log.Printf("[AssetService] host observation %s: dropped a %s identifier: %v",
			hostObservationLabel(ho), r.Identifier.Kind, r.Err)
	}
	if len(clean.Identifiers) == 0 {
		return identity.Observation{}, fmt.Errorf("%w: host observation %s", errNoIdentifiers, hostObservationLabel(ho))
	}
	return clean, nil
}

// isMDNSLocalName reports whether a qualified name is in the mDNS link-local
// domain (`.local`, RFC 6762 §3), which is the one TLD a name can carry and
// still identify a host only on the link it was heard on.
func isMDNSLocalName(name string) bool {
	return hostnamequality.IsMDNSLocalName(name)
}

// isIPLiteral reports whether a name is really an address written down.
//
// AN IP IS NEVER A HOSTNAME (ADR-0002 D3). A name identifier holding "10.0.0.5"
// would be matched against other NAMES, never against the ip_address identifier
// for the same value — so one host reached by both would become two assets, and
// the address-in-a-name-slot would be scoped as a hostname and vote in a dynamic
// segment where the real ip_address identifier is forbidden to.
//
// shared/hostobs will not produce one (its names come from DNS/NetBIOS name
// fields), so this is a second lock on a door that is already shut. It costs a
// parse per name and removes the possibility of a hand-built or future payload
// walking through.
func isIPLiteral(name string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(name))
	return err == nil
}

// hostObservationPrimaryAddress returns the first real address, or nil when the
// observation carries none — which is a normal and expected case (an LLDP frame
// with only a chassis MAC, an ARP probe from a host that has not been given an
// address yet).
func hostObservationPrimaryAddress(ho *hostobs.HostObservation) *string {
	for _, a := range ho.Addresses {
		if a.IsValid() && !a.IsUnspecified() {
			v := a.String()
			return &v
		}
	}
	return nil
}

// hostObservationBestName picks the highest-quality name the host answered to.
// First-FQDN-wins kept hex `.local` advertisements in front of a later DHCP
// hostname (`linux-2`). Nil when the host answered to none.
func hostObservationBestName(ho *hostobs.HostObservation) *string {
	names := make([]string, 0, len(ho.FQDNs)+len(ho.Hostnames))
	names = append(names, ho.FQDNs...)
	names = append(names, ho.Hostnames...)
	if v := hostnamequality.Best(names...); v != "" {
		return &v
	}
	return nil
}

// hostObservationSource attributes the observation to the capture that made it.
//
// Mode is PASSIVE for every ordinary decoder — arp/dhcp/mdns/lldp/cdp all read
// frames that were going to be on the wire anyway — but ACTIVE for a sensor's
// SELF-report (hostObservationIsSelfReport): os.Hostname() and the host's own
// interface table are not "traffic this device happened to see", they are the
// host measuring itself, which identity.ModeActive is documented to rank above
// ModePassive when two measured values disagree (shared/identity/reconcile.go).
// The ref distinguishes the standalone sensor from the platform's own capture,
// because "which sensor told us this" is the question an operator asks of a
// surprising asset, and because the two are different fact producers
// (shared/facts `sensor` vs `platform-sensor`).
func hostObservationSource(f IngestFinding) identity.Source {
	ref := "sensor"
	if hostObservationIsPlatformCapture(f) {
		ref = "sensor:pcap"
	}
	if id := strings.TrimSpace(derefString(f.SourceSensorID)); id != "" {
		ref += ":" + id
	}
	mode := identity.ModePassive
	if hostObservationIsSelfReport(f) {
		mode = identity.ModeActive
	}
	return identity.Source{Kind: identity.SourceMeasured, Ref: ref, Mode: mode}
}

// hostObservationIsPlatformCapture reports whether the row came from the
// platform's own capture (an uploaded PCAP, processed in-cluster) rather than
// from a sensor on the customer's network.
//
// Read from `discovery_method`, which the two producers write differently and
// deliberately: the sensor writes `passive_host_observation`, pcap-processor
// writes `pcap_upload`.
func hostObservationIsPlatformCapture(f IngestFinding) bool {
	switch strings.ToLower(rawDataString(f.RawData, "discovery_method")) {
	case "pcap_upload", "pcap":
		return true
	}
	return false
}

// hostObservationIsSelfReport reports whether the row is a sensor's SELF-report
// of the host it runs on (asset-inventory decision 9) rather than a passive
// capture of some OTHER host. Read the same way
// hostObservationIsPlatformCapture reads its own marker: sensor-manager's
// services/self_observation.go writes `discovery_method: "sensor_self_report"`,
// distinct from the sensor's own passive `passive_host_observation` and
// pcap-processor's `pcap_upload`.
func hostObservationIsSelfReport(f IngestFinding) bool {
	return strings.ToLower(rawDataString(f.RawData, "discovery_method")) == "sensor_self_report"
}

// hostObservationFactProducer is the shared/facts producer key the observation's
// facts are written under.
//
// It must be one the registry lists for every key in the payload, or
// UpsertFacts refuses the write — which is the correct failure (it means two
// subsystems disagree about who owns a fact) and is why this is derived rather
// than hard-coded to one value.
func hostObservationFactProducer(f IngestFinding) string {
	if hostObservationIsPlatformCapture(f) {
		return "platform-sensor"
	}
	return "sensor"
}

// hostObservationTime is when the host was seen.
//
// The payload's own `observed_at` wins: it is the capture timestamp of the
// latest frame that contributed, which is the measurement. The finding's
// envelope timestamp is the fallback, and a zero time is left zero so the engine
// stamps its own clock rather than this inventing one.
func hostObservationTime(f IngestFinding, ho *hostobs.HostObservation) time.Time {
	if !ho.ObservedAt.IsZero() {
		return ho.ObservedAt.UTC()
	}
	return findingObservedAt(f)
}

// hostObservationConfidence is how directly the subject stated its own identity.
//
// The producer already graded it — shared/hostobs.Confidence, the one ladder the
// sensor and pcap-processor both use — and the value travelled here on the row.
// Reading it back rather than re-deriving is the point: a second ladder here
// would be a second opinion about one measurement, and the two would drift the
// way the pcap path's flat 0.85 drifted from the sensor's grading.
//
// Recomputing from the payload is the fallback for a row that carries no
// confidence at all (zero, which on this scale means NOT ASSESSED). That is not
// a second opinion — it is the same function, applied to the same observation,
// one step later.
func hostObservationConfidence(f IngestFinding, ho *hostobs.HostObservation) float64 {
	if c := findingConfidence(f); c > 0 {
		return c
	}
	return hostobs.Confidence(ho)
}

// hostObservationLabel renders an observation for a log line, most specific
// identity first.
func hostObservationLabel(ho *hostobs.HostObservation) string {
	if ho == nil {
		return "(nil)"
	}
	if n := hostObservationBestName(ho); n != nil {
		return *n
	}
	if ho.MAC != "" {
		return ho.MAC
	}
	if a := hostObservationPrimaryAddress(ho); a != nil {
		return *a
	}
	return "(no identity)"
}

// hostObservationFacts projects the payload's registered-key map onto the rows
// asset_facts stores.
//
// The map is written AS GIVEN. shared/hostobs already restricted it to keys the
// registry lists the sensor producers for (hw.vendor, hw.model,
// net.mdns_services), UpsertFacts re-checks both the key and the producer, and
// re-deriving anything here would be a second opinion about a measurement
// somebody else made.
//
// # What is deliberately not written
//
//   - **net.neighbors.** There is none in the payload and there never will be. A
//     captured LLDP or CDP frame proves the ADVERTISER exists; it does not
//     establish that the advertiser is attached to the sensor's host, because a
//     sensor is normally fed by a mirror or SPAN port and the frame arrived by
//     being COPIED there. Synthesising one from `capture_interface` or an
//     `lldp_port_id` attribute would attach a fabricated edge to the sensor's own
//     asset, and mirror placement makes that the common case rather than the rare
//     one.
//   - **net.interfaces.** For the same reason plus two more. `capture_interface`
//     names the SENSOR's interface, not the observed host's — writing it as the
//     subject's interface list would attribute one machine's NIC to another. An
//     `lldp_port_id` is the advertiser's own port, but it is ONE port, and
//     net.interfaces is documented as "every network interface the device has":
//     a one-element list built from the single port that happened to send a frame
//     is a claim about completeness that nothing measured. And the registry does
//     not list `sensor` as a producer for the key at all, so the write would be
//     refused — correctly, as the registry saying the same thing.
//   - **attributes.** Decoder-specific and deliberately unregistered; the wire
//     contract calls them evidence, not statements. They travel in the asset's
//     metadata (see hostObservationMetadata) where a human and a future
//     classifier can read them, and not into asset_facts, which is the contract
//     for what the platform stores AS A FACT.
func hostObservationFacts(ho *hostobs.HostObservation, source identity.Source, observedAt time.Time, confidence float64) []pgidentity.Fact {
	if len(ho.Facts) == 0 {
		return nil
	}
	out := make([]pgidentity.Fact, 0, len(ho.Facts))
	for key, value := range ho.Facts {
		out = append(out, pgidentity.Fact{
			Key:   key,
			Value: value,
			// MEASURED, not inferred: a frame stated this. An inferred fact
			// would owe a model id and a confidence (ADR-0005 D2), and there is
			// no model here — the OUI table is a lookup, not a judgement.
			SourceKind: identity.SourceMeasured,
			SourceRef:  source.Ref,
			Confidence: confidence,
			ObservedAt: observedAt,
		})
	}
	return out
}

// hostObservationMetadata is the asset-level record of where this came from and
// what the frames carried that is not a fact.
//
// `attributes` lands here rather than in asset_facts on purpose — see
// hostObservationFacts. The locally-administered MAC lands here too: it is not
// an identifier (it rotates) but dropping it silently would leave an asset in
// Approvals with no explanation of what was actually seen.
func hostObservationMetadata(f IngestFinding, ho *hostobs.HostObservation) models.JSONB {
	out := discoverySourceMetadata(f)
	out["discovery_kind"] = KindHostObservation
	if len(ho.Sources) > 0 {
		out["host_observation_sources"] = ho.Sources
	}
	if len(ho.Attributes) > 0 {
		out["host_observation_attributes"] = ho.Attributes
	}
	if ho.MAC != "" && ho.MACLocallyAdministered {
		out["host_observation_local_mac"] = ho.MAC
	}
	if ho.MAC != "" {
		if proto, ok := hostobs.VirtualMACProtocol(ho.MAC); ok || ho.MACVirtual {
			// The virtual router MAC, kept the same way: not an identifier,
			// but not lost either.
			out["host_observation_virtual_mac"] = ho.MAC
			if proto != "" {
				out["host_observation_virtual_mac_protocol"] = proto
			}
		}
	}
	return out
}

// ingestHostObservation turns one host observation into an asset, or explains
// why it did not.
//
// The whole unit — the asset, its identifiers, its facts, its context and its
// status — lands in ONE transaction, the engine's. One observation is one fact
// about the world; splitting it would leave an asset whose history says it was
// created and whose facts say nothing was measured, and no later run repairs
// that because the next observation MATCHES the asset that exists and never
// takes the create path again.
func (s *AssetService) ingestHostObservation(ctx context.Context, tenantID uuid.UUID, f IngestFinding, assetStatus string) (identity.Resolution, error) {
	ho, ok := hostObservationPayload(f)
	if !ok {
		return identity.Resolution{}, fmt.Errorf("finding is marked %s but carries no readable host_observation payload", KindHostObservation)
	}

	obs, err := s.hostObservationObservation(tenantID, f, ho)
	if err != nil {
		return identity.Resolution{}, err
	}

	// The rules, over what the frames actually carried (workstream 2.10b). This
	// is the path row 7 of the 2.5 note was waiting on: the OUI vendor, the
	// stated model, the mDNS service types and the LLDP/CDP capability bits were
	// all already being decoded and stored, and none of them could reach a class
	// because there was nowhere honest to record one. `class_source_kind: rule`
	// is that place.
	classProp := s.applyClassProposal(ctx, &obs, hostObservationClassEvidence(ho))

	facts := hostObservationFacts(ho, obs.Source, obs.ObservedAt, obs.Confidence)
	ctxInput := models.AssetInput{
		Metadata: hostObservationMetadata(f, ho),
	}
	ownership := hostObservationOwnership
	ctxInput.AssetOwnership = &ownership
	if tags, _ := s.getTagsForAsset(tenantID, hostObservationPrimaryAddress(ho), hostObservationBestName(ho)); len(tags) > 0 {
		ctxInput.Tags = mergeTags(models.JSONB{}, tags)
	}

	return s.resolveObservationWithRepo(ctx, obs, func(repo *pgidentity.Repository, tx *sqlx.Tx, res identity.Resolution) error {
		if res.Asset.Zero() {
			// The identity floor: every identifier belongs to somebody else and
			// none could decide, so the engine opened a merge proposal and wrote
			// nothing. There is no asset to hang facts or context on.
			return nil
		}
		assetID, perr := uuid.Parse(res.Asset.ID)
		if perr != nil {
			return fmt.Errorf("identification engine returned an unusable asset id %q: %w", res.Asset.ID, perr)
		}
		if res.Outcome != identity.OutcomeConflict {
			if err := repo.ProjectSegmentLocation(ctx, res.Asset, obs.Network.SegmentID, obs.Source); err != nil {
				return err
			}
		}
		if cerr := s.applyAssetContext(tx, tenantID, assetID, ctxInput, obs.Source, res.Outcome); cerr != nil {
			return cerr
		}
		if len(facts) > 0 {
			// On the ENGINE's repository, so the facts share its transaction.
			// Going through s.identityRepo here would open a second transaction
			// on the pool while this one still holds the asset row uncommitted,
			// and UpsertFacts' assertAssetExists would not be able to see it.
			if ferr := repo.UpsertFacts(ctx, res.Asset, hostObservationFactProducer(f), facts); ferr != nil {
				return fmt.Errorf("writing host-observation facts: %w", ferr)
			}
		}
		if cerr := s.recordClassOutcome(ctx, tx, tenantID, assetID, res.Outcome, classProp); cerr != nil {
			return cerr
		}
		if agentID := strings.TrimSpace(ho.AgentID); agentID != "" {
			// Link the sensor to the asset its own self-report resolved to —
			// in the SAME transaction as everything else this observation
			// wrote, so the link is atomic with the asset it points at. This
			// is also the RETRO-LINK path: an existing anonymous unknown_host
			// asset holding only this host's MAC/IP (a real deployment shape:
			// seen passively by another sensor before this one ever reported
			// itself) is exactly what res.Asset already is when the engine
			// matched on mac_address/ip_address, so linking here covers both
			// "created fresh" and "matched existing" without a separate code
			// path.
			//
			// `sensors` belongs to sensor-manager, not this service, but both
			// read/write the one shared database — sensorrouting.Store
			// already SELECTs from `sensors` for the same reason (see its
			// TenantSensors). agentID is the sensor's own id (it set AgentID
			// to sensorID.String() — see sensor-manager's
			// selfHostObservation), so no separate lookup is needed.
			if sensorID, perr := uuid.Parse(agentID); perr == nil {
				if lerr := s.linkSensorAsset(tx, tenantID, sensorID, assetID); lerr != nil {
					return fmt.Errorf("linking sensor %s to its host asset: %w", sensorID, lerr)
				}
			}
			// Upgrade the class on the RETRO-LINK path (asset MATCHED an
			// existing row rather than being created): classForCreate's
			// ClassHint only ever applies at creation, by design — an
			// observation must not overwrite a class an asset already HAS,
			// the same invariant classproposal documents ("It never sets a
			// class on an existing asset... a rule that changed its mind six
			// months after somebody approved a class would be a silent
			// rewrite"). This is the one narrow, deliberate exception: it
			// fires ONLY while the asset's class is still the unassigned
			// floor (unknown_host) — nothing has been decided yet, by a rule,
			// a human, or anything else — and the evidence is the sensor's
			// own self-report, not a guess. Flagged for the owner in the PR:
			// this reaches past the ordinary class-proposal review queue on
			// the reasoning that "nothing was ever decided" is different from
			// "something was decided and this disagrees."
			if hint := classHintForSelfReport(ho); hint != assetclass.KeyUnknownHost {
				if cerr := upgradeUnknownHostClass(ctx, tx, tenantID, assetID, hint, "sensor:"+agentID); cerr != nil {
					return fmt.Errorf("upgrading class for sensor %s's host asset: %w", agentID, cerr)
				}
			}
		}
		if res.Outcome != identity.OutcomeConflict && assetStatus != "" && assetStatus != identity.StatusPendingApproval {
			return s.setStatusUnlessArchived(tx, tenantID, assetID, assetStatus, obs.Source)
		}
		return nil
	})
}

// linkSensorAsset records that sensorID's own host resolved to assetID — the
// "sensors.asset_id" link the sensor-routing "never scan yourself" guard
// reads (services/inventory-service/internal/sensorrouting.Store.TenantSensors)
// and the Sensors & Agents page's "Host" line reads. tenant_id is part of the
// predicate as the repo's belt-and-braces rule requires even though sensors
// is not RLS-scoped through this service's connection.
func (s *AssetService) linkSensorAsset(tx *sqlx.Tx, tenantID, sensorID, assetID uuid.UUID) error {
	_, err := tx.Exec(
		`UPDATE sensors SET asset_id = $1, updated_at = now() WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL`,
		assetID, sensorID, tenantID,
	)
	return err
}

// upgradeUnknownHostClass moves an asset off the unassigned unknown_host
// floor onto hint, source-kind `measured` (a self-report is the host
// measuring itself, ADR-0002 D4's precedence — see hostObservationSource's
// Mode: ModeActive for the same reasoning). The `class_key = 'unknown_host'`
// predicate is the whole safety property: it is a no-op the moment anything
// — a rule, a human, an import — has ever set a real class, same shape as
// applyProposedClass (class_proposal_service.go) which this mirrors for the
// one case that never goes through Approvals.
func upgradeUnknownHostClass(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, hint assetclass.Key, sourceRef string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE assets
		   SET class_key = $3,
		       class_path = $4,
		       class_source_kind = 'measured',
		       class_source_ref = $5,
		       class_confidence = 1,
		       updated_at = now()
		 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL AND class_key = 'unknown_host'`,
		tenantID, assetID, string(hint), classPathForKey(string(hint)), sourceRef,
	)
	return err
}
