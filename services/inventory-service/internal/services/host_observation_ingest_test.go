package services

// The host-observation observation builder (workstream 2.5, consumer half).
//
// These are pure-unit: an AssetService with no database, which is the shape
// observationScope handles by returning the tenant-default scope. What they pin
// is the set of decisions the wire contract's "consumer's obligations" section
// names, plus the three things the builder must refuse to do.

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// hostObsFinding wraps a payload the way discovery-processor's converter does:
// the observation under `host_observation`, the kind on the finding.
func hostObsFinding(t *testing.T, ho *hostobs.HostObservation, extra map[string]interface{}) IngestFinding {
	t.Helper()
	blob, err := json.Marshal(ho)
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatalf("unmarshal observation: %v", err)
	}
	raw := map[string]interface{}{
		"host_observation": generic,
		"source":           "sensor_discovery",
		"kind":             KindHostObservation,
		"discovery_method": "passive_host_observation",
	}
	for k, v := range extra {
		raw[k] = v
	}
	return IngestFinding{
		Kind:           KindHostObservation,
		Protocol:       "HOST",
		IPAddress:      ptr("0.0.0.0"),
		SourceSensorID: ptr("11111111-2222-3333-4444-555555555555"),
		RawData:        raw,
	}
}

func mustAddrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("bad test address %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

func buildHostObs(t *testing.T, svc *AssetService, ho *hostobs.HostObservation) (identity.Observation, error) {
	t.Helper()
	ho.Finalize()
	f := hostObsFinding(t, ho, nil)
	payload, ok := hostObservationPayload(f)
	if !ok {
		t.Fatal("the finding this test built carries no readable payload")
	}
	return svc.hostObservationObservation(uuid.New(), f, payload)
}

// --- one case per source ----------------------------------------------------

// Each decoder's characteristic shape becomes the identifiers the wire
// contract's mapping table says it should. The table is per-source because the
// sources differ in exactly what they carry, which is the whole reason the
// confidence ladder grades them differently.
func TestHostObservationBuilder_PerSource(t *testing.T) {
	cases := []struct {
		name        string
		obs         hostobs.HostObservation
		wantKinds   map[identity.Kind]string
		wantAbsent  []identity.Kind
		wantDisplay string
	}{
		{
			// ARP: a MAC and the address bound to it. No name at all.
			name: "arp",
			obs: hostobs.HostObservation{
				Source:    hostobs.SourceARP,
				MAC:       "28:cf:da:11:22:33",
				Addresses: mustAddrs(t, "192.0.2.50"),
			},
			wantKinds: map[identity.Kind]string{
				identity.KindMACAddress: "28:cf:da:11:22:33",
				identity.KindIPAddress:  "192.0.2.50",
			},
			wantAbsent:  []identity.Kind{identity.KindHostname, identity.KindFQDN},
			wantDisplay: "192.0.2.50",
		},
		{
			// DHCP: option 12 gives the host's own name alongside the lease.
			name: "dhcp with hostname",
			obs: hostobs.HostObservation{
				Source:    hostobs.SourceDHCP,
				MAC:       "28:cf:da:11:22:34",
				Addresses: mustAddrs(t, "192.0.2.51"),
				Hostnames: []string{"acct-ws-14"},
			},
			wantKinds: map[identity.Kind]string{
				identity.KindMACAddress: "28:cf:da:11:22:34",
				identity.KindIPAddress:  "192.0.2.51",
				identity.KindHostname:   "acct-ws-14",
			},
			wantAbsent:  []identity.Kind{identity.KindFQDN},
			wantDisplay: "acct-ws-14",
		},
		{
			// mDNS: a qualified .local name and the services it advertises.
			name: "mdns",
			obs: hostobs.HostObservation{
				Source:    hostobs.SourceMDNS,
				MAC:       "28:cf:da:11:22:35",
				Addresses: mustAddrs(t, "192.0.2.52"),
				FQDNs:     []string{"hp-printer.local"},
				Hostnames: []string{"hp-printer"},
				Services:  []string{"_ipp._tcp"},
			},
			wantKinds: map[identity.Kind]string{
				identity.KindMACAddress: "28:cf:da:11:22:35",
				identity.KindFQDN:       "hp-printer.local",
				identity.KindHostname:   "hp-printer",
				identity.KindIPAddress:  "192.0.2.52",
			},
			wantDisplay: "hp-printer.local",
		},
		{
			// NetBIOS: a machine name from a node-status response.
			name: "nbns",
			obs: hostobs.HostObservation{
				Source:    hostobs.SourceNBNS,
				MAC:       "28:cf:da:11:22:36",
				Addresses: mustAddrs(t, "192.0.2.53"),
				Hostnames: []string{"ws1"},
			},
			wantKinds: map[identity.Kind]string{
				identity.KindMACAddress: "28:cf:da:11:22:36",
				identity.KindHostname:   "ws1",
				identity.KindIPAddress:  "192.0.2.53",
			},
			wantDisplay: "ws1",
		},
		{
			// DNS (opt-in): a name and its addresses, and NO MAC — the answer
			// is hearsay from a resolver about a host that may not even be on
			// this segment, so nothing layer-2 is attributed to it.
			name: "dns",
			obs: hostobs.HostObservation{
				Source:    hostobs.SourceDNS,
				Addresses: mustAddrs(t, "192.0.2.54"),
				FQDNs:     []string{"app.corp.example"},
				Hostnames: []string{"app"},
			},
			wantKinds: map[identity.Kind]string{
				identity.KindFQDN:      "app.corp.example",
				identity.KindHostname:  "app",
				identity.KindIPAddress: "192.0.2.54",
			},
			wantAbsent:  []identity.Kind{identity.KindMACAddress},
			wantDisplay: "app.corp.example",
		},
		{
			// LLDP: the ADVERTISER's own identity — chassis MAC, system name,
			// management address, and a model when the LLDP-MED inventory TLV
			// stated one.
			name: "lldp advertiser",
			obs: hostobs.HostObservation{
				Source:    hostobs.SourceLLDP,
				MAC:       "00:1a:2f:11:22:33",
				Addresses: mustAddrs(t, "192.0.2.2"),
				FQDNs:     []string{"access-sw-3.corp.example"},
				Hostnames: []string{"access-sw-3"},
				Model:     "WS-C2960-24TT-L",
			},
			wantKinds: map[identity.Kind]string{
				identity.KindMACAddress: "00:1a:2f:11:22:33",
				identity.KindFQDN:       "access-sw-3.corp.example",
				identity.KindHostname:   "access-sw-3",
				identity.KindIPAddress:  "192.0.2.2",
			},
			wantDisplay: "access-sw-3.corp.example",
		},
		{
			// CDP: same shape, platform TLV as the model.
			name: "cdp advertiser",
			obs: hostobs.HostObservation{
				Source:    hostobs.SourceCDP,
				MAC:       "00:1a:2f:11:22:44",
				Addresses: mustAddrs(t, "192.0.2.3"),
				Hostnames: []string{"cab-sw-1"},
				Model:     "cisco WS-C2960-24TT-L",
			},
			wantKinds: map[identity.Kind]string{
				identity.KindMACAddress: "00:1a:2f:11:22:44",
				identity.KindHostname:   "cab-sw-1",
				identity.KindIPAddress:  "192.0.2.3",
			},
			wantDisplay: "cab-sw-1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs, err := buildHostObs(t, unscopedService(), &tc.obs)
			if err != nil {
				t.Fatalf("hostObservationObservation: %v", err)
			}
			got := ids(obs)
			for kind, want := range tc.wantKinds {
				id, ok := got[kind]
				if !ok {
					t.Errorf("no %s identifier; got %v", kind, obs.Identifiers)
					continue
				}
				if id.Value != want {
					t.Errorf("%s = %q, want %q", kind, id.Value, want)
				}
			}
			for _, kind := range tc.wantAbsent {
				if id, ok := got[kind]; ok {
					t.Errorf("%s identifier %q was derived from a frame that did not carry one", kind, id.Value)
				}
			}
			if obs.DisplayName != tc.wantDisplay {
				t.Errorf("DisplayName = %q, want %q", obs.DisplayName, tc.wantDisplay)
			}
			// Never a guessed class. A printer advertising _ipp._tcp is a
			// classification RULE's conclusion (ADR-0004 D6), not a builder's.
			if obs.ClassHint != assetclass.KeyUnknownHost {
				t.Errorf("ClassHint = %q, want %q — a class is a rule's decision, not this builder's",
					obs.ClassHint, assetclass.KeyUnknownHost)
			}
			// A host is not a service. `port = 0` in the stored row means "not
			// an endpoint", and honouring that means creating none.
			if len(obs.Endpoints) != 0 {
				t.Errorf("the builder created %d endpoint(s) for a passive host observation", len(obs.Endpoints))
			}
			// Never third_party: that is a claim about a flow, and there is none.
			if obs.Network.Ownership == identity.OwnershipThirdParty {
				t.Error("a passively observed host was classified third_party")
			}
		})
	}
}

// --- a MAC alone is enough --------------------------------------------------

// The case this whole path exists for. An ARP frame from a device that answers
// no name and holds no address still says "this thing is here, and this is its
// hardware address" — and `unknown_host` lists mac_address in its identifier
// precedence, so the engine can match on it.
func TestHostObservationBuilder_MACAloneIdentifies(t *testing.T) {
	obs, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
		Source: hostobs.SourceARP,
		MAC:    "28:cf:da:99:88:77",
	})
	if err != nil {
		t.Fatalf("a MAC-only observation was refused: %v", err)
	}
	got := ids(obs)
	if v, ok := got[identity.KindMACAddress]; !ok || v.Value != "28:cf:da:99:88:77" {
		t.Fatalf("mac identifier = %+v, want the MAC", v)
	}
	if len(obs.Identifiers) != 1 {
		t.Errorf("identifiers = %v, want exactly the MAC", obs.Identifiers)
	}
	// With nothing else to show a human, the MAC is the display name. A blank
	// row in Approvals is worse than a hardware address.
	if obs.DisplayName != "28:cf:da:99:88:77" {
		t.Errorf("DisplayName = %q, want the MAC", obs.DisplayName)
	}
}

// An observation with NOTHING attachable is refused. Accepting it would create
// an asset nothing can ever match again, so every coalescing window would add
// another. That is the rule for every builder, and it has no exception here.
func TestHostObservationBuilder_RefusesAnObservationWithNoIdentifiers(t *testing.T) {
	_, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
		Source: hostobs.SourceMDNS,
		// Services but no name, no MAC, no address: a printer announcing a
		// service type and nothing that says which printer.
		Services: []string{"_ipp._tcp"},
	})
	if err == nil {
		t.Fatal("an observation carrying no identifier was accepted")
	}
	if !strings.Contains(err.Error(), "could never be matched again") {
		t.Errorf("err = %v, want the errNoIdentifiers reason", err)
	}
}

// A randomised MAC is not an asset key. Keying on one produces a fresh asset
// every time the phone rotates its address, each holding a MAC that will never
// be seen again.
//
// Dropped as an IDENTIFIER rather than attached weakly, because identifier
// confidence does not affect whether a kind votes — Engine.kindVotes reads
// scope, not confidence — so "attach it with low confidence" would be
// indistinguishable from attaching it.
func TestHostObservationBuilder_LocallyAdministeredMACIsNotAKey(t *testing.T) {
	t.Run("dropped, and the names still identify", func(t *testing.T) {
		obs, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
			Source:    hostobs.SourceMDNS,
			MAC:       "72:cf:da:11:22:33", // 0x72 has the U/L bit set
			Hostnames: []string{"bobs-phone"},
		})
		if err != nil {
			t.Fatalf("hostObservationObservation: %v", err)
		}
		if id, ok := ids(obs)[identity.KindMACAddress]; ok {
			t.Errorf("a locally-administered MAC was attached as an identifier: %q", id.Value)
		}
		if id, ok := ids(obs)[identity.KindHostname]; !ok || id.Value != "bobs-phone" {
			t.Errorf("the name should still identify it; identifiers = %v", obs.Identifiers)
		}
	})

	t.Run("nothing else means refused", func(t *testing.T) {
		// A rotating MAC and nothing else identifies nothing stable, so the
		// honest outcome is a refusal rather than an asset per rotation.
		_, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
			Source: hostobs.SourceARP,
			MAC:    "72:cf:da:44:55:66",
		})
		if err == nil {
			t.Fatal("an observation whose only identity was a rotating MAC was accepted")
		}
	})
}

// --- an IP is never a hostname ----------------------------------------------

// A name identifier holding an address would be matched against other NAMES and
// never against the ip_address identifier for the same value, so one host
// reached by both would become two assets — and the address-in-a-name-slot
// would be scoped as a hostname and allowed to vote in a dynamic segment where
// the real ip_address identifier is forbidden to.
func TestHostObservationBuilder_AnIPLiteralIsNeverAName(t *testing.T) {
	obs, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
		Source:    hostobs.SourceNBNS,
		MAC:       "28:cf:da:11:22:37",
		Addresses: mustAddrs(t, "192.0.2.60"),
		// A hand-built or future payload that filed an address as a name.
		Hostnames: []string{"192.0.2.60", "real-name"},
		FQDNs:     []string{"2001:db8::1"},
	})
	if err != nil {
		t.Fatalf("hostObservationObservation: %v", err)
	}
	for _, id := range obs.Identifiers {
		if id.Kind != identity.KindHostname && id.Kind != identity.KindFQDN {
			continue
		}
		if isIPLiteral(id.Value) {
			t.Errorf("an address %q was attached as a %s identifier", id.Value, id.Kind)
		}
	}
	// The genuine name survives — the guard must reject addresses, not names.
	found := false
	for _, id := range obs.Identifiers {
		if id.Kind == identity.KindHostname && id.Value == "real-name" {
			found = true
		}
	}
	if !found {
		t.Errorf("the real hostname was dropped along with the address: %v", obs.Identifiers)
	}
}

// --- the addressless observation --------------------------------------------

// 0.0.0.0 is the `dest_ip NOT NULL` column compromise, not an address. An
// observation with no address at all (an LLDP frame carrying only a chassis MAC,
// an ARP probe from a host that has not been given a lease) must identify by
// MAC and derive no ip_address identifier.
func TestHostObservationBuilder_UnspecifiedAddressIsNotAnAddress(t *testing.T) {
	ho := &hostobs.HostObservation{
		Source: hostobs.SourceLLDP,
		MAC:    "00:1a:2f:aa:bb:cc",
	}
	ho.Finalize()
	// Force the unspecified address past the producer's own filter, which is
	// what a hand-built payload would do.
	ho.Addresses = mustAddrs(t, "0.0.0.0")

	f := hostObsFinding(t, ho, nil)
	payload, ok := hostObservationPayload(f)
	if !ok {
		t.Fatal("no readable payload")
	}
	obs, err := unscopedService().hostObservationObservation(uuid.New(), f, payload)
	if err != nil {
		t.Fatalf("hostObservationObservation: %v", err)
	}
	if id, ok := ids(obs)[identity.KindIPAddress]; ok {
		t.Errorf("0.0.0.0 became an ip_address identifier (%q); it means 'no address observed'", id.Value)
	}
	if _, ok := ids(obs)[identity.KindMACAddress]; !ok {
		t.Error("the MAC must identify it when no address was observed")
	}
	// And it is still not a third party, which is what the ownership classifier
	// says about an address that is not RFC 1918.
	if obs.Network.Ownership != identity.OwnershipUnknown {
		t.Errorf("Network.Ownership = %q, want %q", obs.Network.Ownership, identity.OwnershipUnknown)
	}
}

// --- facts ------------------------------------------------------------------

// The facts are written AS GIVEN: the producer already restricted the map to
// registered keys its producer key may write, and re-deriving here would be a
// second opinion about somebody else's measurement.
func TestHostObservationFacts_AreTheProducersMapUnchanged(t *testing.T) {
	ho := &hostobs.HostObservation{
		Source:   hostobs.SourceCDP,
		MAC:      "00:1a:2f:11:22:55",
		Model:    "cisco WS-C2960-24TT-L",
		Services: []string{"_ipp._tcp", "_printer._tcp"},
	}
	ho.Finalize()

	at := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	src := identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:abc", Mode: identity.ModePassive}
	facts := hostObservationFacts(ho, src, at, 0.95)

	byKey := map[string]any{}
	for _, f := range facts {
		byKey[f.Key] = f.Value
		if f.SourceKind != identity.SourceMeasured {
			t.Errorf("fact %s is %s; a frame stated it, so it is measured", f.Key, f.SourceKind)
		}
		if f.SourceRef != "sensor:abc" {
			t.Errorf("fact %s carries source_ref %q, want the sensor's", f.Key, f.SourceRef)
		}
		if !f.ObservedAt.Equal(at) {
			t.Errorf("fact %s observed_at = %v, want the capture time", f.Key, f.ObservedAt)
		}
	}
	if byKey["hw.vendor"] != "Cisco Systems" {
		t.Errorf("hw.vendor = %v, want the OUI table's answer", byKey["hw.vendor"])
	}
	if byKey["hw.model"] != "cisco WS-C2960-24TT-L" {
		t.Errorf("hw.model = %v, want the platform TLV verbatim", byKey["hw.model"])
	}
	if _, ok := byKey["net.mdns_services"]; !ok {
		t.Error("net.mdns_services was not written")
	}

	// Neither of these is in the payload and neither may be synthesised. A
	// captured advertisement identifies its ADVERTISER, not an adjacency to the
	// capture point — a mirror or SPAN port makes that false — and
	// capture_interface names the SENSOR's interface, not the subject's.
	for _, forbidden := range []string{"net.neighbors", "net.interfaces"} {
		if _, ok := byKey[forbidden]; ok {
			t.Errorf("%s was synthesised from a passive capture", forbidden)
		}
	}
}

// Attributes are evidence, not facts. They travel in the asset's metadata,
// where a human and a future classifier can read them, and not into asset_facts
// — which is the contract for what the platform stores as a STATEMENT.
func TestHostObservationMetadata_CarriesAttributesAndTheRotatingMAC(t *testing.T) {
	ho := &hostobs.HostObservation{
		Source:    hostobs.SourceDHCP,
		MAC:       "72:cf:da:11:22:33", // locally administered
		Hostnames: []string{"bobs-phone"},
	}
	ho.Finalize()
	f := hostObsFinding(t, ho, map[string]interface{}{
		"sensor_id": "11111111-2222-3333-4444-555555555555",
		"batch_id":  "batch-7",
	})
	payload, ok := hostObservationPayload(f)
	if !ok {
		t.Fatal("no readable payload")
	}
	meta := hostObservationMetadata(f, payload)

	if meta["discovery_kind"] != KindHostObservation {
		t.Errorf("discovery_kind = %v, want %q", meta["discovery_kind"], KindHostObservation)
	}
	if meta["sensor_id"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("sensor_id = %v, want the sensor that reported it", meta["sensor_id"])
	}
	// The MAC we refused to key on is still recorded, so an asset in Approvals
	// is explicable rather than mysteriously nameless.
	if meta["host_observation_local_mac"] != "72:cf:da:11:22:33" {
		t.Errorf("host_observation_local_mac = %v, want the rotating MAC recorded as evidence", meta["host_observation_local_mac"])
	}
}

// --- confidence -------------------------------------------------------------

// One ladder. The producer graded it and the value travelled on the row; the
// consumer reads it back rather than deriving a second opinion.
func TestHostObservationConfidence_ReadsTheProducersGrade(t *testing.T) {
	ho := &hostobs.HostObservation{Source: hostobs.SourceLLDP, MAC: "00:1a:2f:11:22:66"}
	ho.Finalize()

	t.Run("from the row", func(t *testing.T) {
		f := hostObsFinding(t, ho, map[string]interface{}{"confidence_score": 0.95})
		if got := hostObservationConfidence(f, ho); got != 0.95 {
			t.Errorf("confidence = %v, want the 0.95 the producer graded", got)
		}
	})

	t.Run("recomputed when the row carries none", func(t *testing.T) {
		// Not a second opinion: the same function, applied to the same
		// observation, one step later.
		f := hostObsFinding(t, ho, nil)
		if got := hostObservationConfidence(f, ho); got != hostobs.Confidence(ho) {
			t.Errorf("confidence = %v, want the shared ladder's %v", got, hostobs.Confidence(ho))
		}
	})
}

// --- source attribution -----------------------------------------------------

// Which capture made the observation, and therefore which fact producer wrote
// its facts. A collector writing a key it is not registered for means two
// subsystems disagree about who owns a fact.
func TestHostObservationSourceAttribution(t *testing.T) {
	ho := &hostobs.HostObservation{Source: hostobs.SourceARP, MAC: "28:cf:da:11:22:38"}
	ho.Finalize()

	sensor := hostObsFinding(t, ho, nil)
	if got := hostObservationFactProducer(sensor); got != "sensor" {
		t.Errorf("fact producer = %q, want sensor", got)
	}
	if src := hostObservationSource(sensor); !strings.HasPrefix(src.Ref, "sensor:") || src.Mode != identity.ModePassive {
		t.Errorf("source = %+v, want a passive sensor ref", src)
	}

	pcap := hostObsFinding(t, ho, map[string]interface{}{"discovery_method": "pcap_upload"})
	if got := hostObservationFactProducer(pcap); got != "platform-sensor" {
		t.Errorf("fact producer for an uploaded capture = %q, want platform-sensor", got)
	}
	// Still passive: every decoder behind a host observation reads frames that
	// were going to be on the wire anyway.
	if src := hostObservationSource(pcap); src.Mode != identity.ModePassive {
		t.Errorf("source mode = %q, want passive", src.Mode)
	}
}

// --- payload handling -------------------------------------------------------

// A finding MARKED as a host observation whose payload cannot be read is
// refused, not quietly re-routed onto the crypto path where all three hazards
// are waiting. "We could not read it" and "it is a crypto finding" are different
// answers.
func TestHostObservationIngest_RefusesAnUnreadablePayload(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  map[string]interface{}
	}{
		{"no payload key", map[string]interface{}{"source": "sensor_discovery"}},
		{"nil payload", map[string]interface{}{"host_observation": nil}},
		{"payload is a string", map[string]interface{}{"host_observation": "printer"}},
		{"no raw data at all", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := IngestFinding{Kind: KindHostObservation, RawData: tc.raw}
			if !isHostObservation(f) {
				t.Fatal("the kind alone must decide what this finding is")
			}
			if _, ok := hostObservationPayload(f); ok {
				t.Error("an unreadable payload was accepted")
			}
		})
	}
}

// The kind is the only thing that decides. A crypto finding that happens to
// carry a host_observation key in its raw data is still a crypto finding, and a
// host observation with no payload is still not one.
func TestIsHostObservation_ReadsTheKindAndNothingElse(t *testing.T) {
	withPayload := IngestFinding{RawData: map[string]interface{}{"host_observation": map[string]interface{}{}}}
	if isHostObservation(withPayload) {
		t.Error("a finding with no kind was treated as a host observation because of its raw data")
	}
	bare := IngestFinding{Kind: KindHostObservation}
	if !isHostObservation(bare) {
		t.Error("a finding marked host_observation was not recognised")
	}
}

// --- the kind's spelling ----------------------------------------------------

// One string, spelled in three packages that cannot import each other.
//
// [KindHostObservation] here, `converter.KindHostObservation` in
// discovery-processor, and `approval.KindHostObservation` in shared. The first
// two are separate Go MODULES — neither can import the other — so the only
// thing that can hold them together is the middle one, which both depend on.
//
// This test closes one leg (this service ↔ shared/approval);
// discovery-processor's TestApprovalKindOf closes the other (converter ↔
// shared/approval). Together they pin all three, transitively.
//
// What drifting costs: the converter stamps the string onto the wire, this
// service branches on it, and a tenant's auto-approval rule matches it. Change
// one and nothing fails to compile — host observations simply resume being
// treated as crypto findings, which is every failure the boundary hold existed
// to prevent, back with no error message anywhere.
//
// Mutation check: change either constant and this fails.
func TestHostObservationKindSpellingIsShared(t *testing.T) {
	if KindHostObservation != approval.KindHostObservation {
		t.Errorf("inventory-service spells the kind %q and shared/approval spells it %q; a rule written against one would never match a finding marked with the other",
			KindHostObservation, approval.KindHostObservation)
	}
	// And it is the value on the wire, which is what the converter writes and
	// the ingest handler binds. Spelled as a literal on purpose: a test that
	// compared two constants to each other and nothing else would still pass if
	// BOTH were renamed, and the wire format is not ours to rename.
	if KindHostObservation != "host_observation" {
		t.Errorf("the wire kind is %q, want host_observation — every row already in sensor_discoveries carries the old spelling", KindHostObservation)
	}
}
