package services

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// TestVlanGatewayAddresses pins which net.vlans entries yield an address the
// device claims as its own: only an entry with a segmentable prefix and
// a gateway inside it that is a host address. The vendor shapes are the ones
// TestVlanSegmentSpecs uses.
func TestVlanGatewayAddresses(t *testing.T) {
	got := vlanGatewayAddresses([]map[string]any{
		{"name": "unifi lan", "subnet": "192.0.2.0/24", "gateway": "192.0.2.1", "dhcp_enabled": true},
		{"name": "fortigate vlan", "subnet": "198.51.100.0/25", "gateway": "198.51.100.126"},
		{"name": "ipv6", "subnet": "2001:db8:1::/64", "gateway": "2001:db8:1::1"},
		{"name": "mapped", "subnet": "::ffff:203.0.113.0/120", "gateway": "::ffff:203.0.113.1"},
		{"name": "duplicate", "subnet": "192.0.2.0/24", "gateway": "192.0.2.1"},
		{"name": "cisco vlan, no prefix", "id": 30},
		{"name": "prefix, no gateway", "subnet": "198.51.100.128/25"},
		{"name": "gateway outside the prefix", "subnet": "192.0.2.0/25", "gateway": "192.0.2.200"},
		{"name": "the network address", "subnet": "192.0.2.0/26", "gateway": "192.0.2.0"},
		{"name": "the broadcast address", "subnet": "192.0.2.64/26", "gateway": "192.0.2.127"},
		{"name": "a host route", "subnet": "192.0.2.9/32", "gateway": "192.0.2.9"},
		{"name": "loopback", "subnet": "127.0.0.0/8", "gateway": "127.0.0.1"},
		{"name": "link-local", "subnet": "fe80::/64", "gateway": "fe80::1"},
		{"name": "not an address", "subnet": "192.0.2.0/24", "gateway": "router"},
	})
	want := []string{"192.0.2.1", "198.51.100.126", "2001:db8:1::1", "203.0.113.1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("gateway addresses = %v, want %v", got, want)
	}
	// A /31 has no broadcast: both addresses are hosts.
	if got := vlanGatewayAddresses([]map[string]any{{"subnet": "192.0.2.10/31", "gateway": "192.0.2.11"}}); len(got) != 1 {
		t.Errorf("a /31 peer address was refused: %v", got)
	}
	if got := vlanGatewayAddresses("not a list"); got != nil {
		t.Errorf("a malformed fact yielded %v", got)
	}
}

// Only the interrogated device's OWN net.vlans fact is claimed for it. A fact a
// controller reported about a device it manages (bound to a subject) is that
// device's, and the session was not opened to it.
func TestSelfGatewayAddresses_IgnoresSubjectBoundFacts(t *testing.T) {
	managed := di.PeerRef{DisplayName: "managed switch"}
	managed.AddIdentifier(di.IdentifierMACAddress, "00:00:5e:00:53:10")
	got := selfGatewayAddresses([]di.FactObservation{
		{Key: facts.KeyNetVlans, Value: []map[string]any{{"subnet": "192.0.2.0/24", "gateway": "192.0.2.1"}}},
		{Key: facts.KeyNetVlans, Subject: managed, Value: []map[string]any{{"subnet": "198.51.100.0/24", "gateway": "198.51.100.1"}}},
		{Key: facts.KeyHWModel, Value: "router"},
		{Key: facts.KeyNetVlans, Value: []map[string]any{{"subnet": "192.0.2.0/24", "gateway": "192.0.2.1"}}},
	})
	if strings.Join(got, ",") != "192.0.2.1" {
		t.Fatalf("self gateway addresses = %v, want only the device's own 192.0.2.1", got)
	}
}

// The claim sighting is first-hand (an authenticated session, measured), the
// address is claimed and self-reported, and the device's known identifiers
// ride along as inferred bindings — the shape Intake accepts a claim in.
func TestGatewayClaimSighting_Shape(t *testing.T) {
	tenant := uuid.New()
	known := []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "SN-1",
		Provenance: identity.IdentifierProvenance{Kind: identity.SourceInferred, Ref: "asset:x"}}}
	s := gatewayClaimSighting(tenant, interrogationSource(uuid.New()), time.Now(), "192.0.2.1", known)
	if s.Channel != identity.ChannelAuthenticatedSession || s.Source.Kind != identity.SourceMeasured {
		t.Fatalf("claim sighting is %s/%s, want a measured authenticated session", s.Channel, s.Source.Kind)
	}
	if len(s.Identifiers) != 2 {
		t.Fatalf("identifiers = %+v", s.Identifiers)
	}
	claim := s.Identifiers[0]
	if claim.Kind != identity.KindIPAddress || claim.Value != "192.0.2.1" || !claim.Provenance.Claimed || !claim.Provenance.SelfReported {
		t.Errorf("claimed identifier = %+v", claim)
	}
	if !s.ClaimsAddresses() {
		t.Error("the claim sighting does not say it claims addresses, so the route would place the device by it")
	}
}
