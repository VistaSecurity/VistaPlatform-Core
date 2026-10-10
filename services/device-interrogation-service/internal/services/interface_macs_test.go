package services

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// Three interface MACs in the net.interfaces fact become three MAC
// identifiers; locally-administered and placeholder addresses are skipped, and
// a fact about a neighbour (a Subject) is not the device's own.
func TestSelfInterfaceMACs_OwnFactOnly_SkipsLAAAndPlaceholders(t *testing.T) {
	neighbour := di.PeerRef{DisplayName: "managed switch"}
	neighbour.AddIdentifier(di.IdentifierMACAddress, "00:00:5e:00:53:10")
	got := selfInterfaceMACs([]di.FactObservation{
		{Key: facts.KeyNetInterfaces, Value: []map[string]any{
			{"name": "eth0", "mac": "00:00:5e:00:53:b0"},
			{"name": "eth1", "mac": "00:00:5e:00:53:b1"},
			{"name": "eth2", "mac": "00:00:5e:00:53:b2"},
			{"name": "laa", "mac": "02:00:5e:00:53:b3"},
			{"name": "zero", "mac": "00:00:00:00:00:00"},
			{"name": "bcast", "mac": "ff:ff:ff:ff:ff:ff"},
			{"name": "none", "mac": ""},
		}},
		{Key: facts.KeyNetInterfaces, Subject: neighbour, Value: []map[string]any{{"mac": "00:00:5e:00:53:c0"}}},
		{Key: facts.KeyHWModel, Value: "router"},
	})
	want := []string{"00:00:5e:00:53:b0", "00:00:5e:00:53:b1", "00:00:5e:00:53:b2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selfInterfaceMACs = %v, want %v", got, want)
	}
}

// The sighting is first-hand (an authenticated session), carries the MAC, and
// binds it to the device through the identifiers already held.
func TestInterfaceMACSighting_Shape(t *testing.T) {
	known := []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "SN-1",
		Provenance: identity.IdentifierProvenance{Kind: identity.SourceInferred, Ref: "asset:x"}}}
	s := interfaceMACSighting(uuid.New(), interrogationSource(uuid.New()), time.Now(), "00:00:5e:00:53:b1", known)
	if s.Channel != identity.ChannelAuthenticatedSession || s.Source.Kind != identity.SourceMeasured {
		t.Fatalf("sighting is %s/%s, want a measured authenticated session", s.Channel, s.Source.Kind)
	}
	if len(s.Identifiers) != 2 || s.Identifiers[0].Kind != identity.KindMACAddress || s.Identifiers[0].Value != "00:00:5e:00:53:b1" {
		t.Fatalf("identifiers = %+v", s.Identifiers)
	}
	if s.ClaimsAddresses() {
		t.Error("an interface MAC sighting must not claim addresses")
	}
}
