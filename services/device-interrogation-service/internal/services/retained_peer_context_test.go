package services

import (
	"encoding/json"
	"strings"
	"testing"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// TestRetainedPeerKey_IsStorableAndUnforgeable pins the persisted key's three
// properties: nothing jsonb refuses, a JSON round trip that preserves the
// lookup, and no collision between a two-identifier peer and one identifier
// whose value spells out the old separator-joined form.
func TestRetainedPeerKey_IsStorableAndUnforgeable(t *testing.T) {
	two := di.PeerRef{Identifiers: []di.PeerIdentifier{
		{Kind: di.IdentifierMACAddress, Value: "00:00:5e:00:53:01"},
		{Kind: di.IdentifierIPAddress, Value: "192.0.2.10"},
	}}
	forged := di.PeerRef{Identifiers: []di.PeerIdentifier{
		{Kind: di.IdentifierMACAddress, Value: "00:00:5e:00:53:01\x00ip_address=192.0.2.10"},
	}}
	if identifierKey(two) != identifierKey(forged) {
		t.Fatal("fixture: the forged peer must collide under the NUL-joined key, or this proves nothing")
	}
	if retainedPeerKey(two) == retainedPeerKey(forged) {
		t.Error("a value containing the separator forged another peer's retained key")
	}

	state := retainedPeerContext{Peers: map[string]identity.Observation{retainedPeerKey(two): {DisplayName: "two"}}}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `\u0000`) {
		t.Fatalf("payload carries a NUL escape jsonb refuses: %s", body)
	}
	var back retainedPeerContext
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatal(err)
	}
	if got, ok := back.retainedPeer(two); !ok || got.DisplayName != "two" {
		t.Error("round-tripped context lost the envelope")
	}
	if _, ok := back.retainedPeer(forged); ok {
		t.Error("the forged peer read another peer's envelope")
	}
}

// TestRetainedPeer_ReadsPreFixContexts: a context persisted before the key
// changed can only hold single-identifier keys in identifierKey's form (any NUL
// failed the insert), and must still read back exactly.
func TestRetainedPeer_ReadsPreFixContexts(t *testing.T) {
	one := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierHostname, Value: "printer.local"}}}
	legacy := retainedPeerContext{Peers: map[string]identity.Observation{identifierKey(one): {DisplayName: "legacy"}}}
	if got, ok := legacy.retainedPeer(one); !ok || got.DisplayName != "legacy" {
		t.Error("a pre-fix context no longer reads its own envelope")
	}
	other := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierHostname, Value: "scanner.local"}}}
	if _, ok := legacy.retainedPeer(other); ok {
		t.Error("a pre-fix context answered for a peer it never held")
	}
}
