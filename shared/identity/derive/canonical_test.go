package derive_test

import (
	"net/netip"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/derive"
)

// Whatever this package emits is stored as a mac_address identifier, so it must
// already be the exact form the identity package normalises to. If the two ever
// disagree a derived MAC would never compare equal to the native one it is
// meant to corroborate.
//
// This is an external test package so it may import identity, which will itself
// import derive once the emitters land.
func TestOutputIsCanonicalIdentityForm(t *testing.T) {
	fromIPv6, ok := derive.MACFromEUI64(netip.MustParseAddr("fd00::A2B2:C3FF:FED4:E5F6"))
	if !ok {
		t.Fatal("expected a MAC from the EUI-64 address")
	}
	fromSerial, ok := derive.MACFromSerialRegistered("00000C1A2B3C")
	if !ok {
		t.Fatal("expected a MAC from the serial")
	}
	for _, mac := range []string{fromIPv6, fromSerial} {
		norm, err := identity.Normalize(identity.KindMACAddress, mac)
		if err != nil {
			t.Fatalf("identity rejects derived MAC %q: %v", mac, err)
		}
		if norm != mac {
			t.Fatalf("derived %q but identity normalises it to %q", mac, norm)
		}
	}
}
