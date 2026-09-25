package cryptoparse_test

import (
	"reflect"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse/cryptoparsetest"
)

// The VPN pipeline contract starts here: what a collector's DH-group settings
// parse to is the offered list and the key exchange every later stage is held
// to.
func TestParseIKEGroups_VPNContract(t *testing.T) {
	for _, c := range cryptoparsetest.VPNKeyExchangeCases {
		if c.DHGroup == "" && c.PFSGroup == "" {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			ike := cryptoparse.ParseIKEGroups(c.DHGroup)
			pfs := cryptoparse.ParseIKEGroups(c.PFSGroup)
			if got := cryptoparse.OfferedIKEGroupCodes(ike, pfs); !reflect.DeepEqual(got, c.WantOffered) {
				t.Errorf("offered = %v, want %v", got, c.WantOffered)
			}
			g, ok := cryptoparse.PreferredIKEGroup(ike)
			if c.WantKex == "" {
				if ok {
					t.Errorf("preferred = %+v, want none — the key exchange is unknown", g)
				}
				return
			}
			if !ok || g.Code != c.WantKex || g.Bits != c.WantKeySize {
				t.Errorf("preferred = %+v (ok=%v), want %s at %d bits", g, ok, c.WantKex, c.WantKeySize)
			}
		})
	}
}

// A PFS group is never the preferred IKE group, whatever the order.
func TestOfferedIKEGroupCodes_IKEFirstThenPFSDeduplicated(t *testing.T) {
	ike := cryptoparse.ParseIKEGroups("19 14")
	pfs := cryptoparse.ParseIKEGroups("14 2")
	want := []string{"DH-ECP-256", "DH-MODP-2048", "DH-1024"}
	if got := cryptoparse.OfferedIKEGroupCodes(ike, pfs); !reflect.DeepEqual(got, want) {
		t.Errorf("offered = %v, want %v", got, want)
	}
}
