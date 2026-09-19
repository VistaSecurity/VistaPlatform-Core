package discovery

import (
	"reflect"
	"testing"
)

func TestIdentityDNSInterfacesMapsOnlyConfiguredUnambiguousCapture(t *testing.T) {
	os := map[string][]string{"Ethernet": {"192.0.2.4"}, "VPN": {"198.51.100.4"}, "eth0": {"203.0.113.4"}}
	capture := map[string][]string{`\Device\NPF_{LAN}`: {"192.0.2.4"}, `\Device\NPF_{VPN}`: {"198.51.100.4"}, "ambiguous": {"192.0.2.4", "198.51.100.4"}}
	got := identityDNSInterfaceNames([]string{`\Device\NPF_{LAN}`, "eth0", "missing", "ambiguous"}, os, capture)
	if !reflect.DeepEqual(got, []string{"Ethernet", "eth0"}) {
		t.Fatalf("scope widened or lost: %v", got)
	}
	os["Duplicate"] = []string{"192.0.2.4"}
	if got := identityDNSInterfaceNames([]string{`\Device\NPF_{LAN}`}, os, capture); len(got) != 0 {
		t.Fatalf("ambiguous local mapping accepted: %v", got)
	}
}
