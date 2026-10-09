package services

import (
	"reflect"
	"strings"
	"testing"
)

func TestMergeClassEvidence_UnionsListsAndPrefersStoredDeviceIdentity(t *testing.T) {
	current := classEvidence{
		MACs:             []string{"00:00:0C:12:34:56"},
		Vendor:           "Cisco Systems", // the registry's answer for the observation's MAC
		Model:            "WS-C2960",
		MDNSServices:     []string{"_ipp._tcp"},
		LLDPCapabilities: []string{"bridge"},
		Banners:          map[string]string{"banner": "Server: x"},
		OpenPorts:        []int{631},
	}
	stored := classEvidence{
		MACs:             []string{"00:00:0c:12:34:56", "00:b4:63:00:00:01"},
		Vendor:           "Cisco Systems, Inc",
		MDNSServices:     []string{"_IPP._tcp", "_printer._tcp"},
		LLDPCapabilities: []string{"router"},
		CDPCapabilities:  []string{"switch"},
	}
	got := mergeClassEvidence(current, stored)

	if want := []string{"00:00:0C:12:34:56", "00:b4:63:00:00:01"}; !reflect.DeepEqual(got.MACs, want) {
		t.Errorf("MACs = %v, want %v (one MAC in two spellings is one MAC)", got.MACs, want)
	}
	if want := []string{"_ipp._tcp", "_printer._tcp"}; !reflect.DeepEqual(got.MDNSServices, want) {
		t.Errorf("MDNSServices = %v, want %v", got.MDNSServices, want)
	}
	if want := []string{"bridge", "router"}; !reflect.DeepEqual(got.LLDPCapabilities, want) {
		t.Errorf("LLDPCapabilities = %v, want %v", got.LLDPCapabilities, want)
	}
	if want := []string{"switch"}; !reflect.DeepEqual(got.CDPCapabilities, want) {
		t.Errorf("CDPCapabilities = %v, want %v", got.CDPCapabilities, want)
	}
	if got.Vendor != "Cisco Systems, Inc" {
		t.Errorf("Vendor = %q; a stored device-identity vendor must outrank the observation's registry answer", got.Vendor)
	}
	if got.Model != "WS-C2960" {
		t.Errorf("Model = %q; with no stored device-identity model the observation's stands", got.Model)
	}
	if got.Banners["banner"] != "Server: x" || !reflect.DeepEqual(got.OpenPorts, []int{631}) {
		t.Errorf("observation-only evidence was lost: %+v", got)
	}
}

func TestMergeClassEvidence_EmptyStoredIsTheObservation(t *testing.T) {
	current := classEvidence{MACs: []string{"00:00:0c:12:34:56"}, Vendor: "Cisco Systems"}
	got := mergeClassEvidence(current, classEvidence{})
	if !reflect.DeepEqual(got.MACs, current.MACs) || got.Vendor != current.Vendor || got.MDNSServices != nil {
		t.Errorf("merge with nothing stored = %+v, want the observation unchanged", got)
	}
}

// The DHCP option 60 identifier is a single value, not a list: the current
// observation's wins, and the stored one stands in only when the observation
// carries none.
func TestMergeClassEvidence_DHCPVendorClassCurrentWinsStoredFills(t *testing.T) {
	if got := mergeClassEvidence(classEvidence{DHCPVendorClass: "android-dhcp-14"}, classEvidence{DHCPVendorClass: "MSFT 5.0"}); got.DHCPVendorClass != "android-dhcp-14" {
		t.Errorf("DHCPVendorClass = %q; the current observation's identifier must win", got.DHCPVendorClass)
	}
	if got := mergeClassEvidence(classEvidence{}, classEvidence{DHCPVendorClass: "MSFT 5.0"}); got.DHCPVendorClass != "MSFT 5.0" {
		t.Errorf("DHCPVendorClass = %q; with none in the observation the stored one must stand in", got.DHCPVendorClass)
	}
}

// The provenance rule is SQL, so its text is pinned: deleting an exclusion would
// feed the registry's own answer (or a passive sensor's table) back into the
// classifier as if the device had stated it.
func TestDeviceIdentityFactSQL_ExcludesCatalogueSensorAndInference(t *testing.T) {
	for _, want := range []string{"NOT LIKE 'catalog:%'", "f.source_ref = 'sensor'", "f.source_ref LIKE 'sensor:%'", "source_kind <> 'inferred'"} {
		if !strings.Contains(deviceIdentityFactSQL, want) {
			t.Errorf("deviceIdentityFactSQL lost %q", want)
		}
	}
}
