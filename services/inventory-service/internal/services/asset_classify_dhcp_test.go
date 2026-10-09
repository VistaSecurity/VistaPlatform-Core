package services

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

// Both intake paths carry the option 60 identifier to the classifier, in the
// shapes their producers write it.
func TestClassEvidence_CarriesTheDHCPVendorClass(t *testing.T) {
	ho := &hostobs.HostObservation{Source: hostobs.SourceDHCP, Attributes: map[string]any{"dhcp_vendor_class": " MSFT 5.0 "}}
	if got := hostObservationClassEvidence(ho).DHCPVendorClass; got != "MSFT 5.0" {
		t.Errorf("host observation: DHCPVendorClass = %q, want MSFT 5.0", got)
	}
	ho.Attributes["dhcp_vendor_class"] = 42 // not a string: absent, never stringified
	if got := hostObservationClassEvidence(ho).DHCPVendorClass; got != "" {
		t.Errorf("host observation with a non-string attribute: DHCPVendorClass = %q, want empty", got)
	}

	for _, key := range []string{"dhcp_vendor_class", "dhcp_vendor_class_identifier"} {
		f := IngestFinding{RawData: map[string]interface{}{key: "android-dhcp-14"}}
		if got := findingClassEvidence(f).DHCPVendorClass; got != "android-dhcp-14" {
			t.Errorf("finding raw_data[%s]: DHCPVendorClass = %q, want android-dhcp-14", key, got)
		}
	}
}
