package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

// The source asset wire reaches the identity engine field for field: every
// canonical field a CMDB mapping may pull (platform ADR-0002 M3) lands on the
// AssetInput, the operating system as the class attribute, and nothing the
// allowlist leaves out gets in. MUTATION: drop any line of item()'s mapping,
// or decode an unlisted field, and this goes red.
func TestSourceAssetWire_MapsEveryAllowlistedField(t *testing.T) {
	var w sourceAssetWire
	if err := json.Unmarshal([]byte(`{
		"class_key": "server",
		"display_name": "Web server", "hostname": "web-01", "ip_address": "10.0.0.5",
		"description": "the web tier", "environment": "production", "business_unit": "Retail",
		"owner_email": "owner@example.test", "support_group": "Web Ops", "operating_system": "Ubuntu 24.04",
		"site": "LON1", "region": "eu-west",
		"asset_status": "monitoring", "attributes": {"secret": "x"}
	}`), &w); err != nil {
		t.Fatal(err)
	}
	in := w.item("netbox").Input
	for name, got := range map[string]*string{
		"display_name": in.DisplayName, "hostname": in.Hostname, "ip_address": in.IPAddress,
		"description": in.Description, "environment": in.Environment, "business_unit": in.BusinessUnit,
		"owner_email": in.OwnerEmail, "support_group": in.SupportGroup, "site": in.Site, "region": in.Region,
	} {
		if got == nil || *got == "" {
			t.Errorf("%s did not reach the asset input", name)
		}
	}
	if in.ClassKey != "server" {
		t.Errorf("class_key = %q", in.ClassKey)
	}
	if in.Attributes["operating_system"] != "Ubuntu 24.04" {
		t.Errorf("operating_system did not become the class attribute: %v", in.Attributes)
	}
	if _, leaked := in.Attributes["secret"]; leaked || len(in.Attributes) != 1 {
		t.Errorf("attributes = %v; only operating_system may be set through the wire", in.Attributes)
	}
	if in.AssetStatus != nil {
		t.Errorf("asset_status = %q; approval is the tenant's policy's answer, never a source's", *in.AssetStatus)
	}
}

// A source's declared interfaces reach the asset input with the source's own
// ids keyed by the request's producer (DCIM row 1.5f), and a field the wire
// does not list (a NetBox custom field) does not. MUTATION: drop the
// Interfaces mapping in item(), or key the ids by anything but the producer,
// and this goes red.
func TestSourceAssetWire_MapsDeclaredInterfaces(t *testing.T) {
	var w sourceAssetWire
	if err := json.Unmarshal([]byte(`{
		"class_key": "switch",
		"interfaces": [{
			"name": "GigabitEthernet1/0/1", "type": "1000base-t", "mac_address": "00:1b:54:aa:bb:01",
			"mtu": 9000, "enabled": true, "mode": "access", "untagged_vlan": 30, "external_id": "9001",
			"custom_fields": {"psk": "PlantedWireSecret"},
			"addresses": [{"address": "192.0.2.11/24", "vrf": "", "external_id": "7001"}]
		}]
	}`), &w); err != nil {
		t.Fatal(err)
	}
	in := w.item("netbox").Input
	if len(in.Interfaces) != 1 {
		t.Fatalf("interfaces = %+v", in.Interfaces)
	}
	ifc := in.Interfaces[0]
	if ifc.Name != "GigabitEthernet1/0/1" || ifc.Type != "1000base-t" || ifc.MACAddress != "00:1b:54:aa:bb:01" ||
		ifc.MTU == nil || *ifc.MTU != 9000 || ifc.Enabled == nil || !*ifc.Enabled || ifc.Mode != "access" || ifc.UntaggedVLAN != 30 {
		t.Errorf("interface = %+v", ifc)
	}
	if ifc.ExternalIDs["netbox"] != "9001" || len(ifc.ExternalIDs) != 1 {
		t.Errorf("interface external ids = %v, want {netbox: 9001}", ifc.ExternalIDs)
	}
	if len(ifc.Addresses) != 1 || ifc.Addresses[0].Address != "192.0.2.11/24" || ifc.Addresses[0].ExternalIDs["netbox"] != "7001" {
		t.Errorf("addresses = %+v", ifc.Addresses)
	}
	raw, _ := json.Marshal(in)
	if strings.Contains(string(raw), "PlantedWireSecret") {
		t.Error("an unlisted interface field reached the asset input")
	}
}
