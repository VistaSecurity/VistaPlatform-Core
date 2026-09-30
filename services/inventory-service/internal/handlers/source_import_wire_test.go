package handlers

import (
	"encoding/json"
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
	in := w.item().Input
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
