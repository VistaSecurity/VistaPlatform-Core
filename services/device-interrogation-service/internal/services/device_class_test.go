package services

// device_type -> class, and the two places that mapping is load-bearing.
//
// It is the only thing that says what a device IS. `devices.device_type` never
// did: it named the vendor interrogator for network gear and the resource kind
// for cloud resources, and nothing downstream could tell a firewall from a
// printer. A wrong answer here is worse than no answer — an absent class shows
// in the UI as unclassified, a wrong one shows as a fact — so every case below
// checks BOTH polarities.

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

func TestDeviceTypeClassKey(t *testing.T) {
	cases := map[string]string{
		// The vendor interrogators. What the PRODUCT is, which for these
		// vendors is unambiguous.
		"f5":        assetclass.KeyLoadBalancer,
		"palo_alto": assetclass.KeyFirewall,
		"fortinet":  assetclass.KeyFirewall,
		"unifi":     assetclass.KeyWirelessController,

		// Cisco is the shallowest class that is TRUE: one interrogator covers
		// IOS routers, Catalyst switches and ASAs, and the device_type cannot
		// tell them apart. Narrowing it to `router` would be a guess presented
		// as a measurement.
		"cisco":     assetclass.KeyNetworkDevice,
		"cisco_ios": assetclass.KeyNetworkDevice,
		"cisco_asa": assetclass.KeyFirewall,

		// Generic kinds.
		"switch":        assetclass.KeySwitch,
		"router":        assetclass.KeyRouter,
		"load_balancer": assetclass.KeyLoadBalancer,

		// Cloud: one class per KIND across three providers, because an S3
		// bucket, an Azure storage account and a GCS bucket are the same thing
		// under three names.
		"aws_s3_bucket":         assetclass.KeyObjectStorage,
		"azure_storage_account": assetclass.KeyObjectStorage,
		"gcp_storage_bucket":    assetclass.KeyObjectStorage,
		"aws_rds_instance":      assetclass.KeyManagedDatabase,
		"azure_sql_database":    assetclass.KeyManagedDatabase,
		"gcp_cloudsql_instance": assetclass.KeyManagedDatabase,
		"aws_kms":               assetclass.KeyKeyStore,
		"azure_keyvault_key":    assetclass.KeyKeyStore,
		"gcp_kms_crypto_key":    assetclass.KeyKeyStore,
		"aws_alb":               assetclass.KeyCloudLoadBalancer,
		"azure_load_balancer":   assetclass.KeyCloudLoadBalancer,
		"gcp_ssl_proxy":         assetclass.KeyCloudLoadBalancer,
		"aws_api_gateway":       assetclass.KeyApiGateway,
		"aws_cloudfront":        assetclass.KeyCdnDistribution,

		// Case and whitespace are the operator's, not ours.
		"  F5  ": assetclass.KeyLoadBalancer,
		"UniFi":  assetclass.KeyWirelessController,
	}
	for deviceType, want := range cases {
		if got := DeviceTypeClassKey(deviceType); got != want {
			t.Errorf("DeviceTypeClassKey(%q) = %q, want %q", deviceType, got, want)
		}
	}

	// "" is a REAL ANSWER: no opinion. The engine then falls back to
	// unknown_host / external from the network ownership, which shows as
	// unclassified. Inventing `server` here is what the old ingest did.
	for _, deviceType := range []string{"other", "", "   ", "something_nobody_added_yet"} {
		if got := DeviceTypeClassKey(deviceType); got != "" {
			t.Errorf("DeviceTypeClassKey(%q) = %q, want \"\" — an unknown device type must not be given a class", deviceType, got)
		}
	}
}

// TestDeviceTypeClassKeysAreRegistered stops the map from drifting away from
// the generated taxonomy. A class key that is not in shared/assetclass would be
// written into assets.class_key anyway (class_path falls back to the key
// itself), producing an asset in a class no facet can select and no CMDB sync
// can map.
func TestDeviceTypeClassKeysAreRegistered(t *testing.T) {
	for deviceType, key := range assetclass.DeviceTypeVocabulary() {
		if _, ok := assetclass.Get(string(key)); !ok {
			t.Errorf("device_type %q maps to class %q, which is not in the generated registry", deviceType, key)
		}
	}
}

func TestIsCloudDeviceType(t *testing.T) {
	for _, deviceType := range []string{
		"aws_s3_bucket", "aws_kms", "aws_alb", "aws_cloudfront", "aws_api_gateway",
		"azure_storage_account", "azure_sql_database", "gcp_kms_crypto_key",
	} {
		if !IsCloudDeviceType(deviceType) {
			t.Errorf("IsCloudDeviceType(%q) = false, want true", deviceType)
		}
	}
	// Hardware, and the unknown. Neither is a cloud resource, and answering
	// "yes" for either would give it a cloud_api management protocol it does
	// not have.
	for _, deviceType := range []string{"f5", "unifi", "cisco", "switch", "postgresql", "other", ""} {
		if IsCloudDeviceType(deviceType) {
			t.Errorf("IsCloudDeviceType(%q) = true, want false", deviceType)
		}
	}
}

func TestManagementProtocol(t *testing.T) {
	// The URL's scheme wins: it is what the platform will actually speak.
	if got := managementProtocol("https://fw1.corp.example.com", "cisco"); got != "https" {
		t.Errorf("managementProtocol with an https URL = %q, want https", got)
	}
	if got := managementProtocol("SSH://sw1.corp.example.com:2222", "f5"); got != "ssh" {
		t.Errorf("managementProtocol with an ssh URL = %q, want ssh", got)
	}

	// No URL: the device type's native protocol.
	for deviceType, want := range map[string]string{
		"f5":            "https",
		"unifi":         "https",
		"cisco":         "ssh",
		"postgresql":    "postgresql",
		"aws_kms":       "cloud_api",
		"gcp_ssl_proxy": "cloud_api",
	} {
		if got := managementProtocol("", deviceType); got != want {
			t.Errorf("managementProtocol(\"\", %q) = %q, want %q", deviceType, got, want)
		}
	}

	// Neither: empty, meaning "we have not been told". Guessing https would put
	// a measurement-shaped value in a column nothing measured.
	for _, deviceType := range []string{"other", "", "unheard_of"} {
		if got := managementProtocol("", deviceType); got != "" {
			t.Errorf("managementProtocol(\"\", %q) = %q, want \"\"", deviceType, got)
		}
	}
}

func TestManagementHost(t *testing.T) {
	cases := map[string]string{
		"https://fw1.corp.example.com":      "fw1.corp.example.com",
		"https://fw1.corp.example.com:8443": "fw1.corp.example.com",
		"https://192.0.2.10":                "192.0.2.10",
		"https://192.0.2.10:8443/api":       "192.0.2.10",
		"https://[2001:db8::1]:8443":        "2001:db8::1",
		// An operator typing the address without a scheme is the common case,
		// not an error.
		"fw1.corp.example.com":      "fw1.corp.example.com",
		"fw1.corp.example.com:8443": "fw1.corp.example.com",
		"192.0.2.10":                "192.0.2.10",
		"":                          "",
		"   ":                       "",
	}
	for in, want := range cases {
		if got := managementHost(in); got != want {
			t.Errorf("managementHost(%q) = %q, want %q", in, got, want)
		}
	}
}
