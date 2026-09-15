package services

import (
	"net/url"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// DeviceTypeClassKey maps a `device_type` onto an asset-class key, or "" when
// the type implies no honest class.
//
// The TABLE lives in shared/assetclass, not here. It used to live here, and
// inventory-service kept a second, smaller one of its own for cloud resource
// types — which knew `s3` and `rds` while the collectors wrote `s3_bucket` and
// `rds_instance`, so every bucket was inventoried as an application. Two
// spellings of "what is an S3 bucket" is the drift ADR-0002 exists to end.
//
// This wrapper stays because the interrogation paths and the contract test call
// it by this name, and because the return type they expect is a plain string.
func DeviceTypeClassKey(deviceType string) string {
	return string(assetclass.FromDeviceType(deviceType))
}

// IsCloudDeviceType reports whether a device_type names a cloud resource rather
// than a piece of hardware on a network.
//
// It reads the CLASS, not the name prefix: a cloud resource is one whose class
// descends from `cloud_resource`, which is what the taxonomy already knows. The
// alternative — `strings.HasPrefix(t, "aws_")` — is the kind of check that
// silently answers "no" the first time a provider is added.
func IsCloudDeviceType(deviceType string) bool {
	key := DeviceTypeClassKey(deviceType)
	if key == "" {
		return false
	}
	return key == assetclass.KeyCloudResource || assetclass.IsAncestor(assetclass.KeyCloudResource, key)
}

// managementProtocol names how the platform reaches a device's management
// plane, for `asset_management.management_protocol`.
//
// It is derived from the management URL's scheme when there is one, because
// that is what the platform will actually speak, and falls back to the
// device_type's native protocol. It answers "" when neither is known — an
// empty column means "we have not been told", and guessing `https` would put a
// measurement-shaped value in a column nothing measured.
func managementProtocol(managementURL, deviceType string) string {
	if u := strings.TrimSpace(managementURL); u != "" {
		if parsed, err := url.Parse(u); err == nil && parsed.Scheme != "" {
			return strings.ToLower(parsed.Scheme)
		}
	}
	switch strings.ToLower(strings.TrimSpace(deviceType)) {
	case "f5", "palo_alto", "fortinet", "unifi":
		// Every vendor client in shared/deviceinterrogation talks to these over
		// their HTTPS management API.
		return "https"
	case "cisco", "cisco_ios", "cisco_asa":
		// The Cisco interrogator is SSH-only (`show running-config | include …`).
		return "ssh"
	case "postgresql":
		return "postgresql"
	case "mysql":
		return "mysql"
	}
	if IsCloudDeviceType(deviceType) {
		// Reached through the provider's API with an integration's credentials,
		// not by connecting to the resource.
		return "cloud_api"
	}
	return ""
}
