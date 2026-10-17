package assetclass

import "strings"

// The two maps every intake uses to turn a collector's own vocabulary into a
// class key. They live HERE, in the package that owns the taxonomy, because
// there used to be two of them — device-interrogation-service's
// `deviceTypeClass` and inventory-service's private `cloudClassHint` switch —
// and they disagreed.
//
// The disagreement was not theoretical. The collectors write `s3_bucket`,
// `gcs_bucket`, `rds_instance` and `cloudsql_instance`; the inventory switch
// knew `s3`, `bucket`, `rds` and `sql_database` and none of the four. So a
// bucket arrived with no class hint at all and the engine fell through to the
// legacy `asset_type` — which for these findings is `service`, meaning every S3
// bucket in the tenant was inventoried as an APPLICATION, and every RDS
// instance as a server. Two spellings of one question is the exact failure
// ADR-0002 exists to end, so there is one spelling now.

// deviceTypeClass maps a `device_type` — the string that names a VENDOR
// INTERROGATOR for network gear ("f5", "palo_alto") and a RESOURCE KIND for
// cloud resources ("aws_s3_bucket") — onto a class key.
//
// A device_type with no honest class answers "", and "" is a real answer: the
// identification engine then falls back to `unknown_host` or `external` from the
// network ownership (ADR-0002 D1), which shows in the UI as unclassified. A
// wrong class shows as a fact, and is worse — "other" is not a kind of hardware.
var deviceTypeClass = map[string]Key{
	// --- Network appliances: the vendor interrogators device-interrogation
	// ships. The class is what the product IS, which for these is unambiguous.
	"f5":         KeyLoadBalancer,
	"palo_alto":  KeyFirewall,
	"fortinet":   KeyFirewall,
	"unifi":      KeyWirelessController,
	"cisco":      KeyNetworkDevice,
	"cisco_ios":  KeyNetworkDevice,
	"cisco_asa":  KeyFirewall,
	"postgresql": KeyDatabaseInstance,
	"mysql":      KeyDatabaseInstance,

	// Cisco is deliberately `network_device` and not `router` or `switch`: the
	// same interrogator handles IOS routers, Catalyst switches and (until the
	// operator says "cisco_asa") firewalls, and the device_type cannot tell
	// them apart. `network_device` is the shallowest class that is TRUE, which
	// is the rule FromLegacyAssetType applies to the retired asset_type enum. A
	// later interrogation that reads the platform's own model narrows it
	// through the classifier seam, which is a proposal.

	// --- Generic kinds an operator may type, or a connector may supply.
	"switch":              KeySwitch,
	"router":              KeyRouter,
	"firewall":            KeyFirewall,
	"load_balancer":       KeyLoadBalancer,
	"wireless_controller": KeyWirelessController,
	"access_point":        KeyAccessPoint,
	"vpn_gateway":         KeyVpnGateway,
	"printer":             KeyPrinter,
	"storage_device":      KeyStorageDevice,

	// --- Cloud resources are NOT listed here: their `<provider>_*` device
	// types are aliases in the class registry's provider-type mapping
	// (standards/asset-classes.yaml `provider_types`, generated into
	// cloud_types_gen.go) and are folded in by init below — one mapping for
	// every cloud spelling (asset-inventory ADR-0009 D2).
}

// cloudResourceTypeClass maps the `resource_type` a cloud collector writes into
// a finding's raw data onto a class key.
//
// It is SEPARATE from deviceTypeClass and consulted first, because one string
// means two things in the two vocabularies: a `device_type` of
// "load_balancer" is a piece of hardware in a rack, while a cloud
// `resource_type` of "load_balancer" is a provider's managed load balancer.
// Folding them into one table would silently pick one of those answers for both.
//
// Every literal the collectors actually write is here, and
// TestCloudResourceTypesTheCollectorsWriteAllMap scans the tree to keep it that
// way — a new collector spelling is a compile-green, run-time-wrong class hint,
// which is how buckets came to be applications.
//
// It is DERIVED, at init, from the class registry's provider-type mapping
// (cloud_types_gen.go): every provider type string (`AWS::EC2::Instance`, lower
// cased), every collector alias that is not a `<provider>_*` device type, and
// the provider-neutral `resource_type_aliases`. No network or subnet entries:
// since DCIM row 1.5f a VPC / VNet / GCP network and its child ranges are IPAM
// prefixes, not assets, so "vpc" answers the coarse `cloud_resource`.
var cloudResourceTypeClass = map[string]Key{}

// providerTypeBySpelling resolves any spelling — a provider type string, a
// device type, a resource type alias — to its provider type.
var providerTypeBySpelling = map[string]CloudProviderType{}

func init() {
	for _, pt := range cloudProviderTypes {
		providerTypeBySpelling[strings.ToLower(pt.Type)] = pt
		cloudResourceTypeClass[strings.ToLower(pt.Type)] = pt.Class
		for _, a := range pt.Aliases {
			a = strings.ToLower(a)
			providerTypeBySpelling[a] = pt
			if strings.HasPrefix(a, pt.Provider+"_") {
				deviceTypeClass[a] = pt.Class
			} else {
				cloudResourceTypeClass[a] = pt.Class
			}
		}
	}
	for a, k := range cloudGenericAliases {
		cloudResourceTypeClass[strings.ToLower(a)] = k
	}
}

// ProviderTypeOf answers the provider type a spelling names — a device type
// (`aws_ec2_instance`), a collector resource type (`ec2`) or the provider type
// string itself — or false. Provider-neutral spellings ("bucket") name no one
// provider's type and answer false.
func ProviderTypeOf(spelling string) (CloudProviderType, bool) {
	pt, ok := providerTypeBySpelling[strings.ToLower(strings.TrimSpace(spelling))]
	return pt, ok
}

// CloudProviderTypes returns a copy of the provider-type mapping.
func CloudProviderTypes() []CloudProviderType {
	out := make([]CloudProviderType, len(cloudProviderTypes))
	copy(out, cloudProviderTypes)
	return out
}

// FromDeviceType maps a `device_type` onto a class key, or "" when the type
// implies no honest class.
func FromDeviceType(deviceType string) Key {
	return deviceTypeClass[strings.ToLower(strings.TrimSpace(deviceType))]
}

// FromCloudResourceType maps a cloud collector's `resource_type` onto a class
// key. The second result is false only for an EMPTY value: a resource type we
// do not recognise is still a cloud resource, so it answers the top-level
// `cloud_resource` rather than nothing.
//
// That fallback is the point. "No opinion" used to mean the class hint was
// dropped entirely and the engine fell back to the legacy `asset_type`, which
// for a cloud finding is `service` — so an unrecognised resource became an
// APPLICATION, and one that carried no asset_type at all became a server.
// `cloud_resource` is coarse and TRUE, which is the rule the whole taxonomy
// follows; a guessed leaf class is a fabricated measurement.
func FromCloudResourceType(resourceType string) (Key, bool) {
	v := strings.ToLower(strings.TrimSpace(resourceType))
	if v == "" {
		return "", false
	}
	if k, ok := cloudResourceTypeClass[v]; ok {
		return k, true
	}
	// A provider-prefixed spelling ("aws_s3_bucket") is a device_type as well,
	// and the two tables agree on every one of those.
	if k := FromDeviceType(v); k != "" {
		return k, true
	}
	return KeyCloudResource, true
}

// DeviceTypeVocabulary returns a copy of the device_type → class table, and
// CloudResourceTypeVocabulary a copy of the resource_type one.
//
// They exist for the tests that hold both tables to the generated registry: a
// class key that is not a real class would still be written into
// `assets.class_key` (class_path falls back to the key itself), producing an
// asset in a class no facet can select and no CMDB sync can map. Copies,
// because a caller that could reorder or extend the live map would be a second
// writer of the taxonomy.
func DeviceTypeVocabulary() map[string]Key {
	out := make(map[string]Key, len(deviceTypeClass))
	for k, v := range deviceTypeClass {
		out[k] = v
	}
	return out
}

// CloudResourceTypeVocabulary returns a copy of the resource_type → class table.
func CloudResourceTypeVocabulary() map[string]Key {
	out := make(map[string]Key, len(cloudResourceTypeClass))
	for k, v := range cloudResourceTypeClass {
		out[k] = v
	}
	return out
}
