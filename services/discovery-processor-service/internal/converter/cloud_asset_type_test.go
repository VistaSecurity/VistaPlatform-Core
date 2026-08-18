package converter

import "testing"

// mapCloudDeviceTypeToAssetType may only ever return a value in the
// public.asset_type Postgres enum (scripts/database/schema.sql):
//
//	CREATE TYPE public.asset_type AS ENUM ('server','endpoint','service','appliance')
//
// Anything else is rejected at insert time.
var allowedAssetTypes = map[string]bool{
	"server":    true,
	"endpoint":  true,
	"service":   true,
	"appliance": true,
}

func TestMapCloudDeviceTypeToAssetType(t *testing.T) {
	tests := []struct {
		deviceType string
		want       string
		why        string
	}{
		// Traffic-handling network devices.
		{"aws_alb", "appliance", "load balancer"},
		{"aws_nlb", "appliance", "load balancer"},
		{"aws_elb", "appliance", "load balancer"},
		{"azure_load_balancer", "appliance", "load balancer"},
		{"azure_application_gateway", "appliance", "gateway"},
		{"gcp_https_load_balancer", "appliance", "load balancer"},
		{"gcp_ssl_proxy", "appliance", "TLS-terminating proxy"},

		// Managed platform services. These are the ones that used to fall
		// through to "server", which reads as nonsense in Inventory: a KMS key
		// and an S3 bucket are not servers.
		{"aws_api_gateway", "service", "API front door"},
		{"aws_cloudfront", "service", "CDN"},
		{"aws_kms", "service", "managed key service, was wrongly 'server'"},
		{"aws_s3_bucket", "service", "object storage, was wrongly 'server'"},
		{"azure_keyvault_key", "service", "managed key service"},
		{"azure_storage_account", "service", "object storage"},
		{"gcp_kms_crypto_key", "service", "managed key service"},
		{"gcp_storage_bucket", "service", "object storage"},

		// Managed database instances really are addressable hosts.
		{"aws_rds_instance", "server", "database instance"},
		{"azure_sql_database", "server", "database instance"},
		{"gcp_cloudsql_instance", "server", "database instance"},

		// Unknown types keep the conservative default.
		{"aws_something_new", "server", "unknown default"},
		{"", "server", "empty default"},
	}

	for _, tt := range tests {
		t.Run(tt.deviceType, func(t *testing.T) {
			got := mapCloudDeviceTypeToAssetType(tt.deviceType)
			if got != tt.want {
				t.Errorf("mapCloudDeviceTypeToAssetType(%q) = %q, want %q (%s)",
					tt.deviceType, got, tt.want, tt.why)
			}
			if !allowedAssetTypes[got] {
				t.Fatalf("mapCloudDeviceTypeToAssetType(%q) = %q, which is not in the "+
					"public.asset_type enum — the insert would be rejected", tt.deviceType, got)
			}
		})
	}
}

// TestMapCloudDeviceTypeToAssetType_NeverInventsEnumValues guards the whole
// mapping, not just the cases enumerated above.
func TestMapCloudDeviceTypeToAssetType_NeverInventsEnumValues(t *testing.T) {
	for _, dt := range []string{
		"aws_alb", "aws_nlb", "aws_elb", "aws_api_gateway", "aws_cloudfront",
		"aws_kms", "aws_s3_bucket", "aws_rds_instance",
		"azure_load_balancer", "azure_application_gateway", "azure_keyvault_key",
		"azure_sql_database", "azure_storage_account",
		"gcp_https_load_balancer", "gcp_ssl_proxy", "gcp_kms_crypto_key",
		"gcp_cloudsql_instance", "gcp_storage_bucket",
		"totally_unknown",
	} {
		if got := mapCloudDeviceTypeToAssetType(dt); !allowedAssetTypes[got] {
			t.Errorf("mapCloudDeviceTypeToAssetType(%q) = %q, not a valid asset_type", dt, got)
		}
	}
}
