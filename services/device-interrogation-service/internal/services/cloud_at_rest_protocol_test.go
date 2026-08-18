package services

// Guard against re-manufacturing the phantom TLS endpoint.
//
// WriteSensorDiscoveries' fallback branch (a device with no crypto config)
// hardcoded protocol "TLS" and port 443 for EVERY device. That put S3 buckets,
// RDS instances and KMS keys into Inventory as TLS endpoints on 443 with no
// version and no cipher suite — an invented measurement, which reads to a user
// as a real one. At-rest resources have no negotiated protocol and no port.

import "testing"

func TestAtRestProtocolPort(t *testing.T) {
	atRest := []string{
		"aws_s3_bucket", "aws_rds_instance", "aws_kms",
		"azure_storage_account", "azure_sql_database", "azure_keyvault_key",
		"gcp_storage_bucket", "gcp_cloudsql_instance", "gcp_kms_crypto_key",
	}
	for _, dt := range atRest {
		proto, port := atRestProtocolPort(dt)
		if proto == "TLS" {
			t.Errorf("%s: protocol = TLS — an at-rest resource is not a TLS endpoint", dt)
		}
		if proto != "AT-REST" {
			t.Errorf("%s: protocol = %q, want AT-REST", dt, proto)
		}
		if port != 0 {
			t.Errorf("%s: port = %d, want 0 — an at-rest resource has no listening port", dt, port)
		}
	}

	// The other direction matters just as much: marking a real endpoint as
	// at-rest would suppress a genuine TLS measurement.
	for _, dt := range []string{"aws_alb", "aws_cloudfront", "aws_api_gateway", "azure_application_gateway", ""} {
		proto, port := atRestProtocolPort(dt)
		if proto != "TLS" || port != 443 {
			t.Errorf("%s: got %s:%d, want the historical TLS:443 fallback", dt, proto, port)
		}
	}
}
