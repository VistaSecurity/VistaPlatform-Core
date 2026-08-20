package services

// Guard for B-22: an AT-REST finding must never be materialized as a TLS
// crypto configuration.
//
// device-interrogation-service stamps protocol "AT-REST" on nine cloud device
// types (atRestProtocolPort). Six of them — the storage and database collectors
// — write a `resource_type` metadata key, and inventory-service's at-rest
// producer routes those into crypto_applications. The three key stores
// (aws_kms, azure_keyvault_key, gcp_kms_crypto_key) write no resource_type, so
// atRestPostureFromFinding returned false and execution fell through to
// protocol normalization — whose default arm turned anything unrecognised into
// "TLS". Every discovered customer-managed KMS / Key Vault / Cloud KMS key
// therefore became an asset carrying a TLS crypto configuration with NULL
// protocol_version and NULL cipher_suite: a negotiated-protocol measurement
// that never happened, counted in the risk and PQC denominators. The only
// signal was a "Unknown protocol 'AT-REST', defaulting to TLS" log line.
//
// That fabricating default has since been removed at the root (resolveProtocol),
// so this guard is now the NAMED half of a two-layer defence rather than the
// only one.
//
// These are pure unit tests: the two functions they pin are the whole
// classification decision, and both are DB-free.

import "testing"

func TestIsAtRestProtocol(t *testing.T) {
	for _, in := range []string{"AT-REST", "at-rest", "  AT-REST  ", "At-Rest"} {
		if !isAtRestProtocol(in) {
			t.Errorf("isAtRestProtocol(%q) = false, want true", in)
		}
	}
	// Negative polarity — without it a function returning true for everything
	// would pass the loop above.
	for _, in := range []string{"TLS", "SSH", "", "REST", "AT REST", "atrest"} {
		if isAtRestProtocol(in) {
			t.Errorf("isAtRestProtocol(%q) = true, want false", in)
		}
	}
}

// TestResolveProtocolDoesNotMapAtRest pins the other half of the guard.
//
// This test used to assert the opposite — that resolveProtocol's predecessor
// answered "TLS" for the AT-REST sentinel — because that fabricating default
// was the hazard isAtRestProtocol existed to route around. The default is gone:
// an unrecognised protocol now yields no protocol at all, so AT-REST is
// backstopped generically even if the named short-circuit above were removed.
// The named one stays because it says WHY at-rest findings leave early (they
// belong in crypto_applications), which the generic one cannot.
//
// AT-REST must still never acquire a case arm here: it is not a protocol.
func TestResolveProtocolDoesNotMapAtRest(t *testing.T) {
	got, verdict := resolveProtocol(atRestProtocolSentinel)
	if verdict == protocolEnum {
		t.Fatalf("resolveProtocol(%q) = %q, verdict %v — the AT-REST sentinel must not map "+
			"onto a protocol_type value; it describes cryptography at rest, not on the wire",
			atRestProtocolSentinel, got, verdict)
	}
	if got != "" {
		t.Fatalf("resolveProtocol(%q) returned protocol %q alongside a non-enum verdict; "+
			"an unmodelled protocol must yield nothing storable", atRestProtocolSentinel, got)
	}
	// And the sentinel must not have become a real protocol value.
	if atRestProtocolSentinel == "TLS" {
		t.Fatal("the AT-REST sentinel must not be a protocol value")
	}
}

// TestAtRestPostureFromFinding_KeyStoresAreNotRouted pins the OTHER half of the
// finding: the three key-store collectors write no resource_type, so the at-rest
// producer does not claim them. If someone later adds them to
// atRestResourceTypes, this test fails — deliberately. Routing key stores into
// crypto_applications is a product decision (every rung of that table's ladder
// — Unencrypted / Provider key / Customer key — is a category error for a
// resource that IS the key), so it should not happen as a silent map edit.
func TestAtRestPostureFromFinding_KeyStoresAreNotRouted(t *testing.T) {
	for _, rawType := range []string{"kms_key", "keyvault_key", "kms_crypto_key"} {
		f := IngestFinding{RawData: map[string]interface{}{
			"resource_type": rawType,
			"arn":           "arn:aws:kms:us-east-1:111111111111:key/abc",
		}}
		if _, ok := atRestPostureFromFinding(f); ok {
			t.Errorf("atRestPostureFromFinding routed resource_type %q into crypto_applications — "+
				"if that is now intended, the at-rest posture ladder needs a rung that describes a "+
				"key store, and the Data Protection lens needs to render it", rawType)
		}
	}

	// Positive polarity: a mapped storage type IS routed, so the assertions
	// above are about the key stores and not about the function being broken.
	f := IngestFinding{RawData: map[string]interface{}{
		"resource_type": "s3_bucket",
		"arn":           "arn:aws:s3:::evidence-bucket",
	}}
	if _, ok := atRestPostureFromFinding(f); !ok {
		t.Fatal("atRestPostureFromFinding did not route an s3_bucket finding")
	}
}
