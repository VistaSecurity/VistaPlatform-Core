package services

// Unit proof of the at-rest classification ladder.
//
// This is where a wrong answer becomes a wrong compliance verdict, and two of
// the rungs are ones the platform has got wrong before in other places:
//
//   - "could not determine" must score 0 (NOT ASSESSED) and never as a pass or
//     a fail. The S3 collector used to assume SSE-S3 on ANY error, which turned
//     an AccessDenied into a measured encrypted bucket.
//   - encryption is a LADDER, not a bit: provider-managed and customer-managed
//     keys are different postures and must not collapse into "encrypted: true".

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func s3Finding(extra map[string]interface{}) IngestFinding {
	host := "socialupkeep-marketing"
	raw := map[string]interface{}{
		"resource_type":  "s3_bucket",
		"arn":            "arn:aws:s3:::socialupkeep-marketing",
		"region":         "us-east-1",
		"cloud_provider": "aws",
	}
	for k, v := range extra {
		raw[k] = v
	}
	return IngestFinding{Hostname: &host, RawData: raw}
}

func TestAtRestPosture_RiskLadder(t *testing.T) {
	cases := []struct {
		name       string
		finding    IngestFinding
		wantScore  int
		wantBand   string
		wantKeyMgr string
		wantDet    bool
	}{
		{
			name: "undetermined scores 0 = NOT ASSESSED, not a fail and not a pass",
			finding: s3Finding(map[string]interface{}{
				"encrypted":             false,
				"encryption_determined": false,
				"encryption_type":       "unknown",
				"encryption_error":      "AccessDenied",
			}),
			wantScore: 0, wantBand: "Informational", wantKeyMgr: "", wantDet: false,
		},
		{
			name: "measured unencrypted is Critical",
			finding: s3Finding(map[string]interface{}{
				"encrypted":             false,
				"encryption_determined": true,
				"encryption_type":       "none",
			}),
			wantScore: 90, wantBand: "Critical", wantKeyMgr: "", wantDet: true,
		},
		{
			name: "SSE-S3 is encrypted under a PROVIDER key: Medium, not Low",
			finding: s3Finding(map[string]interface{}{
				"encrypted":             true,
				"encryption_determined": true,
				"encryption_type":       "sse-s3",
				"algorithm":             "AES-256",
			}),
			wantScore: 40, wantBand: "Medium", wantKeyMgr: "provider", wantDet: true,
		},
		{
			name: "the AWS bucket-level default is still a provider key",
			finding: s3Finding(map[string]interface{}{
				"encrypted":             true,
				"encryption_determined": true,
				"encryption_type":       "sse-s3-default",
				"algorithm":             "AES-256",
			}),
			wantScore: 40, wantBand: "Medium", wantKeyMgr: "provider", wantDet: true,
		},
		{
			name: "SSE-KMS is a customer-managed key: Low",
			finding: s3Finding(map[string]interface{}{
				"encrypted":             true,
				"encryption_determined": true,
				"encryption_type":       "sse-kms",
				"algorithm":             "AES-256-KMS",
				"kms_key_id":            "arn:aws:kms:us-east-1:111122223333:key/abc",
			}),
			wantScore: 10, wantBand: "Low", wantKeyMgr: "customer", wantDet: true,
		},
		{
			name: "dual-layer SSE-KMS is customer-managed too",
			finding: s3Finding(map[string]interface{}{
				"encrypted":             true,
				"encryption_determined": true,
				"encryption_type":       "sse-kms-dsse",
				"kms_key_id":            "arn:aws:kms:us-east-1:111122223333:key/abc",
			}),
			wantScore: 10, wantBand: "Low", wantKeyMgr: "customer", wantDet: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := atRestPostureFromFinding(tc.finding)
			if !ok {
				t.Fatalf("atRestPostureFromFinding returned ok=false for an S3 finding")
			}
			if p.Determined != tc.wantDet {
				t.Errorf("Determined = %v, want %v", p.Determined, tc.wantDet)
			}
			if got := p.riskScore(); got != tc.wantScore {
				t.Errorf("riskScore() = %d, want %d", got, tc.wantScore)
			}
			// The band is read through models.RiskBands — never a second ladder.
			if got := models.GetRiskLevel(p.riskScore()); got != tc.wantBand {
				t.Errorf("band = %q, want %q", got, tc.wantBand)
			}
			if p.KeyManager != tc.wantKeyMgr {
				t.Errorf("KeyManager = %q, want %q", p.KeyManager, tc.wantKeyMgr)
			}
		})
	}
}

func TestAtRestPosture_RDS(t *testing.T) {
	host := "prod-db-1"
	base := func(extra map[string]interface{}) IngestFinding {
		raw := map[string]interface{}{
			"resource_type":  "rds_instance",
			"arn":            "arn:aws:rds:us-east-1:111122223333:db:prod-db-1",
			"region":         "us-east-1",
			"cloud_provider": "aws",
		}
		for k, v := range extra {
			raw[k] = v
		}
		return IngestFinding{Hostname: &host, RawData: raw}
	}

	// The RDS collector writes no encryption_determined key at all:
	// DescribeDBInstances is authoritative, so having the instance IS having
	// the measurement. An absent key must therefore mean DETERMINED — reading
	// it as "false" would silently park every RDS instance in NOT ASSESSED.
	enc, ok := atRestPostureFromFinding(base(map[string]interface{}{
		"encrypted":       true,
		"encryption_type": "rds-storage-encryption",
		"algorithm":       "AES-256",
		"kms_key_id":      "arn:aws:kms:us-east-1:111122223333:key/rds",
	}))
	if !ok {
		t.Fatal("RDS finding not recognised as at-rest")
	}
	if !enc.Determined {
		t.Error("absent encryption_determined must read as DETERMINED for RDS, not as not-assessed")
	}
	if enc.ResourceType != "database" {
		t.Errorf("ResourceType = %q, want database", enc.ResourceType)
	}
	if enc.KeyManager != keyManagerCustomer || enc.riskScore() != 10 {
		t.Errorf("encrypted RDS with a KMS key = %q/%d, want customer/10", enc.KeyManager, enc.riskScore())
	}

	plain, _ := atRestPostureFromFinding(base(map[string]interface{}{
		"encrypted":       false,
		"encryption_type": "none",
	}))
	if plain.riskScore() != 90 {
		t.Errorf("StorageEncrypted=false = %d, want 90 (Critical)", plain.riskScore())
	}
}

// An explicit false must always beat the absent-key default. This is the jq
// `//` mistake in Go form: treating false as "missing" inverts a security flag.
func TestAtRestPosture_ExplicitFalseBeatsDefault(t *testing.T) {
	p, _ := atRestPostureFromFinding(s3Finding(map[string]interface{}{
		"encrypted":             false,
		"encryption_determined": false,
	}))
	if p.Determined {
		t.Fatal("explicit encryption_determined=false was overridden by the absent-key default")
	}
	if p.riskScore() != atRestRiskNotAssessed {
		t.Errorf("riskScore = %d, want %d (NOT ASSESSED)", p.riskScore(), atRestRiskNotAssessed)
	}
}

func TestAtRestPosture_IgnoresNonAtRestFindings(t *testing.T) {
	host := "api.example.test"
	for _, f := range []IngestFinding{
		{Hostname: &host, Protocol: "TLS"},
		{Hostname: &host, Protocol: "TLS", RawData: map[string]interface{}{"resource_type": "load_balancer"}},
		{Hostname: &host, RawData: map[string]interface{}{"resource_type": "s3_bucket"}}, // no ARN: nothing to key on
	} {
		if _, ok := atRestPostureFromFinding(f); ok {
			t.Errorf("finding %+v was wrongly classified as at-rest", f.RawData)
		}
	}
}

func TestAtRestPosture_OtherProviders(t *testing.T) {
	cases := []struct {
		rawType, encType string
		wantResource     string
		wantKeyMgr       string
		wantScore        int
	}{
		{"storage_account", "microsoft-managed", "cloud_storage", "provider", 40},
		{"storage_account", "cmk", "cloud_storage", "customer", 10},
		{"gcs_bucket", "google-managed", "cloud_storage", "provider", 40},
		{"gcs_bucket", "cmek", "cloud_storage", "customer", 10},
		{"sql_database", "tde-service-managed", "database", "provider", 40},
		{"sql_database", "tde-cmk", "database", "customer", 10},
		{"cloudsql_instance", "cmek", "database", "customer", 10},
	}
	for _, tc := range cases {
		t.Run(tc.rawType+"/"+tc.encType, func(t *testing.T) {
			p, ok := atRestPostureFromFinding(IngestFinding{RawData: map[string]interface{}{
				"resource_type":   tc.rawType,
				"arn":             "id/" + tc.rawType,
				"encrypted":       true,
				"encryption_type": tc.encType,
			}})
			if !ok {
				t.Fatal("not recognised as at-rest")
			}
			if p.ResourceType != tc.wantResource {
				t.Errorf("ResourceType = %q, want %q", p.ResourceType, tc.wantResource)
			}
			if p.KeyManager != tc.wantKeyMgr {
				t.Errorf("KeyManager = %q, want %q", p.KeyManager, tc.wantKeyMgr)
			}
			if p.riskScore() != tc.wantScore {
				t.Errorf("riskScore = %d, want %d", p.riskScore(), tc.wantScore)
			}
		})
	}
}

func TestAlgorithmCodeForAtRest(t *testing.T) {
	// The collectors report DISPLAY names ("AES-256"); the catalogue keys on
	// CODES ("AES256"). Passing the display name through unchanged resolves
	// nothing and leaves every at-rest row's algorithm_id NULL.
	cases := map[string]string{
		"AES-256":          "AES256",
		"AES-256-KMS":      "AES256",
		"AES-256-KMS-DSSE": "AES256",
		"aes-128":          "AES128",
		"":                 "",
		"something-else":   "",
	}
	for in, want := range cases {
		if got := algorithmCodeForAtRest(in); got != want {
			t.Errorf("algorithmCodeForAtRest(%q) = %q, want %q", in, got, want)
		}
	}
}

// The upsert must conflict on the natural key, or every discovery run appends a
// duplicate row for the same bucket. Asserted on the SQL text (the same
// technique that pins insertCryptoImplementationSQL's bound columns) so the
// guard holds without a database.
func TestUpsertCryptoApplicationSQL_ConflictsOnNaturalKey(t *testing.T) {
	for _, want := range []string{
		"ON CONFLICT (tenant_id, resource_identifier, encryption_context)",
		"WHERE deleted_at IS NULL",
		"DO UPDATE SET",
		"last_verified_at     = NOW()",
	} {
		if !strings.Contains(upsertCryptoApplicationSQL, want) {
			t.Errorf("upsertCryptoApplicationSQL is missing %q — re-discovery would duplicate rows", want)
		}
	}
	if strings.Contains(upsertCryptoApplicationSQL, "first_discovered_at  = ") {
		t.Error("the upsert must not move first_discovered_at on conflict")
	}
}
