package services

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// An ACM certificate as getCertificateDetails projects it, shaped after the one
// the live audit found (RSA-2048, SHA256WITHRSA, a fixed not_after inside the
// 90-day expiry band). Every identifier is a documentation-reserved value —
// account 123456789012, example.com — and none of it names a real account,
// domain or distribution: this file ships to the public repo, and the export's
// leak gate is the last place a real account number should be caught.
func acmDetailsFixture() map[string]interface{} {
	return map[string]interface{}{
		"arn":                       "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000001",
		"domain_name":               "shop.example.com",
		"subject":                   "CN=shop.example.com",
		"issuer":                    "Amazon",
		"serial":                    "0f:1e:2d:3c",
		"status":                    "ISSUED",
		"type":                      "AMAZON_ISSUED",
		"key_algorithm":             "RSA_2048",
		"signature_algorithm":       "SHA256WITHRSA",
		"not_before":                "2025-11-19T00:00:00Z",
		"not_after":                 "2026-12-18T23:59:59Z",
		"renewal_eligibility":       "ELIGIBLE",
		"subject_alternative_names": []interface{}{"shop.example.com", "www.shop.example.com"},
		"in_use_by":                 []interface{}{"arn:aws:cloudfront::123456789012:distribution/EXAMPLE0DIST1"},
	}
}

func acmEntryFixture() map[string]interface{} {
	d := acmDetailsFixture()
	return map[string]interface{}{"arn": d["arn"], "details": d}
}

func TestAcmKeyAlgorithm(t *testing.T) {
	cases := []struct {
		spec   string
		family string
		bits   int
		curve  string
	}{
		{"RSA_2048", "RSA", 2048, ""},
		{"RSA_4096", "RSA", 4096, ""},
		{"EC_prime256v1", "ECDSA", 256, "P-256"},
		{"EC_secp384r1", "ECDSA", 384, "P-384"},
		{"EC_secp521r1", "ECDSA", 521, "P-521"},
		// An unrecognised token is not evidence. Guessing a family from it is
		// how a wrong answer that looks right gets stored.
		{"PQC_SOMETHING", "", 0, ""},
		{"", "", 0, ""},
	}
	for _, tc := range cases {
		family, bits, curve := acmKeyAlgorithm(tc.spec)
		if family != tc.family || bits != tc.bits || curve != tc.curve {
			t.Errorf("acmKeyAlgorithm(%q) = (%q, %d, %q), want (%q, %d, %q)",
				tc.spec, family, bits, curve, tc.family, tc.bits, tc.curve)
		}
	}
}

// The family and the size must stay APART. algorithmCodeForKey in
// inventory-service builds "RSA-<bits>" from the pair, and the bare `RSA` row in
// the `algorithms` catalogue is "RSA key transport (static)" — a TLS
// key-exchange assessment scored 70/weak — not an assessment of a 2048-bit
// public key (RSA-2048, 40/acceptable). Emitting "RSA_2048" or "RSA 2048" as
// the key_algorithm resolves to neither; emitting a bare "RSA" with no size
// resolves to the wrong one.
func TestCanonicalACMCertificateKeepsAlgorithmAndSizeApart(t *testing.T) {
	cert := canonicalACMCertificate(acmEntryFixture())
	if cert == nil {
		t.Fatal("canonicalACMCertificate returned nil for a complete ACM record")
	}
	if got := cert["key_algorithm"]; got != "RSA" {
		t.Errorf("key_algorithm = %v, want the FAMILY %q", got, "RSA")
	}
	if got := cert["key_size"]; got != 2048 {
		t.Errorf("key_size = %v, want 2048 — without it the catalogue lookup has no sized row to resolve to", got)
	}
}

func TestCanonicalACMCertificateShape(t *testing.T) {
	cert := canonicalACMCertificate(acmEntryFixture())
	if cert == nil {
		t.Fatal("canonicalACMCertificate returned nil for a complete ACM record")
	}

	want := map[string]interface{}{
		"subject_dn":    "CN=shop.example.com",
		"issuer_dn":     "Amazon",
		"common_name":   "shop.example.com",
		"serial_number": "0f:1e:2d:3c",
		"not_before":    "2025-11-19T00:00:00Z",
		"not_after":     "2026-12-18T23:59:59Z",
		"signature_alg": "SHA256WITHRSA",
		"data_source":   "cloud_api",
	}
	for k, v := range want {
		if cert[k] != v {
			t.Errorf("%s = %#v, want %#v", k, cert[k], v)
		}
	}

	sans, _ := cert["subject_alternative_names"].([]string)
	if len(sans) != 2 || sans[0] != "shop.example.com" {
		t.Errorf("subject_alternative_names = %#v, want the two names ACM listed", cert["subject_alternative_names"])
	}

	// ABSENT, not invented. DescribeCertificate returns metadata about a
	// certificate, never the certificate, so there is no PEM to hash. A
	// fabricated fingerprint would be compared against real ones.
	for _, k := range []string{"fingerprint_sha256", "fingerprint_sha1", "certificate_pem", "is_ca"} {
		if _, present := cert[k]; present {
			t.Errorf("%s is present (%#v) — an ACM response cannot state it, and a plausible-looking "+
				"value here would be compared against certificates observed on the wire", k, cert[k])
		}
	}

	// The non-certificate ACM facts travel in the same sub-map
	// EnrichCertificatesWithACM stamps, so both paths hand the materializer one
	// shape.
	acm, _ := cert["acm_metadata"].(map[string]interface{})
	if acm == nil {
		t.Fatal("acm_metadata missing")
	}
	if acm["arn"] != "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000001" {
		t.Errorf("acm_metadata.arn = %#v", acm["arn"])
	}
	if acm["status"] != "ISSUED" || acm["renewal_eligibility"] != "ELIGIBLE" {
		t.Errorf("acm_metadata = %#v, want status + renewal_eligibility carried through", acm)
	}

	// D5: expires_in_days is deleted, not fixed. It computed the total validity
	// period and called it time remaining — 197 days for a certificate with 88.
	if _, present := cert["expires_in_days"]; present {
		t.Error("expires_in_days is present — it was deleted (D5); not_after is the fact and readers compute from it")
	}
}

// The materializer needs BOTH a subject and an issuer (extractCertificateData
// returns nil without either), so a record that cannot become a certificate row
// is dropped HERE, out loud, rather than one layer down in silence.
func TestCanonicalACMCertificateRejectsUnusableRecords(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"no details behind the ARN": {"arn": "arn:aws:acm:…"},
		"no issuer": {"arn": "a", "details": map[string]interface{}{
			"domain_name": "example.com", "subject": "CN=example.com",
		}},
		"no subject and no domain": {"arn": "a", "details": map[string]interface{}{
			"issuer": "Amazon",
		}},
	}
	for name, entry := range cases {
		if got := canonicalACMCertificate(entry); got != nil {
			t.Errorf("%s: got %#v, want nil", name, got)
		}
	}

	// Subject absent but the domain present: ACM issues with CN=DomainName, so
	// rendering the domain as a one-RDN DN restates a fact rather than
	// inventing one.
	got := canonicalACMCertificate(map[string]interface{}{"arn": "a", "details": map[string]interface{}{
		"domain_name": "example.com", "issuer": "Amazon",
	}})
	if got == nil || got["subject_dn"] != "CN=example.com" {
		t.Errorf("subject_dn = %#v, want CN=example.com derived from the domain name", got)
	}
}

func TestMergeProviderCertificatesLabelsAndDedupes(t *testing.T) {
	arn := "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000001"

	// A handshake chain in which EnrichCertificatesWithACM already matched the
	// ACM record by domain. Re-appending it would put one certificate in the
	// array twice.
	observed := []interface{}{
		map[string]interface{}{
			"subject_dn":         "CN=shop.example.com",
			"issuer_dn":          "CN=Amazon RSA 2048 M01,O=Amazon,C=US",
			"fingerprint_sha256": "aa",
			"acm_metadata":       map[string]interface{}{"arn": arn},
		},
		map[string]interface{}{
			"subject_dn":         "CN=Amazon RSA 2048 M01,O=Amazon,C=US",
			"issuer_dn":          "CN=Amazon Root CA 1,O=Amazon,C=US",
			"fingerprint_sha256": "bb",
		},
	}

	merged := mergeProviderCertificates(observed, []interface{}{acmEntryFixture()})
	if len(merged) != 2 {
		t.Fatalf("got %d entries, want 2 — the ACM record was already folded into the observed leaf by ARN", len(merged))
	}
	for i, c := range merged {
		m := c.(map[string]interface{})
		if m["data_source"] != certDataSourceObserved {
			t.Errorf("entry %d data_source = %#v, want %q — bytes off the wire are an observation, and "+
				"without a per-entry label every certificate in a cloud discovery reads as provider-managed",
				i, m["data_source"], certDataSourceObserved)
		}
		if m["chain_order"] != i {
			t.Errorf("entry %d chain_order = %#v, want %d", i, m["chain_order"], i)
		}
	}

	// An ACM record with no observed counterpart is the case the whole slice
	// exists for: the CloudFront viewer config carries the ACM certificate and
	// no handshake of its own.
	alone := mergeProviderCertificates(nil, []interface{}{acmEntryFixture()})
	if len(alone) != 1 {
		t.Fatalf("got %d entries, want 1", len(alone))
	}
	m := alone[0].(map[string]interface{})
	if m["data_source"] != certDataSourceCloudAPI {
		t.Errorf("data_source = %#v, want %q", m["data_source"], certDataSourceCloudAPI)
	}
	if m["chain_order"] != 0 {
		t.Errorf("chain_order = %#v, want 0 — a lone certificate is the leaf", m["chain_order"])
	}

	// Nothing to record means no key at all, not an empty array.
	if got := mergeProviderCertificates(nil, nil); got != nil {
		t.Errorf("mergeProviderCertificates(nil, nil) = %#v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// The WIRING.
//
// Everything above tests the projection. This drives the real discovery-row
// write — writeSensorDiscoveriesTx — with a CloudFront device shaped exactly
// like the one the live AWS discovery produced, and reads the metadata JSON
// that actually reaches `sensor_discoveries`.
//
// Deleting the mergeProviderCertificates call in cloud_discovery_service.go
// turns this red. A test of the projection alone would stay green, which is how
// the original defect survived: the ACM data was correctly shaped the whole
// time and simply parked under a key nothing read.
// ---------------------------------------------------------------------------

func TestWriteSensorDiscoveries_ACMCertificateUsesCanonicalKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.New()
	integrationID := uuid.New()
	sensorID := uuid.New()

	var captured []byte
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id FROM sensors`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(sensorID))
	mock.ExpectExec(`(?s)INSERT INTO sensor_discoveries`).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			capturingArg{into: &captured}, // the metadata JSONB — the 9th placeholder
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	hostname := "shop.example.com"
	device := models.Device{
		ID:              uuid.New(),
		TenantID:        tenantID,
		DeviceType:      "aws_cloudfront",
		Hostname:        &hostname,
		DiscoveryMethod: "cloud_api",
		Metadata: models.JSONB(map[string]interface{}{
			"distribution_id": "EXAMPLE0DIST1",
			"crypto_configs": []map[string]interface{}{
				{
					"protocol": "HTTPS",
					"port":     443,
					"hostname": hostname,
					"metadata": map[string]interface{}{
						"resource_kind": "cloudfront_viewer",
						"certificates":  []map[string]interface{}{acmEntryFixture()},
					},
				},
			},
		}),
		CreatedAt: time.Now(),
	}

	svc := &CloudDiscoveryService{}
	// resolveDNS=false: no network from a unit test, so dest_ip stays the
	// unspecified placeholder. Irrelevant to what is asserted here.
	if _, err := svc.writeSensorDiscoveriesTx(context.Background(), tx, tenantID, "batch-1", integrationID, "aws",
		[]models.Device{device}, time.Now(), false); err != nil {
		t.Fatalf("writeSensorDiscoveriesTx: %v", err)
	}
	_ = tx.Rollback()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no discovery row was written: %v", err)
	}
	var meta map[string]interface{}
	if err := json.Unmarshal(captured, &meta); err != nil {
		t.Fatalf("unmarshal discovery metadata: %v", err)
	}

	// Assembled from parts, not spelled out, for the same reason CLAUDE.md's
	// two "quanta"+"view" guards are: the canonical-key guard hunts for this
	// exact literal, and a test that names it would be its own violation.
	retiredKey := "acm_" + "certificates"
	if _, present := meta[retiredKey]; present {
		t.Errorf("the discovery row still carries %q — no materializer reads that key", retiredKey)
	}
	certs, _ := meta["certificates"].([]interface{})
	if len(certs) != 1 {
		t.Fatalf("metadata[\"certificates\"] = %#v, want the ACM certificate under the CANONICAL key", meta["certificates"])
	}
	cert := certs[0].(map[string]interface{})
	if cert["subject_dn"] != "CN=shop.example.com" || cert["not_after"] != "2026-12-18T23:59:59Z" {
		t.Errorf("certificate entry = %#v, want the canonical subject_dn + not_after", cert)
	}
	if cert["data_source"] != certDataSourceCloudAPI {
		t.Errorf("data_source = %#v, want %q so the Certificates lens can badge it", cert["data_source"], certDataSourceCloudAPI)
	}
}

// capturingArg matches any value and keeps a copy of it, so the test can assert
// on the metadata JSON that actually went to the database rather than on a
// value it recomputed itself.
type capturingArg struct{ into *[]byte }

func (c capturingArg) Match(v driver.Value) bool {
	switch b := v.(type) {
	case []byte:
		*c.into = append([]byte(nil), b...)
	case string:
		*c.into = []byte(b)
	default:
		return false
	}
	return true
}
