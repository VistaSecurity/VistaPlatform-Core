package certificates

import (
	"encoding/json"
	"testing"
	"time"
)

// decodeQualityFixture round-trips through encoding/json so numbers and bools
// arrive in the shapes a real import body produces (float64, bool).
func decodeQualityFixture(t *testing.T, v map[string]interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCertificateQualityFromMetadata_ReadsEveryFlag(t *testing.T) {
	q := CertificateQualityFromMetadata(decodeQualityFixture(t, map[string]interface{}{
		"certificates":         []interface{}{map[string]interface{}{"chain_order": 0, "subject_dn": "CN=a"}},
		"cert_has_sct":         true,
		"cert_sct_source":      "embedded",
		"cert_known_bad_ca":    "Superfish",
		"cert_no_subject":      true,
		"cert_no_common_name":  true,
		"cert_is_ev":           true,
		"cert_large_san_count": 150,
		"ocsp_status":          "revoked",
		"ocsp_detail":          "keyCompromise",
	}))
	if q.HasSCT == nil || !*q.HasSCT {
		t.Errorf("HasSCT = %v, want true", q.HasSCT)
	}
	for name, got := range map[string]*string{"SCTSource": q.SCTSource, "KnownBadCA": q.KnownBadCA, "OCSPStatus": q.OCSPStatus, "OCSPDetail": q.OCSPDetail} {
		if got == nil {
			t.Errorf("%s absent", name)
		}
	}
	if *q.KnownBadCA != "Superfish" || *q.OCSPStatus != "revoked" {
		t.Errorf("KnownBadCA/OCSPStatus = %q/%q", *q.KnownBadCA, *q.OCSPStatus)
	}
	if !q.NoSubject || !q.NoCommonName || !q.IsEV {
		t.Errorf("bool flags lost: %+v", q)
	}
	if q.LargeSANCount == nil || *q.LargeSANCount != 150 {
		t.Errorf("LargeSANCount = %v, want 150", q.LargeSANCount)
	}
}

// An explicit false is an answer, not an absence (CLAUDE.md: the jq `//`
// mistake). Both polarities: false stays false, and a missing key stays nil.
func TestCertificateQualityFromMetadata_FalseIsAnAnswer(t *testing.T) {
	q := CertificateQualityFromMetadata(decodeQualityFixture(t, map[string]interface{}{"cert_has_sct": false}))
	if q.HasSCT == nil || *q.HasSCT {
		t.Fatalf("HasSCT = %v, want an explicit false", q.HasSCT)
	}
	q = CertificateQualityFromMetadata(map[string]interface{}{})
	if q.HasSCT != nil {
		t.Fatalf("HasSCT = %v for a discovery that never measured it, want nil", *q.HasSCT)
	}
	if q.SCTSource != nil || q.KnownBadCA != nil || q.OCSPStatus != nil {
		t.Fatalf("empty metadata produced flags: %+v", q)
	}
}

// The TLS enricher puts cert_validation_status on the envelope beside the
// array; a leaf that carries its own wins.
func TestCertificateQualityFromMetadata_ValidationStatus(t *testing.T) {
	q := CertificateQualityFromMetadata(decodeQualityFixture(t, map[string]interface{}{
		"certificates":           []interface{}{map[string]interface{}{"chain_order": 0}},
		"cert_validation_status": "expired",
	}))
	if q.ValidationStatus == nil || *q.ValidationStatus != "expired" {
		t.Fatalf("envelope validation status not read: %v", q.ValidationStatus)
	}
	q = CertificateQualityFromMetadata(decodeQualityFixture(t, map[string]interface{}{
		"certificates": []interface{}{
			map[string]interface{}{"chain_order": 1, "cert_validation_status": "valid"},
			map[string]interface{}{"chain_order": 0, "cert_validation_status": "self_signed"},
		},
		"cert_validation_status": "expired",
	}))
	if q.ValidationStatus == nil || *q.ValidationStatus != "self_signed" {
		t.Fatalf("leaf (lowest chain_order) validation status not preferred: %v", q.ValidationStatus)
	}
}

func TestCertificateQualityFromMetadata_NilMap(t *testing.T) {
	if q := CertificateQualityFromMetadata(nil); q != (CertificateQuality{}) {
		t.Fatalf("nil metadata = %+v, want zero", q)
	}
}

func TestParseMetadataTime_EveryProducerLayout(t *testing.T) {
	want := time.Date(2026, 4, 20, 12, 30, 0, 0, time.UTC)
	for name, value := range map[string]string{
		"RFC3339":                 "2026-04-20T12:30:00Z",
		"Go String() UTC":         "2026-04-20 12:30:00 +0000 UTC",
		"Go String() with offset": "2026-04-20 14:30:00 +0200 CEST",
	} {
		got, ok := ParseMetadataTime(value)
		if !ok || !got.UTC().Equal(want) {
			t.Errorf("%s: ParseMetadataTime(%q) = %v, %v; want %v", name, value, got, ok, want)
		}
	}
	if _, ok := ParseMetadataTime("not a time"); ok {
		t.Error("an unparseable value parsed")
	}
	if _, ok := ParseMetadataTime(""); ok {
		t.Error("the empty string parsed")
	}
}
