package services

// A cloud endpoint's TLS handshake (device-interrogation-service) now carries
// the shared probe's certificate quality flags and OCSP answer at the top level
// of its discovery metadata ( item 3). This is the other half: that
// metadata, ingested, lands in the certificates table's quality columns —
// including an explicit has_sct = false, which is an answer, not a gap.
//
// cert_validation_status rides the same metadata but has no column on the
// internal-asset path: only external_connections stores it, and a cloud
// finding has no source address so it never takes that path.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func TestIntegration_Ingest_CloudEndpointHandshakeValidationReachesTheCertificateRow(t *testing.T) {
	f := newLeafLinkFixture(t)
	fp := hexFingerprint("cloud-endpoint-validation")

	finding := leafCertFinding("lb.cloud.example.test", "203.0.113.40", 443, fp)
	// The metadata a cloud collector's discovery row carries after this change.
	for k, v := range map[string]interface{}{
		"discovery_method":            "cloud_api",
		"cert_validation_status":      "untrusted_ca",
		"cert_validation_error":       "x509: certificate signed by unknown authority",
		"cert_has_sct":                false,
		"cert_sct_source":             "none",
		"cert_is_ev":                  false,
		"ocsp_status":                 "revoked",
		"ocsp_detail":                 "revoked 2026-01-02 (keyCompromise)",
		"server_requests_client_cert": false,
	} {
		finding.RawData[k] = v
	}
	if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{finding}, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var cert models.Certificate
	if err := f.db.Get(&cert, `
		SELECT has_sct, sct_source, is_ev, ocsp_status, ocsp_detail
		FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2`, f.tenant, fp); err != nil {
		t.Fatalf("read back certificate: %v", err)
	}
	if cert.OCSPStatus == nil || *cert.OCSPStatus != "revoked" {
		t.Errorf("ocsp_status = %v, want revoked", cert.OCSPStatus)
	}
	if cert.OCSPDetail == nil || *cert.OCSPDetail != "revoked 2026-01-02 (keyCompromise)" {
		t.Errorf("ocsp_detail = %v, want the responder's detail", cert.OCSPDetail)
	}
	if cert.HasSCT == nil || *cert.HasSCT {
		t.Errorf("has_sct = %v, want a stored false, not NULL", cert.HasSCT)
	}
}
