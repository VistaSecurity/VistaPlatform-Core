package services

//: compliance.certificate.changed fires only when the stored certificate
// row's evaluator-readable content changed.
//
// CertificateService.UpdateCertificate used to publish on EVERY re-sighting of a
// known certificate, so each passive or active TLS observation of an unchanged
// certificate re-triggered a compliance evaluation that wrote nothing. The rule
// is decided from the stored rows before and after the write, never from what
// the caller meant to write. Driven through FindOrCreateCertificate (the path
// ingest takes) against a real Postgres with a recording publisher.
//
// Mutation that proves these tests: in updateCertificate make `changed` always
// true (restore the unconditional publish) - the "same certificate twice" and
// "re-sighting after a quality flag was set" assertions go red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
)

type certChangeRecorder struct {
	changeRecorder
	cmu    sync.Mutex
	certs  []uuid.UUID
	change []sharedevents.ChangeType
}

func (r *certChangeRecorder) PublishCertificateChanged(_ context.Context, _, id uuid.UUID, ct sharedevents.ChangeType, _ string) error {
	r.cmu.Lock()
	defer r.cmu.Unlock()
	r.certs = append(r.certs, id)
	r.change = append(r.change, ct)
	return nil
}

func (r *certChangeRecorder) count() int {
	r.cmu.Lock()
	defer r.cmu.Unlock()
	return len(r.certs)
}

func observedCert(label string, notAfter time.Time) models.CertificateData {
	return models.CertificateData{
		SubjectDN:          "CN=" + label + ".example.test",
		IssuerDN:           "CN=Changed Event CA",
		SerialNumber:       "0a1b2c" + label,
		CommonName:         label + ".example.test",
		NotBefore:          notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:           notAfter,
		FingerprintSHA256:  hexFingerprint("cert-changed-" + label),
		PublicKeyAlgorithm: "RSA",
		PublicKeySize:      2048,
		SignatureAlgorithm: "SHA256-RSA",
		DataSource:         "discovery",
	}
}

func TestIntegration_CertificateChanged_SameCertificateTwicePublishesOnce(t *testing.T) {
	svc, _, tenant := newCertFixture(t)
	rec := &certChangeRecorder{}
	svc.eventPublisher = &EventPublisherService{publisher: rec, lifecycle: &syncLifecycle{}}

	notAfter := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	data := observedCert("resight", notAfter)

	first, err := svc.FindOrCreateCertificate(tenant, data)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n := rec.count(); n != 1 || rec.change[0] != sharedevents.ChangeTypeCreated {
		t.Fatalf("a NEW certificate published %d events (%v), want exactly one created", n, rec.change)
	}

	for i := 0; i < 3; i++ {
		again, err := svc.FindOrCreateCertificate(tenant, data)
		if err != nil {
			t.Fatalf("re-sighting %d: %v", i, err)
		}
		if again.ID != first.ID {
			t.Fatalf("re-sighting resolved to %s, want the existing %s", again.ID, first.ID)
		}
	}
	if n := rec.count(); n != 1 {
		t.Fatalf("%d certificate.changed events after re-sighting an unchanged certificate, want exactly 1 (the creation) - "+
			"a re-sighting that moved only last_seen/updated_at must publish nothing (#2413)", n)
	}
}

func TestIntegration_CertificateChanged_ChangedContentPublishesAgain(t *testing.T) {
	svc, db, tenant := newCertFixture(t)
	rec := &certChangeRecorder{}
	svc.eventPublisher = &EventPublisherService{publisher: rec, lifecycle: &syncLifecycle{}}

	notAfter := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	data := observedCert("moves", notAfter)
	cert, err := svc.FindOrCreateCertificate(tenant, data)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	want := 1
	expect := func(step string) {
		t.Helper()
		if n := rec.count(); n != want {
			t.Fatalf("%s: %d certificate.changed events, want %d", step, n, want)
		}
	}
	expect("creation")

	// A certificate with a different not_after is a different certificate (the
	// fingerprint covers validity; UpdateCertificate never rewrites not_after),
	// so a renewal is a creation, not an update.
	renewed := observedCert("moves", notAfter.Add(30*24*time.Hour))
	renewed.FingerprintSHA256 = hexFingerprint("cert-changed-moves-renewed")
	renewed.SerialNumber = "0a1b2c-renewed"
	if _, err := svc.FindOrCreateCertificate(tenant, renewed); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	want++
	expect("renewed certificate (new not_after)")

	// Re-sighting the original: nothing moved.
	if _, err := svc.FindOrCreateCertificate(tenant, data); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	expect("re-sighting the original certificate")

	// A newly measured quality flag.
	yes := true
	data.HasSCT = &yes
	if _, err := svc.FindOrCreateCertificate(tenant, data); err != nil {
		t.Fatalf("has_sct: %v", err)
	}
	want++
	expect("newly set cert_has_sct")

	// OCSP result arriving later, then repeated.
	data.OCSPStatus = "good"
	if _, err := svc.FindOrCreateCertificate(tenant, data); err != nil {
		t.Fatalf("ocsp: %v", err)
	}
	want++
	expect("newly set ocsp_status")
	if _, err := svc.FindOrCreateCertificate(tenant, data); err != nil {
		t.Fatalf("ocsp repeat: %v", err)
	}
	expect("re-sighting after the quality flags were set")

	// A SAN set or algorithm change is content too.
	data.SubjectAlternativeNames = []string{"a.example.test", "b.example.test"}
	data.PublicKeySize = 4096
	if _, err := svc.FindOrCreateCertificate(tenant, data); err != nil {
		t.Fatalf("key size: %v", err)
	}
	want++
	expect("changed SANs and public key size")

	// The published event names the certificate.
	if got := rec.certs[len(rec.certs)-1]; got != cert.ID {
		t.Fatalf("event names %s, want %s", got, cert.ID)
	}

	// Moving only the bookkeeping timestamps is not a change.
	if _, err := db.Exec(`UPDATE certificates SET last_data_update = NOW() - INTERVAL '1 hour', updated_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, cert.ID); err != nil {
		t.Fatalf("age timestamps: %v", err)
	}
	if _, err := svc.FindOrCreateCertificate(tenant, data); err != nil {
		t.Fatalf("timestamp-only: %v", err)
	}
	expect("observation that only moved timestamps")
}
