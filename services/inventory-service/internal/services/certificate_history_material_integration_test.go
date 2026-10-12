package services

//: certificate_history records real events, not sightings.
//
// updateCertificate wrote a data_enriched row on EVERY re-sighting of a known
// certificate, so the table grew by one row per passive or active TLS
// observation of an unchanged certificate and the timeline buried the events
// that mattered. The row is now written only when the stored row's
// evaluator-readable content changed (the same verdict that gates
// compliance.certificate.changed).
//
// Mutation that proves these tests: in updateCertificate restore the
// unconditional RecordCertificateHistory(... "data_enriched" ...) call (drop the
// `if changed` guard) - the three-sightings assertion goes red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func certHistoryCount(t *testing.T, svc *CertificateService, tenant, cert uuid.UUID, eventType string) int {
	t.Helper()
	hist, err := svc.GetCertificateHistory(tenant, cert)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	n := 0
	for _, h := range hist {
		if h.EventType == eventType {
			n++
		}
	}
	return n
}

func TestIntegration_CertificateHistory_ResightingsWriteNoRows(t *testing.T) {
	svc, _, tenant := newCertFixture(t)

	notAfter := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	data := observedCert("history", notAfter)

	cert, err := svc.FindOrCreateCertificate(tenant, data)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.FindOrCreateCertificate(tenant, data); err != nil {
			t.Fatalf("re-sighting %d: %v", i, err)
		}
	}
	if n := certHistoryCount(t, svc, tenant, cert.ID, "created"); n != 1 {
		t.Fatalf("%d created rows after three sightings, want exactly 1", n)
	}
	if n := certHistoryCount(t, svc, tenant, cert.ID, "data_enriched"); n != 0 {
		t.Fatalf("%d data_enriched rows after re-sighting an unchanged certificate, want 0 (#2413)", n)
	}

	// A newly measured quality flag is a real change: exactly one more row.
	yes := true
	data.HasSCT = &yes
	if _, err := svc.FindOrCreateCertificate(tenant, data); err != nil {
		t.Fatalf("has_sct: %v", err)
	}
	if n := certHistoryCount(t, svc, tenant, cert.ID, "data_enriched"); n != 1 {
		t.Fatalf("%d data_enriched rows after a changed quality flag, want 1", n)
	}
	// ...and sighting it again adds none.
	if _, err := svc.FindOrCreateCertificate(tenant, data); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if n := certHistoryCount(t, svc, tenant, cert.ID, "data_enriched"); n != 1 {
		t.Fatalf("%d data_enriched rows after repeating the changed sighting, want still 1", n)
	}
	if n := certHistoryCount(t, svc, tenant, cert.ID, "created"); n != 1 {
		t.Fatalf("%d created rows at the end, want still 1", n)
	}
}
