package services

// Certificate-change reconcile scoping (W2-13).
//
// Before this, OnCertificateChanged ran a FULL-TENANT reconcile — every published control
// against every asset — once per certificate event. A cert-heavy ingest batch fired those
// back-to-back, and at 10k assets each pass was enormous and identical to the last.
// Scoping is the ADR-0015 per-asset primitive, already used by OnAssetChanged.

import (
	"testing"

	"github.com/google/uuid"
)

// The certificate is always a target, even with no asset binding at all: certificate-
// scoped measurements (cert_pqc_status, signature, validity) key their findings on the
// certificate id. The old code returned early on zero links and left those stale.
func TestCertReconcileTargets_UnlinkedCertificateStillReconcilesItself(t *testing.T) {
	cert := uuid.New()
	targets, tenantWide := certReconcileTargets(cert, nil)
	if tenantWide {
		t.Fatal("an unlinked certificate must not escalate to a whole-tenant reconcile")
	}
	if len(targets) != 1 || targets[0] != cert {
		t.Fatalf("targets = %v, want just the certificate %s", targets, cert)
	}
}

// Linked assets are reconciled alongside the certificate — a cert change moves the
// crypto-configuration measurements of the assets it is bound to.
func TestCertReconcileTargets_IncludesLinkedAssets(t *testing.T) {
	cert := uuid.New()
	a, b := uuid.New(), uuid.New()

	targets, tenantWide := certReconcileTargets(cert, []uuid.UUID{a, b})
	if tenantWide {
		t.Fatal("two linked assets must stay on the scoped path")
	}
	if len(targets) != 3 || targets[0] != cert {
		t.Fatalf("targets = %v, want [cert a b]", targets)
	}
}

// A certificate reachable through several implementations of the same asset must be
// reconciled once, not once per implementation.
func TestCertReconcileTargets_DedupsRepeatedAssets(t *testing.T) {
	cert := uuid.New()
	a := uuid.New()

	targets, _ := certReconcileTargets(cert, []uuid.UUID{a, a, a, cert})
	if len(targets) != 2 {
		t.Fatalf("targets = %v, want the certificate and one asset", targets)
	}
}

// Past the fan-out limit, N bounded per-asset passes stop being cheaper than one shared-
// extraction tenant pass, so the scoped path deliberately gives way.
func TestCertReconcileTargets_EscalatesPastFanOutLimit(t *testing.T) {
	cert := uuid.New()

	atLimit := make([]uuid.UUID, certFanOutLimit)
	for i := range atLimit {
		atLimit[i] = uuid.New()
	}
	if _, tenantWide := certReconcileTargets(cert, atLimit); tenantWide {
		t.Fatalf("exactly %d linked assets must stay scoped", certFanOutLimit)
	}

	overLimit := append(atLimit, uuid.New())
	if _, tenantWide := certReconcileTargets(cert, overLimit); !tenantWide {
		t.Fatalf("%d linked assets must escalate to a tenant-wide reconcile", len(overLimit))
	}
}
