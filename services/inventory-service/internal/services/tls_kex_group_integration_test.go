package services

// End-to-end proof, against a real Postgres with the real schema and seed, that
// a TLS endpoint's negotiated key-exchange group becomes its configuration's
// key_exchange component and decides its PQC class.
//
// Before the TLS probes recorded the group, a TLS 1.3 configuration's key
// exchange was never measured: TLS_AES_128_GCM_SHA256 names none, and the
// cipher-suite parser assumes classical ECDHE for every TLS 1.3 suite. So an
// endpoint already negotiating X25519MLKEM768 was classed needs-migration, and
// the one PQC signal visible on the wire was thrown away.
//
// Each finding arrives the way the Platform Sensor sends it — crypto fields
// nested in "data" — and goes through the real ingest adapter, so the test
// covers the key-name wiring as well as the classification.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// Every name the TLS probes can record must resolve to a key_exchange row in
// the catalogue, or ingest silently leaves the configuration's key exchange
// unlinked. Driven from the probes' own mapping, so renaming a group there
// without the catalogue following turns this red. The match must be the row's
// own code — the refinement's link statement (linkMeasuredGroupSQL) resolves by
// exact code, not by the classifier's substring fallback.
func TestIntegration_TLSKeyExchangeGroup_EveryRecordedNameIsCatalogued(t *testing.T) {
	svc, _, _ := newSSHIngestFixture(t, "tls-kex-catalogue.example.test")
	groups := append(append([]tls.CurveID(nil), discovery.ClassicalTLSGroups...), discovery.PQCHybridTLSGroups...)
	for _, id := range groups {
		name := discovery.TLSKeyExchangeGroupName(id)
		alg, err := svc.algorithmService.ClassifyAlgorithm(name, "key_exchange")
		if err != nil {
			t.Fatalf("classify %q: %v", name, err)
		}
		switch {
		case alg == nil:
			t.Errorf("%q (TLS group %d) resolves to no key_exchange catalogue row", name, id)
		case !strings.EqualFold(alg.Code, name):
			t.Errorf("%q resolves to catalogue row %q only by fuzzy match — it must be the row's code", name, alg.Code)
		case discovery.IsPQCHybridTLSGroup(id) != alg.IsPQC:
			t.Errorf("%q resolves to %q with is_pqc=%v, want %v", name, alg.Code, alg.IsPQC, discovery.IsPQCHybridTLSGroup(id))
		}
	}
}

func tlsGroupFinding(group string) IngestFinding {
	data := map[string]interface{}{
		"version":      "TLS 1.3",
		"cipher_suite": "TLS_AES_128_GCM_SHA256",
	}
	if group != "" {
		data["key_exchange_algorithm"] = group
	}
	return ClusterSensorFinding{Protocol: "TLS", Data: data}.ToIngestFinding()
}

func TestIntegration_TLSKeyExchangeGroup_DecidesPQCClass(t *testing.T) {
	tests := []struct {
		name  string
		group string
		want  func(pqcCounts) bool
		desc  string
	}{
		{"hybrid X25519MLKEM768", "X25519MLKEM768", func(c pqcCounts) bool { return c.PQCReady == 1 }, "PQCReady=1"},
		{"hybrid SecP256r1MLKEM768", "SecP256r1MLKEM768", func(c pqcCounts) bool { return c.PQCReady == 1 }, "PQCReady=1"},
		{"hybrid SecP384r1MLKEM1024", "SecP384r1MLKEM1024", func(c pqcCounts) bool { return c.PQCReady == 1 }, "PQCReady=1"},
		{"classical X25519", "X25519", func(c pqcCounts) bool { return c.NeedsMigration == 1 }, "NeedsMigration=1"},
		{"classical P-256", "DH-ECP-256", func(c pqcCounts) bool { return c.NeedsMigration == 1 }, "NeedsMigration=1"},
		// The pre-fix shape (and what a producer that cannot measure the group
		// still sends): the suite parse assumes ECDHE, so it reads as classical
		// whatever the endpoint really negotiated.
		{"no group recorded", "", func(c pqcCounts) bool { return c.NeedsMigration == 1 }, "NeedsMigration=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, tenant, asset := newSSHIngestFixture(t, "tls-kex.example.test")
			f := tlsGroupFinding(tt.group)
			if tt.group != "" && (f.KeyExchangeAlgorithm == nil || *f.KeyExchangeAlgorithm != tt.group) {
				t.Fatalf("ingest adapter did not promote data.key_exchange_algorithm: %v", f.KeyExchangeAlgorithm)
			}
			ingestSSH(t, svc, tenant, asset, f)

			if tt.group != "" {
				linked := sshLinkedCodes(t, svc, tenant, asset)
				inferred, ok := linked[tt.group]
				if !ok {
					t.Fatalf("group %q not linked to the configuration (linked: %v) — its catalogue code did not resolve", tt.group, linked)
				}
				if inferred {
					t.Errorf("group %q linked as inferred, want measured", tt.group)
				}
			}

			counts, err := classifyTenantImplementationsPQC(svc.db, tenant)
			if err != nil {
				t.Fatalf("classify: %v", err)
			}
			if counts.Total != 1 || !tt.want(counts) {
				t.Errorf("classified as %+v, want Total=1 and %s", counts, tt.desc)
			}
		})
	}
}
