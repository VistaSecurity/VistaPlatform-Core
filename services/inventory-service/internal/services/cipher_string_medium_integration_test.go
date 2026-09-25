package services

// Second review of.
//
// B1: a partial cipher string only stops a Low/Informational result from being
// claimed as complete. It must not erase a Medium (or worse) risk a KNOWN
// component supports — a static-ECDH key exchange, an RSA-2048 one.
//
// B2: EXP / EXPORT / LOW add whole classes of weak suites. Bare or inside a
// string, they must produce the weak finding and the links, as the plain
// substring rule would have for EXPORT.
//
// Also here: the drawer's remediation guidance reads the may-enable list, and the
// crypto.configuration_added event carries the score that was STORED.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

func TestIntegration_Ingest_PartialCipherStringKeepsKnownMediumRisk(t *testing.T) {
	f := newScoringFixture(t)
	mediumMin, _ := riskbands.RiskBandMin("Medium")

	for i, tc := range []struct {
		kex, cipher string
		wantCode    string // the known component whose catalogue score must stand
	}{
		{"ECDH", "DEFAULT", "ECDH"},
		{"RSA-2048", "DEFAULT:!RC4", "RSA-2048"},
	} {
		host := []string{"partial-ecdh.example.com", "partial-rsa2048.example.com"}[i]
		ip := []string{"198.51.100.70", "198.51.100.71"}[i]
		finding := cipherStringFinding(host, ip, tc.cipher)
		finding.KeyExchangeAlgorithm = strPtr(tc.kex)
		impl, risk, codes := f.ingestOne(t, finding)
		want := f.catalogueRisk(t, tc.wantCode, "key_exchange")
		if want < mediumMin {
			t.Fatalf("fixture: catalogue %s scores %d, below Medium — the case would prove nothing", tc.wantCode, want)
		}
		if risk == nil || *risk != want {
			t.Errorf("%s + %q: risk = %v, want the known component's %d (links %v)", tc.kex, tc.cipher, risk, want, codes)
		}
		if a, _ := f.cipherAssessment(t, impl); a != "partial" {
			t.Errorf("%s + %q: cipher_assessment = %q, want partial", tc.kex, tc.cipher, a)
		}
	}

	// Below Medium the partial set still cannot claim Low.
	impl, risk, _ := f.ingestOne(t, cipherStringFinding("partial-low.example.com", "198.51.100.72", "DEFAULT"))
	if risk != nil {
		t.Errorf("DEFAULT over a Low-only known set: risk = %d, want NULL (partially assessed)", *risk)
	}
	if a, _ := f.cipherAssessment(t, impl); a != "partial" {
		t.Errorf("DEFAULT: cipher_assessment = %q, want partial", a)
	}
}

func TestIntegration_Ingest_WeakClassKeywordsAreFlagged(t *testing.T) {
	f := newScoringFixture(t)
	highMin, _ := riskbands.RiskBandMin("High")

	for i, tc := range []struct {
		cipher string
		links  []string // symmetric codes that must be linked
	}{
		{"HIGH:EXP", []string{"RC4", "DES"}},
		{"ECDHE-RSA-AES256-GCM-SHA384:EXP", []string{"RC4", "DES"}},
		{"EXP", []string{"RC4", "DES"}},
		{"HIGH:LOW", []string{"DES"}},
		{"LOW", []string{"DES"}},
	} {
		host := []string{"wk-high-exp.example.com", "wk-suite-exp.example.com", "wk-exp.example.com", "wk-high-low.example.com", "wk-low.example.com"}[i]
		ip := []string{"198.51.100.80", "198.51.100.81", "198.51.100.82", "198.51.100.83", "198.51.100.84"}[i]
		_, risk, codes := f.ingestOne(t, cipherStringFinding(host, ip, tc.cipher))
		for _, code := range tc.links {
			if codes[code] != "symmetric" {
				t.Errorf("%q: %s not linked: %v", tc.cipher, code, codes)
			}
		}
		if risk == nil || *risk < highMin {
			t.Errorf("%q: risk = %v, want a weak-cipher score (High or worse); links %v", tc.cipher, risk, codes)
		}
	}

	// Excluded, the class exposes nothing — EXP and EXPORT are one keyword.
	for i, cipher := range []string{"HIGH:!EXPORT:EXP", "EXP:!EXP", "HIGH:LOW:!LOW"} {
		host := []string{"wk-noexp.example.com", "wk-noexp2.example.com", "wk-nolow.example.com"}[i]
		ip := []string{"198.51.100.85", "198.51.100.86", "198.51.100.87"}[i]
		_, risk, codes := f.ingestOne(t, cipherStringFinding(host, ip, cipher))
		for _, code := range []string{"RC4", "DES", "MD5"} {
			if _, ok := codes[code]; ok {
				t.Errorf("%q: excluded class linked %s: %v", cipher, code, codes)
			}
		}
		if risk != nil {
			t.Errorf("%q: risk = %d, want NULL (partially assessed, nothing weak named)", cipher, *risk)
		}
	}
}

// The drawer's remediation guidance reads the may-enable list: it comes from
// the catalogue rows ingest linked, so an RC4 keyword addition surfaces RC4's
// guidance and its exclusion surfaces none. (This replaced a separate
// remediation endpoint that re-matched the stored string on its own.)
func TestIntegration_ComponentGuidance_ReadsWhatAStringMayEnable(t *testing.T) {
	f := newScoringFixture(t)
	svc := NewCryptoImplementationService(f.db)
	for i, tc := range []struct {
		cipher string
		rc4    bool
	}{
		{"HIGH:MEDIUM:RC4", true},
		{"HIGH:!RC4", false},
	} {
		host := []string{"rem-rc4.example.com", "rem-norc4.example.com"}[i]
		ip := []string{"198.51.100.90", "198.51.100.91"}[i]
		impl, _, _ := f.ingestOne(t, cipherStringFinding(host, ip, tc.cipher))
		components, err := svc.GetCryptoImplementationComponents(f.tenant, impl)
		if err != nil {
			t.Fatalf("%q: components: %v", tc.cipher, err)
		}
		idx := slices.IndexFunc(components, func(c models.CryptoComponentAssessment) bool { return c.Code == "RC4" })
		if got := idx >= 0; got != tc.rc4 {
			t.Fatalf("%q: RC4 component present = %v, want %v (%+v)", tc.cipher, got, tc.rc4, components)
		}
		if tc.rc4 && (components[idx].RemediationGuidance == nil || len(components[idx].RemediationGuidance.Steps) == 0) {
			t.Errorf("%q: RC4 is linked but carries no catalogue remediation steps: %+v", tc.cipher, components[idx].RemediationGuidance)
		}
	}
}

// crypto.configuration_added carries the score that was stored: null for a
// configuration left unassessed, never the working number that was not written.
func TestIntegration_CryptoAddedEvent_CarriesTheStoredScore(t *testing.T) {
	f := newScoringFixture(t)
	// Materialize the asset first, then drive the materialization step the
	// event is built in, with a publisher present so the payload is collected.
	f.ingestOne(t, cipherStringFinding("event.example.com", "198.51.100.95", "ECDHE-RSA-AES256-GCM-SHA384"))
	var assetID uuid.UUID
	if err := f.db.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND hostname = 'event.example.com'`, f.tenant).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	// A publisher only so the payloads are collected: nothing below calls
	// IngestFindings again, and the collected slices are never published.
	f.svc.eventPublisher = &EventPublisherService{}
	svc := f.svc

	for i, tc := range []struct {
		cipher string
		scored bool
	}{
		{"ALL:!aNULL", false},
		{"HIGH:MEDIUM:RC4", true},
	} {
		finding := cipherStringFinding("event.example.com", "198.51.100.95", tc.cipher)
		port := 8443 + i
		finding.Port = &port
		var risk []*events.AssetRiskChangedPayload
		var added []*events.CryptoConfigurationAddedPayload
		var certs []*events.CertificateExpiringPayload
		if err := svc.processDiscoveryCryptoData(f.tenant, assetID, finding, &risk, &added, &certs); err != nil {
			t.Fatalf("%q: %v", tc.cipher, err)
		}
		if len(added) != 1 {
			t.Fatalf("%q: %d configuration_added payloads, want 1", tc.cipher, len(added))
		}
		var stored *int
		if err := f.db.QueryRow(`SELECT risk_score FROM crypto_implementations WHERE id = $1`, added[0].CryptoImplementationID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if (stored == nil) != (added[0].RiskScore == nil) || (stored != nil && *stored != *added[0].RiskScore) {
			t.Errorf("%q: event risk %v, stored %v", tc.cipher, added[0].RiskScore, stored)
		}
		if (stored != nil) != tc.scored {
			t.Errorf("%q: stored %v, want scored=%v", tc.cipher, stored, tc.scored)
		}
	}
}
