package services

// End-to-end proof, against a real Postgres with the real schema and seed, that
// a TLS server which supports hybrid post-quantum key exchange but negotiated a
// classical group carries that evidence through ingest onto its configuration,
// and that the "Why this score" read path (GET
// /crypto-configurations/{id}/components) turns it into the hint on the
// key-exchange component — without moving the score, the band or the PQC
// category ( W1.9).
//
// Findings arrive in the two shapes ingest receives: the Platform Sensor's
// ("data" through the real ingest adapter) and discovery-processor's (flat
// raw_data, the converter's output for sensor, cloud and interrogation rows).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// hybridProbeFinding is a TLS 1.3 active-probe finding that negotiated group,
// with the support answers in support (nil values are left out: never asked).
func hybridProbeFinding(group string, support map[string]interface{}) IngestFinding {
	data := map[string]interface{}{
		"version":                "TLS 1.3",
		"cipher_suite":           "TLS_AES_128_GCM_SHA256",
		"key_exchange_algorithm": group,
	}
	for k, v := range support {
		if v != nil {
			data[k] = v
		}
	}
	return ClusterSensorFinding{Protocol: "TLS", Data: data}.ToIngestFinding()
}

// discoveryProcessorFinding is the same observation as discovery-processor's
// converter emits it: the negotiated group promoted to KeyExchangeAlgorithm and
// every metadata key flattened into raw_data.
func discoveryProcessorFinding(group string, support map[string]interface{}) IngestFinding {
	version, suite := "TLS 1.3", "TLS_AES_128_GCM_SHA256"
	raw := map[string]interface{}{
		"version": version, "cipher_suite": suite, "discovery_method": "active_enrichment",
		"key_exchange_algorithm": group, "key_exchange_group_raw": 29, "source": "sensor_discovery",
	}
	for k, v := range support {
		if v != nil {
			raw[k] = v
		}
	}
	g := group
	return IngestFinding{Protocol: "TLS", ProtocolVersion: &version, CipherSuite: &suite, KeyExchangeAlgorithm: &g, RawData: raw}
}

// onlyConfiguration returns the asset's one live configuration id.
func onlyConfiguration(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := svc.db.QueryRow(`
		SELECT id FROM crypto_implementations
		 WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL`, tenant, asset).Scan(&id); err != nil {
		t.Fatalf("read back the configuration (want exactly one): %v", err)
	}
	return id
}

// kexHint returns the key-exchange component and its hint (nil = no hint).
func kexHint(t *testing.T, components []models.CryptoComponentAssessment) (*models.CryptoComponentAssessment, *models.HybridKexAvailability) {
	t.Helper()
	var kex *models.CryptoComponentAssessment
	for i := range components {
		c := &components[i]
		if c.AlgorithmType != "key_exchange" && c.HybridKexAvailable != nil {
			t.Errorf("hint on a %s component (%s) — it belongs only on the key exchange", c.AlgorithmType, c.Code)
		}
		if c.AlgorithmType == "key_exchange" {
			if kex != nil {
				t.Fatalf("more than one key_exchange component: %s and %s", kex.Code, c.Code)
			}
			kex = c
		}
	}
	if kex == nil {
		t.Fatalf("no key_exchange component resolved (components: %+v)", components)
	}
	return kex, kex.HybridKexAvailable
}

type hybridIngestResult struct {
	raw        map[string]interface{}
	kex        *models.CryptoComponentAssessment
	hint       *models.HybridKexAvailability
	riskScore  *int
	pqc        pqcCounts
	components []models.CryptoComponentAssessment
}

func ingestAndExplain(t *testing.T, findings ...IngestFinding) hybridIngestResult {
	t.Helper()
	svc, tenant, asset := newSSHIngestFixture(t, "hybrid-kex.example.test")
	for _, f := range findings {
		ingestSSH(t, svc, tenant, asset, f)
	}
	impl := onlyConfiguration(t, svc, tenant, asset)

	var r hybridIngestResult
	var raw models.JSONB
	if err := svc.db.QueryRow(`SELECT raw_data, risk_score FROM crypto_implementations WHERE id = $1`, impl).Scan(&raw, &r.riskScore); err != nil {
		t.Fatalf("read raw_data: %v", err)
	}
	r.raw = raw

	components, err := NewCryptoImplementationService(svc.db).GetCryptoImplementationComponents(tenant, impl)
	if err != nil {
		t.Fatalf("GetCryptoImplementationComponents: %v", err)
	}
	r.components = components
	r.kex, r.hint = kexHint(t, components)

	if r.pqc, err = classifyTenantImplementationsPQC(svc.db, tenant); err != nil {
		t.Fatalf("classify: %v", err)
	}
	return r
}

func TestIntegration_HybridKexHint_ThroughIngest(t *testing.T) {
	supportsHybrid := map[string]interface{}{
		"tls_supports_classical_kex": true, "tls_supports_pqc_hybrid_kex": true, "tls_pqc_hybrid_kex_group": "X25519MLKEM768",
	}
	refusedHybrid := map[string]interface{}{"tls_supports_classical_kex": true, "tls_supports_pqc_hybrid_kex": false}
	neverAsked := map[string]interface{}{"tls_supports_classical_kex": true}

	// The baseline the hint must not move: the same classical configuration
	// with no hybrid evidence at all.
	baseline := ingestAndExplain(t, hybridProbeFinding("X25519", neverAsked))

	tests := []struct {
		name       string
		finding    IngestFinding
		wantKex    string
		wantHint   bool
		wantGroups []string
	}{
		{"platform sensor: supports hybrid, negotiated X25519", hybridProbeFinding("X25519", supportsHybrid), "X25519", true, []string{"X25519MLKEM768"}},
		{"discovery-processor shape: supports hybrid, negotiated X25519", discoveryProcessorFinding("X25519", supportsHybrid), "X25519", true, []string{"X25519MLKEM768"}},
		{"hybrid group not recorded", hybridProbeFinding("DH-ECP-256", map[string]interface{}{"tls_supports_pqc_hybrid_kex": true}), "DH-ECP-256", true, []string{}},
		{"server refused the hybrid offer", hybridProbeFinding("X25519", refusedHybrid), "X25519", false, nil},
		{"hybrid support never asked", hybridProbeFinding("X25519", neverAsked), "X25519", false, nil},
		{"a string \"true\" is not an answer", hybridProbeFinding("X25519", map[string]interface{}{"tls_supports_pqc_hybrid_kex": "true"}), "X25519", false, nil},
		{"already negotiating hybrid", hybridProbeFinding("X25519MLKEM768", map[string]interface{}{"tls_supports_pqc_hybrid_kex": true, "tls_pqc_hybrid_kex_group": "X25519MLKEM768"}), "X25519MLKEM768", false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ingestAndExplain(t, tt.finding)
			if r.kex.Code != tt.wantKex {
				t.Fatalf("key exchange = %q, want %q", r.kex.Code, tt.wantKex)
			}
			// The evidence rides on the configuration exactly as sent.
			if want, sent := tt.finding.RawData["tls_supports_pqc_hybrid_kex"]; sent && r.raw["tls_supports_pqc_hybrid_kex"] != want {
				t.Errorf("raw_data tls_supports_pqc_hybrid_kex = %v, want %v", r.raw["tls_supports_pqc_hybrid_kex"], want)
			}
			if _, sent := tt.finding.RawData["tls_supports_pqc_hybrid_kex"]; !sent {
				if v, present := r.raw["tls_supports_pqc_hybrid_kex"]; present {
					t.Errorf("raw_data tls_supports_pqc_hybrid_kex = %v, want absent", v)
				}
			}

			switch {
			case tt.wantHint && r.hint == nil:
				t.Fatalf("no hint on %s; want one naming %v", r.kex.Code, tt.wantGroups)
			case !tt.wantHint && r.hint != nil:
				t.Fatalf("hint on %s = %+v, want none", r.kex.Code, r.hint)
			case tt.wantHint:
				if len(r.hint.Groups) != len(tt.wantGroups) || (len(tt.wantGroups) > 0 && r.hint.Groups[0] != tt.wantGroups[0]) {
					t.Errorf("hint groups = %v, want %v", r.hint.Groups, tt.wantGroups)
				}
			}

			if tt.wantKex != "X25519" {
				return
			}
			// Guidance only: same score, same component assessment, same PQC
			// category as the configuration with no hybrid evidence.
			if (r.riskScore == nil) != (baseline.riskScore == nil) || (r.riskScore != nil && *r.riskScore != *baseline.riskScore) {
				t.Errorf("risk score = %v, want %v (unchanged by the hint)", derefInt(r.riskScore), derefInt(baseline.riskScore))
			}
			if derefInt(r.kex.RiskScore) != derefInt(baseline.kex.RiskScore) || r.kex.SetsScore != baseline.kex.SetsScore {
				t.Errorf("key exchange assessment moved: risk %v sets_score %v, want %v / %v",
					derefInt(r.kex.RiskScore), r.kex.SetsScore, derefInt(baseline.kex.RiskScore), baseline.kex.SetsScore)
			}
			if r.pqc != baseline.pqc || r.pqc.NeedsMigration != 1 {
				t.Errorf("PQC classification = %+v, want %+v with NeedsMigration=1", r.pqc, baseline.pqc)
			}
		})
	}
}

// A later probe that finds the server now refuses hybrid replaces the evidence:
// the hint follows the newest measurement rather than lingering from an old one.
func TestIntegration_HybridKexHint_NewerRefusalRemovesIt(t *testing.T) {
	r := ingestAndExplain(t,
		hybridProbeFinding("X25519", map[string]interface{}{"tls_supports_pqc_hybrid_kex": true, "tls_pqc_hybrid_kex_group": "X25519MLKEM768"}),
		hybridProbeFinding("X25519", map[string]interface{}{"tls_supports_pqc_hybrid_kex": false}),
	)
	if r.hint != nil {
		t.Errorf("hint = %+v after a newer probe saw the hybrid offer refused, want none", r.hint)
	}
}
