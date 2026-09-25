package handlers

// Contract test for the Crypto Configurations HTTP surface.
//
// Fourth vertical slice for the spec-first API contract (ADR-0001), after the
// cbom-service/scopes pilot, the infrastructure-assets slice, and the
// certificates slice. It exercises the REAL gin handlers over httptest (with
// in-memory stub stores, no DB) and asserts every response body conforms to
// the crypto-configurations + asset-certificate-links schemas declared in
// api/openapi/inventory-service.openapi.yaml.
//
// Spec loading + assertConforms come from asset_contract_test.go (same
// package): we reuse loadSpec / specValidator / aUUID / do / strPtr / intPtr.
//
// Scope: the v2 endpoints CryptoImplementationHandler registers —
//   GET    /crypto-configurations
//   GET    /crypto-configurations/{id}
//   GET    /crypto-configurations/{id}/components
//   GET    /asset-certificate-links
//
// The v1 (/api/v1/...) aliases of these handlers point at the same code and are
// not separately specced.

import (
	"encoding/json"
	"github.com/lib/pq"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// --- in-memory stub stores -------------------------------------------------

// stubCryptoConfigStore satisfies the cryptoConfigStore interface used by
// CryptoImplementationHandler.
type stubCryptoConfigStore struct {
	list       []models.CryptoImplementation
	total      int
	listErr    error
	getResult  *models.CryptoImplementation
	getErr     error
	links      []models.AssetCertificateLink
	linksErr   error
	components []models.CryptoComponentAssessment
	compErr    error
}

func (s *stubCryptoConfigStore) GetCryptoImplementations(_ uuid.UUID, _ models.CryptoImplementationFilters) ([]models.CryptoImplementation, int, error) {
	return s.list, s.total, s.listErr
}
func (s *stubCryptoConfigStore) GetCryptoImplementationByID(_, _ uuid.UUID) (*models.CryptoImplementation, error) {
	return s.getResult, s.getErr
}
func (s *stubCryptoConfigStore) GetAssetCertificateLinks(_ uuid.UUID, _ []uuid.UUID, _ []uuid.UUID) ([]models.AssetCertificateLink, error) {
	return s.links, s.linksErr
}
func (s *stubCryptoConfigStore) GetCryptoImplementationComponents(_, _ uuid.UUID) ([]models.CryptoComponentAssessment, error) {
	return s.components, s.compErr
}

// --- test harness ----------------------------------------------------------

// newCryptoConfigEngine wires the real crypto-configuration handler under
// /api/v2 with a middleware that injects tenantID / userID as uuid.UUID
// (matches JWTMiddleware).
func newCryptoConfigEngine(crypto *stubCryptoConfigStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})

	ch := NewCryptoImplementationHandler(crypto)

	// Route order mirrors cmd/main.go's v2 group.
	grp.GET("/inventory-service/crypto-configurations", ch.GetCryptoImplementations)
	grp.GET("/inventory-service/crypto-configurations/:id", ch.GetCryptoImplementationByID)
	grp.GET("/inventory-service/crypto-configurations/:id/components", ch.GetCryptoImplementationComponents)
	grp.GET("/inventory-service/asset-certificate-links", ch.GetAssetCertificateLinks)
	return r
}

// sampleComponents is a realistic two-component explanation: an OBSERVED weak
// key exchange that sets the score, and an OFFERED-only cipher. Deliberately
// includes one entry with no migration guidance, no alternatives and no
// remediation guidance, so the spec's optional/empty handling is exercised
// rather than assumed.
func sampleComponents() []models.CryptoComponentAssessment {
	return models.AnnotateComponentAssessments([]models.CryptoComponentAssessment{
		{
			AlgorithmType:           "key_exchange",
			IsInferred:              false,
			AlgorithmID:             uuid.New(),
			Code:                    "diffie-hellman-group1-sha1",
			Name:                    "Diffie-Hellman Group 1 (SHA-1)",
			Category:                "key_exchange",
			Strength:                "weak",
			DeprecationStatus:       "obsolete",
			RiskScore:               intPtr(82),
			MigrationGuidance:       strPtr("Disable group1; prefer curve25519-sha256."),
			RecommendedAlternatives: []string{"curve25519-sha256"},
			RemediationGuidance: models.ParseComponentRemediationGuidance([]byte(`{
				"summary": "group1 is a 1024-bit MODP group.",
				"impact": "Precomputation makes passive decryption feasible.",
				"steps": ["1. Remove diffie-hellman-group1-sha1 from KexAlgorithms"],
				"timeline": "Within 30 days",
				"cve_references": ["CVE-2015-4000"],
				"resources": ["https://weakdh.org/"]
			}`)),
		},
		{
			AlgorithmType:     "symmetric",
			IsInferred:        true,
			AlgorithmID:       uuid.New(),
			Code:              "3des-cbc",
			Name:              "Triple DES (CBC)",
			Category:          "symmetric",
			Strength:          "weak",
			DeprecationStatus: "deprecated",
			RiskScore:         intPtr(70),
		},
	})
}

// sampleCryptoConfig populates the unconditional fields (matching the
// non-omitempty json tags on models.CryptoImplementation) plus a representative
// subset of the optional ones, so the response body exercises both the
// always-present nullable fields and the `omitempty` device/asset extras.
func sampleCryptoConfig() models.CryptoImplementation {
	now := time.Now().UTC()
	score := 42
	conf := 0.95
	keySize := 2048
	certID := uuid.New()
	sensorID := uuid.New()
	return models.CryptoImplementation{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		AssetID:              uuid.New(),
		Protocol:             "tls",
		ProtocolVersion:      strPtr("TLS 1.2"),
		CipherSuite:          strPtr("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
		KeyExchangeAlgorithm: strPtr("ECDHE"),
		SignatureAlgorithm:   strPtr("RSA"),
		SymmetricEncryption:  strPtr("AES-128-GCM"),
		HashAlgorithm:        strPtr("SHA256"),
		KeySize:              &keySize,
		CertificateID:        &certID,
		DiscoveryMethod:      "passive",
		DiscoveryMethods:     pq.StringArray{"passive", "active"},
		ConfidenceScore:      &conf,
		SourceSensorID:       &sensorID,
		RawData:              models.JSONB{"sni": "example.com"},
		RiskScore:            &score,
		ComplianceStatus:     models.JSONB{"pci-dss": "pass"},
		FirstDiscoveredAt:    now,
		LastVerifiedAt:       now,
		CreatedAt:            now,
		UpdatedAt:            now,
		RiskLevel:            "Medium",
	}
}

// nullableCryptoConfig leaves the nullable pointer fields nil so the response
// serializes them as JSON null — proving the spec's [type,"null"] unions hold
// for every field declared required-but-nullable.
func nullableCryptoConfig() models.CryptoImplementation {
	now := time.Now().UTC()
	return models.CryptoImplementation{
		ID:              uuid.New(),
		TenantID:        uuid.New(),
		AssetID:         uuid.New(),
		Protocol:        "ssh",
		DiscoveryMethod: "active",
		// Never null on the wire: the readers normalise a nil array to empty
		// (crypto_implementation_relations.go), so the spec declares a plain
		// array and this fixture holds the emptiest value it can take.
		DiscoveryMethods:  pq.StringArray{},
		RawData:           models.JSONB{},
		ComplianceStatus:  models.JSONB{},
		FirstDiscoveredAt: now,
		LastVerifiedAt:    now,
		CreatedAt:         now,
		UpdatedAt:         now,
		RiskLevel:         "Informational",
	}
}

func sampleLink() models.AssetCertificateLink {
	score := 50
	return models.AssetCertificateLink{
		AssetID:                uuid.New(),
		CertificateID:          uuid.New(),
		CryptoImplementationID: uuid.New(),
		Protocol:               "tls",
		RiskScore:              &score,
	}
}

// --- the contract tests ----------------------------------------------------

func TestContract_ListCryptoConfigurations_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(
		&stubCryptoConfigStore{
			list:  []models.CryptoImplementation{sampleCryptoConfig(), nullableCryptoConfig()},
			total: 2,
		},
	)
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations?page=1&page_size=20", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoImplementationListResponse", w.Body.Bytes())
}

func TestContract_ListCryptoConfigurations_500_serviceError(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(
		&stubCryptoConfigStore{listErr: io.EOF},
	)
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCryptoConfiguration_200(t *testing.T) {
	sv := loadSpec(t)
	c := sampleCryptoConfig()
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{getResult: &c})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoImplementationResponse", w.Body.Bytes())
}

func TestContract_GetCryptoConfiguration_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Documented quirk: ANY service error (including no-rows) -> 404.
func TestContract_GetCryptoConfiguration_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(
		&stubCryptoConfigStore{getErr: io.EOF},
	)
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCryptoConfigurationComponents_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{components: sampleComponents()})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID+"/components", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoComponentAssessmentListResponse", w.Body.Bytes())

	var body struct {
		Components []struct {
			Code       string `json:"code"`
			RiskLevel  string `json:"risk_level"`
			SetsScore  bool   `json:"sets_score"`
			IsInferred bool   `json:"is_inferred"`
			Alts       []string
		} `json:"components"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Components) != 2 {
		t.Fatalf("components = %d, want 2", len(body.Components))
	}
	// Worst first, and exactly one score-setter — the marker the drawer uses to
	// name "the algorithm that caused this".
	if !body.Components[0].SetsScore || body.Components[1].SetsScore {
		t.Fatalf("sets_score should be true on the FIRST (worst) component only, got %+v", body.Components)
	}
	// Banded server-side from the canonical ladder: 82 -> High, 70 -> High.
	if body.Components[0].RiskLevel != "High" {
		t.Fatalf("risk_level for 82 = %q, want High", body.Components[0].RiskLevel)
	}
	// The observed/offered split must survive serialization — it is the whole point.
	if body.Components[0].IsInferred || !body.Components[1].IsInferred {
		t.Fatalf("is_inferred lost in transit: %+v", body.Components)
	}

	// Catalogue remediation guidance rides on the component that records it
	// and is omitted — not null, not {} — on the one that does not.
	var raw struct {
		Components []map[string]json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var g models.ComponentRemediationGuidance
	if err := json.Unmarshal(raw.Components[0]["remediation_guidance"], &g); err != nil || len(g.Steps) != 1 || g.Timeline != "Within 30 days" {
		t.Errorf("remediation_guidance on the weak key exchange = %s (err %v)", raw.Components[0]["remediation_guidance"], err)
	}
	if got, present := raw.Components[1]["remediation_guidance"]; present {
		t.Errorf("component with no catalogue guidance carries remediation_guidance = %s, want the key omitted", got)
	}
}

// The "supports hybrid, negotiated classical" hint ( W1.9) rides on the
// key-exchange component and must conform to the spec — an additionalProperties:
// false schema rejects an undeclared field, which would fail every consumer
// validating against it. Components without it omit the key entirely.
func TestContract_GetCryptoConfigurationComponents_200_hybridKexHint(t *testing.T) {
	sv := loadSpec(t)
	components := []models.CryptoComponentAssessment{
		{
			AlgorithmType: "key_exchange", AlgorithmID: uuid.New(), Code: "X25519", Name: "X25519",
			Category: "key_exchange", Strength: "strong", DeprecationStatus: "current", RiskScore: intPtr(15),
			RecommendedAlternatives: []string{"X25519MLKEM768"},
			HybridKexAvailable:      &models.HybridKexAvailability{Groups: []string{"X25519MLKEM768"}},
		},
		{
			AlgorithmType: "symmetric", AlgorithmID: uuid.New(), Code: "AES128-GCM", Name: "AES-128-GCM",
			Category: "symmetric", Strength: "strong", DeprecationStatus: "current", RiskScore: intPtr(10),
		},
	}
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{components: models.AnnotateComponentAssessments(components)})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID+"/components", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoComponentAssessmentListResponse", w.Body.Bytes())

	var body struct {
		Components []map[string]json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := string(body.Components[0]["hybrid_kex_available"]); got != `{"groups":["X25519MLKEM768"]}` {
		t.Errorf("key exchange hybrid_kex_available = %s, want {\"groups\":[\"X25519MLKEM768\"]}", got)
	}
	if got, present := body.Components[1]["hybrid_kex_available"]; present {
		t.Errorf("symmetric component carries hybrid_kex_available = %s, want the key omitted", got)
	}
}

// Not-assessed is a 200 with an empty array, NOT a 404 and NOT an error. The
// distinction is load-bearing: score 0 / no components means "we could not
// assess this", which must never be rendered as a clean bill of health.
func TestContract_GetCryptoConfigurationComponents_200_notAssessed(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{components: nil})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID+"/components", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoComponentAssessmentListResponse", w.Body.Bytes())
	// A nil slice must serialize as [] rather than null: `null` invites a
	// consumer to treat it as "unknown" and silently skip the not-assessed
	// branch, which is exactly the honesty this endpoint is protecting.
	if got := w.Body.String(); !strings.Contains(got, `"components":[]`) {
		t.Fatalf("empty components must serialize as [], got %s", got)
	}
}

func TestContract_GetCryptoConfigurationComponents_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/not-a-uuid/components", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A failed lookup must be a 500, distinguishable from "not assessed". Reporting
// a DB error as an empty (= unassessed) list would launder an outage into a
// verdict about the customer's crypto.
func TestContract_GetCryptoConfigurationComponents_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{compErr: io.EOF})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID+"/components", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListAssetCertificateLinks_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(
		&stubCryptoConfigStore{links: []models.AssetCertificateLink{sampleLink()}},
	)
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/asset-certificate-links?asset_ids="+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetCertificateLinksResponse", w.Body.Bytes())
}

// Documented quirk: passing neither asset_ids nor certificate_ids returns 400.
func TestContract_ListAssetCertificateLinks_400_noScope(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/asset-certificate-links", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Documented quirk: unparseable id in the list returns 400 (parseUUIDList
// surfaces the parse error).
func TestContract_ListAssetCertificateLinks_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/asset-certificate-links?asset_ids=not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Empty result still conforms — links is typed as [array,"null"] in the spec
// so a tenant with no edges (nil slice -> JSON null) is valid. Exercises the
// null-on-empty quirk first surfaced by the scopes slice.
func TestContract_ListAssetCertificateLinks_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(
		&stubCryptoConfigStore{links: nil},
	)
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/asset-certificate-links?certificate_ids="+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetCertificateLinksResponse", w.Body.Bytes())
}
