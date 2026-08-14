package handlers

// Contract test for the Crypto Configurations HTTP surface.
//
// Fourth vertical slice for the spec-first API contract (ADR-0001), after the
// cbom-service/scopes pilot, the infrastructure-assets slice, and the
// certificates slice. It exercises the REAL gin handlers over httptest (with
// in-memory stub stores, no DB) and asserts every response body conforms to
// the crypto-configurations + remediation + asset-certificate-links schemas
// declared in api/openapi/inventory-service.openapi.yaml.
//
// Spec loading + assertConforms come from asset_contract_test.go (same
// package): we reuse loadSpec / specValidator / aUUID / do / strPtr / intPtr.
//
// Scope: the v2 endpoints CryptoImplementationHandler and RemediationHandler
// register —
//   GET    /crypto-configurations
//   GET    /crypto-configurations/{id}
//   GET    /crypto-configurations/{id}/remediation
//   GET    /crypto-configurations/{id}/components
//   GET    /remediation/algorithm/{code}
//   GET    /asset-certificate-links
//
// The v1 (/api/v1/...) aliases of these handlers point at the same code and are
// not separately specced.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
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

// stubRemediationStore satisfies the remediationStore interface used by
// RemediationHandler — both the per-configuration summary and the per-algorithm
// catalog lookup.
type stubRemediationStore struct {
	summary    *services.RemediationSummary
	summaryErr error
	issue      *services.RemediationIssue
	issueErr   error
}

func (s *stubRemediationStore) GetRemediationForCryptoImplementation(_ context.Context, _, _ uuid.UUID) (*services.RemediationSummary, error) {
	return s.summary, s.summaryErr
}
func (s *stubRemediationStore) GetRemediationGuidanceByAlgorithm(_ context.Context, _ string) (*services.RemediationIssue, error) {
	return s.issue, s.issueErr
}

// --- test harness ----------------------------------------------------------

// newCryptoConfigEngine wires the real crypto + remediation handlers under
// /api/v2 with a middleware that injects tenantID / userID as uuid.UUID
// (matches JWTMiddleware).
func newCryptoConfigEngine(crypto *stubCryptoConfigStore, remediation *stubRemediationStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})

	ch := NewCryptoImplementationHandler(crypto)
	rh := NewRemediationHandler(remediation)

	// Route order mirrors cmd/main.go's v2 group.
	grp.GET("/inventory-service/crypto-configurations", ch.GetCryptoImplementations)
	grp.GET("/inventory-service/crypto-configurations/:id", ch.GetCryptoImplementationByID)
	grp.GET("/inventory-service/crypto-configurations/:id/remediation", rh.GetRemediationForCryptoImplementation)
	grp.GET("/inventory-service/remediation/algorithm/:code", rh.GetRemediationByAlgorithm)
	grp.GET("/inventory-service/crypto-configurations/:id/components", ch.GetCryptoImplementationComponents)
	grp.GET("/inventory-service/asset-certificate-links", ch.GetAssetCertificateLinks)
	return r
}

// sampleComponents is a realistic two-component explanation: an OBSERVED weak
// key exchange that sets the score, and an OFFERED-only cipher. Deliberately
// includes one entry with no migration guidance and no alternatives, so the
// spec's optional/empty handling is exercised rather than assumed.
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
			RiskScore:               82,
			MigrationGuidance:       strPtr("Disable group1; prefer curve25519-sha256."),
			RecommendedAlternatives: []string{"curve25519-sha256"},
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
			RiskScore:         70,
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
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		AssetID:           uuid.New(),
		Protocol:          "ssh",
		DiscoveryMethod:   "active",
		RawData:           models.JSONB{},
		ComplianceStatus:  models.JSONB{},
		FirstDiscoveredAt: now,
		LastVerifiedAt:    now,
		CreatedAt:         now,
		UpdatedAt:         now,
		RiskLevel:         "Informational",
	}
}

func sampleRemediation(implID uuid.UUID) *services.RemediationSummary {
	return &services.RemediationSummary{
		CryptoImplementationID: implID,
		RiskScore:              70,
		Issues: []services.RemediationIssue{
			{
				Type:         "protocol",
				Code:         "TLS 1.0",
				Name:         "TLS 1.0",
				Severity:     "high",
				Summary:      "Deprecated TLS version",
				Impact:       "Vulnerable to downgrade attacks.",
				Steps:        []string{"Disable TLS 1.0 at the load balancer.", "Re-test endpoint."},
				Timeline:     "Within 30 days",
				Alternatives: []string{"TLS 1.2", "TLS 1.3"},
				Resources:    []string{"https://wiki.example/tls-upgrade"},
			},
		},
		PriorityActions:         []string{"Disable TLS 1.0"},
		OverallTimeline:         "30 days",
		RecommendedAlternatives: []string{"TLS 1.3"},
		ComplianceImpact:        map[string]string{"pci-dss": "Non-compliant"},
		Resources:               []string{"https://wiki.example/tls-upgrade"},
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
		&stubRemediationStore{},
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
		&stubRemediationStore{},
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
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{getResult: &c}, &stubRemediationStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoImplementationResponse", w.Body.Bytes())
}

func TestContract_GetCryptoConfiguration_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{}, &stubRemediationStore{})
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
		&stubRemediationStore{},
	)
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCryptoConfigurationRemediation_200(t *testing.T) {
	sv := loadSpec(t)
	implID := uuid.MustParse(aUUID)
	eng := newCryptoConfigEngine(
		&stubCryptoConfigStore{},
		&stubRemediationStore{summary: sampleRemediation(implID)},
	)
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID+"/remediation", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RemediationResponse", w.Body.Bytes())
}

// Documented quirk: any service error -> 500 (NOT 404), even when the
// underlying row doesn't exist. Asymmetric with the sibling
// GetCryptoImplementationByID handler in the same package.
func TestContract_GetCryptoConfigurationRemediation_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(
		&stubCryptoConfigStore{},
		&stubRemediationStore{summaryErr: io.EOF},
	)
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/"+aUUID+"/remediation", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCryptoConfigurationRemediation_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{}, &stubRemediationStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-configurations/not-a-uuid/remediation", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCryptoConfigurationComponents_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{components: sampleComponents()}, &stubRemediationStore{})
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
}

// Not-assessed is a 200 with an empty array, NOT a 404 and NOT an error. The
// distinction is load-bearing: score 0 / no components means "we could not
// assess this", which must never be rendered as a clean bill of health.
func TestContract_GetCryptoConfigurationComponents_200_notAssessed(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{components: nil}, &stubRemediationStore{})
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
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{}, &stubRemediationStore{})
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
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{compErr: io.EOF}, &stubRemediationStore{})
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
		&stubRemediationStore{},
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
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{}, &stubRemediationStore{})
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
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{}, &stubRemediationStore{})
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
		&stubRemediationStore{},
	)
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/asset-certificate-links?certificate_ids="+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetCertificateLinksResponse", w.Body.Bytes())
}

// --- per-algorithm remediation (web-ui remediation-api.ts getRemediationByAlgorithm) ---

func sampleRemediationIssue() services.RemediationIssue {
	return services.RemediationIssue{
		Type:         "cipher",
		Code:         "RC4",
		Name:         "RC4 stream cipher",
		Severity:     "high",
		Summary:      "RC4 is cryptographically broken",
		Impact:       "Recoverable keystream biases enable plaintext recovery.",
		Steps:        []string{"Remove RC4 from the cipher list.", "Prefer AES-GCM."},
		Timeline:     "Within 30 days",
		Alternatives: []string{"AES-128-GCM", "ChaCha20-Poly1305"},
		Resources:    []string{"https://wiki.example/rc4"},
	}
}

func TestContract_GetRemediationByAlgorithm_200(t *testing.T) {
	sv := loadSpec(t)
	issue := sampleRemediationIssue()
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{}, &stubRemediationStore{issue: &issue})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/remediation/algorithm/RC4", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RemediationByAlgorithmResponse", w.Body.Bytes())
}

// Any lookup error (including an unknown code) maps to 404 — documented quirk.
func TestContract_GetRemediationByAlgorithm_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoConfigEngine(&stubCryptoConfigStore{}, &stubRemediationStore{issueErr: io.EOF})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/remediation/algorithm/BOGUS", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
