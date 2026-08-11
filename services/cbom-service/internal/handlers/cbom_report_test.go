package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/datasources"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/models"
)

func TestCBOMAssembleComponentsIncludesRelationsAndDeterministicIDs(t *testing.T) {
	t.Parallel()

	handler := &CBOMReportHandler{}
	assets := []map[string]interface{}{
		{
			"id":             "asset-1",
			"tenant_id":      "tenant-1",
			"name":           "api-01",
			"asset_type":     "server",
			"environment":    "production",
			"ip_address":     "10.0.0.1",
			"hostname":       "api-01.internal",
			"risk_level":     "high",
			"certificate_id": "cert-1",
		},
	}
	cryptos := []map[string]interface{}{
		{
			"id":                     "impl-1",
			"tenant_id":              "tenant-1",
			"asset_id":               "asset-1",
			"certificate_id":         "cert-1",
			"protocol":               "TLS",
			"protocol_version":       "1.3",
			"key_exchange_algorithm": "ECDHE",
			"symmetric_encryption":   "AES-256-GCM",
			"keys": []map[string]interface{}{
				{
					"id":                 "key-1",
					"key_type":           "RSA",
					"key_usage":          []interface{}{"sign", "decrypt"},
					"public_fingerprint": "fp-key-1",
					"size_bits":          2048,
					"status":             "active",
				},
			},
			"libraries": []map[string]interface{}{
				{
					"id":                    "lib-1",
					"name":                  "OpenSSL",
					"version":               "3.2.1",
					"vendor":                "OpenSSL",
					"cpe":                   "cpe:2.3:a:openssl:openssl:3.2.1:*:*:*:*:*:*:*",
					"known_vulnerabilities": []interface{}{map[string]interface{}{"id": "CVE-2026-0001"}},
				},
			},
		},
	}
	certs := []map[string]interface{}{
		{
			"id":                   "cert-1",
			"tenant_id":            "tenant-1",
			"common_name":          "api.example.com",
			"subject_dn":           "CN=api.example.com",
			"issuer_dn":            "CN=Example CA",
			"public_key_algorithm": "RSA",
			"public_key_size":      2048,
			"signature_algorithm":  "SHA256withRSA",
			"not_before":           "2026-04-15T00:00:00Z",
			"not_after":            "2027-01-01T00:00:00Z",
		},
	}

	components, tenantID := handler.assembleComponents(
		assets,
		cryptos,
		certs,
		nil, // algorithmLookup — nil triggers heuristic fallback
		compilePredicate(AssetPredicate{Include: &AssetClause{
			Environment: []string{"production"},
			RiskLevel:   []string{"high"},
		}}),
		true,
		true,
		true,
		true,
		true,
	)

	if tenantID != "tenant-1" {
		t.Fatalf("tenantID = %q, want tenant-1", tenantID)
	}

	firstIDs := componentIDs(components)
	secondIDs := componentIDs(mustAssembleSameComponents(t, handler, assets, cryptos, certs))
	if strings.Join(firstIDs, ",") != strings.Join(secondIDs, ",") {
		t.Fatalf("component IDs are not deterministic:\nfirst=%v\nsecond=%v", firstIDs, secondIDs)
	}

	byID := indexComponentsByID(components)
	keyID := keyComponentID("key-1")
	libraryID := libraryComponentID("lib-1")
	protocolID := protocolComponentID("impl-1")
	certificateID := certificateComponentID("cert-1")
	algorithmID := algorithmComponentID("impl-1", "symmetric", "AES-256-GCM")

	for _, id := range []string{keyID, libraryID, protocolID, certificateID, algorithmID} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("expected component %s to be present", id)
		}
	}

	// Key component Name must prefer human-readable key_type over opaque fingerprint.
	keyComp := byID[keyID]
	if keyComp.Name != "RSA" {
		t.Fatalf("key component Name = %q, want %q (human-readable key_type preferred over fingerprint)", keyComp.Name, "RSA")
	}

	// Dependency edges must be bom-refs, not the internal component ids they
	// used to carry — nothing resolved a `key:<uuid>` against a component whose
	// bom-ref is `crypto/related-crypto-material/<uuid>`.
	keyRef := byID[keyID].BOMRef
	libraryRef := byID[libraryID].BOMRef
	for _, id := range []string{protocolID, certificateID, algorithmID} {
		component := byID[id]
		if !containsAll(component.DependsOn, []string{keyRef, libraryRef}) {
			t.Fatalf("component %s missing dependency links: %+v (want %s, %s)",
				id, component.DependsOn, keyRef, libraryRef)
		}
		for _, dep := range component.DependsOn {
			if strings.HasPrefix(dep, "key:") || strings.HasPrefix(dep, "library:") {
				t.Fatalf("component %s depends on internal id %q instead of a bom-ref", id, dep)
			}
		}
	}
}

func TestCBOMAssembleComponentsIncludesStandaloneCertificates(t *testing.T) {
	t.Parallel()

	handler := &CBOMReportHandler{}
	assets := []map[string]interface{}{
		{"id": "asset-1", "tenant_id": "tenant-1", "environment": "production", "risk_level": "high"},
	}
	cryptos := []map[string]interface{}{
		{
			"id":               "impl-1",
			"asset_id":         "asset-1",
			"certificate_id":   "cert-linked",
			"protocol":         "TLS",
			"protocol_version": "1.3",
		},
	}
	certs := []map[string]interface{}{
		{
			"id":          "cert-linked",
			"common_name": "linked.example.com",
			"subject_dn":  "CN=linked.example.com",
		},
		{
			"id":          "cert-standalone",
			"common_name": "ca.example.com",
			"subject_dn":  "CN=CA Root",
			"issuer_dn":   "CN=CA Root",
			"is_ca":       true,
		},
	}

	components, _ := handler.assembleComponents(
		assets,
		cryptos,
		certs,
		nil,                 // algorithmLookup
		compiledPredicate{}, // "All" scope
		false,
		true,
		false,
		false,
		false,
	)

	byID := indexComponentsByID(components)
	linkedID := certificateComponentID("cert-linked")
	standaloneID := certificateComponentID("cert-standalone")

	if _, ok := byID[linkedID]; !ok {
		t.Fatalf("expected linked certificate %s to be present", linkedID)
	}
	if _, ok := byID[standaloneID]; !ok {
		t.Fatalf("expected standalone certificate %s to be present (CA/imported certs must not be dropped)", standaloneID)
	}
	if byID[standaloneID].CertificateDetails == nil {
		t.Fatalf("standalone cert should have CertificateDetails")
	}
	if byID[standaloneID].CertificateDetails.CommonName != "ca.example.com" {
		t.Fatalf("standalone cert CommonName = %q, want ca.example.com", byID[standaloneID].CertificateDetails.CommonName)
	}
}

func TestGenerateCBOMDataFailsClosedWhenInventoryDatasetFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/inventory-service/assets":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"assets":     []map[string]interface{}{},
				"pagination": map[string]interface{}{"has_next": false},
			})
		case "/api/v1/inventory-service/crypto-implementations":
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "backend exploded"})
		case "/api/v1/inventory-service/certificates":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"certificates": []map[string]interface{}{},
				"pagination":   map[string]interface{}{"has_next": false},
			})
		case "/api/v1/inventory-service/algorithms":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"algorithms": []map[string]interface{}{},
				"total":      0,
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	dataSource, err := datasources.NewInventoryDataSource(server.URL)
	if err != nil {
		t.Fatalf("NewInventoryDataSource returned error: %v", err)
	}

	handler := NewCBOMReportHandler(dataSource)
	_, err = handler.GenerateCBOMData(context.Background(), map[string]interface{}{}, "test-token", "00000000-0000-0000-0000-000000000001")
	if err == nil {
		t.Fatal("expected fail-closed error, got nil")
	}
	if !strings.Contains(err.Error(), "crypto configurations") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// NOTE: Phase 5 demolition removed EnhancedHandler. The CSV/text/JSON
// formatter tests (TestFormatCBOMAsTextIncludesKeyAndLibrarySections,
// TestFormatCBOMAsCSVIncludesDependencyAndLibraryRows,
// TestGenerateJSONReportForCBOMReturnsRawCBOMPayload,
// TestDownloadReportRejectsExcelForCBOM) lived on EnhancedHandler and are
// retired alongside it. The CBOM artifact pipeline (Phase 2) emits
// canonical CycloneDX JSON directly; SPDX and PDF projections will be
// re-added behind the cbom.Handler download endpoint in a follow-up.

func mustAssembleSameComponents(
	t *testing.T,
	handler *CBOMReportHandler,
	assets, cryptos, certs []map[string]interface{},
) []models.CBOMComponent {
	t.Helper()

	components, _ := handler.assembleComponents(
		assets,
		cryptos,
		certs,
		nil, // algorithmLookup
		compilePredicate(AssetPredicate{Include: &AssetClause{
			Environment: []string{"production"},
			RiskLevel:   []string{"high"},
		}}),
		true,
		true,
		true,
		true,
		true,
	)
	return components
}

func componentIDs(components []models.CBOMComponent) []string {
	ids := make([]string, 0, len(components))
	for _, component := range components {
		ids = append(ids, component.ID)
	}
	sort.Strings(ids)
	return ids
}

func indexComponentsByID(components []models.CBOMComponent) map[string]models.CBOMComponent {
	index := make(map[string]models.CBOMComponent, len(components))
	for _, component := range components {
		index[component.ID] = component
	}
	return index
}

func TestCBOMAlgorithmEnrichmentUsesCanonicalData(t *testing.T) {
	t.Parallel()

	handler := &CBOMReportHandler{}
	assets := []map[string]interface{}{
		{"id": "asset-1", "tenant_id": "tenant-1", "name": "server-01", "environment": "production"},
	}
	cryptos := []map[string]interface{}{
		{
			"id":                     "impl-1",
			"asset_id":               "asset-1",
			"protocol":               "TLS",
			"protocol_version":       "1.3",
			"key_exchange_algorithm": "ECDHE",
			"symmetric_encryption":   "AES-256-GCM",
			"hash_algorithm":         "SHA384",
		},
	}
	certs := []map[string]interface{}{}

	// Build a canonical algorithm lookup simulating data from the algorithms table
	algorithmLookup := buildAlgorithmLookup([]map[string]interface{}{
		{
			"code":                       "AES-256-GCM",
			"name":                       "AES-256 in GCM mode",
			"category":                   "symmetric",
			"strength":                   "recommended",
			"deprecation_status":         "active",
			"is_pqc":                     false,
			"pqc_standardization_status": "none",
			"risk_score":                 5,
			"migration_guidance":         "",
		},
		{
			"code":                        "ML-KEM-768",
			"name":                        "ML-KEM-768",
			"category":                    "key_exchange",
			"strength":                    "recommended",
			"deprecation_status":          "active",
			"is_pqc":                      true,
			"pqc_standardization_status":  "standardized",
			"nist_quantum_security_level": 3,
			"risk_score":                  5,
			"recommended_alternatives":    []interface{}{},
		},
		{
			"code":                       "ECDHE",
			"name":                       "Elliptic Curve Diffie-Hellman Ephemeral",
			"category":                   "key_exchange",
			"strength":                   "strong",
			"deprecation_status":         "active",
			"is_pqc":                     false,
			"pqc_standardization_status": "none",
			"risk_score":                 20,
			"migration_guidance":         "Consider migrating to ML-KEM for post-quantum resistance.",
			"recommended_alternatives":   []interface{}{"ML-KEM-768", "ML-KEM-1024"},
		},
	})

	components, _ := handler.assembleComponents(
		assets,
		cryptos,
		certs,
		algorithmLookup,
		compiledPredicate{},
		true,
		true,
		true,
		false,
		false,
	)

	byID := indexComponentsByID(components)

	// Find the ECDHE algorithm component
	var ecdheComp *models.CBOMComponent
	for _, comp := range components {
		if comp.AlgorithmDetails != nil && comp.AlgorithmDetails.Code == "ECDHE" {
			c := comp
			ecdheComp = &c
			break
		}
	}
	if ecdheComp == nil {
		t.Fatal("expected ECDHE algorithm component")
	}

	// Verify canonical data was used instead of heuristics
	if ecdheComp.AlgorithmDetails.Strength != "strong" {
		t.Errorf("ECDHE strength = %q, want strong (from canonical table)", ecdheComp.AlgorithmDetails.Strength)
	}
	if ecdheComp.AlgorithmDetails.MigrationGuidance == "" {
		t.Error("ECDHE should have migration guidance from canonical table")
	}
	if len(ecdheComp.AlgorithmDetails.RecommendedAlternatives) != 2 {
		t.Errorf("ECDHE recommended_alternatives = %v, want [ML-KEM-768, ML-KEM-1024]", ecdheComp.AlgorithmDetails.RecommendedAlternatives)
	}

	// Find the AES-256-GCM component — should get "recommended" from canonical table, not "strong" from heuristic
	var aesComp *models.CBOMComponent
	for _, comp := range components {
		if comp.AlgorithmDetails != nil && comp.AlgorithmDetails.Code == "AES-256-GCM" {
			c := comp
			aesComp = &c
			break
		}
	}
	if aesComp == nil {
		t.Fatal("expected AES-256-GCM algorithm component")
	}
	if aesComp.AlgorithmDetails.Strength != "recommended" {
		t.Errorf("AES-256-GCM strength = %q, want recommended (from canonical table, not heuristic 'strong')", aesComp.AlgorithmDetails.Strength)
	}
	if aesComp.AlgorithmDetails.RiskScore != 5 {
		t.Errorf("AES-256-GCM risk_score = %d, want 5 (from canonical table)", aesComp.AlgorithmDetails.RiskScore)
	}

	_ = byID // suppress unused warning
}

func TestCBOMPQCAlgorithmEnrichment(t *testing.T) {
	t.Parallel()

	handler := &CBOMReportHandler{}
	assets := []map[string]interface{}{
		{"id": "asset-1", "tenant_id": "tenant-1", "name": "pqc-server"},
	}
	cryptos := []map[string]interface{}{
		{
			"id":                     "impl-pqc",
			"asset_id":               "asset-1",
			"protocol":               "TLS",
			"protocol_version":       "1.3",
			"key_exchange_algorithm": "ML-KEM-768",
			"signature_algorithm":    "ML-DSA-65",
		},
	}

	algorithmLookup := buildAlgorithmLookup([]map[string]interface{}{
		{
			"code":                        "ML-KEM-768",
			"category":                    "key_exchange",
			"strength":                    "recommended",
			"deprecation_status":          "active",
			"is_pqc":                      true,
			"pqc_standardization_status":  "standardized",
			"nist_quantum_security_level": 3,
			"risk_score":                  5,
		},
		{
			"code":                        "ML-DSA-65",
			"category":                    "signature",
			"strength":                    "recommended",
			"deprecation_status":          "active",
			"is_pqc":                      true,
			"pqc_standardization_status":  "standardized",
			"nist_quantum_security_level": 3,
			"risk_score":                  5,
		},
	})

	components, _ := handler.assembleComponents(
		assets,
		cryptos,
		[]map[string]interface{}{},
		algorithmLookup,
		compiledPredicate{},
		true, false, false, false, false,
	)

	for _, comp := range components {
		if comp.AlgorithmDetails == nil {
			continue
		}
		d := comp.AlgorithmDetails
		if !d.IsPQC {
			t.Errorf("%s: is_pqc = false, want true (from canonical table)", d.Code)
		}
		if d.PQCStandardizationStatus != "standardized" {
			t.Errorf("%s: pqc_standardization_status = %q, want standardized (not 'emerging')", d.Code, d.PQCStandardizationStatus)
		}
		if d.NistQuantumSecurityLevel != 3 {
			t.Errorf("%s: nist_quantum_security_level = %d, want 3", d.Code, d.NistQuantumSecurityLevel)
		}
		if d.Strength != "recommended" {
			t.Errorf("%s: strength = %q, want recommended", d.Code, d.Strength)
		}
	}
}

func containsAll(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, item := range have {
		set[item] = true
	}
	for _, item := range want {
		if !set[item] {
			return false
		}
	}
	return true
}
