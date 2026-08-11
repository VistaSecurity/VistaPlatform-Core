package handlers

// Contract test for the Certificates HTTP surface.
//
// Third vertical slice for the spec-first API contract (ADR-0001), after the
// cbom-service/scopes pilot and the infrastructure-assets slice. It exercises
// the REAL gin handlers over httptest (with an in-memory stub store, no DB)
// and asserts every response body conforms to the certificate schemas
// declared in api/openapi/inventory-service.openapi.yaml.
//
// Spec loading + assertConforms come from asset_contract_test.go (same
// package): we reuse loadSpec / specValidator / aUUID / do / strPtr / intPtr.
//
// Scope: the certificate endpoints the web-ui certificates-api.ts client
// exercises and that exist server-side today —
//   GET    /certificates                       (list)
// POST /certificates (create, RBAC assets.manage)
// POST /certificates/upload (multipart upload, assets.manage)
//   GET    /certificates/expiring              (dashboard shape)
//   GET    /certificates/{id}                  (single)
// PUT /certificates/{id} (update, RBAC assets.update)
//   GET    /certificates/{id}/chain            (flat issuer chain)
//   POST   /certificates/{id}/rebuild-chain    (single rebuild)
//   POST   /certificates/rebuild-all-chains    (bulk rebuild)
//
// The UI's search / by-issuer / history methods also exist server-side but are
// not yet specced in this slice (tracked separately).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// --- in-memory stub store --------------------------------------------------

// stubCertificateStore satisfies the certificateStore interface used by
// CertificateHandler. Only the methods exercised in this slice carry behavior.
type stubCertificateStore struct {
	list             []models.Certificate
	total            int
	listErr          error
	getResult        *models.Certificate
	getErr           error
	byAssetResult    []models.Certificate
	byAssetErr       error
	expiringResult   []models.Certificate
	expiringErr      error
	chainResult      []models.Certificate
	chainErr         error
	rebuildResult    *services.RebuildChainResult
	rebuildErr       error
	rebuildAllResult *services.RebuildAllChainsResult
	rebuildAllErr    error
	createResult     *models.Certificate
	createErr        error
	updateResult     *models.Certificate
	updateErr        error
	historyResult    []models.CertificateHistory
	historyErr       error
}

func (s *stubCertificateStore) GetCertificates(_ uuid.UUID, _ models.CertificateFilters) ([]models.Certificate, int, error) {
	return s.list, s.total, s.listErr
}
func (s *stubCertificateStore) GetCertificateByID(_, _ uuid.UUID) (*models.Certificate, error) {
	return s.getResult, s.getErr
}
func (s *stubCertificateStore) GetCertificatesByAssetID(_, _ uuid.UUID) ([]models.Certificate, error) {
	return s.byAssetResult, s.byAssetErr
}
func (s *stubCertificateStore) GetExpiringCertificates(_ uuid.UUID, _ int, _ int, _ ...int) ([]models.Certificate, error) {
	return s.expiringResult, s.expiringErr
}
func (s *stubCertificateStore) GetCertificateChain(_, _ uuid.UUID) ([]models.Certificate, error) {
	return s.chainResult, s.chainErr
}
func (s *stubCertificateStore) RebuildCertificateChain(_, _ uuid.UUID) (*services.RebuildChainResult, error) {
	return s.rebuildResult, s.rebuildErr
}
func (s *stubCertificateStore) RebuildAllCertificateChains(_ context.Context, _ uuid.UUID) (*services.RebuildAllChainsResult, error) {
	return s.rebuildAllResult, s.rebuildAllErr
}
func (s *stubCertificateStore) CreateCertificate(_ uuid.UUID, _ models.CertificateData) (*models.Certificate, error) {
	return s.createResult, s.createErr
}
func (s *stubCertificateStore) UpdateCertificate(_, _ uuid.UUID, _ models.CertificateData) (*models.Certificate, error) {
	return s.updateResult, s.updateErr
}
func (s *stubCertificateStore) GetCertificateHistory(_, _ uuid.UUID) ([]models.CertificateHistory, error) {
	return s.historyResult, s.historyErr
}

// --- test harness ----------------------------------------------------------

// newCertEngine wires the real certificate handlers under /api/v2 with a
// middleware that injects tenantID as uuid.UUID (matches JWTMiddleware).
func newCertEngine(store *stubCertificateStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})

	ch := NewCertificateHandler(store)

	// Route order mirrors cmd/main.go's v2 group: collection routes before
	// /:id-prefixed routes so gin's tree doesn't accidentally treat
	// "expiring" / "rebuild-all-chains" as ids.
	grp.GET("/inventory-service/certificates", ch.GetCertificates)
	grp.POST("/inventory-service/certificates", ch.CreateCertificate)
	grp.POST("/inventory-service/certificates/upload", ch.UploadCertificate)
	grp.GET("/inventory-service/certificates/expiring", ch.GetExpiringCertificates)
	grp.POST("/inventory-service/certificates/rebuild-all-chains", ch.RebuildAllCertificateChains)
	grp.GET("/inventory-service/certificates/:id", ch.GetCertificateByID)
	grp.PUT("/inventory-service/certificates/:id", ch.UpdateCertificate)
	grp.GET("/inventory-service/certificates/:id/chain", ch.GetCertificateChain)
	grp.POST("/inventory-service/certificates/:id/rebuild-chain", ch.RebuildCertificateChain)
	grp.GET("/inventory-service/infrastructure-assets/:id/certificates", ch.GetCertificatesByAsset)
	return r
}

// sampleCertificate populates the unconditional fields plus a representative
// subset of the optional ones. The required JSON keys (id, tenant_id,
// subject_dn, issuer_dn, fingerprint_sha256, is_self_signed,
// is_ca_certificate, certificate_state, certificate_format,
// data_completeness, created_at, updated_at) are all set so the response
// satisfies the spec.
func sampleCertificate() models.Certificate {
	now := time.Now().UTC()
	notBefore := now.Add(-30 * 24 * time.Hour)
	notAfter := now.Add(60 * 24 * time.Hour)
	return models.Certificate{
		ID:                 uuid.New(),
		TenantID:           uuid.New(),
		SubjectDN:          "CN=web-01.example.com,O=Acme",
		IssuerDN:           "CN=Acme Root CA,O=Acme",
		FingerprintSHA256:  "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		IsSelfSigned:       false,
		IsCACertificate:    false,
		CertificateState:   "active",
		CertificateFormat:  "x509",
		DataCompleteness:   "complete",
		CreatedAt:          now,
		UpdatedAt:          now,
		CommonName:         strPtr("web-01.example.com"),
		SerialNumber:       strPtr("01"),
		NotBefore:          &notBefore,
		NotAfter:           &notAfter,
		SignatureAlgorithm: strPtr("SHA256-RSA"),
		PublicKeyAlgorithm: strPtr("RSA"),
		PublicKeySize:      intPtr(2048),
	}
}

// --- the contract tests ----------------------------------------------------

func TestContract_ListCertificates_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{
		list:  []models.Certificate{sampleCertificate()},
		total: 1,
	})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates?page=1&page_size=20", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CertificateListResponse", w.Body.Bytes())
}

func TestContract_ListCertificates_500_serviceError(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{listErr: io.EOF})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCertificate_200(t *testing.T) {
	sv := loadSpec(t)
	c := sampleCertificate()
	eng := newCertEngine(&stubCertificateStore{getResult: &c})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CertificateResponse", w.Body.Bytes())
}

func TestContract_GetCertificate_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Documented quirk: any service error (including no-rows) -> 404.
func TestContract_GetCertificate_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{getErr: io.EOF})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ExpiringCertificates_200(t *testing.T) {
	sv := loadSpec(t)
	cert := sampleCertificate()
	cert.RelatedAssets = []models.Asset{{
		ID:                uuid.New(),
		TenantID:          cert.TenantID,
		AssetType:         "server",
		Tags:              map[string]interface{}{},
		Metadata:          map[string]interface{}{},
		AssetOwnership:    "owned",
		AssetStatus:       "monitoring",
		FirstDiscoveredAt: time.Now().UTC(),
		LastSeenAt:        time.Now().UTC(),
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}}
	eng := newCertEngine(&stubCertificateStore{
		expiringResult: []models.Certificate{cert},
	})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates/expiring?days=30&limit=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ExpiringCertificateListResponse", w.Body.Bytes())
}

// Expiring with no related assets exercises the asset_id="" fallback.
func TestContract_ExpiringCertificates_200_noAssets(t *testing.T) {
	sv := loadSpec(t)
	cert := sampleCertificate()
	eng := newCertEngine(&stubCertificateStore{
		expiringResult: []models.Certificate{cert},
	})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates/expiring", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ExpiringCertificateListResponse", w.Body.Bytes())
}

func TestContract_GetChain_200(t *testing.T) {
	sv := loadSpec(t)
	leaf := sampleCertificate()
	root := sampleCertificate()
	root.IsSelfSigned = true
	root.SubjectDN = "CN=Acme Root CA,O=Acme"
	root.IssuerDN = root.SubjectDN
	eng := newCertEngine(&stubCertificateStore{
		chainResult: []models.Certificate{leaf, root},
	})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates/"+aUUID+"/chain", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CertificateChainResponse", w.Body.Bytes())
}

// Empty chain still conforms — chain is an array (possibly empty), is_complete is false.
func TestContract_GetChain_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{chainResult: []models.Certificate{}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates/"+aUUID+"/chain", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CertificateChainResponse", w.Body.Bytes())
}

func TestContract_RebuildChain_200(t *testing.T) {
	sv := loadSpec(t)
	res := &services.RebuildChainResult{
		CertificateID: uuid.New(),
		LinksCreated:  2,
		ChainLength:   3,
		ChainComplete: true,
	}
	eng := newCertEngine(&stubCertificateStore{rebuildResult: res})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/certificates/"+aUUID+"/rebuild-chain", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RebuildChainResponse", w.Body.Bytes())
}

func TestContract_RebuildAllChains_200(t *testing.T) {
	sv := loadSpec(t)
	res := &services.RebuildAllChainsResult{
		TotalCertificates: 10,
		ChainsRebuilt:     7,
		LinksCreated:      12,
		CompletedChains:   5,
	}
	eng := newCertEngine(&stubCertificateStore{rebuildAllResult: res})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/certificates/rebuild-all-chains", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RebuildAllChainsResponse", w.Body.Bytes())
}

// --- GET /infrastructure-assets/{id}/certificates () --------------
//
// These cover the route the web-ui getCertificatesByAsset() client hits. Not
// yet captured in the OpenAPI spec, so they assert the { "certificates": [...] }
// envelope directly rather than via assertConforms.

func TestAssetCertificates_200_envelope(t *testing.T) {
	eng := newCertEngine(&stubCertificateStore{
		byAssetResult: []models.Certificate{sampleCertificate()},
	})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/certificates", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Certificates []json.RawMessage `json:"certificates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, w.Body.String())
	}
	if len(body.Certificates) != 1 {
		t.Fatalf("certificates len = %d, want 1; body=%s", len(body.Certificates), w.Body.String())
	}
}

// No linked certs returns a present, empty (non-null) array so the client's
// response.data.certificates read stays an array.
func TestAssetCertificates_200_empty(t *testing.T) {
	eng := newCertEngine(&stubCertificateStore{byAssetResult: []models.Certificate{}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/certificates", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := body["certificates"]
	if !ok || string(raw) != "[]" {
		t.Fatalf("certificates = %s, want []; body=%s", string(raw), w.Body.String())
	}
}

func TestAssetCertificates_400_badID(t *testing.T) {
	eng := newCertEngine(&stubCertificateStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/not-a-uuid/certificates", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAssetCertificates_500_serviceError(t *testing.T) {
	eng := newCertEngine(&stubCertificateStore{byAssetErr: io.EOF})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/certificates", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

// Same with a populated errors array — exercises the array branch of the
// top-level errors union (vs. null).
func TestContract_RebuildAllChains_200_withErrors(t *testing.T) {
	sv := loadSpec(t)
	res := &services.RebuildAllChainsResult{
		TotalCertificates: 4,
		ChainsRebuilt:     1,
		LinksCreated:      1,
		CompletedChains:   0,
		Errors:            []string{"failed to rebuild cert abc: not found"},
	}
	eng := newCertEngine(&stubCertificateStore{rebuildAllResult: res})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/certificates/rebuild-all-chains", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RebuildAllChainsResponse", w.Body.Bytes())
}

// --- write surface: create / upload / update -------------------------

// selfSignedCertPEM builds a throwaway self-signed certificate PEM so the
// multipart upload handler has something real to parse.
func selfSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "upload-test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// doMultipartUpload posts a multipart/form-data body with the given field +
// file bytes (or, when fieldName is empty, an empty multipart body).
func doMultipartUpload(eng *gin.Engine, path, fieldName, filename string, content []byte) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if fieldName != "" {
		fw, _ := mw.CreateFormFile(fieldName, filename)
		_, _ = fw.Write(content)
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	return w
}

// POST /certificates with a valid body -> 201 + CertificateResponse.
func TestContract_CreateCertificate_201(t *testing.T) {
	sv := loadSpec(t)
	c := sampleCertificate()
	eng := newCertEngine(&stubCertificateStore{createResult: &c})
	body := strings.NewReader(`{"fingerprint_sha256":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899","subject_dn":"CN=web-01"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/certificates", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CertificateResponse", w.Body.Bytes())
}

// POST /certificates without a fingerprint or serial+issuer -> 400.
func TestContract_CreateCertificate_400_missingIdentity(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{})
	body := strings.NewReader(`{"subject_dn":"CN=web-01"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/certificates", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// POST /certificates with a malformed body -> 400.
func TestContract_CreateCertificate_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/certificates", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// POST /certificates/upload with a valid PEM -> 201 + CertificateResponse.
func TestContract_UploadCertificate_201(t *testing.T) {
	sv := loadSpec(t)
	c := sampleCertificate()
	eng := newCertEngine(&stubCertificateStore{createResult: &c})
	w := doMultipartUpload(eng, "/api/v2/inventory-service/certificates/upload", "certificate_file", "cert.pem", selfSignedCertPEM(t))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CertificateResponse", w.Body.Bytes())
}

// POST /certificates/upload with no file part -> 400.
func TestContract_UploadCertificate_400_missingFile(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{})
	w := doMultipartUpload(eng, "/api/v2/inventory-service/certificates/upload", "", "", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// POST /certificates/upload with non-PEM content -> 400.
func TestContract_UploadCertificate_400_badPEM(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{})
	w := doMultipartUpload(eng, "/api/v2/inventory-service/certificates/upload", "certificate_file", "cert.pem", []byte("not a pem file"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// PUT /certificates/{id} with a valid body -> 200 + CertificateResponse.
func TestContract_UpdateCertificate_200(t *testing.T) {
	sv := loadSpec(t)
	c := sampleCertificate()
	eng := newCertEngine(&stubCertificateStore{updateResult: &c})
	body := strings.NewReader(`{"common_name":"renamed.example.com"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/certificates/"+aUUID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CertificateResponse", w.Body.Bytes())
}

// PUT /certificates/{id} for an unknown id -> 404.
func TestContract_UpdateCertificate_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{updateErr: sql.ErrNoRows})
	body := strings.NewReader(`{"common_name":"x"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/certificates/"+aUUID, body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// PUT /certificates/{id} with a non-UUID id -> 400.
func TestContract_UpdateCertificate_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCertEngine(&stubCertificateStore{})
	body := strings.NewReader(`{"common_name":"x"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/certificates/not-a-uuid", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
