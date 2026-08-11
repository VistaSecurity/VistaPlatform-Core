package handlers

// Contract test for the inventory-service crypto-materials HTTP surface — the
// keys / libraries / external-mappings reads web-ui inventory-api.ts consumes:
//
//   GET /keys
//   GET /libraries
//   GET /mappings?local_type=&local_id=
//
// CryptoAssetsHandler.svc was narrowed to the cryptoAssetsStore interface (the
// concrete *services.AssetService still satisfies it), so the handlers run here
// over httptest with an in-memory stub and no database. loadSpec / do /
// assertConforms / aUUID / strPtr are shared from asset_contract_test.go.

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// --- stub ------------------------------------------------------------------

type stubCryptoAssetsStore struct {
	keys        []models.Key
	keysErr     error
	key         *models.Key
	keyErr      error
	keyImpls    []models.KeyImplementation
	keyImplsErr error
	libs        []models.CryptoLibrary
	libsErr     error
	mappings    []models.ExternalAssetMapping
	mapErr      error
}

func (s *stubCryptoAssetsStore) ListKeys(_ uuid.UUID) ([]models.Key, error) {
	return s.keys, s.keysErr
}
func (s *stubCryptoAssetsStore) GetKeyByID(_, _ uuid.UUID) (*models.Key, error) {
	return s.key, s.keyErr
}
func (s *stubCryptoAssetsStore) GetKeyImplementations(_, _ uuid.UUID) ([]models.KeyImplementation, error) {
	return s.keyImpls, s.keyImplsErr
}
func (s *stubCryptoAssetsStore) ListLibraries(_ uuid.UUID) ([]models.CryptoLibrary, error) {
	return s.libs, s.libsErr
}
func (s *stubCryptoAssetsStore) GetExternalMappings(_ uuid.UUID, _ string, _ uuid.UUID) ([]models.ExternalAssetMapping, error) {
	return s.mappings, s.mapErr
}
func (s *stubCryptoAssetsStore) AttachLibrary(_, _, _ uuid.UUID) error { return nil }
func (s *stubCryptoAssetsStore) AttachKey(_, _, _ uuid.UUID) error     { return nil }
func (s *stubCryptoAssetsStore) CreateLibrary(_ uuid.UUID, _ models.CryptoLibrary) (*models.CryptoLibrary, error) {
	return nil, nil
}

// --- harness ---------------------------------------------------------------

func newCryptoAssetsEngine(store cryptoAssetsStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := &CryptoAssetsHandler{svc: store}
	grp.GET("/keys", h.ListKeys)
	grp.GET("/keys/:id", h.GetKeyByID)
	grp.GET("/keys/:id/implementations", h.GetKeyImplementations)
	grp.GET("/libraries", h.ListLibraries)
	grp.GET("/mappings", h.GetMappings)
	return r
}

const cryptoMaterialsBase = "/api/v2/inventory-service"

// --- sample data -----------------------------------------------------------

func sampleKey() models.Key {
	now := time.Now().UTC()
	return models.Key{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		KeyType:           "rsa",
		KeyUsage:          []string{"sign", "verify"},
		PublicFingerprint: strPtr("ab:cd:ef"),
		SizeBits:          intPtr(2048),
		CreatedAt:         &now,
		Metadata:          map[string]interface{}{"source": "scan"},
		MaterialType:      "public-key",
		State:             "active",
		Format:            strPtr("PEM"),
	}
}

func sampleKeyImplementation() models.KeyImplementation {
	return models.KeyImplementation{
		ImplementationID: uuid.New(),
		AssetID:          uuid.New(),
		AssetHostname:    strPtr("web-01.example.com"),
		Protocol:         strPtr("TLS"),
		ProtocolVersion:  strPtr("1.3"),
	}
}

func sampleCryptoLibrary() models.CryptoLibrary {
	now := time.Now().UTC()
	return models.CryptoLibrary{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		Name:                 "OpenSSL",
		Version:              "3.0.13",
		Vendor:               strPtr("OpenSSL Project"),
		BuildMetadata:        map[string]interface{}{"compiler": "gcc"},
		KnownVulnerabilities: []map[string]interface{}{{"cve": "CVE-2024-0001"}},
		CreatedAt:            now,
		UpdatedAt:            now,
		PURL:                 strPtr("pkg:generic/openssl@3.0.13"),
		CertificationLevel:   []string{"fips140-3-l1"},
	}
}

func sampleExternalMapping() models.ExternalAssetMapping {
	now := time.Now().UTC()
	return models.ExternalAssetMapping{
		ID:             uuid.New(),
		TenantID:       uuid.New(),
		LocalType:      "asset",
		LocalID:        uuid.New(),
		ExternalSystem: "servicenow",
		ExternalID:     "CI0001234",
		SyncStatus:     strPtr("synced"),
		LastSyncedAt:   &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// --- tests -----------------------------------------------------------------

func TestContract_ListKeys_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{keys: []models.Key{sampleKey()}})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/keys", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "KeyListResponse", w.Body.Bytes())
}

// Empty result -> keys serializes as null; the schema allows [array,"null"].
func TestContract_ListKeys_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{keys: nil})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/keys", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "KeyListResponse", w.Body.Bytes())
}

func TestContract_GetKey_200(t *testing.T) {
	sv := loadSpec(t)
	k := sampleKey()
	k.DeploymentCount = intPtr(3)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{key: &k})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/keys/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "KeyResponse", w.Body.Bytes())
}

func TestContract_GetKey_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/keys/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Documented quirk: any service error (including no-rows) -> 404.
func TestContract_GetKey_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{keyErr: io.EOF})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/keys/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetKeyImplementations_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{keyImpls: []models.KeyImplementation{sampleKeyImplementation()}})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/keys/"+aUUID+"/implementations", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "KeyImplementationListResponse", w.Body.Bytes())
}

// Empty result -> implementations serializes as null; schema allows [array,"null"].
func TestContract_GetKeyImplementations_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{keyImpls: nil})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/keys/"+aUUID+"/implementations", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "KeyImplementationListResponse", w.Body.Bytes())
}

func TestContract_ListLibraries_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{libs: []models.CryptoLibrary{sampleCryptoLibrary()}})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/libraries", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoLibraryListResponse", w.Body.Bytes())
}

func TestContract_GetMappings_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{mappings: []models.ExternalAssetMapping{sampleExternalMapping()}})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/mappings?local_type=asset&local_id="+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ExternalAssetMappingListResponse", w.Body.Bytes())
}

// Missing required local_type / local_id -> 400.
func TestContract_GetMappings_400_missingParams(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/mappings", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// An unparseable local_id -> 400.
func TestContract_GetMappings_400_badLocalID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoAssetsEngine(&stubCryptoAssetsStore{})
	w := do(eng, http.MethodGet, cryptoMaterialsBase+"/mappings?local_type=asset&local_id=not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
