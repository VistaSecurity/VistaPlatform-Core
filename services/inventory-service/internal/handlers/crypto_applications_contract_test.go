package handlers

// Contract test for GET /crypto-applications — the at-rest encryption posture
// read the Data Protection lens consumes. Runs the real handler over httptest
// with an in-memory stub (cryptoApplicationsStore), no database.
//
// loadSpec / do / assertConforms are shared from asset_contract_test.go.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type stubCryptoApplicationsStore struct {
	items []models.CryptoApplication
	total int
	err   error
	// gotFilter records what the handler passed down, so the query-param
	// contract (defaults + tri-state) is asserted rather than assumed.
	gotFilter services.CryptoApplicationFilter
}

func (s *stubCryptoApplicationsStore) ListCryptoApplications(_ uuid.UUID, f services.CryptoApplicationFilter) ([]models.CryptoApplication, int, error) {
	s.gotFilter = f
	return s.items, s.total, s.err
}

func newCryptoApplicationsEngine(store cryptoApplicationsStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := &CryptoApplicationsHandler{svc: store}
	grp.GET("/crypto-applications", h.ListCryptoApplications)
	return r
}

const cryptoApplicationsPath = "/api/v2/inventory-service/crypto-applications"

func sampleCryptoApplication() models.CryptoApplication {
	now := time.Now().UTC()
	km := "provider"
	alg := "AES-256"
	provider := "aws"
	region := "us-east-1"
	return models.CryptoApplication{
		ID:                   uuid.New().String(),
		AssetID:              nil,
		ResourceType:         "cloud_storage",
		ResourceName:         "socialupkeep-marketing",
		ResourceIdentifier:   "arn:aws:s3:::socialupkeep-marketing",
		EncryptionContext:    "at_rest",
		Encrypted:            true,
		EncryptionDetermined: true,
		EncryptionType:       "sse-s3",
		Algorithm:            &alg,
		KeyManager:           &km,
		CloudProvider:        &provider,
		CloudRegion:          &region,
		RiskScore:            40,
		RiskLevel:            models.GetRiskLevel(40),
		LastVerifiedAt:       &now,
	}
}

func TestContract_ListCryptoApplications_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoApplicationsEngine(&stubCryptoApplicationsStore{
		items: []models.CryptoApplication{sampleCryptoApplication()},
		total: 4,
	})
	w := do(eng, http.MethodGet, cryptoApplicationsPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoApplicationsResponse", w.Body.Bytes())
}

// An empty result must serialize as [] and not null: the schema types items as
// a plain array, and a null would make the lens' .map() throw.
func TestContract_ListCryptoApplications_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoApplicationsEngine(&stubCryptoApplicationsStore{items: nil, total: 0})
	w := do(eng, http.MethodGet, cryptoApplicationsPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoApplicationsResponse", w.Body.Bytes())

	var body struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Items == nil {
		t.Error("items serialized as null; the lens expects an empty array")
	}
}

func TestContract_ListCryptoApplications_DefaultsToAtRest(t *testing.T) {
	store := &stubCryptoApplicationsStore{}
	eng := newCryptoApplicationsEngine(store)
	if w := do(eng, http.MethodGet, cryptoApplicationsPath, nil); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if store.gotFilter.EncryptionContext != "at_rest" {
		t.Errorf("encryption_context default = %q, want at_rest", store.gotFilter.EncryptionContext)
	}
	if store.gotFilter.Determined != nil {
		t.Error("determined must be UNSET when the param is absent — a false default would hide every measured resource")
	}
}

// determined is a tri-state. `false` must reach the service as an explicit
// false (the "could not determine" bucket), not be flattened into "no filter".
func TestContract_ListCryptoApplications_DeterminedTriState(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  *bool
	}{
		{"?determined=false", boolPtrCA(false)},
		{"?determined=true", boolPtrCA(true)},
	} {
		store := &stubCryptoApplicationsStore{}
		eng := newCryptoApplicationsEngine(store)
		if w := do(eng, http.MethodGet, cryptoApplicationsPath+tc.query, nil); w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", tc.query, w.Code)
		}
		got := store.gotFilter.Determined
		if got == nil || *got != *tc.want {
			t.Errorf("%s: Determined = %v, want %v", tc.query, got, *tc.want)
		}
	}
}

func TestContract_ListCryptoApplications_400_on_bad_params(t *testing.T) {
	sv := loadSpec(t)
	for _, q := range []string{"?determined=maybe", "?limit=0", "?limit=abc", "?offset=-1"} {
		eng := newCryptoApplicationsEngine(&stubCryptoApplicationsStore{})
		w := do(eng, http.MethodGet, cryptoApplicationsPath+q, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", q, w.Code, w.Body.String())
			continue
		}
		sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	}
}

func TestContract_ListCryptoApplications_401_without_tenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &CryptoApplicationsHandler{svc: &stubCryptoApplicationsStore{}}
	r.GET("/crypto-applications", h.ListCryptoApplications)
	w := do(r, http.MethodGet, "/crypto-applications", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func boolPtrCA(b bool) *bool { return &b }
