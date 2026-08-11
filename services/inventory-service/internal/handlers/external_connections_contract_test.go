package handlers

// Contract test for the inventory-service external-connections HTTP surface —
// the Inventory → Connections lens (web-ui inventory-api.ts):
//
//   GET    /external-connections
//   GET    /external-connections/summary
//   GET    /external-connections/{id}
//   GET    /external-connections/{id}/history
//   DELETE /external-connections/{id}
//
// ExternalConnectionsHandler.service was narrowed to the
// externalConnectionsStore interface (the concrete service still satisfies it),
// so the handlers run here over httptest with an in-memory stub and no
// database. loadSpec / do / assertConforms / aUUID are shared from
// asset_contract_test.go.

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// --- stub ------------------------------------------------------------------

type stubExternalConnectionsStore struct {
	list       []models.ExternalConnection
	listTotal  int
	listErr    error
	byID       *models.ExternalConnection
	byIDErr    error
	history    []models.ExternalConnectionHistory
	histTotal  int
	histErr    error
	summary    *models.ExternalConnectionsSummary
	summaryErr error
	deleteErr  error
}

func (s *stubExternalConnectionsStore) Upsert(_ uuid.UUID, _ models.ExternalConnectionUpsert) (*models.ExternalConnection, error) {
	return s.byID, s.byIDErr
}
func (s *stubExternalConnectionsStore) List(_ uuid.UUID, _ models.ExternalConnectionFilters) ([]models.ExternalConnection, int, error) {
	return s.list, s.listTotal, s.listErr
}
func (s *stubExternalConnectionsStore) GetByID(_, _ uuid.UUID) (*models.ExternalConnection, error) {
	return s.byID, s.byIDErr
}
func (s *stubExternalConnectionsStore) GetHistory(_, _ uuid.UUID, _, _ int) ([]models.ExternalConnectionHistory, int, error) {
	return s.history, s.histTotal, s.histErr
}
func (s *stubExternalConnectionsStore) GetSummary(_ uuid.UUID) (*models.ExternalConnectionsSummary, error) {
	return s.summary, s.summaryErr
}
func (s *stubExternalConnectionsStore) Delete(_, _ uuid.UUID) error { return s.deleteErr }

// --- harness ---------------------------------------------------------------

func newExtConnEngine(store externalConnectionsStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := &ExternalConnectionsHandler{service: store}
	grp.GET("/inventory-service/external-connections", h.ListExternalConnections)
	grp.GET("/inventory-service/external-connections/summary", h.GetExternalConnectionsSummary)
	grp.GET("/inventory-service/external-connections/:id", h.GetExternalConnection)
	grp.GET("/inventory-service/external-connections/:id/history", h.GetExternalConnectionHistory)
	grp.DELETE("/inventory-service/external-connections/:id", h.DeleteExternalConnection)
	return r
}

const extConnBase = "/api/v2/inventory-service/external-connections"

// --- sample data -----------------------------------------------------------

func strp(s string) *string { return &s }

// sampleExternalConnection populates the optional cert/service pointer fields so
// the response exercises the spec's optional keys on the populated side.
func sampleExternalConnection() models.ExternalConnection {
	now := time.Now().UTC()
	return models.ExternalConnection{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		SourceIP:             "10.0.0.5",
		SourceHostname:       strp("app-01.internal"),
		DestIP:               "140.82.112.3",
		DestHostname:         strp("api.github.com"),
		DestPort:             443,
		Protocol:             "tls",
		ProtocolVersion:      strp("1.3"),
		CipherSuite:          strp("TLS_AES_128_GCM_SHA256"),
		SupportedTLSVersions: []string{"1.2", "1.3"},
		CryptoStrength:       "good",
		IsPQCResistant:       false,
		CertSubject:          strp("CN=api.github.com"),
		CertIssuer:           strp("CN=DigiCert"),
		CertSAN:              []string{"api.github.com"},
		CertNotAfter:         &now,
		CertIsExpired:        false,
		ServiceName:          strp("github-api"),
		FirstSeenAt:          now,
		LastSeenAt:           now,
		ObservationCount:     42,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

// minimalExternalConnection leaves every omitempty pointer/slice unset, so the
// response serializes only the required keys — proving they hold.
func minimalExternalConnection() models.ExternalConnection {
	now := time.Now().UTC()
	return models.ExternalConnection{
		ID:               uuid.New(),
		TenantID:         uuid.New(),
		SourceIP:         "10.0.0.9",
		DestIP:           "1.1.1.1",
		DestPort:         853,
		Protocol:         "dot",
		CryptoStrength:   "unknown",
		CertIsExpired:    false,
		FirstSeenAt:      now,
		LastSeenAt:       now,
		ObservationCount: 1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func sampleExtConnHistory() models.ExternalConnectionHistory {
	now := time.Now().UTC()
	return models.ExternalConnectionHistory{
		ID:                   uuid.New(),
		ExternalConnectionID: uuid.New(),
		TenantID:             uuid.New(),
		ChangeType:           "cert_rotated",
		PreviousCertNotAfter: &now,
		NewCertNotAfter:      &now,
		CreatedAt:            now,
	}
}

func sampleExtConnSummary() *models.ExternalConnectionsSummary {
	return &models.ExternalConnectionsSummary{
		Total: 12, WeakCrypto: 3, PQCResistant: 1, ExpiredCerts: 2, LegacyTLS: 4, SourceHosts: 5,
	}
}

// --- tests -----------------------------------------------------------------

func TestContract_ListExternalConnections_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newExtConnEngine(&stubExternalConnectionsStore{
		list:      []models.ExternalConnection{sampleExternalConnection(), minimalExternalConnection()},
		listTotal: 2,
	})
	w := do(eng, http.MethodGet, extConnBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ExternalConnectionListResponse", w.Body.Bytes())
}

func TestContract_GetExternalConnectionsSummary_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newExtConnEngine(&stubExternalConnectionsStore{summary: sampleExtConnSummary()})
	w := do(eng, http.MethodGet, extConnBase+"/summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ExternalConnectionsSummary", w.Body.Bytes())
}

func TestContract_GetExternalConnection_200(t *testing.T) {
	sv := loadSpec(t)
	conn := sampleExternalConnection()
	eng := newExtConnEngine(&stubExternalConnectionsStore{byID: &conn})
	w := do(eng, http.MethodGet, extConnBase+"/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ExternalConnection", w.Body.Bytes())
}

func TestContract_GetExternalConnection_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newExtConnEngine(&stubExternalConnectionsStore{})
	w := do(eng, http.MethodGet, extConnBase+"/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A nil connection (no row for the tenant) maps to 404.
func TestContract_GetExternalConnection_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newExtConnEngine(&stubExternalConnectionsStore{byID: nil})
	w := do(eng, http.MethodGet, extConnBase+"/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetExternalConnectionHistory_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newExtConnEngine(&stubExternalConnectionsStore{
		history:   []models.ExternalConnectionHistory{sampleExtConnHistory()},
		histTotal: 1,
	})
	w := do(eng, http.MethodGet, extConnBase+"/"+aUUID+"/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ExternalConnectionHistoryListResponse", w.Body.Bytes())
}

func TestContract_DeleteExternalConnection_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newExtConnEngine(&stubExternalConnectionsStore{})
	w := do(eng, http.MethodDelete, extConnBase+"/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_DeleteExternalConnection_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newExtConnEngine(&stubExternalConnectionsStore{deleteErr: errors.New("external connection not found")})
	w := do(eng, http.MethodDelete, extConnBase+"/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
