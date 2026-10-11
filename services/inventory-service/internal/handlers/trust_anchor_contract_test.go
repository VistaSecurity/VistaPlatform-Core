package handlers

// Contract test for the certificate-trust HTTP surface (slice 1):
//   GET    /trust-anchors                (list)
//   POST   /trust-anchors                (create, RBAC certificates.trust in main.go)
//   GET    /trust-anchors/public-roots   (bundle metadata)
//   PUT    /trust-anchors/{id}           (update)
//   DELETE /trust-anchors/{id}           (remove)
// plus the four trust fields on the Certificate schema.
//
// It drives the REAL handlers over httptest with an in-memory store and
// validates every response body against api/openapi/inventory-service.openapi.yaml.

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
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
)

type stubTrustAnchorStore struct {
	list         []certtrust.Anchor
	listErr      error
	created      *certtrust.Anchor
	createErr    error
	gotCreate    certtrust.CreateRequest
	updated      *certtrust.Anchor
	updateErr    error
	gotUpdate    certtrust.UpdateRequest
	deleteErr    error
	gotFromChain certtrust.FromChainRequest
}

func (s *stubTrustAnchorStore) ListAnchors(context.Context, uuid.UUID) ([]certtrust.Anchor, error) {
	return s.list, s.listErr
}
func (s *stubTrustAnchorStore) CreateAnchor(_ context.Context, _ uuid.UUID, req certtrust.CreateRequest) (*certtrust.Anchor, error) {
	s.gotCreate = req
	return s.created, s.createErr
}
func (s *stubTrustAnchorStore) UpdateAnchor(_ context.Context, _, _ uuid.UUID, req certtrust.UpdateRequest) (*certtrust.Anchor, error) {
	s.gotUpdate = req
	return s.updated, s.updateErr
}
func (s *stubTrustAnchorStore) DeleteAnchor(context.Context, uuid.UUID, uuid.UUID) error {
	return s.deleteErr
}
func (s *stubTrustAnchorStore) CreateAnchorFromChain(_ context.Context, _ uuid.UUID, req certtrust.FromChainRequest) (*certtrust.Anchor, error) {
	s.gotFromChain = req
	return s.created, s.createErr
}

var trustTestUser = uuid.MustParse("22222222-2222-2222-2222-222222222222")

func newTrustEngine(store *stubTrustAnchorStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", trustTestUser)
		c.Next()
	})
	h := NewTrustAnchorHandler(store)
	// Route order mirrors cmd/main.go.
	grp.GET("/inventory-service/trust-anchors", h.ListTrustAnchors)
	grp.GET("/inventory-service/trust-anchors/public-roots", h.GetPublicRoots)
	grp.POST("/inventory-service/trust-anchors", h.CreateTrustAnchor)
	grp.POST("/inventory-service/trust-anchors/from-chain", h.CreateTrustAnchorFromChain)
	grp.PUT("/inventory-service/trust-anchors/:id", h.UpdateTrustAnchor)
	grp.DELETE("/inventory-service/trust-anchors/:id", h.DeleteTrustAnchor)
	return r
}

func sampleAnchor(withOptional bool) certtrust.Anchor {
	now := time.Now().UTC()
	a := certtrust.Anchor{
		ID:            uuid.New(),
		TenantID:      uuid.New(),
		CertificateID: uuid.New(),
		Decision:      certtrust.DecisionTrusted,
		DecidedAt:     now,
		CreatedAt:     now,
		UpdatedAt:     now,
		Certificate: certtrust.AnchorCertificate{
			SubjectDN:         "CN=Example Root CA,O=Example",
			IssuerDN:          "CN=Example Root CA,O=Example",
			FingerprintSHA256: strings.Repeat("ab", 32),
			IsSelfSigned:      true,
			IsCACertificate:   true,
		},
		AffectedCertificates: 3,
		AffectedAssets:       2,
	}
	a.Certificate.ID = a.CertificateID
	if withOptional {
		nb, na := now.Add(-time.Hour), now.Add(24*time.Hour)
		a.Note = strPtr("internal PKI")
		a.DecidedBy = &trustTestUser
		a.Certificate.CommonName = strPtr("Example Root CA")
		a.Certificate.NotBefore = &nb
		a.Certificate.NotAfter = &na
	}
	return a
}

func TestContract_ListTrustAnchors_200(t *testing.T) {
	sv := loadSpec(t)
	for _, list := range [][]certtrust.Anchor{nil, {sampleAnchor(true), sampleAnchor(false)}} {
		w := do(newTrustEngine(&stubTrustAnchorStore{list: list}), http.MethodGet, "/api/v2/inventory-service/trust-anchors", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
		}
		sv.assertConforms(t, "TrustAnchorList", w.Body.Bytes())
		var body struct {
			Anchors []json.RawMessage `json:"anchors"`
			Total   int               `json:"total"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body.Total != len(list) || len(body.Anchors) != len(list) {
			t.Fatalf("total=%d anchors=%d, want %d", body.Total, len(body.Anchors), len(list))
		}
	}
}

func TestContract_ListTrustAnchors_500(t *testing.T) {
	sv := loadSpec(t)
	w := do(newTrustEngine(&stubTrustAnchorStore{listErr: io.EOF}), http.MethodGet, "/api/v2/inventory-service/trust-anchors", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", w.Code)
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_PublicRoots_200(t *testing.T) {
	sv := loadSpec(t)
	w := do(newTrustEngine(&stubTrustAnchorStore{}), http.MethodGet, "/api/v2/inventory-service/trust-anchors/public-roots", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PublicRootsInfo", w.Body.Bytes())
	var info PublicRootsInfo
	_ = json.Unmarshal(w.Body.Bytes(), &info)
	if info.Version == "" || info.RootCount <= 100 {
		t.Fatalf("public roots = %+v, want the embedded bundle's version and > 100 roots", info)
	}
}

func TestContract_CreateTrustAnchor_201(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAnchor(true)
	store := &stubTrustAnchorStore{created: &a}
	certID := uuid.New()
	w := do(newTrustEngine(store), http.MethodPost, "/api/v2/inventory-service/trust-anchors",
		strings.NewReader(`{"certificate_id":"`+certID.String()+`","decision":"trusted","note":"internal PKI"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TrustAnchor", w.Body.Bytes())
	if store.gotCreate.CertificateID == nil || *store.gotCreate.CertificateID != certID ||
		store.gotCreate.Decision != "trusted" || store.gotCreate.Note != "internal PKI" || store.gotCreate.DecidedBy != trustTestUser {
		t.Fatalf("store got %+v", store.gotCreate)
	}

	// The PEM form reaches the store as PEM.
	store2 := &stubTrustAnchorStore{created: &a}
	w = do(newTrustEngine(store2), http.MethodPost, "/api/v2/inventory-service/trust-anchors",
		strings.NewReader(`{"certificate_pem":"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n","decision":"distrusted"}`))
	if w.Code != http.StatusCreated || !strings.Contains(store2.gotCreate.CertificatePEM, "BEGIN CERTIFICATE") || store2.gotCreate.Decision != "distrusted" {
		t.Fatalf("pem create: status %d, store got %+v", w.Code, store2.gotCreate)
	}
}

func TestContract_CreateTrustAnchor_errors(t *testing.T) {
	sv := loadSpec(t)
	cases := []struct {
		name  string
		store *stubTrustAnchorStore
		body  string
		want  int
	}{
		{"store rejects", &stubTrustAnchorStore{createErr: &certtrust.ErrInvalid{Msg: "only a CA certificate can be trusted or distrusted"}}, `{"certificate_id":"` + aUUID + `","decision":"trusted"}`, http.StatusBadRequest},
		{"unknown field", &stubTrustAnchorStore{}, `{"certificate_id":"` + aUUID + `","decision":"trusted","extra":1}`, http.StatusBadRequest},
		{"bad id", &stubTrustAnchorStore{}, `{"certificate_id":"nope","decision":"trusted"}`, http.StatusBadRequest},
		{"not json", &stubTrustAnchorStore{}, `{`, http.StatusBadRequest},
		{"duplicate", &stubTrustAnchorStore{createErr: &certtrust.ErrConflict{ExistingID: uuid.New()}}, `{"certificate_id":"` + aUUID + `","decision":"trusted"}`, http.StatusConflict},
		{"server error", &stubTrustAnchorStore{createErr: io.EOF}, `{"certificate_id":"` + aUUID + `","decision":"trusted"}`, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := do(newTrustEngine(tc.store), http.MethodPost, "/api/v2/inventory-service/trust-anchors", strings.NewReader(tc.body))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		})
	}
}

func TestContract_UpdateTrustAnchor(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAnchor(false)
	a.Decision = certtrust.DecisionDistrusted
	store := &stubTrustAnchorStore{updated: &a}
	w := do(newTrustEngine(store), http.MethodPut, "/api/v2/inventory-service/trust-anchors/"+aUUID, strings.NewReader(`{"decision":"distrusted"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TrustAnchor", w.Body.Bytes())
	if store.gotUpdate.Decision == nil || *store.gotUpdate.Decision != "distrusted" || store.gotUpdate.Note != nil {
		t.Fatalf("store got %+v", store.gotUpdate)
	}

	for _, tc := range []struct {
		name  string
		store *stubTrustAnchorStore
		path  string
		body  string
		want  int
	}{
		{"not found", &stubTrustAnchorStore{updateErr: certtrust.ErrAnchorNotFound}, aUUID, `{"note":"x"}`, http.StatusNotFound},
		{"bad id", &stubTrustAnchorStore{}, "nope", `{"note":"x"}`, http.StatusBadRequest},
		{"invalid", &stubTrustAnchorStore{updateErr: &certtrust.ErrInvalid{Msg: "nothing to change"}}, aUUID, `{}`, http.StatusBadRequest},
		{"server error", &stubTrustAnchorStore{updateErr: io.EOF}, aUUID, `{"note":"x"}`, http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(newTrustEngine(tc.store), http.MethodPut, "/api/v2/inventory-service/trust-anchors/"+tc.path, strings.NewReader(tc.body))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		})
	}
}

func TestContract_DeleteTrustAnchor(t *testing.T) {
	sv := loadSpec(t)
	w := do(newTrustEngine(&stubTrustAnchorStore{}), http.MethodDelete, "/api/v2/inventory-service/trust-anchors/"+aUUID, nil)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("status = %d body=%q, want 204 and no body", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		name string
		err  error
		path string
		want int
	}{
		{"not found", certtrust.ErrAnchorNotFound, aUUID, http.StatusNotFound},
		{"bad id", nil, "nope", http.StatusBadRequest},
		{"server error", io.EOF, aUUID, http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(newTrustEngine(&stubTrustAnchorStore{deleteErr: tc.err}), http.MethodDelete, "/api/v2/inventory-service/trust-anchors/"+tc.path, nil)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		})
	}
}

// The four trust fields on a certificate validate against the Certificate
// schema's TrustStatus / ChainSource enums.
func TestContract_Certificate_TrustFields(t *testing.T) {
	sv := loadSpec(t)
	c := sampleCertificate()
	now := time.Now().UTC()
	anchor := uuid.New()
	c.TrustStatus = strPtr(certtrust.StatusPrivateTrusted)
	c.TrustAnchorCertificateID = &anchor
	c.TrustEvaluatedAt = &now
	c.ChainSource = strPtr(certtrust.ChainSourceUpload)
	eng := newCertEngine(&stubCertificateStore{getResult: &c, chainResult: []models.Certificate{c}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/certificates/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CertificateResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"trust_status":"private_trusted"`) {
		t.Fatalf("trust_status missing from body: %s", w.Body.String())
	}
	for _, status := range []string{certtrust.StatusPublic, certtrust.StatusPrivateTrusted, certtrust.StatusSelfSigned,
		certtrust.StatusUntrusted, certtrust.StatusDistrusted, certtrust.StatusIncomplete} {
		c.TrustStatus = strPtr(status)
		w := do(newCertEngine(&stubCertificateStore{getResult: &c}), http.MethodGet, "/api/v2/inventory-service/certificates/"+aUUID, nil)
		sv.assertConforms(t, "CertificateResponse", w.Body.Bytes())
	}
	// Unevaluated: the fields are absent, not null.
	u := sampleCertificate()
	w = do(newCertEngine(&stubCertificateStore{getResult: &u}), http.MethodGet, "/api/v2/inventory-service/certificates/"+aUUID, nil)
	if strings.Contains(w.Body.String(), "trust_status") {
		t.Fatalf("unevaluated certificate carries trust_status: %s", w.Body.String())
	}
}

// --- slice 4: POST /trust-anchors/from-chain ---------------------------------

func TestContract_CreateTrustAnchorFromChain_201(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAnchor(true)
	store := &stubTrustAnchorStore{created: &a}
	chain := "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n"
	body, _ := json.Marshal(map[string]string{"chain_pem": chain, "decision": "trusted", "note": "netbox"})
	w := do(newTrustEngine(store), http.MethodPost, "/api/v2/inventory-service/trust-anchors/from-chain", strings.NewReader(string(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TrustAnchor", w.Body.Bytes())
	if store.gotFromChain.ChainPEM != chain || store.gotFromChain.Decision != "trusted" ||
		store.gotFromChain.Note != "netbox" || store.gotFromChain.DecidedBy != trustTestUser {
		t.Fatalf("store got %+v", store.gotFromChain)
	}
}

func TestContract_CreateTrustAnchorFromChain_errors(t *testing.T) {
	sv := loadSpec(t)
	ok := `{"chain_pem":"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n","decision":"distrusted"}`
	for _, tc := range []struct {
		name  string
		store *stubTrustAnchorStore
		body  string
		want  int
	}{
		{"no CA in the chain", &stubTrustAnchorStore{createErr: &certtrust.ErrInvalid{Msg: "chain_pem holds no CA certificate"}}, ok, http.StatusBadRequest},
		{"unknown field", &stubTrustAnchorStore{}, `{"chain_pem":"x","decision":"trusted","certificate_id":"` + aUUID + `"}`, http.StatusBadRequest},
		{"not json", &stubTrustAnchorStore{}, `{`, http.StatusBadRequest},
		{"decision exists for the top CA", &stubTrustAnchorStore{createErr: &certtrust.ErrConflict{ExistingID: uuid.New()}}, ok, http.StatusConflict},
		{"server error", &stubTrustAnchorStore{createErr: io.EOF}, ok, http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(newTrustEngine(tc.store), http.MethodPost, "/api/v2/inventory-service/trust-anchors/from-chain", strings.NewReader(tc.body))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		})
	}
}

// --- slice 4: GET /internal/trust/anchors ------------------------------------

type stubInternalTrust struct {
	out certtrust.InternalAnchors
	err error
	got uuid.UUID
}

func (s *stubInternalTrust) InternalAnchors(_ context.Context, tenantID uuid.UUID) (certtrust.InternalAnchors, error) {
	s.got = tenantID
	return s.out, s.err
}

func TestContract_InternalTrustAnchors(t *testing.T) {
	sv := loadSpec(t)
	tenant := uuid.New()
	newEngine := func(store *stubInternalTrust) *gin.Engine {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		grp := r.Group("/api/v1")
		// What RequireSignedServiceCall sets on a verified call.
		grp.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Next() })
		RegisterInternalTrustRoutes(grp, NewInternalTrustHandler(store))
		return r
	}
	for _, out := range []certtrust.InternalAnchors{
		{TrustedPEM: []string{}, DistrustedFingerprintsSHA256: []string{}, BundleVersion: "Tue Sep  9 03:12:01 2026 GMT"},
		{TrustedPEM: []string{"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"},
			DistrustedFingerprintsSHA256: []string{strings.Repeat("ab", 32)}, BundleVersion: "x"},
	} {
		store := &stubInternalTrust{out: out}
		w := do(newEngine(store), http.MethodGet, "/api/v1/inventory-service/internal/trust/anchors", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
		}
		sv.assertConforms(t, "InternalTrustAnchors", w.Body.Bytes())
		if store.got != tenant {
			t.Fatalf("store asked for tenant %s, want the signed tenant %s", store.got, tenant)
		}
	}
	w := do(newEngine(&stubInternalTrust{err: io.EOF}), http.MethodGet, "/api/v1/inventory-service/internal/trust/anchors", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
