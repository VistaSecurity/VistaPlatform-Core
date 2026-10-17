package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

type recordingTrustStore struct{ asked uuid.UUID }

func (s *recordingTrustStore) InternalAnchors(_ context.Context, tenantID uuid.UUID) (certtrust.InternalAnchors, error) {
	s.asked = tenantID
	return certtrust.InternalAnchors{TrustedPEM: []string{}, DistrustedFingerprintsSHA256: []string{"ab"}, BundleVersion: "v"}, nil
}

// GET /internal/trust/anchors through mountSourceImportRoutes — main()'s
// helper: a signed call reaches the handler for exactly the SIGNED tenant;
// an unsigned one never reaches it. (The refusals for tenant tokens, wrong
// secrets and swapped tenants run over sourceRoutes, which lists it.)
func TestInternalTrustRoute_SignedTenantOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &recordingTrustStore{}
	r := gin.New()
	mountSourceImportRoutes(r, handlers.NewSourceImportHandler(nil), handlers.NewCIExportHandler(nil),
		handlers.NewInternalTrustHandler(store), handlers.NewDCIMSyncHandler(nil), handlers.NewDCIMImportHandler(nil), sourceTestSecret)
	const path = "/api/v1/inventory-service/internal/trust/anchors"

	tenant := uuid.New()
	req := sourceRequest(http.MethodGet, path, nil)
	req.Header.Set(serviceauth.HeaderTenantID, tenant.String())
	serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
	w := serve(r, req)
	if w.Code != http.StatusOK {
		t.Fatalf("signed call = %d (%s), want 200", w.Code, w.Body.String())
	}
	if store.asked != tenant {
		t.Fatalf("handler read tenant %s, want the signed %s", store.asked, tenant)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["distrusted_fingerprints_sha256"] == nil {
		t.Fatalf("body %s", w.Body.String())
	}

	store.asked = uuid.Nil
	unsigned := sourceRequest(http.MethodGet, path, nil)
	unsigned.Header.Set(serviceauth.HeaderTenantID, tenant.String())
	if w := serve(r, unsigned); w.Code != http.StatusUnauthorized || store.asked != uuid.Nil {
		t.Fatalf("unsigned call = %d and reached the store: %v; want 401 and no read", w.Code, store.asked != uuid.Nil)
	}

	noTenant := sourceRequest(http.MethodGet, path, nil)
	serviceauth.NewSigner(sourceTestSecret).SignRequest(noTenant)
	if w := serve(r, noTenant); w.Code != http.StatusBadRequest || store.asked != uuid.Nil {
		t.Fatalf("signed call naming no tenant = %d, want 400 and no read", w.Code)
	}
}
