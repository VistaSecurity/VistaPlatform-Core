package api

// Contract test for the tenant-branding HTTP surface (Settings → Organization
// branding). Extends the auth-service spec-first contract (ADR-0001) and reuses
// the shared harness (loadSpec / assertConforms / do / aTenantID) from
// cross_cutter_contract_test.go.
//
// GetTenantBranding / UpdateTenantBranding were refactored to depend on the
// tenantBrandingStore interface (via the *WithStore variants; the *sql.DB-backed
// repo is the production impl), so these tests drive the real handlers with an
// in-memory stub — no database. UploadBrandingAsset does not touch the DB; its
// reachable validation paths are covered directly.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// --- stub tenantBrandingStore ----------------------------------------------

type stubTenantBrandingStore struct {
	brandingJSON []byte
	getErr       error
	updateErr    error
}

func (s *stubTenantBrandingStore) GetBrandingJSON(_ context.Context, _ uuid.UUID) ([]byte, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.brandingJSON == nil {
		return []byte("{}"), nil
	}
	return s.brandingJSON, nil
}

func (s *stubTenantBrandingStore) UpdateBrandingJSON(_ context.Context, _ uuid.UUID, _ []byte) error {
	return s.updateErr
}

func newBrandingEngine(store tenantBrandingStore, authenticated bool, tenantID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if store == nil {
		store = &stubTenantBrandingStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", tenantID)
		}
		c.Next()
	})
	grp.GET("/tenant/branding", GetTenantBrandingWithStore(store))
	// Entitled by default: these cases predate the custom_branding gate and
	// assert the branding behavior itself. The gate has its own tests below.
	entitled := &stubLimitChecker{featureResults: map[string]bool{"custom_branding": true}}
	grp.PUT("/tenant/branding", UpdateTenantBrandingWithStore(store, entitled))
	grp.POST("/tenant/branding/upload", UploadBrandingAssetWithChecker(nil, entitled)) // db unused by upload
	return r
}

// --- GET /tenant/branding ---------------------------------------------------

func TestContract_GetTenantBranding_200_defaults(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{}, true, aTenantID) // empty {} -> color defaults
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/branding", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "BrandingResponse", w.Body.Bytes())
}

func TestContract_GetTenantBranding_200_populated(t *testing.T) {
	sv := loadSpec(t)
	store := &stubTenantBrandingStore{brandingJSON: []byte(`{"primary_color":"#111111","secondary_color":"#222222","accent_color":"#333333","logo_url":"https://cdn.example.com/logo.png","company_name":"Acme"}`)}
	eng := newBrandingEngine(store, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/branding", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "BrandingResponse", w.Body.Bytes())
}

func TestContract_GetTenantBranding_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{}, false, aTenantID) // no tenant in ctx
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/branding", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantBranding_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{getErr: sql.ErrNoRows}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/branding", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantBranding_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{getErr: errors.New("db down")}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/branding", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- PUT /tenant/branding ---------------------------------------------------

func TestContract_UpdateTenantBranding_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{}, true, aTenantID)
	body := strings.NewReader(`{"primary_color":"#0066cc","secondary_color":"#00a86b","accent_color":"#ff6b6b","company_name":"Acme"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/branding", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdateBrandingResponse", w.Body.Bytes())
}

func TestContract_UpdateTenantBranding_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{}, true, aTenantID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/branding", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantBranding_400_invalidColor(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{}, true, aTenantID)
	body := strings.NewReader(`{"primary_color":"not-a-hex-color"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/branding", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantBranding_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{getErr: sql.ErrNoRows}, true, aTenantID)
	body := strings.NewReader(`{"primary_color":"#0066cc"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/branding", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantBranding_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{updateErr: errors.New("db down")}, true, aTenantID)
	body := strings.NewReader(`{"primary_color":"#0066cc"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/branding", body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- POST /tenant/branding/upload (validation paths; no DB) ------------------

func brandingMultipart(t *testing.T, fields map[string]string, fileField, filename string, content []byte, fileContentType string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatalf("write field: %v", err)
		}
	}
	if fileField != "" {
		hdr := make(map[string][]string)
		hdr["Content-Disposition"] = []string{`form-data; name="` + fileField + `"; filename="` + filename + `"`}
		if fileContentType != "" {
			hdr["Content-Type"] = []string{fileContentType}
		}
		fw, err := w.CreatePart(hdr)
		if err != nil {
			t.Fatalf("create part: %v", err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return &buf, w.FormDataContentType()
}

func doBrandingUpload(eng *gin.Engine, body *bytes.Buffer, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/tenant/branding/upload", body)
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	return w
}

func TestContract_UploadBrandingAsset_400_badType(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{}, true, aTenantID)
	body, ct := brandingMultipart(t, map[string]string{"type": "banner"}, "", "", nil, "")
	w := doBrandingUpload(eng, body, ct)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UploadBrandingAsset_400_noFile(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{}, true, aTenantID)
	body, ct := brandingMultipart(t, map[string]string{"type": "logo"}, "", "", nil, "")
	w := doBrandingUpload(eng, body, ct)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UploadBrandingAsset_400_invalidFileType(t *testing.T) {
	sv := loadSpec(t)
	eng := newBrandingEngine(&stubTenantBrandingStore{}, true, aTenantID)
	// A file part with a disallowed content type (text/plain) -> 400.
	body, ct := brandingMultipart(t, map[string]string{"type": "logo"}, "file", "logo.txt", []byte("hello"), "text/plain")
	w := doBrandingUpload(eng, body, ct)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- custom_branding edition gate -------------------------------------------
//
// Branding is the one "gate-don't-move" carve: no code left Core, because the
// read path runs on every page load and a Core install still themes itself.
// What Enterprise buys is the white-label surface — replacing our identity with
// the customer's. These pin exactly where that line sits.

func newBrandingEngineWithEntitlement(store tenantBrandingStore, entitled bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if store == nil {
		store = &stubTenantBrandingStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) { c.Set("tenantID", aTenantID); c.Next() })
	lc := &stubLimitChecker{featureResults: map[string]bool{"custom_branding": entitled}}
	grp.PUT("/tenant/branding", UpdateTenantBrandingWithStore(store, lc))
	grp.POST("/tenant/branding/upload", UploadBrandingAssetWithChecker(nil, lc))
	return r
}

func TestBrandingGate_ColorsAllowedWithoutEntitlement(t *testing.T) {
	eng := newBrandingEngineWithEntitlement(&stubTenantBrandingStore{}, false)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/branding",
		strings.NewReader(`{"primary_color":"#112233","secondary_color":"#445566"}`))
	if w.Code == http.StatusForbidden {
		t.Fatalf("palette-only update was rejected without custom_branding; colors are Core. body=%s", w.Body.String())
	}
}

func TestBrandingGate_LogoRejectedWithoutEntitlement(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"logo", `{"logo_url":"https://cdn.example.com/logo.png"}`},
		{"favicon", `{"favicon_url":"https://cdn.example.com/f.ico"}`},
		{"company_name", `{"company_name":"Acme"}`},
		{"custom_css", `{"custom_css":".x{}"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := newBrandingEngineWithEntitlement(&stubTenantBrandingStore{}, false)
			w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/branding", strings.NewReader(tc.body))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 for white-label field %q without custom_branding; body=%s",
					w.Code, tc.name, w.Body.String())
			}
		})
	}
}

func TestBrandingGate_LogoAllowedWithEntitlement(t *testing.T) {
	eng := newBrandingEngineWithEntitlement(&stubTenantBrandingStore{}, true)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/branding",
		strings.NewReader(`{"logo_url":"https://cdn.example.com/logo.png"}`))
	if w.Code == http.StatusForbidden {
		t.Fatalf("entitled tenant was refused a logo update; body=%s", w.Body.String())
	}
}
