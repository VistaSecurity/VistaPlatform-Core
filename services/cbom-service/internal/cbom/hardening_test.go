package cbom

// Handler-level tests for the export/diff/signing hardening: SPDX/PDF are
// rendered from the internal view, a legacy artifact is refused with 409,
// requested signing is never silently skipped, a presign failure does not leak,
// and the artifact list pages with a total.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
)

const (
	canonicalFixture = `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"cryptographic-asset"}]}`
	internalFixture  = `{"spec_version":"1.7","components":[{"id":"c1","name":"RSA-2048","type":"algorithm"}]}`
)

func downloadEngineWithStore(store *stubArtifactStore, f ArtifactFormatter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/cbom-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New().String())
		c.Set("userID", uuid.New().String())
		c.Next()
	})
	h := &Handler{repo: store, formatter: f}
	h.SetFeatureChecker(&stubFeatureChecker{allowed: true})
	h.RegisterRoutes(grp)
	return r
}

// The renderer must be handed the artifact's INTERNAL view. Handing it the
// canonical CycloneDX bytes was the bug: they decode as an empty CBOMData.
func TestDownload_SPDXAndPDF_RenderFromInternalView(t *testing.T) {
	for _, format := range []string{"spdx", "pdf"} {
		t.Run(format, func(t *testing.T) {
			a := sampleArtifact()
			store := &stubArtifactStore{
				getResult:     &a,
				inlineContent: []byte(canonicalFixture),
				diffContent:   []byte(internalFixture),
			}
			ff := &fakeFormatter{body: []byte("rendered"), mime: "application/octet-stream"}
			w := do(downloadEngineWithStore(store, ff), http.MethodGet,
				"/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format="+format, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			if string(ff.gotBytes) != internalFixture {
				t.Errorf("renderer received %q, want the internal view %q (not the canonical bytes)", ff.gotBytes, internalFixture)
			}
		})
	}
}

// An artifact with no internal view cannot be rendered truthfully: 409, with
// the regenerate instruction, and the renderer is never asked.
func TestDownload_SPDXAndPDF_LegacyArtifactIs409(t *testing.T) {
	for _, format := range []string{"spdx", "pdf"} {
		t.Run(format, func(t *testing.T) {
			a := sampleArtifact()
			store := &stubArtifactStore{getResult: &a, diffContentErr: ErrNoInternalView}
			ff := &fakeFormatter{body: []byte("rendered"), mime: "application/octet-stream"}
			w := do(downloadEngineWithStore(store, ff), http.MethodGet,
				"/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format="+format, nil)
			if w.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "regenerate") {
				t.Errorf("409 body should tell the caller to regenerate: %s", w.Body.String())
			}
			if ff.gotFormat != "" {
				t.Errorf("renderer was called for an artifact with no internal view")
			}
		})
	}
}

// fakeStorage overrides only what these tests exercise; any other call panics
// on the nil embedded interface, which is the point.
type fakeStorage struct {
	sharedstorage.ArtifactStorageService
	getURLErr error
}

func (f fakeStorage) GetURL(context.Context, sharedstorage.ArtifactType, string, *uuid.UUID) (string, error) {
	return "", f.getURLErr
}

func TestDownload_PresignFailureDoesNotLeakDetail(t *testing.T) {
	a := sampleArtifact()
	a.HasInlineContent = false
	a.StorageKey = "cbom/key"
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/cbom-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New().String())
		c.Next()
	})
	h := &Handler{repo: &stubArtifactStore{getResult: &a}, storage: fakeStorage{getURLErr: errors.New("InvalidAccessKeyId: AKIASECRET bucket internal-evidence-bucket")}}
	h.RegisterRoutes(grp)

	w := do(r, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	for _, leak := range []string{"AKIASECRET", "internal-evidence-bucket", "presign"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("response leaks %q: %s", leak, w.Body.String())
		}
	}
}

func generateEngine(signer Signer, allowed bool) (*gin.Engine, *stubPersister, string) {
	scope := sampleScope()
	persisted := sampleArtifact()
	persister := &stubPersister{out: &persisted}
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
		scopes:    &stubScopeGetter{result: scope},
		builder:   &stubBuilder{out: &BuildOutput{CanonicalBytes: []byte("{}"), ContentHash: "deadbeef"}},
		persister: persister,
		features:  &stubFeatureChecker{allowed: allowed},
		signer:    signer,
	})
	return eng, persister, scope.ID.String()
}

func TestGenerate_ExplicitSignWithoutSignerIs503(t *testing.T) {
	eng, persister, scopeID := generateEngine(nil, true)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate",
		strings.NewReader(`{"scope_id":"`+scopeID+`","sign":true}`))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	if persister.input != nil {
		t.Errorf("an artifact was persisted although the requested signing could not happen")
	}
	if !strings.Contains(w.Body.String(), "signing") {
		t.Errorf("503 body should say why: %s", w.Body.String())
	}
}

func TestGenerate_DefaultSigningWithoutSignerIsReported(t *testing.T) {
	eng, persister, scopeID := generateEngine(nil, true)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate",
		strings.NewReader(`{"scope_id":"`+scopeID+`"}`))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	var resp GenerateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.SigningError == "" {
		t.Errorf("unsigned-by-default artifact must carry signing_error: %s", w.Body.String())
	}
	if persister.input == nil || persister.input.Sign {
		t.Errorf("persister must be told not to sign when there is no signer: %+v", persister.input)
	}
}

func TestGenerate_NoSignerNoSigningRequested_NoSigningError(t *testing.T) {
	// Core / unentitled: signing is not on, so nothing is skipped and nothing
	// should be reported.
	eng, _, scopeID := generateEngine(nil, false)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate",
		strings.NewReader(`{"scope_id":"`+scopeID+`"}`))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "signing_error") {
		t.Errorf("unexpected signing_error: %s", w.Body.String())
	}
}

func TestGenerate_PersisterSignerUnavailableIs503(t *testing.T) {
	scope := sampleScope()
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
		scopes:    &stubScopeGetter{result: scope},
		builder:   &stubBuilder{out: &BuildOutput{CanonicalBytes: []byte("{}"), ContentHash: "deadbeef"}},
		persister: &stubPersister{err: ErrSignerUnavailable},
		features:  &stubFeatureChecker{allowed: true},
		signer:    stubSigner{},
	})
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate",
		strings.NewReader(`{"scope_id":"`+scope.ID.String()+`"}`))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
}

func TestList_PagingReachesStoreAndReportsTotal(t *testing.T) {
	store := &stubArtifactStore{list: []Artifact{sampleArtifact()}, total: 123}
	eng := newEngine(handlerDeps{artifacts: store})

	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts?page=3&page_size=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if store.lastLimit != 10 || store.lastOffset != 20 {
		t.Errorf("store got limit=%d offset=%d, want 10/20", store.lastLimit, store.lastOffset)
	}
	var resp struct {
		Total      int64 `json:"total"`
		Page       int   `json:"page"`
		PageSize   int   `json:"page_size"`
		TotalPages int   `json:"total_pages"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 123 || resp.Page != 3 || resp.PageSize != 10 || resp.TotalPages != 13 {
		t.Errorf("paging envelope = %+v", resp)
	}

	// limit stays the page size for existing callers; page still offsets by it.
	w = do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts?limit=5&page=2", nil)
	if w.Code != http.StatusOK || store.lastLimit != 5 || store.lastOffset != 5 {
		t.Errorf("limit+page: code=%d limit=%d offset=%d, want 200/5/5", w.Code, store.lastLimit, store.lastOffset)
	}

	for _, q := range []string{"?page=0", "?page=x", "?page_size=-1"} {
		if w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts"+q, nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q, w.Code)
		}
	}
}
