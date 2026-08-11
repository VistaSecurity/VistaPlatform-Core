package cbom

// Edition gate on /cbom/artifacts/:id/download.
//
// Owner decision: Core serves CycloneDX — the CBOM standard — and
// nothing else; SPDX and PDF are the Enterprise reporting upsell. These tests
// pin both halves of that from the HTTP surface:
//
//   - Core (formatter nil, the zero value): cyclonedx 200, spdx/pdf 402.
//   - Enterprise (a formatter wired): all three 200, with the renderer's
//     content type passed through.
//
// The Enterprise half uses a fake formatter rather than importing
// ee/cbomformats, deliberately. A `//go:build ee` file here would survive the
// open-source repo cut (which deletes only services/*/ee/ and
// services/*/cmd/edition_ee.go) and dangle. What Core owns is the *gate*, and a
// fake proves the gate opens; that the real renderer produces valid SPDX/PDF is
// pinned next to it in ee/cbomformats/renderer_test.go.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// fakeFormatter stands in for the Enterprise renderer.
type fakeFormatter struct {
	gotFormat string
	body      []byte
	mime      string
	err       error
}

func (f *fakeFormatter) Render(_ []byte, format string) ([]byte, string, error) {
	f.gotFormat = format
	if f.err != nil {
		return nil, "", f.err
	}
	return f.body, f.mime, nil
}

// newDownloadEngine mounts the real routes over a stub store holding one
// inline-content artifact, with the given formatter (nil == Core).
func newDownloadEngine(a *Artifact, formatter ArtifactFormatter, features featureChecker) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/cbom-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New().String())
		c.Set("userID", uuid.New().String())
		c.Next()
	})
	h := &Handler{
		repo: &stubArtifactStore{
			getResult:     a,
			inlineContent: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`),
		},
		formatter: formatter,
	}
	h.SetFeatureChecker(features)
	h.RegisterRoutes(grp)
	return r
}

func TestDownload_Core_ServesCycloneDX(t *testing.T) {
	a := sampleArtifact()
	eng := newDownloadEngine(&a, nil, nil) // Core: no formatter

	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=cyclonedx", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("cyclonedx status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/vnd.cyclonedx+json" {
		t.Errorf("cyclonedx content-type = %q, want application/vnd.cyclonedx+json", ct)
	}
	// The canonical bytes must come back verbatim — this is the form
	// content_hash refers to, so Core must not reshape them.
	if got := w.Body.String(); got != `{"bomFormat":"CycloneDX","specVersion":"1.6"}` {
		t.Errorf("cyclonedx body = %q, want the canonical bytes verbatim", got)
	}
}

func TestDownload_Core_DefaultFormatIsCycloneDX(t *testing.T) {
	a := sampleArtifact()
	eng := newDownloadEngine(&a, nil, nil)

	// No ?format= at all: Core must still serve, not 402.
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("default-format status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestDownload_Core_Refuses402_ForEnterpriseFormats(t *testing.T) {
	for _, format := range []string{"spdx", "pdf"} {
		t.Run(format, func(t *testing.T) {
			a := sampleArtifact()
			eng := newDownloadEngine(&a, nil, nil) // Core: no formatter

			w := do(eng, http.MethodGet,
				"/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format="+format, nil)
			if w.Code != http.StatusPaymentRequired {
				t.Fatalf("%s status = %d, want 402; body=%s", format, w.Code, w.Body.String())
			}
			// 402, not 400: the format is valid, the edition is the constraint.
			// The message has to name the requirement or the UI can't tell the
			// user what to do about it.
			var body struct{ Error string }
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal error body: %v; raw=%s", err, w.Body.String())
			}
			if !strings.Contains(body.Error, "Enterprise") {
				t.Errorf("error %q should name the Enterprise requirement", body.Error)
			}
			if !strings.Contains(body.Error, format) {
				t.Errorf("error %q should name the refused format %q", body.Error, format)
			}
		})
	}
}

func TestDownload_Core_RejectsUnknownFormatWith400(t *testing.T) {
	// Guards the distinction the 402 exists to make: an unrecognised format is
	// still a client error, not an upsell.
	a := sampleArtifact()
	eng := newDownloadEngine(&a, nil, nil)

	w := do(eng, http.MethodGet,
		"/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=docx", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown-format status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestDownload_EnterpriseFormatRequiresTenantEntitlement(t *testing.T) {
	a := sampleArtifact()
	features := &stubFeatureChecker{allowed: false}
	eng := newDownloadEngine(&a, &fakeFormatter{body: []byte("x"), mime: "application/spdx+json"}, features)

	w := do(eng, http.MethodGet,
		"/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=spdx", nil)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
	if features.feature != FeatureCBOMSigning {
		t.Fatalf("checked feature %q, want %q", features.feature, FeatureCBOMSigning)
	}
}

func TestDownload_Enterprise_ServesAllThreeFormats(t *testing.T) {
	cases := []struct {
		format string
		mime   string
		body   string
	}{
		{"cyclonedx", "application/vnd.cyclonedx+json", `{"bomFormat":"CycloneDX","specVersion":"1.6"}`},
		{"spdx", "application/spdx+json", `{"spdxVersion":"SPDX-2.3"}`},
		{"pdf", "application/pdf", "%PDF-1.7 fake"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			a := sampleArtifact()
			ff := &fakeFormatter{body: []byte(tc.body), mime: tc.mime}
			eng := newDownloadEngine(&a, ff, &stubFeatureChecker{allowed: true})

			w := do(eng, http.MethodGet,
				"/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format="+tc.format, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200; body=%s", tc.format, w.Code, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); ct != tc.mime {
				t.Errorf("%s content-type = %q, want %q", tc.format, ct, tc.mime)
			}
			if got := w.Body.String(); got != tc.body {
				t.Errorf("%s body = %q, want %q", tc.format, got, tc.body)
			}
			// CycloneDX must be served straight from the canonical bytes even
			// on Enterprise — routing it through the renderer would put a
			// re-serialization between content_hash and the download.
			if tc.format == "cyclonedx" && ff.gotFormat != "" {
				t.Errorf("cyclonedx went through the Enterprise renderer (got format %q); it must be served verbatim", ff.gotFormat)
			}
			if tc.format != "cyclonedx" && ff.gotFormat != tc.format {
				t.Errorf("renderer received format %q, want %q", ff.gotFormat, tc.format)
			}
		})
	}
}

func TestDownload_ContentDispositionPerFormat(t *testing.T) {
	cases := map[string]string{
		"cyclonedx": ".cdx.json",
		"spdx":      ".spdx.json",
		"pdf":       ".pdf",
	}
	for format, suffix := range cases {
		t.Run(format, func(t *testing.T) {
			a := sampleArtifact()
			eng := newDownloadEngine(&a, &fakeFormatter{body: []byte("x"), mime: "application/octet-stream"}, &stubFeatureChecker{allowed: true})
			w := do(eng, http.MethodGet,
				"/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format="+format, nil)
			cd := w.Header().Get("Content-Disposition")
			if !strings.Contains(cd, suffix) {
				t.Errorf("%s Content-Disposition = %q, want it to end in %q", format, cd, suffix)
			}
		})
	}
}
