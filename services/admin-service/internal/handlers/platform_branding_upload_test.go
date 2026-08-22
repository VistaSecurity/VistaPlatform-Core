package handlers

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// A minimal but real PNG (1x1). What matters is the leading magic bytes, since
// the handler admits the file on http.DetectContentType, not on its name.
var onePixelPNG = []byte{
	0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0a, 'I', 'D', 'A', 'T',
	0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05,
	0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00,
	0x00, 0x00, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
}

// uploadBrandingAsset drives the real handler over httptest with a multipart
// body, returning the response and the names of the files left on disk.
func uploadBrandingAsset(t *testing.T, assetType, uploadFilename, declaredContentType string, content []byte) (*httptest.ResponseRecorder, []string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// Redirect local storage into the test's temp dir so we can inspect what
	// name the asset was actually persisted under.
	tmp := t.TempDir()
	orig := platformBrandingUploadDir
	platformBrandingUploadDir = filepath.Join(tmp, "platform-branding")
	t.Cleanup(func() { platformBrandingUploadDir = orig })

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("INSERT INTO platform_settings").
		WillReturnResult(sqlmock.NewResult(1, 1))

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("type", assetType); err != nil {
		t.Fatalf("write field: %v", err)
	}
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{
		`form-data; name="file"; filename="` + uploadFilename + `"`,
	}
	h["Content-Type"] = []string{declaredContentType}
	part, err := w.CreatePart(h)
	if err != nil {
		t.Fatalf("create part: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req := httptest.NewRequest("POST", apiBase+"/admin/branding/upload", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	c.Set("userID", uuid.New().String())

	UploadPlatformBrandingAsset(db)(c)

	var written []string
	entries, err := os.ReadDir(platformBrandingUploadDir)
	if err == nil {
		for _, e := range entries {
			written = append(written, e.Name())
		}
	}
	return rec, written
}

// The regression this guards: the handler used to take the stored extension
// from filepath.Ext(file.Filename). Magic-byte validation constrained the
// CONTENT while the caller still chose the name — so PNG bytes uploaded as
// "evil.svg" were persisted as a .svg asset, despite SVG being deliberately
// excluded from the allowlist (it can carry script → stored XSS).
func TestUploadPlatformBrandingAsset_ExtensionIsServerAuthoritative(t *testing.T) {
	hostileNames := []string{
		"evil.svg",
		"evil.html",
		"evil.js",
		"evil.phtml",
		"logo.png.svg",
		"../../../../etc/cron.d/evil.sh",
		// NB: a NUL byte in the file name is NOT listed here. It makes Go's
		// multipart parser fail the whole form, so the request is rejected at
		// the asset-type check before reaching the extension logic — safe, but a
		// different code path, and asserting 200 on it would be wrong.
	}

	for _, name := range hostileNames {
		t.Run(name, func(t *testing.T) {
			rec, written := uploadBrandingAsset(t, "logo", name, "image/png", onePixelPNG)

			if rec.Code != 200 {
				t.Fatalf("expected the PNG to be accepted, got %d: %s", rec.Code, rec.Body.String())
			}
			if len(written) != 1 {
				t.Fatalf("expected exactly 1 stored file, got %v", written)
			}

			got := written[0]
			if !strings.HasSuffix(got, ".png") {
				t.Fatalf("stored asset did not get the server-derived .png extension: %q", got)
			}
			// The caller's chosen extension must not survive anywhere in the name.
			for _, bad := range []string{".svg", ".html", ".js", ".phtml", ".sh"} {
				if strings.Contains(got, bad) {
					t.Fatalf("caller-supplied extension %q survived into the stored name %q", bad, got)
				}
			}

			// And the URL handed back (which is what gets rendered) agrees.
			var resp struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !strings.HasSuffix(resp.URL, ".png") {
				t.Fatalf("returned URL kept a caller-chosen extension: %q", resp.URL)
			}
		})
	}
}

// The asset must land inside the configured directory — never above it — even
// when the caller's file name is a traversal attempt.
func TestUploadPlatformBrandingAsset_StaysInsideUploadDir(t *testing.T) {
	rec, written := uploadBrandingAsset(t, "logo", "../../../../tmp/pwned.png", "image/png", onePixelPNG)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(written) != 1 {
		t.Fatalf("expected exactly 1 file inside the upload dir, got %v", written)
	}
	if strings.ContainsAny(written[0], `/\`) {
		t.Fatalf("stored name contains a path separator: %q", written[0])
	}
	if !strings.HasPrefix(written[0], "platform-logo-") {
		t.Fatalf("stored name lost its server-generated prefix: %q", written[0])
	}
}

// A file whose CONTENT is not an allowed image is rejected regardless of what
// the caller names it or declares — this is the pre-existing magic-byte check,
// pinned so the extension fix above cannot be "simplified" into removing it.
func TestUploadPlatformBrandingAsset_RejectsNonImageContent(t *testing.T) {
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	rec, written := uploadBrandingAsset(t, "logo", "logo.png", "image/png", svg)

	if rec.Code != 400 {
		t.Fatalf("expected 400 for non-image content, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(written) != 0 {
		t.Fatalf("rejected upload still wrote files: %v", written)
	}
}

func TestBrandingExtForType(t *testing.T) {
	cases := map[string]string{
		"image/png":    ".png",
		"image/jpeg":   ".jpg",
		"image/x-icon": ".ico",
	}
	for mime, want := range cases {
		got, ok := brandingExtForType(mime)
		if !ok || got != want {
			t.Errorf("brandingExtForType(%q) = %q,%v; want %q,true", mime, got, ok, want)
		}
	}
	// Anything not on the allowlist must fail closed, not return "".
	for _, mime := range []string{"image/svg+xml", "text/html", "application/octet-stream", ""} {
		if got, ok := brandingExtForType(mime); ok {
			t.Errorf("brandingExtForType(%q) unexpectedly allowed, returned %q", mime, got)
		}
	}
}
