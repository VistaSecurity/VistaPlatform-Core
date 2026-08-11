package api

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// magic-byte prefixes for the recognized raster types.
var (
	pngBytes  = append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, []byte("rest")...)
	jpegBytes = append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte("jfif")...)
	gifBytes  = []byte("GIF89a............")
	icoBytes  = append([]byte{0x00, 0x00, 0x01, 0x00}, []byte("icon")...)
	webpBytes = append(append([]byte("RIFF"), []byte{0, 0, 0, 0}...), []byte("WEBP....")...)
	svgBytes  = []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	htmlBytes = []byte("<!DOCTYPE html><html><body>hi</body></html>")
)

// buildUpload constructs a multipart body. Each field is (name, filename,
// contentTypeHeader, content); a filename of "" makes it a plain text field.
type uploadField struct {
	name, filename, contentType string
	content                     []byte
}

func buildUpload(t *testing.T, fields []uploadField) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, fld := range fields {
		if fld.filename == "" {
			if err := mw.WriteField(fld.name, string(fld.content)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, fld.name, fld.filename))
		h.Set("Content-Type", fld.contentType)
		part, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write(fld.content)
	}
	_ = mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestSniffImageType(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
		wantOK  bool
		wantExt string
	}{
		{"png", pngBytes, true, ".png"},
		{"jpeg", jpegBytes, true, ".jpg"},
		{"gif", gifBytes, true, ".gif"},
		{"ico", icoBytes, true, ".ico"},
		{"webp", webpBytes, true, ".webp"},
		{"svg rejected", svgBytes, false, ""},
		{"html rejected", htmlBytes, false, ""},
		{"empty rejected", []byte{}, false, ""},
		{"random rejected", []byte("not an image at all"), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, ct := buildUpload(t, []uploadField{{"f", "x.bin", "image/png", tc.content}})
			req := httptest.NewRequest(http.MethodPost, "/", body)
			req.Header.Set("Content-Type", ct)
			if err := req.ParseMultipartForm(1 << 20); err != nil {
				t.Fatalf("parse: %v", err)
			}
			fh := req.MultipartForm.File["f"][0]
			got, ok := sniffImageType(fh)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got.Ext != tc.wantExt {
				t.Fatalf("ext = %q, want %q", got.Ext, tc.wantExt)
			}
		})
	}
}

// A file with a spoofed Content-Type: image/png header but SVG content is
// rejected by the avatar handler (magic-byte validation), before any DB call.
func TestUploadAvatar_RejectsSpoofedContentType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", uuid.New().String()); c.Next() })
	h := &AuthHandlers{}
	r.POST("/upload-avatar", h.UploadAvatar)

	body, ct := buildUpload(t, []uploadField{{"avatar", "evil.png", "image/png", svgBytes}})
	req := httptest.NewRequest(http.MethodPost, "/upload-avatar", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// The branding handler rejects a spoofed-Content-Type SVG (the stored-XSS
// vector that the old filepath.Ext(file.Filename) path allowed onto disk).
func TestUploadBrandingAsset_RejectsSpoofedSVG(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("tenantID", uuid.New().String()); c.Next() })
	// Entitled: this suite asserts upload *validation* (content sniffing), not
	// the custom_branding gate, which has its own tests.
	r.POST("/branding/upload", UploadBrandingAssetWithChecker(nil,
		&stubLimitChecker{featureResults: map[string]bool{"custom_branding": true}}))

	body, ct := buildUpload(t, []uploadField{
		{name: "type", content: []byte("logo")},
		{name: "file", filename: "evil.svg", contentType: "image/png", content: svgBytes},
	})
	req := httptest.NewRequest(http.MethodPost, "/branding/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
