package api

// Upload content validation.
//
// The avatar and branding upload handlers previously trusted the request's
// Content-Type HEADER (attacker-controlled) and, in the branding case, the
// client FILENAME's extension. That let a caller send Content-Type: image/png
// with SVG/HTML/script bytes named "evil.svg" and have it persisted as ".svg" —
// a stored-XSS vector when the asset is served back.
//
// sniffImageType instead identifies the real type from the file's MAGIC BYTES
// and returns a SERVER-AUTHORITATIVE extension. SVG (and anything else without
// raster-image magic) is rejected — SVG can embed JavaScript and is excluded by
// design.

import (
	"bytes"
	"io"
	"mime/multipart"
)

// detectedImage is a raster image type recognized by its magic bytes, with the
// canonical MIME and the server-chosen on-disk extension.
type detectedImage struct {
	MIME string
	Ext  string
}

// sniffImageType reads the leading bytes of an uploaded file and identifies the
// real image type from its magic bytes — never from the Content-Type header or
// the client filename. ok is false for anything that isn't one of the recognized
// raster types (PNG / JPEG / GIF / ICO / WEBP); notably SVG, HTML and scripts
// have no image magic and are rejected. Callers must additionally check the
// returned MIME against the per-endpoint allowlist.
func sniffImageType(fh *multipart.FileHeader) (detectedImage, bool) {
	f, err := fh.Open()
	if err != nil {
		return detectedImage{}, false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 16)
	n, _ := io.ReadFull(f, buf) // short files fill partially; n is the real count
	b := buf[:n]

	switch {
	case len(b) >= 8 && bytes.Equal(b[:8], []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return detectedImage{MIME: "image/png", Ext: ".png"}, true
	case len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return detectedImage{MIME: "image/jpeg", Ext: ".jpg"}, true
	case len(b) >= 6 && (bytes.Equal(b[:6], []byte("GIF87a")) || bytes.Equal(b[:6], []byte("GIF89a"))):
		return detectedImage{MIME: "image/gif", Ext: ".gif"}, true
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x00, 0x00, 0x01, 0x00}):
		return detectedImage{MIME: "image/x-icon", Ext: ".ico"}, true
	case len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return detectedImage{MIME: "image/webp", Ext: ".webp"}, true
	}
	return detectedImage{}, false
}
