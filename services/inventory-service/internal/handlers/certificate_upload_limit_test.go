package handlers

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// The certificate upload capped what it PARSED at 1 MiB with an
// io.LimitReader — but that runs after gin has received and buffered the whole
// multipart body, so a 100 MiB "certificate" was resident in the pod before the
// cap had any say. Same number, moved to the ingress.

func certUploadEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := NewCertificateHandler(&stubCertificateStore{})
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	r.POST("/upload", h.UploadCertificate)
	return r
}

// certUploadCounter records what the server pulled off the wire — the direct
// measure of "refused before buffering". A heap figure after the fact does not
// say it: gin spills a large multipart body to a temp file and the garbage is
// collected before anything can read it.
type certUploadCounter struct {
	r    io.Reader
	read int64
}

func (c *certUploadCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	return n, err
}

func streamCertUpload(t *testing.T, size int) (io.Reader, string) {
	t.Helper()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	ct := mw.FormDataContentType()
	go func() {
		fw, err := mw.CreateFormFile("certificate_file", "huge.pem")
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for written := 0; written < size; {
			n := len(chunk)
			if size-written < n {
				n = size - written
			}
			if _, err := fw.Write(chunk[:n]); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			written += n
		}
		_ = mw.Close()
		_ = pw.Close()
	}()
	return pr, ct
}

func TestUploadCertificate_OversizeIsRefusedBeforeBuffering(t *testing.T) {
	const attack = 100 << 20

	body, ct := streamCertUpload(t, attack)
	counted := &certUploadCounter{r: body}
	req := httptest.NewRequest(http.MethodPost, "/upload", counted)
	req.Header.Set("Content-Type", ct)
	req.ContentLength = -1
	w := httptest.NewRecorder()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	certUploadEngine().ServeHTTP(w, req)
	runtime.ReadMemStats(&after)

	allocatedMiB := float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)
	t.Logf("100 MiB certificate upload: status=%d bytes_read=%.1f MiB total_allocated=%.1f MiB",
		w.Code, float64(counted.read)/(1<<20), allocatedMiB)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	if counted.read > 8*maxCertPEMBytes {
		t.Errorf("the server read %d bytes of a %d-byte upload against a %d-byte cap",
			counted.read, attack, maxCertPEMBytes)
	}
	if allocatedMiB > 32 {
		t.Errorf("the refused upload allocated %.1f MiB in total", allocatedMiB)
	}
}

// The other polarity: an ordinary PEM must still be accepted. A cap that eats
// real certificates is the same defect facing the other way. This one is
// rejected for its CONTENT (it is not a PEM), which is the point — it got past
// the ceiling and reached the parser.
func TestUploadCertificate_OrdinarySizedUploadReachesTheParser(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("certificate_file", "cert.pem")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(bytes.Repeat([]byte("A"), 4096)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	certUploadEngine().ServeHTTP(w, req)

	if w.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("a 4 KiB upload was refused as too large: %s", w.Body.String())
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (no PEM block in the upload); body=%s", w.Code, w.Body.String())
	}
}
